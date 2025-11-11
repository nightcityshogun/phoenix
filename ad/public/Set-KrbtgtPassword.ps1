<#
.SYNOPSIS
Resets the krbtgt account password per domain, PDC-first, with two cycles.

.DESCRIPTION
Set-KrbtgtPassword validates ONLINE writable DCs (skips RODCs), orders domains Forest Root → Child → Tree Root,
binds to the preferred DC (PDC if present), locates the krbtgt user via RootDSE, and performs two password reset
cycles (with a short delay) using ADSI SetPassword. Runs in WhatIf unless -Execute is provided.

.PARAMETER IsolatedDCList
DC inventory objects with at least: FQDN, Domain, Type, Online, IsPdcRoleOwner.

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.PARAMETER Length
Password length for generator (default 24).

.EXAMPLE
# Simulate across all isolated domains
Set-KrbtgtPassword -IsolatedDCList $dcs

.EXAMPLE
# Apply two-cycle reset using 32-char secrets
Set-KrbtgtPassword -IsolatedDCList $dcs -Execute -Length 32

.OUTPUTS
None. Progress is logged via Write-IdentIRLog.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: ADSI (LDAP), Domain/Enterprise Admin privileges.
Behavior: Forest Root → Child → Tree; PDC-first; two cycles with retry; normalizes SecureString → string; honors ShouldProcess; restores WhatIf/Confirm.
Security: Rotating krbtgt immediately invalidates new TGTs after replication; plan downtime/session impact accordingly.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>

function Set-KrbtgtPassword {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]] $IsolatedDCList,
        [switch]     $Execute,
        [int]        $Length = 24
    )

    if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
        Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
        return
    }

    $oldConfirm = $script:ConfirmPreference
    $script:ConfirmPreference = 'None'
    $oldWhatIf = $WhatIfPreference
    try {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        # Validate
        $list = @($IsolatedDCList)
        foreach ($dc in $list) {
            $required = @('FQDN','Domain','IsPdcRoleOwner','Online','Type')
            $missing  = $required | Where-Object { -not $dc.PSObject.Properties[$_] -or $null -eq $dc.$_ -or ($dc.$_.ToString() -eq '') }
            if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
        }

        # Domain order: Forest Root -> Child Domain -> Tree Root
        $sorted = $list | Sort-Object {
            switch ($_.Type) { 'Forest Root' {1}; 'Child Domain' {2}; 'Tree Root' {3}; default {4} }
        }
        $domainGroups = @($sorted | Group-Object Domain)
        if (-not $domainGroups -or @($domainGroups).Count -eq 0) {
            Write-IdentIRLog -Message "No eligible domains to process." -TypeName 'Warning' -ForegroundColor Yellow
            return
        }

        $doExec = [bool]$Execute
        $WhatIfPreference = -not $doExec  # drive native "What if:" lines inside this function
        Write-IdentIRLog -Message ("Starting krbtgt password resets across {0} domain(s) (WhatIf={1})" -f @($domainGroups).Count, $WhatIfPreference) -TypeName 'Info' -ForegroundColor Cyan

        foreach ($grp in $domainGroups) {
            $domainName = $grp.Name

            # Online DCs; skip RODCs if flagged
            $domainDcs = @($grp.Group | Where-Object { $_.Online })
            if ($domainDcs -and $domainDcs[0].PSObject.Properties['IsRODC']) {
                $domainDcs = @($domainDcs | Where-Object { -not $_.IsRODC })
            }
            if (-not $domainDcs -or @($domainDcs).Count -eq 0) {
                Write-IdentIRLog -Message "No online writable DCs for $domainName. Skipping." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # Prefer PDC within domain
            $orderedDcs = @()
            $orderedDcs += @($domainDcs | Where-Object { $_.IsPdcRoleOwner })
            $orderedDcs += @($domainDcs | Where-Object { -not $_.IsPdcRoleOwner })
            $bindServer = $orderedDcs[0].FQDN

            Write-IdentIRLog -Message "Starting krbtgt password resets for domain $domainName ($(@($orderedDcs).Count) online DCs)" -TypeName 'Info' -ForegroundColor Cyan

            # Resolve krbtgt DN via RootDSE
            $defaultNC = $null
            try {
                $rootDSE   = [ADSI]"LDAP://$bindServer/RootDSE"
                $defaultNC = $rootDSE.defaultNamingContext
            } catch {
                Write-IdentIRLog -Message "Unable to read RootDSE on ${bindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                continue
            }
            if (-not $defaultNC) {
                Write-IdentIRLog -Message "defaultNamingContext missing on $bindServer. Skipping $domainName." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # Find krbtgt
            $krbDn = $null
            try {
                $sr  = New-Object System.DirectoryServices.DirectorySearcher
                $sr.Filter      = '(&(objectClass=user)(sAMAccountName=krbtgt))'
                $sr.PageSize    = 1
                $sr.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $sr.SearchRoot  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$bindServer/$defaultNC")
                $res = $sr.FindOne()
                if ($res) { $krbDn = $res.Properties['distinguishedName'][0] }
            } catch {
                Write-IdentIRLog -Message "krbtgt search failed on ${bindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                continue
            }
            if (-not $krbDn) {
                Write-IdentIRLog -Message "krbtgt account not found in $domainName on $bindServer." -TypeName 'Error' -ForegroundColor Red
                continue
            }
            $krbObj = [ADSI]"LDAP://$bindServer/$krbDn"

            # Two cycles; one retry per cycle. ShouldProcess prints native WhatIf lines.
            $okAll = $true
            for ($cycle = 1; $cycle -le 2; $cycle++) {
                $action = "Reset krbtgt password (cycle $cycle/2)"
                $target = "$domainName via $bindServer"

                if ($PSCmdlet.ShouldProcess($target, $action)) {

                    # When actually executing (no WhatIf), emit a mirror line for parity with native WhatIf output.
                    if (-not $WhatIfPreference) {
                        Write-IdentIRLog -Message ("Performing the operation ""{0}"" on target ""{1}""." -f $action, $target) -TypeName 'Info' -ForegroundColor White
                    } else {
                        # In WhatIf mode the native "What if:" line is already written by ShouldProcess
                        continue
                    }

                    $ok = $false
                    for ($attempt = 1; $attempt -le 2; $attempt++) {
                        try {
                            # Generate password and normalize to [string]
                            $pw = New-Password -Length $Length
                            if ($pw -is [System.Security.SecureString]) {
                                $b  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
                                $pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
                                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
                            } elseif ($pw -is [PSCustomObject] -and $pw.PSObject.Properties['Password']) {
                                $pw = $pw.Password
                            } elseif ($null -eq $pw -or $pw -isnot [string]) {
                                throw "Password generator returned invalid value."
                            }

                            $krbObj.SetPassword($pw)
                            $krbObj.SetInfo()
                            $ok = $true
                            break
                        } catch {
                            if ($attempt -eq 2) {
                                Write-IdentIRLog -Message "krbtgt reset failed (cycle $cycle) on ${bindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            } else {
                                Start-Sleep -Milliseconds 400
                            }
                        }
                    }

                    if (-not $ok) { $okAll = $false; break }
                    if ($cycle -eq 1) { Start-Sleep -Seconds 5 }
                }
            }

            if ($okAll) {
                if ($WhatIfPreference) {
                    Write-IdentIRLog -Message "[WhatIf] Would mark password reset completed for $bindServer" -TypeName 'Info' -ForegroundColor Green
                } else {
                    Write-IdentIRLog -Message "Password reset completed for $bindServer" -TypeName 'Normal' -ForegroundColor Green
                }
            }

            Write-IdentIRLog -Message "Completed domain $domainName" -TypeName 'Info' -ForegroundColor White
        }
    }
    catch {
        Write-IdentIRLog -Message "Set-KrbtgtPassword error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
    }
    finally {
        $script:ConfirmPreference = $oldConfirm
        $WhatIfPreference = $oldWhatIf
    }
}
