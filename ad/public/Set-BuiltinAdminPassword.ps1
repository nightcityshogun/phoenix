<#
.SYNOPSIS
Resets the built-in Administrator (RID 500) password per domain using an isolated DC inventory.

.DESCRIPTION
Set-BuiltinAdminPassword validates each domain’s writable ONLINE DCs (PDC preferred), binds via ADSI to the RID 500 account,
and performs a two-cycle password set to satisfy history/policy. Skips a domain if the current logon SID equals that domain’s
RID 500 SID. Runs in WhatIf unless -Execute is supplied.

.PARAMETER IsolatedDCList
Inventory of DC objects (FQDN, Domain, DefaultNamingContext, ConfigurationNamingContext, DomainSid, IsPdcRoleOwner, Type, Online, ForestRootFQDN).

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.PARAMETER Length
Generated password length (default 24).

.EXAMPLE
# Simulate across all domains
Set-BuiltinAdminPassword -IsolatedDCList $dcs

.EXAMPLE
# Apply with 28-char passwords
Set-BuiltinAdminPassword -IsolatedDCList $dcs -Execute -Length 28

.OUTPUTS
[hashtable] when -Execute is used: @{ '<domainFQDN>' = '<last-set-password>'; ... }.
$null in WhatIf or if no resets occur. Progress and results are logged via Write-IdentIRLog.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: ADSI, .NET DirectoryServices; Domain/Enterprise Admin privileges recommended.
Behavior: Prefers PDC; excludes RODCs; verifies RootDSE sync; restores ConfirmPreference on exit.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>

function Set-BuiltinAdminPassword {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]] $IsolatedDCList,
        [Parameter(Mandatory = $false)]
        [switch]$Execute,
        [int] $Length = 24
    )

    if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
        Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
        return $null
    }

    $oldConfirm = $script:ConfirmPreference
    $script:ConfirmPreference = 'None'

    try {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $IsolatedDCList = @($IsolatedDCList)

        $forestRootFqdn = ($IsolatedDCList | Where-Object { $_.ForestRootFQDN } | Select-Object -First 1).ForestRootFQDN
        if (-not $forestRootFqdn) {
            try { $forestRootFqdn = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().RootDomain.Name } catch {}
        }

        foreach ($dc in $IsolatedDCList) {
            if (-not $dc.Type) {
                if ($forestRootFqdn -and ($dc.Domain -ieq $forestRootFqdn)) {
                    $dc.Type = 'Forest Root'
                } elseif ($forestRootFqdn -and ($dc.Domain -like "*.$forestRootFqdn")) {
                    $dc.Type = 'Child Domain'
                } else {
                    $dc.Type = 'Tree Root'
                }
            }
        }

        foreach ($dc in $IsolatedDCList) {
            $required = @(
                'FQDN','Domain','DefaultNamingContext','ConfigurationNamingContext',
                'IsPdcRoleOwner','ForestRootFQDN','DomainSid','Type'
            )
            $missing = $required | Where-Object { -not $dc.PSObject.Properties[$_] -or $null -eq $dc.$_ -or ($dc.$_.ToString() -eq '') }
            if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
        }

        $domainGroups = @()
        foreach ($grp in ($IsolatedDCList | Group-Object Domain)) {
            $domainName = $grp.Name
            $domainType = ($grp.Group | Select-Object -First 1).Type
            $writableOnline = @($grp.Group | Where-Object { $_.Online -and -not $_.IsRODC })
            if (-not $writableOnline) {
                Write-IdentIRLog -Message "No online writable DCs for domain '$domainName'. Skipping." -TypeName 'Error' -ForegroundColor Red
                continue
            }
            $orderedInDomain = @(
                $writableOnline | Where-Object { $_.IsPdcRoleOwner }
                $writableOnline | Where-Object { -not $_.IsPdcRoleOwner }
            )
            $domainGroups += [PSCustomObject]@{
                Domain = $domainName
                Type   = $domainType
                DCs    = $orderedInDomain
            }
        }

        if (-not $domainGroups) {
            Write-IdentIRLog -Message "No eligible domains to process." -TypeName 'Warning' -ForegroundColor Yellow
            return $null
        }

        $isWhatIf = [bool]$WhatIfPreference
        $results = @{} # DomainName -> last password set (string)
        Write-IdentIRLog -Message ("Starting Built-in Administrator (RID 500) password resets ({0} domain(s), WhatIf={1})" -f $domainGroups.Count, $isWhatIf) -TypeName 'Info' -ForegroundColor Cyan

        # Determine the current logon SID once (DOMAIN\User -> SID)
        $currentUserSid = $null
        try { $currentUserSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value } catch {}

        foreach ($dg in $domainGroups) {
            $domainName = $dg.Domain
            $typeName   = $dg.Type
            $target     = $dg.DCs | Select-Object -First 1
            $targetFqdn = $target.FQDN

            Write-IdentIRLog -Message "[$typeName] Domain '$domainName' → target DC: $targetFqdn" -TypeName 'Info' -ForegroundColor Green

            try {
                $rootDSE = [ADSI]"LDAP://$targetFqdn/RootDSE"
                if (-not $rootDSE.isSynchronized) {
                    Write-IdentIRLog -Message "$targetFqdn not synchronized. Skipping domain '$domainName'." -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }
            } catch {
                Write-IdentIRLog -Message "Cannot bind RootDSE on ${targetFqdn}: $($_.Exception.Message). Skipping '$domainName'." -TypeName 'Warning' -ForegroundColor Yellow
                continue
            }

            $adminEntry = $null
            try {
                if (-not (Get-Command -Name Get-BuiltinAdmin -ErrorAction SilentlyContinue)) {
                    Write-IdentIRLog -Message "Get-BuiltinAdmin not available. Skipping '$domainName'." -TypeName 'Error' -ForegroundColor Red
                    continue
                }
                $adminEntry = Get-BuiltinAdmin -TargetDns $targetFqdn -DomSid $target.DomainSid
            } catch {
                Write-IdentIRLog -Message "Get-BuiltinAdmin failed in '$domainName': $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                continue
            }

            if (-not $adminEntry) {
                Write-IdentIRLog -Message "Built-in Administrator (RID 500) not found in '$domainName'." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # --- NEW: Exclude if current logon user IS the built-in admin for this domain ---
            $adminSid = $null
            try {
                $sidProp = $adminEntry.Properties['objectSid']
                if ($sidProp -and $sidProp.Count -gt 0) {
                    $adminSid = (New-Object System.Security.Principal.SecurityIdentifier($sidProp[0], 0)).Value
                }
            } catch {}
            if ($currentUserSid -and $adminSid -and ($currentUserSid -eq $adminSid)) {
                Write-IdentIRLog -Message "Skipping '$domainName' because the current logged-on user is the domain's built-in Administrator (RID 500)." -TypeName 'Warning' -ForegroundColor Yellow
                try { $adminEntry.psbase.Close() } catch {}
                continue
            }
            # ------------------------------------------------------------------------------

            $domainSucceeded = $true

            for ($cycle = 1; $cycle -le 2; $cycle++) {
                if ($PSCmdlet.ShouldProcess(("Domain {0} via {1}" -f $domainName,$targetFqdn),
                                            ("Reset RID 500 password (cycle {0}/2)" -f $cycle))) {

                    $plain = $null
                    try {
                        $plain = New-Password -Length $Length
                        if ($plain -is [System.Security.SecureString]) {
                            $b = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($plain)
                            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
                            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
                        } elseif ($plain -is [PSCustomObject] -and $plain.PSObject.Properties['Password']) {
                            $plain = $plain.Password
                        }
                        if (-not $plain -or $plain.GetType().Name -ne 'String') {
                            throw "Password generator returned invalid value."
                        }
                    } catch {
                        Write-IdentIRLog -Message "Password generation failed for '$domainName': $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        $domainSucceeded = $false
                        break
                    }

                    if ($isWhatIf) {
                        Write-IdentIRLog -Message "Would reset built-in admin in '$domainName' on $targetFqdn (cycle $cycle)." -TypeName 'Info' -ForegroundColor Green
                    } else {
                        $ok = $false
                        for ($attempt = 1; $attempt -le 2; $attempt++) {
                            try {
                                # ADSI-only password set
                                $adminEntry.psbase.Invoke('SetPassword', $plain)
                                $ok = $true
                                break
                            } catch {
                                if ($attempt -eq 2) {
                                    Write-IdentIRLog -Message ("Password reset failed for '{0}' on {1} (cycle {2}): {3}" -f $domainName, $targetFqdn, $cycle, $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
                                } else {
                                    Start-Sleep -Milliseconds 400
                                }
                            }
                        }
                        if (-not $ok) { $domainSucceeded = $false; break }
                        if ($cycle -eq 1) { Start-Sleep -Seconds 5 }
                        $results[$domainName] = $plain
                    }
                }
            }

            if ($domainSucceeded) {
                Write-IdentIRLog -Message "Built-in admin password reset completed for '$domainName' via $targetFqdn." -TypeName 'Info' -ForegroundColor Green
            }

            try { $adminEntry.psbase.Close() } catch {}
        }

        if ($isWhatIf -or $results.Count -eq 0) {
            if ($isWhatIf) {
                Write-IdentIRLog -Message "Simulation complete: no passwords written (WhatIf)." -TypeName 'Info' -ForegroundColor White
            } else {
                Write-IdentIRLog -Message "No built-in admin passwords were reset." -TypeName 'Error' -ForegroundColor Red
            }
            return $null
        }

        Write-IdentIRLog -Message "Built-in admin password reset completed for $($results.Count) domain(s)." -TypeName 'Info' -ForegroundColor White
        return $results
    }
    catch {
        Write-IdentIRLog -Message "Unexpected error in Set-BuiltinAdminPassword: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        return $null
    }
    finally {
        $script:ConfirmPreference = $oldConfirm
    }
}
