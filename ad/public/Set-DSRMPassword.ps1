<#
.SYNOPSIS
Resets DSRM (Directory Services Restore Mode) local admin passwords on DCs, PDC-first per domain.

.DESCRIPTION
Set-DSRMPassword validates ONLINE writable DCs (skips RODCs), orders Forest Root → Child → Tree Root,
opens CIM (DCOM) sessions, generates a strong password, and drives ntdsutil (stdin piped) to set the
DSRM password on each DC. Runs in WhatIf unless -Execute is supplied. Stores results as FQDN→password
in-memory (return value) — handle securely.

.PARAMETER IsolatedDCList
DC inventory objects with at least: FQDN, Domain, Type, Online, IsPdcRoleOwner.

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.PARAMETER Length
Password length for generator (default 24).

.EXAMPLE
# Simulate across all domains
Set-DSRMPassword -IsolatedDCList $dcs

.EXAMPLE
# Apply and return new passwords (protect the output!)
$secrets = Set-DSRMPassword -IsolatedDCList $dcs -Execute

.OUTPUTS
[hashtable] when -Execute succeeds (keys = DC FQDN, values = plaintext passwords); $null on WhatIf or none changed.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: ntdsutil.exe, CIM (DCOM), Domain/Enterprise Admin privileges; ADSI RootDSE health check.
Behavior: Orders Forest Root → Child → Tree; prefers PDC; escapes quotes in passwords; restores WhatIf/Confirm; disposes CIM sessions.
Security: The function returns plaintext passwords — immediately secure/rotate/erase as per policy.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>

function Set-DSRMPassword {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]$IsolatedDCList,
        [switch]$Execute,
        [int]$Length = 24
    )

    begin {
        if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
            Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
            return $null
        }

        $oldConfirm = $ConfirmPreference
        $ConfirmPreference = 'None'
        $oldWhatIfPreference = $WhatIfPreference
        $results = @{}
        $cimSessions = @{}
        $sessionOption = New-CimSessionOption -Protocol Dcom

        try {
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'

            # Normalize and validate IsolatedDCList
            $list = @($IsolatedDCList)
            foreach ($dc in $list) {
                $required = @('FQDN', 'Domain', 'IsPdcRoleOwner', 'Online', 'Type')
                $missing = $required | Where-Object { -not $dc.PSObject.Properties[$_] -or $null -eq $dc.$_ -or ($dc.$_.ToString() -eq '') }
                if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
            }

            # Global order: Forest Root -> Child Domain -> Tree Root
            $sorted = $list | Sort-Object {
                switch ($_.Type) { 'Forest Root' {1}; 'Child Domain' {2}; 'Tree Root' {3}; default {4} }
            }

            # Group by domain
            $domainGroups = @($sorted | Group-Object Domain)
            if (-not $domainGroups -or @($domainGroups).Count -eq 0) {
                Write-IdentIRLog -Message "No eligible domains to process." -TypeName 'Warning' -ForegroundColor Yellow
                return $null
            }

            $doExec = [bool]$Execute
            $WhatIfPreference = -not $doExec
            Write-IdentIRLog -Message ("Starting DSRM password resets across {0} domain(s) (WhatIf={1})" -f @($domainGroups).Count, $WhatIfPreference) -TypeName 'Info' -ForegroundColor Cyan
        } catch {
            Write-IdentIRLog -Message "Initialization error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            return $null
        }
    }

    process {
        foreach ($grp in $domainGroups) {
            $domainName = $grp.Name

            # Online DCs (skip RODCs if property exists & true)
            $domainDcs = @($grp.Group | Where-Object { $_.Online })
            if ($domainDcs -and $domainDcs[0].PSObject.Properties['IsRODC']) {
                $domainDcs = @($domainDcs | Where-Object { -not $_.IsRODC })
            }
            if (-not $domainDcs -or @($domainDcs).Count -eq 0) {
                Write-IdentIRLog -Message "No online writable DCs for $domainName. Skipping." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # PDC first within the domain
            $orderedDcs = @()
            $orderedDcs += @($domainDcs | Where-Object { $_.IsPdcRoleOwner })
            $orderedDcs += @($domainDcs | Where-Object { -not $_.IsPdcRoleOwner })

            Write-IdentIRLog -Message "Starting DSRM password resets for domain $domainName ($(@($orderedDcs).Count) online DCs)" -TypeName 'Info' -ForegroundColor Cyan

            foreach ($dc in $orderedDcs) {
                $fqdn = $dc.FQDN
                if (-not $fqdn) { continue }

                # Create CIM session if not already created
                if (-not $cimSessions.ContainsKey($fqdn)) {
                    if ($PSCmdlet.ShouldProcess($fqdn, 'Open CIM session')) {
                        if ($WhatIfPreference) { continue }
                        try {
                            $cimSessions[$fqdn] = New-CimSession -ComputerName $fqdn -SessionOption $sessionOption -ErrorAction Stop
                            Write-IdentIRLog -Message "CIM session opened to ${fqdn}." -TypeName 'Info' -ForegroundColor Gray
                        } catch {
                            Write-IdentIRLog -Message "CIM session failed for ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            continue
                        }
                    }
                }

                # Health check via ADSI (read-only)
                try {
                    $rootDSE = [ADSI]"LDAP://$fqdn/RootDSE"
                    if (-not $rootDSE.isSynchronized) {
                        Write-IdentIRLog -Message "$fqdn not synchronized. Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                        continue
                    }
                } catch {
                    Write-IdentIRLog -Message "Cannot bind RootDSE on ${fqdn}: $($_.Exception.Message). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }

                # Generate password (normalize to [string])
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
                    Write-IdentIRLog -Message "Password generation failed for ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    continue
                }

                if ($PSCmdlet.ShouldProcess($fqdn, "Reset DSRM password")) {
                    if ($WhatIfPreference) {
                        Write-IdentIRLog -Message "[WhatIf] Would reset DSRM password on $fqdn." -TypeName 'Info' -ForegroundColor Green
                        continue
                    }

                    # Execute ntdsutil via CIM without temporary files
                    try {
                        $cimSession = $cimSessions[$fqdn]
                        # Escape quotes in the password to handle special characters
                        $escapedPassword = $plain -replace '"', '""'
                        # PowerShell command to pipe input to ntdsutil
                        $psCommand = @"
\$input = @""
set dsrm password
reset password on server $fqdn
$escapedPassword
$escapedPassword
q
q
""
\$input | C:\Windows\System32\ntdsutil.exe
"@
                        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($psCommand))
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "powershell.exe -EncodedCommand $encodedCommand" }
                            CimSession = $cimSession
                        }
                        $ntdsutilResult = Invoke-CimMethod @cimParams
                        if ($ntdsutilResult.ReturnValue -eq 0) {
                            Write-IdentIRLog -Message "DSRM password reset completed on $fqdn." -TypeName 'Info' -ForegroundColor Green
                            $results[$fqdn] = $plain
                        } else {
                            Write-IdentIRLog -Message "ntdsutil failed on $fqdn (ReturnValue=$($ntdsutilResult.ReturnValue))." -TypeName 'Error' -ForegroundColor Red
                            continue
                        }
                    } catch {
                        Write-IdentIRLog -Message "Error running ntdsutil for ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        continue
                    }
                }
            }

            Write-IdentIRLog -Message "Completed domain $domainName" -TypeName 'Info' -ForegroundColor White
        }
    }

    end {
        try {
            if ($WhatIfPreference -or $results.Count -eq 0) {
                if ($WhatIfPreference) {
                    Write-IdentIRLog -Message "DSRM password reset simulation complete (WhatIf=True)." -TypeName 'Info' -ForegroundColor White
                } else {
                    Write-IdentIRLog -Message "No DSRM passwords were reset." -TypeName 'Error' -ForegroundColor Red
                }
                return $null
            }

            Write-IdentIRLog -Message "DSRM password reset completed for $($results.Count) DC(s)." -TypeName 'Info' -ForegroundColor White
            return $results
        } catch {
            Write-IdentIRLog -Message "Set-DSRMPassword error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            return $null
        } finally {
            foreach ($sess in $cimSessions.Values) {
                Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue
            }
            $ConfirmPreference = $oldConfirm
            $WhatIfPreference = $oldWhatIfPreference
        }
    }
}
