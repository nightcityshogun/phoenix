<#
.SYNOPSIS
Resets DC machine account passwords (nltest /sc_change_pwd) per domain with PDC-first ordering.

.DESCRIPTION
Set-DcAccountPassword validates ONLINE writable DCs (skips RODCs), opens a CIM session (DCOM then WSMan),
runs two nltest password-change cycles per DC, waits briefly, then recreates the CIM session and restarts
Netlogon to pick up the new secret. Runs in WhatIf unless -Execute is supplied.

.PARAMETER IsolatedDCList
DC inventory objects with at least: FQDN, Domain, Type, Online, IsPdcRoleOwner.

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.EXAMPLE
# Simulate across all domains
Set-DcAccountPassword -IsolatedDCList $dcs

.EXAMPLE
# Apply changes
Set-DcAccountPassword -IsolatedDCList $dcs -Execute

.OUTPUTS
None on success (writes progress via Write-IdentIRLog). Errors/warnings are logged.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: CIM (DCOM/WSMan), nltest.exe; Domain/Enterprise Admin privileges recommended.
Behavior: Orders Forest Root → Child → Tree; prefers PDC; restarts Netlogon after reset; restores WhatIf/Confirm on exit.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>

function Set-DcAccountPassword {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]$IsolatedDCList,
        [switch]$Execute
    )

    begin {
        if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
            Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
            return
        }

        $oldConfirm = $ConfirmPreference
        $ConfirmPreference = 'None'
        $oldWhatIfPreference = $WhatIfPreference
        $cimSessions = @{}
        $sessionOptionDcom = New-CimSessionOption -Protocol Dcom
        $sessionOptionWsman = New-CimSessionOption -Protocol WsMan

        try {
            $ErrorActionPreference = 'Stop'
            Set-StrictMode -Version Latest

            # Normalize to array
            $list = @($IsolatedDCList)
            foreach ($dc in $list) {
                $required = @('FQDN', 'Domain', 'IsPdcRoleOwner', 'Online', 'Type')
                $missing = $required | Where-Object { -not $dc.PSObject.Properties[$_] -or $null -eq $dc.$_ -or ($dc.$_.ToString() -eq '') }
                if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
            }

            # Order: Forest Root -> Child Domain -> Tree Root
            $sorted = $list | Sort-Object {
                switch ($_.Type) { 'Forest Root' {1}; 'Child Domain' {2}; 'Tree Root' {3}; default {4} }
            }

            # Group by domain and force array
            $domainGroups = @($sorted | Group-Object Domain)
            if (-not $domainGroups -or @($domainGroups).Count -eq 0) {
                Write-IdentIRLog -Message "No eligible domains to process." -TypeName 'Warning' -ForegroundColor Yellow
                return
            }

            $doExec = [bool]$Execute
            $WhatIfPreference = -not $doExec
            Write-IdentIRLog -Message ("Starting DC machine-account password resets across {0} domain(s) (WhatIf={1})" -f @($domainGroups).Count, $WhatIfPreference) -TypeName 'Info' -ForegroundColor Cyan
        } catch {
            Write-IdentIRLog -Message "Initialization error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            return
        }
    }

    process {
        foreach ($grp in $domainGroups) {
            $domainName = $grp.Name

            # Skip RODCs if property exists and is $true
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

            Write-IdentIRLog -Message "Starting DC password resets for domain $domainName ($(@($orderedDcs).Count) online DCs)" -TypeName 'Info' -ForegroundColor Cyan

            foreach ($dc in $orderedDcs) {
                $dcFqdn = $dc.FQDN
                if (-not $dcFqdn) { continue }

                # Create CIM session if not already created, try DCOM first, then WSMan
                if (-not $cimSessions.ContainsKey($dcFqdn)) {
                    if ($PSCmdlet.ShouldProcess($dcFqdn, 'Open CIM session')) {
                        if ($WhatIfPreference) { continue }
                        $cimSession = $null
                        foreach ($protocol in @('DCOM', 'WSMan')) {
                            try {
                                $sessionOption = if ($protocol -eq 'DCOM') { $sessionOptionDcom } else { $sessionOptionWsman }
                                $cimSession = New-CimSession -ComputerName $dcFqdn -SessionOption $sessionOption -ErrorAction Stop
                                Write-IdentIRLog -Message "CIM session opened to ${dcFqdn} using $protocol." -TypeName 'Info' -ForegroundColor Gray
                                $cimSessions[$dcFqdn] = $cimSession
                                break
                            } catch {
                                Write-IdentIRLog -Message "CIM session failed for ${dcFqdn} using ${protocol}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                                if ($protocol -eq 'WSMan') {
                                    Write-IdentIRLog -Message "Failed to establish CIM session for ${dcFqdn} with both DCOM and WSMan." -TypeName 'Error' -ForegroundColor Red
                                    continue
                                }
                            }
                        }
                        if (-not $cimSessions.ContainsKey($dcFqdn)) { continue }
                    }
                }

                # Verify DC connectivity before proceeding
                if (-not (Test-Connection -ComputerName $dcFqdn -Count 1 -Quiet)) {
                    Write-IdentIRLog -Message "DC $dcFqdn is not reachable via ping." -TypeName 'Error' -ForegroundColor Red
                    continue
                }

                $okAll = $true

                # Two cycles per DC, one retry per cycle
                for ($cycle = 1; $cycle -le 2; $cycle++) {
                    if ($PSCmdlet.ShouldProcess($dcFqdn, "Reset DC machine-account password (cycle $cycle/2) in $domainName")) {
                        if ($WhatIfPreference) {
                            Write-IdentIRLog -Message "[WhatIf] Would run: nltest /server:$dcFqdn /sc_change_pwd:$domainName" -TypeName 'Info' -ForegroundColor Green
                            continue
                        }

                        $ok = $false
                        for ($attempt = 1; $attempt -le 2; $attempt++) {
                            try {
                                $cimParams = @{
                                    ClassName = 'Win32_Process'
                                    MethodName = 'Create'
                                    Arguments = @{ CommandLine = "C:\Windows\System32\nltest.exe /server:$dcFqdn /sc_change_pwd:$domainName" }
                                    CimSession = $cimSessions[$dcFqdn]
                                }
                                $result = Invoke-CimMethod @cimParams
                                if ($result.ReturnValue -eq 0) {
                                    $ok = $true
                                    Write-IdentIRLog -Message "nltest completed successfully on $dcFqdn (cycle $cycle)." -TypeName 'Info' -ForegroundColor Green
                                    break
                                } else {
                                    if ($attempt -eq 2) {
                                        Write-IdentIRLog -Message "nltest failed on $dcFqdn (cycle $cycle, ReturnValue=$($result.ReturnValue))." -TypeName 'Error' -ForegroundColor Red
                                    } else {
                                        Start-Sleep -Milliseconds 400
                                    }
                                }
                            } catch {
                                if ($attempt -eq 2) {
                                    Write-IdentIRLog -Message "Password reset failed for $dcFqdn (cycle $cycle): $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                                } else {
                                    Start-Sleep -Milliseconds 400
                                }
                            }
                        }

                        if (-not $ok) { $okAll = $false; break }
                        if ($cycle -eq 1 -and -not $WhatIfPreference) { Start-Sleep -Seconds 5 }
                    }
                }

                if ($okAll) {
                    if ($WhatIfPreference) {
                        Write-IdentIRLog -Message "[WhatIf] Would mark password reset completed for $dcFqdn and restart Netlogon" -TypeName 'Info' -ForegroundColor Green
                    } else {
                        Write-IdentIRLog -Message "Password reset completed for $dcFqdn" -TypeName 'Info' -ForegroundColor Green
                        
                        # CRITICAL FIX: Wait for password replication and recreate CIM session
                        Write-IdentIRLog -Message "Waiting 10 seconds for password replication on $dcFqdn..." -TypeName 'Info' -ForegroundColor Gray
                        Start-Sleep -Seconds 10
                        
                        # Close old session and recreate with new credentials
                        $oldProtocol = $cimSessions[$dcFqdn].Protocol
                        Remove-CimSession -CimSession $cimSessions[$dcFqdn] -ErrorAction SilentlyContinue
                        Write-IdentIRLog -Message "Recreating CIM session to $dcFqdn after password change..." -TypeName 'Info' -ForegroundColor Gray
                        
                        $reconnected = $false
                        foreach ($protocol in @($oldProtocol, 'DCOM', 'WSMan')) {
                            try {
                                $sessionOption = if ($protocol -eq 'DCOM') { $sessionOptionDcom } else { $sessionOptionWsman }
                                $cimSessions[$dcFqdn] = New-CimSession -ComputerName $dcFqdn -SessionOption $sessionOption -ErrorAction Stop
                                Write-IdentIRLog -Message "CIM session recreated to $dcFqdn using $protocol." -TypeName 'Info' -ForegroundColor Gray
                                $reconnected = $true
                                break
                            } catch {
                                Write-IdentIRLog -Message "CIM session recreation failed using ${protocol}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                            }
                        }
                        
                        if (-not $reconnected) {
                            Write-IdentIRLog -Message "Failed to recreate CIM session to $dcFqdn. Skipping Netlogon restart." -TypeName 'Error' -ForegroundColor Red
                            continue
                        }
                        
                        try {
                            if ($PSCmdlet.ShouldProcess($dcFqdn, 'Restart Netlogon service')) {
                                Write-IdentIRLog -Message "Restarting Netlogon on $dcFqdn..." -TypeName 'Info' -ForegroundColor White
                                
                                # Get fresh service instance with new session
                                $cimParams = @{
                                    CimSession = $cimSessions[$dcFqdn]
                                    ClassName = 'Win32_Service'
                                    Filter = "Name='Netlogon'"
                                }
                                $svc = Get-CimInstance @cimParams -ErrorAction Stop
                                
                                if ($svc.State -eq 'Running') {
                                    $stopResult = $svc | Invoke-CimMethod -MethodName 'StopService' -ErrorAction Stop
                                    if ($stopResult.ReturnValue -eq 0) {
                                        Write-IdentIRLog -Message "Stopping Netlogon on $dcFqdn..." -TypeName 'Info' -ForegroundColor Gray
                                        $deadline = (Get-Date).AddSeconds(20)
                                        $stopped = $false
                                        while ((Get-Date) -lt $deadline) {
                                            $svc = Get-CimInstance @cimParams -ErrorAction Stop
                                            if ($svc.State -eq 'Stopped') {
                                                $stopped = $true
                                                break
                                            }
                                            Start-Sleep -Milliseconds 200
                                        }
                                        if (-not $stopped) {
                                            Write-IdentIRLog -Message "Netlogon stop failed on $dcFqdn (timeout)." -TypeName 'Error' -ForegroundColor Red
                                            continue
                                        }
                                        Write-IdentIRLog -Message "Netlogon stopped on $dcFqdn." -TypeName 'Info' -ForegroundColor Gray
                                    } else {
                                        Write-IdentIRLog -Message "Netlogon stop failed on $dcFqdn (ReturnValue=$($stopResult.ReturnValue))." -TypeName 'Error' -ForegroundColor Red
                                        continue
                                    }
                                }
                                
                                Write-IdentIRLog -Message "Starting Netlogon on $dcFqdn..." -TypeName 'Info' -ForegroundColor Gray
                                
                                # Get fresh service instance before starting
                                $svc = Get-CimInstance @cimParams -ErrorAction Stop
                                $startResult = $svc | Invoke-CimMethod -MethodName 'StartService' -ErrorAction Stop
                                
                                if ($startResult.ReturnValue -eq 0) {
                                    $deadline = (Get-Date).AddSeconds(20)
                                    $started = $false
                                    while ((Get-Date) -lt $deadline) {
                                        $svc = Get-CimInstance @cimParams -ErrorAction Stop
                                        if ($svc.State -eq 'Running') {
                                            $started = $true
                                            break
                                        }
                                        Start-Sleep -Milliseconds 200
                                    }
                                    if ($started) {
                                        Write-IdentIRLog -Message "Netlogon restarted successfully on $dcFqdn." -TypeName 'Info' -ForegroundColor Green
                                    } else {
                                        Write-IdentIRLog -Message "Netlogon start timeout on $dcFqdn." -TypeName 'Error' -ForegroundColor Red
                                    }
                                } else {
                                    Write-IdentIRLog -Message "Netlogon start failed on $dcFqdn (ReturnValue=$($startResult.ReturnValue))." -TypeName 'Error' -ForegroundColor Red
                                }
                            }
                        } catch {
                            Write-IdentIRLog -Message "Netlogon restart error on ${dcFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                }
            }

            Write-IdentIRLog -Message "Completed domain $domainName" -TypeName 'Info' -ForegroundColor White
        }
    }

    end {
        try {
            if ($WhatIfPreference) {
                Write-IdentIRLog -Message "DC account password reset simulation complete (WhatIf=True)." -TypeName 'Info' -ForegroundColor White
            } elseif ($cimSessions.Count -eq 0) {
                Write-IdentIRLog -Message "No DC account passwords were reset." -TypeName 'Error' -ForegroundColor Red
            } else {
                Write-IdentIRLog -Message "DC account password reset completed for $($cimSessions.Count) DC(s)." -TypeName 'Info' -ForegroundColor White
            }
        } catch {
            Write-IdentIRLog -Message "Set-DcAccountPassword error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        } finally {
            foreach ($sess in $cimSessions.Values) {
                Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue
            }
            $ConfirmPreference = $oldConfirm
            $WhatIfPreference = $oldWhatIfPreference
        }
    }
}
