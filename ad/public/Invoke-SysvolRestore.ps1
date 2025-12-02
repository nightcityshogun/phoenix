<#
.SYNOPSIS
Performs authoritative/non-authoritative SYSVOL restore across domains, handling DFSR or FRS paths with optional event verification.

.DESCRIPTION
Invoke-SysvolRestore orchestrates SYSVOL recovery in isolated AD forests. It orders domains (Forest Root â†’ Child â†’ Tree),
chooses the PDC as authoritative by default, and:
- DFSR: stops service, sets msDFSR-Enabled/Options (authoritative=TRUE after 4114/4602), polls AD, restarts, and resets startup.
- FRS: stops NTFRS, sets BurFlags (D4 on auth, D2 on non-auth), restarts, and resets startup.
Optionally verifies key events (e.g., DFSR 2010/4114/4602/4614/4604; FRS 13568/13553/13516). Runs in WhatIf mode unless -Execute.

.PARAMETER IsolatedDCList
Inventory of DC objects used to order domains and locate PDC/secondary nodes (expects FQDN, Domain, Name, DomainDn, NCs, Type, IsPdcRoleOwner, Online).

.PARAMETER Execute
Apply changes. If omitted, actions are simulated (WhatIf=True).

.PARAMETER Evt2010
Also wait for DFS Replication Event ID 2010 (service stopped) before DFSR steps.

.PARAMETER tStop
Seconds to wait for â€œstopâ€ events (e.g., DFSR 4114, FRS 13568). Default: 320.

.PARAMETER tAuth
Seconds to wait for authoritative initialization events (e.g., DFSR 4602, FRS 13553/13516). Default: 320.

.PARAMETER tNA
Seconds to wait for non-authoritative initialization events (e.g., DFSR 4614/4604, FRS 13516). Default: 320.

.PARAMETER SkipEventCheck
Do not wait for event IDs (useful for single-DC domains or expedited runs).

.EXAMPLE
# Simulate DFSR/FRS restore across all domains in inventory
Invoke-SysvolRestore -IsolatedDCList $dcs

.EXAMPLE
# Apply changes with DFSR Event 2010 gating and custom timeouts
Invoke-SysvolRestore -IsolatedDCList $dcs -Execute -Evt2010 -tStop 420 -tAuth 420 -tNA 420

.OUTPUTS
PSCustomObject per domain: Domain, Path ('DFSR'|'FRS'), Authoritative, Saw2010, Saw4114All, Saw4602.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: Domain Admin-level rights; CIM/DCOM access to DCs; DFSR/FRS service control.
ConfirmImpact: Low; SupportsShouldProcess.
2025 NightCityShogun. All rights reserved.
#>

<#
.SYNOPSIS
Performs authoritative/non-authoritative SYSVOL restore across domains, handling DFSR or FRS paths with optional event verification.
.DESCRIPTION
Invoke-SysvolRestore orchestrates SYSVOL recovery in isolated AD forests. It orders domains (Forest Root to Child to Tree),
chooses the PDC as authoritative by default, and:
- DFSR: stops service, sets msDFSR-Enabled/Options (authoritative=TRUE after 4114/4602), polls AD, restarts, and resets startup.
- FRS: stops NTFRS, sets BurFlags (D4 on auth, D2 on non-auth), restarts, and resets startup.
Optionally verifies key events (e.g., DFSR 2010/4114/4602/4614/4604; FRS 13568/13553/13516). Runs in WhatIf mode unless -Execute.
.PARAMETER IsolatedDCList
Inventory of DC objects used to order domains and locate PDC/secondary nodes (expects FQDN, Domain, Name, DomainDn, NCs, Type, IsPdcRoleOwner, Online).
.PARAMETER Execute
Apply changes. If omitted, actions are simulated (WhatIf=True).
.PARAMETER Evt2010
Also wait for DFS Replication Event ID 2010 (service stopped) before DFSR steps.
.PARAMETER tStop
Seconds to wait for "stop" events (e.g., DFSR 4114, FRS 13568). Default: 320.
.PARAMETER tAuth
Seconds to wait for authoritative initialization events (e.g., DFSR 4602, FRS 13553/13516). Default: 320.
.PARAMETER tNA
Seconds to wait for non-authoritative initialization events (e.g., DFSR 4614/4604, FRS 13516). Default: 320.
.PARAMETER SkipEventCheck
Do not wait for event IDs (useful for single-DC domains or expedited runs).
.EXAMPLE
# Simulate DFSR/FRS restore across all domains in inventory
Invoke-SysvolRestore -IsolatedDCList $dcs
.EXAMPLE
# Apply changes with DFSR Event 2010 gating and custom timeouts
Invoke-SysvolRestore -IsolatedDCList $dcs -Execute -Evt2010 -tStop 420 -tAuth 420 -tNA 420
.OUTPUTS
PSCustomObject per domain: Domain, Path ('DFSR'|'FRS'), Authoritative, Saw2010, Saw4114All, Saw4602.
.NOTES
Author: NightCityShogun
Version: 1.0.2 - Fixed event waiting logic (Dec 2025)
Requires: Domain Admin-level rights; CIM/DCOM access to DCs; DFSR/FRS service control.
ConfirmImpact: Low; SupportsShouldProcess.
2025 NightCityShogun. All rights reserved.
#>
function Invoke-SysvolRestore {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$IsolatedDCList,
        [Parameter(Mandatory = $false)]
        [switch]$Execute,
        [switch]$Evt2010,
        [int]$tStop = 320,
        [int]$tAuth = 320,
        [int]$tNA = 320,
        [switch]$SkipEventCheck
    )
    begin {
        Add-Type -AssemblyName System.ServiceProcess
        $oldConfirmPreference = $ConfirmPreference; $ConfirmPreference = 'None'
        $oldWhatIfPreference = $WhatIfPreference
        $results = New-Object 'System.Collections.Generic.List[object]'
        $IsolatedDCList = @($IsolatedDCList)
        $forestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ForestRootFqdn = $forestInfo.RootDomain.Name
        foreach ($dc in $IsolatedDCList) {
            if (-not $dc.Type) {
                if ($dc.Domain -ieq $ForestRootFqdn) { $dc.Type = 'Forest Root' }
                elseif ($dc.Domain -like "*.$ForestRootFqdn") { $dc.Type = 'Child' }
                else { $dc.Type = 'Tree' }
            }
        }
        $sortedDcList = $IsolatedDCList | Sort-Object {
            switch ($_.Type) { 'Forest Root' {1}; 'Child' {2}; 'Tree' {3}; default {4} }
        }
        foreach ($dc in $sortedDcList) {
            $required = @(
                'FQDN','Domain','DistinguishedName','Name','DomainDn',
                'IsPdcRoleOwner','Type','DefaultNamingContext','ConfigurationNamingContext'
            )
            $missing = $required | Where-Object { -not $dc.PSObject.Properties[$_] -or $dc.$_ -eq $null }
            if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
        }
        Write-IdentIRLog -Message "Validated IsolatedDCList with $(($sortedDcList | Measure-Object).Count) entries (Forest Root to Child to Tree)." -TypeName 'Info' -ForegroundColor Green
        $domainGroups = @{}
        $domainTypeMap = @{}
        foreach ($dc in $sortedDcList) {
            if (-not $domainGroups.ContainsKey($dc.Domain)) {
                $domainGroups[$dc.Domain] = [PSCustomObject]@{
                    Domain = $dc.Domain
                    DCs = New-Object 'System.Collections.Generic.List[PSObject]'
                    Type = $dc.Type
                    DefaultNC = $dc.DefaultNamingContext
                    ConfigNC = $dc.ConfigurationNamingContext
                    Server = $dc.FQDN
                }
                $domainTypeMap[$dc.Domain] = switch ($dc.Type) { 'Forest Root' {1}; 'Child' {2}; 'Tree' {3}; default {4} }
            }
            $domainGroups[$dc.Domain].DCs.Add($dc) | Out-Null
        }
        $domainOrder = $domainGroups.Keys | Sort-Object { $domainTypeMap[$_] }
        $cimSessions = @{}
        $sessionOption = New-CimSessionOption -Protocol Dcom
        function Wait-ForReplicationEvent {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][string]$Computer,
                [Parameter(Mandatory)][int]$EventId,
                [Parameter(Mandatory)][string]$LogName,
                [int]$TimeFrame,
                [int]$MaxWait,
                [string]$Description = ''
            )
            if (-not $script:SeenEventSeq) { $script:SeenEventSeq = @{} }
            $key = "$Computer|$LogName|$EventId"
            if ($script:SeenEventSeq.ContainsKey($key)) {
                Write-IdentIRLog -Message "Already observed $EventId on $Computer; not waiting again." -TypeName 'Info' -ForegroundColor Gray
                return $true
            }
            Write-IdentIRLog -Message "Querying '$LogName' on '$Computer' for Event ID $EventId within the last $TimeFrame seconds." -TypeName 'Info' -ForegroundColor White
            $seen = $false
            $deadline = (Get-Date).AddSeconds($MaxWait)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $nextNote = 0
            $iteration = 0
            $startTime = (Get-Date).AddSeconds(-[math]::Abs($TimeFrame))
            $localShort = $env:COMPUTERNAME
            try { $localFQDN = [System.Net.Dns]::GetHostByName($localShort).HostName } catch { $localFQDN = $null }
            $isLocal = $Computer -ieq $localShort -or $Computer -ieq $localFQDN -or $Computer -eq 'localhost' -or $Computer -eq '127.0.0.1'
            while ((Get-Date) -lt $deadline -and -not $seen) {
                if ($WhatIfPreference) {
                    if ($iteration -le 1) {
                        Write-IdentIRLog -Message "No Event ID $EventId found on '$Computer' within the timeframe." -TypeName 'Info' -ForegroundColor Gray
                    }
                    if ($iteration -ge 2) {
                        $seen = $true
                        $script:SeenEventSeq[$key] = 1
                        Write-IdentIRLog -Message "Simulated: Observed $EventId on $Computer $Description." -TypeName 'Info' -ForegroundColor Cyan
                        break
                    }
                } else {
                    try {
                        $msg = $null
                        if ($LogName -eq 'DFS Replication') {
                            $msg = Get-EventLog -ComputerName $Computer -LogName $LogName -After $startTime -ErrorAction Stop |
                                   Where-Object { $_.EventID -eq $EventId } |
                                   Sort-Object Index -Descending |
                                   Select-Object -First 1
                        } else {
                            if ($isLocal) {
                                $msg = Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId; StartTime=$startTime } -ErrorAction Stop |
                                       Sort-Object RecordId -Descending |
                                       Select-Object -First 1
                            } else {
                                try {
                                    $msg = Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName=$LogName; Id=$EventId; StartTime=$startTime } -ErrorAction Stop |
                                           Sort-Object RecordId -Descending |
                                           Select-Object -First 1
                                } catch {
                                    if ($LogName -eq 'Microsoft-Windows-DFS Replication/Operational') {
                                        $msg = $null
                                    } else {
                                        $msg = Get-EventLog -ComputerName $Computer -LogName $LogName -After $startTime -ErrorAction Stop |
                                               Where-Object { $_.EventID -eq $EventId } |
                                               Sort-Object Index -Descending |
                                               Select-Object -First 1
                                    }
                                }
                            }
                        }
                        if ($msg) {
                            $seen = $true
                            $script:SeenEventSeq[$key] = 1
                            break
                        }
                    } catch {
                        if ($iteration -eq 0 -and $_.Exception.Message -notmatch 'No events were found|does not exist') {
                            Write-IdentIRLog -Message "Failed to query event log on '$Computer': $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                }
                if ($sw.Elapsed.TotalSeconds -ge $nextNote) {
                    $remain = [int][Math]::Max(0, ($deadline - (Get-Date)).TotalSeconds)
                    Write-IdentIRLog -Message "Waiting for $EventId on $Computer - elapsed $([int]$sw.Elapsed.TotalSeconds)s, approx $remain s left." -TypeName 'Info' -ForegroundColor Gray
                    $nextNote += 20
                }
                Start-Sleep -Seconds 5
                $iteration++
            }
            if ($seen -and -not $WhatIfPreference) {
                Write-IdentIRLog -Message "Observed $EventId on $Computer $Description." -TypeName 'Info' -ForegroundColor Cyan
            } elseif (-not $seen) {
                Write-IdentIRLog -Message "No $EventId on $Computer within timeout (continuing)." -TypeName 'Warning' -ForegroundColor Yellow
            }
            return $seen
        }
    }
    process { }
    end {
        $WhatIfPreference = -not [bool]$Execute
        Write-IdentIRLog -Message "Starting SYSVOL authoritative restore (isolated forest recovery). (WhatIf=$WhatIfPreference)" -TypeName 'Info' -ForegroundColor White -PrependNewLine
        try {
            foreach ($domainName in $domainOrder) {
                $dg = $domainGroups[$domainName]
                $dcs = @($dg.DCs)
                Write-IdentIRLog -Message "Processing $($dg.Type) Domain: $domainName" -TypeName 'Info' -ForegroundColor Cyan
                $auth = $dcs | Where-Object { $_.IsPdcRoleOwner } | Select-Object -First 1
                if (-not $auth) { $auth = $dcs | Select-Object -First 1; Write-IdentIRLog -Message "Authoritative DC defaulted to $($auth.FQDN) (no PDC flag provided)." -TypeName 'Warning' -ForegroundColor Yellow }
                else { Write-IdentIRLog -Message "Authoritative DC (PDC) is $($auth.FQDN)." -TypeName 'Info' -ForegroundColor Green }
                $secondaries = $dcs | Where-Object { $_.FQDN -ne $auth.FQDN }
                $isSingleDC = $secondaries.Count -eq 0
                if ($isSingleDC) { Write-IdentIRLog -Message "Single-DC domain detected for $domainName (authoritative only; skipping replication steps)." -TypeName 'Info' -ForegroundColor Yellow }
                else { Write-IdentIRLog -Message "Secondary DC(s) detected for ${domainName}: $($secondaries.FQDN -join ', ')." -TypeName 'Info' -ForegroundColor Green }
                $dns = $auth.FQDN
                $dcName = $auth.Name
                $domainDn = $auth.DomainDn
                $dfsrLocal = "CN=DFSR-LocalSettings,CN=$dcName,OU=Domain Controllers,$domainDn"
                $isDfsr = $false
                try {
                    $null = [ADSI]("LDAP://$dns/$dfsrLocal")
                    $isDfsr = $true
                    Write-IdentIRLog -Message "DFSR subscriptions found; this domain uses DFSR for SYSVOL." -TypeName 'Info' -ForegroundColor Green
                } catch {
                    $isDfsr = $false
                    Write-IdentIRLog -Message "No DFSR subscriptions found; assuming FRS." -TypeName 'Info' -ForegroundColor White
                }
                foreach ($dc in $dcs) {
                    $node = $dc.FQDN
                    if (-not $cimSessions.ContainsKey($node)) {
                        if ($PSCmdlet.ShouldProcess($node, 'Open CIM session')) {
                            if ($WhatIfPreference) { continue }
                            try {
                                $cimSessions[$node] = New-CimSession -ComputerName $node -SessionOption $sessionOption -ErrorAction Stop
                                Write-IdentIRLog -Message "CIM session opened to ${node}." -TypeName 'Info' -ForegroundColor Gray
                            } catch {
                                Write-IdentIRLog -Message "CIM session failed for ${node}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                    }
                }
                if ($isDfsr) {
                    foreach ($dc in $dcs) {
                        $node = $dc.FQDN
                        $cimSess = $cimSessions[$node]
                        if ($PSCmdlet.ShouldProcess($node, 'Set DFSR startup to Manual and stop service')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='DFSR'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Manual' } | Out-Null
                                $svc | Invoke-CimMethod -MethodName 'StopService' | Out-Null
                                $deadline = (Get-Date).AddSeconds(90)
                                while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                                Write-IdentIRLog -Message "DFSR set to Manual and stopped on ${node}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Stop or set startup for DFSR failed on ${node}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                    }
                    # FIXED: Event 2010
                    if ($Evt2010 -and -not ($isSingleDC -and $SkipEventCheck)) {
                        $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tStop)}
                        foreach ($dc in $dcs) {
                            $null = Wait-ForReplicationEvent -Computer $dc.FQDN -EventId 2010 -LogName 'DFS Replication' -TimeFrame $tStop -MaxWait $maxWait -Description ''
                        }
                    }
                    $subDnAuth = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($auth.Name),OU=Domain Controllers,$($auth.DomainDn)"
                    if ($PSCmdlet.ShouldProcess($dns, 'Set msDFSR-Enabled=FALSE and msDFSR-Options=1 on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        try {
                            $sa = [ADSI]("LDAP://$dns/$subDnAuth")
                            $sa.Put('msDFSR-Options',1)
                            $sa.Put('msDFSR-Enabled',$false)
                            $sa.SetInfo()
                            Write-IdentIRLog -Message "Attributes set on authoritative DC ${dns}: msDFSR-Enabled=FALSE, msDFSR-Options=1." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Set attributes failed on ${dns}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    foreach ($sec in $secondaries) {
                        $secNode = $sec.FQDN
                        $subDnSec = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($sec.Name),OU=Domain Controllers,$($sec.DomainDn)"
                        if ($PSCmdlet.ShouldProcess($secNode, 'Set msDFSR-Enabled=FALSE on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            try {
                                $ss = [ADSI]("LDAP://$secNode/$subDnSec")
                                $ss.Put('msDFSR-Enabled',$false)
                                $ss.SetInfo()
                                Write-IdentIRLog -Message "Attribute set on non-authoritative DC ${secNode}: msDFSR-Enabled=FALSE." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Set attribute failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                    }
                    if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Force AD replication (repadmin /syncall)')) {
                        if ($WhatIfPreference) { continue }
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "repadmin /syncall /A /e /q" }
                            CimSession = $cimSessions[$dns]
                        }
                        try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "AD replication forced from ${dns}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "AD replication failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                    }
                    if ($PSCmdlet.ShouldProcess($dns, 'Start DFSR on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        $cimSess = $cimSessions[$dns]
                        $cimParams = @{
                            CimSession = $cimSess
                            ClassName = 'Win32_Service'
                            Filter = "Name='DFSR'"
                        }
                        try {
                            $svc = Get-CimInstance @cimParams
                            $svc | Invoke-CimMethod -MethodName 'StartService' | Out-Null
                            $deadline = (Get-Date).AddSeconds(60)
                            while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                            Write-IdentIRLog -Message "DFSR started on authoritative DC ${dns}." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Start DFSR failed on ${dns}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($dns, 'Set DFSR startup to Automatic on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        $cimSess = $cimSessions[$dns]
                        $cimParams = @{
                            CimSession = $cimSess
                            ClassName = 'Win32_Service'
                            Filter = "Name='DFSR'"
                        }
                        try {
                            $svc = Get-CimInstance @cimParams
                            $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Auto' } | Out-Null
                            Write-IdentIRLog -Message "DFSR startup set to Automatic on authoritative DC ${dns}." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Set startup failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                    }
                    if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Run DFSRDIAG POLLAD on authoritative after start')) {
                        if ($WhatIfPreference) { continue }
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "dfsrdiag pollad" }
                            CimSession = $cimSessions[$dns]
                        }
                        try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "DFSRDIAG POLLAD executed on ${dns} after start." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "DFSRDIAG POLLAD failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                    }
                    $s4114Auth = $true
                    if (-not ($isSingleDC -and $SkipEventCheck)) {
                        $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tStop)}
                        $s4114Auth = Wait-ForReplicationEvent -Computer $dns -EventId 4114 -LogName 'DFS Replication' -TimeFrame $tStop -MaxWait $maxWait -Description '(replication stopped)'
                    }
                    if ($PSCmdlet.ShouldProcess($dns, 'Set msDFSR-Enabled=TRUE on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        try {
                            $sa = [ADSI]("LDAP://$dns/$subDnAuth")
                            $sa.Put('msDFSR-Enabled',$true)
                            $sa.SetInfo()
                            Write-IdentIRLog -Message "Attribute set on authoritative DC ${dns}: msDFSR-Enabled=TRUE." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Set attribute failed on ${dns}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Force AD replication (repadmin /syncall)')) {
                        if ($WhatIfPreference) { continue }
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "repadmin /syncall /A /e /q" }
                            CimSession = $cimSessions[$dns]
                        }
                        try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "AD replication forced from ${dns}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "AD replication failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                    }
                    if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Run DFSRDIAG POLLAD on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "dfsrdiag pollad" }
                            CimSession = $cimSessions[$dns]
                        }
                        try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "DFSRDIAG POLLAD executed on ${dns}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "DFSRDIAG POLLAD failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                    }
                    $s4602 = $true
                    if (-not ($isSingleDC -and $SkipEventCheck)) {
                        $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tAuth)}
                        $s4602 = Wait-ForReplicationEvent -Computer $dns -EventId 4602 -LogName 'DFS Replication' -TimeFrame $tAuth -MaxWait $maxWait -Description '(sysvol replication initialized)'
                    } elseif ($isSingleDC) {
                        Write-IdentIRLog -Message "Single-DC domain: skipping wait for DFSR Event ID 4602 on $dns." -TypeName 'Info' -ForegroundColor Gray
                    }
                    $s4114All = $s4114Auth
                    foreach ($sec in $secondaries) {
                        $secNode = $sec.FQDN
                        $subDnSec = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=$($sec.Name),OU=Domain Controllers,$($sec.DomainDn)"
                        $cimSess = $cimSessions[$secNode]
                        if ($PSCmdlet.ShouldProcess($secNode, 'Start DFSR on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='DFSR'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'StartService' | Out-Null
                                $deadline = (Get-Date).AddSeconds(60)
                                while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                                Write-IdentIRLog -Message "DFSR started on non-authoritative DC ${secNode}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Start DFSR failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                        if ($PSCmdlet.ShouldProcess($secNode, 'Set DFSR startup to Automatic on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='DFSR'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Auto' } | Out-Null
                                Write-IdentIRLog -Message "DFSR startup set to Automatic on non-authoritative DC ${secNode}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Set startup failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                            }
                        }
                        if ($PSCmdlet.ShouldProcess($secNode, 'Run DFSRDIAG POLLAD on non-authoritative after start')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                ClassName = 'Win32_Process'
                                MethodName = 'Create'
                                Arguments = @{ CommandLine = "dfsrdiag pollad" }
                                CimSession = $cimSessions[$secNode]
                            }
                            try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "DFSRDIAG POLLAD executed on ${secNode} after start." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "DFSRDIAG POLLAD failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                        }
                        $s4114Sec = $true
                        if (-not $SkipEventCheck) {
                            $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tStop)}
                            $s4114Sec = Wait-ForReplicationEvent -Computer $secNode -EventId 4114 -LogName 'DFS Replication' -TimeFrame $tStop -MaxWait $maxWait -Description '(replication stopped)'
                            $s4114All = $s4114All -and $s4114Sec
                        }
                        if ($PSCmdlet.ShouldProcess($secNode, 'Set msDFSR-Enabled=TRUE on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            try {
                                $ss = [ADSI]("LDAP://$secNode/$subDnSec")
                                $ss.Put('msDFSR-Enabled',$true)
                                $ss.SetInfo()
                                Write-IdentIRLog -Message "Attribute set on non-authoritative DC ${secNode}: msDFSR-Enabled=TRUE." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Set attribute failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                        if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Force AD replication (repadmin /syncall)')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                ClassName = 'Win32_Process'
                                MethodName = 'Create'
                                Arguments = @{ CommandLine = "repadmin /syncall /A /e /q" }
                                CimSession = $cimSessions[$dns]
                            }
                            try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "AD replication forced from ${dns}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "AD replication failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                        }
                        if ($PSCmdlet.ShouldProcess($secNode, 'Run DFSRDIAG POLLAD on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                ClassName = 'Win32_Process'
                                MethodName = 'Create'
                                Arguments = @{ CommandLine = "dfsrdiag pollad" }
                                CimSession = $cimSessions[$secNode]
                            }
                            try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "DFSRDIAG POLLAD executed on ${secNode}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "DFSRDIAG POLLAD failed on ${secNode}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                        }
                        if (-not $SkipEventCheck) {
                            $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tNA)}
                            $null = Wait-ForReplicationEvent -Computer $secNode -EventId 4614 -LogName 'DFS Replication' -TimeFrame $tNA -MaxWait $maxWait -Description ''
                            $null = Wait-ForReplicationEvent -Computer $secNode -EventId 4604 -LogName 'DFS Replication' -TimeFrame $tNA -MaxWait $maxWait -Description ''
                        }
                    }
                    Write-IdentIRLog -Message "Share check on $dns" -TypeName 'Info' -ForegroundColor White -PrependNewLine
                    if ($WhatIfPreference) {
                        Write-IdentIRLog -Message "Simulated: Would check for SYSVOL and NETLOGON shares on ${dns}." -TypeName 'Info' -ForegroundColor Cyan
                    } else {
                        try {
                            $cimSess = $cimSessions[$dns]
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Share'
                                Filter = "Name='SYSVOL' OR Name='NETLOGON'"
                            }
                            Get-CimInstance @cimParams | Select-Object Name,Path | ForEach-Object {
                                Write-IdentIRLog -Message "$($_.Name) - $($_.Path)" -TypeName 'Info' -ForegroundColor Gray
                            }
                        } catch {
                            Write-IdentIRLog -Message "Share check failed on ${dns}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    $results.Add([pscustomobject]@{
                        Domain=$domainName; Path='DFSR'; Authoritative=$auth.FQDN
                        Saw2010=$false; Saw4114All=[bool]$s4114All; Saw4602=[bool]$s4602
                    }) | Out-Null
                } else {
                    $authFqdn = $auth.FQDN
                    foreach ($dc in $dcs) {
                        $node = $dc.FQDN
                        if (-not $cimSessions.ContainsKey($node)) {
                            if ($PSCmdlet.ShouldProcess($node, 'Open CIM session')) {
                                if ($WhatIfPreference) { continue }
                                try {
                                    $cimSessions[$node] = New-CimSession -ComputerName $node -SessionOption $sessionOption -ErrorAction Stop
                                    Write-IdentIRLog -Message "CIM session opened to ${node}." -TypeName 'Info' -ForegroundColor Gray
                                } catch {
                                    Write-IdentIRLog -Message "CIM session failed for ${node}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                                }
                            }
                        }
                    }
                    foreach ($dc in $dcs) {
                        $node = $dc.FQDN
                        $cimSess = $cimSessions[$node]
                        if ($PSCmdlet.ShouldProcess($node, 'Set NTFRS startup to Manual and stop service')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='NtFrs'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Manual' } | Out-Null
                                $svc | Invoke-CimMethod -MethodName 'StopService' | Out-Null
                                $deadline = (Get-Date).AddSeconds(90)
                                while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                                Write-IdentIRLog -Message "NTFRS set to Manual and stopped on ${node}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Stop or set startup for NTFRS failed on ${node}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                    }
                    # FIXED: FRS stop event 13568
                    if (-not ($isSingleDC -and $SkipEventCheck)) {
                        $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tStop)}
                        foreach ($dc in $dcs) {
                            $null = Wait-ForReplicationEvent -Computer $dc.FQDN -EventId 13568 -LogName 'File Replication Service' -TimeFrame $tStop -MaxWait $maxWait -Description ''
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($authFqdn, 'Set BurFlags = D4 (authoritative)')) {
                        if ($WhatIfPreference) { continue }
                        $cimSess = $cimSessions[$authFqdn]
                        try {
                            $reg = Get-CimInstance -CimSession $cimSess -Namespace root/default -ClassName StdRegProv
                            $args = @{
                                hDefKey = [uint32]0x80000002
                                sSubKeyName = "SYSTEM\CurrentControlSet\Services\NtFrs\Parameters\Backup\Restore\Process at Startup"
                                sValueName = "BurFlags"
                                uValue = [uint32]0xD4
                            }
                            $null = Invoke-CimMethod -CimInstance $reg -MethodName SetDWORDValue -Arguments $args
                            Write-IdentIRLog -Message "BurFlags set to D4 on authoritative DC ${authFqdn}." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Set D4 failed on ${authFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    foreach ($sec in $secondaries) {
                        $secFqdn = $sec.FQDN
                        $cimSess = $cimSessions[$secFqdn]
                        if ($PSCmdlet.ShouldProcess($secFqdn, 'Set BurFlags = D2 (non-authoritative)')) {
                            if ($WhatIfPreference) { continue }
                            try {
                                $reg = Get-CimInstance -CimSession $cimSess -Namespace root/default -ClassName StdRegProv
                                $args = @{
                                    hDefKey = [uint32]0x80000002
                                    sSubKeyName = "SYSTEM\CurrentControlSet\Services\NtFrs\Parameters\Backup\Restore\Process at Startup"
                                    sValueName = "BurFlags"
                                    uValue = [uint32]0xD2
                                }
                                $null = Invoke-CimMethod -CimInstance $reg -MethodName SetDWORDValue -Arguments $args
                                Write-IdentIRLog -Message "BurFlags set to D2 on non-authoritative DC ${secFqdn}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Set D2 failed on ${secFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                    }
                    if (-not $isSingleDC -and $PSCmdlet.ShouldProcess($dns, 'Force AD replication (repadmin /syncall)')) {
                        if ($WhatIfPreference) { continue }
                        $cimParams = @{
                            ClassName = 'Win32_Process'
                            MethodName = 'Create'
                            Arguments = @{ CommandLine = "repadmin /syncall /A /e /q" }
                            CimSession = $cimSessions[$dns]
                        }
                        try { Invoke-CimMethod @cimParams | Out-Null; Write-IdentIRLog -Message "AD replication forced from ${dns}." -TypeName 'Info' -ForegroundColor Green } catch { Write-IdentIRLog -Message "AD replication failed on ${dns}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow }
                    }
                    if ($PSCmdlet.ShouldProcess($authFqdn, 'Start NTFRS on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        $cimSess = $cimSessions[$authFqdn]
                        $cimParams = @{
                            CimSession = $cimSess
                            ClassName = 'Win32_Service'
                            Filter = "Name='NtFrs'"
                        }
                        try {
                            $svc = Get-CimInstance @cimParams
                            $svc | Invoke-CimMethod -MethodName 'StartService' | Out-Null
                            $deadline = (Get-Date).AddSeconds(60)
                            while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                            Write-IdentIRLog -Message "NTFRS started on authoritative DC ${authFqdn}." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Start NTFRS failed on ${authFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    if ($PSCmdlet.ShouldProcess($authFqdn, 'Set NTFRS startup to Automatic on authoritative')) {
                        if ($WhatIfPreference) { continue }
                        $cimSess = $cimSessions[$authFqdn]
                        $cimParams = @{
                            CimSession = $cimSess
                            ClassName = 'Win32_Service'
                            Filter = "Name='NtFrs'"
                        }
                        try {
                            $svc = Get-CimInstance @cimParams
                            $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Auto' } | Out-Null
                            Write-IdentIRLog -Message "NTFRS startup set to Automatic on authoritative DC ${authFqdn}." -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "Set startup failed on ${authFqdn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                    }
                    # FIXED: FRS auth initialization events
                    if (-not ($isSingleDC -and $SkipEventCheck)) {
                        $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tAuth)}
                        $null = Wait-ForReplicationEvent -Computer $authFqdn -EventId 13553 -LogName 'File Replication Service' -TimeFrame $tAuth -MaxWait $maxWait -Description ''
                        $null = Wait-ForReplicationEvent -Computer $authFqdn -EventId 13516 -LogName 'File Replication Service' -TimeFrame $tAuth -MaxWait $maxWait -Description ''
                    }
                    foreach ($sec in $secondaries) {
                        $secFqdn = $sec.FQDN
                        $cimSess = $cimSessions[$secFqdn]
                        if ($PSCmdlet.ShouldProcess($secFqdn, 'Start NTFRS on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='NtFrs'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'StartService' | Out-Null
                                $deadline = (Get-Date).AddSeconds(60)
                                while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) { $svc = Get-CimInstance @cimParams; Start-Sleep -Milliseconds 200 }
                                Write-IdentIRLog -Message "NTFRS started on non-authoritative DC ${secFqdn}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Start NTFRS failed on ${secFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                            }
                        }
                        if ($PSCmdlet.ShouldProcess($secFqdn, 'Set NTFRS startup to Automatic on non-authoritative')) {
                            if ($WhatIfPreference) { continue }
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Service'
                                Filter = "Name='NtFrs'"
                            }
                            try {
                                $svc = Get-CimInstance @cimParams
                                $svc | Invoke-CimMethod -MethodName 'ChangeStartMode' -Arguments @{ StartMode = 'Auto' } | Out-Null
                                Write-IdentIRLog -Message "NTFRS startup set to Automatic on non-authoritative DC ${secFqdn}." -TypeName 'Info' -ForegroundColor Green
                            } catch {
                                Write-IdentIRLog -Message "Set startup failed on ${secFqdn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                            }
                        }
                        # FIXED: FRS non-auth event 13516
                        if (-not $SkipEventCheck) {
                            $maxWait = if ($WhatIfPreference) {15} else {[int][Math]::Max(30, $tNA)}
                            $null = Wait-ForReplicationEvent -Computer $secFqdn -EventId 13516 -LogName 'File Replication Service' -TimeFrame $tNA -MaxWait $maxWait -Description ''
                        }
                    }
                    Write-IdentIRLog -Message "Share check on $authFqdn" -TypeName 'Info' -ForegroundColor White -PrependNewLine
                    if ($WhatIfPreference) {
                        Write-IdentIRLog -Message "Simulated: Would check for SYSVOL and NETLOGON shares on ${authFqdn}." -TypeName 'Info' -ForegroundColor Cyan
                    } else {
                        try {
                            $cimSess = $cimSessions[$authFqdn]
                            $cimParams = @{
                                CimSession = $cimSess
                                ClassName = 'Win32_Share'
                                Filter = "Name='SYSVOL' OR Name='NETLOGON'"
                            }
                            Get-CimInstance @cimParams | Select-Object Name,Path | ForEach-Object {
                                Write-IdentIRLog -Message "$($_.Name) - $($_.Path)" -TypeName 'Info' -ForegroundColor Gray
                            }
                        } catch {
                            Write-IdentIRLog -Message "Share check failed on ${authFqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                    $results.Add([pscustomobject]@{
                        Domain=$domainName; Path='FRS'; Authoritative=$authFqdn
                        Saw2010=$false; Saw4114All=$false; Saw4602=$false
                    }) | Out-Null
                }
                Write-IdentIRLog -Message "Completed SYSVOL sequence for $domainName." -TypeName 'Info' -ForegroundColor Green
            }
        } catch {
            Write-IdentIRLog -Message "SYSVOL restore error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        } finally {
            foreach ($sess in $cimSessions.Values) { Remove-CimSession -CimSession $sess -ErrorAction SilentlyContinue }
            Write-IdentIRLog -Message "SYSVOL restore complete." -TypeName 'Info' -ForegroundColor Green
            $ConfirmPreference = $oldConfirmPreference
            $WhatIfPreference = $oldWhatIfPreference
            $results
        }
    }
}
