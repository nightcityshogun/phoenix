<#
.SYNOPSIS
Recreates and rotates all gMSA accounts and KDS root keys across isolated domains.

.DESCRIPTION
Set-GMSA validates ONLINE writable DCs, orders Forest Root → Child → Tree Root, and creates a new KDS root key
(effective now or offset) strictly on the forest-root PDC. All forest KDS work is bound to that DC. Per-domain
operations are bound to the domain PDC only; if a domain PDC is not online, that domain is skipped.

It restarts kdsSvc on DCs, disables and removes existing gMSAs, then recreates them with restored attributes.
Optionally rebinds computers’ msDS-HostServiceAccount entries. Deletes old KDS root keys on the forest-root PDC
after replication. Runs in WhatIf mode unless -Execute is supplied.

.PARAMETER IsolatedDCList
DC inventory objects with at least: FQDN, Domain, DefaultNamingContext, Type, IsPdcRoleOwner, Online.

.PARAMETER CleanupTag
String tag placed in adminDescription of old gMSAs (default: 'cleanup-gmsa') and appended to their description.

.PARAMETER RebindHosts
When used, rebinds computers to recreated gMSAs.

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.PARAMETER EffectiveImmediately
Create KDS key effective immediately (default).

.PARAMETER EffectiveTimeHoursOffset
Offset in hours for new KDS key usability (default 0).

.EXAMPLE
# Simulate full gMSA rotation
Set-GMSA -IsolatedDCList $dcs

.EXAMPLE
# Apply with host rebinding
Set-GMSA -IsolatedDCList $dcs -RebindHosts -Execute

.OUTPUTS
None. Progress logged via Write-IdentIRLog.

.NOTES
Author: NightCityShogun
Version: 1.3
Requires: Add-KdsRootKey, ADSI, CIM/WMI, Domain/Enterprise Admin privileges.
Behavior: Creates new KDS root key on forest-root PDC, forces replication, restarts kdsSvc, recreates gMSAs
with server-pinned LDAP to domain PDCs, optionally rebinds hosts, deletes old forest KDS keys, verifies new key usage.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>
function Set-GMSA {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [PSObject[]]$IsolatedDCList,

        [string]$CleanupTag = 'cleanup-gmsa',
        [switch]$RebindHosts,
        [switch]$Execute,

        # KDS timing (defaults keep current behavior)
        [switch]$EffectiveImmediately = $true,
        [int]$EffectiveTimeHoursOffset = 0
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        $doExec = [bool]$Execute
        $whatIf = -not $doExec

        # --- helpers ---
        $GetDe = { param([string]$Path) [ADSI]$Path }

        $WI = {
            param([string]$Message)
            if ($whatIf) {
                Write-IdentIRLog -Message "[WHATIF] $Message" -TypeName 'Info' -ForegroundColor Green
            }
        }

        function Get-KdsRootKeys {
            param(
                [string]$BindServer,
                [scriptblock]$GetDe
            )
            $keys = New-Object System.Collections.Generic.List[psobject]
            try {
                $rootDse = & $GetDe ("LDAP://$BindServer/RootDSE")
                $cfgNC   = $rootDse.Properties['configurationNamingContext'][0]
                $kdsPath = "LDAP://$BindServer/CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$cfgNC"
                $searchRoot = & $GetDe $kdsPath

                $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
                $ds.Filter = '(objectClass=msKds-ProvRootKey)'
                $ds.PageSize = 1000
                $ds.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                $null = $ds.PropertiesToLoad.AddRange(@('distinguishedName','cn','whenCreated'))

                foreach ($r in $ds.FindAll()) {
                    $dn = $r.Properties['distinguishedname'][0]
                    $cn = $r.Properties['cn'][0]
                    $wc = if ($r.Properties['whencreated']) { [datetime]$r.Properties['whencreated'][0] } else { $null }

                    $keys.Add([pscustomobject]@{
                        DistinguishedName = $dn
                        CN                = $cn
                        WhenCreated       = $wc
                    })
                }
            } catch {
                Write-IdentIRLog -Message "KDS key query failed on ${BindServer}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
            return ,$keys
        }

        function Remove-KdsRootKeys {
            param(
                [string]$BindServer,
                [scriptblock]$GetDe,
                [psobject[]]$OldKeys
            )
            $count = 0
            if (-not $OldKeys -or $OldKeys.Count -eq 0) { return 0 }

            try {
                $rootDse = & $GetDe ("LDAP://$BindServer/RootDSE")
                $cfgNC   = $rootDse.Properties['configurationNamingContext'][0]
                $kdsPath = "LDAP://$BindServer/CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$cfgNC"
                $container = & $GetDe $kdsPath

                foreach ($key in $OldKeys) {
                    try {
                        $container.Delete("msKds-ProvRootKey", "CN=$($key.CN)")
                        $count++
                    } catch {
                        Write-IdentIRLog -Message "Failed to delete old KDS key CN=$($key.CN): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-IdentIRLog -Message "Old KDS key container access failed on ${BindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }
            return $count
        }

        function Restart-KdsService {
            param([string]$ComputerName)

            if ($whatIf) {
                & $WI ("Restart kdsSvc on $ComputerName")
                return
            }

            try {
                $c = @{
                    ClassName    = 'Win32_Service'
                    Filter       = "Name='kdsSvc'"
                    ComputerName = $ComputerName
                }

                $svc = Get-CimInstance @c
                if (-not $svc) {
                    Write-IdentIRLog -Message "kdsSvc not found on $ComputerName" -TypeName 'Warning' -ForegroundColor Yellow
                    return
                }

                $null = $svc | Invoke-CimMethod -MethodName StopService | Out-Null
                $deadline = (Get-Date).AddSeconds(60)
                while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) {
                    $svc = Get-CimInstance @c
                    Start-Sleep -Milliseconds 200
                }
                if ($svc.State -ne 'Stopped') {
                    Write-IdentIRLog -Message "kdsSvc stop timed out on $ComputerName" -TypeName 'Warning' -ForegroundColor Yellow
                }

                $null = $svc | Invoke-CimMethod -MethodName StartService | Out-Null
                $deadline = (Get-Date).AddSeconds(60)
                while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) {
                    $svc = Get-CimInstance @c
                    Start-Sleep -Milliseconds 200
                }
                if ($svc.State -ne 'Running') {
                    Write-IdentIRLog -Message "kdsSvc start timed out on $ComputerName" -TypeName 'Warning' -ForegroundColor Yellow
                }

                Write-IdentIRLog -Message "kdsSvc restarted on $ComputerName" -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "kdsSvc restart failed on ${ComputerName}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        }

        function Force-ConfigReplication {
            param(
                [string]$SourceDC,
                [string]$CfgNC
            )

            try {
                repadmin /syncall $SourceDC $CfgNC /d /e /P
                Write-IdentIRLog -Message "Config replication triggered from $SourceDC" -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "Config replication failed from ${SourceDC}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        }

        # --- validate DC list ---
        $in = @($IsolatedDCList)
        if (-not $in -or $in.Count -eq 0) {
            Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
            return
        }

        $validated = New-Object System.Collections.Generic.List[psobject]
        foreach ($dc in $in) {
            $required = @('FQDN','Domain','DefaultNamingContext','Type','IsPdcRoleOwner','Online')
            $missing = $required | Where-Object {
                -not $dc.PSObject.Properties[$_] -or
                $null -eq $dc.$_ -or
                ($dc.$_.ToString() -eq '')
            }

            if ($missing) {
                Write-IdentIRLog -Message "Invalid DC entry $($dc.FQDN): missing $($missing -join ', ')" -TypeName 'Warning' -ForegroundColor Yellow
                continue
            }
            $validated.Add($dc)
        }

        if (@($validated).Count -eq 0) {
            Write-IdentIRLog -Message "No valid DC entries after validation." -TypeName 'Error' -ForegroundColor Red
            return
        }

        # Single forest check (based on rootDomainNamingContext)
        $forestRoots = New-Object System.Collections.Generic.HashSet[string]
        foreach ($dc in $validated | Where-Object { $_.Online }) {
            try {
                $rootDse = & $GetDe ("LDAP://$($dc.FQDN)/RootDSE")
                [void]$forestRoots.Add($rootDse.Properties['rootDomainNamingContext'][0])
            } catch {
                Write-IdentIRLog -Message "Failed to read RootDSE from $($dc.FQDN): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        }

        if ($forestRoots.Count -gt 1) {
            Write-IdentIRLog -Message "Multiple forests detected. This function supports a single forest per run." -TypeName 'Error' -ForegroundColor Red
            return
        }
        if ($forestRoots.Count -eq 0) {
            Write-IdentIRLog -Message "Could not detect forest root naming context." -TypeName 'Error' -ForegroundColor Red
            return
        }

        $forestRootNc = $forestRoots | Select-Object -First 1
        $forestRootDomain = ($forestRootNc -replace '^DC=', '' -replace ',DC=', '.').ToLower()

        # Domain metadata and order: Forest Root → Child → Tree Root
        $priority = @{ 'Forest Root' = 1; 'Child Domain' = 2; 'Tree Root' = 3 }
        $groups   = $validated | Group-Object -Property Domain
        $meta     = @{}

        foreach ($g in $groups) {
            $rep = $g.Group | Select-Object -First 1
            $meta[$g.Name] = @{
                Type      = $rep.Type
                DefaultNC = $rep.DefaultNamingContext
                Domain    = $g.Name
            }
        }

        $orderedDomains = ($groups.Name) | Sort-Object {
            $t = $meta[$_].Type
            if ($priority.ContainsKey($t)) { $priority[$t] } else { 4 }
        }, $_

        Write-IdentIRLog -Message ("Domains in scope: {0} (WhatIf={1})" -f (@($orderedDomains).Count), $whatIf) -TypeName 'Info' -ForegroundColor Cyan

        # shared state
        $script:validated      = $validated
        $script:orderedDomains = $orderedDomains
        $script:meta           = $meta
        $script:GetDe          = $GetDe
        $script:whatIf         = $whatIf

        $script:DesiredUsableTime = if ([bool]$EffectiveImmediately -or ($EffectiveTimeHoursOffset -eq 0)) {
            Get-Date
        } else {
            (Get-Date).AddHours($EffectiveTimeHoursOffset)
        }

        # EffectiveTime is in the past so key is usable at DesiredUsableTime
        $script:KdsEffectiveTime = $script:DesiredUsableTime.AddHours(-10)
        $script:newKdsCn         = $null

        # --- KDS on forest-root PDC only (no fallback) ---
        $forestRootPdc = $validated |
            Where-Object { $_.Type -eq 'Forest Root' -and $_.IsPdcRoleOwner -and $_.Online } |
            Select-Object -First 1

        if (-not $forestRootPdc) {
            Write-IdentIRLog -Message "Forest root PDC for '$forestRootDomain' not found or offline. Aborting (KDS must run on forest-root PDC)." -TypeName 'Error' -ForegroundColor Red
            return
        }

        $script:kdsBindServer = $forestRootPdc.FQDN
        Write-IdentIRLog -Message "KDS anchor (forest-root PDC): $($script:kdsBindServer)" -TypeName 'Info' -ForegroundColor Cyan

        # Use forest-root PDC RootDSE for cfgNC
        $script:cfgNC = (& $GetDe ("LDAP://$($script:kdsBindServer)/RootDSE")).Properties['configurationNamingContext'][0]

        # Capture existing KDS keys (old keys)
        $script:existingKeyCount = 0
        $script:oldKeys          = @()

        $existingKeys = Get-KdsRootKeys -BindServer $script:kdsBindServer -GetDe $GetDe
        $script:existingKeyCount = $existingKeys.Count
        $script:oldKeys          = $existingKeys

        if ($script:existingKeyCount -gt 0) {
            Write-IdentIRLog -Message ("Existing KDS keys on forest-root PDC: {0}" -f $script:existingKeyCount) -TypeName 'Info' -ForegroundColor Green
        } else {
            Write-IdentIRLog -Message "No KDS root keys found on forest-root PDC (first-time creation)." -TypeName 'Info' -ForegroundColor Cyan
        }

        # --- Create new KDS root key on forest-root PDC ---
        if ($whatIf) {
            $effLabel = if ($script:DesiredUsableTime -le (Get-Date)) {
                "EffectiveImmediately"
            } else {
                "EffectiveTime=$($script:DesiredUsableTime)"
            }
            & $WI ("Create new KDS root key on $($script:kdsBindServer) ($effLabel)")
        } else {
            $creationOk = $true
            try {
                $cmd = Get-Command -Name Add-KdsRootKey -ErrorAction SilentlyContinue
                if ($cmd -and $cmd.Parameters.ContainsKey('DomainController')) {
                    Add-KdsRootKey -DomainController $script:kdsBindServer -EffectiveTime $script:KdsEffectiveTime | Out-Null
                } else {
                    $sb = { param($time) Add-KdsRootKey -EffectiveTime $time | Out-Null }
                    Invoke-Command -ComputerName $script:kdsBindServer -ScriptBlock $sb -ArgumentList $script:KdsEffectiveTime -ErrorAction Stop
                }
            } catch {
                $creationOk = $false
                Write-IdentIRLog -Message "KDS root key creation FAILED on $($script:kdsBindServer): $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }

            if (-not $creationOk) {
                Write-IdentIRLog -Message "Stopping. No gMSA changes made because KDS key creation failed." -TypeName 'Error' -ForegroundColor Red
                return
            }

            Write-IdentIRLog -Message "New KDS root key requested on $($script:kdsBindServer)" -TypeName 'Info' -ForegroundColor Green
            Force-ConfigReplication -SourceDC $script:kdsBindServer -CfgNC $script:cfgNC

            # Wait until new key is visible and capture its CN
            $keyTimeout = (Get-Date).AddSeconds(180)
            do {
                Start-Sleep -Seconds 3
                $afterKeys = Get-KdsRootKeys -BindServer $script:kdsBindServer -GetDe $GetDe
                $newKey = $afterKeys |
                    Where-Object { $_.CN -notin $script:oldKeys.CN } |
                    Sort-Object WhenCreated -Descending |
                    Select-Object -First 1

                if ($newKey) { $script:newKdsCn = $newKey.CN }
            } until ($script:newKdsCn -or (Get-Date) -gt $keyTimeout)

            if (-not $script:newKdsCn) {
                Write-IdentIRLog -Message "New KDS root key not visible after timeout. Aborting." -TypeName 'Error' -ForegroundColor Red
                return
            }

            Write-IdentIRLog -Message "New KDS root key visible on forest-root PDC: $($script:newKdsCn)" -TypeName 'Info' -ForegroundColor Green
            Restart-KdsService -ComputerName $script:kdsBindServer
        }

        # expose for end{}
        $validated      = $script:validated
        $orderedDomains = $script:orderedDomains
        $meta           = $script:meta
        $GetDe          = $script:GetDe
        $whatIf         = $script:whatIf
        $newKdsCn       = $script:newKdsCn
    }

    process { }

    end {
        foreach ($domain in $script:orderedDomains) {

            # Online DCs in this domain (ignore RODCs if flagged)
            $dcs = @($script:validated | Where-Object { $_.Domain -ieq $domain -and $_.Online })
            if ($dcs -and $dcs[0].PSObject.Properties['IsRODC']) {
                $dcs = @($dcs | Where-Object { -not $_.IsRODC })
            }
            if (-not $dcs -or $dcs.Count -eq 0) {
                Write-IdentIRLog -Message "Domain ${domain}: no online writable DCs. Skipping domain." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # Require PDC in each domain (fail safe if none)
            $anchor = $dcs | Where-Object { $_.IsPdcRoleOwner } | Select-Object -First 1
            if (-not $anchor) {
                Write-IdentIRLog -Message "Domain ${domain}: no online PDC in IsolatedDCList. Skipping domain for safety." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            $bindServer = $anchor.FQDN
            $domainDn   = $script:meta[$domain].DefaultNC
            $domainFqdn = $script:meta[$domain].Domain

            Write-IdentIRLog -Message "Domain ${domain}: using PDC $bindServer" -TypeName 'Info' -ForegroundColor Cyan

            # Restart kdssvc on domain DCs
            if ($script:whatIf) {
                foreach ($c in ($dcs | ForEach-Object { $_.FQDN } | Sort-Object -Unique)) {
                    & $WI ("Restart kdsSvc on $c")
                }
            } else {
                $targets = ($dcs | ForEach-Object { $_.FQDN } | Sort-Object -Unique)

                $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                $pool = [RunspaceFactory]::CreateRunspacePool(1, 16, $iss, $Host)
                $pool.Open()
                $rsJobs = @()

                foreach ($t in $targets) {
                    $ps = [PowerShell]::Create()
                    $ps.RunspacePool = $pool
                    $null = $ps.AddScript({
                        param($ComputerName)
                        try {
                            $c = @{
                                ClassName    = 'Win32_Service'
                                Filter       = "Name='kdsSvc'"
                                ComputerName = $ComputerName
                            }
                            $svc = Get-CimInstance @c
                            if (-not $svc) { return @{Computer=$ComputerName; Success=$false; Error='kdsSvc not found'} }

                            $null = $svc | Invoke-CimMethod -MethodName StopService
                            $deadline = (Get-Date).AddSeconds(60)
                            while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) {
                                $svc = Get-CimInstance @c
                                Start-Sleep -Milliseconds 200
                            }
                            if ($svc.State -ne 'Stopped') { return @{Computer=$ComputerName; Success=$false; Error='Stop timed out'} }

                            $null = $svc | Invoke-CimMethod -MethodName StartService
                            $deadline = (Get-Date).AddSeconds(60)
                            while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) {
                                $svc = Get-CimInstance @c
                                Start-Sleep -Milliseconds 200
                            }
                            if ($svc.State -ne 'Running') { return @{Computer=$ComputerName; Success=$false; Error='Start timed out'} }

                            return @{Computer=$ComputerName; Success=$true}
                        } catch {
                            return @{Computer=$ComputerName; Success=$false; Error=$_.Exception.Message}
                        }
                    }).AddArgument($t)

                    $rsJobs += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
                }

                foreach ($j in $rsJobs) {
                    try {
                        $r = $j.PS.EndInvoke($j.Handle)
                    } finally {
                        $j.PS.Dispose()
                    }
                    foreach ($x in $r) {
                        if ($x.Success) {
                            Write-IdentIRLog -Message "kdsSvc restarted on $($x.Computer)" -TypeName 'Info' -ForegroundColor Green
                        } else {
                            Write-IdentIRLog -Message "kdsSvc restart failed on $($x.Computer): $($x.Error)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                    }
                }

                $pool.Close()
                $pool.Dispose()
            }

            # Enumerate gMSAs in this domain
            $gmsaIndex = New-Object System.Collections.Generic.List[psobject]
            try {
                $root = & $script:GetDe ("LDAP://${bindServer}/${domainDn}")
                $ds   = New-Object System.DirectoryServices.DirectorySearcher($root)
                $ds.PageSize  = 1000
                $ds.Filter    = '(objectClass=msDS-GroupManagedServiceAccount)'
                $null = $ds.PropertiesToLoad.AddRange(@('distinguishedName','sAMAccountName'))

                foreach ($r in $ds.FindAll()) {
                    $dn = $r.Properties['distinguishedname'][0]
                    $parent = if ($dn -and $dn.Contains(',')) { $dn.Substring($dn.IndexOf(',') + 1) } else { $null }
                    $sam = if ($r.Properties['samaccountname']) { $r.Properties['samaccountname'][0] } else { $null }

                    $gmsaIndex.Add([pscustomobject]@{
                        DistinguishedName = $dn
                        ParentContainerDN = $parent
                        SamAccountName    = $sam
                    })
                }
            } catch {
                Write-IdentIRLog -Message "Domain ${domain}: gMSA discovery failed via ${bindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }

            Write-IdentIRLog -Message ("Domain ${domain}: found {0} gMSA object(s)" -f $gmsaIndex.Count) -TypeName 'Info' -ForegroundColor Green

            # Disable & tag → clear SPNs/DNS → delete → confirm → recreate
            $oldToNewMap = @{}
            $firstNewDn  = $null

            foreach ($g in $gmsaIndex) {

                $oldDn  = $g.DistinguishedName
                $parent = $g.ParentContainerDN
                $cn     = ($oldDn -split ',', 2)[0] -replace '^CN='
                $sam    = $g.SamAccountName

                # backup attributes (best-effort)
                $exp = @{
                    DisplayName                         = $null
                    Description                         = $null
                    ServicePrincipalName                = @()
                    ManagedPasswordInterval             = 30
                    AllowedToDelegateTo                 = @()
                    UserAccountControl                  = $null
                    DnsHostName                         = $null
                    GroupMSAMembership                  = $null
                    AllowedToActOnBehalfOfOtherIdentity = $null
                    SupportedEncryptionTypes            = $null
                }

                try {
                    $xde = & $script:GetDe ("LDAP://${bindServer}/${oldDn}")

                    if ($xde.Properties['displayName'])                          { $exp.DisplayName     = $xde.Properties['displayName'][0] }
                    if ($xde.Properties['description'])                          { $exp.Description     = $xde.Properties['description'][0] }
                    if ($xde.Properties['servicePrincipalName'])                 { $exp.ServicePrincipalName = @($xde.Properties['servicePrincipalName']) }
                    if ($xde.Properties['msDS-ManagedPasswordInterval'])         { $exp.ManagedPasswordInterval = [int]$xde.Properties['msDS-ManagedPasswordInterval'][0] }
                    if ($xde.Properties['msDS-AllowedToDelegateTo'])             { $exp.AllowedToDelegateTo    = @($xde.Properties['msDS-AllowedToDelegateTo']) }
                    if ($xde.Properties['userAccountControl'])                   { $exp.UserAccountControl      = [int]$xde.Properties['userAccountControl'][0] }
                    if ($xde.Properties['dnsHostName'])                          { $exp.DnsHostName             = $xde.Properties['dnsHostName'][0] }
                    if ($xde.Properties['msDS-GroupMSAMembership'])              { $exp.GroupMSAMembership      = $xde.Properties['msDS-GroupMSAMembership'][0] }
                    if ($xde.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity']) { $exp.AllowedToActOnBehalfOfOtherIdentity = $xde.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'][0] }
                    if ($xde.Properties['msDS-SupportedEncryptionTypes'])        { $exp.SupportedEncryptionTypes = [int]$xde.Properties['msDS-SupportedEncryptionTypes'][0] }
                } catch {
                    Write-IdentIRLog -Message "Domain ${domain}: backup read failed for ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }

                Write-IdentIRLog -Message "Domain ${domain}: backup done for $oldDn" -TypeName 'Info' -ForegroundColor Green

                # 1) Disable & tag OLD
                if ($script:whatIf) {
                    & $WI ("Domain ${domain}: disable + tag $oldDn")
                } else {
                    try {
                        $de  = & $script:GetDe ("LDAP://${bindServer}/${oldDn}")
                        $uac = [int]($de.Properties['userAccountControl'].Value)
                        $de.Properties['userAccountControl'].Value = ($uac -bor 0x2) # ACCOUNTDISABLE

                        $oldDesc = if ($de.Properties['description']) { $de.Properties['description'][0] } else { $null }
                        $newDesc = if ($oldDesc) { "$oldDesc [$CleanupTag]" } else { $CleanupTag }
                        $de.Properties['description'].Value      = $newDesc
                        $de.Properties['adminDescription'].Value = $CleanupTag

                        $de.SetInfo()
                        Write-IdentIRLog -Message "Domain ${domain}: disabled + tagged $oldDn" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Domain ${domain}: disable/tag failed for ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }

                # 2) Clear SPNs & DNS
                if ($script:whatIf) {
                    & $WI ("Domain ${domain}: clear SPNs + DNS on $oldDn")
                } else {
                    try {
                        $de = & $script:GetDe ("LDAP://${bindServer}/${oldDn}")
                        $de.Properties['servicePrincipalName'].Clear()
                        $de.Properties['dnsHostName'].Value = $null
                        $de.SetInfo()
                        Write-IdentIRLog -Message "Domain ${domain}: cleared SPNs + DNS on $oldDn" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Domain ${domain}: SPN/DNS clear failed for ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }

                if (-not $script:whatIf) { Start-Sleep -Seconds 3 }

                # 3) Delete OLD
                if ($script:whatIf) {
                    & $WI ("Domain ${domain}: delete $oldDn")
                } else {
                    try {
                        $parentDn = $oldDn.Substring($oldDn.IndexOf(',') + 1)
                        $pde      = & $script:GetDe ("LDAP://${bindServer}/${parentDn}")
                        $pde.Delete("msDS-GroupManagedServiceAccount", "CN=$cn")
                        Write-IdentIRLog -Message "Domain ${domain}: deleted old gMSA $oldDn" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Domain ${domain}: delete failed for ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        continue
                    }
                    Start-Sleep -Seconds 3
                }

                # 4) Confirm CN gone
                $ou     = & $script:GetDe ("LDAP://${bindServer}/${parent}")
                $exists = $false

                if (-not $script:whatIf) {
                    $exists     = $true
                    $retryCount = 0
                    $maxRetries = 20
                    while ($exists -and $retryCount -lt $maxRetries) {
                        $exists = $false
                        try {
                            $dsCheck = New-Object System.DirectoryServices.DirectorySearcher($ou)
                            $dsCheck.Filter      = "(cn=$cn)"
                            $dsCheck.SearchScope = 'OneLevel'
                            $dsCheck.PageSize    = 1
                            if ($dsCheck.FindOne()) { $exists = $true }
                        } catch {
                            Write-IdentIRLog -Message "Domain ${domain}: CN check failed for ${cn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                        if ($exists) { Start-Sleep -Seconds 5 }
                        $retryCount++
                    }
                }

                if ($exists) {
                    Write-IdentIRLog -Message "Domain ${domain}: CN $cn still present after retries, skip recreate." -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }

                # Normalize sAM (end with $; <=15 chars)
                if ($sam -and -not $sam.EndsWith('$')) { $sam = "${sam}$" }
                if ($sam -and $sam.Length -gt 15) {
                    $oldSam = $sam
                    $sam    = $sam.Substring(0,15)
                    Write-IdentIRLog -Message "Domain ${domain}: sAM '$oldSam' truncated to '$sam' (<=15 chars)." -TypeName 'Warning' -ForegroundColor Yellow
                }

                # Generate dnsHostName if missing
                if (-not $exp.DnsHostName) {
                    $exp.DnsHostName = "$cn.$domainFqdn"
                    Write-IdentIRLog -Message "Domain ${domain}: dnsHostName generated for $cn → $($exp.DnsHostName)" -TypeName 'Info' -ForegroundColor Cyan
                }

                # 5) Recreate NEW
                $newDn = $null
                if ($script:whatIf) {
                    & $WI ("Domain ${domain}: create CN=$cn,$parent")
                } else {
                    try {
                        $new = $ou.Create("msDS-GroupManagedServiceAccount", "CN=$cn")

                        if ($sam)                 { $new.Put("sAMAccountName", $sam) }
                        if ($exp.DisplayName)     { $new.Put("displayName", $exp.DisplayName) }
                        if ($exp.Description)     { $new.Put("description", $exp.Description) }
                        $new.Put("msDS-ManagedPasswordInterval", $exp.ManagedPasswordInterval)

                        $uac = if ($exp.UserAccountControl) { [int]$exp.UserAccountControl } else { 0x1000 } # WORKSTATION_TRUST_ACCOUNT
                        $uac = ($uac -band (-bnot 0x2)) # ensure enabled
                        $new.Put("userAccountControl", $uac)

                        if ($exp.DnsHostName)       { $new.Put("dnsHostName", $exp.DnsHostName) }
                        if ($exp.GroupMSAMembership){ $new.Put("msDS-GroupMSAMembership", $exp.GroupMSAMembership) }
                        if ($null -ne $exp.SupportedEncryptionTypes) {
                            $new.Put("msDS-SupportedEncryptionTypes", $exp.SupportedEncryptionTypes)
                        }

                        $new.Properties['adminDescription'].Value = 'Restored'

                        # First commit core attributes
                        $new.SetInfo()

                        # Second stage: SPNs / delegation / AOB
                        try {
                            foreach ($spn in @($exp.ServicePrincipalName)) {
                                [void]$new.Properties["servicePrincipalName"].Add($spn)
                            }
                        } catch {
                            Write-IdentIRLog -Message "Domain ${domain}: adding SPNs failed for CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        try {
                            foreach ($svc in @($exp.AllowedToDelegateTo)) {
                                [void]$new.Properties["msDS-AllowedToDelegateTo"].Add($svc)
                            }
                        } catch {
                            Write-IdentIRLog -Message "Domain ${domain}: adding AllowedToDelegateTo failed for CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        try {
                            if ($exp.AllowedToActOnBehalfOfOtherIdentity) {
                                $new.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'].Value = $exp.AllowedToActOnBehalfOfOtherIdentity
                            }
                        } catch {
                            Write-IdentIRLog -Message "Domain ${domain}: restoring AOB identity failed for CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        try {
                            $new.SetInfo()
                        } catch {
                            $e = $_.Exception
                            $detail = if ($e -is [System.DirectoryServices.DirectoryServicesCOMException] -and $e.ExtendedErrorMessage) {
                                $e.ExtendedErrorMessage.Trim()
                            } else {
                                $e.Message
                            }
                            Write-IdentIRLog -Message "Domain ${domain}: final SetInfo failed for CN=$cn,${parent}: $detail" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        $newDn = "CN=$cn,$parent"
                        Write-IdentIRLog -Message "Domain ${domain}: created new gMSA $newDn (Restored)" -TypeName 'Info' -ForegroundColor Green

                    } catch {
                        $e = $_.Exception
                        $detail = if ($e -is [System.DirectoryServices.DirectoryServicesCOMException] -and $e.ExtendedErrorMessage) {
                            $e.ExtendedErrorMessage.Trim()
                        } else {
                            $e.Message
                        }
                        Write-IdentIRLog -Message "Domain ${domain}: create gMSA failed (CN=$cn,$parent): $detail" -TypeName 'Error' -ForegroundColor Red
                    }
                }

                if ($newDn) {
                    $oldToNewMap[$oldDn] = $newDn
                    if (-not $firstNewDn) { $firstNewDn = $newDn }
                }
            }

            # Optional host rebind
            if ($RebindHosts -and $oldToNewMap.Count -gt 0) {
                if ($script:whatIf) {
                    & $WI ("Domain ${domain}: rebind hosts (map entries: $($oldToNewMap.Count))")
                } else {
                    try {
                        $root = & $script:GetDe ("LDAP://${bindServer}/${domainDn}")
                        $ds   = New-Object System.DirectoryServices.DirectorySearcher($root)
                        $ds.PageSize = 1000
                        $ds.Filter   = '(&(objectCategory=computer)(msDS-HostServiceAccount=*))'
                        $null = $ds.PropertiesToLoad.AddRange(@('distinguishedName','msDS-HostServiceAccount'))

                        $reboundCount = 0

                        foreach ($r in $ds.FindAll()) {
                            $compDn = $r.Properties['distinguishedname'][0]
                            $currentAccounts = @($r.Properties['msds-hostserviceaccount'])
                            $updated = $false

                            for ($i = 0; $i -lt $currentAccounts.Count; $i++) {
                                if ($oldToNewMap.ContainsKey($currentAccounts[$i])) {
                                    $currentAccounts[$i] = $oldToNewMap[$currentAccounts[$i]]
                                    $updated = $true
                                }
                            }

                            if ($updated) {
                                try {
                                    $cde = & $script:GetDe ("LDAP://${bindServer}/${compDn}")
                                    $cde.Properties['msDS-HostServiceAccount'].Clear()
                                    foreach ($acc in $currentAccounts) {
                                        [void]$cde.Properties['msDS-HostServiceAccount'].Add($acc)
                                    }
                                    $cde.SetInfo()
                                    Write-IdentIRLog -Message "Domain ${domain}: host rebound $compDn" -TypeName 'Info' -ForegroundColor White
                                    $reboundCount++
                                } catch {
                                    Write-IdentIRLog -Message "Domain ${domain}: host rebind failed for ${compDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                                }
                            }
                        }

                        Write-IdentIRLog -Message "Domain ${domain}: total hosts rebound $reboundCount" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Domain ${domain}: host rebind query failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    }
                }
            }

            # Verify new KDS usage (execution only). GUID starts at offset 24.
            if (-not $script:whatIf -and $gmsaIndex.Count -gt 0 -and $firstNewDn -and $script:newKdsCn) {
                try {
                    Start-Sleep -Seconds 2
                    $nde = & $script:GetDe ("LDAP://${bindServer}/${firstNewDn}")
                    $bytes = $nde.Properties['msDS-ManagedPasswordId'].Value
                    if ($bytes -and $bytes.Length -ge 40) {
                        [byte[]]$guidBytes = $bytes[24..39]
                        $extractedGuid = New-Object Guid -ArgumentList (,$guidBytes)
                        $extractedStr  = $extractedGuid.ToString()

                        if ($extractedStr -eq $script:newKdsCn) {
                            Write-IdentIRLog -Message "Domain ${domain}: verified new gMSA uses new KDS key ($($script:newKdsCn))." -TypeName 'Info' -ForegroundColor Green
                        } else {
                            Write-IdentIRLog -Message "Domain ${domain}: KDS verify mismatch (gMSA GUID $extractedStr vs new key $($script:newKdsCn))." -TypeName 'Error' -ForegroundColor Red
                        }
                    } else {
                        Write-IdentIRLog -Message "Domain ${domain}: msDS-ManagedPasswordId missing/short on $firstNewDn." -TypeName 'Warning' -ForegroundColor Yellow
                    }
                } catch {
                    Write-IdentIRLog -Message "Domain ${domain}: KDS verification failed: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }
            }

            Write-IdentIRLog -Message "Domain ${domain}: rotation finished." -TypeName 'Info' -ForegroundColor White
        }

        if ($script:whatIf) {
            Write-IdentIRLog -Message "Simulation complete (WhatIf=True). No changes applied." -TypeName 'Info' -ForegroundColor White
            return
        }

        # Old KDS key cleanup on forest-root PDC if we had keys before and now have a new key
        if ($script:existingKeyCount -gt 0 -and $script:newKdsCn) {
            try {
                $deleted = Remove-KdsRootKeys -BindServer $script:kdsBindServer -GetDe $script:GetDe -OldKeys $script:oldKeys
                if ($deleted -gt 0) {
                    Write-IdentIRLog -Message "Deleted $deleted old KDS root key(s) on forest-root PDC." -TypeName 'Info' -ForegroundColor Yellow
                } else {
                    Write-IdentIRLog -Message "No old KDS keys deleted (none matched or delete failed)." -TypeName 'Warning' -ForegroundColor Yellow
                }
                Force-ConfigReplication -SourceDC $script:kdsBindServer -CfgNC $script:cfgNC
            } catch {
                Write-IdentIRLog -Message "Old KDS key cleanup failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }
        }

        # Final kdsSvc restart across all online DCs
        $allDcs = $script:validated | Where-Object { $_.Online } | ForEach-Object { $_.FQDN } | Sort-Object -Unique

        if ($script:whatIf) {
            foreach ($c in $allDcs) { & $WI ("Restart kdsSvc on $c") }
        } else {
            $issF  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $poolF = [RunspaceFactory]::CreateRunspacePool(1, 16, $issF, $Host)
            $poolF.Open()
            $jobsF = @()

            foreach ($c in $allDcs) {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $poolF
                $null = $ps.AddScript({
                    param($ComputerName)
                    try {
                        $c = @{
                            ClassName    = 'Win32_Service'
                            Filter       = "Name='kdsSvc'"
                            ComputerName = $ComputerName
                        }
                        $svc = Get-CimInstance @c
                        if (-not $svc) { return @{Computer=$ComputerName; Success=$false; Error='kdsSvc not found'} }

                        $null = $svc | Invoke-CimMethod -MethodName StopService
                        $deadline = (Get-Date).AddSeconds(60)
                        while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) {
                            $svc = Get-CimInstance @c
                            Start-Sleep -Milliseconds 200
                        }
                        if ($svc.State -ne 'Stopped') { return @{Computer=$ComputerName; Success=$false; Error='Stop timed out'} }

                        $null = $svc | Invoke-CimMethod -MethodName StartService
                        $deadline = (Get-Date).AddSeconds(60)
                        while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) {
                            $svc = Get-CimInstance @c
                            Start-Sleep -Milliseconds 200
                        }
                        if ($svc.State -ne 'Running') { return @{Computer=$ComputerName; Success=$false; Error='Start timed out'} }

                        return @{Computer=$ComputerName; Success=$true}
                    } catch {
                        return @{Computer=$ComputerName; Success=$false; Error=$_.Exception.Message}
                    }
                }).AddArgument($c)

                $jobsF += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
            }

            foreach ($j in $jobsF) {
                try {
                    $r = $j.PS.EndInvoke($j.Handle)
                } finally {
                    $j.PS.Dispose()
                }
                foreach ($x in $r) {
                    if ($x.Success) {
                        Write-IdentIRLog -Message "kdsSvc restarted on $($x.Computer)" -TypeName 'Info' -ForegroundColor Green
                    } else {
                        Write-IdentIRLog -Message "kdsSvc restart failed on $($x.Computer): $($x.Error)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }
            }

            $poolF.Close()
            $poolF.Dispose()
        }

        Write-IdentIRLog -Message "gMSA + KDS rotation complete." -TypeName 'Info' -ForegroundColor White
    }
}
