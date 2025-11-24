<# 
.SYNOPSIS
Recreates and rotates all gMSA accounts and KDS root keys across isolated domains.

.DESCRIPTION
Set-GMSA validates ONLINE writable DCs, orders Forest Root → Child → Tree Root, and creates a new KDS root key
(effective now or offset). It restarts kdsSvc on all DCs, disables and removes existing gMSAs, then recreates
them with restored attributes. Optionally rebinds computers’ msDS-HostServiceAccount entries. Deletes old
KDS keys after replication. Runs in WhatIf unless -Execute is supplied.

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
Version: 1.1  
Requires: Add-KdsRootKey, ADSI, CIM/WMI, Domain/Enterprise Admin privileges.  
Behavior: Creates new KDS root key, forces replication, restarts kdsSvc, recreates gMSAs, optionally rebinds hosts, removes old keys.  
SupportsShouldProcess: True  
© 2025 NightCityShogun. All rights reserved.
#>
function Set-GMSA {
    [CmdletBinding()]
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
                $ds.PropertiesToLoad.AddRange(@('distinguishedName','cn','whenCreated')) | Out-Null

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
            } catch { }
            return ,$keys
        }

        function Remove-KdsRootKeys {
            param(
                [string]$BindServer,
                [scriptblock]$GetDe,
                [psobject[]]$OldKeys
            )
            $count = 0
            if (-not $OldKeys) { return 0 }
            try {
                $rootDse = & $GetDe ("LDAP://$BindServer/RootDSE")
                $cfgNC   = $rootDse.Properties['configurationNamingContext'][0]
                $kdsPath = "LDAP://$BindServer/CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$cfgNC"
                $container = & $GetDe $kdsPath
                foreach ($key in $OldKeys) {
                    try {
                        $container.Delete("msKds-ProvRootKey","CN=$($key.CN)")
                        $count++
                    } catch { }
                }
            } catch { }
            return $count
        }

        function Restart-KdsService {
            param([string]$ComputerName)
            if ($whatIf) {
                & $WI ("kdsSvc restarted on {0}" -f $ComputerName)
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
                    Write-IdentIRLog -Message "kdsSvc not found on ${ComputerName}" -TypeName 'Warning' -ForegroundColor Yellow
                    return
                }
                $null = $svc | Invoke-CimMethod -MethodName StopService | Out-Null
                $deadline = (Get-Date).AddSeconds(60)
                while ($svc.State -ne 'Stopped' -and (Get-Date) -lt $deadline) {
                    $svc = Get-CimInstance @c
                    Start-Sleep -Milliseconds 200
                }
                if ($svc.State -ne 'Stopped') {
                    Write-IdentIRLog -Message "kdsSvc stop timed out on ${ComputerName}" -TypeName 'Warning' -ForegroundColor Yellow
                }
                $null = $svc | Invoke-CimMethod -MethodName StartService | Out-Null
                $deadline = (Get-Date).AddSeconds(60)
                while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline) {
                    $svc = Get-CimInstance @c
                    Start-Sleep -Milliseconds 200
                }
                if ($svc.State -ne 'Running') {
                    Write-IdentIRLog -Message "kdsSvc start timed out on ${ComputerName}" -TypeName 'Warning' -ForegroundColor Yellow
                }
                Write-IdentIRLog -Message "kdsSvc restarted on ${ComputerName}" -TypeName 'Info' -ForegroundColor Green
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
                Write-IdentIRLog -Message "Forced replication from $SourceDC for $CfgNC" -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "Failed to force replication: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
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
                Write-IdentIRLog -Message "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" -TypeName 'Warning' -ForegroundColor Yellow
                continue
            }
            $validated.Add($dc)
        }

        if (@($validated).Count -eq 0) {
            Write-IdentIRLog -Message "No valid DC entries." -TypeName 'Warning' -ForegroundColor Yellow
            return
        }

        # Single forest check
        $forestRoots = New-Object System.Collections.Generic.HashSet[string]
        foreach ($dc in $validated | Where-Object { $_.Online }) {
            try {
                $rootDse = & $GetDe ("LDAP://$($dc.FQDN)/RootDSE")
                [void]$forestRoots.Add($rootDse.Properties['rootDomainNamingContext'][0])
            } catch {
                Write-IdentIRLog -Message "Failed to get rootDomainNamingContext from $($dc.FQDN): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        }
        if ($forestRoots.Count -gt 1) {
            Write-IdentIRLog -Message "Multiple forests detected in input. This function supports one forest only." -TypeName 'Error' -ForegroundColor Red
            return
        }
        if ($forestRoots.Count -eq 0) {
            Write-IdentIRLog -Message "No forest root NC detected." -TypeName 'Error' -ForegroundColor Red
            return
        }

        $forestRootNc = $forestRoots | Select-Object -First 1

        # Ordering: Forest Root → Child → Tree Root; PDC first
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

        # FIXED: use the domain Type string to look up numeric priority
        $orderedDomains = ($groups.Name) | Sort-Object {
            $t = $meta[$_].Type
            if ($priority.ContainsKey($t)) { $priority[$t] } else { 4 }
        }, $_

        Write-IdentIRLog -Message ("gMSA rotation scope across {0} domain(s) (WhatIf={1})" -f @($orderedDomains).Count, $whatIf) -TypeName 'Info' -ForegroundColor Cyan

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

        $script:KdsEffectiveTime = $script:DesiredUsableTime.AddHours(-10)
        $script:newKdsCn = $null
        $script:cfgNC = (& $GetDe ("LDAP://$($validated[0].FQDN)/RootDSE")).Properties['configurationNamingContext'][0]

        # Choose bind DC
        $scanOrder = @(
            $validated | Where-Object { $_.IsPdcRoleOwner -and $_.Online }
        ) + @(
            $validated | Where-Object { -not $_.IsPdcRoleOwner -and $_.Online }
        )

        $script:kdsBindServer    = $null
        $script:existingKeyCount = 0
        $script:oldKeys          = @()

        foreach ($dc in $scanOrder) {
            try {
                $keys = Get-KdsRootKeys -BindServer $dc.FQDN -GetDe $GetDe
                if ($keys.Count -gt 0) {
                    $script:kdsBindServer    = $dc.FQDN
                    $script:existingKeyCount = $keys.Count
                    $script:oldKeys          = $keys
                    Write-IdentIRLog -Message ("Observed {0} existing KDS root key(s) via {1}; will recreate using new key and delete old at end." -f $keys.Count, $dc.FQDN) -TypeName 'Info' -ForegroundColor Green
                    break
                }
            } catch { }
        }

        if (-not $script:kdsBindServer) {
            $forestRootSet = @($validated | Where-Object { $_.Type -eq 'Forest Root' -and $_.Online })
            if ($forestRootSet.Count -gt 0) {
                $frOrdered = @(
                    $forestRootSet | Where-Object { $_.IsPdcRoleOwner }
                ) + @(
                    $forestRootSet | Where-Object { -not $_.IsPdcRoleOwner }
                )
                $script:kdsBindServer = $frOrdered[0].FQDN
                Write-IdentIRLog -Message "No existing KDS root key found. Selected Forest Root DC for first-time creation: $($script:kdsBindServer)" -TypeName 'Info' -ForegroundColor Cyan
            } else {
                $any = @($validated | Where-Object { $_.Online }) | Select-Object -First 1
                $script:kdsBindServer = $any.FQDN
                Write-IdentIRLog -Message "No existing KDS root key and no Forest Root DC online. Falling back to online DC: $($script:kdsBindServer)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        }

        # Create new KDS root key
        if ($whatIf) {
            $effLabel = if ($script:DesiredUsableTime -le (Get-Date)) {
                "EffectiveImmediately"
            } else {
                "EffectiveTime=$($script:DesiredUsableTime)"
            }
            & $WI ("CREATE new KDS root key on {0} ({1})" -f $script:kdsBindServer, $effLabel)
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
                Write-IdentIRLog -Message "KDS root key creation FAILED on ${script:kdsBindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }

            if ($creationOk) {
                Write-IdentIRLog -Message "KDS root key creation requested on ${script:kdsBindServer}" -TypeName 'Info' -ForegroundColor Green
                Force-ConfigReplication -SourceDC $script:kdsBindServer -CfgNC $script:cfgNC

                # Wait until visible and capture its CN
                $keyTimeout = (Get-Date).AddSeconds(180)
                do {
                    Start-Sleep -Seconds 3
                    $afterKeys = Get-KdsRootKeys -BindServer $script:kdsBindServer -GetDe $GetDe
                    $newKey = $afterKeys |
                        Where-Object { $_.CN -notin $script:oldKeys.CN } |
                        Sort-Object WhenCreated -Descending |
                        Select-Object -First 1
                    $script:newKdsCn = $newKey.CN
                } until ($script:newKdsCn -or (Get-Date) -gt $keyTimeout)

                if (-not $script:newKdsCn) {
                    Write-IdentIRLog -Message "CRITICAL: New KDS root key not visible after timeout." -TypeName 'Error' -ForegroundColor Red
                    return
                } else {
                    Write-IdentIRLog -Message "New KDS root key presence verified: $($script:newKdsCn)" -TypeName 'Info' -ForegroundColor Green
                }
            }
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

            $dcs = @($script:validated | Where-Object { $_.Domain -ieq $domain -and $_.Online })
            if ($dcs -and $dcs[0].PSObject.Properties['IsRODC']) {
                $dcs = @($dcs | Where-Object { -not $_.IsRODC })
            }
            if (-not $dcs) {
                Write-IdentIRLog -Message "No online writable DCs for $domain. Skipping." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            $orderedDcs = @()
            $orderedDcs += @($dcs | Where-Object { $_.IsPdcRoleOwner })
            $orderedDcs += @($dcs | Where-Object { -not $_.IsPdcRoleOwner })

            $bindServer = $orderedDcs[0].FQDN
            $domainDn   = $script:meta[$domain].DefaultNC
            $domainFqdn = $script:meta[$domain].Domain

            Write-IdentIRLog -Message "Starting gMSA Rotation Domain $domain" -TypeName 'Info' -ForegroundColor Cyan

            # Restart kdssvc on domain DCs
            if ($whatIf) {
                foreach ($c in ($orderedDcs | ForEach-Object { $_.FQDN } | Sort-Object -Unique)) {
                    & $WI ("kdsSvc restarted on {0}" -f $c)
                }
            } else {
                $targets = ($orderedDcs | ForEach-Object { $_.FQDN } | Sort-Object -Unique)
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
                    $rsJobs += [pscustomobject]@{PS=$ps;Handle=$ps.BeginInvoke()}
                }

                foreach ($j in $rsJobs) {
                    try { $r = $j.PS.EndInvoke($j.Handle) } finally { $j.PS.Dispose() }
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

            # Enumerate gMSAs
            $gmsaIndex = New-Object System.Collections.Generic.List[psobject]
            try {
                $root = & $script:GetDe ("LDAP://${bindServer}/${domainDn}")
                $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
                $ds.PageSize = 1000
                $ds.Filter   = '(objectClass=msDS-GroupManagedServiceAccount)'
                $ds.PropertiesToLoad.AddRange(@('distinguishedName','sAMAccountName')) | Out-Null
                foreach ($r in $ds.FindAll()) {
                    $dn = $r.Properties['distinguishedname'][0]
                    $parent = if ($dn -and $dn.Contains(',')) { $dn.Substring($dn.IndexOf(',')+1) } else { $null }
                    $sam = if ($r.Properties['samaccountname']) { $r.Properties['samaccountname'][0] } else { $null }
                    $gmsaIndex.Add([pscustomobject]@{
                        DistinguishedName = $dn
                        ParentContainerDN = $parent
                        SamAccountName    = $sam
                    })
                }
            } catch {
                Write-IdentIRLog -Message "gMSA discovery failed in ${domainDn} via ${bindServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }

            Write-IdentIRLog -Message ("Found {0} gMSA object(s)" -f $gmsaIndex.Count) -TypeName 'Info' -ForegroundColor Green

            # Disable & tag → clear SPNs/DNS → delete → confirm → recreate
            $oldToNewMap = @{}
            $firstNewDn  = $null

            foreach ($g in $gmsaIndex) {

                $oldDn  = $g.DistinguishedName
                $parent = $g.ParentContainerDN
                $cn     = ($oldDn -split ',',2)[0] -replace '^CN='
                $sam    = $g.SamAccountName

                # backup attributes
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
                } catch { }

                Write-IdentIRLog -Message "Backed up for ${oldDn}: dnsHostName=$($exp.DnsHostName); SPNs=$($exp.ServicePrincipalName -join ', ')" -TypeName 'Info' -ForegroundColor Green

                # 1) Disable & tag OLD (append tag to description)
                if ($whatIf) {
                    & $WI ("Disabled & Tagged gMSA: {0}" -f $oldDn)
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
                        Write-IdentIRLog -Message "Disabled & tagged gMSA: ${oldDn} (description updated to '$newDesc')" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Update failed for gMSA ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }

                # 2) Clear SPNs & DNS on OLD
                if ($whatIf) {
                    & $WI ("Clear SPNs and dnsHostName on {0}" -f $oldDn)
                } else {
                    try {
                        $de = & $script:GetDe ("LDAP://${bindServer}/${oldDn}")
                        $de.Properties['servicePrincipalName'].Clear()
                        $de.Properties['dnsHostName'].Value = $null
                        $de.SetInfo()
                        Write-IdentIRLog -Message "Cleared SPNs and dnsHostName from old gMSA: ${oldDn}" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Clearing SPNs/DNS failed for ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }

                if (-not $whatIf) { Start-Sleep -Seconds 3 }

                # 3) Delete OLD
                if ($whatIf) {
                    & $WI ("Deleted {0}" -f $oldDn)
                } else {
                    try {
                        $parentDn = $oldDn.Substring($oldDn.IndexOf(',')+1)
                        $pde      = & $script:GetDe ("LDAP://${bindServer}/${parentDn}")
                        $pde.Delete("msDS-GroupManagedServiceAccount","CN=$cn")
                        Write-IdentIRLog -Message "Deleted old gMSA: ${oldDn}" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Delete failed for old gMSA ${oldDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        continue
                    }
                    Start-Sleep -Seconds 3
                }

                # 4) Confirm CN gone (more patient)
                $ou     = & $script:GetDe ("LDAP://${bindServer}/${parent}")
                $exists = $false
                if (-not $whatIf) {
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
                            Write-IdentIRLog -Message "CN existence check failed for $cn in ${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                        if ($exists) { Start-Sleep -Seconds 5 }
                        $retryCount++
                    }
                }
                if ($exists) {
                    Write-IdentIRLog -Message "Failed to confirm deletion of $cn after retries. Skipping recreation to avoid LDAP unwillingToPerform." -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }

                # Normalize sAM (end with $; <=15 chars)
                if ($sam -and -not $sam.EndsWith('$')) { $sam = "${sam}$" }
                if ($sam -and $sam.Length -gt 15) {
                    $oldSam = $sam
                    $sam    = $sam.Substring(0,15)
                    Write-IdentIRLog -Message "sAMAccountName '$oldSam' truncated to '$sam' to meet 15-char limit." -TypeName 'Warning' -ForegroundColor Yellow
                }

                # Generate dnsHostName if missing
                if (-not $exp.DnsHostName) {
                    $exp.DnsHostName = "$cn.$domainFqdn"
                    Write-IdentIRLog -Message "Generated dnsHostName for CN=$cn,${parent}: $($exp.DnsHostName)" -TypeName 'Info' -ForegroundColor Cyan
                }

                # 5) Recreate NEW (correct attribute order)
                $newDn = $null
                if ($whatIf) {
                    & $WI ("Create CN={0},{1}" -f $cn,$parent)
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

                        if ($exp.DnsHostName)        { $new.Put("dnsHostName", $exp.DnsHostName) }
                        if ($exp.GroupMSAMembership)  { $new.Put("msDS-GroupMSAMembership", $exp.GroupMSAMembership) }
                        if ($null -ne $exp.SupportedEncryptionTypes) { $new.Put("msDS-SupportedEncryptionTypes", $exp.SupportedEncryptionTypes) }

                        $new.Properties['adminDescription'].Value = 'Restored'

                        # First commit core attributes
                        $new.SetInfo()

                        # Second stage: SPNs / delegation / AOB
                        try {
                            foreach ($spn in @($exp.ServicePrincipalName)) {
                                [void]$new.Properties["servicePrincipalName"].Add($spn)
                            }
                        } catch {
                            Write-IdentIRLog -Message "Adding SPNs failed on CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        try {
                            foreach ($svc in @($exp.AllowedToDelegateTo)) {
                                [void]$new.Properties["msDS-AllowedToDelegateTo"].Add($svc)
                            }
                        } catch {
                            Write-IdentIRLog -Message "Adding AllowedToDelegateTo failed on CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        try {
                            if ($exp.AllowedToActOnBehalfOfOtherIdentity) {
                                $new.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'].Value = $exp.AllowedToActOnBehalfOfOtherIdentity
                            }
                        } catch {
                            Write-IdentIRLog -Message "Restoring msDS-AllowedToActOnBehalfOfOtherIdentity failed on CN=$cn,${parent}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
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
                            Write-IdentIRLog -Message "Second-stage SetInfo failed for CN=$cn,${parent}: $detail" -TypeName 'Warning' -ForegroundColor Yellow
                        }

                        $newDn = "CN=$cn,$parent"
                        Write-IdentIRLog -Message "Created new gMSA: ${newDn} (tagged 'Restored')" -TypeName 'Info' -ForegroundColor Green

                    } catch {
                        $e = $_.Exception
                        $detail = if ($e -is [System.DirectoryServices.DirectoryServicesCOMException] -and $e.ExtendedErrorMessage) {
                            $e.ExtendedErrorMessage.Trim()
                        } else {
                            $e.Message
                        }
                        Write-IdentIRLog -Message "Create gMSA failed (CN=$cn,$parent): $detail" -TypeName 'Error' -ForegroundColor Red
                    }
                }

                if ($newDn) {
                    $oldToNewMap[$oldDn] = $newDn
                    if (-not $firstNewDn) { $firstNewDn = $newDn }
                }
            }

            # Optional host rebind
            if ($RebindHosts -and $oldToNewMap.Count -gt 0) {
                if ($whatIf) {
                    & $WI ("Rebind hosts using map (count: {0})" -f $oldToNewMap.Count)
                } else {
                    try {
                        $root = & $script:GetDe ("LDAP://${bindServer}/${domainDn}")
                        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
                        $ds.PageSize = 1000
                        $ds.Filter   = '(&(objectCategory=computer)(msDS-HostServiceAccount=*))'
                        $ds.PropertiesToLoad.AddRange(@('distinguishedName','msDS-HostServiceAccount')) | Out-Null
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
                                    Write-IdentIRLog -Message "Rebound host: ${compDn}" -TypeName 'Info' -ForegroundColor White
                                    $reboundCount++
                                } catch {
                                    Write-IdentIRLog -Message "Rebind failed: ${compDn}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                                }
                            }
                        }
                        Write-IdentIRLog -Message "Rebound ${reboundCount} host(s) in batch" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Batch rebind query failed in ${domainDn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    }
                }
            }

            # Verify new KDS usage (execution only). GUID starts at offset 24.
            if (-not $whatIf -and $gmsaIndex.Count -gt 0 -and $firstNewDn -and $newKdsCn) {
                try {
                    Start-Sleep -Seconds 2
                    $nde = & $script:GetDe ("LDAP://${bindServer}/${firstNewDn}")
                    $bytes = $nde.Properties['msDS-ManagedPasswordId'].Value
                    if ($bytes -and $bytes.Length -ge 40) {
                        [byte[]]$guidBytes = $bytes[24..39]
                        $extractedGuid = New-Object Guid -ArgumentList (,$guidBytes)
                        $extractedStr  = $extractedGuid.ToString()
                        if ($extractedStr -eq $newKdsCn) {
                            Write-IdentIRLog -Message "Verified new gMSA (${firstNewDn}) uses new KDS root key (${newKdsCn})." -TypeName 'Info' -ForegroundColor Green
                        } else {
                            Write-IdentIRLog -Message "Verification failed for gMSA (${firstNewDn}): extracted GUID ${extractedStr} != new KDS ${newKdsCn}" -TypeName 'Error' -ForegroundColor Red
                        }
                    } else {
                        Write-IdentIRLog -Message "msDS-ManagedPasswordId not set or too short for verification on ${firstNewDn}" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                } catch {
                    Write-IdentIRLog -Message "KDS verification failed: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }
            }

            Write-IdentIRLog -Message "Completed gMSA Rotation Domain $domain" -TypeName 'Info' -ForegroundColor White
        }

        if ($whatIf) {
            Write-IdentIRLog -Message "gMSA operation simulation complete (WhatIf=True)." -TypeName 'Info' -ForegroundColor White
            return
        }

        # Old KDS key cleanup if we created a new one earlier
        if ($script:existingKeyCount -gt 0) {
            try {
                $deleted = Remove-KdsRootKeys -BindServer $script:kdsBindServer -GetDe $script:GetDe -OldKeys $script:oldKeys
                if ($deleted -gt 0) {
                    Write-IdentIRLog -Message ("Deleted old KDS root key(s) (forest-wide).") -TypeName 'Info' -ForegroundColor Yellow
                }
                Force-ConfigReplication -SourceDC $script:kdsBindServer -CfgNC $script:cfgNC
            } catch {
                Write-IdentIRLog -Message "Failed deleting old KDS root keys: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            }
        }

        $allDcs = $script:validated | Where-Object { $_.Online } | ForEach-Object { $_.FQDN } | Sort-Object -Unique
        if ($whatIf) {
            foreach ($c in $allDcs) { & $WI ("kdsSvc restarted on {0}" -f $c) }
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
                $jobsF += [pscustomobject]@{PS=$ps;Handle=$ps.BeginInvoke()}
            }

            foreach ($j in $jobsF) {
                try { $r = $j.PS.EndInvoke($j.Handle) } finally { $j.PS.Dispose() }
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

        Write-IdentIRLog -Message "gMSA operations complete." -TypeName 'Info' -ForegroundColor White
    }
}
