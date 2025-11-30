<#
.SYNOPSIS
Cleans orphaned Active Directory metadata while preserving online DCs from the provided inventory.

.DESCRIPTION
Invoke-MetadataCleanup removes stale AD DS objects—nTDSConnections, nTDSDSA, server objects,
orphan Sites/SiteLinks, DFSR members with broken references, krbtgt_* orphans—and clears
msDS-RevealedUsers on preserved RODCs.  
Operates in simulation mode by default (WhatIf=True). Use -Execute to apply changes.

.PARAMETER IsolatedDCList
Collection of DC objects (Domain, FQDN, Type, Online, Default/Configuration NCs, etc.) used
to determine preserved identities and per-domain bind targets.

.PARAMETER Execute
Applies deletions and updates. When omitted, actions are simulated (WhatIf=True).

.EXAMPLE
# Simulate cleanup across all domains in the list
Invoke-MetadataCleanup -IsolatedDCList $dcs

.EXAMPLE
# Perform deletions and updates
Invoke-MetadataCleanup -IsolatedDCList $dcs -Execute

.OUTPUTS
PSCustomObject  
Structured report with counts (sites/servers/connections found and deleted, RODCs cleared,
DFSR/krbtgt_* orphans removed), warnings, errors, and duration.

.NOTES
Author: NightCityShogun  
Version: 1.0  
Requires: Rights to modify Sites/Services and domain objects; writable DC connectivity.  
© 2025 NightCityShogun. All rights reserved.
#>

function Invoke-MetadataCleanup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$IsolatedDCList,
        [Parameter()]
        [switch]$Execute
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest
        $ConfirmPreference = 'None'
        $WhatIfPreference  = $false

        $isWhatIf = -not $Execute.IsPresent
        $modeText = if ($isWhatIf) { "WhatIf=True" } else { "WhatIf=False" }

        # ---- Safe array/count helpers ----
        function AsArray { param($x) if ($null -eq $x) { @() } elseif ($x -is [System.Collections.IEnumerable] -and $x -isnot [string]) { @($x) } else { ,$x } }
        function CountOf { param($x) (@(AsArray $x)).Count }

        # ---- Report object ----
        $Report = [PSCustomObject]@{
            Mode             = $modeText
            StartTime        = Get-Date
            EndTime          = $null
            Duration         = $null
            DomainsProcessed = @()
            SitesProcessed   = @()
            DeletedObjects   = New-Object 'System.Collections.Generic.List[string]'
            SkippedObjects   = New-Object 'System.Collections.Generic.List[string]'
            Warnings         = New-Object 'System.Collections.Generic.List[string]'
            Errors           = New-Object 'System.Collections.Generic.List[string]'
            Stats            = [PSCustomObject]@{
                FoundSites=0; FoundServers=0; FoundConnections=0;
                OrphanComputersFound=0; OrphanComputersDeleted=0;
                PreservedRODCs=0; RODCsCleared=0;
                KrbtgtOrphansFound=0; KrbtgtOrphansDeleted=0;
                DfsrMemberOrphansFound=0; DfsrMembersDeleted=0;
                NtDsConnectionsDeleted=0; NtDsObjectsDeleted=0;
                SiteServersDeleted=0; SitesDeleted=0; SiteLinksDeleted=0; IstgCleared=0
            }
        }

        Write-IdentIRLog -Message "Starting Metadata Cleanup ($modeText)" -TypeName 'Info' -ForegroundColor Green
        # if ($isWhatIf) { Write-IdentIRLog -Message "RUNNING IN WHATIF - no deletions will be performed. Use -Execute to apply." -TypeName 'Warning' -ForegroundColor Yellow }

        # ---- Privilege check ----
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-IdentIRLog -Message "Checking admin privileges for $currentUser" -TypeName 'Info' -ForegroundColor Green

            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $rootDomain = $forest.RootDomain.Name

            $isAdmin = $false
            $userName = $currentUser.Split('\\')[-1]

            $usrRoot = [ADSI]"LDAP://$rootDomain"
            $userSearch = New-Object System.DirectoryServices.DirectorySearcher($usrRoot)
            $userSearch.Filter   = "(&(objectClass=user)(sAMAccountName=$userName))"
            $userSearch.PageSize = 1000
            $user = $userSearch.FindOne() ; if (-not $user) { throw "User $userName not found" }
            $userDN = $user.Properties['distinguishedName'][0]

            foreach ($group in @('Domain Admins','Enterprise Admins')) {
                try {
                    $gSearch = New-Object System.DirectoryServices.DirectorySearcher($usrRoot)
                    $gSearch.Filter   = "(&(objectClass=group)(sAMAccountName=$group))"
                    $gSearch.PageSize = 1000
                    $g = $gSearch.FindOne()
                    if ($g -and $g.Properties['member'] -contains $userDN) { $isAdmin = $true; break }
                } catch {}
            }
            if (-not $isAdmin) { throw "Insufficient permissions (need Domain Admins or Enterprise Admins)" }
            Write-IdentIRLog -Message "Verified admin privileges" -TypeName 'Info' -ForegroundColor Green
        } catch {
            Write-IdentIRLog -Message "Failed to verify admin permissions: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            throw
        }

        # ---- Normalize inputs to ONLINE only ----
        $IsolatedDCList = @($IsolatedDCList)
        $forestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ForestRootFqdn = $forestInfo.RootDomain.Name

        foreach ($dc in $IsolatedDCList) {
            if (-not $dc.Type) {
                if ($dc.Domain -ieq $ForestRootFqdn) { $dc.Type = 'Forest Root' }
                elseif ($dc.Domain -like "*.$ForestRootFqdn") { $dc.Type = 'Child Domain' }
                else { $dc.Type = 'Tree Root' }
            }
        }

        $onlineDCs  = $IsolatedDCList | Where-Object { $_.Online -eq $true }
        if (-not $onlineDCs) { throw "No ONLINE DCs provided; nothing to preserve." }

        # ---- Group DCs by domain ----
        $domainGroups = @{}
        foreach ($dc in $onlineDCs) {
            if (-not $domainGroups.ContainsKey($dc.Domain)) {
                $domainGroups[$dc.Domain] = [PSCustomObject]@{
                    Domain    = $dc.Domain
                    DCs       = New-Object 'System.Collections.Generic.List[object]'
                    Type      = $dc.Type
                    DefaultNC = $dc.DefaultNamingContext
                    ConfigNC  = $dc.ConfigurationNamingContext
                }
            }
            [void]$domainGroups[$dc.Domain].DCs.Add($dc)
        }

        $rootDc = $onlineDCs | Where-Object { $_.Domain -ieq $ForestRootFqdn } | Select-Object -First 1
        if (-not $rootDc) { throw "No ONLINE Forest Root DC found in IsolatedDCList" }

        $ActiveDirectoryInfo = [PSCustomObject]@{
            RootServerFqdn             = $rootDc.FQDN
            ForestRootFqdn             = $ForestRootFqdn
            DefaultNamingContext       = $rootDc.DefaultNamingContext
            ConfigurationNamingContext = $rootDc.ConfigurationNamingContext
        }
        Write-IdentIRLog -Message "Retrieved AD info from: RootServer=$($ActiveDirectoryInfo.RootServerFqdn), Forest=$($ActiveDirectoryInfo.ForestRootFqdn)" -TypeName 'Info' -ForegroundColor Green

        # ---- Preservation sets (ONLINE DC identities only) ----
        $allowedNames      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $allowedServerRefs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $allowedNtdsDNs    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($dc in $onlineDCs) {
            if ($dc.FQDN) {
                [void]$allowedNames.Add($dc.FQDN)
                [void]$allowedNames.Add( ($dc.FQDN -split '\.')[0] )
            }
            if ($dc.SamAccountName) { [void]$allowedNames.Add( ($dc.SamAccountName -replace '\$','') ) }
            if ($dc.Name)           { [void]$allowedNames.Add($dc.Name) }
            if ($dc.NetBIOS)        { [void]$allowedNames.Add($dc.NetBIOS) }
            if ($dc.ServerReferenceBL)  { [void]$allowedNtdsDNs.Add($dc.ServerReferenceBL) }
            if ($dc.DistinguishedName)  { [void]$allowedServerRefs.Add($dc.DistinguishedName) }
        }
        Write-IdentIRLog -Message "Preserving ONLINE DCs: names=$($allowedNames.Count), NTDS=$($allowedNtdsDNs.Count), servers=$($allowedServerRefs.Count)" -TypeName 'Info' -ForegroundColor Green

        # ---- Helpers ----
        $DeletedSites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        function New-Searcher([string]$Server,[string]$BaseDN,[string]$Filter){
            $root=[ADSI]"LDAP://$Server/$BaseDN"
            $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
            $ds.Filter=$Filter; $ds.PageSize=1000; return $ds
        }

        function Get-Prop($result, [string]$name){
            if ($result -and $result.Properties -and $result.Properties.Contains($name) -and $result.Properties[$name].Count -gt 0) { return [string]$result.Properties[$name][0] }
            try { $de=$result.GetDirectoryEntry(); $val=$de.Properties[$name].Value; $de.psbase.Close(); return $val } catch { return $null }
        }

        function Unprotect-DN([string]$DN,[string]$Server,[switch]$WhatIf){
            if (-not $DN -or $DN -like 'DC=*') { return }
            $curDn=$DN; $announced=$false
            for ($i=0; $i -lt 6 -and $curDn -and $curDn -notmatch '^DC='; $i++) {
                try {
                    $de=[ADSI]"LDAP://$Server/$curDn"
                    if ($de.Path) {
                        if ($WhatIf) {
                            if (-not $announced) { Write-IdentIRLog -Message "[WHATIF] Would remove explicit deny protections on $DN (and parents)" -TypeName 'Info' -ForegroundColor White; $announced=$true }
                        } else {
                            $didChange=$false
                            try {
                                if ($de.Properties.Contains('msDS-isProtectedFromAccidentalDeletion') -and $de.Properties['msDS-isProtectedFromAccidentalDeletion'].Value -eq $true) {
                                    $de.Properties['msDS-isProtectedFromAccidentalDeletion'].Value=$false; $didChange=$true
                                }
                            } catch {}
                            try {
                                $sd=$de.ObjectSecurity
                                $everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
                                $rules=$sd.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier])
                                foreach ($ace in @($rules)) {
                                    if (-not $ace.IsInherited -and $ace.IdentityReference -eq $everyone -and $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                                        $hasDel   = (($ace.ActiveDirectoryRights -band [DirectoryServices.ActiveDirectoryRights]::Delete) -ne 0)
                                        $hasTree  = (($ace.ActiveDirectoryRights -band [DirectoryServices.ActiveDirectoryRights]::DeleteTree) -ne 0)
                                        $hasChild = (($ace.ActiveDirectoryRights -band [DirectoryServices.ActiveDirectoryRights]::DeleteChild) -ne 0)
                                        if ($hasDel -or $hasTree -or $hasChild) { $null=$sd.RemoveAccessRule($ace); $didChange=$true }
                                    }
                                }
                                if ($didChange) { $de.ObjectSecurity=$sd }
                            } catch {}
                            if ($didChange) { try { $de.CommitChanges() } catch {} }
                        }
                        $de.psbase.Close()
                    }
                } catch {}
                $next = ($curDn -replace '^[^,]+,',''); if ($next -and $next -ne $curDn) { $curDn=$next } else { break }
            }
        }

        # --- ADSI-only existence + delete helpers ---
        function Test-DNExists([string]$Server,[string]$DN,[int]$Retries=0){
            # Returns $true if DN exists on Server; uses base-scope, no-cache search to avoid ADSI caching.
            for ($i=0; $i -le $Retries; $i++) {
                try {
                    $base = [ADSI]"LDAP://$Server/$DN"
                    if (-not $base.Path) { return $false }
                    $ds = New-Object System.DirectoryServices.DirectorySearcher($base)
                    $ds.CacheResults = $false
                    $ds.SearchScope  = [System.DirectoryServices.SearchScope]::Base
                    $ds.Filter       = '(objectClass=*)'
                    $ds.PageSize     = 1
                    $r  = $ds.FindOne()
                    if ($r) { return $true }
                    return $false
                } catch {
                    # Common for non-existent DN: treat as gone.
                    return $false
                } finally {
                    try { if ($base) { $base.psbase.Close() } } catch {}
                }
                if ($i -lt $Retries) { Start-Sleep -Milliseconds (200 * [math]::Pow(3,$i)) }
            }
            return $false
        }

        function Get-ParentDn([string]$dn){
            if (-not $dn) { return $null }
            return ($dn -replace '^[^,]+,','')
        }
        function Get-Rdn([string]$dn){
            if (-not $dn) { return $null }
            return ($dn -split ',',2)[0]
        }

        function Remove-DN([string]$DN,[string]$Server,[string]$What,[ref]$StatCounter){
            if (-not $DN) { return $false }

            # 1) Remove accidental deletion protections (object and short ancestry)
            Unprotect-DN -DN $DN -Server $Server -WhatIf:$isWhatIf

            if ($isWhatIf) {
                Write-IdentIRLog -Message "[WHATIF] Would delete $What $DN" -TypeName 'Info' -ForegroundColor White
                return $true
            }

            $deleted = $false

            try {
                # 2) Try direct DeleteTree() on the object
                try {
                    $obj = [ADSI]"LDAP://$Server/$DN"
                    if ($obj.Path) {
                        try { $obj.RefreshCache() } catch {}
                        try { $obj.DeleteTree(); $obj.CommitChanges() } catch {}
                        try { $obj.psbase.Close() } catch {}
                    }
                } catch {}

                # 3) Verify; if still present, ask parent to remove child
                if (Test-DNExists -Server $Server -DN $DN -Retries 2) {
                    $parentDn = Get-ParentDn $DN
                    $rdn      = Get-Rdn $DN
                    if ($parentDn -and $rdn) {
                        try {
                            $parent = [ADSI]"LDAP://$Server/$parentDn"
                            if ($parent.Path) {
                                try {
                                    $child = $parent.Children.Find($rdn)
                                    try { $child.RefreshCache() } catch {}
                                    try { $child.DeleteTree(); $child.CommitChanges() } catch {}
                                    try { $parent.Children.Remove($child); $parent.CommitChanges() } catch {}
                                } catch {}
                                try { $parent.psbase.Close() } catch {}
                            }
                        } catch {}
                    }
                }

                # 4) Final verification (authoritative, no cache)
                $deleted = -not (Test-DNExists -Server $Server -DN $DN -Retries 2)

            } catch {
                $deleted = $false
            }

            if ($deleted) {
                if ($StatCounter) { $StatCounter.Value++ }
                $Report.DeletedObjects.Add($DN) | Out-Null
                Write-IdentIRLog -Message "Deleted $What $DN" -TypeName 'Info' -ForegroundColor Green
                return $true
            } else {
                Write-IdentIRLog -Message "FAILED to delete $What $DN (it still exists or delete not permitted)" -TypeName 'Error' -ForegroundColor Red
                $Report.Errors.Add("Delete failed: $DN") | Out-Null
                return $false
            }
        }

        function Set-KccStay([string]$Server,[string]$ConfigNC,[int]$Value){
            try {
                $path="LDAP://$Server/CN=Directory Service,CN=Windows NT,CN=Services,$ConfigNC"
                if ($isWhatIf) {
                    Write-IdentIRLog -Message "[WHATIF] Would set replTopologyStayOfExecution=$Value at $path" -TypeName 'Info' -ForegroundColor White
                } else {
                    $de=[ADSI]$path; $de.Properties['replTopologyStayOfExecution'].Value=$Value; $de.CommitChanges(); $de.psbase.Close()
                    Write-IdentIRLog -Message "Set replTopologyStayOfExecution=$Value" -TypeName 'Info' -ForegroundColor Green
                }
            } catch {
                Write-IdentIRLog -Message "Failed to set replTopologyStayOfExecution=$Value : $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                $Report.Warnings.Add("Failed to set KCC stay=$Value : $($_.Exception.Message)") | Out-Null
            }
        }

        # Forest-root deferred context: orphan sites processed AFTER per-domain hygiene and BEFORE replication
        $ForestRootDeferred = @{ Server=$null; ConfigNC=$null; Sites=@() }

        try {
            Write-IdentIRLog -Message "Setting replTopologyStayOfExecution=1 forest-wide on $($ActiveDirectoryInfo.RootServerFqdn)" -TypeName 'Info' -ForegroundColor Green
            Set-KccStay -Server $ActiveDirectoryInfo.RootServerFqdn -ConfigNC $ActiveDirectoryInfo.ConfigurationNamingContext -Value 1
        } catch {}
    }

    process {
        $priority = @{ 'Forest Root' = 1; 'Child Domain' = 2; 'Tree Root' = 3 }
        $domainOrder = ($domainGroups.Keys | Sort-Object { $priority[$domainGroups[$_].Type] })

        foreach ($domain in $domainOrder) {
            $dg = $domainGroups[$domain]
            $domainName = $dg.Domain
            $defaultNC  = $dg.DefaultNC
            $configNC   = $dg.ConfigNC
            $server     = ($dg.DCs | Select-Object -First 1).FQDN

            try {
                # ensure server knows this NC
                try {
                    $rootDSE = [ADSI]"LDAP://$server/rootDSE"
                    if ($rootDSE.namingContexts -notcontains $defaultNC) {
                        $alt = ($dg.DCs | Where-Object {
                            try { ([ADSI]"LDAP://$($_.FQDN)/rootDSE").namingContexts -contains $defaultNC } catch { $false }
                        } | Select-Object -First 1).FQDN
                        if ($alt) { $server = $alt }
                    }
                } catch {}

                $Report.DomainsProcessed += $domainName
                Write-IdentIRLog -Message "Processing $($dg.Type): $domainName (bind=$server)" -TypeName 'Info' -ForegroundColor Cyan

                # ===== Forest Root Phase 1: connections/servers/ISTG =====
                if ($domainName -ieq $ActiveDirectoryInfo.ForestRootFqdn) {
                    # sites list (defer orphan delete)
                    $allSites = @()
                    try {
                        $s = New-Searcher -Server $server -BaseDN "CN=Sites,$configNC" -Filter '(objectClass=site)'
                        $allSites = @($s.FindAll() | ForEach-Object { Get-Prop $_ 'distinguishedName' } | Where-Object { $_ })
                        $ForestRootDeferred.Server   = $server
                        $ForestRootDeferred.ConfigNC = $configNC
                        $ForestRootDeferred.Sites    = $allSites
                        $Report.Stats.FoundSites    += $allSites.Count
                        Write-IdentIRLog -Message "Found $(@($allSites).Count) site(s)" -TypeName 'Info' -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "Failed to enumerate Sites: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }

                    # connection sweep (delete connections whose fromServer is NOT preserved)
                    foreach ($siteDN in $allSites) {
                        $serversContainerDN = "CN=Servers,$siteDN"
                        try {
                            $srvSearch = New-Searcher -Server $server -BaseDN $serversContainerDN -Filter '(objectClass=server)'
                            foreach ($srv in @($srvSearch.FindAll())) {
                                $srvDN = Get-Prop $srv 'distinguishedName'
                                if (-not $srvDN) { continue }
                                $ntdsSettingsDN = "CN=NTDS Settings,$srvDN"
                                try {
                                    $connSearch = New-Searcher -Server $server -BaseDN $ntdsSettingsDN -Filter '(objectClass=nTDSConnection)'
                                    $conns=@($connSearch.FindAll())
                                    $Report.Stats.FoundConnections += $conns.Count
                                    foreach ($conn in $conns) {
                                        $connDN = Get-Prop $conn 'distinguishedName'
                                        $from   = Get-Prop $conn 'fromServer'
                                        if (-not $connDN) { continue }
                                        if (-not $from -or -not $allowedNtdsDNs.Contains($from)) {
                                            Unprotect-DN -DN $connDN -Server $server -WhatIf:$isWhatIf
                                            if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would delete nTDSConnection $connDN" -TypeName 'Info' -ForegroundColor White }
                                            else { [void](Remove-DN -DN $connDN -Server $server -What 'nTDSConnection' -StatCounter ([ref]$Report.Stats.NtDsConnectionsDeleted)) }
                                        }
                                    }
                                } catch {}
                            }
                        } catch {}
                    }

                    # remove non-preserved servers (+ NTDS + connections)
                    foreach ($siteDN in $allSites) {
                        try {
                            $serversContainerDN = "CN=Servers,$siteDN"
                            $srvSearch = New-Searcher -Server $server -BaseDN $serversContainerDN -Filter '(objectClass=server)'
                            $servers = @($srvSearch.FindAll() | ForEach-Object {
                                $dn = Get-Prop $_ 'distinguishedName'
                                $host = Get-Prop $_ 'dNSHostName'
                                if (-not $host -and $dn) { $host = ( ($dn -split ',')[0] -replace '^CN=' ) }
                                if ($dn) { [PSCustomObject]@{ DN=$dn; SiteDN=$siteDN; Host=$host } }
                            })
                            $Report.Stats.FoundServers += $servers.Count

                            foreach ($srvObj in $servers) {
                                $keep = $false
                                if ($srvObj.Host) { $keep = $allowedNames.Contains($srvObj.Host) }
                                if ($keep) { continue }

                                $ntdsDN = $null; $connDNs = @(); $sysvolRef=$null
                                try {
                                    $ntdsSettingsDN = "CN=NTDS Settings,$($srvObj.DN)"
                                    $ntdsRoot=[ADSI]"LDAP://$server/$ntdsSettingsDN"
                                    if ($ntdsRoot.Path) {
                                        $ds1 = New-Searcher -Server $server -BaseDN $ntdsSettingsDN -Filter '(objectClass=nTDSDSA)'
                                        $n = $ds1.FindOne()
                                        if ($n) { $ntdsDN=Get-Prop $n 'distinguishedName'; $sysvolRef=Get-Prop $n 'serverReferenceBL' }
                                        $ds2 = New-Searcher -Server $server -BaseDN $ntdsSettingsDN -Filter '(objectClass=nTDSConnection)'
                                        foreach ($c in @($ds2.FindAll())) { $cd = Get-Prop $c 'distinguishedName'; if ($cd) { $connDNs += $cd } }
                                    }
                                } catch {}

                                foreach ($dn in @($connDNs + $ntdsDN + $srvObj.DN + $sysvolRef)) { if ($dn) { Unprotect-DN -DN $dn -Server $server -WhatIf:$isWhatIf } }

                                foreach ($dn in $connDNs) {
                                    if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would delete nTDSConnection $dn" -TypeName 'Info' -ForegroundColor White }
                                    else { [void](Remove-DN -DN $dn -Server $server -What 'nTDSConnection' -StatCounter ([ref]$Report.Stats.NtDsConnectionsDeleted)) }
                                }
                                if ($ntdsDN) {
                                    if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would delete nTDSDSA $ntdsDN" -TypeName 'Info' -ForegroundColor White }
                                    else { [void](Remove-DN -DN $ntdsDN -Server $server -What 'nTDSDSA' -StatCounter ([ref]$Report.Stats.NtDsObjectsDeleted)) }
                                }
                                if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would delete site server $($srvObj.DN)" -TypeName 'Info' -ForegroundColor White }
                                else { [void](Remove-DN -DN $srvObj.DN -Server $server -What 'site server' -StatCounter ([ref]$Report.Stats.SiteServersDeleted)) }
                            }
                        } catch {}
                    }

                    # ISTG sanity: clear if pointing at a non-preserved DC
                    foreach ($siteDN in $allSites) {
                        try {
                            $ntdsSiteSettingsDn = "CN=NTDS Site Settings,$siteDN"
                            $ntds = [ADSI]"LDAP://$server/$ntdsSiteSettingsDn"
                            if ($ntds.Path) {
                                $istg = AsArray $ntds.Properties['interSiteTopologyGenerator']
                                if ((CountOf $istg) -gt 0) {
                                    $cur = [string]$istg[0]
                                    if (-not $allowedNtdsDNs.Contains($cur)) {
                                        if ($isWhatIf) {
                                            Write-IdentIRLog -Message "[WHATIF] Would clear ISTG on $ntdsSiteSettingsDn (current=$cur not preserved)" -TypeName 'Info' -ForegroundColor White
                                        } else {
                                            $null = $ntds.Properties['interSiteTopologyGenerator'].Clear()
                                            $ntds.CommitChanges()
                                            $Report.Stats.IstgCleared++
                                            Write-IdentIRLog -Message "Cleared ISTG on $ntdsSiteSettingsDn" -TypeName 'Info' -ForegroundColor Green
                                        }
                                    }
                                }
                            }
                        } catch {}
                    }
                } # end Forest Root Phase 1

                # ===== Per-domain hygiene (all online domains) =====
                try {
                    # DC computer accounts under OU=Domain Controllers (subtree)
                    $dcOuDN = "OU=Domain Controllers,$defaultNC"
                    $dcAccounts = @()
                    try {
                        $s = New-Searcher -Server $server -BaseDN $dcOuDN -Filter '(objectClass=computer)'
                        $dcAccounts = @($s.FindAll() | ForEach-Object {
                            $dn=Get-Prop $_ 'distinguishedName'; $hn=Get-Prop $_ 'dNSHostName'; $nm=Get-Prop $_ 'name'
                            $isRodc = $false; try { $isRodc = ($null -ne (Get-Prop $_ 'msDS-KrbTgtLink')) } catch {}
                            $revealed=@(); try { $de=$_.GetDirectoryEntry(); if ($de) { $revealed = AsArray $de.Properties['msDS-RevealedUsers'] }; $de.psbase.Close() } catch {}
                            [PSCustomObject]@{ distinguishedName=$dn; dNSHostName=$hn; Name=$nm; IsRODC=[bool]$isRodc; RevealedUsers=$revealed }
                        })
                    } catch {}

                    Write-IdentIRLog -Message "Found $(@($dcAccounts).Count) DC computer object(s) in $domainName" -TypeName 'Info' -ForegroundColor Green

                    $orphanDcAccounts = @($dcAccounts | Where-Object {
                        $n = if ($_.dNSHostName) { $_.dNSHostName } elseif ($_.Name) { $_.Name } else { $null }
                        $n -and -not $allowedNames.Contains($n) -and -not $allowedNames.Contains(($n -split '\.')[0])
                    })

                    $Report.Stats.OrphanComputersFound += (CountOf $orphanDcAccounts)
                    if ((CountOf $orphanDcAccounts) -gt 0) {
                        Write-IdentIRLog -Message "Found $((CountOf $orphanDcAccounts)) orphan DC computer object(s) in $domainName" -TypeName 'Info' -ForegroundColor Yellow
                    } else {
                        Write-IdentIRLog -Message "No orphan DC computer objects detected in $domainName" -TypeName 'Info' -ForegroundColor Green
                    }

                    foreach ($acc in $orphanDcAccounts) {
                        [void](Remove-DN -DN $acc.distinguishedName -Server $server -What 'non-preserved DC computer account' -StatCounter ([ref]$Report.Stats.OrphanComputersDeleted))
                    }

                    # Preserved RODCs: clear msDS-RevealedUsers
                    $preservedRodcs = @($dcAccounts | Where-Object {
                        $_.IsRODC -and ($_.dNSHostName -and ($allowedNames.Contains($_.dNSHostName) -or $allowedNames.Contains( ($_.dNSHostName -split '\.')[0] )))
                    })
                    $Report.Stats.PreservedRODCs += (CountOf $preservedRodcs)
                    if ((CountOf $preservedRodcs) -eq 0) {
                        Write-IdentIRLog -Message "No RODCs detected in $domainName" -TypeName 'Info' -ForegroundColor Green
                    } else {
                        Write-IdentIRLog -Message "Clearing msDS-RevealedUsers on $((CountOf $preservedRodcs)) RODC(s) in $domainName" -TypeName 'Info' -ForegroundColor Yellow
                    }
                    foreach ($r in $preservedRodcs) {
                        if ((CountOf $r.RevealedUsers) -gt 0) {
                            if ($isWhatIf) {
                                Write-IdentIRLog -Message "[WHATIF] Would clear msDS-RevealedUsers on $($r.Name)" -TypeName 'Info' -ForegroundColor White
                            } else {
                                try {
                                    $adsi=[ADSI]"LDAP://$server/$($r.distinguishedName)"
                                    $adsi.PSBase.Invoke('PutEx', @([int]1, 'msDS-RevealedUsers', @()))
                                    $adsi.SetInfo()
                                    $Report.Stats.RODCsCleared++
                                } catch {}
                            }
                        }
                    }

                    # krbtgt_* orphans
                    try {
                        $ks = New-Searcher -Server $server -BaseDN $defaultNC -Filter '(&(objectClass=user)(sAMAccountName=krbtgt_*))'
                        $krbObjs = @($ks.FindAll() | ForEach-Object {
                            $dn=Get-Prop $_ 'distinguishedName'; $sam=Get-Prop $_ 'sAMAccountName'
                            $bl=@(); try { $de=$_.GetDirectoryEntry(); if ($de) { $bl = AsArray $de.Properties['msDS-KrbTgtLinkBL'] }; $de.psbase.Close() } catch { $bl=@() }
                            [PSCustomObject]@{ DN=$dn; Sam=$sam; Backlinks=$bl }
                        })
                        $rodcDns = @($preservedRodcs | ForEach-Object { $_.distinguishedName })
                        $orphans = @()
                        foreach ($k in $krbObjs) {
                            if ($k.Sam -eq 'krbtgt') { continue }
                            $hasBack = ((CountOf $k.Backlinks) -gt 0)
                            $backToExistingRODC = $false
                            foreach ($bl in (AsArray $k.Backlinks)) { if ($rodcDns -contains $bl) { $backToExistingRODC=$true; break } }
                            if (-not $hasBack -or -not $backToExistingRODC) { $orphans += $k }
                        }
                        $Report.Stats.KrbtgtOrphansFound += (CountOf $orphans)
                        if ((CountOf $orphans) -eq 0) {
                            Write-IdentIRLog -Message "No orphaned krbtgt_* detected in $domainName" -TypeName 'Info' -ForegroundColor Green
                        } else {
                            Write-IdentIRLog -Message "Found $((CountOf $orphans)) orphan krbtgt_* in $domainName" -TypeName 'Info' -ForegroundColor Yellow
                            foreach ($k in $orphans) {
                                [void](Remove-DN -DN $k.DN -Server $server -What "orphan $($k.Sam)" -StatCounter ([ref]$Report.Stats.KrbtgtOrphansDeleted))
                            }
                        }
                    } catch {
                        Write-IdentIRLog -Message "krbtgt_* sweep failed in $domainName : $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }

                    # DFSR orphan members
                    try {
                        $dfsrRoot = "CN=DFSR-GlobalSettings,CN=System,$defaultNC"
                        $r = [ADSI]"LDAP://$server/$dfsrRoot"
                        if ($r.Path) {
                            $s = New-Searcher -Server $server -BaseDN $dfsrRoot -Filter '(objectClass=msDFSR-Member)'
                            $members=@($s.FindAll())
                            $orphans=@()
                            foreach ($m in $members) {
                                $dn = Get-Prop $m 'distinguishedName'
                                $ref = $null; try { $ref = Get-Prop $m 'msDFSR-ComputerReference' } catch {}
                                $isValidRef=$false; if ($ref) { try { $isValidRef = ([ADSI]"LDAP://$server/$ref").Path -ne $null } catch { $isValidRef=$false } }
                                if (-not $isValidRef -and $dn) { $orphans += $dn }
                            }
                            $Report.Stats.DfsrMemberOrphansFound += (CountOf $orphans)
                            if ((CountOf $orphans) -eq 0) {
                                Write-IdentIRLog -Message "No orphan DFSR members detected in $domainName" -TypeName 'Info' -ForegroundColor Green
                            } else {
                                Write-IdentIRLog -Message "Found $((CountOf $orphans)) orphan DFSR member(s) in $domainName" -TypeName 'Info' -ForegroundColor Yellow
                                foreach ($dn in $orphans) {
                                    [void](Remove-DN -DN $dn -Server $server -What 'DFSR member (orphan ComputerReference)' -StatCounter ([ref]$Report.Stats.DfsrMembersDeleted))
                                }
                            }
                        }
                    } catch {
                        Write-IdentIRLog -Message "DFSR cleanup failed ($domainName): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        $Report.Warnings.Add("DFSR cleanup ${domainName}: $($_.Exception.Message)") | Out-Null
                    }
                } catch {
                    Write-IdentIRLog -Message "Per-domain cleanup failed in $domainName : $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }

                # ===== Forest Root Phase 2: Orphan sites then replication =====
                if ($domainName -ieq $ActiveDirectoryInfo.ForestRootFqdn) {
                    $serverFR = $ForestRootDeferred.Server
                    $configFR = $ForestRootDeferred.ConfigNC
                    $allSites = @($ForestRootDeferred.Sites)

                    foreach ($siteDN in $allSites) {
                        if ($DeletedSites.Contains($siteDN)) { continue }

                        # orphan = 0 servers & 0 subnets
                        $serversContainerDN = "CN=Servers,$siteDN"
                        $srvCount = 0
                        try { $sLeft = New-Searcher -Server $serverFR -BaseDN $serversContainerDN -Filter '(objectClass=server)'; $srvCount = (@($sLeft.FindAll())).Count } catch {}
                        $subnetCount = 0
                        try {
                            $subnetsBase = "CN=Subnets,CN=Sites,$configFR"
                            $ss = New-Searcher -Server $serverFR -BaseDN $subnetsBase -Filter '(objectClass=subnet)'
                            $subnetCount = (@($ss.FindAll() | Where-Object { $_.Properties['siteobject'] -and $_.Properties['siteobject'][0] -eq $siteDN })).Count
                        } catch {}

                        if ($srvCount -eq 0 -and $subnetCount -eq 0) {
                            Unprotect-DN -DN $siteDN -Server $serverFR -WhatIf:$isWhatIf
                            Unprotect-DN -DN "CN=Servers,$siteDN" -Server $serverFR -WhatIf:$isWhatIf

                            foreach ($transport in @('IP','SMTP')) {
                                $linksBase = "CN=$transport,CN=Inter-Site Transports,CN=Sites,$configFR"
                                try {
                                    $ls = New-Searcher -Server $serverFR -BaseDN $linksBase -Filter '(objectClass=siteLink)'
                                    foreach ($res in @($ls.FindAll())) {
                                        $linkDn = Get-Prop $res 'distinguishedName'; if (-not $linkDn) { continue }
                                        try {
                                            $de = [ADSI]"LDAP://$serverFR/$linkDn"
                                            $inLink = ($de.Properties['siteList'] -and @($de.Properties['siteList']) -contains $siteDN)
                                            if ($inLink) {
                                                if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would remove $siteDN from siteLink $linkDn" -TypeName 'Info' -ForegroundColor White }
                                                else { $null = $de.Properties['siteList'].Remove($siteDN); $de.CommitChanges() }
                                            }
                                            $currentSites = AsArray $de.Properties['siteList']
                                            $de.psbase.Close()
                                            if ((CountOf $currentSites) -eq 0) {
                                                [void](Remove-DN -DN $linkDn -Server $serverFR -What 'empty siteLink' -StatCounter ([ref]$Report.Stats.SiteLinksDeleted))
                                            }
                                        } catch {}
                                    }
                                } catch {}
                            }

                            $ntdsSiteSettingsDn = "CN=NTDS Site Settings,$siteDN"
                            if ($isWhatIf) {
                                Write-IdentIRLog -Message "[WHATIF] Would delete NTDS Site Settings $ntdsSiteSettingsDn" -TypeName 'Info' -ForegroundColor White
                                Write-IdentIRLog -Message "[WHATIF] Would delete orphan Site $siteDN" -TypeName 'Info' -ForegroundColor White
                            } else {
                                [void](Remove-DN -DN $ntdsSiteSettingsDn -Server $serverFR -What 'NTDS Site Settings' -StatCounter ([ref]([int]0)))
                                if (Remove-DN -DN $siteDN -Server $serverFR -What 'orphan Site' -StatCounter ([ref]$Report.Stats.SitesDeleted)) {
                                    [void]$DeletedSites.Add($siteDN)
                                }
                            }
                        }
                    }

                    # Final replication fan-out (Default/Config/Schema)
                    try {
                        $rootDSE = [ADSI]"LDAP://$serverFR/rootDSE"
                        $defNC   = [string]$rootDSE.defaultNamingContext
                        $cfgNC   = [string]$rootDSE.configurationNamingContext
                        $schNC   = [string]$rootDSE.schemaNamingContext
                        $frDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
                            (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$ActiveDirectoryInfo.ForestRootFqdn))
                        )
                        foreach ($dc in $frDomain.DomainControllers) {
                            $name = $dc.Name
                            if (-not ($allowedNames.Contains($name) -or $allowedNames.Contains( ($name -split '\.')[0] ))) { continue }
                            foreach ($nc in @($defNC,$cfgNC,$schNC)) {
                                if ($isWhatIf) { Write-IdentIRLog -Message "[WHATIF] Would SyncReplicaFromAllServers($nc, 'CrossSite') on $name" -TypeName 'Info' -ForegroundColor White }
                                else {
                                    try { $dc.SyncReplicaFromAllServers($nc, [System.DirectoryServices.ActiveDirectory.SyncFromAllServersOptions]::CrossSite) | Out-Null
                                          Write-IdentIRLog -Message "Triggered SyncFromAllServers(CrossSite) on $name for $nc" -TypeName 'Info' -ForegroundColor Green
                                    } catch {
                                        Write-IdentIRLog -Message "SyncFromAllServers failed on $name ($nc): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-IdentIRLog -Message "Forest root replication step failed: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                }

                Write-IdentIRLog -Message "Processing $($dg.Type) Complete" -TypeName 'Info' -ForegroundColor Cyan
            } catch {
                Write-IdentIRLog -Message "Error processing domain $domainName : $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                $Report.Errors.Add("Domain $domainName error: $($_.Exception.Message)") | Out-Null
            }
        }
    }

    end {
        try {
            Write-IdentIRLog -Message "Metadata cleanup completed (see structured report output)" -TypeName 'Info' -ForegroundColor Green
        } catch {
            Write-IdentIRLog -Message "MetaData Cleanup failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            $Report.Errors.Add("End block error: $($_.Exception.Message)") | Out-Null
        } finally {
            if ($ActiveDirectoryInfo -and $ActiveDirectoryInfo.RootServerFqdn) {
                try {
                    Write-IdentIRLog -Message "Restoring replTopologyStayOfExecution=0 forest-wide on $($ActiveDirectoryInfo.RootServerFqdn)" -TypeName 'Info' -ForegroundColor Green
                    $path = "LDAP://$($ActiveDirectoryInfo.RootServerFqdn)/CN=Directory Service,CN=Windows NT,CN=Services,$($ActiveDirectoryInfo.ConfigurationNamingContext)"
                    if ($isWhatIf) {
                        Write-IdentIRLog -Message "[WHATIF] Would set replTopologyStayOfExecution=0 at $path" -TypeName 'Info' -ForegroundColor White
                    } else {
                        $de=[ADSI]$path; $de.Properties['replTopologyStayOfExecution'].Value=0; $de.CommitChanges(); $de.psbase.Close()
                    }
                } catch {}
            }
            $Report.EndTime = Get-Date
            $Report.Duration = [int]((New-TimeSpan -Start $Report.StartTime -End $Report.EndTime).TotalSeconds)
            Write-Output $Report
        }
    }
}
