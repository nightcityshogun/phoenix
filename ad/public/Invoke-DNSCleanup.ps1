<#
.SYNOPSIS
Automates stale DNS record remediation across isolated or recovery Active Directory environments.

.DESCRIPTION
Invoke-DnsCleanup detects and removes stale DNS records referencing non-active or decommissioned
domain controllers across specified or discovered DNS servers.  

By default, the function operates in simulation mode (WhatIf=True).  
Use the -Execute parameter to perform actual cleanup actions.

.PARAMETER IsolatedDCList
Specifies a collection of active or restored domain controller objects (from Get-ForestInfo),
including metadata such as FQDN, Domain name, and SIDs.  
Used to validate live DCs and identify stale DNS targets per domain context.

.PARAMETER Execute
Applies all DNS cleanup actions. When omitted, actions are simulated (WhatIf=True).

.PARAMETER RecordTypes
Defines DNS record types to process.  
Default: A, AAAA, CNAME, SRV, NS, TXT, SOA.

.PARAMETER IncludePtrRecords
Includes PTR records located in reverse lookup zones during processing.

.PARAMETER DnsServers
Specifies DNS servers to target for query and cleanup operations.  
Defaults to all servers enumerated from the IsolatedDCList.

.PARAMETER ExcludedDCs
Defines fully qualified domain names (FQDNs) of DCs to exclude from stale record detection
(e.g., temporarily offline or intentionally retained systems).

.PARAMETER WinStyleHidden
Suppresses console output.  
Logging continues if Write-IdentIRLog is configured to output to file.

.EXAMPLE
# Simulate DNS cleanup actions
Invoke-DnsCleanup -IsolatedDCList $dcs

.EXAMPLE
# Apply DNS cleanup including PTR records
Invoke-DnsCleanup -IsolatedDCList $dcs -Execute -IncludePtrRecords

.OUTPUTS
PSCustomObject  
Returns a structured summary containing identified stale DNS records, zones processed,
records deleted, DNS servers targeted, and remediation statistics.

.NOTES
Author: NightCityShogun  
Version: 1.9  
Requires: PowerShell 5.1+, DirectoryServices, and administrative privileges.  
DnsServer module (RSAT-DNS) optional — falls back to remote DCOM (no WinRM).  
© 2025 NightCityShogun. All rights reserved.
#>
function Invoke-DnsCleanup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$IsolatedDCList,
        [switch]$Execute,
        [string[]]$RecordTypes = @("A", "AAAA", "CNAME", "SRV", "NS", "TXT", "SOA"),
        [switch]$IncludePtrRecords,
        [string[]]$DnsServers = @(),
        [string[]]$ExcludedDCs = @(),
        [switch]$WinStyleHidden
    )
    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest
        Write-IdentIRLog -Message 'Starting Invoke-DnsCleanup' -TypeName 'Info' -ForegroundColor Green

        # === COLLECTIONS ===
        $script:ActiveDirectoryInfo = [PSCustomObject]@{
            QueryServer = [string]::Empty
            ForestRootFqdn = [string]::Empty
            DefaultNamingContext = [string]::Empty
            ConfigurationNamingContext = [string]::Empty
        }
        $script:DomainMap = @{}
        $script:DcList = [System.Collections.Generic.List[PSObject]]::new()
        $script:StaleDnsRecords = [System.Collections.Generic.List[PSObject]]::new()
        $script:StaleDcTargets = [System.Collections.Generic.List[string]]::new()
        $script:StaleDcIps = [System.Collections.Generic.List[string]]::new()
        $script:SitesProcessed = [System.Collections.Generic.List[string]]::new()
        $script:ExcludedDcIps = [System.Collections.Generic.List[string]]::new()
        $dcSrvPatterns = @('_ldap._tcp*', '_kerberos._tcp*', '_kerberos._udp*', '_gc._tcp*',
            '_kpasswd._tcp*', '_kpasswd._udp*', '_ldap._tcp.dc._msdcs*',
            '_kerberos._tcp.dc._msdcs*', '_ldap._tcp.pdc._msdcs*',
            '_ldap._tcp.*._sites.*', '_kerberos._tcp.*._sites.*',
            '_gc._tcp.*._sites.*', '_ldap._tcp.gc._msdcs*',
            '_ldap._tcp.*.domains._msdcs*')

        # === Get-SiteFromDN ===
        function Get-SiteFromDN {
            param ([string]$DN)
            if ([string]::IsNullOrWhiteSpace($DN)) {
                Write-IdentIRLog -Message "Invalid DN: Empty or null" -TypeName 'Warning' -ForegroundColor Yellow
                return "Unknown"
            }
            $components = $DN -split ','
            $siteIndex = [array]::IndexOf($components, "CN=Sites")
            if ($siteIndex -ge 0 -and $siteIndex -gt 0) {
                $site = $components[$siteIndex - 1] -replace '^CN='
                if ($site -and $site -notin $script:SitesProcessed) {
                    $script:SitesProcessed.Add($site)
                    Write-IdentIRLog -Message "Discovered site: ${site}" -TypeName 'Info' -ForegroundColor Green
                }
                return $site
            }
            Write-IdentIRLog -Message "Could not determine site from DN: $DN" -TypeName 'Warning' -ForegroundColor Yellow
            return "Unknown"
        }

        # === Test-IsDomainController ===
        function Test-IsDomainController {
            param (
                [string]$Fqdn,
                [string]$NamingContext,
                [string]$Server
            )
            $dcARecordPatterns = @(
                $script:ActiveDirectoryInfo.ForestRootFqdn,
                "gc._msdcs.$($script:ActiveDirectoryInfo.ForestRootFqdn)"
            )
            if (-not $Fqdn -or $Fqdn -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$' -or
                $Fqdn -in $dcARecordPatterns) {
                Write-IdentIRLog -Message "Skipping ${Fqdn}: Not a valid DC FQDN format or matches a record pattern" -TypeName 'Info' -ForegroundColor Gray
                return $false, $null, $null
            }
            $domainLower = $Fqdn -replace '^[^.]+\.', ''.ToLower()
            if ($script:DomainMap.ContainsKey($domainLower)) {
                $NamingContext = $script:DomainMap[$domainLower].NamingContext
                $Server = $script:DomainMap[$domainLower].Server
            }
            if (-not $NamingContext -or -not $Server) {
                Write-IdentIRLog -Message "No naming context or server for domain $domainLower of $Fqdn; assuming not a DC" -TypeName 'Warning' -ForegroundColor Yellow
                return $false, $null, $null
            }
            try {
                $searchRoot = [ADSI]"LDAP://$Server/$NamingContext"
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
                $searcher.Filter = "(&(objectCategory=computer)(dNSHostName=$Fqdn)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
                $searcher.PropertiesToLoad.AddRange(@("dNSHostName", "objectGUID", "serverReferenceBL"))
                $result = $searcher.FindOne()
                if ($result) {
                    Write-IdentIRLog -Message "Confirmed $Fqdn is a domain controller in AD (NC: $NamingContext, Server: $Server)" -TypeName 'Info' -ForegroundColor Green
                    $guid = if ($result.Properties["objectGUID"]) { ([guid]$result.Properties["objectGUID"][0]).ToString() } else { $null }
                    $serverRefBL = if ($result.Properties["serverReferenceBL"]) { $result.Properties["serverReferenceBL"][0].ToString() } else { $null }
                    return $true, $guid, $serverRefBL
                }
                Write-IdentIRLog -Message "$Fqdn is not a domain controller in AD (NC: $NamingContext, Server: $Server)" -TypeName 'Info' -ForegroundColor Gray
                return $false, $null, $null
            } catch {
                Write-IdentIRLog -Message "Error checking if $Fqdn is a DC: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                return $false, $null, $null
            } finally {
                if ($searcher) { $searcher.Dispose() }
            }
        }

        # === Resolve-ExcludedDcIps ===
        function Resolve-ExcludedDcIps {
            foreach ($dc in $ExcludedDCs) {
                try {
                    $ips = [System.Net.Dns]::GetHostAddresses($dc) | Where-Object AddressFamily -eq InterNetwork | ForEach-Object IPAddressToString
                    $ips | ForEach-Object { $script:ExcludedDcIps.Add($_) }
                } catch {
                    Write-IdentIRLog -Message "Failed to resolve IP for excluded DC ${dc}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }
            }
            Write-IdentIRLog -Message "Excluded DC IPs: $($script:ExcludedDcIps -join ', ')" -TypeName 'Info' -ForegroundColor Green
        }

        # === DETECT RSAT-DNS & IMPORT MODULES ===
        $script:RSAT_DNS = $false
        if (Get-Module -ListAvailable -Name DnsServer) {
            try {
                Import-Module DnsServer -ErrorAction Stop
                $script:RSAT_DNS = $true
                Write-IdentIRLog -Message 'RSAT-DNS installed -> using local DnsServer cmdlets' -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "Failed to import DnsServer module: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        } else {
            Write-IdentIRLog -Message 'RSAT-DNS not installed -> using remote DCOM (NO WINRM)' -TypeName 'Warning' -ForegroundColor Yellow
        }

        # ActiveDirectory is optional - use LDAP fallback if missing
        $script:RSAT_AD = $false
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                $script:RSAT_AD = $true
                Write-IdentIRLog -Message 'RSAT-AD-PowerShell installed -> using local AD cmdlets' -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "Failed to import ActiveDirectory: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
        } else {
            Write-IdentIRLog -Message 'RSAT-AD-PowerShell not installed -> using LDAP fallback' -TypeName 'Warning' -ForegroundColor Yellow
        }

        # === UNIVERSAL DNS CMDLET EXECUTOR (DCOM ONLY via Invoke-Command) ===
        function script:Run-Dns {
            param($Server, $Cmd, $Params)

            if ($script:RSAT_DNS) {
                try {
                    & $Cmd @Params
                    return
                } catch {
                    throw "Local $Cmd failed: $($_.Exception.Message)"
                }
            }

            # REMOTE: DCOM ONLY using Invoke-Command with -ComputerName
            try {
                $remoteParams = $Params.Clone()
                $remoteParams.Remove('ComputerName') | Out-Null

                $scriptBlock = {
                    param($c, $p)
                    Import-Module DnsServer -ErrorAction Stop
                    & $c @p
                }

                $result = Invoke-Command -ComputerName $Server -ScriptBlock $scriptBlock -ArgumentList $Cmd, $remoteParams -ErrorAction Stop
                Write-IdentIRLog -Message "Executed $Cmd on $Server via DCOM" -TypeName 'Info' -ForegroundColor Cyan
                return $result
            } catch {
                throw "Remote $Cmd failed on $Server via DCOM: $($_.Exception.Message)"
            }
        }

        if ($ExcludedDCs) { Resolve-ExcludedDcIps }
    }

    process {
        try {
            # === VALIDATE & DISCOVER SITES ===
            $sortedDcList = $IsolatedDCList | Sort-Object {
                switch ($_.Type) {
                    "Forest Root" { 1 }
                    "Child Domain" { 2 }
                    "Tree Root" { 3 }
                    default { 4 }
                }
            }
            foreach ($dc in $sortedDcList) {
                if (-not ($dc.FQDN -and $dc.Domain -and $dc.ServerReferenceBL -and $dc.DomainSid -and $dc.SamAccountName)) {
                    Write-IdentIRLog -Message "Invalid RestoredDCList entry for $($dc.FQDN): Required properties missing" -TypeName 'Error' -ForegroundColor Red
                    throw "Invalid RestoredDCList entry"
                }
                Write-IdentIRLog -Message "Validated DC in Isolated DC List: $($dc.FQDN), ServerReferenceBL: $($dc.ServerReferenceBL)" -TypeName 'Info' -ForegroundColor Green
                $script:DcList.Add($dc)
                Get-SiteFromDN -DN $dc.ServerReferenceBL
            }
            Write-IdentIRLog -Message "Validated Isolated DC List with $($script:DcList.Count) entries" -TypeName 'Info' -ForegroundColor Green

            # === BUILD DOMAIN MAP ===
            foreach ($grp in $script:DcList | Group-Object Domain) {
                $domainLower = $grp.Name.ToLower()
                $pdc = $grp.Group | Where-Object { $_.IsPdcRoleOwner } | Select-Object -First 1
                $anyDc = $grp.Group[0]
                $script:DomainMap[$domainLower] = @{
                    NamingContext = $anyDc.DefaultNamingContext
                    Server = if ($pdc) { $pdc.FQDN } else { $anyDc.FQDN }
                }
            }
            Write-IdentIRLog -Message "Built domain map for $($script:DomainMap.Count) domains" -TypeName 'Info' -ForegroundColor Green

            # === GET AD INFO ===
            $preferredDC = $script:DcList | Where-Object { $_.Type -eq 'Forest Root' -and $_.IsPdcRoleOwner } | Select-Object -First 1
            if (-not $preferredDC) { $preferredDC = $script:DcList | Where-Object { $_.Type -eq 'Forest Root' } | Select-Object -First 1 }
            if (-not $preferredDC) { $preferredDC = $script:DcList | Select-Object -First 1 }
            $queryServer = $preferredDC.FQDN
            $rootDSE = [ADSI]"LDAP://$queryServer/RootDSE"
            if ($rootDSE.Properties['isSynchronized'][0] -ne $true) { throw "Not synchronized" }
            $script:ActiveDirectoryInfo.QueryServer = $queryServer
            $script:ActiveDirectoryInfo.ForestRootFqdn = $rootDSE.rootDomainNamingContext -replace '^DC=','' -replace ',DC=','.'
            $script:ActiveDirectoryInfo.DefaultNamingContext = $rootDSE.defaultNamingContext
            $script:ActiveDirectoryInfo.ConfigurationNamingContext = $rootDSE.configurationNamingContext
            Write-IdentIRLog -Message "Retrieved AD info from ${queryServer}: Forest=$($script:ActiveDirectoryInfo.ForestRootFqdn)" -TypeName 'Info' -ForegroundColor Green

            # === ADMIN CHECK (LDAP fallback if no RSAT-AD) ===
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $adminGroups = @('Domain Admins', 'Schema Admins', 'Enterprise Admins')
            $isAdmin = $false
            $rootServer = ($script:DomainMap[$script:ActiveDirectoryInfo.ForestRootFqdn.ToLower()]).Server
            if (-not $rootServer) { $rootServer = $queryServer }

            if ($script:RSAT_AD) {
                foreach ($group in $adminGroups) {
                    try {
                        $members = Get-ADGroupMember -Identity $group -Server $rootServer -ErrorAction Stop
                        if ($members | Where-Object { $_.SamAccountName -eq $currentUser.Split('\')[1] }) {
                            $isAdmin = $true; break
                        }
                    } catch { }
                }
            } else {
                # LDAP fallback
                $domainDN = $rootDSE.defaultNamingContext
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = [ADSI]"LDAP://$rootServer/$domainDN"
                foreach ($group in $adminGroups) {
                    $searcher.Filter = "(&(objectClass=group)(name=$group))"
                    $result = $searcher.FindOne()
                    if ($result) {
                        $members = $result.Properties['member']
                        foreach ($member in $members) {
                            $user = [ADSI]"LDAP://$rootServer/$member"
                            if ($user.sAMAccountName -eq $currentUser.Split('\')[1]) {
                                $isAdmin = $true; break
                            }
                        }
                    }
                    if ($isAdmin) { break }
                }
            }

            if (-not $isAdmin) { throw "Insufficient permissions" }
            Write-IdentIRLog -Message "Verified user $currentUser has admin privileges" -TypeName 'Info' -ForegroundColor Green

            # === ACTIVE LISTS ===
            $activeDcFqdns = $script:DcList.FQDN | ForEach-Object { $_.ToLower() }
            $activeDcIps = $script:DcList.IPv4Address | ForEach-Object { $_ -split ', ' } | Where-Object { $_ }
            Write-IdentIRLog -Message "Active DC FQDNs: $($activeDcFqdns -join ', ')" -TypeName 'Info' -ForegroundColor Green
            Write-IdentIRLog -Message "Active DC IPs: $($activeDcIps -join ', ')" -TypeName 'Info' -ForegroundColor Green

            # === DNS SERVERS (ORDERED) ===
            if (-not $DnsServers) { $DnsServers = $script:DcList.FQDN | Sort-Object -Unique }
            $orderedDnsServers = @()
            $forestRootDc = $script:DcList | Where-Object { $_.Type -eq 'Forest Root' } | Select-Object -First 1
            if ($forestRootDc) { $orderedDnsServers += $forestRootDc.FQDN }
            $orderedDnsServers += $script:DcList | Where-Object { $_.Type -eq 'Child Domain' } | Select-Object -ExpandProperty FQDN -Unique
            $orderedDnsServers += $script:DcList | Where-Object { $_.Type -eq 'Tree Root' } | Select-Object -ExpandProperty FQDN -Unique
            $orderedDnsServers = $orderedDnsServers | Sort-Object -Unique
            $DnsServers = $orderedDnsServers

            # === FIRST PASS: COLLECT STALE TARGETS FROM ALL ZONES ===
            foreach ($dnsServer in $DnsServers) {
                Write-IdentIRLog -Message "Processing DNS server: $dnsServer..." -TypeName 'Info' -ForegroundColor Green
                try { Test-Connection -ComputerName $dnsServer -Count 1 -ErrorAction Stop | Out-Null }
                catch { Write-IdentIRLog -Message "Failed to connect to ${dnsServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red; continue }

                $zones = Run-Dns $dnsServer 'Get-DnsServerZone' @{ComputerName=$dnsServer; ErrorAction='Stop'} |
                    Where-Object { $_.ZoneType -eq 'Primary' -and $_.ZoneName -notin 'TrustAnchors','0.in-addr.arpa','127.in-addr.arpa','255.in-addr.arpa' }
                if ($IncludePtrRecords) {
                    $ptr = Run-Dns $dnsServer 'Get-DnsServerZone' @{ComputerName=$dnsServer} | Where-Object { $_.ZoneName -like '*.in-addr.arpa' -and $_.ZoneType -eq 'Primary' }
                    $zones += $ptr
                }

                foreach ($zone in $zones) {
                    Write-IdentIRLog -Message "Discovered DNS zone: $($zone.ZoneName) on $dnsServer (IsDsIntegrated: $($zone.IsDsIntegrated))" -TypeName 'Info' -ForegroundColor Green
                }

                foreach ($zone in $zones) {
                    Write-IdentIRLog -Message "First pass: Collecting stale DC targets in zone: $($zone.ZoneName) on $dnsServer" -TypeName 'Info' -ForegroundColor Cyan
                    $records = Run-Dns $dnsServer 'Get-DnsServerResourceRecord' @{ZoneName=$zone.ZoneName; ComputerName=$dnsServer; ErrorAction='SilentlyContinue'}
                    if (-not $records) {
                        Write-IdentIRLog -Message "No records found for zone $($zone.ZoneName) on $dnsServer" -TypeName 'Warning' -ForegroundColor Yellow
                        continue
                    }
                    foreach ($r in $records) {
                        if ($r.RecordType -notin "NS","A","AAAA","CNAME","SRV","PTR") { continue }
                        $target = $null; $ip = $null; $recordFqdn = $null
                        $isDcRelated = $false
                        switch ($r.RecordType) {
                            'NS' { $target = $r.RecordData.NameServer.TrimEnd('.') }
                            'A' { 
                                # Handle deserialized object: IPv4Address may be string or IPAddress
                                $ipv4 = $r.RecordData.IPv4Address
                                $ip = if ($ipv4 -is [string]) { $ipv4 } elseif ($ipv4) { $ipv4.IPAddressToString } else { $null }
                            }
                            'CNAME' { $target = $r.RecordData.HostNameAlias.TrimEnd('.') }
                            'SRV' { $target = $r.RecordData.DomainName.TrimEnd('.') }
                            'PTR' { $target = $r.RecordData.PtrDomainName.TrimEnd('.') }
                        }
                        $recordFqdn = if ($r.HostName -eq '@' -or $r.HostName -notlike '*.*') { "$($r.HostName).$($zone.ZoneName)" } else { $r.HostName }

                        if ($r.RecordType -eq 'NS') {
                            $isDcRelated = $true
                            Write-IdentIRLog -Message "NS record $($r.HostName): NameServer=$target" -TypeName 'Info' -ForegroundColor Green
                        } elseif ($r.RecordType -eq 'SRV' -and ($dcSrvPatterns | Where-Object { $r.HostName -like $_ })) {
                            $isDcRelated = $true
                            Write-IdentIRLog -Message "SRV record $($r.HostName): Priority=$($r.RecordData.Priority), Weight=$($r.RecordData.Weight), Port=$($r.RecordData.Port), DomainName=$target (DC-related)" -TypeName 'Info' -ForegroundColor Green
                        } elseif ($r.RecordType -eq 'CNAME') {
                            if ($recordFqdn.ToLower() -in $script:StaleDcTargets -or $target.ToLower() -in $script:StaleDcTargets) {
                                $isDcRelated = $true
                                Write-IdentIRLog -Message "CNAME record $($r.HostName): Alias=$target (DC-related)" -TypeName 'Info' -ForegroundColor Green
                            }
                        } elseif ($r.RecordType -eq 'A') {
                            if ($recordFqdn.ToLower() -in $activeDcFqdns -or $recordFqdn.ToLower() -in $script:StaleDcTargets -or
                                $r.HostName -in @($script:ActiveDirectoryInfo.ForestRootFqdn, "gc._msdcs.$($script:ActiveDirectoryInfo.ForestRootFqdn)", 'gc')) {
                                $isDcRelated = $true
                                Write-IdentIRLog -Message "A record $($r.HostName): IP=$ip, FQDN=$recordFqdn (DC-related)" -TypeName 'Info' -ForegroundColor Green
                            }
                        } elseif ($r.RecordType -eq 'PTR' -and $IncludePtrRecords) {
                            $isDcRelated = $true
                            Write-IdentIRLog -Message "PTR record $($r.HostName): PtrDomainName=$target" -TypeName 'Info' -ForegroundColor Green
                        }

                        if ($target -and $target.ToLower() -notin $activeDcFqdns -and $target.ToLower() -notin $ExcludedDCs -and $target.ToLower() -notin $script:StaleDcTargets) {
                            $isDc = (Test-IsDomainController -Fqdn $target -NamingContext $script:ActiveDirectoryInfo.DefaultNamingContext -Server $queryServer)[0]
                            if (-not $isDc) {
                                $script:StaleDcTargets.Add($target.ToLower())
                                Write-IdentIRLog -Message "Identified stale DC target: $target" -TypeName 'Info' -ForegroundColor Yellow
                            }
                        }

                        if ($ip -and $isDcRelated -and $ip -notin $activeDcIps -and $ip -notin $script:ExcludedDcIps -and $ip -notin $script:StaleDcIps) {
                            $script:StaleDcIps.Add($ip)
                            Write-IdentIRLog -Message "Identified stale DC IP: $ip for $recordFqdn" -TypeName 'Info' -ForegroundColor Yellow
                        }
                    }
                }
            }

            # === SECOND PASS: REMOVE STALE RECORDS ===
            foreach ($dnsServer in $DnsServers) {
                Write-IdentIRLog -Message "Processing DNS server: $dnsServer (Second Pass)" -TypeName 'Info' -ForegroundColor Green
                $zones = Run-Dns $dnsServer 'Get-DnsServerZone' @{ComputerName=$dnsServer; ErrorAction='Stop'} |
                    Where-Object { $_.ZoneType -eq 'Primary' -and $_.ZoneName -notin 'TrustAnchors','0.in-addr.arpa','127.in-addr.arpa','255.in-addr.arpa' }
                if ($IncludePtrRecords) { $zones += Run-Dns $dnsServer 'Get-DnsServerZone' @{ComputerName=$dnsServer} | Where-Object { $_.ZoneName -like '*.in-addr.arpa' } }

                foreach ($zone in $zones) {
                    Write-IdentIRLog -Message "Second pass: Processing zone: $($zone.ZoneName) on $dnsServer" -TypeName 'Info' -ForegroundColor Cyan
                    $records = Run-Dns $dnsServer 'Get-DnsServerResourceRecord' @{ZoneName=$zone.ZoneName; ComputerName=$dnsServer; ErrorAction='SilentlyContinue'}
                    if (-not $records) { continue }

                    foreach ($r in $records) {
                        if ($RecordTypes -notcontains $r.RecordType -and (-not $IncludePtrRecords -or $r.RecordType -ne 'PTR')) { continue }
                        $target = $null; $ip = $null
                        switch ($r.RecordType) {
                            'NS' { $target = $r.RecordData.NameServer.TrimEnd('.') }
                            'A' { 
                                $ipv4 = $r.RecordData.IPv4Address
                                $ip = if ($ipv4 -is [string]) { $ipv4 } elseif ($ipv4) { $ipv4.IPAddressToString } else { $null }
                            }
                            'CNAME' { $target = $r.RecordData.HostNameAlias.TrimEnd('.') }
                            'SRV' { $target = $r.RecordData.DomainName.TrimEnd('.') }
                            'PTR' { $target = $r.RecordData.PtrDomainName.TrimEnd('.') }
                        }
                        $recordFqdn = if ($r.HostName -eq '@' -or $r.HostName -notlike '*.*') { "$($r.HostName).$($zone.ZoneName)" } else { $r.HostName }
                        $isStale = ($target -and $target.ToLower() -in $script:StaleDcTargets) -or ($ip -and $ip -in $script:StaleDcIps)
                        if (-not $isStale) { continue }

                        $targetValue = if ($target) { $target } else { $ip }
                        $enriched = [PSCustomObject]@{
                            ZoneName = $zone.ZoneName
                            RecordType = $r.RecordType
                            HostName = $r.HostName
                            Target = $targetValue
                            DnsServer = $dnsServer
                            RecordObject = $r
                            DnsGuid = if ($r.HostName -match '^[0-9a-f-]{36}$') { $r.HostName } else { $null }
                        }
                        $script:StaleDnsRecords.Add($enriched)

                        if ($PSCmdlet.ShouldProcess("$($r.HostName) [$($r.RecordType)]", "Remove from zone $($zone.ZoneName) on $dnsServer")) {
                            if ($Execute) {
                                try {
                                    Run-Dns $dnsServer 'Remove-DnsServerResourceRecord' @{
                                        ZoneName = $zone.ZoneName
                                        ComputerName = $dnsServer
                                        InputObject = $r
                                        Force = $true
                                        ErrorAction = 'Stop'
                                    }
                                    Write-IdentIRLog -Message "Deleted $($r.RecordType) record $($r.HostName) with data $targetValue" -TypeName 'Info' -ForegroundColor Green
                                } catch {
                                    Write-IdentIRLog -Message "Failed to delete $($r.HostName) [$($r.RecordType)] in $($zone.ZoneName) on ${dnsServer}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                                }
                            } else {
                                Write-IdentIRLog -Message "[WhatIf] Would delete $($r.RecordType) record $($r.HostName) with data $targetValue" -TypeName 'Info' -ForegroundColor Yellow
                            }
                        }
                    }
                }
            }

            if ($script:StaleDnsRecords.Count -eq 0) {
                Write-IdentIRLog -Message "No stale DNS records found" -TypeName 'Info' -ForegroundColor Green
            } else {
                Write-IdentIRLog -Message "Found $($script:StaleDnsRecords.Count) stale DNS record(s)" -TypeName 'Warning' -ForegroundColor Yellow
                if (-not $Execute) {
                    Write-IdentIRLog -Message "Dry run: The following records are stale and would be deleted:" -TypeName 'Info' -ForegroundColor Cyan -PrependNewLine
                    $script:StaleDnsRecords | Format-Table ZoneName, RecordType, HostName, Target, DnsServer -AutoSize
                }
            }
        } catch {
            Write-IdentIRLog -Message "Error in Invoke-DnsCleanup: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            throw
        }
    }

    end {
        Write-IdentIRLog -Message "DNS cleanup completed successfully" -TypeName 'Info' -ForegroundColor Green
        foreach ($dc in $script:DcList) {
            Write-IdentIRLog -Message "Processing $($dc.FQDN) completed" -TypeName 'Info' -ForegroundColor Green
        }
        Write-IdentIRLog -Message "Invoke-DnsCleanup completed. Sites processed: $($script:SitesProcessed -join ', ')" -TypeName 'Info' -ForegroundColor Green
        return $script:StaleDnsRecords
    }
}
