<#
.SYNOPSIS
Enumerates all domain controllers in the current forest and returns a normalized inventory.

.DESCRIPTION
Get-ForestInfo queries the forest’s Configuration NC for NTDS Settings (DCs), resolves server
objects, converts objectGUID to DnsGuid, maps each DC to its domain/site, and validates LDAP
reachability (port 389) in parallel via Test-OnlineStatus. Offline/unreachable DCs are flagged.
Supports alternate credentials. Logging uses Write-IdentIRLog and can be quieted with -WinStyleHidden.

.PARAMETER Credential
Optional PSCredential for LDAP binds (RootDSE, CN=Sites,…, per-DC/domain queries).

.PARAMETER WinStyleHidden
Suppresses informational logging (keeps errors/warnings minimal).

.EXAMPLE
# Basic discovery with default creds and logging
Get-ForestInfo

.EXAMPLE
# Run with alternate creds and minimal console output
$cred = Get-Credential
Get-ForestInfo -Credential $cred -WinStyleHidden

.OUTPUTS
[System.Collections.Generic.List[psobject]]
Each object includes:
 Type, Domain, DomainSid, Site, SamAccountName, NetBIOS, FQDN, IsGC, IsRODC, IPv4Address,
 Online, DistinguishedName, ServerReferenceBL, IsPdcRoleOwner, DefaultNamingContext,
 ConfigurationNamingContext, DnsGuid, ForestRootFQDN

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: LDAP (389), ADSI/.NET DirectoryServices, Test-OnlineStatus helper, DNS resolution.
© 2025 NightCityShogun. All rights reserved.
#>

function Get-ForestInfo {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Management.Automation.PSCredential] $Credential,
        [switch]$WinStyleHidden
    )
    $domainList = New-Object 'System.Collections.Generic.List[PSObject]'
    try {
        if (-not $WinStyleHidden) {
            Write-IdentIRLog -Message "Querying forest for domain controllers" -TypeName 'Info' -ForegroundColor White
        }
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $forestRootDomain = $forest.RootDomain.Name.ToLower()
        $dcCandidates = New-Object 'System.Collections.Generic.List[PSObject]'
        # Get RootDSE for naming contexts
        $rootDSE = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            [ADSI]"LDAP://RootDSE"
        }
        if ($null -eq $rootDSE) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Failed to connect to LDAP://RootDSE. Ensure a DC is reachable and credentials are valid. Verify DNS (Resolve-DnsName $env:USERDNSDOMAIN)." -TypeName 'Error' -ForegroundColor Red
            }
            return $domainList
        }
        try {
            $rootDSE.RefreshCache()
        } catch {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Failed to refresh RootDSE: $($_.Exception.Message). Verify DNS (Resolve-DnsName $env:USERDNSDOMAIN) and LDAP (Test-NetConnection -Port 389)." -TypeName 'Error' -ForegroundColor Red
            }
            return $domainList
        }
        $configNC = $rootDSE.Properties["configurationNamingContext"][0].ToString()
        # Query NTDS Settings objects in the Configuration partition
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Sites,$configNC", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else {
            [ADSI]"LDAP://CN=Sites,$configNC"
        }
        if ($null -eq $searcher.SearchRoot) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Failed to connect to LDAP://CN=Sites,$configNC. Ensure the Configuration partition is accessible." -TypeName 'Error' -ForegroundColor Red
            }
            return $domainList
        }
        $searcher.Filter = "(objectClass=ntdsDsa)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "serverReference", "objectGUID"))
        $ntdsObjects = $searcher.FindAll()
        if ($null -eq $ntdsObjects -or $ntdsObjects.Count -eq 0) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "No NTDS Settings objects found in the forest. Verify AD health (dcdiag /s:<DC>)." -TypeName 'Error' -ForegroundColor Red
            }
            return $domainList
        }
        # Early online status check
        $potentialDCs = @()
        foreach ($ntds in $ntdsObjects) {
            $serverDN = if ($ntds.Properties["serverReference"] -and $ntds.Properties["serverReference"][0]) {
                $ntds.Properties["serverReference"][0].ToString()
            } else {
                $ntdsDN = if ($ntds.Properties["distinguishedName"] -and $ntds.Properties["distinguishedName"][0]) {
                    $ntds.Properties["distinguishedName"][0].ToString()
                }
                if ($ntdsDN -and $ntdsDN -like "CN=NTDS Settings,*") {
                    ($ntdsDN -split ',',2)[1]
                } else {
                    $null
                }
            }
            if ($serverDN) {
                $serverEntry = if ($Credential) {
                    New-Object System.DirectoryServices.DirectoryEntry("LDAP://$serverDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
                } else {
                    [ADSI]"LDAP://$serverDN"
                }
                if ($serverEntry -and $serverEntry.dNSHostName) {
                    $fqdn = $serverEntry.dNSHostName.ToString().ToLower()
                    if ($fqdn) { $potentialDCs += $fqdn }
                }
            }
        }
        $onlineDCs = @{}
        if ($potentialDCs.Count -gt 0) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Testing online status for $($potentialDCs.Count) potential DCs in parallel (500ms timeout)." -TypeName 'Info' -ForegroundColor White
            }
            $testParams = @{
                ComputerNames = $potentialDCs
                Port = 389
                TimeoutMilliseconds = 500
                MaxConcurrent = 10
            }
            if ($WinStyleHidden) {
                $testParams['WinStyleHidden'] = $true
            }
            try {
                $onlineDCs = Test-OnlineStatus @testParams
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to test online status: $($_.Exception.Message). Proceeding with available DCs." -TypeName 'Warning' -ForegroundColor Yellow
                }
            }
        }
        foreach ($ntds in $ntdsObjects) {
            $ntdsDN = if ($ntds.Properties["distinguishedName"] -and $ntds.Properties["distinguishedName"][0]) {
                $ntds.Properties["distinguishedName"][0].ToString()
            } else {
                $null
            }
            $serverDN = if ($ntds.Properties["serverReference"] -and $ntds.Properties["serverReference"][0]) {
                $ntds.Properties["serverReference"][0].ToString()
            } else {
                if ($ntdsDN -and $ntdsDN -like "CN=NTDS Settings,*") {
                    ($ntdsDN -split ',',2)[1]
                } else {
                    $null
                }
            }
            $dnsGuid = if ($ntds.Properties["objectGUID"] -and $ntds.Properties["objectGUID"][0]) {
                try {
                    $guidBytes = $ntds.Properties["objectGUID"][0]
                    $guidString = [System.Guid]::new($guidBytes).ToString()
                    if (-not $WinStyleHidden) {
                        Write-IdentIRLog -Message "Converted objectGUID for NTDS object ${ntdsDN} to string: ${guidString}" -TypeName 'Info' -ForegroundColor White
                    }
                    $guidString
                } catch {
                    $hexBytes = if ($ntds.Properties["objectGUID"][0]) {
                        ($ntds.Properties["objectGUID"][0] | ForEach-Object { $_.ToString("X2") }) -join ""
                    } else {
                        "None"
                    }
                    if (-not $WinStyleHidden) {
                        Write-IdentIRLog -Message "Failed to convert objectGUID for NTDS object ${ntdsDN}. Raw hex bytes: ${hexBytes}. Error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    }
                    $null
                }
            } else {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "objectGUID missing or empty for NTDS object ${ntdsDN}. DnsGuid will be null." -TypeName 'Warning' -ForegroundColor Yellow
                }
                $null
            }
            if (-not $ntdsDN -or -not $serverDN) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Invalid NTDS object: ntdsDN=${ntdsDN}, serverDN=${serverDN}. Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            # Get server object details
            $serverEntry = if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$serverDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                [ADSI]"LDAP://$serverDN"
            }
            if ($null -eq $serverEntry) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to connect to LDAP://$serverDN. Verify LDAP (Test-NetConnection -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            try {
                $serverEntry.RefreshCache()
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to refresh server entry for ${serverDN}: $($_.Exception.Message). Verify LDAP (Test-NetConnection -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            $fqdn = if ($serverEntry.dNSHostName) { $serverEntry.dNSHostName.ToString().ToLower() } else { $null }
            $domainDN = ($serverEntry.serverReference -split ',' | Where-Object { $_ -match '^DC=' }) -join ','
            $domainName = ($domainDN -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=' }) -join '.'
            if (-not $fqdn -or -not $domainDN) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Invalid server entry for ${serverDN}: fqdn=${fqdn}, domainDN=${domainDN}. Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            # Skip offline DCs
            if (-not $onlineDCs.ContainsKey($fqdn) -or -not $onlineDCs[$fqdn]) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "DC ${fqdn} is offline or unreachable (LDAP port 389). Verify with Test-NetConnection ${fqdn} -Port 389. Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            # Get domain details
            $domainEntry = if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$fqdn/$domainDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                [ADSI]"LDAP://$fqdn/$domainDN"
            }
            if ($null -eq $domainEntry) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to connect to LDAP://$fqdn/$domainDN. Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            try {
                $domainEntry.RefreshCache()
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to refresh domain entry for ${fqdn}/${domainDN}: $($_.Exception.Message). Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            $domainSidBytes = $domainEntry.objectSid[0]
            $domainSid = if ($domainSidBytes) {
                try {
                    (New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)).Value
                } catch {
                    if (-not $WinStyleHidden) {
                        Write-IdentIRLog -Message "Failed to convert Domain SID for ${fqdn}/${domainDN}: $($_.Exception.Message). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                    }
                    continue
                }
            } else {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Domain SID is null for ${fqdn}/${domainDN}. Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            # Check PDC Emulator status
            $pdcEntry = if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$fqdn/$domainDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                [ADSI]"LDAP://$fqdn/$domainDN"
            }
            if ($null -eq $pdcEntry) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to connect to LDAP://$fqdn/$domainDN for PDC check. Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            try {
                $pdcEntry.RefreshCache()
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to refresh PDC entry for ${fqdn}/${domainDN}: $($_.Exception.Message). Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            $isPdc = if ($pdcEntry.fSMORoleOwner) { $pdcEntry.fSMORoleOwner.ToString() -eq $ntdsDN } else { $false }
            # Get computer object for additional properties
            $computerSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $computerSearcher.SearchRoot = if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN", $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                [ADSI]"LDAP://$domainDN"
            }
            if ($null -eq $computerSearcher.SearchRoot) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to connect to LDAP://$domainDN for computer search. Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            $computerSearcher.Filter = "(&(objectCategory=computer)(dNSHostName=$fqdn))"
            $computerSearcher.PropertiesToLoad.AddRange(@("name", "sAMAccountName", "distinguishedName", "msDS-isGC", "msDS-isRODC"))
            try {
                $computer = $computerSearcher.FindOne()
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to search for computer object for ${fqdn}: $($_.Exception.Message). Verify LDAP (Test-NetConnection ${fqdn} -Port 389). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            if ($null -eq $computer) {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to find computer object for ${fqdn}. Verify AD configuration (Get-ADComputer -Identity $($fqdn -split '\.')[0] -Server $fqdn). Skipping." -TypeName 'Warning' -ForegroundColor Yellow
                }
                continue
            }
            $dcName = $computer.Properties["name"][0]
            $site = ($serverDN -split ',')[2] -replace '^CN='
            $isGC = if ($computer.Properties["msDS-isGC"].Count -gt 0) { [bool]$computer.Properties["msDS-isGC"][0] } else { $false }
            $isRODC = if ($computer.Properties["msDS-isRODC"].Count -gt 0) { [bool]$computer.Properties["msDS-isRODC"][0] } else { $false }
            # Get IP address
            $ipv4List = try {
                [System.Net.Dns]::GetHostAddresses($fqdn) |
                    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                    ForEach-Object { $_.IPAddressToString }
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "IP resolution failed for ${fqdn}: $($_.Exception.Message). Setting to 'Unknown'." -TypeName 'Warning' -ForegroundColor Yellow
                }
                @("Unknown")
            }
            $dcCandidates.Add([PSCustomObject]@{
                Type = if ($domainName.ToLower() -eq $forestRootDomain) { "Forest Root" } elseif ($domainName -like "*.$forestRootDomain") { "Child Domain" } else { "Tree Root" }
                Domain = $domainName
                DomainSid = $domainSid
                Site = $site
                SamAccountName = $computer.Properties["sAMAccountName"][0]
                NetBIOS = $dcName
                FQDN = $fqdn
                IsGC = $isGC
                IsRODC = $isRODC
                IPv4Address = $ipv4List -join ", "
                Online = $true # Confirmed by early online check
                DistinguishedName = $computer.Properties["distinguishedName"][0]
                ServerReferenceBL = $ntdsDN
                IsPdcRoleOwner = $isPdc
                DefaultNamingContext = $domainDN
                ConfigurationNamingContext = $configNC
                DnsGuid = $dnsGuid
                ForestRootFQDN = $forestRootDomain
            })
        }
        if ($dcCandidates.Count -eq 0) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "No domain controllers found after processing NTDS objects. Verify AD health (dcdiag /s:<DC>)." -TypeName 'Warning' -ForegroundColor Yellow
            }
            return $domainList
        }
        # Final online status verification
        $fqdns = $dcCandidates | ForEach-Object { $_.FQDN } | Where-Object { $_ }
        if ($fqdns.Count -eq 0) {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "No valid FQDNs found for online status test. Verify AD configuration (dcdiag /s:<DC>)." -TypeName 'Warning' -ForegroundColor Yellow
            }
            return $domainList
        }
        if (-not $WinStyleHidden) {
            Write-IdentIRLog -Message "Verifying online status for $($fqdns.Count) DCs in parallel (500ms timeout)." -TypeName 'Info' -ForegroundColor White
        }
        $testParams = @{
            ComputerNames = $fqdns
            Port = 389
            TimeoutMilliseconds = 500
            MaxConcurrent = 10
        }
        if ($WinStyleHidden) {
            $testParams['WinStyleHidden'] = $true
        }
        try {
            $ldapResults = Test-OnlineStatus @testParams
        } catch {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Failed to test online status: $($_.Exception.Message). Marking all DCs as offline." -TypeName 'Warning' -ForegroundColor Yellow
            }
            $ldapResults = @{}
        }
        foreach ($dc in $dcCandidates) {
            $fqdnLower = $dc.FQDN.ToLower()
            $ldapAccessible = if ($ldapResults.ContainsKey($fqdnLower)) { [bool]$ldapResults[$fqdnLower] } else { $false }
            $domainList.Add([PSCustomObject]@{
                Type = $dc.Type
                Domain = $dc.Domain
                DomainSid = $dc.DomainSid
                Site = $dc.Site
                SamAccountName = $dc.SamAccountName
                NetBIOS = $dc.NetBIOS
                FQDN = $dc.FQDN
                IsGC = $dc.IsGC
                IsRODC = $dc.IsRODC
                IPv4Address = $dc.IPv4Address
                Online = $ldapAccessible
                DistinguishedName = $dc.DistinguishedName
                ServerReferenceBL = $dc.ServerReferenceBL
                IsPdcRoleOwner = $dc.IsPdcRoleOwner
                DefaultNamingContext = $dc.DefaultNamingContext
                ConfigurationNamingContext = $dc.ConfigurationNamingContext
                DnsGuid = $dc.DnsGuid
                ForestRootFQDN = $dc.ForestRootFQDN
            })
        }
    } catch {
        if (-not $WinStyleHidden) {
            Write-IdentIRLog -Message "Error in Get-ForestInfo: $($_.Exception.Message) at line $($_.ScriptStackTrace). Verify DNS (Resolve-DnsName $env:USERDNSDOMAIN), LDAP (Test-NetConnection -Port 389), and AD health (dcdiag)." -TypeName 'Error' -ForegroundColor Red
        }
    } finally {
        if ($ntdsObjects) { $ntdsObjects.Dispose() }
        if ($computerSearcher) { $computerSearcher.Dispose() }
    }
    return $domainList
}
