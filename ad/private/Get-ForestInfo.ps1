<#
    .SYNOPSIS
    Discovers and inventories Active Directory domain controllers across the current forest.

    .DESCRIPTION
    Get-ForestInfo enumerates NTDS Settings objects under the forest Configuration
    naming context (CN=Sites,...) to identify all domain controllers, then:

    * Resolves associated server and computer objects.
    * Derives domain names, domain SIDs, and default naming contexts.
    * Determines GC, RODC, and PDC status.
    * Resolves IPv4 addresses and AD site membership.
    * Tests LDAP 389 connectivity to mark DCs as Online/Offline.
    * Classifies each DC as Forest Root, Child Domain, or Tree Root.

    Per-DC work is parallelized through a runspace pool. When -MaxConcurrent is not
    specified, a dynamic value is chosen based on the number of DCs and processor
    count, capped at 32.

    Logging is performed via Write-IdentIRLog. When -WinStyleHidden is specified,
    console output is suppressed, but logging still occurs.

    .PARAMETER Credential
    Specifies alternate credentials to use for all LDAP and configuration queries.
    Useful for isolated or recovery environments where the current logon context
    does not have forest-wide visibility.

    When omitted, the current logon context is used. This function does not prompt
    interactively for credentials; callers are responsible for providing them.

    .PARAMETER WinStyleHidden
    Suppresses console output for quieter operation (e.g., when called from a GUI
    or hidden console window). Logging via Write-IdentIRLog continues as normal.

    .PARAMETER MaxConcurrent
    Sets the maximum number of parallel runspaces used to process DC inventory
    work items. If omitted, a dynamic value is calculated based on processor count
    and the number of discovered DCs, with a hard cap of 32.

    .EXAMPLE
    # Discover DCs in the current forest using the current logon context
    $dcs = Get-ForestInfo

    .EXAMPLE
    # Discover DCs in a recovery environment using explicit credentials
    $cred = Get-Credential
    $dcs  = Get-ForestInfo -Credential $cred -WinStyleHidden

    .EXAMPLE
    # Discover DCs with constrained parallelism
    $dcs = Get-ForestInfo -MaxConcurrent 8

    .OUTPUTS
    PSCustomObject

    Returns one object per domain controller with (at minimum) the following
    properties:

    * Type                       (Forest Root | Child Domain | Tree Root | Unknown)
    * Domain                     (FQDN)
    * DomainSid                  (string SID)
    * Site                       (AD site name)
    * SamAccountName             (DC computer account sAMAccountName)
    * NetBIOS                    (NetBIOS name)
    * FQDN                       (DNS host name)
    * IsGC                       (bool)
    * IsRODC                     (bool)
    * IPv4Address                (string, one or more IPv4 addresses)
    * Online                     (bool, based on LDAP 389 test)
    * DistinguishedName          (DC computer DN)
    * ServerReferenceBL          (NTDS Settings DN)
    * IsPdcRoleOwner             (bool)
    * DefaultNamingContext       (domain DN)
    * ConfigurationNamingContext (forest configuration DN)
    * DnsGuid                    (string GUID / DnsHostName GUID)
    * ForestRootFQDN             (forest root domain FQDN)

    .NOTES
    Author:  NightCityShogun
    Version: 1.9
    Requires: PowerShell 5.1+, System.DirectoryServices, System.DirectoryServices.ActiveDirectory
    Privileges: Domain / Enterprise admin privileges recommended for full visibility.
    © 2025 NightCityShogun. All rights reserved.
    #>
function Get-ForestInfo {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$WinStyleHidden,
        [int]$MaxConcurrent
    )

    begin {
        $domainList = New-Object 'System.Collections.Generic.List[PSObject]'

        [void][System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices')
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices.ActiveDirectory')
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Core')

        $searcher    = $null
        $ntdsObjects = $null
    }

    process {
        try {
            if (-not $WinStyleHidden) {
                Write-IdentIRLog -Message "Starting forest discovery." -TypeName "Info" -ForegroundColor White
            }

            $forest           = $null
            $rootDSE          = $null
            $forestRootDomain = $null

            # Try to resolve forest via current context (non-fatal if it fails)
            try {
                $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Get-ForestInfo: GetCurrentForest() failed, continuing with RootDSE only: $($_.Exception.Message)" -TypeName "Warning" -ForegroundColor Yellow
                }
            }

            $rootDsePath = "LDAP://RootDSE"
            if ($Credential) {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry(
                    $rootDsePath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
            } else {
                $rootDSE = [ADSI]$rootDsePath
            }

            if (-not $rootDSE) {
                Write-IdentIRLog -Message "Get-ForestInfo: Unable to bind to LDAP://RootDSE. Ensure a DC is reachable." -TypeName "Error" -ForegroundColor Red
                return
            }

            try {
                $rootDSE.RefreshCache()
            } catch {
                Write-IdentIRLog -Message "Get-ForestInfo: RootDSE.RefreshCache() failed: $($_.Exception.Message)" -TypeName "Error" -ForegroundColor Red
                return
            }

            # Forest root domain: prefer Forest object, fall back to RootDSE
            if ($forest) {
                $forestRootDomain = $forest.RootDomain.Name.ToLower()
            } else {
                try {
                    $rootDomainNC = $rootDSE.Properties['rootDomainNamingContext'][0].ToString()
                    $forestRootDomain = (
                        $rootDomainNC -split ',' |
                        Where-Object { $_ -like 'DC=*' } |
                        ForEach-Object { $_ -replace '^DC=' }
                    ) -join '.'
                    $forestRootDomain = $forestRootDomain.ToLower()
                } catch {
                    Write-IdentIRLog -Message "Get-ForestInfo: Unable to derive forest root domain: $($_.Exception.Message)" -TypeName "Error" -ForegroundColor Red
                    return
                }
            }

            $configNC = $rootDSE.Properties['configurationNamingContext'][0].ToString()

            # -------- Query NTDS Settings (DCs) --------
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            if ($Credential) {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(
                    "LDAP://CN=Sites,$configNC",
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
            } else {
                $searcher.SearchRoot = [ADSI]"LDAP://CN=Sites,$configNC"
            }

            if (-not $searcher.SearchRoot) {
                Write-IdentIRLog -Message "Get-ForestInfo: Unable to bind to LDAP://CN=Sites,$configNC." -TypeName "Error" -ForegroundColor Red
                return
            }

            $searcher.Filter   = "(objectClass=nTDSDSA)"
            $searcher.PageSize = 1000
            [void]$searcher.PropertiesToLoad.Add("distinguishedName")
            [void]$searcher.PropertiesToLoad.Add("serverReference")
            [void]$searcher.PropertiesToLoad.Add("objectGUID")

            try {
                $ntdsObjects = $searcher.FindAll()
            } catch {
                Write-IdentIRLog -Message "Get-ForestInfo: NTDS search failed: $($_.Exception.Message)" -TypeName "Error" -ForegroundColor Red
                return
            }

            if (-not $ntdsObjects -or $ntdsObjects.Count -eq 0) {
                Write-IdentIRLog -Message "Get-ForestInfo: No NTDS Settings objects found in CN=Sites,$configNC." -TypeName "Error" -ForegroundColor Red
                return
            }

            # -------- Build work items (one per DC) --------
            $workItems = @()

            foreach ($ntds in $ntdsObjects) {
                $ntdsDN = if ($ntds.Properties['distinguishedName'] -and $ntds.Properties['distinguishedName'][0]) {
                    $ntds.Properties['distinguishedName'][0].ToString()
                } else { $null }

                if (-not $ntdsDN) { continue }

                # serverDN from serverReference or NTDS parent
                $serverDN = if ($ntds.Properties['serverReference'] -and $ntds.Properties['serverReference'][0]) {
                    $ntds.Properties['serverReference'][0].ToString()
                } else {
                    if ($ntdsDN -like "CN=NTDS Settings,*") {
                        ($ntdsDN -split ',', 2)[1]
                    } else {
                        $null
                    }
                }

                if (-not $serverDN) { continue }

                # Server object in Configuration NC
                if ($Credential) {
                    $serverEntry = New-Object System.DirectoryServices.DirectoryEntry(
                        "LDAP://$serverDN",
                        $Credential.UserName,
                        $Credential.GetNetworkCredential().Password
                    )
                } else {
                    $serverEntry = [ADSI]"LDAP://$serverDN"
                }

                if (-not $serverEntry -or -not $serverEntry.dNSHostName) { continue }

                $fqdn = $serverEntry.dNSHostName.ToString().ToLower()
                if ([string]::IsNullOrWhiteSpace($fqdn)) { continue }

                # Convert objectGUID -> DnsGuid
                $dnsGuid = $null
                if ($ntds.Properties['objectGUID'] -and $ntds.Properties['objectGUID'][0]) {
                    try {
                        $guidBytes = $ntds.Properties['objectGUID'][0]
                        $dnsGuid   = (New-Object System.Guid -ArgumentList (, $guidBytes)).ToString()
                    } catch {
                        if (-not $WinStyleHidden) {
                            Write-IdentIRLog -Message "Get-ForestInfo: Failed to convert objectGUID for ${ntdsDN}: $($_.Exception.Message)" -TypeName "Warning" -ForegroundColor Yellow
                        }
                    }
                }

                $workItems += [PSCustomObject]@{
                    NtdsDN         = $ntdsDN
                    ServerDN       = $serverDN
                    FQDN           = $fqdn
                    DnsGuid        = $dnsGuid
                    ConfigNC       = $configNC
                    ForestRootFQDN = $forestRootDomain
                }
            }

            if ($workItems.Count -eq 0) {
                Write-IdentIRLog -Message "Get-ForestInfo: No valid NTDS/Server pairs discovered in the forest." -TypeName "Error" -ForegroundColor Red
                return
            }

            # -------- Dynamic concurrency if not specified --------
            if (-not $PSBoundParameters.ContainsKey("MaxConcurrent") -or $MaxConcurrent -lt 1) {
                $workCount = $workItems.Count
                $cores     = [Environment]::ProcessorCount
                $base      = [Math]::Ceiling($cores * 1.5)
                $hardCap   = 32

                $calc = [Math]::Min([Math]::Min($base, $hardCap), $workCount)

                if ($calc -lt 4 -and $workCount -ge 4) { $calc = 4 }
                if ($calc -lt 1) { $calc = 1 }

                $MaxConcurrent = [int]$calc
            }

            if (-not $WinStyleHidden) {
                $msg = "Get-ForestInfo: Discovered {0} NTDS objects. Using MaxConcurrent={1} (Cores={2})." -f $workItems.Count, $MaxConcurrent, [Environment]::ProcessorCount
                Write-IdentIRLog -Message $msg -TypeName "Info" -ForegroundColor White
            }

            # -------- Runspace pool setup --------
            $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrent)
            $runspacePool.Open()

            $jobs = @()

            foreach ($item in $workItems) {
                $ps = [PowerShell]::Create()
                $ps.RunspacePool = $runspacePool

                [void]$ps.AddScript({
                    param(
                        $WorkItem,
                        [System.Management.Automation.PSCredential]$Cred
                    )

                    [void][System.Reflection.Assembly]::LoadWithPartialName('System.DirectoryServices')

                    $ntdsDN         = $WorkItem.NtdsDN
                    $serverDN       = $WorkItem.ServerDN
                    $fqdn           = $WorkItem.FQDN
                    $dnsGuid        = $WorkItem.DnsGuid
                    $configNC       = $WorkItem.ConfigNC
                    $forestRootFQDN = $WorkItem.ForestRootFQDN

                    if (-not $ntdsDN -or -not $serverDN -or -not $fqdn) {
                        return $null
                    }

                    # ---------- 1) Online test (LDAP 389, 500ms) ----------
                    $online = $false
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $ar  = $tcp.BeginConnect($fqdn, 389, $null, $null)
                        if ($ar.AsyncWaitHandle.WaitOne(500, $false) -and $tcp.Connected) {
                            $tcp.EndConnect($ar)
                            $online = $true
                        }
                    } catch {
                    } finally {
                        if ($tcp) { $tcp.Close() }
                    }

                    # ---------- 2) Server entry (Configuration NC) ----------
                    if ($Cred) {
                        $serverEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            "LDAP://$serverDN",
                            $Cred.UserName,
                            $Cred.GetNetworkCredential().Password
                        )
                    } else {
                        $serverEntry = [ADSI]"LDAP://$serverDN"
                    }

                    # Site from serverDN (CN=Server,CN=<Site>,CN=Servers,...)
                    $site = $null
                    try {
                        $parts = $serverDN -split ','
                        if ($parts.Length -ge 3) {
                            $site = $parts[2] -replace '^CN=', ''
                        }
                    } catch { }

                    # ---------- 3) Domain DN + name ----------
                    $domainDN   = $null
                    $domainName = "Unknown"
                    try {
                        if ($serverEntry -and $serverEntry.serverReference) {
                            $srvRef = $serverEntry.serverReference
                            if ($srvRef) {
                                $domainDN = ($srvRef -split ',' | Where-Object { $_ -like 'DC=*' }) -join ','
                            }
                        }
                        if ($domainDN) {
                            $domainName = (
                                $domainDN -split ',' |
                                Where-Object { $_ -like 'DC=*' } |
                                ForEach-Object { $_ -replace '^DC=' }
                            ) -join '.'
                        }
                    } catch { }

                    # ---------- 4) Domain entry (SID + FSMO) ----------
                    $domainEntry = $null
                    if ($domainDN) {
                        # Pin to this DC's FQDN so we do not depend on DC Locator
                        if ($fqdn) {
                            $ldapPath = "LDAP://$fqdn/$domainDN"
                        } else {
                            $ldapPath = "LDAP://$domainDN"
                        }

                        if ($Cred) {
                            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry(
                                $ldapPath,
                                $Cred.UserName,
                                $Cred.GetNetworkCredential().Password
                            )
                        } else {
                            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                        }
                    }

                    $domainSid = $null
                    if ($domainEntry -and $domainEntry.objectSid) {
                        try {
                            $sidBytes = $domainEntry.objectSid[0]
                            $sidObj   = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                            $domainSid = $sidObj.Value
                        } catch { }
                    }

                    # PDC role (compare fSMORoleOwner to this NTDS DN)
                    $isPdc = $false
                    if ($domainEntry -and $domainEntry.fSMORoleOwner) {
                        try {
                            $fsmo = $domainEntry.fSMORoleOwner.ToString()
                            if ($fsmo.ToLower() -eq $ntdsDN.ToLower()) {
                                $isPdc = $true
                            }
                        } catch { }
                    }

                    # ---------- 5) Computer object (DC) ----------
                    $dcName            = $null
                    $samAccountName    = $null
                    $distinguishedName = $null
                    $isGC              = $false
                    $isRODC            = $false

                    if ($domainDN) {
                        $compSearcher = New-Object System.DirectoryServices.DirectorySearcher

                        # Pin search root to this DC
                        if ($fqdn) {
                            $searchRootPath = "LDAP://$fqdn/$domainDN"
                        } else {
                            $searchRootPath = "LDAP://$domainDN"
                        }

                        if ($Cred) {
                            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry(
                                $searchRootPath,
                                $Cred.UserName,
                                $Cred.GetNetworkCredential().Password
                            )
                        } else {
                            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry($searchRootPath)
                        }

                        $compSearcher.SearchRoot = $searchRoot
                        $compSearcher.Filter = "(&(objectCategory=computer)(dNSHostName=$fqdn))"
                        $compSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                        $compSearcher.PageSize = 1
                        [void]$compSearcher.PropertiesToLoad.Add("name")
                        [void]$compSearcher.PropertiesToLoad.Add("sAMAccountName")
                        [void]$compSearcher.PropertiesToLoad.Add("distinguishedName")
                        [void]$compSearcher.PropertiesToLoad.Add("msDS-isGC")
                        [void]$compSearcher.PropertiesToLoad.Add("msDS-isRODC")

                        try {
                            $computer = $compSearcher.FindOne()
                            if ($computer) {
                                if ($computer.Properties['name'].Count -gt 0) {
                                    $dcName = $computer.Properties['name'][0]
                                }
                                if ($computer.Properties['sAMAccountName'].Count -gt 0) {
                                    $samAccountName = $computer.Properties['sAMAccountName'][0]
                                }
                                if ($computer.Properties['distinguishedName'].Count -gt 0) {
                                    $distinguishedName = $computer.Properties['distinguishedName'][0]
                                }
                                if ($computer.Properties['msDS-isGC'].Count -gt 0) {
                                    $isGC = [bool]$computer.Properties['msDS-isGC'][0]
                                }
                                if ($computer.Properties['msDS-isRODC'].Count -gt 0) {
                                    $isRODC = [bool]$computer.Properties['msDS-isRODC'][0]
                                }
                            }
                        } catch { }
                        finally {
                            if ($compSearcher) { $compSearcher.Dispose() }
                        }
                    }

                    # ---------- 6) IPv4 resolution ----------
                    $ipv4 = "Unknown"
                    try {
                        $addrs = [System.Net.Dns]::GetHostAddresses($fqdn) |
                                 Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                                 ForEach-Object { $_.IPAddressToString }
                        if ($addrs -and $addrs.Count -gt 0) {
                            $ipv4 = ($addrs -join ", ")
                        }
                    } catch { }

                    # ---------- 7) Type classification ----------
                    $type = "Unknown"
                    if ($domainName -ne "Unknown") {
                        $lowerDomain = $domainName.ToLower()
                        if ($lowerDomain -eq $forestRootFQDN) {
                            $type = "Forest Root"
                        } elseif ($lowerDomain.EndsWith(".$forestRootFQDN")) {
                            $type = "Child Domain"
                        } else {
                            $type = "Tree Root"
                        }
                    }

                    return [PSCustomObject]@{
                        Type                       = $type
                        Domain                     = $domainName
                        DomainSid                  = $domainSid
                        Site                       = $site
                        SamAccountName             = $samAccountName
                        NetBIOS                    = $dcName
                        FQDN                       = $fqdn
                        IsGC                       = $isGC
                        IsRODC                     = $isRODC
                        IPv4Address                = $ipv4
                        Online                     = $online
                        DistinguishedName          = $distinguishedName
                        ServerReferenceBL          = $ntdsDN
                        IsPdcRoleOwner             = $isPdc
                        DefaultNamingContext       = $domainDN
                        ConfigurationNamingContext = $configNC
                        DnsGuid                    = $dnsGuid
                        ForestRootFQDN             = $forestRootFQDN
                    }

                }).AddParameter("WorkItem", $item).
                  AddParameter("Cred", $Credential)

                $handle = $ps.BeginInvoke()
                $jobs += [PSCustomObject]@{
                    PowerShell = $ps
                    Handle     = $handle
                }
            }

            # -------- Collect results --------
            foreach ($job in $jobs) {
                try {
                    $results = $job.PowerShell.EndInvoke($job.Handle)
                    foreach ($obj in $results) {
                        if ($obj -ne $null) {
                            $domainList.Add($obj)
                        }
                    }
                } catch {
                    if (-not $WinStyleHidden) {
                        Write-IdentIRLog -Message "Get-ForestInfo: Per-DC runspace failed: $($_.Exception.Message)" -TypeName "Warning" -ForegroundColor Yellow
                    }
                } finally {
                    $job.PowerShell.Dispose()
                }
            }

            $runspacePool.Close()
            $runspacePool.Dispose()

            if (-not $WinStyleHidden) {
                $msg = "Get-ForestInfo: Completed. DC objects returned: {0}." -f $domainList.Count
                Write-IdentIRLog -Message $msg -TypeName "Info" -ForegroundColor Green
            }
        }
        catch {
            Write-IdentIRLog -Message "Get-ForestInfo: Fatal error: $($_.Exception.Message)" -TypeName "Error" -ForegroundColor Red
        }
        finally {
            if ($ntdsObjects) { $ntdsObjects.Dispose() }
            if ($searcher)     { $searcher.Dispose() }
        }
    }

    end {
        return $domainList
    }
}
