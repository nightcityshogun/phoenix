<#
.SYNOPSIS
Resets inter/intra-forest trust passwords (or deletes orphaned trusts) using DCs from an isolated recovery inventory.

.DESCRIPTION
Invoke-TrustPasswordReset discovers Trusted Domain Objects (TDOs) per domain (Forest Root → Child → Tree), prefers the PDC
for operations, and:
- Deletes orphaned trusts (e.g., single-domain recoveries or partners not in the isolated set).
- Resets passwords for valid pairs with one shared secret, updating both sides in correct order (trusting first).
Runs in WhatIf mode unless -Execute is supplied. Requires Domain/Enterprise Admin privileges.

.PARAMETER IsolatedDCList
Inventory of ONLINE DCs (FQDN, Domain, DefaultNamingContext, ConfigurationNamingContext, Type, IsPdcRoleOwner, Online).

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.EXAMPLE
# Simulate full trust sweep and report actions
Invoke-TrustPasswordReset -IsolatedDCList $dcs

.EXAMPLE
# Apply: delete orphans and reset valid trust passwords
Invoke-TrustPasswordReset -IsolatedDCList $dcs -Execute

.OUTPUTS
Writes a summary to the log; increments counters: Passwords Reset, Trusts Deleted, Errors.

.NOTES
Author: NightCityShogun
Version: 1.0
Requires: Domain/Enterprise Admin rights; ADSI; .NET DirectoryServices.
SupportsShouldProcess: True
© 2025 NightCityShogun. All rights reserved.
#>

function Invoke-TrustPasswordReset {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [psobject[]]$IsolatedDCList,
        [Parameter()]
        [switch]$Execute
    )
    
    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest
        
        $whatIfMode = -not $Execute
        $modeText   = if ($whatIfMode) { "WhatIf=True" } else { "WhatIf=False" }
        Write-IdentIRLog -Message "Starting Trust Password Reset ($modeText)" -TypeName 'Info' -ForegroundColor White
        
        # ---- Privilege check ----
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-IdentIRLog -Message "Checking admin privileges for $currentUser" -TypeName 'Info' -ForegroundColor Green
            
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $rootDomain = $forest.RootDomain.Name
            
            $isAdmin = $false
            $userName = $currentUser.Split('\')[-1]
            
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
        
        if (-not $IsolatedDCList) {
            Write-IdentIRLog -Message "No DCs supplied to -IsolatedDCList." -TypeName 'Error' -ForegroundColor Red
            throw "No DCs supplied to -IsolatedDCList."
        }
        
        $acc     = @()
        $resets  = 0
        $deletes = 0
        $errors  = 0
    }
    
    process {
        foreach ($x in $IsolatedDCList) { $acc += ,$x }
    }
    
    end {
        $IsolatedDCList = @($acc)
        if ($IsolatedDCList.Count -eq 0) {
            Write-IdentIRLog -Message "No DCs in accumulator after processing." -TypeName 'Error' -ForegroundColor Red
            throw "No DCs in accumulator."
        }
        
        # --- Forest info ---
        try {
            $forestInfo     = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $ForestRootFqdn = $forestInfo.RootDomain.Name
            Write-IdentIRLog -Message "Forest root: $ForestRootFqdn" -TypeName 'Info' -ForegroundColor White
        } catch {
            Write-IdentIRLog -Message "Failed to get forest info: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
            throw
        }
        
        # --- Validate each DC ---
        foreach ($dc in $IsolatedDCList) {
            if (-not $dc.Type) {
                if ($dc.Domain -ieq $ForestRootFqdn) { $dc.Type = 'Forest Root' }
                elseif ($dc.Domain -like "*.$ForestRootFqdn") { $dc.Type = 'Child Domain' }
                else { $dc.Type = 'Tree Root' }
            }
            if (-not $dc.FQDN -or -not $dc.DefaultNamingContext) {
                Write-IdentIRLog -Message "Invalid DC data - FQDN=$($dc.FQDN), DefaultNC=$($dc.DefaultNamingContext)" -TypeName 'Warning' -ForegroundColor Yellow
                $dc.Online = $false; $errors++; continue
            }
            try {
                $null = [ADSI]"LDAP://$($dc.FQDN)/CN=System,$($dc.DefaultNamingContext)"
                Write-IdentIRLog -Message "Validated DC $($dc.FQDN) for domain $($dc.Domain)" -TypeName 'Info' -ForegroundColor Green
            } catch {
                Write-IdentIRLog -Message "LDAP bind failed for $($dc.FQDN): $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                $dc.Online = $false; $errors++; continue
            }
        }
        
        $onlineDCs = $IsolatedDCList | Where-Object { $_.Online -eq $true }
        if (-not $onlineDCs) { throw "No ONLINE DCs provided." }
        
        # --- Domain groups ---
        $domainGroups   = @{}
        $isolatedDomains = @($onlineDCs | Select-Object -ExpandProperty Domain -Unique)
        
        # Build domain hierarchy map
        $domainHierarchy = @{}
        foreach ($domainName in $isolatedDomains) {
            $depth = ($domainName -split '\.').Count
            $domainHierarchy[$domainName] = $depth
        }
        
        # Order domains: Forest root first, then by depth (shallowest to deepest)
        $orderedDomainsForEnum = @($ForestRootFqdn) + ($isolatedDomains | Where-Object { $_ -ne $ForestRootFqdn } | Sort-Object)
        
        Write-IdentIRLog -Message "Domain processing order: $($orderedDomainsForEnum -join ', ')" -TypeName 'Info' -ForegroundColor Cyan
        
        foreach ($dc in $onlineDCs) {
            if (-not $domainGroups.ContainsKey($dc.Domain)) {
                $domainGroups[$dc.Domain] = [PSCustomObject]@{
                    Domain    = $dc.Domain
                    DCs       = @()
                    Type      = $dc.Type
                    DefaultNC = $dc.DefaultNamingContext
                    ConfigNC  = $dc.ConfigurationNamingContext
                    Depth     = $domainHierarchy[$dc.Domain]
                }
            }
            $domainGroups[$dc.Domain].DCs += ,$dc
        }
        
        $isSingleDomain = ($domainGroups.Count -eq 1)
        Write-IdentIRLog -Message "Single domain forest: $isSingleDomain" -TypeName 'Info' -ForegroundColor White
        
        # --- Helpers ---
        function Get-AnchorDC([pscustomobject]$grp) {
            # Prefer PDC emulator for trust operations per Microsoft guidance
            $p = $grp.DCs | Where-Object { $_.IsPdcRoleOwner -or $_.IsPDC } | Select-Object -First 1
            if ($p) { return [string]$p.FQDN }
            return [string]($grp.DCs | Select-Object -First 1).FQDN
        }
        
        function Get-PairKey([string]$a,[string]$b) {
            $a = $a.ToLowerInvariant(); $b = $b.ToLowerInvariant()
            if ([string]::Compare($a,$b,[StringComparison]::Ordinal) -le 0) { "$a|$b" } else { "$b|$a" }
        }
        
        # --- Trust type mapping ---
        function Get-TrustTypeString([int]$trustType) {
            switch ($trustType) {
                1 { return 'TRUST_TYPE_DOWNLEVEL' }      # Windows domain not running AD
                2 { return 'TRUST_TYPE_UPLEVEL' }        # Windows domain running AD (ParentChild/TreeRoot)
                3 { return 'TRUST_TYPE_MIT' }            # Non-Windows Kerberos
                4 { return 'TRUST_TYPE_DCE' }            # Historical
                5 { return 'TRUST_TYPE_AAD' }            # Azure AD
                default { return "Unknown ($trustType)" }
            }
        }
        
        function Get-TrustDirectionString([int]$trustDirection) {
            switch ($trustDirection) {
                0 { return 'Disabled' }
                1 { return 'Inbound' }      # Local domain is TRUSTED
                2 { return 'Outbound' }     # Local domain is TRUSTING
                3 { return 'Bidirectional' }
                default { return "Unknown ($trustDirection)" }
            }
        }
        
        # --- TDO deletion logic ---
        function Delete-LocalTrust {
            param(
                [Parameter(Mandatory=$true)][string]$AnchorDC,
                [Parameter(Mandatory=$true)][string]$RemoteDomain,
                [Parameter(Mandatory=$true)][string]$DN
            )
            try {
                $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $AnchorDC)
                $dc  = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctx)
                $dom = $dc.Domain
                if ($PSCmdlet.ShouldProcess($dom.Name, "Delete trust with $RemoteDomain")) {
                    $dom.DeleteLocalSideOfTrustRelationship($RemoteDomain)
                    Write-IdentIRLog -Message "Deleted local trust object between $($dom.Name) and $RemoteDomain via API" -TypeName 'Info' -ForegroundColor Green
                    return $true
                }
            } catch {
                Write-IdentIRLog -Message "DeleteLocalSideOfTrustRelationship failed on $AnchorDC for ${RemoteDomain}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }
            
            try {
                $obj = [ADSI]"LDAP://$AnchorDC/$DN"
                if ($obj.Path -and $PSCmdlet.ShouldProcess($DN, "Delete TDO")) {
                    $obj.psbase.DeleteTree()
                    $obj.CommitChanges()
                    Write-IdentIRLog -Message "Deleted trust TDO at $DN on $AnchorDC" -TypeName 'Info' -ForegroundColor Green
                    return $true
                }
            } catch {
                Write-IdentIRLog -Message "ADSI deletion failed on $AnchorDC for DN=${DN}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                return $false
            }
        }
        
        # --- Enumerate trusts with proper direction understanding ---
        Write-IdentIRLog -Message "Enumerating trust objects from all domains..." -TypeName 'Info' -ForegroundColor White
        $allTrustObjects = @()
        
        foreach ($dom in $orderedDomainsForEnum) {
            $server = Get-AnchorDC $domainGroups[$dom]
            $defaultNC = $domainGroups[$dom].DefaultNC
            $root = [ADSI]"LDAP://$server/CN=System,$defaultNC"
            $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
            $ds.Filter = "(objectClass=trustedDomain)"
            $ds.PageSize = 1000
            
            # Retrieve all relevant TDO attributes
            foreach ($p in 'cn','trustPartner','distinguishedName','trustType','trustDirection','trustAttributes') { 
                [void]$ds.PropertiesToLoad.Add($p) 
            }
            
            $res = $ds.FindAll()
            foreach ($r in $res) {
                $cn = [string]$r.Properties['cn'][0]
                $trustPartner = [string]$r.Properties['trustPartner'][0]  # DNS name of TRUSTED domain
                $dn = [string]$r.Properties['distinguishedName'][0]
                
                # trustType: 1=Downlevel, 2=Uplevel (AD), 3=MIT, etc.
                $trustType = if ($r.Properties['trustType']) { 
                    [int]$r.Properties['trustType'][0] 
                } else { 2 }  # Default to Uplevel
                
                # trustDirection: 0=Disabled, 1=Inbound (local is TRUSTED), 2=Outbound (local is TRUSTING), 3=Bidirectional
                $trustDirection = if ($r.Properties['trustDirection']) { 
                    [int]$r.Properties['trustDirection'][0] 
                } else { 3 }  # Default to bidirectional for intra-forest
                
                # trustAttributes: Check for WITHIN_FOREST (0x00000020) to identify parent-child trusts
                $trustAttributes = if ($r.Properties['trustAttributes']) {
                    [int]$r.Properties['trustAttributes'][0]
                } else { 0 }
                
                $isWithinForest = ($trustAttributes -band 0x00000020) -ne 0
                $isForestTransitive = ($trustAttributes -band 0x00000008) -ne 0
                
                if (-not $trustPartner -or -not $cn) { continue }
                
                $trustTypeString = Get-TrustTypeString $trustType
                $directionString = Get-TrustDirectionString $trustDirection
                
                # Determine trust relationship type
                $relationshipType = if ($isWithinForest) { 
                    'ParentChild' 
                } elseif ($isForestTransitive) { 
                    'TreeRoot' 
                } else { 
                    'External' 
                }
                
                # Check if trusted domain is in our isolated domains list
                $isInternal = $isolatedDomains -contains $trustPartner
                $isOrphan   = $isSingleDomain -or (-not $isInternal)
                $action     = if ($isOrphan) { 'Delete' } else { 'Reset Password' }
                
                $localDepth = $domainHierarchy[$dom]
                $remoteDepth = if ($domainHierarchy.ContainsKey($trustPartner)) { $domainHierarchy[$trustPartner] } else { 0 }
                
                # Store TDO with complete information
                $allTrustObjects += [pscustomobject]@{
                    LocalDomain       = $dom                    # Domain where TDO was found
                    TrustedDomain     = $trustPartner           # DNS name from trustPartner attribute
                    CN                = $cn                     # CN of the TDO
                    DN                = $dn
                    Server            = $server
                    TrustType         = $trustType
                    TrustTypeString   = $trustTypeString
                    TrustDirection    = $trustDirection
                    DirectionString   = $directionString
                    TrustAttributes   = $trustAttributes
                    RelationshipType  = $relationshipType
                    IsWithinForest    = $isWithinForest
                    IsInternal        = $isInternal
                    Action            = $action
                    LocalDepth        = $localDepth
                    RemoteDepth       = $remoteDepth
                }
            }
        }
        
        Write-IdentIRLog -Message "Enumerated $($allTrustObjects.Count) trust objects." -TypeName 'Info' -ForegroundColor Green
        
        # --- Log detailed trust information ---
        Write-IdentIRLog -Message "Trust Relationship Details:" -TypeName 'Info' -ForegroundColor Cyan
        foreach ($tdo in $allTrustObjects) {
            $trustDesc = switch ($tdo.TrustDirection) {
                1 { "$($tdo.LocalDomain) is TRUSTED by $($tdo.TrustedDomain)" }  # Inbound
                2 { "$($tdo.LocalDomain) TRUSTS $($tdo.TrustedDomain)" }         # Outbound
                3 { "$($tdo.LocalDomain) <-> $($tdo.TrustedDomain) (Bidirectional)" }
                default { "$($tdo.LocalDomain) <-> $($tdo.TrustedDomain)" }
            }
            Write-IdentIRLog -Message "  TDO: $trustDesc [$($tdo.RelationshipType), Action: $($tdo.Action)]" -TypeName 'Info' -ForegroundColor White
        }
        
        # --- Process deletes ---
        foreach ($tdo in $allTrustObjects | Where-Object { $_.Action -eq 'Delete' }) {
            if ($whatIfMode) {
                Write-IdentIRLog -Message "WhatIf: Would delete trust: $($tdo.LocalDomain) -> $($tdo.TrustedDomain) ($($tdo.RelationshipType))" -TypeName 'Info' -ForegroundColor White
                $deletes++
                continue
            }
            if (Delete-LocalTrust -AnchorDC $tdo.Server -RemoteDomain $tdo.TrustedDomain -DN $tdo.DN) {
                $deletes++
            } else {
                $errors++
            }
        }
        
        # --- Process trust password resets ---
        if (-not $isSingleDomain) {
            # Build trust pairs by matching TDOs from both domains
            $trustPairs = @{}
            $resetTDOs = $allTrustObjects | Where-Object { $_.Action -eq 'Reset Password' }
            
            foreach ($tdo in $resetTDOs) {
                $pairKey = Get-PairKey $tdo.LocalDomain $tdo.TrustedDomain
                
                if (-not $trustPairs.ContainsKey($pairKey)) {
                    $trustPairs[$pairKey] = @{
                        TDOs = @()
                    }
                }
                
                $trustPairs[$pairKey].TDOs += $tdo
            }
            
            # Process each trust pair
            $processedPairs = @()
            
            foreach ($pairKey in $trustPairs.Keys) {
                $pair = $trustPairs[$pairKey]
                $tdos = $pair.TDOs
                
                if ($tdos.Count -lt 2) {
                    Write-IdentIRLog -Message "Warning: Only found one side of trust for pair $pairKey" -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }
                
                # Get both TDOs
                $tdo1 = $tdos[0]
                $tdo2 = $tdos[1]
                
                # Determine which domain is trusting and which is trusted for each direction
                # Remember: Outbound = Local domain TRUSTS the trustPartner
                #           Inbound = Local domain is TRUSTED by trustPartner
                
                $trustingDomain = $null
                $trustedDomain = $null
                $trustingAnchor = $null
                $trustedAnchor = $null
                $trustingTDO = $null
                $trustedTDO = $null
                
                # Analyze trust direction
                if ($tdo1.TrustDirection -eq 2 -and $tdo2.TrustDirection -eq 1) {
                    # TDO1: Local TRUSTS TrustedDomain (Outbound)
                    # TDO2: Local is TRUSTED by TrustedDomain (Inbound)
                    # This means: tdo1.LocalDomain trusts tdo1.TrustedDomain
                    $trustingDomain = $tdo1.LocalDomain
                    $trustedDomain = $tdo1.TrustedDomain
                    $trustingAnchor = $tdo1.Server
                    $trustedAnchor = $tdo2.Server
                    $trustingTDO = $tdo1
                    $trustedTDO = $tdo2
                } elseif ($tdo1.TrustDirection -eq 1 -and $tdo2.TrustDirection -eq 2) {
                    # Reverse of above
                    $trustingDomain = $tdo2.LocalDomain
                    $trustedDomain = $tdo2.TrustedDomain
                    $trustingAnchor = $tdo2.Server
                    $trustedAnchor = $tdo1.Server
                    $trustingTDO = $tdo2
                    $trustedTDO = $tdo1
                } elseif ($tdo1.TrustDirection -eq 3 -and $tdo2.TrustDirection -eq 3) {
                    # Bidirectional - determine parent/child
                    if ($tdo1.LocalDepth -le $tdo2.LocalDepth) {
                        # tdo1's domain is parent (or equal depth)
                        $trustingDomain = $tdo1.LocalDomain  # Reset parent first
                        $trustedDomain = $tdo1.TrustedDomain
                        $trustingAnchor = $tdo1.Server
                        $trustedAnchor = $tdo2.Server
                        $trustingTDO = $tdo1
                        $trustedTDO = $tdo2
                    } else {
                        $trustingDomain = $tdo2.LocalDomain
                        $trustedDomain = $tdo2.TrustedDomain
                        $trustingAnchor = $tdo2.Server
                        $trustedAnchor = $tdo1.Server
                        $trustingTDO = $tdo2
                        $trustedTDO = $tdo1
                    }
                } else {
                    Write-IdentIRLog -Message "Warning: Unexpected trust direction combination for $pairKey" -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }
                
                $minDepth = [Math]::Min($tdo1.LocalDepth, $tdo2.LocalDepth)
                
                $processedPairs += [pscustomobject]@{
                    TrustingDomain    = $trustingDomain
                    TrustedDomain     = $trustedDomain
                    TrustingAnchor    = $trustingAnchor
                    TrustedAnchor     = $trustedAnchor
                    TrustingTDO       = $trustingTDO
                    TrustedTDO        = $trustedTDO
                    MinDepth          = $minDepth
                    RelationshipType  = $tdo1.RelationshipType
                }
            }
            
            # Sort: Parent-child first (by depth), then tree root
            $sortedPairs = $processedPairs | Sort-Object {
                if ($_.RelationshipType -eq 'ParentChild') {
                    "ParentChild_{0:D5}" -f $_.MinDepth
                } elseif ($_.RelationshipType -eq 'TreeRoot') {
                    if ($_.TrustingDomain -eq $ForestRootFqdn -or $_.TrustedDomain -eq $ForestRootFqdn) {
                        "TreeRoot_0"
                    } else {
                        "TreeRoot_1"
                    }
                } else {
                    "External_99999"
                }
            }
            
            Write-IdentIRLog -Message "Processing $($sortedPairs.Count) trust pairs (Microsoft best practice: parent before child, trusting domain first)..." -TypeName 'Info' -ForegroundColor Cyan
            Write-IdentIRLog -Message "Trust reset order:" -TypeName 'Info' -ForegroundColor Cyan
            
            foreach ($pair in $sortedPairs) {
                Write-IdentIRLog -Message "  - TRUSTING: $($pair.TrustingDomain) -> TRUSTED: $($pair.TrustedDomain) [$($pair.RelationshipType), MinDepth: $($pair.MinDepth)]" -TypeName 'Info' -ForegroundColor White
            }
            
            # Reset each trust pair
            foreach ($pair in $sortedPairs) {
                if ($whatIfMode) {
                    Write-IdentIRLog -Message "WhatIf: Would reset trust password" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   TRUSTING: $($pair.TrustingDomain) (on $($pair.TrustingAnchor))" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   TRUSTED:  $($pair.TrustedDomain) (on $($pair.TrustedAnchor))" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   Type: $($pair.RelationshipType)" -TypeName 'Info' -ForegroundColor White
                    $resets++
                    continue
                }
                
                Write-IdentIRLog -Message "Resetting trust: $($pair.TrustingDomain) <-> $($pair.TrustedDomain) [$($pair.RelationshipType)]" -TypeName 'Info' -ForegroundColor Cyan
                Write-IdentIRLog -Message "  First: $($pair.TrustingDomain) (on $($pair.TrustingAnchor))" -TypeName 'Info' -ForegroundColor Cyan
                Write-IdentIRLog -Message "  Second: $($pair.TrustedDomain) (on $($pair.TrustedAnchor))" -TypeName 'Info' -ForegroundColor Cyan
                
                try {
                    # Generate ONE password for this trust pair
                    $pw = New-Password -Length 24
                    Write-IdentIRLog -Message "Generated shared secret for $($pair.TrustingDomain) <-> $($pair.TrustedDomain)" -TypeName 'Info' -ForegroundColor Cyan
                    
                    # Get domain controller contexts
                    $ctxTrusting = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustingAnchor)
                    $ctxTrusted = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustedAnchor)
                    
                    Write-IdentIRLog -Message "Connecting to TRUSTING DC: $($pair.TrustingAnchor)" -TypeName 'Info' -ForegroundColor Cyan
                    Write-IdentIRLog -Message "Connecting to TRUSTED DC: $($pair.TrustedAnchor)" -TypeName 'Info' -ForegroundColor Cyan
                    
                    $dcTrusting = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusting)
                    $dcTrusted = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusted)
                    
                    $resetSuccessful = $false
                    try {
                        # CRITICAL: Use the method overload WITHOUT TrustDirection parameter
                        # This automatically updates BOTH inbound and outbound trust passwords
                        # Using TrustDirection::Outbound only updates one direction, breaking the trust!
                        
                        # Step 1: Reset first domain (parent/trusting domain first per MS guidance)
                        Write-IdentIRLog -Message "Step 1: Resetting trust on $($pair.TrustingDomain) for partner $($pair.TrustedDomain)" -TypeName 'Info' -ForegroundColor Cyan
                        if ($PSCmdlet.ShouldProcess("$($pair.TrustingDomain) trust with $($pair.TrustedDomain)", "Reset trust password")) {
                            # Call without TrustDirection - updates both inbound and outbound automatically
                            $dcTrusting.Domain.UpdateLocalSideOfTrustRelationship($pair.TrustedDomain, $pw)
                            Write-IdentIRLog -Message "Successfully reset trust on $($pair.TrustingDomain) (both directions updated)" -TypeName 'Info' -ForegroundColor Green
                        }
                        
                        # Brief pause to allow AD to process
                        Start-Sleep -Milliseconds 500
                        
                        # Step 2: Reset second domain (child/trusted domain)
                        Write-IdentIRLog -Message "Step 2: Resetting trust on $($pair.TrustedDomain) for partner $($pair.TrustingDomain)" -TypeName 'Info' -ForegroundColor Cyan
                        if ($PSCmdlet.ShouldProcess("$($pair.TrustedDomain) trust with $($pair.TrustingDomain)", "Reset trust password")) {
                            # Call without TrustDirection - updates both inbound and outbound automatically
                            $dcTrusted.Domain.UpdateLocalSideOfTrustRelationship($pair.TrustingDomain, $pw)
                            Write-IdentIRLog -Message "Successfully reset trust on $($pair.TrustedDomain) (both directions updated)" -TypeName 'Info' -ForegroundColor Green
                        }
                        
                        $resetSuccessful = $true
                    } catch {
                        Write-IdentIRLog -Message "CRITICAL: Trust reset failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        Write-IdentIRLog -Message "Trust between $($pair.TrustingDomain) and $($pair.TrustedDomain) may be in inconsistent state" -TypeName 'Error' -ForegroundColor Red
                        $errors++
                        continue
                    }
                    
                    if ($resetSuccessful) {
                        # Wait for replication
                        Write-IdentIRLog -Message "Waiting 15 seconds for AD replication..." -TypeName 'Info' -ForegroundColor Cyan
                        Start-Sleep -Seconds 15
                        
                        # Verify trust connectivity by testing authentication
                        try {
                            Write-IdentIRLog -Message "Verifying trust authentication..." -TypeName 'Info' -ForegroundColor Cyan
                            
                            # Test trust from TrustingDomain to TrustedDomain
                            $netlogonPath = "\\$($pair.TrustedDomain)\NETLOGON"
                            $testAccess = Test-Path $netlogonPath -ErrorAction SilentlyContinue
                            
                            if ($testAccess) {
                                Write-IdentIRLog -Message "Trust verification successful (authenticated to $($pair.TrustedDomain))" -TypeName 'Info' -ForegroundColor Green
                            } else {
                                Write-IdentIRLog -Message "Warning: Trust verification failed - cannot access $netlogonPath (authentication may not be working)" -TypeName 'Warning' -ForegroundColor Yellow
                            }
                        } catch {
                            Write-IdentIRLog -Message "Warning: Could not verify trust authentication: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                        
                        Write-IdentIRLog -Message "Successfully reset trust password for $($pair.TrustingDomain) <-> $($pair.TrustedDomain) [$($pair.RelationshipType)]" -TypeName 'Info' -ForegroundColor Green
                        $resets++
                    }
                } catch {
                    Write-IdentIRLog -Message "Failed to reset trust password for $($pair.TrustingDomain) <-> $($pair.TrustedDomain): $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    $errors++
                }
            }
        }
        
        # --- Summary ---
        Write-IdentIRLog -Message "========================================" -TypeName 'Info' -ForegroundColor White
        Write-IdentIRLog -Message "Trust Operation Summary" -TypeName 'Info' -ForegroundColor White
        Write-IdentIRLog -Message "  Passwords Reset: $resets" -TypeName 'Info' -ForegroundColor $(if ($resets -gt 0) { 'Green' } else { 'White' })
        Write-IdentIRLog -Message "  Trusts Deleted:  $deletes" -TypeName 'Info' -ForegroundColor $(if ($deletes -gt 0) { 'Yellow' } else { 'White' })
        Write-IdentIRLog -Message "  Errors:          $errors" -TypeName 'Info' -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
        Write-IdentIRLog -Message "========================================" -TypeName 'Info' -ForegroundColor White
        Write-IdentIRLog -Message "Invoke-TrustPasswordReset completed" -TypeName 'Info' -ForegroundColor Green
    }
}
