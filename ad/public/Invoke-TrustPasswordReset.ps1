<#
.SYNOPSIS
Resets inter/intra-forest trust passwords (or deletes orphaned trusts) using DCs from an isolated recovery inventory.

.DESCRIPTION
Invoke-TrustPasswordReset discovers Trusted Domain Objects (TDOs) per domain (Forest Root → Child → Tree), prefers the PDC
for operations, and:
- Deletes orphaned trusts (e.g., single-domain recoveries or partners not in the isolated set).
- Resets passwords for valid pairs with one shared secret, updating both sides in correct order (trusting first).
- Also deletes corresponding inter-domain trust accounts (CN=Users\<NetBIOS$>) when removing orphaned trusts.
Runs in WhatIf mode unless -Execute is supplied. Requires Domain/Enterprise Admin privileges.

.PARAMETER IsolatedDCList
Inventory of ONLINE DCs (FQDN, Domain, DefaultNamingContext, ConfigurationNamingContext, Type, IsPdcRoleOwner, Online).

.PARAMETER Execute
Apply changes; omit to simulate (WhatIf=True).

.EXAMPLE
# Simulate full trust sweep and report actions
Invoke-TrustPasswordReset -IsolatedDCList $dcs

.EXAMPLE
# Apply: delete orphans, remove CN=Users\<NetBIOS$> trust accounts, and reset valid trust passwords
Invoke-TrustPasswordReset -IsolatedDCList $dcs -Execute

.OUTPUTS
Writes a summary to the log; increments counters: Passwords Reset, Trusts Deleted, Trust Accounts Deleted, Errors.

.NOTES
Author: NightCityShogun
Version: 1.5 (counts trust-account deletes in WhatIf; DNS-only; PDC-only; deep hierarchy safe)
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
        $trustAcctDeletes = 0
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

        # --- DNS canonicalizer ---
        function Resolve-DomainDns([string]$name) {
            if (-not $name) { return $null }
            try {
                $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $name)
                return ([System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)).Name.ToLowerInvariant()
            } catch {
                return $name.TrimEnd('.').ToLowerInvariant()
            }
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

        # Build domain hierarchy (supports child/grandchild)
        $domainHierarchy = @{}
        foreach ($domainName in $isolatedDomains) {
            $depth = ($domainName -split '\.').Count
            $domainHierarchy[$(Resolve-DomainDns $domainName)] = $depth
        }

        $ForestRootFqdn = Resolve-DomainDns $ForestRootFqdn

        # Order domains: root first → others by depth/name
        $orderedDomainsForEnum = @($ForestRootFqdn) + (
            $isolatedDomains |
                ForEach-Object { Resolve-DomainDns $_ } |
                Where-Object { $_ -ne $ForestRootFqdn } |
                Sort-Object
        )

        Write-IdentIRLog -Message "Domain processing order: $($orderedDomainsForEnum -join ', ')" -TypeName 'Info' -ForegroundColor Cyan

        foreach ($dc in $onlineDCs) {
            $norm = Resolve-DomainDns $dc.Domain
            if (-not $domainGroups.ContainsKey($norm)) {
                $domainGroups[$norm] = [PSCustomObject]@{
                    Domain    = $norm
                    DCs       = @()
                    Type      = $dc.Type
                    DefaultNC = $dc.DefaultNamingContext
                    ConfigNC  = $dc.ConfigurationNamingContext
                    Depth     = $domainHierarchy[$norm]
                }
            }
            $domainGroups[$norm].DCs += ,$dc
        }

        $isSingleDomain = ($domainGroups.Count -eq 1)
        Write-IdentIRLog -Message "Single domain forest: $isSingleDomain" -TypeName 'Info' -ForegroundColor White

        # --- Helpers ---
        function Get-AnchorDC([pscustomobject]$grp) {
            # PDC-only for trust operations (more reliable)
            $p = $grp.DCs | Where-Object { $_.IsPdcRoleOwner -or $_.IsPDC } | Select-Object -First 1
            if ($p) { return [string]$p.FQDN }
            throw "No PDC emulator available for $($grp.Domain). Aborting trust resets for safety."
        }
        function Get-PairKey([string]$a,[string]$b) {
            $a = (Resolve-DomainDns $a); $b = (Resolve-DomainDns $b)
            if ([string]::Compare($a,$b,[StringComparison]::Ordinal) -le 0) { "$a|$b" } else { "$b|$a" }
        }
        function Test-IsSuffix([string]$a, [string]$b) {
            if (-not $a -or -not $b) { return $false }
            if ($a -ieq $b) { return $false }
            return $a.EndsWith(".$b", [System.StringComparison]::OrdinalIgnoreCase)
        }
        function Get-TrustTypeString([int]$trustType) {
            switch ($trustType) {
                1 { return 'TRUST_TYPE_DOWNLEVEL' }
                2 { return 'TRUST_TYPE_UPLEVEL' }
                3 { return 'TRUST_TYPE_MIT' }
                4 { return 'TRUST_TYPE_DCE' }
                5 { return 'TRUST_TYPE_AAD' }
                default { return "Unknown ($trustType)" }
            }
        }
        function Get-TrustDirectionString([int]$trustDirection) {
            switch ($trustDirection) {
                0 { return 'Disabled' }
                1 { return 'Inbound' }
                2 { return 'Outbound' }
                3 { return 'Bidirectional' }
                default { return "Unknown ($trustDirection)" }
            }
        }

        # Delete TDO + corresponding CN=Users\<NetBIOS$> TRUST_ACCOUNT
        function Delete-LocalTrust {
            param(
                [Parameter(Mandatory=$true)][string]$AnchorDC,
                [Parameter(Mandatory=$true)][string]$RemoteDomain,
                [Parameter(Mandatory=$true)][string]$DN,
                [Parameter()][string]$LocalDefaultNC,
                [Parameter()][string]$RemoteFlatName   # NetBIOS/flat name from TDO if available
            )
            $tdoDeleted = $false
            $acctDeleted = $false

            # Pre-log explicit intent
            if ($LocalDefaultNC) {
                $expected = if ($RemoteFlatName) { ($RemoteFlatName.TrimEnd('$') + '$') } else { "<unknown$>" }
                Write-IdentIRLog -Message "Will attempt to delete interdomain trust account CN=Users\$expected in $(($LocalDefaultNC -replace '^.*?DC=','') -replace ',DC=', '.')" -TypeName 'Info' -ForegroundColor Cyan
            }

            try {
                $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $AnchorDC)
                $dc  = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctx)
                $dom = $dc.Domain
                if ($PSCmdlet.ShouldProcess($dom.Name, "Delete trust with $RemoteDomain")) {
                    $dom.DeleteLocalSideOfTrustRelationship((Resolve-DomainDns $RemoteDomain))
                    Write-IdentIRLog -Message "Deleted local trust object between $($dom.Name) and $(Resolve-DomainDns $RemoteDomain) via API" -TypeName 'Info' -ForegroundColor Green
                    $tdoDeleted = $true
                }
            } catch {
                Write-IdentIRLog -Message "DeleteLocalSideOfTrustRelationship failed on $AnchorDC for ${RemoteDomain}: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            }

            if (-not $tdoDeleted) {
                try {
                    $obj = [ADSI]"LDAP://$AnchorDC/$DN"
                    if ($obj.Path -and $PSCmdlet.ShouldProcess($DN, "Delete TDO")) {
                        $obj.psbase.DeleteTree()
                        $obj.CommitChanges()
                        Write-IdentIRLog -Message "Deleted trust TDO at $DN on $AnchorDC" -TypeName 'Info' -ForegroundColor Green
                        $tdoDeleted = $true
                    }
                } catch {
                    Write-IdentIRLog -Message "ADSI deletion failed on $AnchorDC for DN=${DN}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                }
            }

            # If we deleted the trust TDO, try to remove the inter-domain trust account in CN=Users
            if ($tdoDeleted -and $LocalDefaultNC) {
                try {
                    $usersDn = "CN=Users,$LocalDefaultNC"
                    $searchRoot = [ADSI]"LDAP://$AnchorDC/$usersDn"

                    # If flat name is known, target exact <flat$>
                    $candidate = $null
                    if ($RemoteFlatName) {
                        $target = ($RemoteFlatName.TrimEnd('$') + '$')
                        $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
                        $ds.PageSize = 1000
                        $ds.Filter = "(&(objectClass=user)(sAMAccountType=805306370)(|(sAMAccountName=$target)(name=$target)))"
                        foreach ($p in 'distinguishedName','sAMAccountName','name') { [void]$ds.PropertiesToLoad.Add($p) }
                        $one = $ds.FindOne()
                        if ($one) { $candidate = $one }
                    }

                    # Fallback: scan all trust accounts and match by DNS left label
                    if (-not $candidate) {
                        $prefix = if ($RemoteDomain) { ($RemoteDomain.Split('.')[0]).ToLower() } else { $null }
                        $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
                        $ds.PageSize = 1000
                        $ds.Filter = "(&(objectClass=user)(sAMAccountType=805306370))"
                        foreach ($p in 'distinguishedName','sAMAccountName','name') { [void]$ds.PropertiesToLoad.Add($p) }
                        $all = $ds.FindAll()
                        foreach ($r in $all) {
                            $sam = ([string]$r.Properties['sAMAccountName'][0])
                            $nm  = ([string]$r.Properties['name'][0])
                            if ($sam -and $sam.EndsWith('$') -and $prefix -and $sam.TrimEnd('$').ToLower() -eq $prefix) { $candidate = $r; break }
                            if (-not $candidate -and $nm -and $nm.EndsWith('$') -and $prefix -and $nm.TrimEnd('$').ToLower() -eq $prefix) { $candidate = $r; break }
                        }
                    }

                    if ($candidate) {
                        $acctDn  = [string]$candidate.Properties['distinguishedName'][0]
                        $acctSam = [string]$candidate.Properties['sAMAccountName'][0]
                        if ($PSCmdlet.ShouldProcess($acctDn, "Delete inter-domain trust account")) {
                            $acct = [ADSI]"LDAP://$AnchorDC/$acctDn"
                            $acct.DeleteTree()
                            $acct.CommitChanges()
                            Write-IdentIRLog -Message "Deleted interdomain trust account: $acctSam ($acctDn)" -TypeName 'Info' -ForegroundColor Green
                            $acctDeleted = $true
                        }
                    } else {
                        $shown = if ($RemoteFlatName) { ($RemoteFlatName.TrimEnd('$') + '$') } else { "<unknown$>" }
                        Write-IdentIRLog -Message "No matching interdomain trust account found in $usersDn for partner '$RemoteDomain' (expected '$shown')" -TypeName 'Warning' -ForegroundColor Yellow
                    }
                } catch {
                    Write-IdentIRLog -Message "Failed to evaluate/delete interdomain trust account in CN=Users: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }
            }

            return $tdoDeleted, $acctDeleted
        }

        # --- Enumerate trusts (DNS-only, canonicalized) ---
        Write-IdentIRLog -Message "Enumerating trust objects from all domains..." -TypeName 'Info' -ForegroundColor White
        $allTrustObjects = @()

        foreach ($dom in $orderedDomainsForEnum) {
            $server = Get-AnchorDC $domainGroups[$dom]
            $defaultNC = $domainGroups[$dom].DefaultNC
            $root = [ADSI]"LDAP://$server/CN=System,$defaultNC"
            $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
            $ds.Filter = "(objectClass=trustedDomain)"
            $ds.PageSize = 1000

            foreach ($p in 'cn','trustPartner','flatName','distinguishedName','trustType','trustDirection','trustAttributes') { [void]$ds.PropertiesToLoad.Add($p) }

            $res = $ds.FindAll()
            foreach ($r in $res) {
                $cn = [string]$r.Properties['cn'][0]
                $partnerRaw = [string]$r.Properties['trustPartner'][0]
                $flat = if ($r.Properties['flatName']) { [string]$r.Properties['flatName'][0] } else { $null }
                $dn = [string]$r.Properties['distinguishedName'][0]
                if (-not $partnerRaw -or -not $cn) { continue }

                $partnerDns = Resolve-DomainDns $partnerRaw
                $localDns   = $dom

                $trustType = if ($r.Properties['trustType']) { [int]$r.Properties['trustType'][0] } else { 2 }
                $trustDirection = if ($r.Properties['trustDirection']) { [int]$r.Properties['trustDirection'][0] } else { 3 }
                $trustAttributes = if ($r.Properties['trustAttributes']) { [int]$r.Properties['trustAttributes'][0] } else { 0 }

                $WITHIN_FOREST     = 0x00000020
                $FOREST_TRANSITIVE = 0x00000008
                $intraForest = ($trustAttributes -band $WITHIN_FOREST) -ne 0
                $forestTrust = ($trustAttributes -band $FOREST_TRANSITIVE) -ne 0

                $trustTypeString = Get-TrustTypeString $trustType
                $directionString = Get-TrustDirectionString $trustDirection

                if ($intraForest) {
                    if ( (Test-IsSuffix $localDns $partnerDns) -or (Test-IsSuffix $partnerDns $localDns) ) {
                        $relationshipType = 'ParentChild'
                    } else {
                        $relationshipType = 'TreeRoot'
                    }
                }
                elseif ($forestTrust) {
                    $relationshipType = 'ForestTrust'
                }
                else {
                    $relationshipType = 'External'
                }

                $isInternal = $false
                foreach ($idom in $isolatedDomains) {
                    if ((Resolve-DomainDns $idom) -eq $partnerDns) { $isInternal = $true; break }
                }

                $isOrphan   = $isSingleDomain -or (-not $isInternal)
                $action     = if ($isOrphan) { 'Delete' } else { 'Reset Password' }

                $localDepth  = $domainHierarchy[$localDns]
                $remoteDepth = if ($domainHierarchy.ContainsKey($partnerDns)) { $domainHierarchy[$partnerDns] } else { ($partnerDns -split '\.').Count }

                $allTrustObjects += [pscustomobject]@{
                    LocalDomain       = $localDns
                    TrustedDomain     = $partnerDns
                    FlatName          = $flat
                    CN                = $cn
                    DN                = $dn
                    Server            = $server
                    LocalDefaultNC    = $defaultNC
                    TrustType         = $trustType
                    TrustTypeString   = $trustTypeString
                    TrustDirection    = $trustDirection
                    DirectionString   = $directionString
                    TrustAttributes   = $trustAttributes
                    RelationshipType  = $relationshipType
                    IsWithinForest    = $intraForest
                    IsInternal        = $isInternal
                    Action            = $action
                    LocalDepth        = $localDepth
                    RemoteDepth       = $remoteDepth
                }
            }
        }

        Write-IdentIRLog -Message "Enumerated $($allTrustObjects.Count) trust objects." -TypeName 'Info' -ForegroundColor Green

        # --- Log details ---
        Write-IdentIRLog -Message "Trust Relationship Details:" -TypeName 'Info' -ForegroundColor Cyan
        foreach ($tdo in $allTrustObjects) {
            $arrow = if ($tdo.TrustDirection -eq 3) { '-' } elseif ($tdo.TrustDirection -eq 2) { '->' } else { '<-' }
            Write-IdentIRLog -Message "  TDO: $($tdo.LocalDomain) $arrow $($tdo.TrustedDomain) [$($tdo.RelationshipType), Action: $($tdo.Action)]" -TypeName 'Info' -ForegroundColor White
        }

        # --- Deletes ---
        foreach ($tdo in $allTrustObjects | Where-Object { $_.Action -eq 'Delete' }) {
            if ($whatIfMode) {
                Write-IdentIRLog -Message "WhatIf: Would delete trust: $($tdo.LocalDomain) - $($tdo.TrustedDomain) ($($tdo.RelationshipType))" -TypeName 'Info' -ForegroundColor White
                if ($tdo.FlatName) {
                    Write-IdentIRLog -Message "WhatIf: Would also delete interdomain trust account CN=Users\$($tdo.FlatName.TrimEnd('$'))$ in $($tdo.LocalDomain)" -TypeName 'Info' -ForegroundColor White
                    $trustAcctDeletes++   # <-- count simulated interdomain trust account deletion
                } else {
                    $prefix = $tdo.TrustedDomain.Split('.')[0]
                    Write-IdentIRLog -Message "WhatIf: Would also delete interdomain trust account CN=Users\$($prefix)$ in $($tdo.LocalDomain) (flatName not present on TDO)" -TypeName 'Info' -ForegroundColor White
                    $trustAcctDeletes++   # <-- count simulated based on prefix heuristic
                }
                $deletes++
                continue
            }

            $tdoDeleted, $acctDeleted = Delete-LocalTrust `
                -AnchorDC $tdo.Server `
                -RemoteDomain $tdo.TrustedDomain `
                -DN $tdo.DN `
                -LocalDefaultNC $tdo.LocalDefaultNC `
                -RemoteFlatName $tdo.FlatName

            if ($tdoDeleted) {
                $deletes++
                if ($acctDeleted) { $trustAcctDeletes++ }
            } else {
                $errors++
            }
        }

        # --- Resets ---
        if (-not $isSingleDomain) {
            $trustPairs = @{}
            $resetTDOs = $allTrustObjects | Where-Object { $_.Action -eq 'Reset Password' }

            foreach ($tdo in $resetTDOs) {
                $pairKey = Get-PairKey $tdo.LocalDomain $tdo.TrustedDomain
                if (-not $trustPairs.ContainsKey($pairKey)) {
                    $trustPairs[$pairKey] = @{ TDOs = @() }
                }
                $trustPairs[$pairKey].TDOs += $tdo
            }

            $processedPairs = @()

            foreach ($pairKey in $trustPairs.Keys) {
                $tdos = $trustPairs[$pairKey].TDOs
                if ($tdos.Count -lt 2) {
                    Write-IdentIRLog -Message "Warning: Only one side of trust found for $pairKey" -TypeName 'Warning' -ForegroundColor Yellow
                    continue
                }
                $tdo1 = $tdos[0]; $tdo2 = $tdos[1]

                $trustingDomain = $null; $trustedDomain = $null
                $trustingAnchor = $null; $trustedAnchor = $null

                if ($tdo1.TrustDirection -eq 2 -and $tdo2.TrustDirection -eq 1) {
                    $trustingDomain = $tdo1.LocalDomain; $trustedDomain = $tdo1.TrustedDomain
                    $trustingAnchor = $tdo1.Server;      $trustedAnchor = $tdo2.Server
                } elseif ($tdo1.TrustDirection -eq 1 -and $tdo2.TrustDirection -eq 2) {
                    $trustingDomain = $tdo2.LocalDomain; $trustedDomain = $tdo2.TrustedDomain
                    $trustingAnchor = $tdo2.Server;      $trustedAnchor = $tdo1.Server
                } elseif ($tdo1.TrustDirection -eq 3 -and $tdo2.TrustDirection -eq 3) {
                    if ($tdo1.LocalDepth -le $tdo2.LocalDepth) {
                        $trustingDomain = $tdo1.LocalDomain; $trustedDomain = $tdo1.TrustedDomain
                        $trustingAnchor = $tdo1.Server;      $trustedAnchor = $tdo2.Server
                    } else {
                        $trustingDomain = $tdo2.LocalDomain; $trustedDomain = $tdo2.TrustedDomain
                        $trustingAnchor = $tdo2.Server;      $trustedAnchor = $tdo1.Server
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
                    MinDepth          = $minDepth
                    RelationshipType  = $tdo1.RelationshipType
                }
            }

            # ParentChild by depth (root→child→grandchild), then TreeRoot, then others
            $sortedPairs = $processedPairs | Sort-Object {
                if ($_.RelationshipType -eq 'ParentChild') {
                    "A_{0:D5}" -f $_.MinDepth
                } elseif ($_.RelationshipType -eq 'TreeRoot') {
                    if ($_.TrustingDomain -eq $ForestRootFqdn -or $_.TrustedDomain -eq $ForestRootFqdn) { "B_0" } else { "B_1" }
                } else {
                    "C_99999"
                }
            }

            Write-IdentIRLog -Message "Processing $($sortedPairs.Count) trust pairs (parent→child order, trusting side first)..." -TypeName 'Info' -ForegroundColor Cyan
            Write-IdentIRLog -Message "Trust reset order:" -TypeName 'Info' -ForegroundColor Cyan
            foreach ($pair in $sortedPairs) {
                Write-IdentIRLog -Message "  - TRUSTING: $($pair.TrustingDomain) -> TRUSTED: $($pair.TrustedDomain) [$($pair.RelationshipType), MinDepth: $($pair.MinDepth)]" -TypeName 'Info' -ForegroundColor White
            }

            foreach ($pair in $sortedPairs) {
                if ($whatIfMode) {
                    Write-IdentIRLog -Message "WhatIf: Would reset trust password" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   TRUSTING: $($pair.TrustingDomain) (on $($pair.TrustingAnchor))" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   TRUSTED : $($pair.TrustedDomain) (on $($pair.TrustedAnchor))" -TypeName 'Info' -ForegroundColor White
                    Write-IdentIRLog -Message "WhatIf:   Type    : $($pair.RelationshipType)" -TypeName 'Info' -ForegroundColor White
                    $resets++; continue
                }

                Write-IdentIRLog -Message "Resetting trust: $($pair.TrustingDomain) <-> $($pair.TrustedDomain) [$($pair.RelationshipType)]" -TypeName 'Info' -ForegroundColor Cyan
                Write-IdentIRLog -Message "  First : $($pair.TrustingDomain) (on $($pair.TrustingAnchor))" -TypeName 'Info' -ForegroundColor Cyan
                Write-IdentIRLog -Message "  Second: $($pair.TrustedDomain) (on $($pair.TrustedAnchor))" -TypeName 'Info' -ForegroundColor Cyan

                try {
                    $pw = New-Password -Length 24
                    Write-IdentIRLog -Message "Generated shared secret for $($pair.TrustingDomain) <-> $($pair.TrustedDomain)" -TypeName 'Info' -ForegroundColor Cyan

                    $ctxTrusting = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustingAnchor)
                    $ctxTrusted  = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustedAnchor)
                    $dcTrusting = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusting)
                    $dcTrusted  = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusted)

                    try {
                        if ($PSCmdlet.ShouldProcess("$($pair.TrustingDomain) trust with $($pair.TrustedDomain)", "Reset trust password")) {
                            $dcTrusting.Domain.UpdateLocalSideOfTrustRelationship((Resolve-DomainDns $pair.TrustedDomain), $pw)
                            Write-IdentIRLog -Message "Trusting side updated (DNS)" -TypeName 'Info' -ForegroundColor Green
                        }
                        Start-Sleep -Milliseconds 500
                        if ($PSCmdlet.ShouldProcess("$($pair.TrustedDomain) trust with $($pair.TrustingDomain)", "Reset trust password")) {
                            $dcTrusted.Domain.UpdateLocalSideOfTrustRelationship((Resolve-DomainDns $pair.TrustingDomain), $pw)
                            Write-IdentIRLog -Message "Trusted side updated (DNS)" -TypeName 'Info' -ForegroundColor Green
                        }
                    } catch {
                        Write-IdentIRLog -Message "CRITICAL: Trust reset failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        $errors++; continue
                    }

                    Write-IdentIRLog -Message "Waiting 15 seconds for AD replication..." -TypeName 'Info' -ForegroundColor Cyan
                    Start-Sleep -Seconds 15

                    try {
                        $netlogonPath = "\\$($pair.TrustedDomain)\NETLOGON"
                        $testAccess = Test-Path $netlogonPath -ErrorAction SilentlyContinue
                        if ($testAccess) {
                            Write-IdentIRLog -Message "Trust verification successful (accessed $netlogonPath)" -TypeName 'Info' -ForegroundColor Green
                        } else {
                            Write-IdentIRLog -Message "Warning: Could not access $netlogonPath for verification" -TypeName 'Warning' -ForegroundColor Yellow
                        }
                    } catch {
                        Write-IdentIRLog -Message "Warning: Verification attempt raised: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                    }

                    Write-IdentIRLog -Message "Successfully reset trust password for $($pair.TrustingDomain) <-> $($pair.TrustedDomain) [$($pair.RelationshipType)]" -TypeName 'Info' -ForegroundColor Green
                    $resets++

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
        Write-IdentIRLog -Message "  Trusts Deleted : $deletes" -TypeName 'Info' -ForegroundColor $(if ($deletes -gt 0) { 'Yellow' } else { 'White' })
        Write-IdentIRLog -Message "  Trust Accts Del: $trustAcctDeletes" -TypeName 'Info' -ForegroundColor $(if ($trustAcctDeletes -gt 0) { 'Yellow' } else { 'White' })
        Write-IdentIRLog -Message "  Errors         : $errors" -TypeName 'Info' -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
        Write-IdentIRLog -Message "========================================" -TypeName 'Info' -ForegroundColor White
        Write-IdentIRLog -Message "Invoke-TrustPasswordReset completed" -TypeName 'Info' -ForegroundColor Green
    }
}
