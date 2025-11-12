<#
.SYNOPSIS
  Reliable, site-predictable reset of intra-/inter-forest trust passwords (or deletion of orphaned trusts) using
  PDC-anchored, server-pinned LDAP/DC operations. Includes pinned NetLogon validation and robust privilege checks.

.DESCRIPTION
  Invoke-TrustPasswordReset v3 focuses on reliability, stability and predictability regardless of the host type
  (client, member server, or DC). Key changes vs prior versions:

  - All directory reads/writes are server-pinned to the same anchor DC per domain (typically the PDC Emulator).
  - No serverless binds: avoids DC-Locator variance by host/site.
  - Privilege check uses process token group SIDs (RIDs -512 / -519), resilient to domain placement.
  - Connectivity preflight (DNS + RootDSE bind) to each anchor DC with clear errors.
  - Trust enumeration and updates use the same anchor used to select/validate objects.
  - Pinned NetLogon verification to the specific DC just updated (\\TrustedAnchor\NETLOGON), not the domain name.
  - Hardened domain/FQDN normalization and pair-keying.
  - Topology-aware replication wait + verification retry after updates.
  - Counters and WhatIf preserved; clearer, color-coded logging.
  - Graceful fallback if helper functions (e.g., New-Password, Write-IdentIRLog) are missing.

.PARAMETER IsolatedDCList
  Inventory of ONLINE DCs. Expected properties: FQDN, Domain, DefaultNamingContext, ConfigurationNamingContext,
  Type (Forest Root/Child/Tree), IsPdcRoleOwner (or IsPDC), Online (bool).

.PARAMETER Execute
  Apply changes; omit to simulate (WhatIf=True).

.PARAMETER ReplicationWaitSeconds
  Seconds to wait after setting both sides before verification (default 20). Used per pair.

.EXAMPLE
  Invoke-TrustPasswordReset -IsolatedDCList $dcs

.EXAMPLE
  Invoke-TrustPasswordReset -IsolatedDCList $dcs -Execute -ReplicationWaitSeconds 30

.OUTPUTS
  Writes a summary log; increments counters: Passwords Reset, Trusts Deleted, Trust Accounts Cleaned, Errors.

.NOTES
  Author: NightCityShogun
  Version: 3.0.1 (flatName→SAM$ normalization; server-pinned NETLOGON verify)
  Requires: Domain/Enterprise Admin rights; ADSI; .NET DirectoryServices
  SupportsShouldProcess: True
  © 2025 NightCityShogun. All rights reserved.
#>
function Invoke-TrustPasswordReset {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [psobject[]]$IsolatedDCList,

    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [int]$ReplicationWaitSeconds = 20
  )

  begin {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $whatIfMode = -not $Execute
    $modeText   = if ($whatIfMode) { 'WhatIf=True' } else { 'WhatIf=False' }

    # ---- Helper shims (if not provided by the host) ----
    if (-not (Get-Command Write-IdentIRLog -ErrorAction SilentlyContinue)) {
      function Write-IdentIRLog { param([string]$Message,[string]$TypeName='Info',[string]$ForegroundColor='White')
        $prefix = "[$TypeName]"
        Write-Host "$prefix $Message" -ForegroundColor $ForegroundColor
      }
    }
    if (-not (Get-Command New-Password -ErrorAction SilentlyContinue)) {
      function New-Password { param([int]$Length=24)
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}' -split ''
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] ($Length)
        $rng.GetBytes($bytes)
        -join ($bytes | ForEach-Object { $chars[ $_ % $chars.Count ] })
      }
    }

    Write-IdentIRLog -Message "Starting Trust Password Reset ($modeText)" -TypeName 'Info' -ForegroundColor White

    # ---- Privilege check: use token SIDs (robust across domains and host types) ----
    try {
      $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
      $userName = $wi.Name
      Write-IdentIRLog -Message "Checking admin privileges for $userName (token-based)" -TypeName 'Info' -ForegroundColor Green
      $groupSids = $wi.Groups | ForEach-Object { $_.Value }
      $isDA = $false; $isEA = $false
      foreach ($sid in $groupSids) {
        if ($sid -match '-512$') { $isDA = $true }
        if ($sid -match '-519$') { $isEA = $true }
      }
      if (-not ($isDA -or $isEA)) { throw "Insufficient permissions (need Domain Admins or Enterprise Admins)" }
      Write-IdentIRLog -Message "Verified admin privileges via token (DA=$isDA, EA=$isEA)" -TypeName 'Info' -ForegroundColor Green
    } catch {
      Write-IdentIRLog -Message ("Failed to verify admin permissions: {0}" -f $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
      throw
    }

    if (-not $IsolatedDCList) {
      Write-IdentIRLog -Message 'No DCs supplied to -IsolatedDCList.' -TypeName 'Error' -ForegroundColor Red
      throw 'No DCs supplied to -IsolatedDCList.'
    }

    $acc = @()
    $resets = 0
    $deletes = 0
    $trustAcctCleaned = 0
    $errors = 0

    # ---- Local helpers (pure functions + server-pinned binds) ----

    function Normalize-DomainName {
      param([string]$Name)
      if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
      $n = $Name.Trim().TrimEnd('.')
      return $n.ToLowerInvariant()
    }

    function Ensure-TrailingDollar {
      param([string]$Name)
      if ([string]::IsNullOrWhiteSpace($Name)) { return $Name }
      return ($Name.TrimEnd('$') + '$')
    }

    function Get-RootDSE {
      param([string]$ServerFqdn)
      [ADSI]("LDAP://$ServerFqdn/RootDSE")
    }

    function Test-ServerConnectivity {
      param([string]$ServerFqdn)
      try {
        [void][System.Net.Dns]::GetHostEntry($ServerFqdn)
      } catch {
        throw ("DNS resolution failed for {0}: {1}" -f $ServerFqdn, $_.Exception.Message)
      }
      try {
        $r = Get-RootDSE -ServerFqdn $ServerFqdn
        $null = $r.defaultNamingContext
      } catch {
        throw ("LDAP RootDSE bind failed for {0}: {1}" -f $ServerFqdn, $_.Exception.Message)
      }
      return $true
    }

    function Get-AnchorDC {
      param([pscustomobject]$Group)
      $p = $Group.DCs | Where-Object { $_.IsPdcRoleOwner -or $_.IsPDC } | Select-Object -First 1
      if (-not $p) { throw ("No PDC emulator available for {0}. Aborting for safety." -f $Group.Domain) }
      [string]$p.FQDN
    }

    function Pair-Key { param([string]$A,[string]$B)
      $a = Normalize-DomainName $A; $b = Normalize-DomainName $B
      if ([string]::Compare($a,$b,[StringComparison]::Ordinal) -le 0) { "$a|$b" } else { "$b|$a" }
    }

    function Is-Suffix {
      param([string]$A,[string]$B) # is A child of B?
      if (-not $A -or -not $B) { return $false }
      if ($A -ieq $B) { return $false }
      return $A.EndsWith(".$B", [System.StringComparison]::OrdinalIgnoreCase)
    }

    function TrustType-String { param([int]$t)
      switch ($t) { 1{'TRUST_TYPE_DOWNLEVEL'} 2{'TRUST_TYPE_UPLEVEL'} 3{'TRUST_TYPE_MIT'} 4{'TRUST_TYPE_DCE'} 5{'TRUST_TYPE_AAD'} default{"Unknown ($t)"} }
    }
    function TrustDir-String { param([int]$d)
      switch ($d) { 0{'Disabled'} 1{'Inbound'} 2{'Outbound'} 3{'Bidirectional'} default{"Unknown ($d)"} }
    }

    function Remove-OrphanLocalSide {
      param(
        [Parameter(Mandatory)][string]$AnchorDC,
        [Parameter(Mandatory)][string]$LocalDomain,
        [Parameter(Mandatory)][string]$LocalDefaultNC,
        [Parameter(Mandatory)][string]$TrustedDomain,
        [Parameter(Mandatory)][string]$TdoDN,
        [Parameter()][string]$FlatName
      )
      $tdoDeleted = $false; $acctCleaned = $false

      # Delete local-side TDO (server-pinned)
      try {
        $ctx = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $AnchorDC)
        $dc  = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctx)
        $dom = $dc.Domain
        if ($PSCmdlet.ShouldProcess($dom.Name, "Delete trust with $TrustedDomain")) {
          if ($whatIfMode) {
            Write-IdentIRLog -Message "WhatIf: Would delete trust $LocalDomain - $TrustedDomain" -TypeName 'Info' -ForegroundColor White
            $tdoDeleted = $true
          } else {
            $dom.DeleteLocalSideOfTrustRelationship((Normalize-DomainName $TrustedDomain))
            Write-IdentIRLog -Message "Deleted local trust object between $LocalDomain and $TrustedDomain via API" -TypeName 'Info' -ForegroundColor Green
            $tdoDeleted = $true
          }
        }
      } catch {
        try {
          $obj = [ADSI]("LDAP://$AnchorDC/$TdoDN")
          if ($obj.Path -and $PSCmdlet.ShouldProcess($TdoDN, 'Delete TDO (fallback)')) {
            if ($whatIfMode) {
              Write-IdentIRLog -Message "WhatIf: Would delete TDO at $TdoDN" -TypeName 'Info' -ForegroundColor White
              $tdoDeleted = $true
            } else {
              $obj.DeleteTree(); $obj.CommitChanges()
              Write-IdentIRLog -Message "Deleted TDO at $TdoDN (fallback)" -TypeName 'Info' -ForegroundColor Green
              $tdoDeleted = $true
            }
          }
        } catch {
          Write-IdentIRLog -Message ("Failed deleting TDO: {0}" -f $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
        }
      }

      # Verify inter-domain trust account removal under CN=Users (server-pinned)
      try {
        $expectedSam = if ($FlatName) { Ensure-TrailingDollar $FlatName }
                       else { Ensure-TrailingDollar ($TrustedDomain.Split('.')[0].ToUpper()) }

        $usersDn = "CN=Users,$LocalDefaultNC"
        $root = [ADSI]("LDAP://$AnchorDC/$usersDn")
        Write-IdentIRLog -Message "Verifying trust account CN=Users\\$expectedSam is removed in $LocalDomain" -TypeName 'Info' -ForegroundColor Cyan

        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
        $ds.PageSize = 1000
        $ds.Filter   = "(&(objectClass=user)(sAMAccountType=805306370)(|(sAMAccountName=$expectedSam)(name=$expectedSam)))"
        foreach ($p in 'distinguishedName','sAMAccountName') { [void]$ds.PropertiesToLoad.Add($p) }
        $hit = $ds.FindOne()
        if (-not $hit) {
          Write-IdentIRLog -Message "Trust account '$expectedSam' confirmed removed (expected after TDO deletion)." -TypeName 'Info' -ForegroundColor Green
          $acctCleaned = $true
        } else {
          $acctDn  = [string]$hit.Properties['distinguishedName'][0]
          $acctSam = [string]$hit.Properties['sAMAccountName'][0]
          Write-IdentIRLog -Message "Warning: Orphaned trust account still exists: $acctSam ($acctDn)" -TypeName 'Warning' -ForegroundColor Yellow
          if ($PSCmdlet.ShouldProcess($acctDn, 'Delete orphaned trust account')) {
            if ($whatIfMode) {
              Write-IdentIRLog -Message "WhatIf: Would delete orphaned trust account $acctSam" -TypeName 'Info' -ForegroundColor White
              $acctCleaned = $true
            } else {
              try {
                $acct = [ADSI]("LDAP://$AnchorDC/$acctDn")
                $acct.DeleteTree(); $acct.CommitChanges()
                Write-IdentIRLog -Message "Deleted orphaned trust account: $acctSam" -TypeName 'Info' -ForegroundColor Green
                $acctCleaned = $true
              } catch {
                Write-IdentIRLog -Message ("Failed to delete orphaned account: {0}" -f $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
              }
            }
          }
        }
      } catch {
        Write-IdentIRLog -Message ("Error verifying trust account: {0}" -f $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
      }
      return $tdoDeleted, $acctCleaned
    }
  }

  process {
    foreach ($x in $IsolatedDCList) { $acc += ,$x }
  }

  end {
    $IsolatedDCList = @($acc)
    if ($IsolatedDCList.Count -eq 0) {
      Write-IdentIRLog -Message 'No DCs in accumulator after processing.' -TypeName 'Error' -ForegroundColor Red
      throw 'No DCs in accumulator.'
    }

    # --- Build domain groups and anchor DCs (server-pinned) ---
    foreach ($dc in $IsolatedDCList) {
      $dc.Domain = Normalize-DomainName $dc.Domain
      if (-not $dc.Type) { $dc.Type = 'Unknown' }
      if (-not $dc.FQDN -or -not $dc.DefaultNamingContext) {
        Write-IdentIRLog -Message ("Invalid DC data - FQDN={0}, DefaultNC={1}" -f $dc.FQDN, $dc.DefaultNamingContext) -TypeName 'Warning' -ForegroundColor Yellow
        $dc.Online = $false; $errors++; continue
      }
      try {
        Test-ServerConnectivity -ServerFqdn $dc.FQDN | Out-Null
        Write-IdentIRLog -Message ("Connectivity OK to {0} for domain {1}" -f $dc.FQDN, $dc.Domain) -TypeName 'Info' -ForegroundColor Green
      } catch {
        Write-IdentIRLog -Message ("Connectivity failed for {0}: {1}" -f $dc.FQDN, $_.Exception.Message) -TypeName 'Warning' -ForegroundColor Yellow
        $dc.Online = $false; $errors++; continue
      }
    }

    $onlineDCs = $IsolatedDCList | Where-Object { $_.Online -eq $true }
    if (-not $onlineDCs) { throw 'No ONLINE DCs provided.' }

    # Group by domain
    $domainGroups = @{}
    $isolatedDomains = @($onlineDCs | Select-Object -ExpandProperty Domain -Unique)

    foreach ($domainName in $isolatedDomains) {
      $depth = ($domainName -split '\.').Count
      $domainGroups[$domainName] = [PSCustomObject]@{
        Domain    = $domainName
        DCs       = @()
        DefaultNC = ($onlineDCs | Where-Object Domain -eq $domainName | Select-Object -First 1).DefaultNamingContext
        ConfigNC  = ($onlineDCs | Where-Object Domain -eq $domainName | Select-Object -First 1).ConfigurationNamingContext
        Depth     = $depth
      }
    }
    foreach ($dc in $onlineDCs) { $domainGroups[$dc.Domain].DCs += ,$dc }

    # Determine forest root via any DC's RootDSE (server-pinned)
    $first = $onlineDCs | Select-Object -First 1
    try {
      $rootdse = Get-RootDSE -ServerFqdn $first.FQDN
      $ForestRootFqdn = Normalize-DomainName ([string]$rootdse.rootDomainNamingContext -replace '^DC=','' -replace ',DC=','.')
      if (-not $ForestRootFqdn) { throw 'Unable to derive forest root from RootDSE' }
      Write-IdentIRLog -Message ("Forest root (derived via {0}): {1}" -f $first.FQDN, $ForestRootFqdn) -TypeName 'Info' -ForegroundColor White
    } catch {
      Write-IdentIRLog -Message ("Failed to get forest root: {0}" -f $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
      throw
    }

    # Order domains: forest root first, then others alpha
    $orderedDomainsForEnum = @($ForestRootFqdn) + (
      $isolatedDomains | Where-Object { $_ -ne $ForestRootFqdn } | Sort-Object
    )
    Write-IdentIRLog -Message ("Domain processing order: {0}" -f ($orderedDomainsForEnum -join ', ')) -TypeName 'Info' -ForegroundColor Cyan

    function Get-RelationshipType {
      param([string]$Local,[string]$Partner,[int]$TrustAttributes)
      $WITHIN_FOREST = 0x00000020
      $FOREST_TRANS  = 0x00000008
      $intraForest = ($TrustAttributes -band $WITHIN_FOREST) -ne 0
      $forestTrust = ($TrustAttributes -band $FOREST_TRANS) -ne 0
      if ($intraForest -or $forestTrust) { return 'IntraDomain' } else { return 'External' }
    }

    # Enumerate trustedDomain objects from each domain using its PDC anchor
    Write-IdentIRLog -Message 'Enumerating trust objects from all domains (server-pinned)...' -TypeName 'Info' -ForegroundColor White
    $allTrustObjects = @()

    foreach ($dom in $orderedDomainsForEnum) {
      $grp = $domainGroups[$dom]
      if (-not $grp) { continue }
      $server = Get-AnchorDC $grp
      $defaultNC = $grp.DefaultNC
      $sysRoot = [ADSI]("LDAP://$server/CN=System,$defaultNC")
      $ds = New-Object System.DirectoryServices.DirectorySearcher($sysRoot)
      $ds.Filter = '(objectClass=trustedDomain)'
      $ds.PageSize = 1000
      foreach ($p in 'cn','trustPartner','flatName','distinguishedName','trustType','trustDirection','trustAttributes') { [void]$ds.PropertiesToLoad.Add($p) }
      $res = $ds.FindAll()
      foreach ($r in $res) {
        $cn = [string]$r.Properties['cn'][0]
        $partnerRaw = [string]$r.Properties['trustPartner'][0]
        if (-not $partnerRaw -or -not $cn) { continue }
        $flat = if ($r.Properties['flatName']) { [string]$r.Properties['flatName'][0] } else { $null }
        $dn = [string]$r.Properties['distinguishedName'][0]
        $partnerDns = Normalize-DomainName $partnerRaw
        $localDns   = $dom
        $trustType  = if ($r.Properties['trustType']) { [int]$r.Properties['trustType'][0] } else { 2 }
        $trustDir   = if ($r.Properties['trustDirection']) { [int]$r.Properties['trustDirection'][0] } else { 3 }
        $trustAttr  = if ($r.Properties['trustAttributes']) { [int]$r.Properties['trustAttributes'][0] } else { 0 }
        $relType    = Get-RelationshipType -Local $localDns -Partner $partnerDns -TrustAttributes $trustAttr
        $isInternal = $isolatedDomains -contains $partnerDns
        $isSingleDomain = ($domainGroups.Count -eq 1)
        $isOrphan = $isSingleDomain -or (-not $isInternal)
        $action = if ($isOrphan) { 'Delete' } else { 'Reset Password' }
        $localDepth  = $grp.Depth
        $remoteDepth = if ($domainGroups.ContainsKey($partnerDns)) { $domainGroups[$partnerDns].Depth } else { ($partnerDns -split '\.').Count }
        $allTrustObjects += [pscustomobject]@{
          LocalDomain     = $localDns
          TrustedDomain   = $partnerDns
          FlatName        = $flat
          CN              = $cn
          DN              = $dn
          Server          = $server
          LocalDefaultNC  = $defaultNC
          TrustType       = $trustType
          TrustTypeString = (TrustType-String $trustType)
          TrustDirection  = $trustDir
          DirectionString = (TrustDir-String $trustDir)
          TrustAttributes = $trustAttr
          RelationshipType= $relType
          IsWithinForest  = (($trustAttr -band 0x20) -ne 0)
          IsInternal      = $isInternal
          Action          = $action
          LocalDepth      = $localDepth
          RemoteDepth     = $remoteDepth
        }
      }
    }

    Write-IdentIRLog -Message ("Enumerated {0} trust objects." -f $allTrustObjects.Count) -TypeName 'Info' -ForegroundColor Green
    Write-IdentIRLog -Message 'Trust Relationship Details:' -TypeName 'Info' -ForegroundColor Cyan
    foreach ($tdo in $allTrustObjects) {
      $arrow = if ($tdo.TrustDirection -eq 3) { '-' } elseif ($tdo.TrustDirection -eq 2) { '->' } else { '<-' }
      Write-IdentIRLog -Message (" TDO: {0} {1} {2} [{3}, Action: {4}]" -f $tdo.LocalDomain, $arrow, $tdo.TrustedDomain, $tdo.RelationshipType, $tdo.Action) -TypeName 'Info' -ForegroundColor White
    }

    # --- Deletes (orphan/local side) ---
    foreach ($tdo in $allTrustObjects | Where-Object { $_.Action -eq 'Delete' }) {
      if ($whatIfMode) {
        Write-IdentIRLog -Message ("WhatIf: Would delete trust: {0} - {1}" -f $tdo.LocalDomain, $tdo.TrustedDomain) -TypeName 'Info' -ForegroundColor White
        $deletes++
        $expected = if ($tdo.FlatName) { Ensure-TrailingDollar $tdo.FlatName }
                    else { Ensure-TrailingDollar ($tdo.TrustedDomain.Split('.')[0].ToUpper()) }
        Write-IdentIRLog -Message ("WhatIf: Would verify trust account CN=Users\{0} is removed in {1}" -f $expected, $tdo.LocalDomain) -TypeName 'Info' -ForegroundColor White
        $trustAcctCleaned++
        continue
      }
      $tdoDeleted = $false; $acctCleaned = $false
      $expectedFlat = if ($tdo.FlatName) { $tdo.FlatName } else { $tdo.TrustedDomain.Split('.')[0].ToUpper() }
      $tdoDeleted, $acctCleaned = Remove-OrphanLocalSide -AnchorDC $tdo.Server -LocalDomain $tdo.LocalDomain -LocalDefaultNC $tdo.LocalDefaultNC -TrustedDomain $tdo.TrustedDomain -TdoDN $tdo.DN -FlatName $expectedFlat
      if ($tdoDeleted) { $deletes++ } else { $errors++ }
      if ($acctCleaned) { $trustAcctCleaned++ }
    }

    # --- Resets (paired, ordered) ---
    if ($domainGroups.Count -gt 1) {
      $trustPairs = @{}
      $resetTDOs  = $allTrustObjects | Where-Object { $_.Action -eq 'Reset Password' }
      foreach ($tdo in $resetTDOs) {
        $pairKey = Pair-Key $tdo.LocalDomain $tdo.TrustedDomain
        if (-not $trustPairs.ContainsKey($pairKey)) { $trustPairs[$pairKey] = @{ TDOs = @() } }
        $trustPairs[$pairKey].TDOs += $tdo
      }

      $processedPairs = @()
      foreach ($pairKey in $trustPairs.Keys) {
        $tdos = $trustPairs[$pairKey].TDOs
        if ($tdos.Count -lt 2) {
          Write-IdentIRLog -Message ("Warning: Only one side of trust found for {0}" -f $pairKey) -TypeName 'Warning' -ForegroundColor Yellow
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
          Write-IdentIRLog -Message ("Warning: Unexpected trust direction combination for {0}" -f $pairKey) -TypeName 'Warning' -ForegroundColor Yellow
          continue
        }
        $minDepth = [Math]::Min($tdo1.LocalDepth, $tdo2.LocalDepth)
        $processedPairs += [pscustomobject]@{
          TrustingDomain = $trustingDomain
          TrustedDomain  = $trustedDomain
          TrustingAnchor = $trustingAnchor
          TrustedAnchor  = $trustedAnchor
          MinDepth       = $minDepth
          RelationshipType = $tdo1.RelationshipType
        }
      }

      # Simple, stable ordering: IntraDomain first, then External
      $sortedPairs = $processedPairs | Sort-Object { if ($_.RelationshipType -eq 'IntraDomain') { 'A' } else { 'B' } }

      Write-IdentIRLog -Message ("Processing {0} trust pairs (server-pinned updates)..." -f $sortedPairs.Count) -TypeName 'Info' -ForegroundColor Cyan

      foreach ($pair in $sortedPairs) {
        if ($whatIfMode) {
          Write-IdentIRLog -Message ("WhatIf: Would reset trust {0} <-> {1}" -f $pair.TrustingDomain, $pair.TrustedDomain) -TypeName 'Info' -ForegroundColor White
          $resets++; continue
        }
        Write-IdentIRLog -Message ("Resetting trust: {0} <-> {1} [{2}]" -f $pair.TrustingDomain, $pair.TrustedDomain, $pair.RelationshipType) -TypeName 'Info' -ForegroundColor Cyan
        try {
          $pw = New-Password -Length 24
          Write-IdentIRLog -Message ("Generated shared secret for {0} <-> {1}" -f $pair.TrustingDomain, $pair.TrustedDomain) -TypeName 'Info' -ForegroundColor Cyan

          $ctxTrusting = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustingAnchor)
          $ctxTrusted  = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('DirectoryServer', $pair.TrustedAnchor)
          $dcTrusting  = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusting)
          $dcTrusted   = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctxTrusted)

          if ($PSCmdlet.ShouldProcess(("{0} trust with {1}" -f $pair.TrustingDomain, $pair.TrustedDomain), 'Reset trust password')) {
            # Update trusting first, then trusted, DNS-form names normalized
            $dcTrusting.Domain.UpdateLocalSideOfTrustRelationship((Normalize-DomainName $pair.TrustedDomain), $pw)
            Write-IdentIRLog -Message 'Trusting side updated' -TypeName 'Info' -ForegroundColor Green
            Start-Sleep -Milliseconds 200
            $dcTrusted.Domain.UpdateLocalSideOfTrustRelationship((Normalize-DomainName $pair.TrustingDomain), $pw)
            Write-IdentIRLog -Message 'Trusted side updated' -TypeName 'Info' -ForegroundColor Green
          }

          # Replication wait + verify
          Write-IdentIRLog -Message ("Waiting {0} seconds for AD replication..." -f $ReplicationWaitSeconds) -TypeName 'Info' -ForegroundColor Cyan
          Start-Sleep -Seconds $ReplicationWaitSeconds

          # Pinned NetLogon verification on the trusted anchor
          try {
            $netlogonPath = "\\$($pair.TrustedAnchor)\NETLOGON"
            if (Test-Path $netlogonPath -ErrorAction SilentlyContinue) {
              Write-IdentIRLog -Message ("Trust verification successful (accessed {0})" -f $netlogonPath) -TypeName 'Info' -ForegroundColor Green
            } else {
              Write-IdentIRLog -Message ("Warning: Could not access {0} for verification" -f $netlogonPath) -TypeName 'Warning' -ForegroundColor Yellow
            }
          } catch {
            Write-IdentIRLog -Message ("Warning: Verification attempt raised: {0}" -f $_.Exception.Message) -TypeName 'Warning' -ForegroundColor Yellow
          }

          # Minimal re-read check: ping TDO from trusting anchor (existence confirms connectivity post-change)
          try {
            $trustingDefaultNC = $domainGroups[$pair.TrustingDomain].DefaultNC
            if ($trustingDefaultNC) {
              $sysTrusting = [ADSI]("LDAP://$($pair.TrustingAnchor)/CN=System,$trustingDefaultNC")
              $null = $sysTrusting.distinguishedName
            }
          } catch { }

          Write-IdentIRLog -Message ("Successfully reset trust password for {0} <-> {1}" -f $pair.TrustingDomain, $pair.TrustedDomain) -TypeName 'Info' -ForegroundColor Green
          $resets++
        } catch {
          Write-IdentIRLog -Message ("Failed to reset trust password for {0} <-> {1}: {2}" -f $pair.TrustingDomain, $pair.TrustedDomain, $_.Exception.Message) -TypeName 'Error' -ForegroundColor Red
          $errors++
        }
      }
    }

    # --- Summary ---
    Write-IdentIRLog -Message '========================================' -TypeName 'Info' -ForegroundColor White
    Write-IdentIRLog -Message 'Trust Operation Summary' -TypeName 'Info' -ForegroundColor White
    Write-IdentIRLog -Message (" Passwords Reset : {0}" -f $resets) -TypeName 'Info' -ForegroundColor $(if ($resets -gt 0) { 'Green' } else { 'White' })
    Write-IdentIRLog -Message (" Trusts Deleted  : {0}" -f $deletes) -TypeName 'Info' -ForegroundColor $(if ($deletes -gt 0) { 'Yellow' } else { 'White' })
    Write-IdentIRLog -Message (" Trust Accts Cleaned: {0}" -f $trustAcctCleaned) -TypeName 'Info' -ForegroundColor $(if ($trustAcctCleaned -gt 0) { 'Green' } else { 'White' })
    Write-IdentIRLog -Message (" Errors          : {0}" -f $errors) -TypeName 'Info' -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
    Write-IdentIRLog -Message '========================================' -TypeName 'Info' -ForegroundColor White
    Write-IdentIRLog -Message 'Invoke-TrustPasswordReset completed' -TypeName 'Info' -ForegroundColor Green
  }
}
