    <#
    .SYNOPSIS
    Seizes FSMO roles to a chosen online, writable domain controller in an isolated AD environment.
    If and only if the RID Master changes in a domain, raises rIDAvailablePool by +100000
    and invalidates the RID pool using ADSI.

    .DESCRIPTION
    Invoke-FSMORoleSeizure validates the DC list, prefers the PDC, and reassigns FSMO roles.
    - All FSMO seizures use ADSI with simple string assignment
    - If RID Master changes, performs RID pool increase and invalidation via ADSI
    Runs in simulation mode by default (WhatIf=True). Use -Execute to apply changes.

    .PARAMETER IsolatedDCList
    List of domain controller objects (FQDN, Domain, Type, Online, Naming Contexts).

    .PARAMETER Credential
    Optional credential for ADSI binds.

    .PARAMETER Execute
    Applies changes. When omitted, actions are simulated.

    .EXAMPLE
    # Simulate all remediation actions
    Invoke-FSMORoleSeizure -IsolatedDCList $dcs  

    .EXAMPLE
    # Apply all remediation changes
    Invoke-FSMORoleSeizure -IsolatedDCList $dcs -Execute

    .NOTES
    Author: NightCityShogun  
    Version: 3.0  
    All operations use ADSI (FSMO seizure and RID maintenance)
    © 2025 NightCityShogun. All rights reserved.
    #>
function Invoke-FSMORoleSeizure {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject[]]$IsolatedDCList,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$Execute
    )

    if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
        Write-IdentIRLog -Message "IsolatedDCList is empty." -TypeName 'Error' -ForegroundColor Red
        return
    }

    $oldConfirm = $script:ConfirmPreference
    $script:ConfirmPreference = 'None'
    $oldWhatIf = $WhatIfPreference

    try {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        # Validate (ServerReferenceBL is optional; we'll prefer it when present)
        $list = @($IsolatedDCList)
        foreach ($dc in $list) {
            $required = @('FQDN','Domain','Type','Online','DefaultNamingContext','ConfigurationNamingContext')
            $missing  = $required | Where-Object {
                -not $dc.PSObject.Properties[$_] -or $null -eq $dc.$_ -or ($dc.$_.ToString() -eq '')
            }
            if ($missing) { throw "Invalid IsolatedDCList entry for $($dc.FQDN): Missing $($missing -join ', ')" }
        }

        # Forest Root -> Child Domain -> Tree Root (PDC first within domain later)
        $sorted = $list | Sort-Object {
            switch ($_.Type) { 'Forest Root' {1}; 'Child Domain' {2}; 'Tree Root' {3}; default {4} }
        }
        $domainGroups = @($sorted | Group-Object Domain)
        if (-not $domainGroups -or @($domainGroups).Count -eq 0) {
            Write-IdentIRLog -Message "No eligible domains to process." -TypeName 'Warning' -ForegroundColor Yellow
            return
        }

        # Drive native WhatIf from -Execute
        $WhatIfPreference = -not [bool]$Execute
        Write-IdentIRLog -Message ("Starting FSMO role seizures across {0} domain(s) (WhatIf={1})" -f @($domainGroups).Count, $WhatIfPreference) -TypeName 'Info' -ForegroundColor Cyan

        # ADSI helper with optional credential
        function _GetDE {
            param([string]$Path)
            if ($Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            } else {
                [ADSI]$Path
            }
        }

        foreach ($grp in $domainGroups) {
            $domainName = $grp.Name

            # Online only; skip RODCs if flagged
            $domainDcs = @($grp.Group | Where-Object { $_.Online })
            if ($domainDcs -and $domainDcs[0].PSObject.Properties['IsRODC']) {
                $domainDcs = @($domainDcs | Where-Object { -not $_.IsRODC })
            }
            if (-not $domainDcs) {
                Write-IdentIRLog -Message "No online writable DCs for $domainName. Skipping." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            # PDC first
            $orderedDcs = @()
            $orderedDcs += @($domainDcs | Where-Object { $_.IsPdcRoleOwner })
            $orderedDcs += @($domainDcs | Where-Object { -not $_.IsPdcRoleOwner })

            # Target DC (first in ordered list)
            $t = $orderedDcs[0]
            $fqdn     = $t.FQDN
            $domainNC = $t.DefaultNamingContext
            $configNC = $t.ConfigurationNamingContext
            $isForestRoot = ($t.Type -eq 'Forest Root')

            # Prefer ServerReferenceBL from input, else resolve from RootDSE.serverName
            $serverRefBL = $null
            if ($t.PSObject.Properties['ServerReferenceBL'] -and $t.ServerReferenceBL) {
                # Normalize whitespace in case the string was line-wrapped in output
                $serverRefBL = ($t.ServerReferenceBL -replace '\s+', ' ').Trim()
                Write-IdentIRLog -Message "Using ServerReferenceBL from inventory for $fqdn" -TypeName 'Info' -ForegroundColor White
            } else {
                try {
                    $r = [ADSI]"LDAP://$fqdn/RootDSE"
                    $serverRefBL = ("" + $r.serverName).Trim()
                    Write-IdentIRLog -Message "Resolved ServerReferenceBL from RootDSE for $fqdn" -TypeName 'Info' -ForegroundColor White
                } catch {
                    Write-IdentIRLog -Message "Unable to read RootDSE.serverName on ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    continue
                }
            }
            if (-not $serverRefBL) {
                Write-IdentIRLog -Message "serverName / ServerReferenceBL not available for $fqdn. Skipping $domainName." -TypeName 'Error' -ForegroundColor Red
                continue
            }

            Write-IdentIRLog -Message "Starting FSMO processing for domain $domainName via $fqdn ($(@($orderedDcs).Count) online DCs)" -TypeName 'Info' -ForegroundColor Cyan

            # CORRECT FSMO PATHS - Domain roles; add forest roles only in Forest Root
            $roles = @(
                @{ Name='PDC Emulator'; Path="LDAP://$fqdn/$domainNC" },
                @{ Name='RID Master'; Path="LDAP://$fqdn/CN=RID Manager$,CN=System,$domainNC" },
                @{ Name='Infrastructure Master'; Path="LDAP://$fqdn/CN=Infrastructure,$domainNC" }
            )
            if ($isForestRoot) {
                $roles += @(
                    @{ Name='Schema Master'; Path="LDAP://$fqdn/CN=Schema,$configNC" },
                    @{ Name='Domain Naming Master'; Path="LDAP://$fqdn/CN=Partitions,$configNC" }
                )
            }

            $anyChanged = $false
            $ridChanged = $false

            foreach ($role in $roles) {
                $roleName = $role.Name
                $path     = $role.Path

                $de = _GetDE -Path $path
                if (-not $de) {
                    Write-IdentIRLog -Message "Bind failed: $path ($roleName)" -TypeName 'Error' -ForegroundColor Red
                    continue
                }

                # Read current owner with safe property checking
                $current = $null
                try {
                    $de.RefreshCache(@('fSMORoleOwner'))
                    if ($de.Properties.Contains('fSMORoleOwner') -and $de.Properties['fSMORoleOwner'].Count -gt 0) {
                        $current = [string]$de.Properties['fSMORoleOwner'][0]
                        if ($current) {
                            $current = $current.Trim()
                            Write-IdentIRLog -Message "$roleName current owner: $current" -TypeName 'Info' -ForegroundColor Gray
                        }
                    }
                } catch {
                    Write-IdentIRLog -Message "Read fSMORoleOwner failed on $path ($roleName): $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    continue
                }

                if ($current -and ($current -eq $serverRefBL)) {
                    Write-IdentIRLog -Message "$roleName already owned by $fqdn, skipping." -TypeName 'Info' -ForegroundColor Yellow
                    continue
                }

                if ($PSCmdlet.ShouldProcess("$fqdn", "Seize $roleName")) {
                    if ($WhatIfPreference) {
                        # Native "What if:" line printed by PowerShell
                        $anyChanged = $true
                        if ($roleName -eq 'RID Master') { $ridChanged = $true }
                        continue
                    }
                    try {
                        # ADSI simple string assignment (no COM objects required)
                        $de.Put('fSMORoleOwner', $serverRefBL)
                        $de.SetInfo()
                        Write-IdentIRLog -Message "Seized $roleName to $fqdn" -TypeName 'Info' -ForegroundColor Green
                        $anyChanged = $true
                        if ($roleName -eq 'RID Master') { $ridChanged = $true }
                    } catch {
                        Write-IdentIRLog -Message "Seize $roleName failed on ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    }
                }
            }

            # Update RID Manager owner if any domain role changed (safe and idempotent)
            if ($anyChanged) {
                if ($PSCmdlet.ShouldProcess("$fqdn", "Update RID Manager owner")) {
                    if (-not $WhatIfPreference) {
                        try {
                            $ridPath = "LDAP://$fqdn/CN=RID Manager$,CN=System,$domainNC"
                            $ridDE   = _GetDE -Path $ridPath
                            $ridDE.RefreshCache()
                            $ridDE.Put('fSMORoleOwner', $serverRefBL)
                            $ridDE.SetInfo()
                            Write-IdentIRLog -Message "RID Manager owner updated for $fqdn" -TypeName 'Info' -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "RID Manager owner update failed on ${fqdn}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                        }
                    }
                }
            } else {
                Write-IdentIRLog -Message "No FSMO role changes required for $fqdn." -TypeName 'Info' -ForegroundColor Yellow
            }

            # ========================================================================
            # RID MAINTENANCE: ONLY if RID Master changed AND Execute mode is on
            # Uses ADSI directly (no remote execution needed)
            # ========================================================================
            if ($ridChanged) {
                if ($WhatIfPreference) {
                    Write-IdentIRLog -Message "Skipping RID maintenance for $domainName (WhatIf=True; RID change simulated)." -TypeName 'Info' -ForegroundColor Yellow
                } else {
                    Write-IdentIRLog -Message "Starting RID maintenance for domain $domainName (+100000 & invalidate) on $fqdn" -TypeName 'Info' -ForegroundColor Cyan

                    try {
                        # Bind to RID Manager object on target DC
                        $ridPath = "LDAP://$fqdn/CN=RID Manager$,CN=System,$domainNC"
                        Write-IdentIRLog -Message "Binding to RID Manager: $ridPath" -TypeName 'Info' -ForegroundColor White
                        $ridObject = _GetDE -Path $ridPath
                        
                        # Read current RID pool using DirectorySearcher
                        Write-IdentIRLog -Message "Reading current rIDAvailablePool value" -TypeName 'Info' -ForegroundColor White
                        $ridPoolSearcher = New-Object System.DirectoryServices.DirectorySearcher($ridObject)
                        $ridPoolSearcher.PropertiesToLoad.Add("rIDAvailablePool") | Out-Null
                        $searchResult = $ridPoolSearcher.FindOne()
                        
                        if (-not $searchResult -or -not $searchResult.Properties.Contains("ridavailablepool")) {
                            throw "Failed to retrieve rIDAvailablePool attribute"
                        }
                        
                        $currentRidPool = $searchResult.Properties["ridavailablepool"][0]
                        Write-IdentIRLog -Message "Current rIDAvailablePool: $currentRidPool" -TypeName 'Info' -ForegroundColor Gray
                        
                        # Calculate new RID pool value
                        $increase = 100000
                        $newRidPool = [string]([int64]$currentRidPool + $increase)
                        Write-IdentIRLog -Message "New rIDAvailablePool: $newRidPool (increase of $increase)" -TypeName 'Info' -ForegroundColor White
                        
                        # Update RID pool
                        Write-IdentIRLog -Message "Updating rIDAvailablePool attribute" -TypeName 'Info' -ForegroundColor White
                        $ridObject.Put('rIDAvailablePool', $newRidPool)
                        $ridObject.SetInfo()
                        Write-IdentIRLog -Message "Successfully raised RID pool from $currentRidPool to $newRidPool" -TypeName 'Info' -ForegroundColor Green
                        
                        # Verify the change
                        Write-IdentIRLog -Message "Verifying RID pool update" -TypeName 'Info' -ForegroundColor White
                        $ridObject.RefreshCache(@("rIDAvailablePool"))
                        $verifySearcher = New-Object System.DirectoryServices.DirectorySearcher($ridObject)
                        $verifySearcher.PropertiesToLoad.Add("rIDAvailablePool") | Out-Null
                        $verifyResult = $verifySearcher.FindOne()
                        $verifiedValue = $verifyResult.Properties["ridavailablepool"][0]
                        
                        if ([int64]$verifiedValue -ne [int64]$newRidPool) {
                            throw "Verification failed! Expected $newRidPool but got $verifiedValue"
                        }
                        Write-IdentIRLog -Message "Verified: rIDAvailablePool = $verifiedValue" -TypeName 'Info' -ForegroundColor Green
                        
                        # Invalidate RID Pool
                        Write-IdentIRLog -Message "Invalidating RID pool on $fqdn" -TypeName 'Info' -ForegroundColor White
                        
                        # Get domain SID
                        $domainRootPath = "LDAP://$fqdn/$domainNC"
                        $domainObject = _GetDE -Path $domainRootPath
                        $domainObject.RefreshCache(@("objectSid"))
                        $domainSid = $domainObject.Properties["objectSid"][0]
                        
                        if (-not $domainSid) {
                            throw "Failed to retrieve domain SID"
                        }
                        
                        # Bind to RootDSE and invalidate
                        $rootDSEPath = "LDAP://$fqdn/RootDSE"
                        $rootDSE = _GetDE -Path $rootDSEPath
                        $rootDSE.UsePropertyCache = $false
                        $rootDSE.Put('invalidateRidPool', $domainSid)
                        $rootDSE.SetInfo()
                        Write-IdentIRLog -Message "Successfully invalidated RID pool" -TypeName 'Info' -ForegroundColor Green
                        
                        Write-IdentIRLog -Message "Completed RID maintenance for $domainName" -TypeName 'Info' -ForegroundColor Green
                        
                    } catch {
                        Write-IdentIRLog -Message "RID maintenance failed for ${domainName}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    }
                }
            } else {
                Write-IdentIRLog -Message "Skipping RID maintenance for $domainName (RID Master did not change)." -TypeName 'Info' -ForegroundColor Yellow
            }

            Write-IdentIRLog -Message "Completed domain $domainName" -TypeName 'Info' -ForegroundColor White
        }
    }
    catch {
        Write-IdentIRLog -Message "Seize FSMO Roles failed: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        throw
    }
    finally {
        $script:ConfirmPreference = $oldConfirm
        $WhatIfPreference = $oldWhatIf
    }
}
