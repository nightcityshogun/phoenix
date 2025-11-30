function Invoke-MassPasswordReset {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludedOUs = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$KeywordRules = @(),

        [Parameter(Mandatory = $true)]
        [bool]$Execute,

        [Parameter(Mandatory = $true)]
        [object[]]$IsolatedDCList,

        # 0 = auto (4 x cores, max 128). Otherwise explicit max concurrent user operations.
        [int]$MaxConcurrency = 0,

        # How many times to set the same password (max 2; WinUI dropdown will send 1 or 2)
        [ValidateSet(1, 2)]
        [int]$PasswordResetCount = 1
    )

    # Ensure sane default even if someone bypasses validation somehow
    if ($PasswordResetCount -lt 1 -or $PasswordResetCount -gt 2) {
        $PasswordResetCount = 1
    }

    $allUsers     = $null
    $runspacePool = $null

    # -----------------------------
    # Embedded helper "functions"
    # -----------------------------
    # (scriptblocks so we don't pollute global function namespace)

    # RFC4515-safe escaping for LDAP filter values
    $escapeLdapFilterValue = {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Value
        )
        $v = $Value
        $v = $v -replace '\\', '\5c'
        $v = $v -replace '\*', '\2a'
        $v = $v -replace '\(', '\28'
        $v = $v -replace '\)', '\29'
        $v = $v -replace '\x00', '\00'
        return $v
    }

    # Convert SID string (S-1-5-21-...) -> LDAP binary filter value (\01\02\03...)
    $convertSidToLdapFilter = {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SidString
        )
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $bytes = New-Object byte[] ($sid.BinaryLength)
        $sid.GetBinaryForm($bytes, 0)
        return (($bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join '')
    }

    $excludeCurrentUser = {
        param (
            [string]$TargetDC,
            [string]$DomainNC,
            [System.Collections.Generic.HashSet[string]]$Excluded
        )
        $cUSamAccountName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[-1]
        $searcher = [ADSISearcher]"(&(objectCategory=user)(samAccountName=$cUSamAccountName))"
        $searcher.SearchRoot = [ADSI]"LDAP://$TargetDC/$DomainNC"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.SearchScope = "Subtree"
        $result = $searcher.FindOne()
        if ($result) {
            $Excluded.Add($result.Properties["distinguishedname"][0]) | Out-Null
        } else {
            Write-IdentIRLog -Message "Current logged-on user not found in domain." -TypeName "Warning"
        }
    }

    $excludeMSOLAccount = {
        param (
            [string]$TargetDC,
            [string]$DomainNC,
            [System.Collections.Generic.HashSet[string]]$Excluded
        )
        $searcher = [ADSISearcher]"(&(objectCategory=user)(samAccountName=MSOL_*))"
        $searcher.SearchRoot = [ADSI]"LDAP://${TargetDC}/${DomainNC}"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.SearchScope = "Subtree"
        $results = $searcher.FindAll()
        foreach ($result in $results) {
            $Excluded.Add($result.Properties["distinguishedname"][0]) | Out-Null
        }
        if ($results.Count -eq 0) {
            Write-IdentIRLog -Message "MSOL account not found in domain." -TypeName "Warning"
            Write-Host "MSOL account not found in domain." -ForegroundColor Yellow
        }
        $results.Dispose()
    }

    $excludeBuiltinAdmin = {
        param (
            [string]$TargetDC,
            [string]$DomainNC,
            [System.Collections.Generic.HashSet[string]]$Excluded,
            [scriptblock]$ConvertSidToFilter
        )

        $sidSearcher = [ADSISearcher]"(&(objectCategory=domain)(distinguishedName=${DomainNC}))"
        $sidSearcher.SearchRoot = [ADSI]"LDAP://${TargetDC}"
        $sidSearcher.PropertiesToLoad.Add("objectSid") | Out-Null
        $sidResult = $sidSearcher.FindOne()
        if ($sidResult) {
            $domainSidBytes = $sidResult.Properties["objectsid"][0]
            $domainSidValue = (New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)).Value
        } else {
            Write-IdentIRLog -Message "Failed to retrieve domain SID." -TypeName "Warning"
            Write-Host "Failed to retrieve domain SID." -ForegroundColor Yellow
            return
        }

        $adminSid = $domainSidValue + '-500'
        $adminSidFilter = & $ConvertSidToFilter -SidString $adminSid

        $searcher = [ADSISearcher]"(&(objectCategory=user)(objectSid=$adminSidFilter))"
        $searcher.SearchRoot = [ADSI]"LDAP://${TargetDC}/${DomainNC}"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.SearchScope = "Subtree"
        $result = $searcher.FindOne()
        if ($result) {
            $Excluded.Add($result.Properties["distinguishedname"][0]) | Out-Null
        } else {
            Write-IdentIRLog -Message "Built-in admin account not found in domain." -TypeName "Warning"
            Write-Host "Built-in admin account not found in domain." -ForegroundColor Yellow
        }
    }

    $excludeSpecialAccounts = {
        param (
            [string]$TargetDC,
            [string]$DomainNC,
            [System.Collections.Generic.HashSet[string]]$Excluded
        )

        # KRBTGT
        $searcher = [ADSISearcher]"(&(objectCategory=user)(samAccountName=krbtgt))"
        $searcher.SearchRoot = [ADSI]"LDAP://${TargetDC}/${DomainNC}"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.SearchScope = "Subtree"
        $result = $searcher.FindOne()
        if ($result) {
            $Excluded.Add($result.Properties["distinguishedname"][0]) | Out-Null
        } else {
            Write-IdentIRLog -Message "KRBTGT account not found in domain." -TypeName "Warning"
            Write-Host "KRBTGT account not found in domain." -ForegroundColor Yellow
        }

        # Guest
        $searcher = [ADSISearcher]"(&(objectCategory=user)(samAccountName=Guest))"
        $searcher.SearchRoot = [ADSI]"LDAP://${TargetDC}/${DomainNC}"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.SearchScope = "Subtree"
        $result = $searcher.FindOne()
        if ($result) {
            $Excluded.Add($result.Properties["distinguishedname"][0]) | Out-Null
        } else {
            Write-IdentIRLog -Message "Guest account not found in domain." -TypeName "Warning"
            Write-Host "Guest account not found in domain." -ForegroundColor Yellow
        }
    }

    try {
        Add-Type -AssemblyName System.DirectoryServices

        # -----------------------------
        # Validate IsolatedDCList / pick DC
        # -----------------------------
        if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
            $message = "No domain controllers provided in IsolatedDCList for domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        # Defensive: ensure objects have expected properties
        foreach ($dc in $IsolatedDCList) {
            if (-not ($dc.PSObject.Properties.Name -contains 'FQDN')) {
                throw "IsolatedDCList contains an object without an FQDN property."
            }
        }

        $pdc = $IsolatedDCList |
            Where-Object { $_.IsPdcRoleOwner -and $_.Online } |
            Select-Object -First 1

        $targetDC = if ($pdc) {
            $pdc.FQDN
        } else {
            ($IsolatedDCList | Where-Object { $_.Online } | Select-Object -First 1).FQDN
        }

        if (-not $targetDC) {
            $message = "No online domain controller found for domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        $domainNC = ($IsolatedDCList |
            Where-Object { $_.Domain.ToLower() -eq $Domain.ToLower() } |
            Select-Object -First 1).DefaultNamingContext

        if (-not $domainNC) {
            $message = "DefaultNamingContext not found for domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        $message = "Initiating mass password reset in domain $Domain using DC $targetDC (Execute: $Execute, PasswordResetCount: $PasswordResetCount)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green

        # -------------------------
        # Build excluded users set
        # -------------------------
        $excludedUsers = [System.Collections.Generic.HashSet[string]]::new()

        # Fixed exclusions (now embedded)
        & $excludeCurrentUser     -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        & $excludeMSOLAccount     -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        & $excludeBuiltinAdmin    -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers -ConvertSidToFilter $convertSidToLdapFilter
        & $excludeSpecialAccounts -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers

        # DistinguishedName / OU exclusions (from UI)
        foreach ($ou in $ExcludedOUs) {
            if (-not $ou) { continue }
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(!(objectCategory=computer)))"
                $searcher.SearchRoot = [ADSI]"LDAP://${targetDC}/${ou}"
                $searcher.SearchScope = "Subtree"
                $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
                $searcher.PageSize = 1000

                $results = $searcher.FindAll()
                $ouUserCount = 0
                foreach ($result in $results) {
                    $dn = $result.Properties["distinguishedname"][0]
                    if ($dn) {
                        [void]$excludedUsers.Add($dn)
                        $ouUserCount++
                    }
                }
                $results.Dispose()

                $message = "Excluded $ouUserCount users from DN root ${ou}"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                Write-Host $message -ForegroundColor Cyan
            } catch {
                $message = "Error excluding users from DN root ${ou}: $($_.Exception.Message)"
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
            }
        }

        # Log excluded users (log-only, no console spam)
        $message = "Total excluded accounts (pre-LDAP filter): $($excludedUsers.Count)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan

        foreach ($ex in $excludedUsers) {
            $message = "[EXCLUSION] Excluded Account: $ex"
            Write-IdentIRLog -Message $message -TypeName 'Info'
        }

        # ----------------------
        # Build LDAP filter
        # ----------------------
        $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(objectCategory=computer))(!(samAccountName=*$))"

        if ($KeywordRules -and $KeywordRules.Count -gt 0) {
            $excludeClauses = @()

            foreach ($rule in $KeywordRules) {
                if (-not $rule) { continue }

                $typeProp  = $null
                $valueProp = $null

                if ($rule -is [System.Collections.IDictionary]) {
                    if ($rule.Contains('Type'))  { $typeProp  = $rule['Type'] }
                    if ($rule.Contains('Value')) { $valueProp = $rule['Value'] }
                } else {
                    try { $typeProp  = $rule.Type }  catch {}
                    try { $valueProp = $rule.Value } catch {}

                    if (-not $typeProp) {
                        $typeProp = $rule | Select-Object -ExpandProperty Type -ErrorAction SilentlyContinue
                    }
                    if (-not $valueProp) {
                        $valueProp = $rule | Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue
                    }
                }

                if (-not $typeProp -or -not $valueProp) {
                    $message = "Keyword rule missing Type/Value; skipping rule: $($rule | ConvertTo-Json -Compress -ErrorAction SilentlyContinue)"
                    Write-IdentIRLog -Message $message -TypeName 'Warning'
                    Write-Host $message -ForegroundColor Yellow
                    continue
                }

                $type  = $typeProp.ToString().ToLower()
                $raw   = $valueProp.ToString()
                if ([string]::IsNullOrWhiteSpace($raw)) { continue }

                $value = & $escapeLdapFilterValue -Value $raw

                switch ($type) {
                    'startswith' { $excludeClauses += "(samAccountName=${value}*)" }
                    'starts'     { $excludeClauses += "(samAccountName=${value}*)" }
                    'endswith'   { $excludeClauses += "(samAccountName=*${value})" }
                    'ends'       { $excludeClauses += "(samAccountName=*${value})" }
                    'contains'   { $excludeClauses += "(samAccountName=*${value}*)" }
                    'equals'     { $excludeClauses += "(samAccountName=${value})" }
                    'equal'      { $excludeClauses += "(samAccountName=${value})" }
                    'eq'         { $excludeClauses += "(samAccountName=${value})" }
                    'has' {
                        $message = "Keyword rule type 'has' will be applied in PowerShell filtering only (not LDAP)."
                        Write-IdentIRLog -Message $message -TypeName 'Info'
                        Write-Host $message -ForegroundColor Yellow
                    }
                    default {
                        $message = "Unknown keyword rule type for LDAP filter: $type"
                        Write-IdentIRLog -Message $message -TypeName 'Warning'
                        Write-Host $message -ForegroundColor Yellow
                    }
                }
            }

            if ($excludeClauses.Count -gt 0) {
                $orBlock = "(|" + ($excludeClauses -join '') + ")"
                $ldapFilter += "(!${orBlock})"
            }
        }

        $ldapFilter += ")"

        $message = "Using LDAP filter for mass reset in ${Domain}: $ldapFilter"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan

        # ----------------------
        # Get users via LDAP
        # ----------------------
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = $ldapFilter
        $searcher.SearchRoot = [ADSI]"LDAP://${targetDC}/${domainNC}"
        $searcher.SearchScope = "Subtree"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.PropertiesToLoad.Add("samAccountName")     | Out-Null
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
        $searcher.PageSize = 1000

        try {
            $allUsers = $searcher.FindAll()
            if (-not $allUsers -or $allUsers.Count -eq 0) {
                $message = "No users found in domain $Domain with specified criteria."
                Write-IdentIRLog -Message $message -TypeName 'Warning'
                Write-Host $message -ForegroundColor Yellow
                return
            }
            $message = "Found $($allUsers.Count) users in domain $Domain after LDAP filtering."
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Green
        } catch {
            $message = "Failed to query users in domain ${Domain}: $($_.Exception.Message)"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        # ----------------------
        # PowerShell-side keyword filter
        # ----------------------
        $usersToProcess = @()

        foreach ($userResult in $allUsers) {
            $dn = $userResult.Properties["distinguishedname"][0]
            if (-not $dn) {
                $message = "[SKIPPED] User skipped due to missing distinguishedName"
                Write-IdentIRLog -Message $message -TypeName 'Warning'
                Write-Host $message -ForegroundColor Yellow
                continue
            }

            if ($excludedUsers.Contains($dn)) {
                $message = "[EXCLUSION] Skipped due to exclusion list: $dn"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                continue
            }

            $sam = $userResult.Properties["samaccountname"][0]
            if (-not $sam) {
                $message = "[SKIPPED] User skipped due to missing samAccountName: $dn"
                Write-IdentIRLog -Message $message -TypeName 'Warning'
                Write-Host $message -ForegroundColor Yellow
                continue
            }

            $excludeByKeyword = $false

            foreach ($rule in $KeywordRules) {
                if (-not $rule) { continue }

                $typeProp  = $null
                $valueProp = $null

                if ($rule -is [System.Collections.IDictionary]) {
                    if ($rule.Contains('Type'))  { $typeProp  = $rule['Type'] }
                    if ($rule.Contains('Value')) { $valueProp = $rule['Value'] }
                } else {
                    try { $typeProp  = $rule.Type }  catch {}
                    try { $valueProp = $rule.Value } catch {}

                    if (-not $typeProp) {
                        $typeProp = $rule | Select-Object -ExpandProperty Type -ErrorAction SilentlyContinue
                    }
                    if (-not $valueProp) {
                        $valueProp = $rule | Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue
                    }
                }

                if (-not $typeProp -or -not $valueProp) { continue }

                $type  = $typeProp.ToString().ToLower()
                $value = $valueProp.ToString()

                switch ($type) {
                    'startswith' { if ($sam.StartsWith($value, [StringComparison]::OrdinalIgnoreCase)) { $excludeByKeyword = $true } }
                    'starts'     { if ($sam.StartsWith($value, [StringComparison]::OrdinalIgnoreCase)) { $excludeByKeyword = $true } }
                    'endswith'   { if ($sam.EndsWith($value, [StringComparison]::OrdinalIgnoreCase))   { $excludeByKeyword = $true } }
                    'ends'       { if ($sam.EndsWith($value, [StringComparison]::OrdinalIgnoreCase))   { $excludeByKeyword = $true } }
                    'contains'   { if ($sam -imatch [regex]::Escape($value))                          { $excludeByKeyword = $true } }
                    'has'        { if ($sam -imatch "\b$([regex]::Escape($value))\b")                 { $excludeByKeyword = $true } }
                    'equals'     { if ($sam -ieq $value)                                             { $excludeByKeyword = $true } }
                    'equal'      { if ($sam -ieq $value)                                             { $excludeByKeyword = $true } }
                    'eq'         { if ($sam -ieq $value)                                             { $excludeByKeyword = $true } }
                    default {
                        $message = "Unknown keyword rule type (PowerShell filter): $type"
                        Write-IdentIRLog -Message $message -TypeName 'Warning'
                        Write-Host $message -ForegroundColor Yellow
                    }
                }

                if ($excludeByKeyword) { break }
            }

            if ($excludeByKeyword) {
                $message = "[EXCLUSION] Keyword Excluded: $dn (sAM: $sam)"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                continue
            }

            $usersToProcess += [PSCustomObject]@{
                DistinguishedName  = $dn
                SamAccountName     = $sam
                UserAccountControl = $userResult.Properties["useraccountcontrol"][0]
            }
        }

        # ----------------------
        # Process users (runspace pool)
        # ----------------------
        $totalUsers = $usersToProcess.Count
        if ($totalUsers -eq 0) {
            $message = "No users to process after applying exclusions in domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Warning'
            Write-Host $message -ForegroundColor Yellow
            return
        }

        $message = "Processing $totalUsers users for password reset in domain $Domain"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green

        # Determine max concurrency
        if ($MaxConcurrency -le 0) {
            $cpuCount = [System.Environment]::ProcessorCount
            $MaxConcurrency = [Math]::Min(($cpuCount * 4), 128)
        }
        if ($MaxConcurrency -lt 1) { $MaxConcurrency = 1 }

        $message = "Using runspace pool with max concurrency: $MaxConcurrency"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan

        # Create runspace pool (fully qualified type to avoid type resolution issues)
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrency)
        $runspacePool.ApartmentState = 'MTA'
        $runspacePool.Open()

        $runspaces = [System.Collections.Generic.List[object]]::new()

        # Create worker tasks
        foreach ($user in $usersToProcess) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $runspacePool

            # Generate password here so we don't depend on New-Password inside the runspace
            $password = $null
            if ($Execute) {
                $password = New-Password
                if (-not $password) {
                    $msg = "Failed to generate a new password for $($user.DistinguishedName); skipping."
                    Write-IdentIRLog -Message $msg -TypeName 'Error'
                    Write-Host $msg -ForegroundColor Red
                    continue
                }
            }

            [void]$ps.AddScript({
                param(
                    $User,
                    [string]$TargetDC,
                    [bool]$Execute,
                    [int]$PasswordResetCount,
                    [string]$Password
                )

                Add-Type -AssemblyName System.DirectoryServices

                $dn  = $User.DistinguishedName
                $sam = $User.SamAccountName

                $result = [PSCustomObject]@{
                    DistinguishedName = $dn
                    SamAccountName    = $sam
                    Success           = $false
                    Error             = $null
                    Executed          = $Execute
                }

                if (-not $Execute) {
                    # WhatIf: no LDAP changes, just mark as "would reset"
                    $result.Success = $true
                    return $result
                }

                try {
                    $userObj = [ADSI]"LDAP://${TargetDC}/${dn}"
                    if (-not $userObj) {
                        throw "Failed to bind to user object $dn"
                    }

                    for ($i = 1; $i -le $PasswordResetCount; $i++) {
                        $userObj.SetPassword($Password)
                        $userObj.SetInfo()

                        if ($i -eq 1) {
                            try {
                                $uac = [int]$userObj.userAccountControl[0]
                                if ($uac -band 0x10000) { # PasswordNeverExpires
                                    $uac = $uac -band -bnot 0x10000
                                    $userObj.userAccountControl = $uac
                                    $userObj.SetInfo()
                                }
                            } catch {
                                # UAC adjustment is best-effort; ignore errors here
                            }
                        }
                    }

                    $result.Success = $true
                } catch {
                    $result.Error = $_.Exception.Message
                }

                return $result
            }).AddParameter("User", $user).
               AddParameter("TargetDC", $targetDC).
               AddParameter("Execute", $Execute).
               AddParameter("PasswordResetCount", $PasswordResetCount).
               AddParameter("Password", $password)

            $handle = $ps.BeginInvoke()

            $runspaces.Add([PSCustomObject]@{
                PowerShell = $ps
                Handle     = $handle
            })
        }

        $processedCount = 0
        $successCount   = 0
        $failureCount   = 0

        # Collect results as they complete
        while ($runspaces.Count -gt 0) {
            foreach ($rs in @($runspaces.ToArray())) {
                if ($rs.Handle.IsCompleted) {
                    $result = $rs.PowerShell.EndInvoke($rs.Handle)
                    $rs.PowerShell.Dispose()
                    [void]$runspaces.Remove($rs)

                    if ($result) {
                        $processedCount++

                        $dn  = $result.DistinguishedName
                        $sam = $result.SamAccountName

                        if ($result.Success) {
                            $successCount++

                            if ($Execute) {
                                $msg = "[USER] Password successfully reset for: $dn"
                                Write-IdentIRLog -Message $msg -TypeName 'Info'
                                # no Write-Host here to avoid console spam
                            } else {
                                $msg = "[WHATIF] Would reset password for: $dn"
                                Write-IdentIRLog -Message $msg -TypeName 'Info'
                            }
                        } else {
                            $failureCount++
                            $errMsg = if ($result.Error) {
                                "[USER] Error resetting password for ${dn}: $($result.Error)"
                            } else {
                                "[USER] Error resetting password for ${dn}: Unknown error."
                            }
                            Write-IdentIRLog -Message $errMsg -TypeName 'Error'
                            Write-Host $errMsg -ForegroundColor Red
                        }

                        # Progress (based on processed, not just scheduled)
                        $percentComplete = [math]::Round(($processedCount / $totalUsers) * 100, 2)
                        Write-Progress -Activity "Resetting User Passwords in $Domain" `
                                       -Status "Processing $processedCount of $totalUsers users" `
                                       -PercentComplete $percentComplete
                    }
                }
            }

            Start-Sleep -Milliseconds 50
        }

        # Final summary
        $message = "[USERS RESET] Total users where password was $(if ($Execute) { 'reset' } else { 'would be reset' }): $successCount"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green

        if ($failureCount -gt 0) {
            $message = "[USERS RESET] Total users that failed password reset: $failureCount"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
        }

        $message = "[SCRIPT] Completed mass password reset for domain $Domain (Execute: $Execute, Success: $successCount, Failed: $failureCount)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green
    }
    catch {
        # beefed-up logging so if anything remains, you see where
        Write-Host "=== MASS RESET EXCEPTION ===" -ForegroundColor Red
        Write-Host ("Type:      {0}" -f $_.Exception.GetType().FullName) -ForegroundColor Red
        Write-Host ("Message:   {0}" -f $_.Exception.Message) -ForegroundColor Red
        Write-Host "StackTrace:" -ForegroundColor Red
        Write-Host $_.Exception.StackTrace -ForegroundColor Red

        $message = "Fatal error in mass password reset for domain ${Domain}: $($_.Exception.Message)"
        Write-IdentIRLog -Message $message -TypeName 'Error'
        Write-Host $message -ForegroundColor Red
        throw
    }
    finally {
        Write-Progress -Activity "Resetting User Passwords in $Domain" -Completed

        if ($allUsers) { $allUsers.Dispose() }

        if ($runspacePool) {
            $runspacePool.Close()
            $runspacePool.Dispose()
        }
    }
}
