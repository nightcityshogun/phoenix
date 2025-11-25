function Invoke-MassPasswordReset {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string[]]$ExcludedOUs = @(),

        [Parameter(Mandatory=$false)]
        [object[]]$KeywordRules = @(),

        [Parameter(Mandatory=$true)]
        [bool]$Execute,

        [Parameter(Mandatory=$true)]
        [object[]]$IsolatedDCList
    )

    try {
        # Validate IsolatedDCList
        if (-not $IsolatedDCList -or $IsolatedDCList.Count -eq 0) {
            $message = "No domain controllers provided in IsolatedDCList for domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        # Select target DC, prefer PDC
        $pdc = $IsolatedDCList | Where-Object { $_.IsPdcRoleOwner -and $_.Online } | Select-Object -First 1
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

        $domainNC = ($IsolatedDCList | Where-Object { $_.Domain.ToLower() -eq $Domain.ToLower() } | Select-Object -First 1).DefaultNamingContext
        if (-not $domainNC) {
            $message = "DefaultNamingContext not found for domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }

        $message = "Initiating mass password reset in domain $Domain using DC $targetDC (Execute: $Execute)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green

        # Initialize excluded users
        $excludedUsers = New-Object System.Collections.Generic.HashSet[string]

        # Fixed exclusions
        Exclude-CurrentUser     -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-MSOLAccount     -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-BuiltinAdmin    -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-SpecialAccounts -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers

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
                        $excludedUsers.Add($dn) | Out-Null
                        $ouUserCount++
                    }
                }

                $message = "Excluded $ouUserCount users from DN root ${ou}"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                Write-Host $message -ForegroundColor Cyan
            } catch {
                $message = "Error excluding users from DN root ${ou}: $($_.Exception.Message)"
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
            }
        }

        # Log excluded users
        $message = "Total excluded accounts (pre-LDAP filter): $($excludedUsers.Count)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan

        foreach ($ex in $excludedUsers) {
            $message = "[EXCLUSION] Excluded Account: $ex"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Cyan
        }

        # ----------------------
        # Build LDAP filter
        # ----------------------
        $ldapFilter = "(&(objectCategory=person)(objectClass=user)(!(objectCategory=computer))(!(samAccountName=*$))"

        if ($KeywordRules -and $KeywordRules.Count -gt 0) {
            $excludeClauses = @()

            foreach ($rule in $KeywordRules) {
                if (-not $rule) { continue }

                # Support both hashtables and PSCustomObjects / real objects
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

                $value = Escape-LdapFilterValue -Value $raw

                switch ($type) {
                    'startswith' { $excludeClauses += "(samAccountName=${value}*)" }
                    'starts'     { $excludeClauses += "(samAccountName=${value}*)" }

                    'endswith'   { $excludeClauses += "(samAccountName=*${value})" }
                    'ends'       { $excludeClauses += "(samAccountName=*${value})" }

                    'contains'   { $excludeClauses += "(samAccountName=*${value}*)" }

                    'equals'     { $excludeClauses += "(samAccountName=${value})" }
                    'equal'      { $excludeClauses += "(samAccountName=${value})" }
                    'eq'         { $excludeClauses += "(samAccountName=${value})" }

                    # 'has' and any other advanced rule types stay in the *PowerShell* layer only
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
                # Build:  ... ( ! ( | (cond1)(cond2)... ) )
                $orBlock = "(|" + ($excludeClauses -join '') + ")"
                $ldapFilter += "(!${orBlock})"
            }
        }

        # Close outer (& ...)
        $ldapFilter += ")"

        $message = "Using LDAP filter for mass reset in ${Domain}: $ldapFilter"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan

        # Get all users via LDAP with the composed filter
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
        # PowerShell-side keyword filter (belt & suspenders)
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
                Write-Host $message -ForegroundColor Cyan
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

                # Same robust handling as above
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

                    'contains'   { if ($sam -imatch [regex]::Escape($value))                         { $excludeByKeyword = $true } }

                    'has'        { if ($sam -imatch "\b$([regex]::Escape($value))\b")                { $excludeByKeyword = $true } }

                    'equals'     { if ($sam -ieq $value)                                            { $excludeByKeyword = $true } }
                    'equal'      { if ($sam -ieq $value)                                            { $excludeByKeyword = $true } }
                    'eq'         { if ($sam -ieq $value)                                            { $excludeByKeyword = $true } }

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
                Write-Host $message -ForegroundColor Cyan
                continue
            }

            $usersToProcess += @{
                DistinguishedName  = $dn
                SamAccountName     = $sam
                UserAccountControl = $userResult.Properties["useraccountcontrol"][0]
            }
        }

        # Process users
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

        $currentCount = 0

        foreach ($user in $usersToProcess) {
            $currentCount++
            $dn = $user.DistinguishedName

            if ($Execute) {
                try {
                    $newPassword = New-Password
                    if (-not $newPassword) {
                        $message = "Failed to generate a new password for $dn"
                        Write-IdentIRLog -Message $message -TypeName 'Error'
                        Write-Host $message -ForegroundColor Red
                        throw $message
                    }

                    $userObj = [ADSI]"LDAP://${targetDC}/${dn}"
                    if (-not $userObj) {
                        $message = "Failed to bind to user object $dn"
                        Write-IdentIRLog -Message $message -TypeName 'Error'
                        Write-Host $message -ForegroundColor Red
                        throw $message
                    }

                    # Reset password twice to ensure history compliance
                    for ($i = 1; $i -le 2; $i++) {
                        $userObj.SetPassword($newPassword)
                        $userObj.SetInfo()
                        if ($i -eq 1) {
                            $uac = $userObj.userAccountControl[0]
                            if ($uac -band 0x10000) { # PasswordNeverExpires
                                $uac = $uac -band -bnot 0x10000
                                $userObj.userAccountControl = $uac
                                $userObj.SetInfo()
                            }
                        }
                    }

                    $message = "[USER] Password successfully reset for: $dn"
                    Write-IdentIRLog -Message $message -TypeName 'Info'
                    Write-Host $message -ForegroundColor Green
                } catch {
                    $message = "[USER] Error resetting password for ${dn}: $($_.Exception.Message)"
                    Write-IdentIRLog -Message $message -TypeName 'Error'
                    Write-Host $message -ForegroundColor Red
                    continue
                }
            } else {
                $message = "[WHATIF] Would reset password for: $dn"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                Write-Host $message -ForegroundColor Yellow
            }

            $percentComplete = [math]::Round(($currentCount / $totalUsers) * 100, 2)
            Write-Progress -Activity "Resetting User Passwords in $Domain" -Status "Processing $currentCount of $totalUsers users" -PercentComplete $percentComplete
        }

        $message = "[USERS RESET] Total users where password was $(if ($Execute) { 'reset' } else { 'would be reset' }): $currentCount"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green

        $message = "[SCRIPT] Completed mass password reset for domain $Domain (Execute: $Execute)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green
    }
    catch {
        $message = "Fatal error in mass password reset for domain ${Domain}: $($_.Exception.Message)"
        Write-IdentIRLog -Message $message -TypeName 'Error'
        Write-Host $message -ForegroundColor Red
        throw
    }
    finally {
        Write-Progress -Activity "Resetting User Passwords in $Domain" -Completed
        if ($allUsers) { $allUsers.Dispose() }
    }
}
