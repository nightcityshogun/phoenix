<#
.SYNOPSIS
Performs bulk password resets for user accounts in an isolated Active Directory domain.

.DESCRIPTION
Invoke-MassPasswordReset enumerates all user accounts in a target domain and resets their passwords, 
excluding accounts from specific OUs, keywords, or predefined exclusion rules.  
By default, runs in simulation mode (WhatIf=True). When -Execute is specified, passwords are reset on the target DC.

.PARAMETER Domain
Specifies the Active Directory domain to target.

.PARAMETER ExcludedOUs
Optional list of organizational units to exclude from processing.

.PARAMETER KeywordRules
Optional keyword-based filters for excluding specific accounts.

.PARAMETER Execute
Applies password resets. When omitted, actions are simulated (WhatIf=True).

.PARAMETER IsolatedDCList
List of isolated domain controller objects used to locate the target DC.  
The PDC emulator is preferred when available.

.EXAMPLE
Invoke-MassPasswordReset -Domain "contoso.com" -IsolatedDCList $dcs -Execute

.EXAMPLE
Invoke-MassPasswordReset -Domain "contoso.com" -ExcludedOUs "OU=Service,DC=contoso,DC=com" -IsolatedDCList $dcs

.OUTPUTS
None. Writes log and progress output for each account processed.

.NOTES
Author: NightCityShogun  
Version: 1.0  
Requires: LDAP (ADSI) access to a writable DC with sufficient privileges.  
© 2025 NightCityShogun. All rights reserved.
#>

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
        $targetDC = if ($pdc) { $pdc.FQDN } else { ($IsolatedDCList | Where-Object { $_.Online } | Select-Object -First 1).FQDN }
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
        $message = "Initiating mass password reset in domain $Domain using DC $targetDC (WhatIf: $Execute)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green
        # Initialize excluded users
        $excludedUsers = New-Object System.Collections.Generic.HashSet[string]
        # Fixed exclusions
        Exclude-CurrentUser -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-MSOLAccount -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-BuiltinAdmin -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        Exclude-SpecialAccounts -TargetDC $targetDC -DomainNC $domainNC -Excluded $excludedUsers
        # OU exclusions
        foreach ($ou in $ExcludedOUs) {
            try {
                $searcher = [ADSISearcher]"(&(objectCategory=person)(objectClass=user)(!(objectCategory=computer)))"
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
                $message = "Excluded $ouUserCount users from OU ${ou}"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                Write-Host $message -ForegroundColor Cyan
            } catch {
                $message = "Error excluding users from OU ${ou}: $($_.Exception.Message)"
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
            }
        }
        # Log excluded users
        $message = "Total excluded accounts: $($excludedUsers.Count)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Cyan
        foreach ($ex in $excludedUsers) {
            $message = "[EXCLUSION] Excluded Account: $ex"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Cyan
        }
        # Get all users
        $searcher = [ADSISearcher]"(&(objectCategory=person)(objectClass=user)(!(objectCategory=computer))(!(samAccountName=*$)))"
        $searcher.SearchRoot = [ADSI]"LDAP://${targetDC}/${domainNC}"
        $searcher.SearchScope = "Subtree"
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
        $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
        $searcher.PageSize = 1000
        try {
            $allUsers = $searcher.FindAll()
            if (-not $allUsers -or $allUsers.Count -eq 0) {
                $message = "No users found in domain $Domain"
                Write-IdentIRLog -Message $message -TypeName 'Warning'
                Write-Host $message -ForegroundColor Yellow
                return
            }
            $message = "Found $($allUsers.Count) users in domain $Domain"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Green
        } catch {
            $message = "Failed to query users in domain ${Domain}: $($_.Exception.Message)"
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            throw $message
        }
        # Filter users
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
                $value = $rule.Value
                switch ($rule.Type.ToLower()) {
                    'startswith' { if ($sam.StartsWith($value, [StringComparison]::OrdinalIgnoreCase)) { $excludeByKeyword = $true } }
                    'endswith' { if ($sam.EndsWith($value, [StringComparison]::OrdinalIgnoreCase)) { $excludeByKeyword = $true } }
                    'contains' { if ($sam -imatch [regex]::Escape($value)) { $excludeByKeyword = $true } }
                    'has' { if ($sam -imatch "\b$([regex]::Escape($value))\b") { $excludeByKeyword = $true } }
                    'equals' { if ($sam -ieq $value) { $excludeByKeyword = $true } }
                    default {
                        $message = "Unknown keyword rule type: $($rule.Type)"
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
                DistinguishedName = $dn
                SamAccountName = $sam
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
                            $uac = $userObj.userAccountControl[0] # Access first value
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
        $message = "[SCRIPT] Completed mass password reset for domain $Domain (WhatIf: $Execute)"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green
    } catch {
        $message = "Fatal error in mass password reset for domain ${Domain}: $($_.Exception.Message)"
        Write-IdentIRLog -Message $message -TypeName 'Error'
        Write-Host $message -ForegroundColor Red
        throw
    } finally {
        Write-Progress -Activity "Resetting User Passwords in $Domain" -Completed
        if ($allUsers) { $allUsers.Dispose() }
    }
}
