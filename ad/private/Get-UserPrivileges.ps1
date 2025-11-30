function Get-UserPrivileges {
    [CmdletBinding()]
    param(
        [string[]]$Groups = @('Domain Admins', 'Enterprise Admins'),
        [switch]$PassThru
    )

    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-IdentIRLog -Message "Checking admin privileges for ${currentUser}" -TypeName 'Info' -ForegroundColor Green

        $forest     = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $rootDomain = $forest.RootDomain.Name

        $isAdmin  = $false
        $userName = $currentUser.Split('\')[-1]

        # Find the user DN
        $userSearch = New-Object System.DirectoryServices.DirectorySearcher([System.DirectoryServices.DirectoryEntry]"LDAP://$rootDomain")
        $userSearch.Filter = "(&(objectClass=user)(sAMAccountName=$userName))"
        [void]$userSearch.PropertiesToLoad.Add('distinguishedName')
        $userSearch.PageSize = 1000

        $user = $userSearch.FindOne()
        if (-not $user) { throw "User ${userName} not found" }

        $userDN = $user.Properties['distinguishedName'][0]

        foreach ($group in $Groups) {
            try {
                $gSearch = New-Object System.DirectoryServices.DirectorySearcher([System.DirectoryServices.DirectoryEntry]"LDAP://$rootDomain")
                $gSearch.Filter = "(&(objectClass=group)(sAMAccountName=$group))"
                [void]$gSearch.PropertiesToLoad.Add('member')
                $gSearch.PageSize = 1000

                $g = $gSearch.FindOne()
                if ($g -and $g.Properties['member'] -contains $userDN) {
                    $isAdmin = $true
                    break
                }
            } catch {
                # Ignore group lookup errors and continue
            }
        }

        if (-not $isAdmin) {
            $msg = "Insufficient permissions (need one of: {0})" -f ($Groups -join ', ')
            throw $msg
        }

        Write-IdentIRLog -Message "Verified Administrative Permissions" -TypeName 'Info' -ForegroundColor Green
        if ($PassThru) { return $true }
    }
    catch {
        Write-IdentIRLog -Message ("Failed to verify admin permissions: {0}`nDetails: {1}" -f `
            $_.Exception.Message, ($_.Exception | Format-List -Property * -Force | Out-String)) `
            -TypeName 'Error' -ForegroundColor Red
        if ($PassThru) { return $false }
        throw
    }
}
