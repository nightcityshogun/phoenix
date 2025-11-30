function Get-DeletionProtection {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject] $AccessEntry
    )

    try {
        $targetIdentity   = $AccessEntry.IdentityReference
        $permissionType   = $AccessEntry.AccessControlType
        $rightsAssigned   = $AccessEntry.ActiveDirectoryRights
        $isInheritedFlag  = $AccessEntry.IsInherited
        $matchesIdentity  = $targetIdentity -eq 'Everyone'
        $deniedAccess     = $permissionType -eq 'Deny'
        $deleteProtection = ($rightsAssigned -match 'Delete') -and ($rightsAssigned -match 'DeleteTree')
        $explicitOnly     = $isInheritedFlag -eq $false
        $isProtected = $matchesIdentity -and $deniedAccess -and $deleteProtection -and $explicitOnly
        return $isProtected
    }
    catch {
        Write-Error "Failed to evaluate protection status: $($_.Exception.Message)"
        return $false
    }
}
