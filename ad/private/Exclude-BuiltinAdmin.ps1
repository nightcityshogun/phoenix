function Exclude-BuiltinAdmin {
    param (
        [string]$TargetDC,
        [string]$DomainNC,
        [System.Collections.Generic.HashSet[string]]$Excluded
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
    $adminSidFilter = Convert-SidToLdapFilter -SidString $adminSid
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
