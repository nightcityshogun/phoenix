function Exclude-CurrentUser {
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
