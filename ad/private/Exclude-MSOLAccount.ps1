function Exclude-MSOLAccount {
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
}
