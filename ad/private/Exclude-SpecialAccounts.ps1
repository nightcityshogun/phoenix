function Exclude-SpecialAccounts {
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
