function Get-BuiltinAdmin {
    param (
        [Parameter(Mandatory=$true)][string] $TargetDns,
        [Parameter(Mandatory=$true)][string] $DomSid
    )

    # SID to LDAP Octet-String
    function _Escape-SidForLdap([System.Security.Principal.SecurityIdentifier]$Sid) {
        $bytes = New-Object byte[] ($Sid.BinaryLength)
        $Sid.GetBinaryForm($bytes, 0)
        ($bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
    }

    try {
        $rootDse = [ADSI]("LDAP://$TargetDns/RootDSE")
        $defaultNC = $rootDse.defaultNamingContext
        if (-not $defaultNC) { throw "defaultNamingContext is null" }
    } catch {
        return $null
    }

    try {
        $rid500 = New-Object System.Security.Principal.SecurityIdentifier("$DomSid-500")
        $escapedSid = _Escape-SidForLdap $rid500
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$TargetDns/$defaultNC")
        $ds = New-Object System.DirectoryServices.DirectorySearcher $de
        $ds.PageSize = 1000
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $null = $ds.PropertiesToLoad.Add('distinguishedName')
        $null = $ds.PropertiesToLoad.Add('sAMAccountName')
        $null = $ds.PropertiesToLoad.Add('objectSid')
        $ds.Filter = "(&(objectClass=user)(objectSid=$escapedSid))"
        $sr = $ds.FindOne()
        if (-not $sr) {
            return $null
        }
        $dn = $sr.Properties['distinguishedName'][0]
        $user = [ADSI]"LDAP://$TargetDns/$dn"
        if (-not $user) {
            return $null
        }
        return $user
    } catch {
        return $null
    }
}