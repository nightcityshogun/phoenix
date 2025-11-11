function Convert-SidToLdapFilter {
    param (
        [string]$SidString
    )
    $sid = New-Object System.Security.Principal.SecurityIdentifier $SidString
    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)
    $filter = '\' + (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join '\')
    return $filter
}
