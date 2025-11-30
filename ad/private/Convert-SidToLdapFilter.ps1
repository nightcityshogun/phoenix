function Convert-SidToLdapFilter {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SidString
    )

    $sid   = New-Object System.Security.Principal.SecurityIdentifier($SidString)
    $bytes = New-Object byte[]($sid.BinaryLength)
    $sid.GetBinaryForm($bytes, 0)

    return ($bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
}
