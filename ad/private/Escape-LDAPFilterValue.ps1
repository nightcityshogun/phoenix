function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    # RFC 4515: escape \ * ( ) and NUL
    $v = $Value
    $v = $v -replace '\\', '\5c'
    $v = $v -replace '\*', '\2a'
    $v = $v -replace '\(', '\28'
    $v = $v -replace '\)', '\29'
    $v = $v -replace '\x00', '\00'
    return $v
}
