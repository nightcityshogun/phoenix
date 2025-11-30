function Get-ReverseZoneIPv6 {
    param ([string]$IPAddress)
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()
        $nibbles = ($bytes | ForEach-Object { '{0:x2}' -f $_ } | ForEach-Object { $_.ToCharArray() }) -join '.'
        $reverseZones = @()
        for ($i = 4; $i -le 32; $i += 4) {
            $nibbleCount = $i * 2
            $zoneNibbles = $nibbles.Split('.') | Select-Object -Last $nibbleCount
            $zone = ($zoneNibbles -join '.') + '.ip6.arpa'
            $reverseZones += $zone
        }
        return $reverseZones
    } catch {
        Write-IdentIRLog -Message "Failed to compute IPv6 reverse zones for ${IPAddress}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        return @()
    }
}