function Get-ReverseZoneIPv4 {
    param ([string]$IPAddress)
    try {
        $ipParts = $IPAddress.Split('.')
        if ($ipParts.Length -ne 4) { return @() }
        $reverseZones = @()
        for ($i = 1; $i -le 3; $i++) {
            $zone = ($ipParts[($i-1)..0] -join '.') + '.in-addr.arpa'
            $reverseZones += $zone
        }
        return $reverseZones
    } catch {
        Write-IdentIRLog -Message "Failed to compute IPv4 reverse zones for ${IPAddress}: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        return @()
    }
}