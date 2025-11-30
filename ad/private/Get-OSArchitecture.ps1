function Get-OSArchitecture {
    try {
        $osInfo = [System.Management.ManagementObjectSearcher]::new("SELECT OSArchitecture FROM Win32_OperatingSystem").Get()
        $architecture = $osInfo | Select-Object -ExpandProperty OSArchitecture

        if ($architecture -match "ARM") {
            Write-IdentIRLog -Message "[UNSUPPORTED] This script requires x64 or x86 architecture." -TypeName 'Error' -ForegroundColor 'Red'
            exit
        } else {
            Write-IdentIRLog -Message "[SUPPORTED] OS architecture detected: $architecture." -TypeName 'Info' -ForegroundColor 'Cyan'
        }
    } catch {
        Write-IdentIRLog -Message "[UNKNOWN] Failed to determine OS architecture. Error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor 'Red'
        exit
    }
}