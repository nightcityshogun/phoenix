function Get-OSVersion {
    [CmdletBinding()]
    param(
        # Require a specific arch or allow any
        [ValidateSet('Any','x86','x64')]
        [string]$RequiredArch = 'Any',

        # Throw if unsupported (instead of just logging + returning IsSupported=$false)
        [switch]$ThrowOnUnsupported
    )

    try {
        # Prefer CIM for OS basics
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        $arch   = $os.OSArchitecture
        $isARM  = ($arch -match 'ARM')
        $isX86  = ($arch -match '32-bit')
        $isX64  = ($arch -match '64-bit')

        # Read richer version info from registry
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

        $caption        = $os.Caption
        $productTypeMap = @{ 1 = 'Workstation'; 2 = 'Domain Controller'; 3 = 'Server' }
        $productType    = $productTypeMap[[int]$os.ProductType]
        $isServer       = ($os.ProductType -in 2,3)

        # Build components
        $build = if ($cv.CurrentBuild) { [int]$cv.CurrentBuild } else { [int]$os.BuildNumber }
        $ubr   = if ($cv.UBR -ne $null) { [int]$cv.UBR } else { 0 }

        # Compose a [version] object (Major.Minor.Build.Revision)
        $major = if ($cv.CurrentMajorVersionNumber -ne $null) { [int]$cv.CurrentMajorVersionNumber } else { ($os.Version.Split('.')[0] -as [int]) }
        $minor = if ($cv.CurrentMinorVersionNumber -ne $null) { [int]$cv.CurrentMinorVersionNumber } else { ($os.Version.Split('.')[1] -as [int]) }
        $verObj = [version]::new($major, $minor, $build, $ubr)

        # Determine support based on arch requirement
        $supported = -not $isARM
        if ($RequiredArch -eq 'x86') { $supported = $supported -and $isX86 }
        elseif ($RequiredArch -eq 'x64') { $supported = $supported -and $isX64 }

        $obj = [pscustomobject]@{
            CSName         = $os.CSName
            Caption        = $caption
            Architecture   = $arch
            IsARM          = $isARM
            IsX86          = $isX86
            IsX64          = $isX64
            RequiredArch   = $RequiredArch
            IsSupported    = $supported
            ProductType    = $productType
            IsServer       = $isServer
            EditionID      = $cv.EditionID
            ProductName    = $cv.ProductName
            DisplayVersion = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
            Version        = $verObj                 # [version] type
            VersionString  = "$($verObj.Major).$($verObj.Minor).$($verObj.Build).$($verObj.Revision)"
            Build          = $build
            UBR            = $ubr
            InstallDate    = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
            LastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        }

        if ($isARM) {
            Write-IdentIRLog -Message "[UNSUPPORTED] ARM architecture detected: $arch." -TypeName 'Error' -ForegroundColor Red
            if ($ThrowOnUnsupported) { throw "Unsupported architecture: $arch" }
        } else {
            Write-IdentIRLog -Message "[SUPPORTED] $($obj.Caption) ($arch) Build $build.$ubr [$productType]." -TypeName 'Info' -ForegroundColor Cyan
        }

        return $obj
    }
    catch {
        Write-IdentIRLog -Message "[UNKNOWN] Failed to determine OS info. Error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        if ($ThrowOnUnsupported) { throw }
        return $null
    }
}
