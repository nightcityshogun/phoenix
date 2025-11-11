#region Strings (reserved for localization)

#region Function Imports
# Load all private function
Get-ChildItem -Path "$PSScriptRoot\Private" -Filter *.ps1 -Recurse |
    ForEach-Object { . $_.FullName }

# Load all public functions
Get-ChildItem -Path "$PSScriptRoot\Public" -Filter *.ps1 -Recurse |
    ForEach-Object { . $_.FullName }
#endregion

#region Global Script Variables
$script:useCcmLogFormat = $true
$script:logDirectory    = 'logs'

# Generate timestamped log file name
$timestamp = Get-Date -Format "ddMMyyyyHHmmss"
$script:logName = "$timestamp-IdentIR.log"

$userPath = [Environment]::GetFolderPath('MyDocuments')
$script:userPath = Join-Path -Path $userPath -ChildPath 'IdentIR'

foreach ($subPath in @($script:userPath, "$script:userPath\IdentIR", "$script:userPath\IdentIR\$script:logDirectory")) {
    if (-not (Test-Path -Path $subPath)) {
        $null = New-Item -Path $subPath -ItemType Directory -Force
    }
}

$script:moduleDocsPath = Join-Path -Path $script:userPath -ChildPath 'IdentIR'
$script:moduleLogPath  = Join-Path -Path $script:moduleDocsPath -ChildPath $script:logDirectory
#endregion
