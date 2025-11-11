function Write-IdentIRLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position=0)]
        [string]$Message,
        [Parameter()]
        [ValidateSet('Normal', 'Warning', 'Error', 'Info')]
        [string]$TypeName = 'Normal',
        [Parameter()]
        [ValidateSet('Gray', 'Green', 'Red', 'White', 'Yellow', 'Cyan')]
        [System.ConsoleColor]$ForegroundColor,
        [Parameter()]
        [switch]$PrependNewLine,
        [Parameter()]
        [switch]$AppendNewLine,
        [Parameter()]
        [string]$LogDirectory = "$env:LOCALAPPDATA\Praevia",
        [Parameter()]
        [string]$LogFileName,
        [Parameter()]
        [ValidateSet('CCM', 'JSON', 'Simple', 'Compact')]
        [string]$LogFormat = 'Simple'
    )
    begin {
        # Ensure log directory exists
        if (-not (Test-Path -Path $LogDirectory)) {
            try {
                New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "Failed to create log directory at $LogDirectory : $_"
                return
            }
        }
        # Set default log file name with daily timestamp if not provided
        if (-not $LogFileName) {
            $timestamp = Get-Date -Format 'yyyyMMdd'
            $LogFileName = "IdentIR_$timestamp.log"
        }
        $fullLogPath = Join-Path -Path $LogDirectory -ChildPath $LogFileName
        # Create log file if it doesn't exist
        if (-not (Test-Path -Path $fullLogPath)) {
            try {
                New-Item -Path $fullLogPath -ItemType File -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "Failed to create log file at $fullLogPath : $_"
                return
            }
        }
        # Sanitize log message to prevent injection
        $sanitizedMessage = $Message -replace '[\r\n<>]', ''
    }
    process {
        # Write to console if ForegroundColor is specified
        if ($ForegroundColor) {
            if ($PrependNewLine) { Write-Host "`n" -NoNewline }
            Write-Host $sanitizedMessage -ForegroundColor $ForegroundColor
            if ($AppendNewLine) { Write-Host "`n" }
        }
        # Write to log file based on format
        try {
            switch ($LogFormat) {
                'CCM' {
                    $typeMap = @{ Normal = 1; Warning = 2; Error = 3; Info = 1 }
                    $logHeader = 'IdentIR<![LOG[{0}]LOG]!>' -f $sanitizedMessage
                    $sb = [System.Text.StringBuilder]::new()
                    # Generate unique log entry ID and message hash
                    $logEntryId = [guid]::NewGuid().ToString()
                    $messageHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($sanitizedMessage)
                    ) | ForEach-Object { $_.ToString('x2') } | Join-String -Separator ''
                    $messageHash = $messageHash.Substring(0, 8) # Shorten for brevity
                    # Collect unique metadata
                    $metadata = @{
                        time = Get-Date -Format 'HH:mm:ss.ffffff'
                        date = Get-Date -Format 'M-d-yyyy'
                        component = (Get-PSCallStack)[1].Command
                        context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        type = $typeMap[$TypeName]
                        thread = [Threading.Thread]::CurrentThread.ManagedThreadId
                        file = Split-Path -Path $MyInvocation.ScriptName -Leaf
                        logId = $logEntryId
                        msgHash = $messageHash
                        machine = $env:COMPUTERNAME
                        psVersion = $PSVersionTable.PSVersion.ToString()
                    }
                    $null = $sb.Append($logHeader)
                    $null = $sb.Append('<time="').Append($metadata.time).Append('" ')
                    $null = $sb.Append('date="').Append($metadata.date).Append('" ')
                    $null = $sb.Append('component="').Append($metadata.component).Append('" ')
                    $null = $sb.Append('context="').Append($metadata.context).Append('" ')
                    $null = $sb.Append('type="').Append($metadata.type).Append('" ')
                    $null = $sb.Append('thread="').Append($metadata.thread).Append('" ')
                    $null = $sb.Append('file="').Append($metadata.file).Append('" ')
                    $null = $sb.Append('logId="').Append($metadata.logId).Append('" ')
                    $null = $sb.Append('msgHash="').Append($metadata.msgHash).Append('" ')
                    $null = $sb.Append('machine="').Append($metadata.machine).Append('" ')
                    $null = $sb.Append('psVersion="').Append($metadata.psVersion).Append('">')
                    [System.IO.File]::AppendAllText($fullLogPath, $sb.ToString() + [Environment]::NewLine)
                }
                'JSON' {
                    $logEntry = @{
                        Timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'
                        Type = $TypeName
                        Message = $sanitizedMessage
                        Component = (Get-PSCallStack)[1].Command
                        Thread = [Threading.Thread]::CurrentThread.ManagedThreadId
                        LogId = [guid]::NewGuid().ToString()
                        Machine = $env:COMPUTERNAME
                    } | ConvertTo-Json -Compress
                    [System.IO.File]::AppendAllText($fullLogPath, $logEntry + [Environment]::NewLine)
                }
                'Simple' {
                    $logEntry = 'IdentIR {0} : {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $sanitizedMessage
                    [System.IO.File]::AppendAllText($fullLogPath, $logEntry + [Environment]::NewLine)
                }
                'Compact' {
                    $logEntryId = [guid]::NewGuid().ToString().Substring(0, 8)
                    $messageHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($sanitizedMessage)
                    ) | ForEach-Object { $_.ToString('x2') } | Join-String -Separator ''
                    $messageHash = $messageHash.Substring(0, 8)
                    $logEntry = "IdentIR|$logEntryId|$($TypeName.Substring(0,1))|$((Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'))|$sanitizedMessage|$messageHash"
                    [System.IO.File]::AppendAllText($fullLogPath, $logEntry + [Environment]::NewLine)
                }
            }
        }
        catch {
            Write-Error "Failed to write to log file at $fullLogPath : $_"
        }
    }
}