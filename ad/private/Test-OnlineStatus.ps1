function Test-OnlineStatus {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,
        [int]$Port = 389,
        [int]$TimeoutMilliseconds = 200,
        [int]$MaxConcurrent = 50,
        [switch]$WinStyleHidden
    )
    $results = @{}
    if (-not $ComputerNames -or $ComputerNames.Count -eq 0) {
        if (-not $WinStyleHidden) {
            Write-IdentIRLog -Message "Test-OnlineStatus: No computer names provided, returning empty results." -TypeName 'Warning' -ForegroundColor Yellow
        }
        return $results
    }
    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrent)
    $runspacePool.Open()
    $runspaces = @()
    foreach ($computer in $ComputerNames) {
        $powershell = [PowerShell]::Create()
        $powershell.RunspacePool = $runspacePool
        [void]$powershell.AddScript({
            param($ComputerName, $Port, $TimeoutMilliseconds, $WinStyleHidden)
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $result = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
                $success = $result.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)
                if ($success) {
                    $tcpClient.EndConnect($result)
                    return $true
                }
                return $false
            } catch {
                if (-not $WinStyleHidden) {
                    Write-IdentIRLog -Message "Failed to connect to ${ComputerName}:$Port - $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
                }
                return $false
            } finally {
                if ($tcpClient) { $tcpClient.Close() }
            }
        }).AddParameter("ComputerName", $computer).AddParameter("Port", $Port).AddParameter("TimeoutMilliseconds", $TimeoutMilliseconds).AddParameter("WinStyleHidden", $WinStyleHidden)
        $runspaces += [PSCustomObject]@{
            PowerShell = $powershell
            Handle = $powershell.BeginInvoke()
            ComputerName = $computer
        }
    }
    foreach ($runspace in $runspaces) {
        $fqdnLower = $runspace.ComputerName.ToLower()
        $results[$fqdnLower] = $runspace.PowerShell.EndInvoke($runspace.Handle)
        $runspace.PowerShell.Dispose()
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
    return $results
}