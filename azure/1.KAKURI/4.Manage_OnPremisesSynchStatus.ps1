<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Graph and checks/updates the current status of On-Premises AD synchronization.

.DESCRIPTION
    This script connects to Azure and:
    - Checks the current status of On-Premises Synchronisation
    - Enables On-Premises Synchronisation
    - Disables On-Premises Synchronisation

.NOTES
    Author: NightCityShogun
    Name: Manage_OnPremisesSynchStatus
    Version: 3.8
    Date: 2023-06-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Beta.Identity.DirectoryManagement"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @("Directory.Read.All",
"Directory.ReadWrite.All",
"Organization.ReadWrite.All",
"Policy.ReadWrite.ConditionalAccess",
"Policy.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Ensure $OrgID is Initially Blank
$OrgID = $null

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# ------------------------------------------------------------------------------------------------------------------------

# Ensure the NCS Log Directory Exists in $env:LOCALAPPDATA\Temp
if (!(Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# Function to Write Log File Entries
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("SOS", "ERROR", "INFO", "WARNING", "IMPORTANT")]
        [string]$Level = "INFO",
        [bool]$LogOnly = $false  
    )

    $logEntry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFilePath -Value $logEntry

    if (-not $LogOnly) {
        # Define colors for each log level
        $logColor = @{
            "SOS"        = [System.ConsoleColor]::Green
            "ERROR"      = [System.ConsoleColor]::Red
            "INFO"       = [System.ConsoleColor]::White
            "WARNING"    = [System.ConsoleColor]::Yellow
            "IMPORTANT"  = [System.ConsoleColor]::Cyan
        }[$Level]

        # Write the log entry to the console with the specified color
        Write-Host -ForegroundColor $logColor $logEntry
    }
}

# Mark the Start of the Script
Write-Log -Message "[SCRIPT] Start of Manage_OnPremisesSynchStatus Script." -Level "SOS"

# Function: Check OS Architecture
function Check-OSArchitecture {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $architecture = $osInfo.OSArchitecture

        if ($architecture -match "ARM") {
            Write-Log -Message "[UNSUPPORTED] This script requires x64 or x86 architecture to install RSAT tools." -Level "ERROR"
            exit
        } else {
            Write-Log -Message "[SUPPORTED] OS architecture detected: $architecture." -Level "IMPORTANT"
        }
    } catch {
        Write-Log -Message "[UNKNOWN] Failed to determine OS architecture. Error: $_" -Level "ERROR"
        exit
    }
}

# Modules For Microsoft Graph
function Initialize-MicrosoftGraphEnvironment {
    # Ensure NuGet provider is installed and imported
    Write-Log -Message "Checking for NuGet provider..." -Level "INFO"
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue

    if (-not $nugetProvider) {
        Write-Log -Message "NuGet provider not found. Installing..." -Level "INFO"
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop
            Write-Log -Message  "NuGet provider installed successfully."
        } catch {
            Write-Log -Message  "Failed to install the NuGet provider. Error: $_" -Level "ERROR"
            exit
        }
    } else {
        Write-Log -Message "NuGet provider is already installed." -Level "INFO"
    }

    # Import NuGet provider
    Import-PackageProvider -Name NuGet -ErrorAction SilentlyContinue

    # Install and Import Microsoft Graph modules
    foreach ($module in $Modules) {
        try {
            if (!(Get-Module -ListAvailable -Name $module)) {
                Write-Log -Message "Module $module not found. Installing..." -Level "INFO"
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction SilentlyContinue 3>$null
            }
            Import-Module -Name $module -Force -ErrorAction SilentlyContinue 3>$null
            Write-Log -Message "Module $module imported successfully." -Level "INFO"
        } catch {
            Write-Log -Message "Error installing/importing module ${module}: $($_.Exception.Message)" -Level "ERROR"
            exit
        }
    }
}

# Function to connect to Microsoft Graph
function Connect-MSGraph {

    # Function to prompt for TenantId and validate user's confirmation only if a TenantId is provided
    function Get-TenantId {
        do {
            $TenantId = Read-Host "Enter the Tenant ID (leave blank to skip)"
            if ($TenantId) {
                do {
                    $confirmTenantId = Read-Host "You have entered: $TenantId. Is this correct? (Yes/No)"
                    if ($confirmTenantId -match '^(yes|y)$') {
                        return $TenantId  # Return TenantId if confirmed
                    } elseif ($confirmTenantId -match '^(no|n)$' -or -not $confirmTenantId) {
                        Write-Host "Proceeding without a Tenant ID." -ForegroundColor Yellow
                        return ""  # Return empty string to skip TenantId
                    } else {
                        Write-Host "Invalid input. Please answer Yes or No." -ForegroundColor Red
                    }
                } while ($true)
            } else {
                Write-Host "You have decided to proceed without a Tenant ID." -ForegroundColor Yellow
                return ""
            }
        } while ($true)
    }

    # Function to prompt for Environment and ensure valid input
    function Get-Environment {
        do {
            $Environment = Read-Host "Enter the Environment (China, Global, USGov, USGovDoD). Leave blank for 'Global'"
            if (-not $Environment) {
                Write-Host "No environment specified, defaulting to 'Global'." -ForegroundColor Yellow
                return "Global"
            } elseif ($validEnvironments -contains $Environment) {
                return $Environment
            } else {
                Write-Host "Invalid environment specified. Please enter one of the valid options: China, Global, USGov, USGovDoD." -ForegroundColor Red
            }
        } while ($true)
    }

    # Prompt for and validate TenantId and Environment
    $TenantId = Get-TenantId
    $Environment = Get-Environment

    # Attempt Microsoft Graph Connection
    try {
        $params = @{
            Scopes    = $Scopes
            NoWelcome = $true
            Environment = $Environment
        }

        if ($TenantId) {
            $params.TenantId = $TenantId
        }

        # Connect to Microsoft Graph
        Connect-MgGraph @params

        Write-Log -Message "Successfully connected to Microsoft Graph in the '$Environment' environment." -Level "SOS"
    } catch {
        Write-Log -Message "Failed to connect to Microsoft Graph. Error: $($_.Exception.Message)" -Level "ERROR"
        exit
    }
}

# Function to disconnect from Microsoft Graph
function Disconnect-MSGraph {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log -Message "Disconnected from Microsoft Graph" -Level "INFO"
    } catch {
        Write-Log -Message "Error disconnecting from Microsoft Graph: $_" -Level "ERROR"
    }
}

# Check License
function Check-License {
    try {
        $license = (Get-MgSubscribedSku).ServicePlans | Where-Object { $_.ServicePlanName -eq 'AAD_PREMIUM_P2' -and $_.ProvisioningStatus -eq 'Success' }
        if (-not $license) {
            $errorMessage = "Required AAD_PREMIUM_P2 license with 'Success' status not found."
            Write-Log -Message $errorMessage -Level "ERROR"
            exit
        }
        Write-Log -Message "Required AAD_PREMIUM_P2 license found with 'Success' status." -Level "INFO"
    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
        exit
    }
}

# Function to get the Organization ID
function Get-OrganizationID {
    try {
        $OrgID = (Get-MgOrganization).Id
        return $OrgID
    } catch {
        $errorMessage = "Failed to retrieve Organization ID: $($_.Exception.Message)"
        Write-Log -Message $errorMessage -Level "ERROR"
        Disconnect-MgGraph
        exit 1
    }
}

# Main Script Execution Flow

# Validate x86 Architecture
Check-OSArchitecture > $null

# Import Microsoft Graph Modules
Initialize-MicrosoftGraphEnvironment

Connect-MSGraph
Check-License
$OrgID = Get-OrganizationID
SLEEP 2
CLS

# ------------------------------------------------------------------------------------------------------------------------

# Function to Check OnPremisesSyncStatus
function Check-OnPremisesSyncStatus {
    try {
        $orgInfo = Get-MgBetaOrganization -OrganizationId $OrgID
        $syncStatusRaw = $orgInfo.OnPremisesSyncEnabled
        $lastSyncDateTime = $orgInfo.OnPremisesLastSyncDateTime

        $syncStatus = switch ($syncStatusRaw) {
            $true  { "Enabled" }
            $false {
                if ($lastSyncDateTime -ne $null) {
                    "Disabled (Historic Sync Detected)"
                } else {
                    "Disabled"
                }
            }
            Default { "Unknown" }
        }

        return $syncStatus
    } catch {
        $errorMessage = "Failed to check On-Premises Sync status: $($_.Exception.Message)"
        Write-Log -Message $errorMessage -Level "ERROR"
        return $null
    }
    SLEEP 2
    CLS
}

# Function to Enable On-Premises Synchronisation
function Enable-OnPremisesSync {
    $currentStatus = Check-OnPremisesSyncStatus
    if ($currentStatus -eq "Enabled") {
        Write-Log -Message "On-Premises Sync is already enabled. No action needed." -Level "INFO"
        return
    } elseif ($currentStatus -eq $null) {
        Write-Log -Message "Could not determine current sync status; enable action aborted." -Level "ERROR"
        return
    }

    $consent = Read-Host -Prompt "Are you sure you want to enable On-Premises Sync? (Yes/No)"
    if ($consent.ToLower() -notmatch '^(yes|y)$') {
        Write-Log -Message "Enable action canceled by user." -Level "INFO"
        return
    }

    $params = @{
        OnPremisesSyncEnabled = $true
    }
    try {
        Update-MgBetaOrganization -OrganizationId $OrgID -BodyParameter $params -ErrorAction SilentlyContinue
        Write-Log -Message "On-Premises Sync has been successfully enabled." -Level "INFO"
    } catch {
        if ($_.Exception.Message -match "Cannot Disable DirSync while enable is pending") {
            Write-Log -Message "A change is currently pending; enable action cannot proceed." -Level "WARNING"
        } else {
            Write-Log -Message "An error occurred while enabling On-Premises Sync: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Function to Disable On-Premises Synchronisation
function Disable-OnPremisesSync {
    $currentStatus = Check-OnPremisesSyncStatus
    if ($currentStatus -eq "Disabled" -or $currentStatus -eq "Disabled (Historic Sync Detected)") {
        Write-Log -Message "On-Premises Sync is already disabled. No action needed." -Level "INFO"
        return
    } elseif ($currentStatus -eq $null) {
        Write-Log -Message "Could not determine current sync status; disable action aborted." -Level "ERROR"
        return
    }

    $consent = Read-Host -Prompt "Are you sure you want to disable On-Premises Sync? (Yes/No)"
    if ($consent.ToLower() -notmatch '^(yes|y)$') {
        Write-Log -Message "Disable action canceled by user." -Level "INFO"
        return
    }

    $params = @{
        OnPremisesSyncEnabled = $false
    }
    try {
        Update-MgBetaOrganization -OrganizationId $OrgID -BodyParameter $params -ErrorAction SilentlyContinue
        Write-Log -Message "On-Premises Sync has been successfully disabled." -Level "INFO"
    } catch {
        if ($_.Exception.Message -match "Cannot Enable DirSync while disable is pending") {
            Write-Log -Message "A change is currently pending; disable action cannot proceed." -Level "WARNING"
        } else {
            Write-Log -Message "An error occurred while disabling On-Premises Sync: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}


# ------------------------------------------------------------------------------------------------------------------------

# Function to Show the Menu
function Show-Menu {
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host "Phase 1: KAKURI - Managed On-Premises Active Directory Synchronisation."        -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host "[1]: Enable OnPremisesSyncEnabled"
    Write-Host "[2]: Disable OnPremisesSyncEnabled"
    Write-Host "[3]: Exit"
    Write-Host ""
    Write-Host "Changes can take up to seventy-two (72) hours to take effect."                            -ForegroundColor Red
}

# Loop the Menu
do {
    Show-Menu
    Write-Host "--------------------------------------------------------------------------------------"
    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        1 { 
            Enable-OnPremisesSync  
            SLEEP 2
            CLS
        }
        2 { 
            Disable-OnPremisesSync
            SLEEP 2
            CLS
        }
        3 {
            Write-Host "Exiting the script..." -ForegroundColor Yellow
            # Exit Microsoft Graph Session
            Disconnect-MSGraph > $Null

            # Mark The End of the Script
            Write-Log -Message "[SCRIPT] End of Manage_OnPremisesSynchStatus Script." -Level "SOS"
            SLEEP 2
            CLS
            Exit
        }
        default { 
            Write-Host "Invalid choice. Please select again." 
            SLEEP 2
            CLS
        }
    }
} while ($true)


# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
