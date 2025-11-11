<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Graph and allows for the creation of Temporary Access Passes (TAP) for either a single user or multiple users imported from a CSV file. It also provides operator consent prompts before proceeding with critical actions.

.DESCRIPTION
    The script connects to Azure via Microsoft Graph and provides the following capabilities:
    - Creates Temporary Access Passes for single or multiple users to facilitate authentication.
    - Can generate Temporary Access Passes with configurable attributes like duration and one-time use.

.NOTES
    Author: NightCityShogun
    Name: Manage_TemporaryAccessPass
    Version: 2.0
    Date: 2023-06-15
#>

# ------------------------------------------------------------------------------------------------------------------------
# Microsoft Graph PowerShell Modules
$modules = @("Microsoft.Graph.Authentication",
             "Microsoft.Graph.Identity.DirectoryManagement",
             "Microsoft.Graph.Identity.SignIns",
             'Microsoft.Graph.Users',
             'Microsoft.Graph.Users.Actions')

# Microsoft Graph API Scope and Permissions
$Scopes = @("Directory.Read.All",
            "Directory.ReadWrite.All",
            "Organization.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "User.ReadWrite",
            "User.ReadBasic.All",
            "User.Read.All",
            "User.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Search Pattern and Import Path
$csvFilePattern = "Generate_TemporaryAccessPass*.csv"
$csvPath = Get-ChildItem -Path $PSScriptRoot -Filter $csvFilePattern | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Export Paths
$SingleEPath = Join-Path $PSScriptRoot "Single_TemporaryAccessPass_$(Get-Date -Format "yyyyMMdd_HHmmss").csv"
$MultipleEPath = Join-Path $PSScriptRoot "Multi_TemporaryAccessPass_$(Get-Date -Format "yyyyMMdd_HHmmss").csv"

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
Write-Log -Message "[SCRIPT] Start of Manage_TemporaryAccessPass Script." -Level "SOS"

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

# Main Script Execution Flow

# Validate x86 Architecture
Check-OSArchitecture > $null

# Import Microsoft Graph Modules
Initialize-MicrosoftGraphEnvironment

Connect-MSGraph
Check-License

SLEEP 2
CLS

# ------------------------------------------------------------------------------------------------------------------------

# Function to Request Consent
function Request-Consent {
    param([string]$message)
    $confirmation = Read-Host "$message (Yes/No)"
    Write-Log -Message "You have Provided Consent to Generate Temporary Access Passes" -Level "INFO"
    return $confirmation -match '^(yes|y)$'
}

# Function to Create Temporary Access Pass for a Single User
function Create-TAPSingleUser {
    param ([string]$upn)

    if (-not (Request-Consent "Do you provide consent to generate a Temporary Access Pass for a single user?")) {
        Write-Log -Message "Consent has not been provided. Exiting..." -Level "WARNING"
        return
    }

    # UPN Input
    if (-not $upn) { $upn = Read-Host "Enter the UPN for the single user" }

    # User Lookup and TAP Generation
    $user = Get-MgUser -Filter "userPrincipalName eq '$upn'"
    if ($user) {
        $params = @{
            "startDateTime" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
            "lifetimeInMinutes" = 60
            "isUsableOnce" = $true
        }
        $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -BodyParameter $params

        # Log success message without TAP details
        Write-Log -Message "[USER] Temporary Access Pass successfully created for ${upn}" -Level "IMPORTANT"
        
        # Export TAP Details to file only, without displaying TAP on console
        [pscustomobject]@{
            UserPrincipalName = $upn
            TemporaryAccessPass = $tap.TemporaryAccessPass
            StartDateTime = $params.startDateTime
            LifetimeInMinutes = $params.lifetimeInMinutes
            IsUsableOnce = $params.isUsableOnce
        } | Export-Csv -Path $SingleEPath -Append -NoTypeInformation

        # Display completion message and pause briefly
        Write-Host "Temporary Access Pass Generation is Complete. Please Refer to CSV" -ForegroundColor Cyan
    } else {
        Write-Log -Message "[USER] User not found for UPN: $upn" -Level "ERROR"
    }
}

# Function to Create Temporary Access Passes for Multiple Users
function Create-TAPMultipleUsers {
    if (-not (Request-Consent "Do you provide consent to generate Temporary Access Passes for multiple users?")) {
        Write-Log -Message "Consent has not been provided. Exiting..." -Level "WARNING"
        return
    }

    # Check for CSV file existence and content
    if (-not $csvPath -or -not (Test-Path -Path $csvPath) -or (Get-Content -Path $csvPath | Measure-Object -Line).Lines -eq 0) {
        Write-Log -Message "CSV file not found or is empty: $csvPath" -Level "WARNING"
        
        # Prompt user for new file path if initial file is missing or empty
        $csvPath = Read-Host "No valid CSV found or the file is empty. Please provide the path to a valid CSV file"
        if (-not (Test-Path -Path $csvPath) -or (Get-Content -Path $csvPath | Measure-Object -Line).Lines -eq 0) {
            Write-Log -Message "Provided CSV file is invalid or empty. Exiting..." -Level "ERROR"
            return
        }
    }

    # Import and Process CSV Data
    try {
        $csvData = Import-Csv -Path $csvPath
        if ($csvData.Count -eq 0) {
            Write-Log -Message "CSV file is empty: $csvPath. Exiting..." -Level "WARNING"
            return
        }
    } catch {
        Write-Log -Message "Failed to import CSV file: $_" -Level "ERROR"
        return
    }

    # Generate TAP for Each User
    foreach ($entry in $csvData) {
        $upn = $entry.UPN
        if (-not $upn) {
            Write-Log -Message "UPN is missing in entry. Skipping..." -Level "WARNING"
            continue
        }
        try {
            $user = Get-MgUser -Filter "userPrincipalName eq '$upn'"
            if ($user) {
                $params = @{
                    "startDateTime" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                    "lifetimeInMinutes" = 60
                    "isUsableOnce" = $true
                }
                $tap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.Id -BodyParameter $params
                
                # Log creation message without TAP details
                Write-Log -Message "[USER] Temporary Access Pass successfully created for ${upn}" -Level "IMPORTANT"
               
                # Export TAP Details without displaying them on screen
                [pscustomobject]@{
                    UserPrincipalName = $upn
                    TemporaryAccessPass = $tap.TemporaryAccessPass
                    StartDateTime = $params.startDateTime
                    LifetimeInMinutes = $params.lifetimeInMinutes
                    IsUsableOnce = $params.isUsableOnce
                } | Export-Csv -Path $MultipleEPath -Append -NoTypeInformation
            } else {
                Write-Log -Message "[USER] User not found for UPN: $upn" -Level "ERROR"
            }
        } catch {
            Write-Log -Message "Error processing UPN ${upn}: $_" -Level "ERROR"
        }
    }
    Write-Log -Message "Multiple TAP Generation Complete. Please Refer to CSV" -Level "SOS"
}


# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
do {
    Clear-Host
    Write-Host "------------------------------------------------------------------"
    Write-Host "             -" -ForegroundColor Cyan
    Write-Host "Phase 2: Tenso - Create a Temporary Access Pass for Users"          -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------------"
    Write-Host ""
    Write-Host "[1] Temporary Access Pass for a Single User"
    Write-Host "[2] Temporary Access Passes for Multiple Users from CSV"
    Write-Host "[3] Exit"
    Write-Host ""
    Write-Host "------------------------------------------------------------------"
    $choice = Read-Host "Enter your choice (1, 2, or 3)"
    
    switch ($choice) {
        1 { Create-TAPSingleUser 
            SLEEP 3
        }
        2 { Create-TAPMultipleUsers
            SLEEP 4
         }
        3 {
            # Exit Microsoft Graph Session
            Disconnect-MSGraph > $Null

            # Mark The End of the Script
            Write-Log -Message "[SCRIPT] End of Manage_TemporaryAccessPass Script." -Level "SOS"
            SLEEP 2
            CLS
            exit
        }
        default { Write-Host "Invalid choice. Please select again." }
    }
} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
