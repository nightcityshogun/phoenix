<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Graph and provides options to manage Microsoft Entra ID Security Default Enforcement Policy.

.DESCRIPTION
    This script connects to Azure and:
    - Ensure that Security Default settings are disabled ahead of making changes to Microsoft Entra Conditional Access Policies

.PARAMETER NULL
    There are no supported parameters

.NOTES
    Author: NightCityShogun
    Name: Manage_SecurityDefaults
    Version: 3.8
    Date: 2023-06-15
#>

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @("Directory.ReadWrite.All",
"Directory.ReadWrite.All",
"Policy.Read.All",
"Policy.ReadWrite.SecurityDefaults")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

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
Write-Log -Message "[SCRIPT] Start of Manage_SecurityDefaults Script." -Level "SOS"

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

# Function to Check Current Policy Status
function Check-SecurityDefaultsStatus {
    try {
        $currentPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        if ($currentPolicy -and $currentPolicy.IsEnabled -eq $true) {
            Write-Log -Message "Identity Security Default Enforcement Policy is currently enabled." -Level "IMPORTANT"
        } elseif ($currentPolicy -and $currentPolicy.IsEnabled -eq $false) {
            Write-Log -Message "Identity Security Default Enforcement Policy is currently disabled." -Level "IMPORTANT"
        } else {
            Write-Log -Message "Identity Security Default Enforcement Policy not found." -Level "INFO"
        }
    } catch {
        Write-Log -Message "Failed to check Identity Security Default Enforcement Policy. Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to Enable Security Defaults
function Enable-SecurityDefaults {
    try {
        $existingPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq 'Enabled' }
        $currentPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy

        if ($existingPolicies.Count -gt 0) {
            Write-Log -Message "You have active Conditional Access policies. Please disable them before enabling Security Defaults." -Level "ERROR"
        } elseif ($currentPolicy -and $currentPolicy.IsEnabled -eq $true) {
            Write-Log -Message "Identity Security Default Enforcement Policy is already enabled." -Level "IMPORTANT"
        } else {
            $params = @{
                isEnabled = $true
            }
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
            Write-Log -Message "Identity Security Default Enforcement Policy is now enabled." -Level "IMPORTANT"
        }
    } catch {
        Write-Log -Message "Failed to enable Identity Security Default Enforcement Policy. Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to Disable Security Defaults
function Disable-SecurityDefaults {
    try {
        $currentPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        if ($currentPolicy -and $currentPolicy.IsEnabled -eq $false) {
            Write-Log -Message "Identity Security Default Enforcement Policy is already disabled." -Level "IMPORTANT"
        } else {
            $params = @{
                isEnabled = $false
            }
            Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params
            Write-Log -Message "Identity Security Default Enforcement Policy is now disabled." -Level "IMPORTANT"
        }
    } catch {
        Write-Log -Message "Failed to disable Identity Security Default Enforcement Policy. Error: $($_.Exception.Message)" -Level "ERROR"
    }
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
function Show-Menu {
    do {
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------"
        Write-Host "Phase 1: KAKURI - MANAGE SECURITY DEFAULT POLICY ENFORCEMENTS."                     -ForegroundColor Cyan
        Write-Host "----------------------------------------------------------------------------------"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "[1] Check Current Status"
        Write-Host "[2] Enable Security Default Policy Enforcement"
        Write-Host "[3] Disable Security Defaults Policy Enforcement"
        Write-Host "[4] Exit"
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------"
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            1 { 
                Check-SecurityDefaultsStatus
                Start-Sleep 2
                CLS
            }
            2 { 
                Enable-SecurityDefaults
                Start-Sleep 2
                CLS 
            }
            3 { 
                Disable-SecurityDefaults
                Start-Sleep 2
                CLS 
            }
            4 {
                Write-Host "Exiting the script..." -ForegroundColor Yellow
                # Exit Microsoft Graph Session
                Disconnect-MSGraph > $Null

                # Mark The End of the Script
                Write-Log -Message "Script finished" -Level "SOS"
                SLEEP 2
                CLS
                Exit
            }
            default { 
                Write-Host "Invalid choice. Please select again." 
            }
        }
    } while ($true)
}

# Display the Menu
Show-Menu

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
