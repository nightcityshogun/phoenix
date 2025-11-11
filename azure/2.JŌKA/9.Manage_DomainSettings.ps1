<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Graph, collates a table of domains in the tenant, allows for changing Authentication Type from Federated to Managed, and includes options for deleting a domain..

.DESCRIPTION
    This script connects to Azure, requests operator consent, and provides options to:
    - Builds a results table of available 'custom' domains.
    - Removal of suspicious Federation configuration from a selected 'custom' domain back to Managed state.
    - Deletes a 'custom' domain from the Microsoft Entra ID tenant.
    - Checks dependancies where the Domain has been used by a Microsoft Entra ID resource.

.PARAMETER NULL
    There are no supported parameters

.NOTES
    Author: NightCityShogun
    Name: Manage_DomainSettings
    Version: 3.8
    Date: 2023-06-15
#>


# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Users"
)

# Define default Microsoft Graph scopes
$Scopes = @("Directory.AccessAsUser.All",
"Domain.ReadWrite.All",
"Directory.Read.All",
"Directory.ReadWrite.All",
"Organization.ReadWrite.All",
"User.Read.All")

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
Write-Log -Message "[SCRIPT] Start of Manage_DomainSettings Script." -Level "SOS"

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

# Update Authentication Type
function UpdateDomainAuthenticationType {
    param ($DomainId, $TargetAuthType)
    $params = @{
        AuthenticationType = $TargetAuthType
    }

    Update-MgDomain -DomainId $DomainId -AdditionalProperties $params
    Write-Log -Message "The domain '$DomainId' has been updated to use '$TargetAuthType' authentication." -Level "INFO"
}

# Update Federated Domain
function DeleteDomain {
    param ($DomainId)

    # Initialize variables for user and group dependencies
    $usersWithDomain = @()
    $groupsWithDomain = @()

    try {
        # Check for any users with the domain suffix
        Write-Log -Message "Checking for users with domain suffix '@$DomainId'..." -Level "INFO"
        $usersWithDomain = Get-MgUser -All | Where-Object { $_.UserPrincipalName -like "*@$DomainId" } | Select-Object -Property UserPrincipalName

        Write-Log -Message "Found $($usersWithDomain.Count) user(s) with domain suffix '@$DomainId'." -Level "INFO"

        # Check for any groups with the domain suffix
        Write-Log -Message "Checking for groups with domain suffix '@$DomainId'..." -Level "INFO"
        $groupsWithDomain = Get-MgGroup -All | Where-Object { $_.Mail -like "*@$DomainId" } | Select-Object -Property DisplayName, Mail

        Write-Log -Message "Found $($groupsWithDomain.Count) group(s) with domain suffix '@$DomainId'." -Level "INFO"
    } catch {
        Write-Log -Message "Error checking dependencies for domain '$DomainId'. Error: $($_.Exception.Message)" -Level "ERROR"
        return
    }

    # If there are dependencies, log details and exit
    if ($usersWithDomain.Count -gt 0 -or $groupsWithDomain.Count -gt 0) {
        Write-Log -Message "Dependencies found for domain '$DomainId':" -Level "WARNING"

        if ($usersWithDomain.Count -gt 0) {
            Write-Log -Message " - $($usersWithDomain.Count) user(s) have the domain suffix '@$DomainId'." -Level "ERROR"
            Write-Log -Message "User Details: $($usersWithDomain | ForEach-Object { $_.UserPrincipalName })" -Level "INFO"
        }

        if ($groupsWithDomain.Count -gt 0) {
            Write-Log -Message " - $($groupsWithDomain.Count) group(s) have the domain suffix '@$DomainId'." -Level "ERROR"
            Write-Log -Message "Group Details: $($groupsWithDomain | ForEach-Object { $_.DisplayName })" -Level "INFO"
        }

        Write-Log -Message "Domain cannot be deleted due to existing dependencies. Exiting script." -Level "SOS"
        return
    }

    # No dependencies found, proceed with deletion
    Write-Log -Message "No dependencies found for the domain '$DomainId'. Proceeding with deletion..." -Level "INFO"
    $confirmation = Read-Host "Are you sure you want to DELETE the domain '$DomainId'? This action cannot be undone. [Yes/No]"

    # Check if the input is a valid "yes" or "no" option
    if ($confirmation -match '^(?i)(yes|y)$') {
        try {
            Remove-MgDomain -DomainId $DomainId -ErrorAction Stop
            Write-Log -Message "The domain '$DomainId' has been successfully deleted." -Level "INFO"
        } catch {
            Write-Log -Message "Failed to delete the domain '$DomainId'. Error: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "Domain deletion cancelled by user." -Level "WARNING"
    }
}

# Function to display domains in columns
function DisplayDomainsInColumns {
    param (
        [array]$Domains
    )

    # Use Format-Table to display the domains. Automatic header generation based on property names.
    $Domains | Format-Table -Property Index, Id, AuthenticationType, IsInitial, IsDefault, IsVerified -AutoSize
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
function Main {
    $domains = Get-MgDomain | Sort-Object Id
    $index = 0

    if (-not $domains) {
        Write-Host "No domains found in your Microsoft Entra ID tenant."
        return
    }
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "          -" -ForegroundColor Cyan
    Write-Host "Phase 2: Joka - Restore Positive Administrative Control Management Groups."          -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host ""

    $formattedDomains = @()
    $domains | ForEach-Object {
        $index++
        $formattedDomain = [PSCustomObject]@{
            Index = "[$index]"
            Id = $_.Id
            AuthenticationType = $_.AuthenticationType
            IsInitial = $_.IsInitial
            IsDefault = $_.IsDefault
            IsVerified = $_.IsVerified
        }
        $formattedDomains += $formattedDomain
    }

    DisplayDomainsInColumns -Domains $formattedDomains

    Write-Host ""
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "Provide the number of the domain you want to manage or enter E to Exit."
    Write-Host ""

    $selection = Read-Host "Selection"
    if ($selection -eq "E") {
        Write-Host "Exiting script."
        return
    }

    $selectedDomainIndex = $selection - 1

    if ($selectedDomainIndex -lt 0 -or $selectedDomainIndex -ge $formattedDomains.Count) {
        Write-Host "Invalid selection. Exiting script."
        return
    }

    $selectedDomain = $formattedDomains[$selectedDomainIndex]

    if (-not $selectedDomain) {
        Write-Host "Invalid selection. Exiting script."
        return
    }

    $action = Read-Host "Enter 'D' to delete, 'M' to change authentication to Managed (for Federated domains only), or 'E' to exit"
    switch ($action) {
        'D' {
            DeleteDomain -DomainId $selectedDomain.Id
        }
        'M' {
            if ($selectedDomain.AuthenticationType -eq "Federated") {
                UpdateDomainAuthenticationType -DomainId $selectedDomain.Id -TargetAuthType "Managed"
            } else {
                Write-Host "Domain is already in the target state: Managed."
            }
        }
        'E' {
            Write-Host "Exiting script."
        }
        default {
            Write-Host "Invalid option selected."
        }
    }
}

# Run the main function
Main

# ------------------------------------------------------------------------------------------------------------------------

# Exit Microsoft Graph Session
Disconnect-MSGraph > $Null

# Mark The End of the Script
Write-Log -Message "[SCRIPT] End of Manage_DomainSettings Script." -Level "SOS"
SLEEP 2
CLS

# (C) NightCityShogun 2024
