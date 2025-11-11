<#
.SYNOPSIS
    Creates two (2) new Temporary administrative Administrators, adds role assignment of Global Admins to members of a new role assignable group

.DESCRIPTION
    This script connects to Azure and:
    - Creates temporary administrative accounts to support the recovery of a compromised Microsoft Entra ID tenant


.PARAMETER PasswordLength
    Specifies the length of the randomly generated password. Default is 24 characters.

.NOTES
    Author: NightCityShogun
    Name: New_TemporaryUsers
    Version: 3.8
    Date: 2023-06-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Add PasswordLength parameter with default value of 24
param (
    [int]$PasswordLength = 24
)

# Microsoft Graph PowerShell Modules
$modules = @(
  "Microsoft.Graph.Authentication",
  "Microsoft.Graph.Groups",
  "Microsoft.Graph.Identity.DirectoryManagement",
  "Microsoft.Graph.Identity.Governance",
  "Microsoft.Graph.Users"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @("Directory.ReadWrite.All",
"Group.ReadWrite.All",
"RoleManagement.ReadWrite.Directory",
"User.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Password Configuration
$Lowercase = "abcdefghijkmnopqrstuvwxyz"
$Uppercase = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
$Numbers = "0123456789"
$Symbols = '@#$%^&*-_=+[]{}|:,''.?/`~";()<>'
$AllChars = $Lowercase + $Uppercase + $Numbers + $Symbols

# Assignable Roles and Permissions
$RoleTemplateIds = @(
    "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
)

# Groups and User Variables
$GroupNames = @('NCSIRTeam')
$GroupIds = @()
$userList = @()
$newUsersCreated = $false

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")


# Export File Path
$exportPath = Join-Path $PSScriptRoot "New_TemporaryUsers_$(Get-Date -Format "yyyyMMdd_HHmmss").csv"

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
Write-Log -Message "[SCRIPT] Start of New_TemporaryUsers Script." -Level "SOS"

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

# Create a Random Password for Temproary Administrative Users
function Generate-RandomPassword {
    param (
        [int]$PasswordLength = 24
    )
    # Ensure password starts with one character from each set for complexity
    $Password = [System.Text.StringBuilder]::new()
    $Password.Append($Lowercase[(Get-Random -Maximum $Lowercase.Length)]) | Out-Null
    $Password.Append($Uppercase[(Get-Random -Maximum $Uppercase.Length)]) | Out-Null
    $Password.Append($Numbers[(Get-Random -Maximum $Numbers.Length)]) | Out-Null
    $Password.Append($Symbols[(Get-Random -Maximum $Symbols.Length)]) | Out-Null

    # Fill the remaining password length with random characters from all sets
    for ($i = $Password.Length; $i -lt $PasswordLength; $i++) {
        $randomChar = $AllChars[(Get-Random -Maximum $AllChars.Length)]
        $Password.Append($randomChar) | Out-Null
    }

    # Shuffle the password to randomize the order of characters
    $PasswordString = $Password.ToString()
    $CharArray = $PasswordString.ToCharArray()
    $ShuffledArray = $CharArray | Get-Random -Count $CharArray.Length
    $ShuffledPassword = -join $ShuffledArray

    return $ShuffledPassword
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
Write-Host ""
Write-Host "----------------------------------------------------------------------------------"
Write-Host "Phase 1: KAKURI - Create Temporary Global Administrators for the IR Team." -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------------------"
Write-Host ""
try {
    $domains = Get-MgDomain | Select-Object Id, IsDefault | Sort-Object Id
    if (-not $domains) {
        throw "No domains found. Please check your Microsoft Entra ID Tenant."
    }

    for ($i = 0; $i -lt $domains.Count; $i++) {
        Write-Host "[$($i + 1)] $($domains[$i].Id)"
    }
    Write-Host "[E] Exit"
    Write-Host "-"
    Write-Host "----------------------------------------------------------------------------------"
    $selectedDomainIndex = Read-Host -Prompt "Enter the number of the domain or E to exit (will use default domain if no entry)"

    if ($selectedDomainIndex -ieq 'E') {
    Write-Log -Message "User chose to exit the script." -Level "IMPORTANT"
    Exit
    }

    $selectedDomain = $null
    if ([string]::IsNullOrEmpty($selectedDomainIndex) -or $selectedDomainIndex -lt 1 -or $selectedDomainIndex -gt $domains.Count) {
        $selectedDomain = $domains | Where-Object { $_.IsDefault -eq $true }
        Write-Log -Message "Using default domain: $($selectedDomain.Id)" -Level "IMPORTANT"
    } else {
        $selectedDomain = $domains[$selectedDomainIndex - 1]
        Write-Log -Message "Using selected domain: $($selectedDomain.Id)" -Level "IMPORTANT"
    }
} catch {
    Write-Log -Message "Error: $_" -Level "ERROR"
    Exit
}

# Set the Domain Suffix
$userPrincipalNameSuffix = "@" + $selectedDomain.Id

# Validate User Consent
try {
    $consent = (Read-Host "Do you consent to temporarily transfer Global Administrator permissions to a Third Party? (Yes/No)").Trim().ToLower()
    
    if ($consent -notmatch '^(yes|y)$') {
        throw "You have not consented to temporarily transfer Global Administrator permissions to a Third Party. Exiting script.."
    }
    
    Write-Log -Message "CAUTION!! You have consented to temporarily transfer Global Administrator permissions to a Third Party" -Level "WARNING"
    
} catch {
    Write-Log -Message "Error: $_" -Level "ERROR"
    exit
}

# Create User Group
foreach ($GroupName in $GroupNames) {
    try {
        $GroupDisplayName = "$GroupName"
        $GroupMailNickname = $GroupName.ToLower()
        $existingGroup = Get-MgGroup -Filter "displayName eq '$GroupDisplayName'" -ErrorAction SilentlyContinue

        if ($existingGroup) {
            Write-Log -Message "[GROUP] $GroupDisplayName already exists. Skipping creation." -Level "INFO"
            $GroupIds += $existingGroup.Id
        } else {
            $GroupParams = @{
                "displayName" = $GroupDisplayName
                "mailEnabled" = $false
                "mailNickname" = $GroupMailNickname
                "securityEnabled" = $true
                "isAssignableToRole" = $true
            }

            $NewGroup = New-MgGroup -BodyParameter $GroupParams
            $GroupIds += $NewGroup.Id
            Write-Log -Message "[GROUP] $GroupDisplayName created with ID: $($NewGroup.Id)" -Level "INFO"

            # Randomly select a role to assign to this group
            $SelectedRoleId = $RoleTemplateIds | Get-Random
            $RoleDefinition = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $SelectedRoleId
            if ($RoleDefinition) {
                try {
                    $RoleAssignmentParams = @{
                        "PrincipalId" = $NewGroup.Id
                        "RoleDefinitionId" = $SelectedRoleId
                        "DirectoryScopeId" = "/"
                    }
                    $RoleAssignment = New-MgRoleManagementDirectoryRoleAssignment @RoleAssignmentParams
                    Write-Log -Message "[ROLE] $($RoleDefinition.DisplayName) assigned to $GroupDisplayName" -Level "INFO"
                } catch {
                    Write-Log -Message "[ROLE] Failed to assign $($RoleDefinition.DisplayName) to $GroupDisplayName. Error: $_" -Level "ERROR"
                }
            } else {
                Write-Log -Message "Role Definition not found for ID: $SelectedRoleId" -Level "WARNING"
            }
        }
    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
    }
}

# Create Users
$Users = @(
    [PSCustomObject]@{ FirstName = 'NCS'; LastName = 'ADM01' },
    [PSCustomObject]@{ FirstName = 'NCS'; LastName = 'ADM02' }
)

foreach ($User in $Users) {
    try {
        $FirstName = $User.FirstName
        $LastName = $User.LastName
        $Password = Generate-RandomPassword
        $UPN = "$FirstName.$LastName$userPrincipalNameSuffix".ToLower()

        # Check if user already exists
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

        if ($existingUser) {
            Write-Log -Message "[USER] $UPN already exists. Skipping creation." -Level "INFO"
        } else {
            $UserParams = @{
                "accountEnabled" = $true
                "displayName" = "$FirstName $LastName"
                "mailNickname" = "$FirstName$LastName".ToLower()
                "userPrincipalName" = $UPN
                "passwordProfile" = @{
                    "forceChangePasswordNextSignIn" = $true
                    "password" = $Password
                }
                "givenName" = $FirstName
                "surname" = $LastName
            }
            $NewUser = New-MgUser -BodyParameter $UserParams
            $SelectedGroupId = $GroupIds | Get-Random
            New-MgGroupMember -GroupId $SelectedGroupId -DirectoryObjectId $NewUser.Id

            # Log user creation and addition to group
            Write-Log -Message "[USER] $UPN created and added to group ID $SelectedGroupId" -Level "INFO"

            # Add user data to list for CSV export
            $userList += [PSCustomObject]@{ UPN = $UPN; Password = $Password }
            $newUsersCreated = $true
        }
    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
    }
}

# Export Temporary Users to CSV
if ($newUsersCreated) {
    try {
        $userList | Export-Csv -Path $exportPath -NoTypeInformation
        Write-Log -Message "Exported user list to CSV at $exportPath" -Level "IMPORTANT"
    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
    }
} else {
    Write-Log -Message "No Users Created. Skipping CSV Export." -Level "INFO"
}

# ------------------------------------------------------------------------------------------------------------------------

# Exit Microsoft Graph Session
Disconnect-MSGraph > $Null

# Mark The End of the Script
Write-Log -Message "[SCRIPT] End of New_TemporaryUsers Script." -Level "SOS"
SLEEP 2
CLS

# (C) NightCityShogun 2024
