<#
.SYNOPSIS
    Manages Microsoft Entra ID Sensitive Roles to ensure tenant security following systemic identity compromises.

.DESCRIPTION
    This script connects to Microsoft Entra ID (Azure AD), obtains operator consent, and provides functionality to:
    - Reset passwords and disable accounts for exposed or compromised users.
    - Remove all configured authentication methods for compromised accounts.
    - Refresh user tokens to prevent unauthorized access with invalidated credentials.
    - Remove Microsoft Entra ID Eligible Role Assignments for sensitive roles.
    - Remove Microsoft Entra ID Permanent Role Assignments for sensitive roles.
    - Log all actions taken for auditing and accountability.

    The script supports the `-WhatIf` switch to simulate actions and preview their impact without making actual changes, ensuring safe execution in sensitive environments.

.PARAMETER PasswordLength
    Specifies the length of randomly generated passwords when resetting user passwords. The default is 24 characters.

.PARAMETER WhatIf
    Simulates the execution of the script, logging the actions that would be taken without making actual changes.

.NOTES
    Author: NightCityShogun
    Name: Manage_EntraDirectoryRoleAssignments
    Version: 3.8
    Date: 2023-12-15
#>

# ------------------------------------------------------------------------------------------------------------------------

param (
    [int]$PasswordLength = 24,
    [switch]$WhatIf  
)

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.DirectoryObjects",
    "Microsoft.Graph.Identity.Governance",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Users.Actions"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @(
    "Directory.AccessAsUser.All",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "RoleAssignmentSchedule.Remove.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.Remove.Directory",
    "RoleManagement.Read.All",
    "RoleManagement.Read.Directory",
    "RoleManagement.ReadWrite.Directory",
    "User.Read.All",
    "User.ReadBasic.All",
    "UserAuthenticationMethod.Read.All",
    "UserAuthenticationMethod.ReadWrite",
    "UserAuthenticationMethod.ReadWrite.All"
)

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Password Configuration
$Lowercase = "abcdefghijkmnopqrstuvwxyz"
$Uppercase = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
$Numbers = "0123456789"
$Symbols = '@#$%^&*-_=+[]{}|:,''.?/`~";()<>'
$AllChars = $Lowercase + $Uppercase + $Numbers + $Symbols

# Exclude Temporary Administrative Accounts
$excludePattern = "^ncs\.adm0"  

# Define Empty Variables
$csvFilePath = ""
$loggedOnUserUPN = ""
$loUPNID = ""
$exGroupID = ""

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Search Pattern
$csvFilePattern = "Backup_EntraDirectoryRoleAssignments_*.csv"

# Import File Path
$csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter $csvFilePattern | Sort-Object LastWriteTime -Descending

# ------------------------------------------------------------------------------------------------------------------------

# Ensure the NCS Log Directory Exists in $env:LOCALAPPDATA\Temp
if (!(Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# Function to Write Log File Entries
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("SOS", "ERROR", "INFO", "WARNING", "IMPORTANT", "DEBUG")]
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
            "DEBUG"      = [System.ConsoleColor]::Blue
        }[$Level]

        # Write the log entry to the console with the specified color
        Write-Host -ForegroundColor $logColor $logEntry
    }
}

# Mark the Start of the Script
Write-Log -Message "[SCRIPT] Start of Manage_EntraDirectoryRoleAssignments Script." -Level "SOS"

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

# Create a Random Password for Exposed Administrative Users
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

# Function to Initialize User Data and Exclusions
function InitializeUserData {
    param (
        [string]$excludePattern = "^ncs\.adm0"  # Define exclusion pattern for temporary administrative accounts
    )

    # Define CSV file search pattern and retrieve the latest file
    $csvFilePattern = "*.csv"  # Update this as needed
    $csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter $csvFilePattern | Sort-Object LastWriteTime -Descending
    $csvFilePath = if ($csvFiles.Count -gt 0) { $csvFiles[0].FullName } else {
        if ((Read-Host "No CSV found. Enter path manually? (Y/N)") -match '^(Y|y)$') {
            Read-Host "Enter the path to the CSV file containing user data"
        } else {
            Write-Log -Message "No CSV file found. Exiting the script." -Level "INFO"
            exit
        }
    }

    # Import CSV data
    $csvUsers = Import-Csv -Path $csvFilePath | Sort-Object -Property Principal -Descending

    # Retrieve the logged-on user's UPN and ID
    $loggedOnUserUPN = (Get-MgContext).Account
    $loUPNID = (Get-MgUser -Filter "UserPrincipalName eq '$loggedOnUserUPN'").Id

    # Retrieve the group ID for NCSIRTeam
    $exGroupID = (Get-MgGroup -Filter "displayName eq 'NCSIRTeam'").Id
    if (-not $exGroupID) {
        Write-Log -Message "Group 'NCSIRTeam' not found. Exiting the script." -Level "ERROR"
        exit
    }

    # Retrieve all users that match the exclusion pattern and log their UPNs
    $excludedUsers = Get-MgUser -All | Where-Object { $_.UserPrincipalName -match $excludePattern } | 
                     Select-Object UserPrincipalName, Id

    # Filter csvUsers to exclude any that match the exclusion pattern
    $excludedUserIDs = $excludedUsers | ForEach-Object { $_.Id }
    $filteredCsvUsers = $csvUsers | Where-Object { $_.ID -notin $excludedUserIDs }

    # Return user data, exclusions, and excluded user UPNs and IDs
    return @{
        CsvUsers = $filteredCsvUsers
        LoUPNID = $loUPNID
        LoggedOnUserUPN = $loggedOnUserUPN
        ExGroupID = $exGroupID
        ExcludedUsers = $excludedUsers  # Includes both UPNs and IDs
    }
}

# Initialize Data
$data = InitializeUserData
$csvUsers = $data.CsvUsers
$loUPNID = $data.LoUPNID
$loggedOnUserUPN = $data.LoggedOnUserUPN
$exGroupID = $data.ExGroupID
$excludedUsers = $data.ExcludedUsers

function Request-Consent {
    # Display consent message
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "          -" -ForegroundColor Cyan
    Write-Host "Phase 2: Joka - Restore Positive Administrative Control Management Groups."          -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------------------"

    try {
        # Prompt for consent
        $consent = (Read-Host "Do you wish to start cleaning Entra ID Privileged Roles? (Yes/No)").Trim().ToLower()

        # Check for consent confirmation
        if ($consent -notmatch '^(yes|y)$') {
            throw "Exiting script."
        }

        # Log confirmation message
        Write-Log -Message "CAUTION! You have provided consent to start cleaning Entra ID Privileged Roles." -Level "WARNING"
        SLEEP 2
        CLS

    } catch {
        Write-Log -Message "Error: $_" -Level "ERROR"
        exit
    }
}

# ------------------------------------------------------------------------------------------------------------------------

# Function to Reset and Disable Accounts
function Reset-PasswordAndDisableAccount {
    param (
        [array]$csvUsers,
        [array]$excludedUsers,
        [string]$loUPNID,
        [string]$loggedOnUserUPN,
        [switch]$WhatIf  # Add WhatIf parameter
    )

    # Log Start of Function
    Write-Log -Message "Starting Reset and Disable Accounts Process" -Level "SOS"

    Request-Consent

    # Log Exclusions
    Write-Log -Message "[USER] $loggedOnUserUPN will be Excluded" -Level "IMPORTANT"
    foreach ($excludedUser in $excludedUsers) {
        Write-Log -Message "[USER] $($excludedUser.UserPrincipalName) will be Excluded" -Level "IMPORTANT"
    }

    # Prepare List of Excluded IDs
    $excludedUserIDs = $excludedUsers | ForEach-Object { $_.Id }

    # Filter Objects
    $filteredCsvUsers = $csvUsers | Where-Object {
        $_.PrincipalType -eq "USER" -and
        $_.ID -ne $loUPNID -and
        $_.ID -notin $excludedUserIDs
    } | Sort-Object -Property Principal -Unique

    # Process Filtered List
    foreach ($user in $filteredCsvUsers) {
        $UserId = $user.Id
        $UserPrincipalName = $user.Principal
        $actionMessage = "[USER] Reset Password and Disable Account for $UserPrincipalName."

        if ($WhatIf) {
            # Simulate Action
            Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
        } else {
            # Proceed with Password Reset and Account Disabling
            try {
                $user = Get-MgUser -UserId $UserId -ErrorAction Stop
                $userPrincipalName = $user.UserPrincipalName
                $newPassword = Generate-RandomPassword
                $params = @{
                    PasswordProfile = @{
                        ForceChangePasswordNextSignIn = $true
                        Password = $newPassword
                    }
                    AccountEnabled = $false
                }
                $null = Update-MgUser -UserId $UserId -BodyParameter $params
                Write-Log -Message "[USER] Password Reset and Account Disabled for $userPrincipalName." -Level "INFO"
            } catch {
                Write-Log -Message "[ERROR] Error resetting password and disabling account for $userPrincipalName. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    Write-Log -Message "Password Reset and Account Disabled Process Complete." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Remove Registered Authentication Methods
function Remove-RegisteredAuthenticationMethods {
    param (
        [array]$csvUsers,
        [string]$loUPNID,
        [array]$excludedUsers,
        [string]$loggedOnUserUPN,
        [switch]$WhatIf
    )

    # Log Start of Function
    Write-Log -Message "Starting Remove Registered Authentication Methods Process" -Level "SOS"

    Request-Consent

    # Log Exclusions
    Write-Log -Message "[USER] $loggedOnUserUPN will be Excluded" -Level "IMPORTANT"
    foreach ($excludedUser in $excludedUsers) {
        Write-Log -Message "[USER] $($excludedUser.UserPrincipalName) will be Excluded." -Level "IMPORTANT"
    }

    # Prepare List of Excluded IDs
    $excludedUserIDs = $excludedUsers | ForEach-Object { $_.Id }

    # Filter Objects
    $filteredCsvUsers = $csvUsers | Where-Object {
        $_.PrincipalType -eq "USER" -and
        $_.ID -ne $loUPNID -and
        $_.ID -notin $excludedUserIDs
    } | Sort-Object -Property Principal -Unique

    # Process Filtered List
    foreach ($user in $filteredCsvUsers) {
        $UserId = $user.Id
        $UserPrincipalName = $user.Principal
        $actionMessage = "[USER] Remove Authentication Methods for $UserPrincipalName."

        if ($WhatIf) {
            # Simulate Action
            Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
        } else {
            try {
                $userAuthMethods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction SilentlyContinue
                if ($null -eq $userAuthMethods) {
                    Write-Log -Message "No Authentication Methods found for $UserPrincipalName ($UserId), or the user does not exist." -Level "WARNING"
                    continue
                }

                foreach ($userAuthMethod in $userAuthMethods) {
                    $odataType = $userAuthMethod.AdditionalProperties['@odata.type']
                    switch -Wildcard ($odataType) {
                        '#microsoft.graph.emailAuthenticationMethod' {
                            Remove-MgUserAuthenticationEmailMethod -UserId $UserId -EmailAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed emailAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.fido2AuthenticationMethod' {
                            Remove-MgUserAuthenticationFido2Method -UserId $UserId -Fido2AuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed fido2AuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                            Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -MicrosoftAuthenticatorAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed microsoftAuthenticatorAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.phoneAuthenticationMethod' {
                            Remove-MgUserAuthenticationPhoneMethod -UserId $UserId -PhoneAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed phoneAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.softwareOathAuthenticationMethod' {
                            Remove-MgUserAuthenticationSoftwareOathMethod -UserId $UserId -SoftwareOathAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed softwareOathAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                            Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -TemporaryAccessPassAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed temporaryAccessPassAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                            Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $UserId -WindowsHelloForBusinessAuthenticationMethodId $userAuthMethod.Id -ErrorAction SilentlyContinue > $null
                            Write-Log -Message "[USER] Removed windowsHelloForBusinessAuthenticationMethod for $UserPrincipalName" -Level "INFO"
                        }
                        default {
                            Write-Log -Message "[USER] Unsupported authentication method type for $UserPrincipalName ($odataType)" -Level "WARNING"
                        }
                    }
                }
            } catch {
                Write-Log -Message "[ERROR] Error removing authentication methods for $UserPrincipalName. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    Write-Log -Message "Remove Registered Authentication Methods Process Complete." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Refresh Sign-In Tokens
function Refresh-UserSigninTokens {
    param (
        [array]$csvUsers,
        [array]$excludedUsers,
        [string]$loUPNID,
        [string]$loggedOnUserUPN,
        [switch]$WhatIf
    )

    # Log Start of Function
    Write-Log -Message "Starting Revoke Sign-in Tokens Process" -Level "SOS"

    Request-Consent

    # Log Exclusions
    Write-Log -Message "[USER] $loggedOnUserUPN will be Excluded." -Level "IMPORTANT"
    foreach ($excludedUser in $excludedUsers) {
        Write-Log -Message "[USER] $($excludedUser.UserPrincipalName) will be Excluded" -Level "IMPORTANT"
    }

    # Prepare List of Excluded IDs
    $excludedUserIDs = $excludedUsers | ForEach-Object { $_.Id }

    # Filter Objects
    $filteredCsvUsers = $csvUsers | Where-Object {
        $_.PrincipalType -eq "USER" -and
        $_.ID -ne $loUPNID -and
        $_.ID -notin $excludedUserIDs
    } | Sort-Object -Property Principal -Unique

    # Process Filtered List
    foreach ($user in $filteredCsvUsers) {
        $UserId = $user.Id
        $UserPrincipalName = $user.Principal
        $actionMessage = "[USER] Revoke Sign-in Tokens for $UserPrincipalName."

        if ($WhatIf) {
            # Simulate Action
            Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
        } else {
            # Proceed with Token Refresh
            try {
                $user = Get-MgUser -UserId $UserId -ErrorAction Stop
                $userPrincipalName = $user.UserPrincipalName
                $null = Revoke-MgUserSignInSession -UserId $UserId
                Write-Log -Message "[USER] Sign-in Tokens Revoked for $userPrincipalName." -Level "INFO"
            } catch {
                Write-Log -Message "[ERROR] Error Revoking Sign-in Tokens for $UserPrincipalName. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    Write-Log -Message "Revoke Sign-in Tokens Process Complete." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Remove Eligible Role Assignments
function Remove-EligibleRoleAssignments {
    param (
        [switch]$WhatIf
    )

    Write-Log -Message "Starting Remove All Eligible Role Assignments Process" -Level "SOS"

    Request-Consent

    try {
        # Resolve excluded principals
        Write-Log -Message "[INFO] Resolving excluded principals and their assignments..." -Level "INFO"

        # Logged-on user
        $loggedOnUserUPN = (Get-MgContext).Account
        $loggedOnUserId = (Get-MgUser -Filter "UserPrincipalName eq '$loggedOnUserUPN'" -ErrorAction Stop).Id

        # Exclusion group
        $exGroupName = "NCSIRTeam"
        $exGroup = Get-MgGroup -Filter "DisplayName eq '$exGroupName'" -ErrorAction SilentlyContinue
        $excludedGroupMembers = if ($exGroup) {
            Get-MgGroupMember -GroupId $exGroup.Id -All | Select-Object -ExpandProperty Id
        } else {
            Write-Log -Message "[WARNING] Exclusion group '$exGroupName' not found. Skipping group exclusions." -Level "WARNING"
            @()
        }

        # Excluded users based on pattern
        $excludePattern = "^ncs\.adm0"
        $excludedUsers = Get-MgUser -Filter "startswith(UserPrincipalName, 'ncs.adm0')" -ErrorAction SilentlyContinue
        $excludedUserIds = if ($excludedUsers) {
            $excludedUsers | ForEach-Object { $_.Id }
        } else {
            @()
        }

        # Combine exclusions into a single list
        $excludedPrincipalIds = @($loggedOnUserId, $exGroup.Id) + $excludedUserIds + $excludedGroupMembers
        $excludedPrincipalIds = $excludedPrincipalIds | Where-Object { $_ -ne $null } | Sort-Object -Unique

        Write-Log -Message "[INFO] Excluded Principal IDs resolved: $($excludedPrincipalIds.Count) IDs resolved." -Level "DEBUG"

        # Fetch Role Templates
        Write-Log -Message "[INFO] Fetching all role templates..." -Level "INFO"
        $allRoleTemplates = Get-MgDirectoryRoleTemplate -All | Sort-Object -Property DisplayName

        if (-not $allRoleTemplates) {
            Write-Log -Message "[INFO] No role templates found." -Level "INFO"
            return
        }

        Write-Log -Message "[INFO] Retrieved $($allRoleTemplates.Count) role templates." -Level "INFO"

        # Remove Active Role Assignments
        Write-Log -Message "[INFO] Retrieving activated role assignments..." -Level "INFO"
        $activatedAssignments = @(
            Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter "AssignmentType eq 'Activated'" |
            Select-Object -Property Id, RoleDefinitionId, PrincipalId -ErrorAction SilentlyContinue
        )

        if ($activatedAssignments.Count -gt 0) {
            Write-Log -Message "[INFO] Found $($activatedAssignments.Count) activate assignments." -Level "IMPORTANT"

            foreach ($roleTemplate in $allRoleTemplates) {
                $roleDisplayName = $roleTemplate.DisplayName
                $roleDefinitionId = $roleTemplate.Id

                # Filter activated assignments for the current role
                $assignmentsForRole = $activatedAssignments | Where-Object {
                    $_.RoleDefinitionId -eq $roleDefinitionId -and $_.PrincipalId -notin $excludedPrincipalIds
                }

                if (-not $assignmentsForRole) {
                    Write-Log -Message "[INFO] No members to process for Role: $roleDisplayName." -Level "INFO"
                    continue
                }

                Write-Log -Message "[INFO] Role: $roleDisplayName ($($assignmentsForRole.Count) members)" -Level "INFO"

                foreach ($assignment in $assignmentsForRole) {
                    $principalId = $assignment.PrincipalId

                    # Attempt to resolve Principal Details
                    $principalObject = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction SilentlyContinue
                    $principalName = "Unknown Principal"
                    $principalTypeName = "UNKNOWN"

                    if ($null -ne $principalObject) {
                        $principalType = $principalObject.AdditionalProperties['@odata.type']
                        $principalName = if ($principalType -eq '#microsoft.graph.user') {
                            $principalObject.AdditionalProperties['userPrincipalName']
                        } else {
                            $principalObject.AdditionalProperties['displayName']
                        }

                        $principalTypeName = switch ($principalType) {
                            '#microsoft.graph.user' { "USER" }
                            '#microsoft.graph.group' { "GROUP" }
                            '#microsoft.graph.servicePrincipal' { "SERVICE_PRINCIPAL" }
                            default { "UNKNOWN" }
                        }
                    } else {
                        Write-Log -Message "[WARNING] Unknown PrincipalId $principalId. Proceeding with removal." -Level "WARNING"
                    }

                    # Construct action message
                    $actionMessage = "[$principalTypeName] Removing Activate Assignment for $principalName from $roleDisplayName."

                    if ($WhatIf) {
                        Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
                    } else {
                        try {
                            $params = @{
                                Action            = "adminRemove"
                                Justification     = "Policy enforcement: Removing activated assignment."
                                RoleDefinitionId  = $roleDefinitionId
                                DirectoryScopeId  = "/"
                                PrincipalId       = $principalId
                            }
                            $null = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest @params -ErrorAction SilentlyContinue
                            Write-Log -Message $actionMessage -Level "IMPORTANT"
                        } catch {
                            Write-Log -Message "[ERROR] Failed to remove assignment for $principalName. Error: $($_.Exception.Message)" -Level "ERROR"
                        }
                    }
                }
            }
        } else {
            Write-Log -Message "[INFO] No activated role assignments found." -Level "INFO"
        }

        # Remove Inactive Eligible Role Assignments
        Write-Log -Message "[INFO] Retrieving eligible role assignments..." -Level "INFO"
        $eligibleRoleAssignmentsInfo = @(
            Get-MgRoleManagementDirectoryRoleEligibilitySchedule |
            Select-Object -Property Id, RoleDefinitionId, PrincipalId -ErrorAction SilentlyContinue
        )

        if ($eligibleRoleAssignmentsInfo.Count -gt 0) {
            Write-Log -Message "[INFO] Found $($eligibleRoleAssignmentsInfo.Count) eligible assignments." -Level "IMPORTANT"

            foreach ($roleTemplate in $allRoleTemplates) {
                $roleDisplayName = $roleTemplate.DisplayName
                $roleDefinitionId = $roleTemplate.Id

                # Filter eligible assignments for the current role
                $assignmentsForRole = $eligibleRoleAssignmentsInfo | Where-Object {
                    $_.RoleDefinitionId -eq $roleDefinitionId -and $_.PrincipalId -notin $excludedPrincipalIds
                }

                if (-not $assignmentsForRole) {
                    Write-Log -Message "[INFO] No members to process for Role: $roleDisplayName." -Level "INFO"
                    continue
                }

                Write-Log -Message "[INFO] Role: $roleDisplayName ($($assignmentsForRole.Count) members)" -Level "INFO"

                foreach ($assignment in $assignmentsForRole) {
                    $principalId = $assignment.PrincipalId

                    # Attempt to resolve Principal Details
                    $principalObject = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction SilentlyContinue
                    $principalName = "Unknown Principal"
                    $principalTypeName = "UNKNOWN"

                    if ($null -ne $principalObject) {
                        $principalType = $principalObject.AdditionalProperties['@odata.type']
                        $principalName = if ($principalType -eq '#microsoft.graph.user') {
                            $principalObject.AdditionalProperties['userPrincipalName']
                        } else {
                            $principalObject.AdditionalProperties['displayName']
                        }

                        $principalTypeName = switch ($principalType) {
                            '#microsoft.graph.user' { "USER" }
                            '#microsoft.graph.group' { "GROUP" }
                            '#microsoft.graph.servicePrincipal' { "SERVICE_PRINCIPAL" }
                            default { "UNKNOWN" }
                        }
                    } else {
                        Write-Log -Message "[WARNING] Unknown PrincipalId $principalId. Proceeding with removal." -Level "WARNING"
                    }

                    # Construct action message
                    $actionMessage = "[$principalTypeName] Removing Eligible Assignment for $principalName from $roleDisplayName."

                    if ($WhatIf) {
                        Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
                    } else {
                        try {
                            $params = @{
                                Action            = "adminRemove"
                                Justification     = "Removing eligible assignments due to script execution."
                                RoleDefinitionId  = $roleDefinitionId
                                DirectoryScopeId  = "/"
                                PrincipalId       = $principalId
                                ScheduleInfo      = @{
                                    Expiration = @{
                                        Type        = "afterDateTime"
                                        EndDateTime = [System.DateTime]::SpecifyKind(
                                            (Get-Date),  # Current date and time (NOW)
                                            [System.DateTimeKind]::Utc
                                        )
                                    }
                                }
                            }
                            $null = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest @params -ErrorAction SilentlyContinue
                            Write-Log -Message $actionMessage -Level "IMPORTANT"
                        } catch {
                            Write-Log -Message "[ERROR] Failed to remove eligible assignment for $principalName. Error: $($_.Exception.Message)" -Level "ERROR"
                        }
                    }
                }
            }
        } else {
            Write-Log -Message "[INFO] No eligible role assignments found." -Level "INFO"
        }

        Write-Log -Message "Remove All Eligible Role Assignments Process Complete." -Level "SOS"

    } catch {
        Write-Log -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level "ERROR"
    }

    SLEEP 2
    CLS
}

# Function to Revoke Permanent Role Assignment Access
function Remove-PermanentRoleAssignments {
    param (
        [switch]$WhatIf
    )

    Write-Log -Message "Starting Revoke Permanent Role Assignments Process" -Level "SOS"

    Request-Consent

    try {
        # Identify Excluded Principals
        Write-Log -Message "[INFO] Resolving excluded principals and their assignments..." -Level "INFO"

        # Logged-on user
        $loggedOnUserUPN = (Get-MgContext).Account
        $loUPNID = (Get-MgUser -Filter "UserPrincipalName eq '$loggedOnUserUPN'" -ErrorAction Stop).Id

        # Exclusion group
        $exGroupID = (Get-MgGroup -Filter "DisplayName eq 'NCSIRTeam'" -ErrorAction Stop).Id

        # Excluded users based on pattern
        $excludePattern = "^ncs\.adm0"
        $excludedUsers = Get-MgUser -All | Where-Object { $_.UserPrincipalName -match $excludePattern }

        # Expand excluded group members
        $excludedGroupMembers = Get-MgGroupMember -GroupId $exGroupID -All | Select-Object -ExpandProperty Id

        # Combine exclusions into a list
        $excludedPrincipalIds = @($loUPNID, $exGroupID) + ($excludedUsers | ForEach-Object { $_.Id }) + $excludedGroupMembers
        $excludedPrincipalIds = $excludedPrincipalIds | Where-Object { $_ -ne $null } | Sort-Object -Unique

        Write-Log -Message "[INFO] Excluded Principal IDs resolved: $($excludedPrincipalIds.Count) IDs resolved." -Level "DEBUG"

        # Retrieve All Microsoft Entra ID Directory Roles
        Write-Log -Message "[INFO] Retrieving all Microsoft Entra ID roles..." -Level "INFO"

        $allActiveRoles = Get-MgDirectoryRole | Where-Object { $_.Id -ne $null } | Sort-Object -Property DisplayName

        if (-not $allActiveRoles) {
            Write-Log -Message "[INFO] No Microsoft Entra ID roles found." -Level "INFO"
            return
        }

        Write-Log -Message "[INFO] Found $($allActiveRoles.Count) active directory roles." -Level "INFO"

        # Process Roles in Alphabetical Order
        foreach ($role in $allActiveRoles) {
            # Retrieve and filter members, excluding those in $excludedPrincipalIds
            $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id |
                           Where-Object { $_.Id -notin $excludedPrincipalIds }

            if (-not $roleMembers) {
                Write-Log -Message "[INFO] No members to process for Role: $($role.DisplayName)." -Level "INFO"
                continue
            }

            Write-Log -Message "[INFO] Role: $($role.DisplayName) ($($roleMembers.Count) members)" -Level "INFO"

            foreach ($member in $roleMembers) {
                # Attempt to resolve principal details
                $principalObject = Get-MgDirectoryObject -DirectoryObjectId $member.Id -ErrorAction SilentlyContinue
                if ($null -eq $principalObject) {
                    # Default details for unresolvable principal
                    $principalTypeName = "UNKNOWN"
                    $principalName = "Unresolvable PrincipalId: $($member.Id)"
                    Write-Log -Message "[WARNING] Unknown PrincipalId $($member.Id). Proceeding with removal." -Level "WARNING"
                } else {
                    # Extract details for resolvable principal
                    $principalType = $principalObject.AdditionalProperties['@odata.type']
                    $principalName = if ($principalType -eq '#microsoft.graph.user') {
                        $principalObject.AdditionalProperties['userPrincipalName']
                    } else {
                        $principalObject.AdditionalProperties['displayName']
                    }

                    $principalTypeName = switch ($principalType) {
                        '#microsoft.graph.user' { "USER" }
                        '#microsoft.graph.group' { "GROUP" }
                        '#microsoft.graph.servicePrincipal' { "SERVICE_PRINCIPAL" }
                        default { "UNKNOWN" }
                    }
                }

                # Construct action message
                $actionMessage = "[$principalTypeName] Removing Permanent Assignment for $principalName from $($role.DisplayName)."

                if ($WhatIf) {
                    Write-Log -Message "[SIMULATION] $actionMessage" -Level "IMPORTANT"
                } else {
                    try {
                        Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -DirectoryObjectId $member.Id
                        Write-Log -Message $actionMessage -Level "IMPORTANT"
                    } catch {
                        Write-Log -Message "[ERROR] Failed to remove permanent role assignment for $principalName. Error: $($_.Exception.Message)" -Level "ERROR"
                    }
                }
            }
        }

        Write-Log -Message "Revoke Permanent Role Assignments Process Complete." -Level "SOS"

    } catch {
        Write-Log -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level "ERROR"
    }

    SLEEP 2
    CLS
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
do {
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "Phase 2: Joka - Restore Positive Administrative Control Microsoft Entra ID." -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "Select an action:"
    Write-Host "[1] Reset Password and Disable Account"
    Write-Host "[2] Remove Authentication Methods"
    Write-Host "[3] Refresh User Token"
    Write-Host "[4] Remove Eligible Role Assignments"
    Write-Host "[5] Remove Permanent Role Assignments"
    Write-Host "[6] Exit"
    Write-Host ""

    # Dynamically show mode based on -WhatIf
    if ($WhatIf) {
        Write-Host "!![SIMULATION MODE] This Mode will not make any changes to your environment!!." -ForegroundColor Yellow
    } else {
        Write-Host "!![CHANGE MODE] WARNING This Mode will make changes to your environment!!." -ForegroundColor Red
    }

    Write-Host "----------------------------------------------------------------------------------"
    $choice = Read-Host "Enter your choice (1-6)"

    switch ($choice) {
        1 {
            Reset-PasswordAndDisableAccount -csvUsers $csvUsers -excludedUsers $excludedUsers -loUPNID $loUPNID -loggedOnUserUPN $loggedOnUserUPN -WhatIf:$WhatIf
        }

        2 {
            Remove-RegisteredAuthenticationMethods -csvUsers $csvUsers -excludedUsers $excludedUsers -loUPNID $loUPNID -loggedOnUserUPN $loggedOnUserUPN -WhatIf:$WhatIf
        }

        3 {
            Refresh-UserSigninTokens -csvUsers $csvUsers -excludedUsers $excludedUsers -loUPNID $loUPNID -loggedOnUserUPN $loggedOnUserUPN -WhatIf:$WhatIf
          }
        4 {
            Remove-EligibleRoleAssignments -WhatIf:$WhatIf
        }
        5 {
            Remove-PermanentRoleAssignments -WhatIf:$WhatIf
            }
        6 {
            # Exit Microsoft Graph Session
            Disconnect-MSGraph > $Null

            # Mark The End of the Script
            Write-Log -Message "[SCRIPT] End of Manage_EntraDirectoryRoleAssignments Script." -Level "SOS"
            SLEEP 2
            CLS
            exit
        }
    }
} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
