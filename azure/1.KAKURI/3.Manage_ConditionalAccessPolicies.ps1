<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Graph, allows creation of new conditional access policies, manages existing conditional access policies based on user choice, and includes logging and error handling.

.DESCRIPTION
    This script connects to Azure and:
    - Creates a new trusted location to define a series of trusted networks for MFA (Re-)Registration
    - Creates new Microsoft Entra ID Conditional Access Policies & provides an option to update historic policies
    - Creates new Microsoft Entra ID Conditional Access Policies only
    - Updates all Microsoft Entra ID Conditional Access Policies policies
    - Update specific Microsoft Entra ID Conditional Access Policies
    - Export all Conditional Access Policies for Analysis

.PARAMETER NULL
    There are no supported parameters

.NOTES
    Author: NightCityShogun
    Name:   
    Version: 3.8
    Date: 2023-06-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Graph PowerShell Modules
$modules = @("Microsoft.Graph.Applications",
    "Microsoft.Graph.Beta.Applications",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Beta.DirectoryObjects",
    "Microsoft.Graph.Beta.Identity.SignIns",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Users"
)

# Microsoft Graph API Scope and Permissions
$Scopes = @("Application.ReadWrite.All",
"Directory.AccessAsUser.All", 
"Directory.ReadWrite.All",
"Directory.Read.All",
"Group.Read.All",
"Group.ReadWrite.All",
"Organization.Read.All",
"Policy.Read.All",
"Policy.ReadWrite.ConditionalAccess",
"RoleEligibilitySchedule.ReadWrite.Directory",
"RoleManagement.ReadWrite.Directory",
"User.ReadBasic.All",
"User.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Default named location settings
$defaultDisplayName = "NightCityShogun"
$maxIpAddressesOrRanges = 5
$ipAddressCidrRegex = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[1-2][0-9]|3[0-2]))$"

# Default Policy Names
$policyNames = @{
    MultiFactorForAllUsers = "[Allow] Multi-Factor for All Users"
    AzurePortalForNonAdmins = "[Block] Azure Portal for Non-Admins"
    LegacyAuthentication = "[Block] Legacy Authentication"
    SignInRisk = "[Block] SignIn Risk"
    UserRisk = "[Block] User Risk"
    AdministratorSessionManagement = "[Allow] Administrator Session Management"
    RegisterSecurityInfo = "[Block] Register Security Info"
}

# Hashtable to Store The Dynamic Lookup Values
$global:ServicePrincipalsCache = @{}
$global:RolesCache = @{}
$global:NamedLocationCache = @{}

$operationMode = $null
$global:newPolicyNames = @()
$global:selectedIndices = @{}

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Export File Path
$ExportCSV = "$PSScriptRoot\Manage_ConditionalAccessPolicies_$((Get-Date -format yyyy-MM-dd-HH-mm)).csv"

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
Write-Log -Message "[SCRIPT] Start of Manage_ConditionalAccessPolicies Script." -Level "SOS"

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

# Function to Chck if Policy Exists by DisplayName
Function PolicyExists {
    param (
        [string]$displayName,
        [array]$existingPolicies
    )

    $existingPolicy = $existingPolicies | Where-Object { $_.DisplayName -eq $displayName }
    return $existingPolicy -ne $null
}

# Function to get Group ID by DisplayName
Function Get-GroupIdByDisplayName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$displayName
    )

    $group = Get-MgGroup -Filter "DisplayName eq '$displayName'" -Select Id
    if ($group -ne $null) {
        return $group.Id
    } else {
        Write-Log -Message "Group not found with DisplayName: $displayName." -Level "ERROR"
        return $null
    }
}

# Function to get LocationName ID by DisplayName
function Get-NamedLocationByDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $matchedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "DisplayName eq '$displayName'" -Select Id

    if ($matchedLocation) {
        return $matchedLocation.Id
    } else {
        Write-Log "Named Location not found with the display name `'$DisplayName`'."  -Level "INFO"
        return $null
    }
}

function Create-TrustedLocations {
    # Display Name for the New Location
    $displayName = $defaultDisplayName

    # Check if Location Exists
    $existingLocationId = Get-NamedLocationByDisplayName -DisplayName $displayName 

    if ($existingLocationId -ne $null) {
        Write-Log -Message "A location with the display name '$displayName' already exists. ID: $existingLocationId" -Level "IMPORTANT"
        return
    }

    # Secure List of IP Ranges
    $userInput = Read-Host "Enter up to five IP addresses or ranges, separated by commas"
    $locations = $userInput.Split(',', [StringSplitOptions]::RemoveEmptyEntries).Trim()

    # Limit to Five Approved IP Addresses or Ranges
    if ($locations.Count -gt $maxIpAddressesOrRanges) {
        Write-Log -Message  "Error: Please provide no more than five IP addresses or ranges." -Level "ERROR"
        return
    }

    # Validate Format
    foreach ($s in $locations) {
        if (-not ($s -match $ipAddressCidrRegex)) {
            Write-Log -Message "Error: The input '$s' is not a valid IPv4 address or range. Please ensure all entries are in the correct format (e.g., 10.10.10.0/24)." -Level "ERROR"
            return
        }
    }

    $params = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName = $displayName
        IsTrusted = $true
        IpRanges = @()
    }

    foreach ($s in $locations) {
        $ipRange = @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            "CidrAddress" = $s
        }
        $params.IpRanges += $ipRange
    }

    # Create New Named Location
    try {
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params > $null
        Write-Log -Message "Successfully created trusted location: '$displayName'" -Level "INFO"
    }
    catch {
        Write-Log -Message "Failed to create trusted location: '$displayName'. Error: $_" -Level "ERROR"
    }
}

# Function to Create New Policies
Function CreateNewPolicies {
    # Create Policies
    $existingPolicies = Get-MgIdentityConditionalAccessPolicy -Property DisplayName, Id, State
    $newPolicyNames = @()

    # Check and create [Allow] Multi-Factor for All Users policy
    $policyName = $policyNames.MultiFactorForAllUsers
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        
        try {
            # Retrieve the group ID by DisplayName
            $excludeGroupId = Get-GroupIdByDisplayName -displayName "NCSIRTeam"
            if ($excludeGroupId -ne $null) {
                # Define and create the policy
                $paramsMFA = @{
                    displayName = $policyName
                    state = "disabled"
                    conditions = @{
                        users = @{
                            includeUsers = @("All")
                            excludeUsers = @()
                            includeGroups = @() 
                            excludeGroups = @()
                        }
                        applications = @{
                            includeApplications = @("All") 
                        }
                    }
                    grantControls = @{
                        operator = "OR"
                        builtInControls = @("mfa")
                    }
                }
                New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsMFA > $null
                $newPolicyNames += $policyName
                Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
            } else {
                Write-Log -Message "Group not found with DisplayName 'NCSIRTeam'. Policy creation aborted." -Level "ERROR"
            }
        } catch {
            Write-Log -Message "Failed to create policy: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Block] Azure Portal for Non-Admins policy
    $policyName = $policyNames.AzurePortalForNonAdmins
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        # Retrieve the group ID by DisplayName
        $excludeGroupId = Get-GroupIdByDisplayName -displayName "NCSIRTeam"
        if ($excludeGroupId -ne $null) {
            # Define and create the policy
            $paramsAPA = @{
                displayName = $policyName
                state = "disabled"
                conditions = @{
                    users = @{
                        includeUsers = @("All")
                        excludeUsers = @()
                        includeGroups = @()
                        excludeGroups = @($excludeGroupId)
                    }
                    applications = @{
                        includeApplications = @("MicrosoftAdminPortals","797f4846-ba00-4fd7-ba43-dac1f8f63013","14d82eec-204b-4c2f-b7e8-296a70dab67e") 
                    }
                }
                grantControls = @{
                    operator = "Or"
                    builtInControls = @("block")
                }
            }
            New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsAPA > $null
            $newPolicyNames += $policyName
            Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
        } else {
            Write-Log -Message "Group not found with DisplayName 'NCSIRTeam'. Policy creation aborted." -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Block] Legacy Authentication for All Users policy
    $policyName = $policyNames.LegacyAuthentication
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        
        try {
            # Define and create the policy
            $paramsLAU = @{
                displayName = $policyName
                state = "disabled"
                conditions = @{
                    users = @{
                        includeUsers = @("All")
                        excludeUsers = @()
                        includeGroups = @() 
                        excludeGroups = @()
                    }
                    clientAppTypes = @("exchangeActiveSync","other")
                    applications = @{
                        includeApplications = @("All") 
                    }
                }
                grantControls = @{
                    operator = "OR"
                    builtInControls = @("block")
                }
            }
            New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsLAU > $null
            $newPolicyNames += $policyName
            Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
        } catch {
            Write-Log -Message "Failed to create policy: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Block] SignIn Risk policy
    $policyName = $policyNames.SignInRisk
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        
        try {
            # Define and create the policy
            $paramsSIR = @{
                displayName = $policyName
                state = "disabled"
                conditions = @{
                    signInRiskLevels = @("high","medium")
                    users = @{
                        includeUsers = @("All")
                        excludeUsers = @()
                        includeGroups = @() 
                        excludeGroups = @()
                    }
                    applications = @{
                        includeApplications = @("All") 
                    }
                }
                grantControls = @{
                    operator = "OR"
                    builtInControls = @("block")
                }
            }
            New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsSIR > $null
            $newPolicyNames += $policyName
            Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
        } catch {
            Write-Log -Message "Failed to create policy: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Block] User Risk policy
    $policyName = $policyNames.UserRisk
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        
        try {
            # Define and create the policy
            $paramsUSR = @{
                displayName = $policyName
                state = "disabled"
                conditions = @{
                    userRiskLevels = @("high","medium")
                    users = @{
                        includeUsers = @("All")
                        excludeUsers = @()
                        includeGroups = @() 
                        excludeGroups = @()
                    }
                    applications = @{
                        includeApplications = @("All") 
                    }
                }
                grantControls = @{
                    operator = "OR"
                    builtInControls = @("block")
                }
            }
            New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsUSR > $null
            $newPolicyNames += $policyName
            Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
        } catch {
            Write-Log -Message "Failed to create policy: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Allow] Administrator Session Management policy
    $policyName = $policyNames.AdministratorSessionManagement
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        # Retrieve the group ID by DisplayName
        $excludeGroupId = Get-GroupIdByDisplayName -displayName "NCSIRTeam"
        if ($excludeGroupId -ne $null) {
            $paramsASM = @{
                displayName = $policyName
                state = "disabled"
                conditions = @{
                    users = @{
                        includeUsers = @()
                        excludeUsers = @()
                        includeGroups = @($excludeGroupId) 
                        excludeGroups = @()
                    }
                    applications = @{
                        includeApplications = @("All") 
                    }
                }
                grantControls = @{
                    operator = "OR"
                    builtInControls = @()
                }
                sessionControls = @{
                    applicationEnforcedRestrictions = $null
                    PersistentBrowser= @{
                        IsEnabled = $true
                        Mode = "never"
                    }
                    signInFrequency = @{
                        isEnabled = $true
                        value = 4
                        type = "hours"
                    }
                }
            }
            New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsASM > $null
            $newPolicyNames += $policyName
            Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
        } else {
            Write-Log -Message "Group not found with DisplayName 'NCSIRTeam'. Policy creation aborted." -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    # Check and create [Block] Register SecurityInfo policy
    $policyName = $policyNames.RegisterSecurityInfo
    if (-not (PolicyExists -displayName $policyName -existingPolicies $existingPolicies)) {
        Write-Log -Message "Creating $policyName policy..." -Level "INFO"
        
        try {
            # Retrieve the group ID by DisplayName
            $excludeGroupId = Get-GroupIdByDisplayName -displayName "NCSIRTeam"
            
            # Retrieve the location ID by DisplayName for exclusion
            $excludeLocationId = Get-NamedLocationByDisplayName -DisplayName $defaultDisplayName

            if ($excludeGroupId -ne $null) {
                # Check if the location to exclude exists
                if ($excludeLocationId -ne $null) {
                    # Define and create the policy with the excluded location
                    $paramsRSI = @{
                        displayName = $policyName
                        state = "disabled"
                        conditions = @{
                            users = @{
                                includeUsers = @("All")
                                excludeUsers = @()
                                includeGroups = @()
                                excludeGroups = @($excludeGroupId)
                            }
                            applications = @{
                                includeApplications = @("All") 
                                excludeApplications = @()     
                            }
                            locations = @{  
                                includeLocations = @("All")
                                excludeLocations = @($excludeLocationId)
                            }
                        }
                        grantControls = @{
                            operator = "OR"
                            builtInControls = @("block") # This control enforces the policy action
                        }
                    }
                    New-MgIdentityConditionalAccessPolicy -BodyParameter $paramsRSI > $null
                    $newPolicyNames += $policyName
                    Write-Log -Message "$policyName policy created." -Level "IMPORTANT"
                } else {
                    Write-Log -Message "Named Location '$defaultDisplayName' not found. Policy creation aborted." -Level "ERROR"
                }
            } else {
                Write-Log -Message "Group not found with DisplayName 'NCSIRTeam'. Policy creation aborted." -Level "ERROR"
            }
        } catch {
            Write-Log -Message "Failed to create policy: $($_.Exception.Message)" -Level "ERROR"
        }
    } else {
        Write-Log -Message "$policyName policy already exists." -Level "WARNING"
    }

    return 
}

# Function to Update Policies
Function UpdatePolicies {
    param (
        [string]$updateMode,
        [string]$desiredState,
        [string[]]$selectedPolicyIndices = @(),
        [string[]]$newPolicyNames = @()
    )

    # Ask for operator's consent to proceed
    $consent = Read-Host -Prompt "Do you wish to update Conditional Access Policies? (Yes/No)"

    # Check the consent and act accordingly
    if ($consent -notmatch '^(yes|y)$') {
    # Log and exit if the consent is not given
    Write-Log -Message "You did not consent to update Conditional Access Policies. Exiting script." -Level "ERROR"
    Exit
    } else {
    # Log if the consent is given
    Write-Log -Message "You have consented to updating existing Conditional Access Policies." -Level "IMPORTANT"
    }

    $policies = Get-MgIdentityConditionalAccessPolicy -Property DisplayName, Id, State

    # Filter policies for selected mode
    $policiesToUpdate = @()
    if ($updateMode -eq "selected") {
        foreach ($index in $selectedPolicyIndices) {
            $policyIndex = [int]$index - 1
            if ($policyIndex -lt $policies.Count -and $policyIndex -ge 0) {
                $policiesToUpdate += $policies[$policyIndex]
            }
        }
    } else {
        $policiesToUpdate = $policies
    }

    # Update policies, excluding newly created ones if mode is "all"
    foreach ($policy in $policiesToUpdate) {
        if ($updateMode -eq "all" -and $newPolicyNames -contains $policy.DisplayName) {
            Write-Log -Message "Skipping update for newly created policy $($policy.DisplayName)." -Level "INFO"
            continue
        }

        # Check if the current state matches the desired state
        if ($policy.State -ne $desiredState) {
            try {
                # Explicitly pass the parameters to the cmdlet
                $policyParameters = @{
                    ConditionalAccessPolicyId = $policy.Id
                    BodyParameter = @{
                        DisplayName = $policy.DisplayName
                        State = $desiredState
                        Conditions = $policy.Conditions
                        GrantControls = $policy.GrantControls
                        SessionControls = $policy.SessionControls
                    }
                }
                Update-MgIdentityConditionalAccessPolicy @policyParameters > $null
                Write-Log -Message "Updated policy $($policy.DisplayName) to state: $desiredState" -Level "IMPORTANT"
            } catch {
                Write-Log -Message "Failed to update policy: $($policy.DisplayName). Error: $($_.Exception.Message)" -Level "ERROR"
            }
        } else {
            Write-Log -Message "Policy $($policy.DisplayName) is already in the desired state: $desiredState. No update needed." -Level "INFO"
        }
    }
}

# Function to Change Policy Activation Status
Function Get-DesiredState {
    param (
        [string]$choice
    )

    switch ($choice) {
        'E' { return 'enabled' }
        'D' { return 'disabled' }
        'R' { return 'enabledForReportingButNotEnforced' }
        default {
            Write-Log -Message "Invalid choice: $choice. Exiting." -Level "ERROR"
            exit
        }
    }
}

# Function to Display Policies in Columns
Function DisplayPoliciesInColumns {
    param (
        [array]$policies,
        [int]$itemsPerPage = 5  # Default items per page
    )

    $totalPolicies = $policies.Count
    $totalPages = [math]::Ceiling($totalPolicies / $itemsPerPage)
    $currentPage = 1
    $selectedIndices = @{}
    $selectedIndex = 1  # Start the index at 1

    do {
        CLS
        Write-Host "---------------------------------------------------------------------------------------------"
        Write-Host "Microsoft Entra ID Conditional Access Policies             (Page $currentPage of $totalPages)"
        Write-Host "---------------------------------------------------------------------------------------------"
        Write-Host ""

        $startIndex = ($currentPage - 1) * $itemsPerPage
        $endIndex = [math]::Min($startIndex + $itemsPerPage - 1, $totalPolicies - 1)

        $currentPolicies = $policies[$startIndex..$endIndex]

        # Display the pointer (>>>)
        $pointer = @{}
        $pointer[$selectedIndex] = " >>>"

        $index = $startIndex
        $currentPolicies | ForEach-Object {
            $indexString = ($index + 1).ToString().PadLeft([math]::Log10($totalPolicies) + 1, '0')  # Adjust index display
            $checkMark = if ($selectedIndices.ContainsKey($index + 1)) { "[X]" } else { "[ ]" }
            $pointerString = if ($pointer.ContainsKey($index - $startIndex + 1)) { $pointer[$index - $startIndex + 1] } else { "    " }  # Adjust pointer display
            Write-Host "$indexString) $pointerString $checkMark $($_.DisplayName) [$($_.State)]"
            $index++
        }

        Write-Host ""
        Write-Host "---------------------------------------------------------------------------------------------"
        Write-Host "(N) Next Page (P) Previous Page (U) Up a Policy (D) Down a Policy (S) Toggle Selection"
        Write-Host "(C) Confirm Selection (E) Exit Update"
        Write-Host "---------------------------------------------------------------------------------------------"
        Write-Host ""
        $input = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode
        
        switch ($input) {
            0x4E {  # 'N' key
                if ($currentPage -lt $totalPages) { 
                    $currentPage++
                    $selectedIndex = 1  # Reset selectedIndex when moving to the next page
                }
            }
            0x50 {  # 'P' key
                if ($currentPage -gt 1) { 
                    $currentPage--
                    $selectedIndex = 1  # Reset selectedIndex when moving to the previous page
                }
            }
            0x55 {  # 'U' key
                if ($selectedIndex -gt 1) { 
                    $selectedIndex-- 
                } elseif ($currentPage -gt 1) {
                    $currentPage--
                    $selectedIndex = [math]::Min($itemsPerPage, $totalPolicies - ($currentPage - 1) * $itemsPerPage)
                }
            }
            0x53 {  # 'S' key
                $index = $startIndex + $selectedIndex - 1
                if ($selectedIndices.ContainsKey($index + 1)) {
                    $selectedIndices.Remove($index + 1)
                } else {
                    $selectedIndices.Add($index + 1, $true)
                }
            }
            0x44 {  # 'D' key
                if ($selectedIndex -lt $itemsPerPage) { 
                    $selectedIndex++ 
                } elseif ($currentPage -lt $totalPages) {
                    $currentPage++
                    $selectedIndex = 1
                }
            }
            0x43 {  # 'C' key
                if ($selectedIndices.Count -eq 0) {
                    Write-Host "No policies selected. Returning empty selection."
                }
                return $selectedIndices.Keys
            }
            0x45 {  # 'E' key
                Write-Host "Exiting Update..."
                return @()  # Return empty array to indicate exit without selection
            }
            default {
                Write-Host "Invalid option: $($input)"
            }
        }
    } while ($true)
}

# Function to Convert Object IDs to Display Names
Function ConvertTo-DisplayName {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$InputIds,
        [string]$Type
    )

    $ConvertedNames = @()

    # Ensure caches are initialized
    $RolesCache = if ($null -eq $RolesCache) { @{} } else { $RolesCache }
    $ServicePrincipalsCache = if ($null -eq $ServicePrincipalsCache) { @{} } else { $ServicePrincipalsCache }
    $NamedLocationCache = if ($null -eq $NamedLocationCache) { @{} } else { $NamedLocationCache }

    foreach ($Id in $InputIds) {
        # Handle special cases for 'All' and 'None'
        if ($Id -in @('All', 'None')) {
            $ConvertedNames += $Id
            continue
        }

        try {
            $Name = switch ($Type) {
                "User" {
                    (Get-MgUser -UserId $Id -ErrorAction SilentlyContinue).DisplayName
                }
                "ServicePrincipal" {
                    # Resolve by ServicePrincipalId or AppId
                    if ($ServicePrincipalsCache.ContainsKey($Id)) {
                        $ServicePrincipalsCache[$Id].DisplayName
                    } else {
                        # Attempt to fetch directly using both ServicePrincipalId and AppId
                        $ServicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $Id -ErrorAction SilentlyContinue
                        if (-not $ServicePrincipal) {
                            $ServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$Id'" -ErrorAction SilentlyContinue
                        }
                        if ($ServicePrincipal) {
                            # Cache the result
                            $ServicePrincipalsCache[$ServicePrincipal.Id] = $ServicePrincipal
                            $ServicePrincipal.DisplayName
                        } else {
                            $Id  # Fallback if not found
                        }
                    }
                }
                "Group" {
                    (Get-MgGroup -GroupId $Id -ErrorAction SilentlyContinue).DisplayName
                }
                "Location" {
                    if ($NamedLocationCache.ContainsKey($Id)) {
                        $NamedLocationCache[$Id].DisplayName
                    } else {
                        $Id  # Fallback if not found
                    }
                }
                "DirectoryRole" {
                    if ($RolesCache.ContainsKey($Id)) {
                        $RolesCache[$Id]
                    } else {
                        # Fallback to fetching the Directory Role if not in cache
                        $RoleTemplate = Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $Id -ErrorAction SilentlyContinue
                        if ($RoleTemplate) {
                            $RolesCache[$Id] = $RoleTemplate.DisplayName
                            $RoleTemplate.DisplayName
                        } else {
                            $Id  # Fallback if not found
                        }
                    }
                }
                default {
                    $Id  # Fallback for unrecognized types
                }
            }

            # Add the resolved name or fallback ID to the results
            $ConvertedNames += if ($Name) { $Name } else { $Id }
        } catch {
            Write-Host "Error retrieving Display Name for $Type ID: $Id - $_"
            $ConvertedNames += $Id  # Fallback to ID if lookup fails
        }
    }

    return $ConvertedNames -join ", "
}

# Function to export Conditional Access Policies
function Export-ConditionalAccessPolicies {
    Write-Log -Message "Exporting all Conditional Access Policies..." -Level "IMPORTANT"
    $OutputCount = 0

    # Initialize global caches for Service Principals and Named Locations for efficient lookups
    Write-Log -Message "Initializing Service Principals and Named Location caches..." -Level "INFO"
    $global:ServicePrincipalsCache = Get-MgBetaServicePrincipal -All | Group-Object -Property Id -AsHashTable
    $global:NamedLocationCache = Get-MgBetaIdentityConditionalAccessNamedLocation -All | Group-Object -Property Id -AsHashTable

    # Retrieve Conditional Access policies
    Write-Log -Message "Retrieving Conditional Access Policies..." -Level "INFO"
    $CAPolicies = Get-MgBetaIdentityConditionalAccessPolicy -All

    # Check if any policies are returned
    if (-not $CAPolicies) {
        Write-Log -Message "[ERROR] No Conditional Access Policies found for export." -Level "ERROR"
        return
    }

    Write-Log -Message "Found $($CAPolicies.Count) Conditional Access Policies. Processing..." -Level "INFO"

    # Process each policy
    $CAPolicies | ForEach-Object {
        $CAName = $_.DisplayName
        $Description = $_.Description
        $CreationTime = $_.CreatedDateTime
        $LastModifiedTime = $_.ModifiedDateTime
        $State = $_.State

        # Conditions
        $Conditions = $_.Conditions

        # Convert object IDs to display names for users, groups, roles, and applications
        $IncludeUsers = if ($Conditions.Users.IncludeUsers.Count -gt 0) { ConvertTo-DisplayName -Type "User" -InputIds $Conditions.Users.IncludeUsers } else { "" }
        $ExcludeUsers = if ($Conditions.Users.ExcludeUsers.Count -gt 0) { ConvertTo-DisplayName -Type "User" -InputIds $Conditions.Users.ExcludeUsers } else { "" }
        $IncludeGroups = if ($Conditions.Users.IncludeGroups.Count -gt 0) { ConvertTo-DisplayName -Type "Group" -InputIds $Conditions.Users.IncludeGroups } else { "" }
        $ExcludeGroups = if ($Conditions.Users.ExcludeGroups.Count -gt 0) { ConvertTo-DisplayName -Type "Group" -InputIds $Conditions.Users.ExcludeGroups } else { "" }
        $IncludeRoles = if ($Conditions.Users.IncludeRoles.Count -gt 0) { ConvertTo-DisplayName -Type "DirectoryRole" -InputIds $Conditions.Users.IncludeRoles } else { "" }
        $ExcludeRoles = if ($Conditions.Users.ExcludeRoles.Count -gt 0) { ConvertTo-DisplayName -Type "DirectoryRole" -InputIds $Conditions.Users.ExcludeRoles } else { "" }
        $IncludeApplications = if ($Conditions.Applications.IncludeApplications.Count -gt 0) { ConvertTo-DisplayName -Type "ServicePrincipal" -InputIds $Conditions.Applications.IncludeApplications } else { "" }
        $ExcludeApplications = if ($Conditions.Applications.ExcludeApplications.Count -gt 0) { ConvertTo-DisplayName -Type "ServicePrincipal" -InputIds $Conditions.Applications.ExcludeApplications } else { "" }
        $IncludeLocations = if ($Conditions.Locations.IncludeLocations.Count -gt 0) { ConvertTo-DisplayName -Type "Location" -InputIds $Conditions.Locations.IncludeLocations } else { "" }
        $ExcludeLocations = if ($Conditions.Locations.ExcludeLocations.Count -gt 0) { ConvertTo-DisplayName -Type "Location" -InputIds $Conditions.Locations.ExcludeLocations } else { "" }

        # Other conditions and controls
        $UserRisk = $Conditions.UserRiskLevels -join ","
        $SigninRisk = $Conditions.SignInRiskLevels -join ","
        $ClientApps = $Conditions.ClientAppTypes -join ","
        $IncludeDevicePlatform = $Conditions.Platforms.IncludePlatforms -join ","
        $ExcludeDevicePlatform = $Conditions.Platforms.ExcludePlatforms -join ","

        # Grant and session controls
        $AccessControl = $_.GrantControls.BuiltInControls -join ","
        $AccessControlOperator = $_.GrantControls.Operator
        $AuthenticationStrength = $_.GrantControls.AuthenticationStrength.DisplayName
        $AuthenticationStrengthAllowedCombo = $_.GrantControls.AuthenticationStrength.AllowedCombinations -join ","
        $AppEnforcedRestrictions = $_.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
        $CloudAppSecurity = $_.SessionControls.CloudAppSecurity.IsEnabled
        $CAEMode = $_.SessionControls.ContinuousAccessEvaluation.Mode
        $DisableResilienceDefaults = $_.SessionControls.DisableResilienceDefaults
        $IsSigninFrequencyEnabled = $_.SessionControls.SignInFrequency.IsEnabled
        $SignInFrequencyValue = if ($_.SessionControls.SignInFrequency) { "$($_.SessionControls.SignInFrequency.Value) $($_.SessionControls.SignInFrequency.Type)" } else { "" }

        # Prepare result for CSV export
        $Result = [PSCustomObject]@{
            'CA Policy Name'                    = $CAName
            'Description'                       = $Description
            'Creation Time'                     = $CreationTime
            'Modified Time'                     = $LastModifiedTime
            'State'                             = $State
            'Include Users'                     = $IncludeUsers
            'Exclude Users'                     = $ExcludeUsers
            'Include Groups'                    = $IncludeGroups
            'Exclude Groups'                    = $ExcludeGroups
            'Include Roles'                     = $IncludeRoles
            'Exclude Roles'                     = $ExcludeRoles
            'Include Applications'              = $IncludeApplications
            'Exclude Applications'              = $ExcludeApplications
            'Include Locations'                 = $IncludeLocations
            'Exclude Locations'                 = $ExcludeLocations
            'User Risk'                         = $UserRisk
            'Signin Risk'                       = $SigninRisk
            'Client Apps'                       = $ClientApps
            'Include Device Platform'           = $IncludeDevicePlatform
            'Exclude Device Platform'           = $ExcludeDevicePlatform
            'Access Control'                    = $AccessControl
            'Access Control Operator'           = $AccessControlOperator
            'Authentication Strength'           = $AuthenticationStrength
            'Auth Strength Allowed Combo'       = $AuthenticationStrengthAllowedCombo
            'App Enforced Restrictions Enabled' = $AppEnforcedRestrictions
            'Cloud App Security'                = $CloudAppSecurity
            'CAE Mode'                          = $CAEMode
            'Disable Resilience Defaults'       = $DisableResilienceDefaults
            'Is Signin Frequency Enabled'       = $IsSigninFrequencyEnabled
            'Signin Frequency Value'            = $SignInFrequencyValue
        }

        # Export each policy entry to CSV
        $Result | Export-Csv -Path $ExportCSV -Append -NoTypeInformation
        Write-Log -Message "Exported policy: $CAName" -Level "INFO"
        $OutputCount++
    }

    if ($OutputCount -eq 0) {
        Write-Log -Message "No data found for export." -Level "ERROR"
    } else {
        Write-Log -Message "`nThe output file contains $OutputCount CA policies." -Level "INFO"
        Write-Log -Message "`nThe X Output file is available at: $ExportCSV" -ForegroundColor -Level "IMPORTANT"
    }
}

# ------------------------------------------------------------------------------------------------------------------------

# Main Script Logic
do {
    # Check if Security Defaults are Enabled
    try {
        $currentPolicy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        if ($currentPolicy -and $currentPolicy.IsEnabled -eq $true) {
            Write-Log -Message "Security Defaults is enabled in the tenant. Exiting script." -Level "ERROR"
            exit
        }
    } catch {
        Write-Log -Message "Failed to check Identity Security Default Enforcement Policy. Error: $($_.Exception.Message)" -Level "ERROR"
    }

    SLEEP 2
    CLS
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host "Phase 1: KAKURI - Restore Positive Administrative Control Conditional Access." -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host ""
    Write-Host "[1]: Create A New Trusted Location"
    Write-Host "[2]: Create New & update Existing Policies"
    Write-Host "[3]: Create New Policies Only"
    Write-Host "[4]: Update All Policies"
    Write-Host "[5]: Update Specific Policies"
    Write-Host "[6]: Export All Policies"
    Write-Host "[7]: Exit"
    Write-Host ""
    Write-Host "----------------------------------------------------------------------------------"
    $operationMode = Read-Host "Enter your choice"

    switch ($operationMode) {
        "1" { 
            CLS
            Create-TrustedLocations
        }
        "2" { 
            CLS
            $newPolicyNames = CreateNewPolicies
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host "Options to update NEW Conditional Access Policies"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host "[E]: enabled"
            Write-Host "[D]: disabled"
            Write-Host "[R]: enabledForReportingButNotEnforced"
            Write-Host "[Q]: Quit Update"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host ""
            $choice = Read-Host "Choose an action to perform on existing Conditional Access Policies"
            if ($choice -eq "Q" -or $choice -eq "q") {
                continue
            }
            $desiredState = Get-DesiredState -choice $choice
            UpdatePolicies -updateMode "all" -desiredState $desiredState -newPolicyNames $newPolicyNames
        }
        "3" { 
            CLS
            CreateNewPolicies
        }
        "4" { 
            CLS
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host "Options to update ALL Conditional Access Policies"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host ""
            Write-Host "[E]: enabled"
            Write-Host "[D]: disabled"
            Write-Host "[R]: enabledForReportingButNotEnforced"
            Write-Host "[Q]: Quit Update"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host ""
            $choice = Read-Host "Choose an action for all policies"
            if ($choice -eq "Q" -or $choice -eq "q") {
                continue
            }
            $desiredState = Get-DesiredState -choice $choice
            UpdatePolicies -updateMode "all" -desiredState $desiredState
        }
        "5" {
            CLS
            $policies = Get-MgIdentityConditionalAccessPolicy -Property DisplayName, Id, State
            $selectedPolicyIndicesArray = DisplayPoliciesInColumns -policies $policies | Sort-Object -Property DisplayName
            if ($selectedPolicyIndicesArray.Count -eq 0) {
                Write-Host "No policies selected. Returning to main menu."
                continue
            }
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host "Options to update SPECIFIC Conditional Access Policies"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host ""
            Write-Host "[E]: enabled"
            Write-Host "[D]: disabled"
            Write-Host "[R]: enabledForReportingButNotEnforced"
            Write-Host "----------------------------------------------------------------------------------"
            Write-Host ""
            $choice = Read-Host "Choose an action to perform on existing Conditional Access Policies"
            $desiredState = Get-DesiredState -choice $choice
            UpdatePolicies -updateMode "selected" -desiredState $desiredState -selectedPolicyIndices $selectedPolicyIndicesArray
        }
        "6" { 
            CLS
            Export-ConditionalAccessPolicies
        }
        "7" {
             Write-Host "Exiting the script..." -ForegroundColor Yellow
             # Exit Microsoft Graph Session
             Disconnect-MSGraph > $Null

             # Mark The End of the Script
             Write-Log -Message "[SCRIPT] End of Manage_ConditionalAccessPolicies Script." -Level "SOS"
             SLEEP 2
             CLS
             Exit
        }
        default {
            Write-Host "Invalid choice. Please select again."
            Return
        }
    }

} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
