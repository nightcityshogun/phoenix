<#
.SYNOPSIS
    This PowerShell script connects to Microsoft Entra ID using Microsoft Graph and exports all permanent and eligible role assignments for users, groups, and service principals.

.DESCRIPTION
    This script connects to Azure and:
    - Exports current Privileged Eligible and Permanent Role Assiignments in Microsoft Entra ID

.PARAMETER NULL
    There are no supported parameters

.NOTES
    Author: NightCityShogun
    Name: Backup_EntraDirectoryRoleAssignments
    Version: 3.8
    Date: 2023-12-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.Governance",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Users"
)

$Scopes = @("Application.Read.All",
"Group.Read.All",
"GroupMember.Read.All",
"Directory.Read.All",
"Organization.Read.All",
"RoleManagement.Read.Directory",
"RoleEligibilitySchedule.Read.Directory",
"RoleManagement.Read.All",
"RoleManagement.Read.Directory",
"User.ReadBasic.All",
"User.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

$roleTemplateIdMapping = @{}
$roleAssignments = @()

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Export File Path
$csvFilePath = Join-Path -Path $PSScriptRoot -ChildPath ("Backup_EntraDirectoryRoleAssignments_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

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
        [string]$PrincipalType = "",
        [bool]$LogOnly = $false  
    )

    # Format Log Entry PrincipalType
    $principalTag = if ($PrincipalType) { "[{0}]" -f $PrincipalType.ToUpper() } else { "" }
    $logEntry = "[{0}] [{1}] {2} {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $principalTag, $Message
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
Write-Log -Message "[SCRIPT] Start of Backup_EntraDirectoryRoleAssignments Script." -Level "SOS"

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

# Modules For Microsoft Azure
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

# Main Script Logic
Write-Host "----------------------------------------------------------------------------------"
Write-Host "          -" -ForegroundColor Cyan
Write-Host "Phase 2: Joka - Restore Positive Administrative Control Management Groups."          -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------------------"
Write-Host ""

# Fetch Roles and Associated Role Templates
$allRoleTemplates = Get-MgDirectoryRoleTemplate | Select-Object DisplayName, Id | Sort-Object DisplayName
foreach ($roleTemplate in $allRoleTemplates) {
    $roleTemplateIdMapping[$roleTemplate.DisplayName] = $roleTemplate.Id
}

# Function to Get PrincipalType and PrincipalDisplayName
function Get-PrincipalDetails {
    param (
        [string]$PrincipalId
    )

    $user = Get-MgUser -UserId $PrincipalId -ErrorAction SilentlyContinue
    if ($user) {
        return "USER", $user.DisplayName, $user.UserPrincipalName
    }

    $group = Get-MgGroup -GroupId $PrincipalId -ErrorAction SilentlyContinue
    if ($group) {
        return "GROUP", $group.DisplayName, $group.DisplayName
    }

    $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -ErrorAction SilentlyContinue
    if ($sp) {
        return "SERVICEPRINCIPAL", $sp.DisplayName, $sp.DisplayName
    }

    return "UNKNOWN", "Unknown", "Unknown"
}

# Process Eligible Role Assignments
Write-Log -Message "Starting Backup of Eligible Role Assignments" -Level "SOS"
$eligibleRoleAssignmentsInfo = Get-MgRoleManagementDirectoryRoleEligibilitySchedule | Select-Object -Property RoleDefinitionId, PrincipalId -ErrorAction SilentlyContinue
foreach ($roleAssignmentInfo in $eligibleRoleAssignmentsInfo) {
    $roleDefinitionId = $roleAssignmentInfo.RoleDefinitionId
    $principalId = $roleAssignmentInfo.PrincipalId

    $principalDetails = Get-PrincipalDetails -PrincipalId $principalId
    $principalType = $principalDetails[0]
    $principalDisplayName = $principalDetails[1]
    $principalName = $principalDetails[2]

    $role = Get-MgDirectoryRoleByRoleTemplateId -RoleTemplateId $roleDefinitionId
    $roleDisplayName = if ($role) { $role.DisplayName } else { "RoleNameNotFound" }
    $roleTemplateId = $roleTemplateIdMapping[$role.DisplayName]

    if ($principalType -eq "GROUP") {
        Write-Log -Message "$principalDisplayName which has Eligible role $roleDisplayName" -Level "INFO" -PrincipalType $principalType

        $group = Get-MgGroup -GroupId $principalId
        $groupDetails = [PSCustomObject]@{
            Principal           = $principalName
            PrincipalDisplayName= $principalDisplayName
            PrincipalType       = $principalType
            Id                  = $principalId
            GroupDescription    = $group.Description
            GroupVisibility     = $group.Visibility
            AssignedRole        = $roleDisplayName
            RoleTemplateID      = $roleTemplateId
            AssignedRoleScope   = "/"
            AssignmentType      = "Eligible"
            IsPrivileged        = $true 
            IsBuiltIn           = $false 
        }
        $roleAssignments += $groupDetails

        $groupMembers = Get-MgGroupMember -GroupId $principalId
        foreach ($groupMember in $groupMembers) {
            $groupMemberDetails = Get-PrincipalDetails -PrincipalId $groupMember.Id
            $groupMemberType = $groupMemberDetails[0]
            $groupMemberDisplayName = $groupMemberDetails[1]
            $groupMemberName = $groupMemberDetails[2]

            if ($groupMemberType -eq "SERVICE_PRINCIPAL") {
                Write-Log -Message "$groupMemberDisplayName is a Service Principal member of $principalDisplayName" -Level "INFO" -PrincipalType $groupMemberType
            }

            $roleAssignments += [PSCustomObject]@{
                Principal           = $groupMemberName
                PrincipalDisplayName= $groupMemberDisplayName
                PrincipalType       = $groupMemberType
                Id                  = $groupMember.Id
                AssignedRole        = $roleDisplayName
                RoleTemplateID      = $roleTemplateId
                AssignedRoleScope   = "/"
                AssignmentType      = "Eligible"
                IsPrivileged        = $true 
                IsBuiltIn           = $false 
            }
            Write-Log -Message "$groupMemberName is a Member of $principalDisplayName which has Eligible Role $roleDisplayName" -Level "INFO" -PrincipalType $groupMemberType
        }
    } elseif ($principalType -eq "SERVICE_PRINCIPAL") {
        Write-Log -Message "$principalDisplayName which has Role $roleDisplayName" -Level "INFO" -PrincipalType $principalType

        $roleAssignments += [PSCustomObject]@{
            Principal           = $principalName
            PrincipalDisplayName= $principalDisplayName
            PrincipalType       = $principalType
            Id                  = $principalId
            AssignedRole        = $roleDisplayName
            RoleTemplateID      = $roleTemplateId
            AssignedRoleScope   = "/"
            AssignmentType      = "Eligible"
            IsPrivileged        = $true 
            IsBuiltIn           = $false 
        }

        Write-Log -Message "$principalName is an Eligible Role Member of $roleDisplayName" -Level "INFO" -PrincipalType $principalType
    } else {
        $roleAssignments += [PSCustomObject]@{
            Principal           = $principalName
            PrincipalDisplayName= $principalDisplayName
            PrincipalType       = $principalType
            Id                  = $principalId
            AssignedRole        = $roleDisplayName
            RoleTemplateID      = $roleTemplateId
            AssignedRoleScope   = "/"
            AssignmentType      = "Eligible"
            IsPrivileged        = $true 
            IsBuiltIn           = $false 
        }

        Write-Log -Message "$principalName is an Eligible Role Member of $roleDisplayName" -Level "INFO" -PrincipalType $principalType
    }
}

# Log No of Eligible Role Assignments
$eligibleAssignmentsCount = $roleAssignments | Where-Object AssignmentType -eq "Eligible" | Measure-Object
Write-Host "----------------------------------------------------------------------------------" 
Write-Log -Message "Eligible Role Assignment Count: $($eligibleAssignmentsCount.Count)" -Level "IMPORTANT" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------------------"

# Process Permanent Role Assignments
Write-Log -Message "Starting Backup of Permanent Role Assignments" -Level "SOS"
$allRoles = Get-MgDirectoryRole | Select-Object -Property DisplayName, Id | Sort-Object -Property DisplayName
foreach ($role in $allRoles) {
    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id

    foreach ($member in $roleMembers) {
        $principalDetails = Get-PrincipalDetails -PrincipalId $member.Id
        $principalType = $principalDetails[0]
        $principalDisplayName = $principalDetails[1]
        $principalName = $principalDetails[2]

        $roleDisplayName = $role.DisplayName

        if ($principalType -eq "GROUP") {
            Write-Log -Message "$principalDisplayName which has role $roleDisplayName" -Level "INFO" -PrincipalType $principalType

            $group = Get-MgGroup -GroupId $member.Id
            $groupDetails = [PSCustomObject]@{
                Principal           = $principalName
                PrincipalDisplayName= $principalDisplayName
                PrincipalType       = $principalType
                Id                  = $member.Id
                GroupDescription    = $group.DisplayName
                GroupVisibility     = $group.Visibility
                AssignedRole        = $roleDisplayName
                RoleTemplateID      = $roleTemplateIdMapping[$role.DisplayName]
                AssignedRoleScope   = "/"
                AssignmentType      = "Permanent"
                IsPrivileged        = $true 
                IsBuiltIn           = $false 
            }
            $roleAssignments += $groupDetails

            $groupMembers = Get-MgGroupMember -GroupId $member.Id
            foreach ($groupMember in $groupMembers) {
                $groupMemberDetails = Get-PrincipalDetails -PrincipalId $groupMember.Id
                $groupMemberType = $groupMemberDetails[0]
                $groupMemberDisplayName = $groupMemberDetails[1]
                $groupMemberName = $groupMemberDetails[2]

                if ($groupMemberType -eq "SERVICE_PRINCIPAL") {
                    Write-Log -Message "$groupMemberDisplayName is a Service Principal member of $principalDisplayName" -Level "INFO" -PrincipalType $groupMemberType
                }

                $roleAssignments += [PSCustomObject]@{
                    Principal           = $groupMemberName
                    PrincipalDisplayName= $groupMemberDisplayName
                    PrincipalType       = $groupMemberType
                    Id                  = $groupMember.Id
                    AssignedRole        = $roleDisplayName
                    RoleTemplateID      = $roleTemplateIdMapping[$role.DisplayName]
                    AssignedRoleScope   = "/"
                    AssignmentType      = "Permanent"
                    IsPrivileged        = $true 
                    IsBuiltIn           = $false 
                }
                Write-Log -Message "$groupMemberName is a Member of $principalDisplayName which has Permanent Role $roleDisplayName" -Level "INFO" -PrincipalType $groupMemberType
            }
        } elseif ($principalType -eq "SERVICE_PRINCIPAL") {
            Write-Log -Message "$principalDisplayName which has role $roleDisplayName" -Level "INFO" -PrincipalType $principalType

            $roleAssignments += [PSCustomObject]@{
                Principal           = $principalName
                PrincipalDisplayName= $principalDisplayName
                PrincipalType       = $principalType
                Id                  = $member.Id
                AssignedRole        = $roleDisplayName
                RoleTemplateID      = $roleTemplateIdMapping[$role.DisplayName]
                AssignedRoleScope   = "/"
                AssignmentType      = "Permanent"
                IsPrivileged        = $true 
                IsBuiltIn           = $false 
            }

            Write-Log -Message "$principalName is a Permanent Role Member of $roleDisplayName" -Level "INFO" -PrincipalType $principalType
        } else {
            $roleAssignments += [PSCustomObject]@{
                Principal           = $principalName
                PrincipalDisplayName= $principalDisplayName
                PrincipalType       = $principalType
                Id                  = $member.Id
                AssignedRole        = $roleDisplayName
                RoleTemplateID      = $roleTemplateIdMapping[$role.DisplayName]
                AssignedRoleScope   = "/"
                AssignmentType      = "Permanent"
                IsPrivileged        = $true 
                IsBuiltIn           = $false 
            }

            Write-Log -Message "$principalName is a Permanent Role Member of $roleDisplayName" -Level "INFO" -PrincipalType $principalType
        }
    }
}

# Log No of Permanent Role Assignments
$permanentAssignmentsCount = $roleAssignments | Where-Object AssignmentType -eq "Permanent" | Measure-Object
Write-Host "----------------------------------------------------------------------------------"
Write-Log -Message "Permanent Role Assignment Count: $($permanentAssignmentsCount.Count)" -Level "IMPORTANT" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------------------"

# Sort Role Assignments by Principal
$sortedRoleAssignments = $roleAssignments | Sort-Object -Property Principal

# Export to CSV
$sortedRoleAssignments | Export-Csv -Path $csvFilePath -NoTypeInformation
Write-Log -Message "Data exported to CSV in sorted order." -Level "INFO"

# ------------------------------------------------------------------------------------------------------------------------

# Exit Microsoft Graph Session
Disconnect-MSGraph > $Null

# Mark The End of the Script
Write-Log -Message "[SCRIPT] End of Backup_EntraDirectoryRoleAssignments Script." -Level "SOS"
SLEEP 2
CLS

# (C) NightCityShogun 2024
