<#
.SYNOPSIS
    Manages Azure Management Group role assignments, including creation, backup, and cleanup.
    Includes configurable parameters for retry logic and delay intervals.

.DESCRIPTION
    This script connects to Azure, requests operator consent, and provides options to:
    - Create role assignments for Azure Management Groups.
    - Backup existing role assignments to a CSV file.
    - Clean up role assignments from Azure Management Groups.

.PARAMETER maxRoles
    Specifies the maximum number of roles to assign per subscription. Default is set to 2.

.PARAMETER maxUsers
    Specifies the maximum number of users to assign per subscription. Default is set to 2.

.PARAMETER maxGroups
    Specifies the maximum number of groups to assign per subscription. Default is set to 1.

.PARAMETER maxMgmtGroupsToUse
    Specifies the maximum number of subscriptions to process in a single execution. Default is set to 1.

.PARAMETER maxRetries
    Specifies the maximum number of retries for operations requiring retry logic. Default is set to 2.

.PARAMETER delaySeconds
    Specifies the delay, in seconds, between retry attempts. Default is set to 2.

.NOTES
    Author: NightCityShogun
    Name: Manage_AzureManagementGroupRoleAssignments
    Version: 3.8
    Date: 2023-06-15
#>
# ------------------------------------------------------------------------------------------------------------------------

# Parameters
param (
    [int]$maxRoles = 2,  
    [int]$maxUsers = 2,  
    [int]$maxGroups = 1,  
    [int]$maxMgmtGroupsToUse = 1,
    [int]$maxRetries = 2,
    [int]$delaySeconds = 2
)

# Microsoft Az PowerShell Modules
$modules = @("Az.Accounts", 
"Az.Resources")

# Exclude Temporary Administrative Accounts
$excludePattern = "^ncs\.adm0" 

# Azure Role Assignments for Lab
$Roles = @{
    "Azure Front Door Secret Reader" = "0db238c4-885e-4c4f-a933-aa2cef684fca"
    "Contributor" = "b24988ac-6180-42a0-ab88-20f7382dd24c"
    "Cosmos DB Operator" = "230815da-be43-4aae-9cb4-875f7bd000aa"
    "Desktop Virtualization Host Pool Contributor" = "e307426c-f9b6-4e81-87de-d99efb3c32bc"
    "Kubernetes Extension Contributor" = "85cb6faf-e071-4c9b-8136-154b5a04f717"
    "Network Contributor" = "4d97b98b-1d4f-4787-a291-c67834d212e7"
    "Reader" = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
    "Role Based Access Control Administrator" = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
    "Storage Blob Data Contributor" = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
    "Virtual Machine Contributor" = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
}

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Search Pattern
$backupFilePattern = "Manage_AzureManagementGroupRoleAssignments_Backup_*.csv"

# Export File Path
$backupFileName = "Manage_AzureManagementGroupRoleAssignments_Backup" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv"
$backupFilePath = Join-Path $PSScriptRoot $backupFileName

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
Write-Log -Message "[SCRIPT] Start of Manage_AzureManagementGroupRoleAssignments Script." -Level "SOS"

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
function Import-Modules {
    Write-Log -Message "Starting module import process..." -Level "INFO"

    foreach ($module in $modules) {
        try {
            # Attempt to remove the module if it's already loaded
            if (Get-Module -Name $module) {
                Write-Log -Message "Removing old version of $module..." -Level "INFO"
                Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log -Message "Error removing module ${module}: $($_.Exception.Message)" -Level "ERROR"
        }

        try {
            # Check if the module is installed; if not, install it
            if (!(Get-Module -ListAvailable -Name $module)) {
                Write-Log -Message "Installing module $module..." -Level "INFO"
                Install-Module -Name $module -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }

            # Import the module
            Write-Log -Message "Importing module $module..." -Level "INFO"
            Import-Module -Name $module -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Error installing/importing module ${module}: $($_.Exception.Message)" -Level "ERROR"
            exit
        }
    }

    Write-Log -Message "All required Azure modules have been imported successfully." -Level "INFO"
}

# Function to Connect to Azure
function Connect-Azure {
    param (
        [int]$maxRetries = 2,      # Number of retry attempts for context validation
        [int]$delaySeconds = 2     # Delay between retries
    )

    try {
        # Clear existing Azure context
        Clear-AzContext -Force -Scope Process
        Write-Log -Message "Azure context cleared successfully." -Level "INFO"

        # Connect to Azure
        Write-Log -Message "Initiating connection to Azure..." -Level "INFO"
        $azContext = Connect-AzAccount -ErrorAction Stop

        # Validate Azure context initialization
        $retryCount = 0
        while ($retryCount -lt $maxRetries) {
            Start-Sleep -Seconds $delaySeconds
            $azContext = Get-AzContext -ErrorAction SilentlyContinue

            if ($azContext -and $azContext.Account -and $azContext.Subscription) {
                Write-Log -Message "Azure context successfully initialized for account: $($azContext.Account.Id)." -Level "INFO"
                break
            }

            $retryCount++
            Write-Log -Message "Waiting for Azure context to initialize... Attempt $retryCount of $maxRetries." -Level "WARNING"

            if ($retryCount -eq $maxRetries) {
                Write-Log -Message "Failed to initialize Azure context after $maxRetries attempts." -Level "ERROR"
                exit
            }
        }

        # Retrieve logged-on user's UPN
        $loggedOnUserUPN = $azContext.Account.Id.Trim()
        if (-not $loggedOnUserUPN -or $loggedOnUserUPN -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
            Write-Log -Message "Invalid UPN detected: $loggedOnUserUPN. Ensure the account is valid." -Level "ERROR"
            exit
        }

        Write-Log -Message "Account ID (UPN) retrieved: $loggedOnUserUPN" -Level "INFO"

        # Validate user details in Azure AD
        try {
            $loggedOnUser = Get-AzADUser -UserPrincipalName $loggedOnUserUPN -ErrorAction Stop
            Write-Log -Message "Logged-on user details retrieved successfully: UPN=$($loggedOnUserUPN), Id=$($loggedOnUser.Id)" -Level "INFO"
        } catch {
            Write-Log -Message "Unable to retrieve user details for UPN: $loggedOnUserUPN. Verify Azure AD permissions." -Level "ERROR"
            exit
        }

        # Return structured object with UPN and Id
        return [PSCustomObject]@{
            UPN = $loggedOnUserUPN
            Id  = $loggedOnUser.Id
        }
    } catch {
        Write-Log -Message "Critical error during Azure connection process: $($_.Exception.Message)" -Level "ERROR"
        exit
    }
}

# Function to Validate Prerequisites
function Check-Prerequisites {
    param (
        [string]$loggedOnUserUPN
    )

    # Validate $loggedOnUserUPN
    if (-not $loggedOnUserUPN) {
        Write-Log -Message "Error: UPN is null or empty. Verify Azure connection." -Level "ERROR"
        exit
    }

    if ($loggedOnUserUPN -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Write-Log -Message "Invalid UPN format detected: $loggedOnUserUPN. Ensure the UPN is correct." -Level "ERROR"
        exit
    }

    Write-Log -Message "Valid UPN detected: $loggedOnUserUPN" -Level "INFO"

    try {
        # Fetch role assignments for the user
        $roles = Get-AzRoleAssignment -SignInName $loggedOnUserUPN -Scope "/" -ErrorAction SilentlyContinue

        if (-not $roles -or $roles.Count -eq 0) {
            Write-Log -Message "No role assignments found for UPN: $loggedOnUserUPN. Ensure the account has access." -Level "ERROR"
            exit
        }

        # Log all roles for debugging
        Write-Log -Message "Debug: Roles assigned to ${loggedOnUserUPN}:" -Level "INFO"
        foreach ($role in $roles) {
            Write-Log -Message "Role: $($role.RoleDefinitionName), Scope: $($role.Scope), Assigned to: $($role.DisplayName)" -Level "INFO"
        }

        # Validate 'User Access Administrator' role
        $hasRequiredRole = $roles | Where-Object { $_.RoleDefinitionName -eq "User Access Administrator" }
        if (-not $hasRequiredRole -or $hasRequiredRole.Count -eq 0) {
            Write-Log -Message "User does not have the required 'User Access Administrator' role. Exiting." -Level "ERROR"
            exit
        }

        Write-Log -Message "User has the required role: User Access Administrator." -Level "INFO"
    } catch {
        Write-Log -Message "Failed to validate user role for UPN: $loggedOnUserUPN. Error: $($_.Exception.Message)" -Level "ERROR"
        exit
    }
}

# Validate x86 Architecture
Check-OSArchitecture > $null

# IMport Az Resource Modules
Import-Modules

# Connect to Azure and get the logged-on user's UPN
$loggedOnUserInfo = Connect-Azure
$loggedOnUserUPN = $loggedOnUserInfo.UPN

# Validate prerequisites
Check-Prerequisites -loggedOnUserUPN $loggedOnUserUPN

SLEEP 2
CLS

# ------------------------------------------------------------------------------------------------------------------------

# Function to Create New Role Assignments
function Create-NewRoleAssignments {
    # Get Management Groups
    $mgmtGroups = Get-AzManagementGroup | Select-Object -First $maxMgmtGroupsToUse

    # Prompt for consent to Create Management Group Role Assignments
    $consent = Read-Host -Prompt "Do you wish to create Role Assignments for Management Groups? (Yes/No)"
    if ($consent -notmatch '^(yes|y)$') {
        Write-Log -Message "Consent has not been provided for Management Group Role Assignment Creation." -Level "ERROR"
        exit
    }
    Write-Log -Message "Consent provided for Management Group Role Assignment Creation." -Level "IMPORTANT"

    # Iterate Management Groups
    foreach ($mgmtGroup in $mgmtGroups) {
        Write-Log -Message "Creating Role Assignments for $($mgmtGroup.DisplayName)" -Level "SOS"

        # Select Random Groups and Users
        $randomGroups = Get-AzADGroup -Filter "securityEnabled eq true" | Sort-Object DisplayName | Get-Random -Count $maxGroups
        $randomUsers = Get-AzADUser | Where-Object { $_.Id -ne $azContext.Account.Id -and $_.Id -ne $loggedOnUserInfo.Id } | Sort-Object DisplayName | Get-Random -Count $maxUsers

        # Assign Roles
        $roleCount = 0
        foreach ($roleName in ($Roles.Keys | Sort-Object)) {
            if ($roleCount -ge $maxRoles) {
                break
            }
            $roleId = $Roles[$roleName]
            $existingAssignments = Get-AzRoleAssignment -Scope $mgmtGroup.Id

            # Assign Groups to Roles
            foreach ($entity in $randomGroups) {
                if (-not ($existingAssignments | Where-Object { $_.RoleDefinitionId -eq $roleId -and $_.ObjectId -eq $entity.Id })) {
                    try {
                        New-AzRoleAssignment -ObjectId $entity.Id -RoleDefinitionId $roleId -Scope $mgmtGroup.Id -ErrorAction SilentlyContinue > $null
                        Write-Log -Message "[GROUP] $($entity.DisplayName) assigned with $roleName at $($mgmtGroup.DisplayName)." -Level "INFO"
                    } catch {
                        Write-Log -Message "[GROUP] Failed to assign $roleName to $($entity.DisplayName) at $($mgmtGroup.DisplayName): $($_.Exception.Message)" -Level "ERROR"
                    }
                }
            }

            # Assign role to users after groups, if not already assigned
            foreach ($user in $randomUsers) {
                if (-not ($existingAssignments | Where-Object { $_.RoleDefinitionId -eq $roleId -and $_.ObjectId -eq $user.Id })) {
                    try {
                        New-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionId $roleId -Scope $mgmtGroup.Id -ErrorAction SilentlyContinue > $null
                        Write-Log -Message "[USER] $($user.UserPrincipalName) assigned with $roleName at $($mgmtGroup.DisplayName)." -Level "INFO"
                    } catch {
                        Write-Log -Message "[USER] Failed to assign $roleName to $($user.UserPrincipalName) at $($mgmtGroup.DisplayName): $($_.Exception.Message)" -Level "ERROR"
                    }
                }
            }
            $roleCount++
        }
    }

    Write-Log -Message "Management Group Role Assignment Complete" -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Backup Role Assignments
function Backup-RoleAssignments {
    $AllAssignments = @()
    $AllMgmtGroups = Get-AzManagementGroup

    foreach ($SingleMgmtGroup in $AllMgmtGroups) {
        $assignments = Get-AzRoleAssignment -Scope $SingleMgmtGroup.Id
        $AllAssignments += $assignments
        Write-Log -Message "Collected assignments for Management Group '$($SingleMgmtGroup.Id)'" -Level "INFO"
    }

    # Sort assignments alphabetically by DisplayName before exporting
    $AllAssignments | Sort-Object -Property DisplayName | 
        Select-Object RoleAssignmentName, RoleAssignmentId, Scope, DisplayName, SignInName, RoleDefinitionName, ObjectId, ObjectType, CanDelegate |
        Export-Csv -Path $backupFilePath -NoTypeInformation -Append

    Write-Log -Message "Management Group Role Assignment Backup Complete. File saved to: $backupFilePath" -Level "IMPORTANT"
    SLEEP 2
    CLS
}

# Function to Clean Management Groups
function Clean-ManagementGroups {
    param (
        [PSCustomObject]$loggedOnUserInfo  # Pass the structured object containing logged-on user details
    )

    if (-not $loggedOnUserInfo -or -not $loggedOnUserInfo.UPN) {
        Write-Log -Message "[ERROR] No logged-on user UPN found. Ensure Connect-Azure has been run." -Level "ERROR"
        return
    }

    $loggedOnUserUPN = $loggedOnUserInfo.UPN

    # Retrieve all Management Groups
    $allManagementGroups = Get-AzManagementGroup
    if ($allManagementGroups.Count -eq 0) {
        Write-Log -Message "No management groups found." -Level "ERROR"
        return
    }

    # Prompt for consent to clean Role Assignments
    $consent = Read-Host -Prompt "Do you wish to start cleaning Role Assignments for Management Groups? (Yes/No)"
    if ($consent -notmatch '^(yes|y)$') {
        Write-Log -Message "Consent not provided for Role Assignment cleanup for Management Groups." -Level "ERROR"
        return
    }

    Write-Log -Message "Consent provided for Role Assignment cleanup for Management Groups." -Level "IMPORTANT"

    foreach ($mg in $allManagementGroups) {
        $mgDisplayName = $mg.DisplayName
        $mgId = $mg.Id

        Write-Log -Message "Starting cleanup for Management Group: $mgDisplayName. Excluding User: $loggedOnUserUPN." -Level "IMPORTANT"

        $uaAssignments = Get-AzRoleAssignment -Scope $mgId | Where-Object {
            $_.RoleDefinitionName -eq "User Access Administrator" -and $_.ObjectType -ne "ServicePrincipal" -and $_.SignInName -ne $loggedOnUserUPN
        }

        foreach ($uaAssignment in $uaAssignments) {
            $displayName = if ($uaAssignment.SignInName) { $uaAssignment.SignInName } else { $uaAssignment.DisplayName }
            $tag = if ($uaAssignment.ObjectType -eq "User") { "[USER]" } elseif ($uaAssignment.ObjectType -eq "Group") { "[GROUP]" } else { "[UNKNOWN]" }

            try {
                Remove-AzRoleAssignment -ObjectId $uaAssignment.ObjectId -RoleDefinitionName "User Access Administrator" -Scope "/" -ErrorAction SilentlyContinue > $null
                
                Write-Log -Message "$tag $displayName removed from Role: User Access Administrator in Management Group: $mgDisplayName." -Level "INFO"
            } catch {
                Write-Log -Message "[ERROR] Failed to remove $tag $displayName from Role: User Access Administrator in Management Group: $mgDisplayName. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }

        $roleAssignments = Get-AzRoleAssignment -Scope $mgId | Where-Object {
            $_.RoleDefinitionName -ne "User Access Administrator" -and $_.ObjectType -ne "ServicePrincipal" -and $_.SignInName -ne $loggedOnUserUPN
        } | Sort-Object -Property RoleDefinitionName

        foreach ($roleAssignment in $roleAssignments) {
            $roleDefinitionName = $roleAssignment.RoleDefinitionName
            $displayName = ""
            $tag = ""

            # Determine object type and tag
            if ($roleAssignment.ObjectType -eq "User") {
                $displayName = $roleAssignment.SignInName
                $tag = "[USER]"
            } elseif ($roleAssignment.ObjectType -eq "Group") {
                $group = Get-AzADGroup -ObjectId $roleAssignment.ObjectId -ErrorAction SilentlyContinue
                $displayName = if ($group) { $group.DisplayName } else { "Unknown Group" }
                $tag = "[GROUP]"
            } else {
                $displayName = if ($roleAssignment.DisplayName) { $roleAssignment.DisplayName } else { "Unknown" }
                $tag = "[UNKNOWN]"
            }

            try {
                Remove-AzRoleAssignment -ObjectId $roleAssignment.ObjectId -RoleDefinitionName $roleDefinitionName -Scope $mgId -ErrorAction SilentlyContinue > $null

                Write-Log -Message "$tag $displayName removed from Role: $roleDefinitionName in Management Group: $mgDisplayName." -Level "INFO"
            } catch {
                Write-Log -Message "[ERROR] Failed to remove $tag $displayName from Role: $roleDefinitionName in Management Group: $mgDisplayName. Error: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    Write-Log -Message "Management Group Role Assignments cleaned." -Level "SOS"
    SLEEP 2
    CLS
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
do {
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "          -" -ForegroundColor Cyan
    Write-Host "Phase 2: Joka - Restore Positive Administrative Control Management Groups."          -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host ""
    Write-Host "Select an option:"
    Write-Host "[1] Create Management Group Role Assignments"
    Write-Host "[2] Backup Management Group Role Assignments"
    Write-Host "[3] Clean Management Group Role Assignments"
    Write-Host "[4] Exit"
    Write-Host ""
    Write-Host "----------------------------------------------------------------------------------"
    $option = Read-Host "Enter your choice"

    switch ($option) {
        "1" { 
            Create-NewRoleAssignments 
            }
        "2" { 
            Backup-RoleAssignments 
            }
        "3" { 
            Clean-ManagementGroups -loggedOnUserInfo $loggedOnUserInfo
            }
        "4" {
           # Exit Microsoft Az Session
            Disconnect-AzAccount > $null

            # Mark The End of the Script
            Write-Log -Message "[SCRIPT] End of Manage_AzureManagementGroupRoleAssignments Script." -Level "SOS"
            SLEEP 2
            CLS
            exit
        }
        default { Write-Log -Message "Invalid option selected." -Level "ERROR" }
    }
} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
