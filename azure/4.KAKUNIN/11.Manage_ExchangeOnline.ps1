<#
.SYNOPSIS
    The PowerShell script manages Exchange Online role assignments, ensuring that the logged-in user remains a member of essential groups before cleanup.

.DESCRIPTION
    - Backup Exchange Online Role Assignments.
    - Add the logged-in user to essential role groups before cleanup.
    - Remove all other role assignments while ensuring critical groups retain at least one administrator.

.NOTES
    Author: NightCityShogun
    Version: 4.6
    Date: 2025-02-07
#>

# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Exchange Management PowerShell Modules
$Modules = @("ExchangeOnlineManagement")

# Regex Patterns for Partner-Managed Role Groups (Dynamically Identified)
$PartnerManagedRolePatterns = @(
    "^ComplianceAdmins_[0-9]{9,10}$",
    "^ExchangeServiceAdmins_[0-9]{9,10}$",
    "^GlobalReaders_-[0-9]{9,10}$",
    "^SecurityAdmins_[0-9]{9,10}$",
    "^TenantAdmins_-[0-9]{9,10}$",
    "^RIM-MailboxAdmins[a-f0-9]{32}$", # RIM-MailboxAdmins with 32-character GUID
    "^View-Only\s+Organization\s+Management$", # Ensures exact match with spaces
    "^Security Administrator$",
    "^Security Reader$"
)

# Define Default Role Groups (These should remain in Exchange Online)
$DefaultRoleGroups = @(
    "Communication Compliance",
    "Communication Compliance Administrators",
    "Compliance Administrator",
    "Compliance Management",
    "Discovery Management",
    "Help Desk",
    "Hygiene Management",
    "Information Protection",
    "Information Protection Admins",
    "Information Protection Analysts",
    "Information Protection Investigators",
    "Information Protection Readers",
    "Insider Risk Management",
    "Insider Risk Management Admins",
    "Insider Risk Management Investigators",
    "Organization Management",
    "Privacy Management",
    "Privacy Management Administrators",
    "Privacy Management Investigators",
    "Recipient Management",
    "Records Management",
    "Security Operator"
)

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Export File Path
$csvFilePath = Join-Path -Path $PSScriptRoot -ChildPath ("Backup_ExchangeRoleAssignments_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

# ------------------------------------------------------------------------------------------------------------------------

# Ensure the NCS Log Directory Exists
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
        $logColor = @{
            "SOS"        = [System.ConsoleColor]::Green
            "ERROR"      = [System.ConsoleColor]::Red
            "INFO"       = [System.ConsoleColor]::White
            "WARNING"    = [System.ConsoleColor]::Yellow
            "IMPORTANT"  = [System.ConsoleColor]::Cyan
        }[$Level]

        Write-Host -ForegroundColor $logColor $logEntry
    }
}

# Start of the Script
Write-Log -Message "[SCRIPT] Start of Manage_ExchangeOnline Script." -Level "SOS"

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

# Modules For Exchange Online
function Initialize-ExchangeOnlineManagement {
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

# Main Script Execution Flow

# Validate x86 Architecture
Check-OSArchitecture > $null

# Validate x86 Architecture
Initialize-ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline -ShowBanner:$false
# Connect to Exchange Online and fetch the logged-in user's UPN (Ensure only one result)
$currentUser = (Get-ConnectionInformation).UserPrincipalName | Select-Object -Unique -First 1

# Display confirmation
Write-Log -Message  "Logged-in User: $currentUser" -Level "SOS"
SLEEP 2
CLS

# ------------------------------------------------------------------------------------------------------------------------

# Function to Backup Role Assignments
function Backup-ExchangeOnlineRoleAssignments {
    Write-Log -Message "Starting Backup of Exchange Online Role Assignments" -Level "SOS"
    
    $roleGroups = Get-RoleGroup | Sort-Object Name
    $output = @()

    foreach ($roleGroup in $roleGroups) {
        Write-Log -Message "Finding members for Role Group: $($roleGroup.Name)" -Level "SOS"
        
        $members = Get-RoleGroupMember -Identity $roleGroup.Identity
        if ($members.Count -eq 0) {
            Write-Log -Message "No members found for Role Group: $($roleGroup.Name)" -Level "WARNING"
        }

        foreach ($member in $members) {
            $output += [PSCustomObject]@{
                RoleGroupName = $roleGroup.Name
                MemberDisplayName = $member.DisplayName
                PrimarySmtpAddress = $member.PrimarySmtpAddress
                RecipientType = $member.RecipientType
                ManagedBy = $roleGroup.ManagedBy
                WhenCreated = $member.WhenCreated
                WhenChanged = $member.WhenChanged
            }
            Write-Log -Message "Member '$($member.DisplayName)' found in $($roleGroup.Name)." -Level "INFO"
        }
    }

    $output | Sort-Object RoleGroupName | Export-Csv -Path $csvFilePath -NoTypeInformation
    Write-Log -Message "Backup for Exchange Online Role Assignments completed." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Remove Role Assignments
function Manage-RoleGroupMemberships {
    Write-Log -Message "Starting role group management..." -Level "SOS"

    # Cache Role Group Members Before Processing
    Write-Log -Message "Caching role group memberships..." -Level "INFO"
    
    $roleGroups = Get-RoleGroup | Sort-Object Name
    $RoleGroupMembersCache = @{}

    foreach ($roleGroup in $roleGroups) {
        try {
            $members = Get-RoleGroupMember -Identity $roleGroup.Identity -ErrorAction Stop
            if ($members.Count -gt 0) {
                $RoleGroupMembersCache[$roleGroup.Name] = @(
                    foreach ($member in $members) {
                        [PSCustomObject]@{
                            RoleGroupName       = $roleGroup.Name
                            MemberDisplayName   = $member.DisplayName
                            PrimarySmtpAddress  = $member.PrimarySmtpAddress
                            RecipientType       = $member.RecipientType
                            ManagedBy           = $roleGroup.ManagedBy
                            WhenCreated         = $member.WhenCreated
                            WhenChanged         = $member.WhenChanged
                        }
                    }
                )
            }
        } catch {
            Write-Log -Message "Failed to retrieve members for '$($roleGroup.Name)': $_" -Level "ERROR"
        }
    }

    Write-Log -Message "Membership caching complete." -Level "INFO"

    # Ensure `$currentUser` is a single value, not an array
    $currentUserUPN = $currentUser | Select-Object -First 1
    $currentUserDisplayName = (Get-User -Identity $currentUserUPN).DisplayName

    # Ensure logged-in user is in 'Organization Management'
    $orgManagementMembers = Get-RoleGroupMember -Identity "Organization Management" | Select-Object -ExpandProperty DisplayName
    if ($currentUserDisplayName -notin $orgManagementMembers) {
        Write-Log -Message "Adding logged-in user ($currentUserDisplayName) to 'Organization Management'" -Level "IMPORTANT"
        try {
            Add-RoleGroupMember -Identity "Organization Management" -Member $currentUserUPN -ErrorAction Stop
        } catch {
            Write-Log -Message "Failed to add user to 'Organization Management': $_" -Level "ERROR"
        }
    }

    # Exclude Partner-Managed Role Groups Before Processing
    $FilteredRoleGroups = @()
    foreach ($roleGroupName in $RoleGroupMembersCache.Keys) {
        if ($PartnerManagedRolePatterns -match $roleGroupName) {
            Write-Log -Message "Skipping partner-managed role group: $roleGroupName" -Level "IMPORTANT"
        } else {
            $FilteredRoleGroups += $roleGroupName
        }
    }

    # Process Default Role Groups
    foreach ($roleGroupName in ($DefaultRoleGroups | Sort-Object)) {
        if ($roleGroupName -in $FilteredRoleGroups) {
            $members = $RoleGroupMembersCache[$roleGroupName]
            Write-Log -Message "Processing role group: $roleGroupName" -Level "INFO"

            foreach ($member in $members) {
                $memberIdentity = if ($member.PrimarySmtpAddress) { 
                    $member.PrimarySmtpAddress 
                } elseif ($member.MemberDisplayName) { 
                    $member.MemberDisplayName 
                } else { 
                    $null 
                }

                if (-not $memberIdentity) { 
                    Write-Log -Message "Skipping member with missing identifiers in '$roleGroupName'" -Level "WARNING"
                    continue
                }

                if ($member.MemberDisplayName -eq $currentUserDisplayName) { 
                    Write-Log -Message "Skipping removal of logged-in user ($currentUserDisplayName) from '$roleGroupName'" -Level "INFO"
                    continue 
                }

                try {
                    Remove-RoleGroupMember -Identity $roleGroupName -Member $memberIdentity -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
                    Write-Log -Message "Removed '$memberIdentity' from '$roleGroupName'" -Level "IMPORTANT"
                } catch {
                    if ($_ -match "does not exist") {
                        Write-Log -Message "Member '$memberIdentity' not found in '$roleGroupName' - Skipping removal." -Level "INFO"
                    } else {
                        Write-Log -Message "Failed to remove '$memberIdentity' from '$roleGroupName': $_" -Level "ERROR"
                    }
                }
            }
        }
    }

    Write-Log -Message "Role group management completed." -Level "SOS"
    SLEEP 2
    CLS
}

# ------------------------------------------------------------------------------------------------------------------------

# Menu Function
do {
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "Phase 4: KAKUNIN - Restore Positive Administrative Control Exchange Online."            -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------------------"
    Write-Host "Select an action:"
    Write-Host "[1] Backup Exchange Online Role Assignments"
    Write-Host "[2] Remove Exchange Online Role Assignments"
    Write-Host "[3] Exit"
    Write-Host ""
    Write-Host "Linked or Partner Role Groups cannot be modified within Exchange Online"
    Write-Host "----------------------------------------------------------------------------------"
    $input = Read-Host "Enter your choice (1-3)"

    switch ($input) {
        "1" {
            Backup-ExchangeOnlineRoleAssignments
        }
        "2" {
            # Directly use the script-level ExcludeRoles parameter
            Manage-RoleGroupMemberships
        }
        "3" {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Log -Message "[SCRIPT] End of Manage_ExchangeOnline Script." -Level "SOS"
            SLEEP 2
            CLS
            exit
        }
        default {
            Write-Host "Invalid option. Please try again."
            SLEEP 2
            CLS
        }
    }
} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
