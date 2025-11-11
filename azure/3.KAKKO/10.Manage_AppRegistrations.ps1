<#
.SYNOPSIS
    Extracts App Registrations in Microsoft Entra ID for review of API Risky API permissions, Exports Names and Expiration Data of Secrets and Certificates, and Deletes an Application by ID as specified by the operator.

.DESCRIPTION
    This script connects to Azure, requests operator consent, and provides options to:
    - Creates dummy App Registrations with 'risky permissions' to support a Lab or test scenario.
    - Exports a list of App Registrations that have been assigned 'risky permissions' that could lead to Business Email Compromise (BEC) or Persistence.
    - Removes the 'owner' for ALL identified App Registrations with 'risky permissions' to mitigate possible persistence related issues.
    - Deletes a risky App Registration from the Microsoft Entra ID tenant.

.PARAMETER NULL
    There are no supported parameters

.NOTES
    Author: NightCityShogun
    Name: Manage_AppRegistrations
    Version: 3.8
    Date: 2023-06-15
#>

# ------------------------------------------------------------------------------------------------------------------------

# Microsoft Graph PowerShell Modules
$modules = @(
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Reports",
    "Microsoft.Graph.Users"
)

# Scopes for Microsoft Graph connection
$Scopes = @("AuditLog.Read.All",
"Directory.Read.All", 
"Directory.ReadWrite.All", 
"Group.ReadWrite.All", 
"RoleEligibilitySchedule.ReadWrite.Directory", 
"RoleManagement.Read.All", 
"RoleManagement.ReadWrite.Directory",
"User.ReadBasic.All", 
"User.Read.All")

# Microsoft Graph Environment Options
$validEnvironments = @("China", "Global", "USGov", "USGovDoD")

# Microsoft Graph App Permissions Considered Risky ####
$Permissions = @{
    Application = @{
        "1dfe531a-24a6-4f1b-80f4-7a0dc5a0a171" = "APIConnectors.ReadWrite.All" # Allows the app to read, create and manage the API connectors used in user authentication flows, without a signed-in user.
        "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" = "Application.Read.All" # Allows the app to read all applications and service principals without a signed-in user.
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All" # Allows the app to create, read, update and delete applications and service principals without a signed-in user. Does not allow management of consent grants.
        "18a4783c-866b-4cc7-a460-3d5e5662c884" = "Application.ReadWrite.OwnedBy" # Allows the app to create other applications, and fully manage those applications (read, update, update application secrets and delete), without a signed-in user.  It cannot update any apps that it is not an owner of.
        "3be0012a-cc4e-426b-895b-f9c836bf6381" = "Application-RemoteDesktopConfig.ReadWrite.All" # Allows the app to read and write the remote desktop security configuration for all apps in your organization, without a signed-in user.
        "089fe4d0-434a-44c5-8827-41ba8a0b17f5" = "Contacts.Read" # Allows the app to read all contacts in all mailboxes without a signed-in user.
        "6918b873-d17a-4dc1-b314-35f528134491" = "Contacts.ReadWrite" # Allows the app to create, read, update, and delete all contacts in all mailboxes without a signed-in user.
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61" = "Directory.Read.All" # Allows the app to read data in your organization's directory, such as users, groups and apps, without a signed-in user.
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All" # Allows the app to read and write data in your organization's directory, such as users, and groups, without a signed-in user. Does not allow user or group deletion.
        "f20584af-9290-4153-9280-ff8bb2c0ea7f" = "Directory.Write.Restricted" # Allows the app to manage restricted resources based on the other permissions granted to the app, without a signed-in user.
        "dbb9058a-0e50-45d7-ae91-66909b5d4664" = "Domain.Read.All" # Allows the app to read all domain properties without a signed-in user.
        "7e05723c-0bb0-42da-be95-ae9f08a6e53c" = "Domain.ReadWrite.All" # Allows the app to read and write all domain properties without a signed in user.  Also allows the app to add,  verify and remove domains.
        "d1808e82-ce13-47af-ae0d-f9b254e6d58a" = "EduRoster.ReadWrite.All" # Allows the app to read and write the structure of schools and classes in the organization's roster and education-specific information about all users to be read and written.
        "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "Files.Read.All" # Allows the app to read all files in all site collections without a signed in user.
        "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All" # Allows the app to read, create, update and delete all files in all site collections without a signed in user.
        "62a82d76-70ea-41e2-9197-370581804d09" = "Group.ReadWrite.All" # Allows the app to create groups, read all group properties and memberships, update group properties and memberships, and delete groups. Also allows the app to read and write conversations. All of these operations can be performed by the app without a signed-in user.
        "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" = "GroupMember.ReadWrite.All" #  	Allows the app to list groups, read basic properties, read and update the membership of the groups this app has access to without a signed-in user. Group properties and owners cannot be updated and groups cannot be deleted. 
        "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read" # Allows the app to read mail in all mailboxes without a signed-in user.
        "693c5e45-0940-467d-9b8a-1022fb9d42ef" = "Mail.ReadBasic.All" # Allows the app to read basic mail properties in all mailboxes without a signed-in user. Includes all properties except body, previewBody, attachments and any extended properties.
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite" # Allows the app to create, read, update, and delete mail in all mailboxes without a signed-in user. Does not include permission to send mail.
        "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Mail.Send" # Allows the app to send mail as any user without a signed-in user.
        "40f97065-369a-49f4-947c-6a255697ae91" = "MailboxSettings.Read" # Allows the app to read user's mailbox settings without a signed-in user. Does not include permission to send mail.
        "6931bccd-447a-43d1-b442-00a195474933" = "MailboxSettings.ReadWrite" # Allows the app to create, read, update, and delete user's mailbox settings without a signed-in user. Does not include permission to send mail.
        "658aa5d8-239f-45c4-aa12-864f4fc7e490" = "Member.Read.Hidden" # Allows the app to read the memberships of hidden groups and administrative units without a signed-in user.
        "3aeca27b-ee3a-4c2b-8ded-80376e2134a4" = "Notes.Read.All" # Allows the app to read all the OneNote notebooks in your organization, without a signed-in user.
        "0c458cef-11f3-48c2-a568-c66751c238c0" = "Notes.ReadWrite.All" # Allows the app to read all the OneNote notebooks in your organization, without a signed-in user.
        "b528084d-ad10-4598-8b93-929746b4d7d6" = "People.Read.All" # Allows the app to read any user's scored list of relevant people, without a signed-in user. The list can include local contacts, contacts from social networking, your organization's directory, and people from recent communications (such as email and Skype).
        "ef02f2e7-e22d-4c77-8614-8f765683b86e" = "PeopleSettings.Read.All" # Allows the application to read tenant-wide people settings without a signed-in user.
        "b6890674-9dd5-4e42-bb15-5af07f541ae1" = "PeopleSettings.ReadWrite.All" # Allows the application to read and write tenant-wide people settings without a signed-in user.
        "a402ca1c-2696-4531-972d-6e5ee4aa11ea" = "Policy.ReadWrite.PermissionGrant" # Allows the app to manage policies related to consent and permission grants for applications, without a signed-in user.
        "29c18626-4985-4dcd-85c0-193eef327366" = "Policy.ReadWrite.AuthenticationMethod" # Allows the app to read and write all authentication method policies for the tenant, without a signed-in user. 
        "37730810-e9ba-4e46-b07e-8ca78d182097" = "Policy.Read.ConditionalAccess" # Allows the app to read your organization's conditional access policies, without a signed-in user.
        "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "Policy.ReadWrite.ConditionalAccess" # Allows the app to read and write your organization's conditional access policies, without a signed-in user.
        "854d9ab1-6657-4ec8-be45-823027bcd009" = "PrivilegedAccess.ReadWrite.AzureAD" # Allows the app to request and manage time-based assignment and just-in-time elevation (including scheduled elevation) of Azure AD built-in and custom administrative roles in your organization, without a signed-in user..
        "dd199f4a-f148-40a4-a2ec-f0069cc799ec" = "RoleAssignmentSchedule.ReadWrite.Directory" # Allows the app to read, update, and delete policies for privileged role-based access control (RBAC) assignments of your company's directory, without a signed-in user.
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory" # Allows the app to read and manage the role-based access control (RBAC) settings for your company's directory, without a signed-in user. This includes instantiating directory roles and managing directory role membership, and reading directory role templates, directory roles and memberships.
        "fee28b28-e1f3-4841-818e-2704dc62245f" = "RoleEligibilitySchedule.ReadWrite.Directory" # Allows the app to read and manage the eligible role-based access control (RBAC) assignments and schedules for your company's directory, without a signed-in user. This includes managing eligible directory role membership, and reading directory role templates, directory roles and eligible memberships.
        "09850681-111b-4a89-9bed-3f2cae46d706" = "User.Invite.All" # Allows the app to invite guest users to the organization, without a signed-in user.
        "c529cfca-c91b-489c-af2b-d92990b66ce6" = "User.ManageIdentities.All" # Allows the app to read, update and delete identities that are associated with a user's account, without a signed in user. This controls the identities users can sign-in with.
        "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All" # Allows the app to read and update user profiles without a signed in user.
        # Add more application permissions as needed
    }
    Delegated = @{
        "c67b52c5-7c69-48b6-9d48-7b3af3ded914" = "APIConnectors.ReadWrite.All" # Allows the app to read, create and manage the API connectors used in user authentication flows, on behalf of the signed-in user.
        "c79f8feb-a9db-4090-85f9-90d820caa0eb" = "Application.Read.All" # Allows the app to read applications and service principals on behalf of the signed-in user.
        "bdfbf15f-ee85-4955-8675-146e8e5296b5" = "Application.ReadWrite.All" # Allows the app to create, read, update and delete applications and service principals on behalf of the signed-in user. Does not allow management of consent grants. 
        "ff74d97f-43af-4b68-9f2a-b77ee6968c5d" = "Contacts.Read" # Allows the app to read user contacts.
        "242b9d9e-ed24-4d09-9a52-f43769beb9d4" = "Contacts.Read.Shared" # Allows the app to read contacts a user has permissions to access, including their own and shared contacts.
        "d56682ec-c09e-4743-aaf4-1a3aac4caa21" = "Contacts.ReadWrite" # Allows the app to create, read, update, and delete user contacts
        "afb6c84b-06be-49af-80bb-8f3f77004eab" = "Contacts.ReadWrite.Shared" # Allows the app to create, read, update, and delete contacts a user has permissions to, including their own and shared contacts.
        "06da0dbc-49e2-44d2-8312-53f166ab848a" = "Directory.Read.All" # Allows the app to read data in your organization's directory, such as users, groups and apps.
        "c5366453-9fb0-48a5-a156-24f0c49a4b84" = "Directory.ReadWrite.All" # Allows the app to read and write data in your organization's directory, such as users, and groups. It does not allow the app to delete users or groups, or reset user passwords.
        "cba5390f-ed6a-4b7f-b657-0efc2210ed20" = "Directory.Write.Restricted" # Allows the app to manage restricted resources based on the other permissions granted to the app, on behalf of the signed-in user.
        "2f9ee017-59c1-4f1d-9472-bd5529a7b311" = "Domain.Read.All" # Allows the app to read all domain properties on behalf of the signed-in user.
        "0b5d694c-a244-4bde-86e6-eb5cd07730fe" = "Domain.ReadWrite.All" # Allows the app to read and write all domain properties on behalf of the signed-in user. Also allows the app to add, verify and remove domains.
        "0e263e50-5827-48a4-b97c-d940288653c7" = "Directory.AccessAsUser.All" # Allows the app to have the same access to information in the directory as the signed-in user.
        "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0" = "Email" # Allows the app to read your users' primary email address
        "10465720-29dd-4523-a11a-6a75c743c9d9" = "Files.Read" # Allows the app to read the signed-in user's files.
        "df85f4d6-205c-4ac5-a5ea-6bf408dba283" = "Files.Read.All" # Allows the app to read all files the signed-in user can access.
        "5447fe39-cb82-4c1a-b977-520e67e724eb" = "Files.Read.Selected" # (Preview) Allows the app to read files that the user selects. The app has access for several hours after the user selects a file.
        "5c28f0bf-8a70-41f1-8ab2-9032436ddb65" = "Files.ReadWrite" # Allows the app to read, create, update and delete the signed-in user's files.
        "863451e7-0667-486c-a5d6-d135439485f0" = "Files.ReadWrite.All" # Allows the app to read, create, update and delete all files the signed-in user can access.
        "8019c312-3263-48e6-825e-2b833497195b" = "Files.ReadWrite.AppFolder" # (Preview) Allows the app to read, create, update and delete files in the application's folder.
        "17dde5bd-8c17-420f-a486-969730c1b827" = "Files.ReadWrite.Selected" # (Preview) Allows the app to read and write files that the user selects. The app has access for several hours after the user selects a file.
        "4e46008b-f24c-477d-8fff-7bb4ec7aafe0" = "Group.ReadWrite.All" # Allows the app to create groups and read all group properties and memberships on behalf of the signed-in user. Additionally allows group owners to manage their groups and allows group members to update group content.
        "f81125ac-d3b7-4573-a3b2-7099cc39df9e" = "GroupMember.ReadWrite.All" # Allows the app to list groups, read basic properties, read and update the membership of the groups the signed-in user has access to. Group properties and owners cannot be updated and groups cannot be deleted.
        "570282fd-fa5c-430d-a7fd-fc8dc98a9dca" = "Mail.Read" # Allows the app to read the signed-in user's mailbox.
        "7b9103a5-4610-446b-9670-80643382c1fa" = "Mail.Read.Shared" # Allows the app to read mail a user can access, including their own and shared mail.
        "b11fa0e7-fdb7-4dc9-b1f1-59facd463480" = "Mail.ReadBasic.Shared" # Allows the app to read mail the signed-in user can access, including their own and shared mail, except for body, bodyPreview, uniqueBody, attachments, extensions, and any extended properties.
        "024d486e-b451-40bb-833d-3e66d98c5c73" = "Mail.ReadWrite" # Allows the app to create, read, update, and delete email in user mailboxes. Does not include permission to send mail.
        "5df07973-7d5d-46ed-9847-1271055cbd51" = "Mail.ReadWrite.Shared" # Allows the app to create, read, update, and delete mail a user has permission to access, including their own and shared mail. Does not include permission to send mail.
        "e383f46e-2787-4529-855e-0e479a3ffac0" = "Mail.Send" # Allows the app to send mail as users in the organization.
        "a367ab51-6b49-43bf-a716-a1fb06d2a174" = "Mail.Send.Shared" # Allows the app to send mail as the signed-in user, including sending on-behalf of others.
        "87f447af-9fa4-4c32-9dfa-4a57a73d18ce" = "MailboxSettings.Read" # Allows the app to the read user's mailbox settings. Does not include permission to send mail.
        "818c620a-27a9-40bd-a6a5-d96f7d610b4b" = "MailboxSettings.ReadWrite" # Allows the app to create, read, update, and delete user's mailbox settings. Does not include permission to send mail.
        "f6a3db3e-f7e8-4ed2-a414-557c8c9830be" = "Member.Read.Hidden" # Allows the app to read the memberships of hidden groups and administrative units on behalf of the signed-in user, for those hidden groups and administrative units that the signed-in user has access to.
        "9d822255-d64d-4b7a-afdb-833b9a97ed02" = "Notes.Create" # Allows the app to read the titles of OneNote notebooks and sections and to create new pages, notebooks, and sections on behalf of the signed-in user.
        "371361e4-b9e2-4a3f-8315-2a301a3b0a3d" = "Notes.Read" # Allows the app to read OneNote notebooks on behalf of the signed-in user.
        "dfabfca6-ee36-4db2-8208-7a28381419b3" = "Notes.Read.All" # Allows the app to read OneNote notebooks that the signed-in user has access to in the organization.
        "615e26af-c38a-4150-ae3e-c3b0d4cb1d6a" = "Notes.ReadWrite" # Allows the app to read, share, and modify OneNote notebooks on behalf of the signed-in user.
        "64ac0503-b4fa-45d9-b544-71a463f05da0" = "Notes.ReadWrite.All" # Allows the app to read, share, and modify OneNote notebooks that the signed-in user has access to in the organization.
        "ed68249d-017c-4df5-9113-e684c7f8760b" = "Notes.ReadWrite.CreatedByApp" # This is deprecated! Do not use! This permission no longer has any effect. You can safely consent to it. No additional privileges will be granted to the app.
        "7427e0e9-2fba-42fe-b0c0-848c9e6a8182" = "offline_access" # Allows the app to see and update the data you gave it access to, even when users are not currently using the app. This does not give the app any additional permissions.
        "37f7f235-527c-4136-accd-4a02d197296e" = "openid" # Allows users to sign in to the app with their work or school accounts and allows the app to see basic user profile information.
        "ba47897c-39ec-4d83-8086-ee8256fa737d" = "People.Read"  # Allows the app to read a ranked list of relevant people of the signed-in user. The list includes local contacts, contacts from social networking, your organization's directory, and people from recent communications (such as email and Skype).
        "b89f9189-71a5-4e70-b041-9887f0bc7e4a" = "People.Read.All" # Allows the app to read a scored list of relevant people of the signed-in user or other users in the signed-in user's organization. The list can include local contacts, contacts from social networking, your organization's directory, and people from recent communications (such as email and Skype).
        "ec762c5f-388b-4b16-8693-ac1efbc611bc" = "PeopleSettings.Read.All" # Allows the application to read tenant-wide people settings on behalf of the signed-in user.
        "e67e6727-c080-415e-b521-e3f35d5248e9" = "PeopleSettings.ReadWrite.All" # Allows the application to read and write tenant-wide people settings on behalf of the signed-in user.
        "2672f8bb-fd5e-42e0-85e1-ec764dd2614e" = "Policy.ReadWrite.PermissionGrant" # Allows the app to manage policies related to consent and permission grants for applications, on behalf of the signed-in user.
        "7e823077-d88e-468f-a337-e18f1f0e6c7c" = "Policy.ReadWrite.AuthenticationMethod" # Allows the app to read and write the authentication method policies, on behalf of the signed-in user. 
        "633e0fce-8c58-4cfb-9495-12bbd5a24f7c" = "Policy.Read.ConditionalAccess" # Allows the app to read your organization's conditional access policies on behalf of the signed-in user.
        "ad902697-1014-4ef5-81ef-2b4301988e8c" = "Policy.ReadWrite.ConditionalAccess" # Allows the app to read and write your organization's conditional access policies on behalf of the signed-in user.
        "3c3c74f5-cdaa-4a97-b7e0-4e788bfcfb37" = "PrivilegedAccess.ReadWrite.AzureAD" # Allows the app to request and manage just in time elevation (including scheduled elevation) of users to Azure AD built-in administrative roles, on behalf of signed-in users.
        "14dad69e-099b-42c9-810b-d002981feec1" = "profile" # Allows the app to see your users' basic profile (e.g., name, picture, user name, email address)
        "8c026be3-8e26-4774-9372-8d5d6f21daff" = "RoleAssignmentSchedule.ReadWrite.Directory" # Allows the app to read and manage the active role-based access control (RBAC) assignments for your company's directory, on behalf of the signed-in user. This includes managing active directory role membership, and reading directory role templates, directory roles and active memberships.
        "62ade113-f8e0-4bf9-a6ba-5acb31db32fd" = "RoleEligibilitySchedule.ReadWrite.Directory" # Allows the app to read and manage the eligible role-based access control (RBAC) assignments for your company's directory, on behalf of the signed-in user. This includes managing eligible directory role membership, and reading directory role templates, directory roles and eligible memberships. 
        "d01b97e9-cbc0-49fe-810a-750afd5527a3" = "RoleManagement.ReadWrite.Directory" # Allows the app to read and manage the role-based access control (RBAC) settings for your company's directory, on behalf of the signed-in user. This includes instantiating directory roles and managing directory role membership, and reading directory role templates, directory roles and memberships. 
        "63dd7cd9-b489-4adf-a28c-ac38b9a0f962" = "User.Invite.All" # Allows the app to invite guest users to the organization, on behalf of the signed-in user
        "637d7bec-b31e-4deb-acc9-24275642a2c9" = "User.ManageIdentities.All" # Allows the app to read, update and delete identities that are associated with a user's account that the signed-in user has access to. This controls the identities users can sign-in with.
        "204e0828-b5ca-4ad8-b9f3-f32a958e7cc4" = "User.ReadWrite.All" # Allows the app to read and write the full set of profile properties, reports, and managers of other users in your organization, on behalf of the signed-in user.
        # Add more delegated permissions as needed
    }
}

# Feudal Locations for Secret Name Generation
$feudalLocations = @("Kyoto", 
"Edo", 
"Osaka", 
"Nara", 
"Kamakura", 
"Himeji")

# Application Names for Creation
$appNames = @("Kuranosuke", 
"Horibe", 
"Kanroku", 
"Goemon", 
"Hazama", 
"Nobunaga")

# NCS Log File Path
$logDirectory = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Temp\NCS"
$logFilePath = Join-Path -Path $logDirectory -ChildPath ("NCS_Log_" + (Get-Date -Format "yyyyMMdd") + ".log")

# Define Data Export Directory
$exportDirectory = $PSScriptRoot 

# Export File Path
$permissionsExportPath = Join-Path -Path $exportDirectory -ChildPath ("Manage_AppPermissions_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")

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
Write-Log -Message "[SCRIPT] Start of Manage_AppRegistrations Script." -Level "SOS"

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

# Function to Get the Latest App Permissions File
function Get-LatestAppPermissionsFile {
    param (
        [string]$directoryPath
    )

    # Retrieve the latest file dynamically
    $latestFile = Get-ChildItem -Path $directoryPath -Filter "Manage_AppPermissions_*.csv" |
        Where-Object { -not $_.PSIsContainer } |  # Exclude directories
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    return $latestFile
}

# Function to Create Risky Applications
function Create-Applications {
    try {
        # Fetching 5 random users
        $randomUsers = Get-MgUser | Get-Random -Count 5

        $appsCreated = $false

        foreach ($name in $appNames) {
            # Use the predefined app name
            $appName = "App-" + $name

            # Check if the app already exists
            $existingApp = Get-MgApplication -Filter "displayName eq '$appName'"

            if ($existingApp) {
                Write-Log -Message "[APP] '$appName' already exists in the tenant. Skipping creation..." -Level "INFO"
                continue
            }

            # Create the app registration
            $appRegistration = New-MgApplication -BodyParameter @{
                displayName = $appName
            }

            # Define unique permissions for each application (Application Permissions)
            $selectedAppPermissions = @(
                "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30", # Application.Read.All
                "dbb9058a-0e50-45d7-ae91-66909b5d4664", # Domain.Read.All
                "d1808e82-ce13-47af-ae0d-f9b254e6d58a", # EduRoster.ReadWrite.All
                "62a82d76-70ea-41e2-9197-370581804d09", # Group.ReadWrite.All
                "658aa5d8-239f-45c4-aa12-864f4fc7e490", # Member.Read.Hidden
                "09850681-111b-4a89-9bed-3f2cae46d706"  # User.Invite.All
            ) | Get-Random -Count (Get-Random -Minimum 2 -Maximum 4) | Get-Unique

            # Placeholder for Delegated permissions (adjust as necessary)
            $selectedDelegatedPermissions = @(
                "0b5d694c-a244-4bde-86e6-eb5cd07730fe", # Domain.ReadWrite.All
                "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0", # Email
                "0e263e50-5827-48a4-b97c-d940288653c7", # Directory.AccessAsUser.All
                "0b5d694c-a244-4bde-86e6-eb5cd07730fe", # Domain.ReadWrite.All (Duplicate, consider removing)
                "371361e4-b9e2-4a3f-8315-2a301a3b0a3d", # Notes.Read
                "37f7f235-527c-4136-accd-4a02d197296e"  # openid
            ) | Get-Random -Count (Get-Random -Minimum 2 -Maximum 4) | Get-Unique

            # Create a single entry for the Microsoft Graph resource with all selected permissions
            $resourceAccessList = @()

            # Add Application permissions
            foreach ($appId in $selectedAppPermissions) {
                $resourceAccessList += @{
                    Id = $appId
                    Type = "Role"
                }
            }

            # Add Delegated permissions
            foreach ($scopeId in $selectedDelegatedPermissions) {
                $resourceAccessList += @{
                    Id = $scopeId
                    Type = "Scope"
                }
            }

            # Combine into a single entry for the requiredResourceAccess
            $requiredResourceAccess = @(
                @{
                    ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph resource ID
                    ResourceAccess = $resourceAccessList
                }
            )

            # Update the app registration with the combined permissions
            Update-MgApplication -ApplicationId $appRegistration.Id -RequiredResourceAccess $requiredResourceAccess

            Write-Log -Message "[APP] '$appName' created in Microsoft Entra ID." -Level "INFO"

            # Add a random user as owner
            $randomUser = $randomUsers | Get-Random
            $ownerId = $randomUser.Id
            $ownerRef = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$ownerId"
            }
            New-MgApplicationOwnerByRef -ApplicationId $appRegistration.Id -BodyParameter $ownerRef

            # Generate a random secret name using locations
            $secretName = "Secret-" + ($feudalLocations | Get-Random)

            # Add a client secret with the generated secret name
            $passwordCred = @{
                displayName = $secretName
                endDateTime = (Get-Date).AddMonths(12)
            }
            $ClientSecret = Add-MgApplicationPassword -ApplicationId $appRegistration.Id -PasswordCredential $passwordCred

            $appsCreated = $true
        }

        # If no apps were created, exit the function
        if (-not $appsCreated) {
            Write-Log -Message "All apps already exist in the tenant. No new apps created." -Level "IMPORTANT"
            SLEEP 2
            CLS
        }
    }
    catch {
        Write-Log -Message "An error occurred: $_" -Level "ERROR"
    }
    SLEEP 2
    CLS
}

# Function to Get Risky App Registrations
function Get-AppRegistrations {
    Write-Log -Message "Starting to Enumerate Risky Applications in the Tenant. Please Remain Patient" -Level "INFO"

    # Retrieve and Cache Applications
    $Applications = Get-MgApplication | Sort-Object DisplayName

    # Exit if no applications exist
    if (-not $Applications) {
        Write-Log -Message "No applications found. Exiting." -Level "ERROR"
        Exit
    }

    # Identify Risky Applications
    $riskyApps = @()
    foreach ($app in $Applications) {
        $riskyPermissionsApp = @()
        $riskyPermissionsDelegated = @()

        foreach ($access in $app.RequiredResourceAccess) {
            foreach ($resAccess in $access.ResourceAccess) {
                $permType = if ($resAccess.Type -eq "Role") { "Application" } else { "Delegated" }
                $normalizedScope = $resAccess.Id.Trim()

                if ($Permissions[$permType] -and $Permissions[$permType].ContainsKey($normalizedScope)) {
                    if ($permType -eq "Application") {
                        $riskyPermissionsApp += $Permissions[$permType][$normalizedScope]
                    } else {
                        $riskyPermissionsDelegated += $Permissions[$permType][$normalizedScope]
                    }
                }
            }
        }

        # If risky permissions exist, store the app for further processing
        if ($riskyPermissionsApp -or $riskyPermissionsDelegated) {
            $riskyApps += [PSCustomObject]@{
                Application         = $app
                RiskyPermsApp       = $riskyPermissionsApp
                RiskyPermsDelegated = $riskyPermissionsDelegated
            }
        }
    }

    # If no risky apps, exit early
    if (-not $riskyApps) {
        Write-Log -Message "[APP] No Risky App Registrations found." -Level "INFO"
        SLEEP 2
        CLS
        Exit
    }

    Write-Log -Message "[APP] Found $($riskyApps.Count) Risky Applications. Gathering Additional Data..." -Level "INFO"

    # Retrieve Additional Lookups (Only for Risky Apps)
    $servicePrincipals = Get-MgServicePrincipal | Select-Object AppId, Id
    $oauthGrants = Get-MgOauth2PermissionGrant | Select-Object ClientId, ConsentType, Scope
    $results = @()

    foreach ($entry in $riskyApps) {
        $app = $entry.Application
        $riskyPermissionsApp = $entry.RiskyPermsApp
        $riskyPermissionsDelegated = $entry.RiskyPermsDelegated
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id
        $ownerNames = ($owners | ForEach-Object { (Get-MgUser -UserId $_.Id).DisplayName }) -join ', '

        # Check if Service Principal Exists
        $spId = ($servicePrincipals | Where-Object { $_.AppId -eq $app.AppId }).Id
        $hasServicePrincipal = if ($spId) { "Yes" } else { "No" }

        # Retrieve Consent Type
        $appGrants = $oauthGrants | Where-Object { $_.ClientId -eq $spId }
        $consentType = if ($appGrants) {
            ($appGrants | Select-Object -Unique ConsentType).ConsentType -join ", "
        } else { "" }

        # Retrieve Sign-in Data
        $signInLogs = Get-MgAuditLogSignIn -Filter "appId eq '$($app.AppId)'" -Top 1 | Sort-Object CreatedDateTime -Descending
        $lastSignInEntry = $signInLogs | Select-Object -First 1

        $signInDetails = [PSCustomObject]@{
            LastSignIn             = if ($lastSignInEntry) { $lastSignInEntry.CreatedDateTime } else { "" }
            ClientAppUsed          = if ($lastSignInEntry) { $lastSignInEntry.ClientAppUsed } else { "" }
            IPAddress              = if ($lastSignInEntry) { $lastSignInEntry.IPAddress } else { "" }
            IsInteractive          = if ($lastSignInEntry) { $lastSignInEntry.IsInteractive } else { "" }
            Location               = if ($lastSignInEntry -and $lastSignInEntry.Location) {
                                        "$($lastSignInEntry.Location.City), $($lastSignInEntry.Location.State), $($lastSignInEntry.Location.CountryOrRegion)"
                                    } else { "" }
            UserPrincipalName      = if ($lastSignInEntry) { $lastSignInEntry.UserPrincipalName } else { "" }
            ConditionalAccessStatus = if ($lastSignInEntry) { $lastSignInEntry.ConditionalAccessStatus } else { "" }
            ResourceDisplayName    = if ($lastSignInEntry) { $lastSignInEntry.ResourceDisplayName } else { "" }
        }

        # Retrieve Secrets & Certificates
        $AppCreds = Get-MgApplication -ApplicationId $app.Id
        $Secrets = $AppCreds.PasswordCredentials
        $Certs = $AppCreds.KeyCredentials

        $secretDetails = ($Secrets | ForEach-Object { "$($_.DisplayName) [Start: $($_.StartDateTime), End: $($_.EndDateTime)]" }) -join " | "
        $certDetails = ($Certs | ForEach-Object { "$($_.DisplayName) [Start: $($_.StartDateTime), End: $($_.EndDateTime)]" }) -join " | "

        # Store Final Data
        $results += [PSCustomObject]@{
            'ApplicationName'         = $app.DisplayName
            'ApplicationID'           = $app.Id
            'ServicePrincipal'        = $hasServicePrincipal
            'UserPrincipalName'       = $signInDetails.UserPrincipalName
            'LastSignIn'              = $signInDetails.LastSignIn
            'ClientAppUsed'           = $signInDetails.ClientAppUsed
            'Location'                = $signInDetails.Location
            'IPAddress'               = $signInDetails.IPAddress
            'IsInteractive'           = $signInDetails.IsInteractive
            'ConditionalAccessStatus' = $signInDetails.ConditionalAccessStatus
            'ResourceDisplayName'     = $signInDetails.ResourceDisplayName
            'ApplicationPermissions'  = ($riskyPermissionsApp -join ", ")  
            'DelegatedPerissions    ' = ($riskyPermissionsDelegated -join ", ")  
            'ConsentType'             = $consentType
            'Secrets'                 = $secretDetails  
            'Certificates'            = $certDetails  
        }
    }

    # Export Results
    if ($results) {
        try {
            $results | Export-Csv -Path $permissionsExportPath -NoTypeInformation -Force
            Write-Log -Message "[APP] Risky App Registrations Exported to $permissionsExportPath." -Level "INFO"
            SLEEP 2
            CLS

            # Ensure the file is completely written before continuing
            $fileReady = $false
            while (-not $fileReady) {
                try {
                    $stream = [System.IO.File]::Open($permissionsExportPath, 'Open', 'Read')
                    $stream.Close()
                    $fileReady = $true
                } catch {
                    Write-Log -Message "Waiting for the export file to be available..." -Level "WARNING"
                    SLEEP 2
                }
            }
        } catch {
            Write-Log -Message "[ERROR] Failed to export results: $_" -Level "ERROR"
            SLEEP 2
            CLS

        }
    }
}

# Function to Remove All Application Owners
function Remove-AllAppOwners {
    Write-Log -Message "Starting to remove all owners from all applications in the tenant." -Level "SOS"

    # Retrieve all Applications in the tenant
    $applications = Get-MgApplication

    # Check if there are no applications, if true, exit the script
    if ($applications.Count -eq 0) {
        Write-Log -Message "[APP] No applications found in the tenant. Exiting script." -Level "INFO"
        Exit
    }

    foreach ($app in $applications) {
        # Log information about the application being processed
        Write-Log -Message "[APP] Processing: $($app.DisplayName) (ID: $($app.Id))" -Level "INFO"

        # Retrieve all owners of the current application
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id

        # Check if the application has no owners and skip if true
        if ($owners.Count -eq 0) {
            Write-Log -Message "[APP] No owners found for $($app.DisplayName) (ID: $($app.Id)). Skipping..." -Level "INFO"
            Continue
        }

        foreach ($owner in $owners) {
            try {
                # Attempt to remove each owner from the application
                Remove-MgApplicationOwnerByRef -ApplicationId $app.Id -DirectoryObjectId $owner.Id > $null
                # Log successful removal
                Write-Log -Message "[APP] Successfully removed (ID: $($owner.Id)) from application $($app.DisplayName)" -Level "IMPORTANT"
            }
            catch {
                # Log failure to remove owner
                Write-Log -Message "[APP] Failed to remove owner (ID: $($owner.Id)) from application $($app.DisplayName): $_" -Level "ERROR"
            }
        }
    }

    Write-Log -Message "[APP] Removal complete." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Delete a single Risky App Registration by ID
function Delete-Application {
    # Prompt for Application ID
    Write-Log -Message "Start App Deletion." -Level "SOS"
    $ApplicationId = Read-Host "Please enter the Application Object ID you want to Delete"
    
    # Check if Application Exists
    $existingApp = Get-MgApplication -ApplicationId $ApplicationId -ErrorAction SilentlyContinue
    if ($existingApp -eq $null) {
        Write-Log -Message "[APP] Application with ID $ApplicationId does not Exist in the Tenant." -Level "WARNING"
        Write-Log -Message "[APP] Finished App Deletion." -Level "SOS"
        SLEEP 2
        CLS
        return
    }

    # Consent Validation
    $confirmation = Read-Host "Are you sure you want to Delete this App Registration? (Yes/No)"
    if ($confirmation -notmatch '^(yes|y|Yes|Y)$') {
        Write-Log -Message "[APP] Deletion Cancelled. Exiting to Menu." -Level "INFO"
        SLEEP 2
        CLS
        return
    }

    try {
        # Attempt to Delete the App Registration
        Remove-MgApplication -ApplicationId $ApplicationId -ErrorAction Stop
        Write-Log -Message "[APP] Application with ID $ApplicationId has been successfully deleted." -Level "IMPORTANT"
        
    } catch {
        Write-Log -Message "[APP] Failed to Delete the App Registration. Error: $_" -Level "ERROR"
    }

    Write-Log -Message "[APP] Finished App Deletion." -Level "SOS"
    SLEEP 2
    CLS
}

# Function to Delete Multiple Risky App Registrations by ID
function Delete-Applications {
    Write-Log -Message "Starting Multiple Deletion of App Registrations from CSV." -Level "SOS"

    Start-Sleep -Seconds 3

    # Get the latest CSV file dynamically before deletion
    $latestFile = Get-LatestAppPermissionsFile -directoryPath $PSScriptRoot

    # Check if the CSV file exists
    if (-not $latestFile) {
        Write-Log -Message "[APP] No CSV File Found. Exiting." -Level "ERROR"
        Start-Sleep -Seconds 2
        Clear-Host
        return
    }

    Write-Log -Message "[APP] Importing App Registrations from $($latestFile.FullName)" -Level "INFO"

    # Import the CSV and ensure it correctly references 'ApplicationID'
    try {
        $appList = Import-Csv -Path $latestFile.FullName | Select-Object -Unique -Property ApplicationID
    } catch {
        Write-Log -Message "[APP] Error Importing CSV: $_" -Level "ERROR"
        Start-Sleep -Seconds 2
        Clear-Host
        return
    }

    # Check if there are App Registrations in CSV
    if (-not $appList -or $appList.Count -eq 0) {
        Write-Log -Message "[APP] No App Registrations found in CSV." -Level "INFO"
        Start-Sleep -Seconds 2
        Clear-Host
        return
    }

    # Consent Validation
    $confirmation = Read-Host "Are you sure you want to delete these App Registrations? (Yes/No)"
    if ($confirmation -notmatch '^(yes|y|Yes|Y)$') {
        Write-Log -Message "[APP] Deletion Cancelled. Exiting to Menu." -Level "INFO"
        Start-Sleep -Seconds 2
        Clear-Host
        return
    }

    # Iterate through each ApplicationID in the CSV
    foreach ($app in $appList) {
        $appId = $app.ApplicationID  # Correctly using the ApplicationID column

        # Check if Application Exists
        $existingApp = Get-MgApplication -ApplicationId $appId -ErrorAction SilentlyContinue
        if (-not $existingApp) {
            Write-Log -Message "[APP] Application with ID $appId does not exist in the Tenant. Skipping." -Level "WARNING"
            continue
        }

        try {
            Write-Log -Message "[APP] Attempting to Delete App Registration: $appId" -Level "WARNING"
            
            # Attempt deletion of application
            Remove-MgApplication -ApplicationId $appId -ErrorAction Stop
            Write-Log -Message "[APP] Successfully Deleted App Registration: $appId" -Level "IMPORTANT"
            
        } catch {
            Write-Log -Message "[APP] Failed to Delete App Registration: $appId. Error: $_" -Level "ERROR"
        }
    }

    Write-Log -Message "[APP] Finished Multiple App Deletion." -Level "SOS"
    Start-Sleep -Seconds 2
    Clear-Host
}

# Menu Function
do {
    # Display the menu options directly within the loop
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host "Phase 3: KAKKO - Restore Positive Administrative Control App Registrations."            -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------------------"
    Write-Host ""
    Write-Host "Menu Options:"
    Write-Host "[1] Create Ronin Applications"
    Write-Host "[2] Export All App Registrations to csv"
    Write-Host "[3] Remove Owner(s) from all App Registrations apps in the Tenant"
    Write-Host "[4] Delete an App Registration"
    Write-Host "[5] Delete Multiple App Registrations"
    Write-Host "[6] Exit"
    Write-Host "--------------------------------------------------------------------------------------"

    $choice = Read-Host -Prompt "Enter your choice"
    
    switch ($choice) {
        "1" {
            Create-Applications
        }
        "2" {
            Get-AppRegistrations
        }
        "3" {
            Remove-AllAppOwners
        }
        "4" {
            Delete-Application
        }
        "5" {
            Delete-Applications
          }
        "6" {
            # Exit Microsoft Graph Session
            Disconnect-MSGraph > $Null

            # Mark The End of the Script
            Write-Log -Message "[SCRIPT] End of Manage_AppRegistrations Script." -Level "SOS"
            SLEEP 2
            CLS
            exit
        }
        default {
            Write-Host "Invalid choice. Please enter a valid option."
        }
    }
} while ($true)

# ------------------------------------------------------------------------------------------------------------------------

# (C) NightCityShogun 2024
