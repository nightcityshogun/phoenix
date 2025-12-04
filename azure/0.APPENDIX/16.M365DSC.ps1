<#
.SYNOPSIS
    Exports Microsoft 365 configuration using Microsoft365DSC with Managed Identity.

.DESCRIPTION
    This script connects to a specified Azure Storage Account and exports selected
    Microsoft 365 workloads using Microsoft365DSC. It supports
    granular selection of Azure AD components while defaulting to export all
    available components for the chosen workload(s).

.PARAMETER TenantId
    The Microsoft 365 tenant ID or primary domain name
    (for example: contoso.onmicrosoft.com).

.PARAMETER StorageAccountName
    The name of the Azure Storage Account that will store the exported JSON
    configuration files.

.PARAMETER ContainerName
    The name of the blob container within the specified Storage Account used
    to store the exported configuration.

.PARAMETER Mode
    Specifies the export mode.
    Valid values: 'Default', 'Full'
    Default     : 'Default'

.PARAMETER Workloads
    Specifies which Microsoft 365 workloads to export.
    Valid values: 'AAD', 'ADO', 'AZURE', 'COMMERCE', 'DEFENDER', 'EXO',
                  'FABRIC', 'INTUNE', 'O365', 'OD', 'PLANNER', 'PP', 'SC',
                  'SENTINEL', 'SH', 'SPO', 'TEAMS'
    Default     : 'AAD'

.PARAMETER Components
    Specifies the components of a workload to run. For the AAD workload, this
    corresponds to individual Azure AD / Entra ID configuration areas.
    By default, all available components are selected.

    Examples of valid components include:
        AADActivityBasedTimeoutPolicy
        AADAdministrativeUnit
        AADApplication
        AADAttributeSet
        AADUser
    (See the ValidateSet on $Components for the full list.)

.NOTES
    Author  : NightCityShogun
    Version : 1.0.0
    Date    : 2025-11-30
#>


[CmdletBinding()]
param(
    [ValidatePattern('^[\w\-]+\@[\w\-]+\.\w{2,}$')]
    [string] $TenantId = "",
    [ValidateNotNullOrEmpty()]
    [string] $StorageAccountName = "",
    [ValidateNotNullOrEmpty()]
    [string] $ContainerName = "",
    [ValidateSet("Default", "Full")]
    [string] $Mode = "Default",
    [ValidateSet("AAD", "ADO", "AZURE", "COMMERCE", "DEFENDER", "EXO", "FABRIC", "INTUNE", "O365", "OD", "PLANNER", "PP", "SC", "SENTINEL", "SH", "SPO", "TEAMS")]
    [string[]] $Workloads = @("AAD"),
    [ValidateSet(
        "AADActivityBasedTimeoutPolicy",
        "AADAdministrativeUnit",
        "AADApplication",
        "AADAttributeSet",
        "AADAuthenticationFlowPolicy",
        "AADAuthenticationMethodPolicy",
        "AADAuthenticationMethodPolicyAuthenticator",
        "AADAuthenticationMethodPolicyEmail",
        "AADAuthenticationMethodPolicyFido2",
        "AADAuthenticationMethodPolicySms",
        "AADAuthenticationMethodPolicySoftware",
        "AADAuthenticationMethodPolicyTemporary",
        "AADAuthenticationMethodPolicyVoice",
        "AADAuthenticationMethodPolicyX509",
        "AADAuthenticationStrengthPolicy",
        "AADAuthorizationPolicy",
        "AADConditionalAccessPolicy",
        "AADCrossTenantAccessPolicy",
        "AADCrossTenantAccessPolicyConfigurationDefault",
        "AADCrossTenantAccessPolicyConfigurationPartner",
        "AADEntitlementManagementAccessPackage",
        "AADEntitlementManagementAccessPackageAssignmentPolicy",
        "AADEntitlementManagementAccessPackageCatalog",
        "AADEntitlementManagementAccessPackageCatalogResource",
        "AADEntitlementManagementConnectedOrganization",
        "AADEntitlementManagementRoleAssignment",
        "AADExternalIdentityPolicy",
        "AADGroup",
        "AADGroupLifecyclePolicy",
        "AADGroupsNamingPolicy",
        "AADGroupsSettings",
        "AADNamedLocationPolicy",
        "AADRoleDefinition",
        "AADRoleEligibilityScheduleRequest",
        "AADRoleSetting",
        "AADSecurityDefaults",
        "AADServicePrincipal",
        "AADSocialIdentityProvider",
        "AADTenantDetails",
        "AADTokenLifetimePolicy",
        "AADUser"
    )]
    [string[]] $Components = @(
        "AADActivityBasedTimeoutPolicy",
        "AADAdministrativeUnit",
        "AADApplication",
        "AADAttributeSet",
        "AADAuthenticationFlowPolicy",
        "AADAuthenticationMethodPolicy",
        "AADAuthenticationMethodPolicyAuthenticator",
        "AADAuthenticationMethodPolicyEmail",
        "AADAuthenticationMethodPolicyFido2",
        "AADAuthenticationMethodPolicySms",
        "AADAuthenticationMethodPolicySoftware",
        "AADAuthenticationMethodPolicyTemporary",
        "AADAuthenticationMethodPolicyVoice",
        "AADAuthenticationMethodPolicyX509",
        "AADAuthenticationStrengthPolicy",
        "AADAuthorizationPolicy",
        "AADConditionalAccessPolicy",
        "AADCrossTenantAccessPolicy",
        "AADCrossTenantAccessPolicyConfigurationDefault",
        "AADCrossTenantAccessPolicyConfigurationPartner",
        "AADEntitlementManagementAccessPackage",
        "AADEntitlementManagementAccessPackageAssignmentPolicy",
        "AADEntitlementManagementAccessPackageCatalog",
        "AADEntitlementManagementAccessPackageCatalogResource",
        "AADEntitlementManagementConnectedOrganization",
        "AADEntitlementManagementRoleAssignment",
        "AADExternalIdentityPolicy",
        "AADGroup",
        "AADGroupLifecyclePolicy",
        "AADGroupsNamingPolicy",
        "AADGroupsSettings",
        "AADNamedLocationPolicy",
        "AADRoleDefinition",
        "AADRoleEligibilityScheduleRequest",
        "AADRoleSetting",
        "AADSecurityDefaults",
        "AADServicePrincipal",
        "AADSocialIdentityProvider",
        "AADTenantDetails",
        "AADTokenLifetimePolicy",
        "AADUser"
    )
)

$ErrorActionPreference = "Stop"

Write-Host "M365DSC Export Started" -ForegroundColor Cyan
Write-Host "Tenant      : $TenantId"
Write-Host "Workloads   : $($Workloads -join ', ')"
Write-Host "Mode        : $Mode"
Write-Host "Storage     : $StorageAccountName/$ContainerName"
Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

try {
    Import-Module PSDesiredStateConfiguration -ErrorAction Stop
    Write-Host "PSDesiredStateConfiguration loaded" -ForegroundColor Green

    Import-Module Microsoft365DSC -Force -ErrorAction Stop
    Write-Host "Microsoft365DSC loaded" -ForegroundColor Green
} catch {
    Write-Error "Module loading failed: $_"
    exit 1
}

try {
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
} catch {
    Write-Error "Authentication or context creation failed: $_"
    exit 1
}

$ts   = Get-Date -Format "yyyyMMdd-HHmmss"
$path = Join-Path $env:TEMP "M365DSC_$ts"

try {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
} catch {
    Write-Error "Failed to create export directory: $_"
    exit 1
}

Write-Host "Exporting configuration using Managed Identity..." -ForegroundColor Yellow

try {
    $exportParams = @{
        TenantId        = $TenantId
        ManagedIdentity = $true
#       Workloads       = $Workloads
        Components      = $Components
        Mode            = $Mode
        Path            = $path
        FileName        = "M365DSC-Export-$ts.ps1"
    }
    Export-M365DSCConfiguration @exportParams | Out-Null
} catch {
    Write-Error "Export failed: $_"
    exit 1
}

Write-Host "Export completed!" -ForegroundColor Green

$errLog = Get-ChildItem -Path $path -Filter '*ErrorLog.log' -ErrorAction SilentlyContinue
if ($errLog) {
    Write-Host "Microsoft365DSC reported errors. Error log content:" -ForegroundColor Red
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Get-Content $errLog.FullName | Write-Host
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
}

Get-ChildItem $path | Where-Object Name -NotLike "*.partial.ps1" | ForEach-Object {
    $blob = "$ts-$($_.Name)"
    try {
        Set-AzStorageBlobContent -File $_.FullName -Container $ContainerName -Blob $blob -Context $ctx -Force | Out-Null
        Write-Host "Uploaded: $blob" -ForegroundColor Green
    } catch {
        Write-Host "Failed to upload $($_.FullName): $_" -ForegroundColor Red
    }
}

Write-Host "SUCCESS! Files at https://$StorageAccountName.blob.core.windows.net/$ContainerName/" -ForegroundColor Cyan
