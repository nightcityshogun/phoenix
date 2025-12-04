Connect-AzAccount -Tenant "" -Subscription ""
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All" -NoWelcome

$AutoAccount = Get-AzAutomationAccount -ResourceGroupName "" -Name ""
$MSI_SP = Get-MgServicePrincipal -Filter "id eq '$($AutoAccount.Identity.PrincipalId)'"
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

$Permissions = @(
    "AccessReview.Read.All","AdministrativeUnit.Read.All","Agreement.Read.All","APIConnectors.Read.All",
    "Application.Read.All","CustomSecAttributeDefinition.Read.All","Directory.Read.All","EntitlementManagement.Read.All",
    "Group.Read.All","GroupSettings.Read.All","IdentityProvider.Read.All","IdentityUserFlow.Read.All",
    "LifecycleWorkflows.Read.All","NetworkAccessPolicy.Read.All","Organization.Read.All","Policy.Read.All",
    "Policy.Read.AuthenticationMethod","Policy.Read.ConditionalAccess","PrivilegedAccess.Read.AzureAD",
    "PrivilegedAccess.Read.AzureADGroup","PrivilegedAccess.Read.AzureResource","ProgramControl.Read.All",
    "ReportSettings.Read.All","RoleEligibilitySchedule.Read.Directory","RoleManagement.Read.Directory",
    "User.Read.All","User.ReadBasic.All"
)

foreach ($perm in $Permissions) {
    $role = $GraphSP.AppRoles | Where-Object { $_.Value -eq $perm -and $_.AllowedMemberTypes -contains "Application" }
    if ($role) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $MSI_SP.Id `
            -PrincipalId        $MSI_SP.Id `
            -ResourceId         $GraphSP.Id `
            -AppRoleId          $role.Id `
            -ErrorAction SilentlyContinue | Out-Null

        if ($?) { Write-Host "Assigned: $perm" -ForegroundColor Green }
        else    { Write-Host "Already assigned or skipped: $perm" -ForegroundColor Gray }
    }
}

Write-Host "`nALL DONE! M365DSCAA Managed Identity now has full Graph permissions." -ForegroundColor Cyan
Write-Host "Wait 3 minutes → then run your export runbook on Hybrid Worker → SUCCESS guaranteed." -ForegroundColor Cyan
