function New-ServicePrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName = "phoenix",
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificatePath,
        [Parameter(Mandatory = $false)]
        [SecureString]$CertificatePassword,
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$DeviceCodeClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e",  # Microsoft Graph PowerShell public client – works without prior consent
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $oldConfirm = $ConfirmPreference
    $ConfirmPreference = 'None'

    Write-IdentIRLog "Starting New-ServicePrincipal – DisplayName: $DisplayName" -TypeName Info -ForegroundColor Cyan

    $graphResourceAppId = "00000003-0000-0000-c000-000000000000"
    $graphBase = "https://graph.microsoft.com/v1.0"
    $orgEndpoint = "$graphBase/organization"
    $appEndpoint = "$graphBase/applications"
    $spEndpoint = "$graphBase/servicePrincipals"
    $spGraphQuery = "$graphBase/servicePrincipals?`$filter=appId eq '$graphResourceAppId'"

    $bootstrapScopes = @(
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All"
    )

    $appRequiredPermissions = @(
        "Application.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "Group.Read.All",
        "GroupMember.Read.All",
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
        "PrivilegedAccess.Read.AzureADGroup",
        "User.Read.All"
    )

    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        $err = "Certificate not found at path: $CertificatePath"
        Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
        throw $err
    }

    function Get-GraphRestErrorText {
        param($ErrorRecord)
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { return $ErrorRecord.ErrorDetails.Message }
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return "" }
        try { if ($resp.Content) { return $resp.Content.ReadAsStringAsync().Result } } catch {}
        try {
            $stream = $resp.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $text = $reader.ReadToEnd()
                $reader.Close()
                return $text
            }
        } catch {}
        return ""
    }

    function Invoke-GraphRest {
        param(
            [Parameter(Mandatory = $true)][string]$Uri,
            [Parameter(Mandatory = $false)][ValidateSet("GET","POST","PATCH","PUT","DELETE")][string]$Method = "GET",
            [Parameter(Mandatory = $true)][hashtable]$Headers,
            [Parameter(Mandatory = $false)][object]$Body
        )
        try {
            $params = @{
                Uri = $Uri
                Method = $Method
                Headers = $Headers
                ErrorAction = "Stop"
            }
            if ($null -ne $Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 12)
                $params.ContentType = "application/json"
            }
            Invoke-RestMethod @params
        }
        catch {
            $errText = Get-GraphRestErrorText $_
            $fullErr = "Graph REST call failed. Uri: {0}. Details: {1}" -f $Uri, $errText
            Write-IdentIRLog $fullErr -TypeName Error -ForegroundColor Red
            throw $fullErr
        }
    }

    function New-ODataFilterUri {
        param(
            [Parameter(Mandatory = $true)][string]$BaseUri,
            [Parameter(Mandatory = $true)][string]$Filter
        )
        return ($BaseUri + "?`$filter=" + [System.Uri]::EscapeDataString($Filter))
    }

    function Read-CertificateForUpload {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $false)][SecureString]$Password
        )
        $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
        if ($ext -eq ".cer") {
            Write-IdentIRLog "Using .cer for upload. Keep the .pfx private/installed for later authentication." -TypeName Info -ForegroundColor Cyan
            return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path))
        }
        if ($ext -eq ".pfx") {
            Write-IdentIRLog "You provided a .pfx. Only the public bytes are uploaded. Prefer .cer for upload." -TypeName Warning -ForegroundColor Yellow
            if ($Password) { return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path, $Password)) }
            return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path))
        }
        $err = "Unsupported certificate extension '$ext'. Use .cer (preferred) or .pfx."
        Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
        throw $err
    }

    try {
        # Delegated auth
        Write-IdentIRLog "Performing delegated authentication (device code flow)..." -TypeName Info

        if ($TenantId -and $TenantId.Trim() -ne "") {
            $delegatedAuth = Connect-MicrosoftAzure -UseDeviceCode -ClientId $DeviceCodeClientId -TenantId $TenantId -Scopes $bootstrapScopes -RequiredScopes $bootstrapScopes
        } else {
            $delegatedAuth = Connect-MicrosoftAzure -UseDeviceCode -ClientId $DeviceCodeClientId -Scopes $bootstrapScopes -RequiredScopes $bootstrapScopes
        }

        if (-not $delegatedAuth -or -not $delegatedAuth.AccessToken) {
            throw "Delegated authentication failed (no AccessToken returned)."
        }

        Write-IdentIRLog "Device code authentication successful." -TypeName Info -ForegroundColor Green
        $delegatedHeaders = @{ Authorization = "Bearer $($delegatedAuth.AccessToken)" }

        # Resolve tenant id
        $resolvedTenantId = $delegatedAuth.TenantId
        if (-not $resolvedTenantId -or $resolvedTenantId -eq "common") {
            $tenantInfo = Invoke-GraphRest -Uri $orgEndpoint -Headers $delegatedHeaders
            $resolvedTenantId = $tenantInfo.value[0].id
        }
        Write-IdentIRLog "Resolved TenantId: $resolvedTenantId" -TypeName Info

        # Load Graph SP
        $graphSP = Invoke-GraphRest -Uri $spGraphQuery -Headers $delegatedHeaders
        if (-not $graphSP.value -or $graphSP.value.Count -eq 0) {
            throw "Microsoft Graph service principal not found for appId $graphResourceAppId."
        }
        $graphSpObject = $graphSP.value[0]
        $graphSpId = $graphSpObject.id

        # Resolve permissions
        $resourceAccess = @()
        $roleAssignments = @{}
        foreach ($permission in $appRequiredPermissions) {
            $role = $graphSpObject.appRoles | Where-Object { $_.value -eq $permission -and $_.isEnabled -eq $true }
            if ($role) {
                $resourceAccess += @{ id = $role.id; type = "Role" }
                $roleAssignments[$permission] = $role.id
            }
            else { Write-IdentIRLog "Permission not found/disabled in Graph SP: $permission" -TypeName Warning -ForegroundColor Yellow }
        }
        if ($resourceAccess.Count -eq 0) {
            throw "No Graph application permissions could be resolved for requiredResourceAccess."
        }

        # 2) Create or reuse application
        $safeName = $DisplayName.Replace("'", "''")
        $existingUri = New-ODataFilterUri -BaseUri $appEndpoint -Filter ("displayName eq '$safeName'")
        $existing = Invoke-GraphRest -Uri $existingUri -Headers $delegatedHeaders
        $app = $null
        $reused = $false
        if ($existing.value -and $existing.value.Count -gt 0) {
            if (-not $Force) {
                Write-IdentIRLog "An application with displayName '$DisplayName' already exists. Re-run with -Force to reuse it." -TypeName Warning -ForegroundColor Yellow
                Write-IdentIRLog "To update the existing app, re-run with -Force." -TypeName Info -ForegroundColor White
                Write-IdentIRLog "Example: New-ServicePrincipal -CertificatePath '$CertificatePath' -Force" -TypeName Info -ForegroundColor Gray
                return
            }
            $app = $existing.value[0]
            $reused = $true
            Invoke-GraphRest -Uri "$appEndpoint/$($app.id)" -Method PATCH -Headers $delegatedHeaders -Body @{
                requiredResourceAccess = @(@{
                    resourceAppId = $graphResourceAppId
                    resourceAccess = $resourceAccess
                })
            } | Out-Null
            Write-IdentIRLog "Reusing existing application: $($app.displayName) (appId=$($app.appId))" -TypeName Info -ForegroundColor Green
        }
        else {
            $app = Invoke-GraphRest -Uri $appEndpoint -Method POST -Headers $delegatedHeaders -Body @{
                displayName = $DisplayName
                signInAudience = "AzureADMyOrg"
                requiredResourceAccess = @(@{
                    resourceAppId = $graphResourceAppId
                    resourceAccess = $resourceAccess
                })
            }
            Write-IdentIRLog "Application created: $($app.displayName) (appId=$($app.appId))" -TypeName Info -ForegroundColor Green
        }
        if (-not $app -or -not $app.appId -or -not $app.id) {
            throw "Application object missing required identifiers (appId/id)."
        }

        # 3) Ensure service principal exists
        $spQueryUri = New-ODataFilterUri -BaseUri $spEndpoint -Filter ("appId eq '$($app.appId)'")
        $spQuery = Invoke-GraphRest -Uri $spQueryUri -Headers $delegatedHeaders
        $sp = $null
        if ($spQuery.value -and $spQuery.value.Count -gt 0) {
            $sp = $spQuery.value[0]
            Write-IdentIRLog "Reusing existing service principal (objectId=$($sp.id))" -TypeName Info
        }
        else {
            $sp = Invoke-GraphRest -Uri $spEndpoint -Method POST -Headers $delegatedHeaders -Body @{ appId = $app.appId }
            Write-IdentIRLog "Service principal created (objectId=$($sp.id))" -TypeName Info -ForegroundColor Green
        }
        if (-not $sp -or -not $sp.id) { throw "Service principal objectId not available." }

        # Grant admin consent (programmatic)
        Write-IdentIRLog "Granting admin consent for permissions..." -TypeName Info -ForegroundColor Cyan
        foreach ($permission in $appRequiredPermissions) {
            $appRoleId = $roleAssignments[$permission]
            if ($appRoleId) {
                try {
                    Invoke-GraphRest -Uri "$spEndpoint/$($sp.id)/appRoleAssignments" -Method POST -Headers $delegatedHeaders -Body @{
                        principalId = $sp.id
                        resourceId = $graphSpId
                        appRoleId = $appRoleId
                    } | Out-Null
                    Write-IdentIRLog "Granted permission: $permission" -TypeName Info -ForegroundColor Green
                } catch {
                    Write-IdentIRLog "Failed to grant $permission (manual consent may be needed)." -TypeName Warning -ForegroundColor Yellow
                }
            }
        }

        # 7) Upload certificate using Update (PATCH) endpoint
        $cert = Read-CertificateForUpload -Path $CertificatePath -Password $CertificatePassword
        $certRawB64 = [Convert]::ToBase64String($cert.GetRawCertData())

        # Fetch current app to get existing keyCredentials
        $currentApp = Invoke-GraphRest -Uri "$appEndpoint/$($app.id)" -Headers $delegatedHeaders
        $existingKeys = $currentApp.keyCredentials
        if ($reused -and $existingKeys.Count -gt 0) {
            Write-IdentIRLog "Appending to existing key credentials on the app." -TypeName Info -ForegroundColor Cyan
        } else {
            $existingKeys = @()
        }

        $newKey = @{
            type = "AsymmetricX509Cert"
            usage = "Verify"
            key = $certRawB64
            displayName = "phoenix-" + $cert.Thumbprint
            startDateTime = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            endDateTime = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }

        $updatedKeys = $existingKeys + $newKey

        # Patch the app with updated keyCredentials
        Invoke-GraphRest -Uri "$appEndpoint/$($app.id)" -Method PATCH -Headers $delegatedHeaders -Body @{
            keyCredentials = $updatedKeys
        } | Out-Null

        Write-IdentIRLog "Certificate credential added. Thumbprint: $($cert.Thumbprint)" -TypeName Info -ForegroundColor Green

        $consentUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.appId)/isMSAApp~/false"
        Write-IdentIRLog "Admin consent / permissions URL (if programmatic grant failed):" -TypeName Info -ForegroundColor Cyan
        Write-IdentIRLog $consentUrl -TypeName Info -ForegroundColor White
        Write-IdentIRLog "Connection information:" -TypeName Info -ForegroundColor Cyan
        Write-IdentIRLog "TenantId : $resolvedTenantId" -TypeName Info -ForegroundColor White
        Write-IdentIRLog "ClientId : $($app.appId)" -TypeName Info -ForegroundColor White
        Write-IdentIRLog "Thumbprint : $($cert.Thumbprint)" -TypeName Info -ForegroundColor White
        Write-IdentIRLog "Service principal creation completed successfully." -TypeName Info -ForegroundColor Green

        return [PSCustomObject]@{
            DisplayName    = $app.displayName
            ApplicationId  = $app.appId
            ObjectId       = $sp.id
            TenantId       = $resolvedTenantId
            CertThumbprint = $cert.Thumbprint
            CertNotBefore  = $cert.NotBefore
            CertNotAfter   = $cert.NotAfter
            Permissions    = $appRequiredPermissions
            ConsentUrl     = $consentUrl
            ReusedExisting = $reused
        }
    }
    catch {
        Write-IdentIRLog "Failed to create certificate-based service principal: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
        throw $_
    }
    finally {
        $ConfirmPreference = $oldConfirm
    }
}
