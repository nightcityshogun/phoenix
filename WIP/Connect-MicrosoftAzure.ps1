function Connect-MicrosoftAzure {
    <#
    .SYNOPSIS
        Acquires a Microsoft Graph access token using OAuth2 (REST only)
    #>
function Connect-MicrosoftAzure {
    <#
    .SYNOPSIS
        Acquires a Microsoft Graph access token using OAuth2 (REST only).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AllowExternalAccessToken,

        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,

        [Parameter(Mandatory = $true, ParameterSetName = 'DeviceCode')]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [string]$ClientId,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [string[]]$Scopes = @(
            "Application.ReadWrite.All",
            "Directory.ReadWrite.All"
        ),

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [string[]]$RequiredScopes,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientSecret')]
        [string]$ClientSecret,

        # FIXED: Optional with fixed default for break-glass scenarios
        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [string]$CertificateThumbprint = "1F7E7C0EECFC36E96FD6CE912DD542BFD53ED5CB",

        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [string]$TenantId = "common",

        [Parameter(Mandatory = $false)]
        [string]$Resource = "https://graph.microsoft.com/.default",

        [Parameter(Mandatory = $false)]
        [switch]$ForceRefresh,

        [Parameter(Mandatory = $false, ParameterSetName = 'DeviceCode')]
        [switch]$NoBrowserLaunch
    )

    $ErrorActionPreference = 'Stop'
}

    function Get-RestErrorText {
        param($ErrorRecord)
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            return $ErrorRecord.ErrorDetails.Message
        }
        $ex = $ErrorRecord.Exception
        if (-not $ex) { return "" }
        $resp = $ex.Response
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

    function Set-TokenGlobals {
        param([string]$Token, [int]$ExpiresInSeconds)
        $global:MicrosoftAzureAccessToken = $Token
        if ($ExpiresInSeconds -gt 0) {
            $global:MicrosoftAzureTokenExpires = (Get-Date).AddSeconds($ExpiresInSeconds - 300)
        } else {
            $global:MicrosoftAzureTokenExpires = (Get-Date).AddMinutes(55)
        }
    }

    function Get-JwtPayload {
        param([Parameter(Mandatory = $true)][string]$Jwt)
        $parts = $Jwt.Split(".")
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace("-", "+").Replace("_", "/")
        switch ($p.Length % 4) {
            2 { $p += "==" }
            3 { $p += "=" }
        }
        try {
            $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
            return ($json | ConvertFrom-Json)
        } catch {
            return $null
        }
    }

    function Get-TokenContext {
        param([Parameter(Mandatory=$true)][string]$Token)
        $payload = Get-JwtPayload -Jwt $Token
        if (-not $payload) { return $null }
        $scp = @()
        if ($payload.scp) { $scp = ($payload.scp -split " ") }
        [pscustomobject]@{
            TenantId = $payload.tid
            UserObjectId = $payload.oid
            Scopes = $scp
            Audience = $payload.aud
            AppId = $payload.appid
        }
    }

    function Assert-DelegatedScopes {
        param([string]$Token, [string[]]$MustHaveScopes)
        if (-not $MustHaveScopes -or $MustHaveScopes.Count -eq 0) { return @() }
        $ctx = Get-TokenContext -Token $Token
        $granted = @()
        if ($ctx -and $ctx.Scopes) { $granted = $ctx.Scopes }
        $missing = @()
        foreach ($s in $MustHaveScopes) {
            if (-not ($granted -contains $s)) { $missing += $s }
        }
        if ($missing.Count -gt 0) {
            throw ("Token missing delegated scopes: " + ($missing -join ", ") +
                   ". This usually means the device-code client id is not admin-consented for those scopes in this tenant.")
        }
        return $granted
    }

    function Get-DeviceCodeScopeString {
        param([string[]]$RequestedScopes)
        $base = @("openid", "profile", "offline_access")
        $clean = @()
        foreach ($s in $RequestedScopes) {
            if (-not $s) { continue }
            $t = $s.Trim()
            if ($t -eq "") { continue }
            if ($t -like "https://graph.microsoft.com/*") {
                $t = $t.Replace("https://graph.microsoft.com/", "")
            }
            $clean += $t
        }
        return (($base + $clean) -join " ")
    }

    function Invoke-DeviceCodeAuth {
        param([string]$Tenant, [string]$Client, [string[]]$ScopeList, [switch]$SkipBrowser)
        $authTenant = if ($Tenant -and $Tenant.Trim() -ne "") { $Tenant } else { "common" }
        $deviceEndpoint = "https://login.microsoftonline.com/$authTenant/oauth2/v2.0/devicecode"
        $tokenEndpoint = "https://login.microsoftonline.com/$authTenant/oauth2/v2.0/token"
        $scopeString = Get-DeviceCodeScopeString -RequestedScopes $ScopeList
        $dcResponse = $null
        try {
            $dcResponse = Invoke-RestMethod -Uri $deviceEndpoint -Method POST -Body @{
                client_id = $Client
                scope = $scopeString
            } -ContentType "application/x-www-form-urlencoded"
        } catch {
            $err = "Device code request failed. " + (Get-RestErrorText $_)
            Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
            throw $err
        }
        Write-IdentIRLog "Open the following URL and enter the code:" -TypeName Info -ForegroundColor Cyan
        Write-IdentIRLog "URL : $($dcResponse.verification_uri)" -TypeName Info -ForegroundColor White
        Write-IdentIRLog "Code: $($dcResponse.user_code)" -TypeName Info -ForegroundColor Yellow
        if (-not $SkipBrowser) {
            try { Start-Process $dcResponse.verification_uri | Out-Null } catch {
                Write-IdentIRLog "Could not auto-open browser. Please open the URL manually." -TypeName Warning -ForegroundColor Yellow
            }
        }
        $interval = if ($dcResponse.interval -gt 0) { $dcResponse.interval } else { 5 }
        while ($true) {
            Start-Sleep -Seconds $interval
            try {
                $tokenResult = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body @{
                    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id = $Client
                    device_code = $dcResponse.device_code
                } -ContentType "application/x-www-form-urlencoded"
                if ($tokenResult.access_token) { return $tokenResult }
            } catch {
                $errText = Get-RestErrorText $_
                $code = $null
                try { $code = ($errText | ConvertFrom-Json).error } catch {}
                if ($code -eq "authorization_pending") { continue }
                if ($code -eq "slow_down") { $interval += 5; continue }
                if ($code -eq "expired_token") {
                    Write-IdentIRLog "Device code expired." -TypeName Error -ForegroundColor Red
                    throw "Device code expired."
                }
                Write-IdentIRLog "Token polling failed: $errText" -TypeName Error -ForegroundColor Red
                throw "Token polling failed. $errText"
            }
        }
    }

    # Cache reuse
    if (-not $ForceRefresh -and $global:MicrosoftAzureAccessToken -and $global:MicrosoftAzureTokenExpires) {
        if ((Get-Date) -lt $global:MicrosoftAzureTokenExpires) {
            if ($PSCmdlet.ParameterSetName -eq 'DeviceCode') {
                $ok = $true
                if ($RequiredScopes -and $RequiredScopes.Count -gt 0) {
                    try { $null = Assert-DelegatedScopes -Token $global:MicrosoftAzureAccessToken -MustHaveScopes $RequiredScopes } catch { $ok = $false }
                }
                if ($ok) {
                    $ctx = Get-TokenContext -Token $global:MicrosoftAzureAccessToken
                    return [pscustomobject]@{
                        AccessToken = $global:MicrosoftAzureAccessToken
                        ExpiresOn = $global:MicrosoftAzureTokenExpires
                        TenantId = $ctx.TenantId
                        UserObjectId = $ctx.UserObjectId
                        Scopes = $ctx.Scopes
                        AuthType = "DeviceCode"
                    }
                }
            } else {
                return [pscustomobject]@{
                    AccessToken = $global:MicrosoftAzureAccessToken
                    ExpiresOn = $global:MicrosoftAzureTokenExpires
                    TenantId = $TenantId
                    UserObjectId = $null
                    Scopes = @()
                    AuthType = $PSCmdlet.ParameterSetName
                }
            }
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'AccessToken' {
            if (-not $AllowExternalAccessToken) {
                throw "External access token injection is disabled. Re-run with -AllowExternalAccessToken if you intend to use it."
            }
            Set-TokenGlobals -Token $AccessToken -ExpiresInSeconds 3600
            $ctx = Get-TokenContext -Token $global:MicrosoftAzureAccessToken
            return [pscustomobject]@{
                AccessToken = $global:MicrosoftAzureAccessToken
                ExpiresOn = $global:MicrosoftAzureTokenExpires
                TenantId = $ctx.TenantId
                UserObjectId = $ctx.UserObjectId
                Scopes = $ctx.Scopes
                AuthType = "ExternalAccessToken"
            }
        }
        'DeviceCode' {
            if (-not $ClientId -or $ClientId.Trim() -eq "") {
                $ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
            }
            Write-IdentIRLog "Authenticating with device code flow..." -TypeName Info -ForegroundColor Cyan
            $result = Invoke-DeviceCodeAuth -Tenant $TenantId -Client $ClientId -ScopeList $Scopes -SkipBrowser:$NoBrowserLaunch
            Set-TokenGlobals -Token $result.access_token -ExpiresInSeconds $result.expires_in
            $granted = @()
            if ($RequiredScopes -and $RequiredScopes.Count -gt 0) {
                $granted = Assert-DelegatedScopes -Token $global:MicrosoftAzureAccessToken -MustHaveScopes $RequiredScopes
            } else {
                $ctxTmp = Get-TokenContext -Token $global:MicrosoftAzureAccessToken
                $granted = $ctxTmp.Scopes
            }
            $ctx = Get-TokenContext -Token $global:MicrosoftAzureAccessToken
            Write-IdentIRLog "Device code authentication successful." -TypeName Info -ForegroundColor Green
            return [pscustomobject]@{
                AccessToken = $global:MicrosoftAzureAccessToken
                ExpiresOn = $global:MicrosoftAzureTokenExpires
                TenantId = $ctx.TenantId
                UserObjectId = $ctx.UserObjectId
                Scopes = $granted
                AuthType = "DeviceCode"
            }
        }
        'ClientSecret' {
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            try {
                $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body @{
                    client_id = $ClientId
                    client_secret = $ClientSecret
                    scope = $Resource
                    grant_type = "client_credentials"
                } -ContentType "application/x-www-form-urlencoded"
                Set-TokenGlobals -Token $tokenResponse.access_token -ExpiresInSeconds $tokenResponse.expires_in
                Write-IdentIRLog "Client secret authentication successful." -TypeName Info -ForegroundColor Green
                return [pscustomobject]@{
                    AccessToken = $global:MicrosoftAzureAccessToken
                    ExpiresOn = $global:MicrosoftAzureTokenExpires
                    TenantId = $TenantId
                    UserObjectId = $null
                    Scopes = @()
                    AuthType = "ClientSecret"
                }
            } catch {
                $err = "Client secret authentication failed. " + (Get-RestErrorText $_)
                Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
                throw $err
            }
        }
        'Certificate' {
            $cert = Get-ChildItem "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) {
                $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
            }
            if (-not $cert) {
                $err = "Certificate with thumbprint '$CertificateThumbprint' not found in CurrentUser or LocalMachine store."
                Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
                throw $err
            }
            Write-IdentIRLog "Authenticating using certificate thumbprint: $CertificateThumbprint" -TypeName Info -ForegroundColor Cyan
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $now = [DateTime]::UtcNow
            $epoch = [DateTime]'1970-01-01T00:00:00Z'
            $nbf = [int]($now - $epoch).TotalSeconds
            $exp = [int]($now.AddMinutes(5) - $epoch).TotalSeconds
            $header = @{ alg="RS256"; typ="JWT"; x5t=[Convert]::ToBase64String($cert.GetCertHash()) } | ConvertTo-Json -Compress
            $payload = @{
                aud=$tokenEndpoint
                iss=$ClientId
                sub=$ClientId
                jti=[Guid]::NewGuid().ToString()
                nbf=$nbf
                exp=$exp
            } | ConvertTo-Json -Compress
            $h64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $p64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $data = "$h64.$p64"
            $rsa = $cert.GetRSAPrivateKey()
            if (-not $rsa) {
                $err = "Certificate does not have an RSA private key."
                Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
                throw $err
            }
            $sig = $rsa.SignData(
                [Text.Encoding]::UTF8.GetBytes($data),
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $jwt = "$data.$([Convert]::ToBase64String($sig).TrimEnd('=').Replace('+','-').Replace('/','_'))"
            try {
                $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body @{
                    client_id = $ClientId
                    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    client_assertion = $jwt
                    scope = $Resource
                    grant_type = "client_credentials"
                } -ContentType "application/x-www-form-urlencoded"
                Set-TokenGlobals -Token $tokenResponse.access_token -ExpiresInSeconds $tokenResponse.expires_in
                Write-IdentIRLog "Certificate authentication successful." -TypeName Info -ForegroundColor Green
                return [pscustomobject]@{
                    AccessToken = $global:MicrosoftAzureAccessToken
                    ExpiresOn = $global:MicrosoftAzureTokenExpires
                    TenantId = $TenantId
                    UserObjectId = $null
                    Scopes = @()
                    AuthType = "Certificate"
                }
            } catch {
                $err = "Certificate authentication failed. " + (Get-RestErrorText $_)
                Write-IdentIRLog $err -TypeName Error -ForegroundColor Red
                throw $err
            }
        }
    }
}
