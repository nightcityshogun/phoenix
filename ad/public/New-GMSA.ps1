<#
.SYNOPSIS
    Creates diverse gMSA accounts demonstrating ALL available properties.
.DESCRIPTION
    This script creates gMSA accounts using every possible parameter from New-ADServiceAccount
    to provide maximum diversity and examples for all configuration options.
.NOTES
    Requirements:
    - Run as Domain Admin
    - Active Directory PowerShell module
    - KDS Root Key must exist
    - Windows Server 2012+
#>
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

# Environment Configuration - Auto-detected
$DomainDNS = $null
$DomainDN = $null
$PDC = $null
$gMSAOU = $null

# Comprehensive gMSA configurations using ALL available parameters
$gMSAConfigs = @(
    # Config 1: Maximum properties
    @{
        Name = "gmsa-Full-Featured"
        DNSHostName = "gmsa-Full-Featured.contoso.com"
        DisplayName = "Full Featured gMSA Account"
        Description = "Demonstrates maximum property usage"
        SamAccountName = "gmsa-Full`$"
        Enabled = $true
        HomePage = "https://full-featured.contoso.com"
        ServicePrincipalNames = @(
            "HTTP/full-featured.contoso.com"
            "HTTP/full-featured"
            "HOST/full-featured.contoso.com"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-FullFeatured")
        PrincipalsAllowedToDelegateToAccount = @("Group-FullFeatured")
        KerberosEncryptionType = "AES256"
        TrustedForDelegation = $false
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 30
    },
    # Config 2: Outbound-only with minimal properties
    @{
        Name = "gmsa-Outbound-Client"
        DisplayName = "Outbound Only Client Service"
        Description = "Client-side outbound authentication only - no DNSHostName needed"
        SamAccountName = "gmsa-Outbound`$"
        Enabled = $true
        RestrictToOutboundAuthenticationOnly = $true
        KerberosEncryptionType = "AES256,AES128"
        AccountNotDelegated = $true
    },
    # Config 3: SQL Server with multiple SPNs and expiration
    @{
        Name = "gmsa-SQL-TimeLimit"
        DNSHostName = "gmsa-SQL-TimeLimit.contoso.com"
        DisplayName = "Time-Limited SQL Server Account"
        Description = "SQL Server gMSA with account expiration for temporary projects"
        SamAccountName = "gmsa-SQLTime`$"
        Enabled = $true
        ServicePrincipalNames = @(
            "MSSQLSvc/sqltemp.contoso.com"
            "MSSQLSvc/sqltemp.contoso.com:1433"
            "MSSQLSvc/sqltemp"
            "MSSQLSvc/sqltemp:1433"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-SQL")
        PrincipalsAllowedToDelegateToAccount = @("Group-SQL")
        KerberosEncryptionType = "AES256,AES128"
        TrustedForDelegation = $false
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 60
        AccountExpirationDate = (Get-Date).AddMonths(6)
        HomePage = "https://sql-temp.contoso.com"
    },
    # Config 4: Legacy support with RC4
    @{
        Name = "gmsa-Legacy-RC4"
        DNSHostName = "gmsa-Legacy-RC4.contoso.com"
        DisplayName = "Legacy System Support Account"
        Description = "Legacy service supporting RC4 for older systems - delegation blocked"
        SamAccountName = "gmsa-Legacy`$"
        Enabled = $true
        ServicePrincipalNames = @(
            "HTTP/legacy-app.contoso.com"
            "HTTP/legacy-app"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-Legacy")
        KerberosEncryptionType = "RC4,AES128"
        TrustedForDelegation = $false
        AccountNotDelegated = $true
        CompoundIdentitySupported = $false
        ManagedPasswordIntervalInDays = 30
    },
    # Config 5: Trusted for delegation
    @{
        Name = "gmsa-Delegation-Trusted"
        DNSHostName = "gmsa-Delegation-Trusted.contoso.com"
        DisplayName = "Trusted Delegation Service"
        Description = "Service trusted for Kerberos delegation to backend systems"
        SamAccountName = "gmsa-DelTrust`$"
        Enabled = $true
        ServicePrincipalNames = @(
            "HTTP/frontend.contoso.com"
            "HOST/frontend.contoso.com"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-Frontend")
        PrincipalsAllowedToDelegateToAccount = @("Group-Frontend", "Group-Backend")
        KerberosEncryptionType = "AES256"
        TrustedForDelegation = $true
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 30
        HomePage = "https://frontend.contoso.com"
    },
    # Config 6: High-security with short password interval
    @{
        Name = "gmsa-HighSec-API"
        DNSHostName = "gmsa-HighSec-API.contoso.com"
        DisplayName = "High Security API Service"
        Description = "High-security API with 10-day password rotation and strict encryption"
        SamAccountName = "gmsa-HighSec`$"
        Enabled = $true
        ServicePrincipalNames = @(
            "HTTP/secure-api.contoso.com"
            "HTTPS/secure-api.contoso.com"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-SecureAPI")
        KerberosEncryptionType = "AES256"
        TrustedForDelegation = $false
        AccountNotDelegated = $true
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 10
        HomePage = "https://secure-api.contoso.com"
    },
    # Config 7: Multi-protocol service
    @{
        Name = "gmsa-MultiProtocol"
        DNSHostName = "gmsa-MultiProtocol.contoso.com"
        DisplayName = "Multi-Protocol Service Account"
        Description = "Service supporting LDAP, HTTP, and custom SPNs"
        SamAccountName = "gmsa-Multi`$"
        Enabled = $true
        ServicePrincipalNames = @(
            "LDAP/multiservice.contoso.com"
            "LDAP/multiservice"
            "HTTP/multiservice.contoso.com"
            "TERMSRV/multiservice.contoso.com"
            "WSMAN/multiservice.contoso.com"
        )
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-MultiService")
        PrincipalsAllowedToDelegateToAccount = @("Group-MultiService")
        KerberosEncryptionType = "AES256,AES128"
        TrustedForDelegation = $false
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 30
        HomePage = "https://multiservice.contoso.com"
    },
    # Config 8: Disabled account for future use
    @{
        Name = "gmsa-Future-Disabled"
        DNSHostName = "gmsa-Future-Disabled.contoso.com"
        DisplayName = "Future Service Account (Disabled)"
        Description = "Pre-created account for future service deployment - currently disabled"
        SamAccountName = "gmsa-Future`$"
        Enabled = $false
        ServicePrincipalNames = @("HTTP/future-service.contoso.com")
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-Future")
        KerberosEncryptionType = "AES256"
        TrustedForDelegation = $false
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 30
    },
    # Config 9: Custom OtherAttributes example
    @{
        Name = "gmsa-CustomAttribs"
        DNSHostName = "gmsa-CustomAttribs.contoso.com"
        DisplayName = "Custom Attributes Example"
        Description = "Demonstrates OtherAttributes parameter usage"
        SamAccountName = "gmsa-Custom`$"
        Enabled = $true
        ServicePrincipalNames = @("HTTP/custom.contoso.com")
        PrincipalsAllowedToRetrieveManagedPassword = @("Group-Custom")
        KerberosEncryptionType = "AES256"
        TrustedForDelegation = $false
        AccountNotDelegated = $false
        CompoundIdentitySupported = $true
        ManagedPasswordIntervalInDays = 30
        HomePage = "https://custom.contoso.com"
        OtherAttributes = @{
            'info' = 'Custom informational text'
            'department' = 'IT Operations'
        }
    }
)

# Security groups
$securityGroups = @(
    @{Name = "Group-FullFeatured"; Description = "Full featured gMSA access"},
    @{Name = "Group-Clients"; Description = "Client-side outbound services"},
    @{Name = "Group-SQL"; Description = "SQL Server instances"},
    @{Name = "Group-Legacy"; Description = "Legacy system support"},
    @{Name = "Group-Frontend"; Description = "Frontend delegation services"},
    @{Name = "Group-Backend"; Description = "Backend services for delegation"},
    @{Name = "Group-SecureAPI"; Description = "High-security API hosts"},
    @{Name = "Group-MultiService"; Description = "Multi-protocol service hosts"},
    @{Name = "Group-Future"; Description = "Future service deployment"},
    @{Name = "Group-Custom"; Description = "Custom attribute testing"}
)

# Functions
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-KDSRootKey {
    Write-ColorOutput "`nChecking KDS Root Key..." "Cyan"
    $kdsKeys = Invoke-Command -ComputerName $script:PDC -ScriptBlock { Get-KdsRootKey }
    $now = Get-Date
    $validKey = $kdsKeys | Where-Object { $_.EffectiveTime -le $now.AddHours(-10) }
    
    if ($validKey) {
        Write-ColorOutput "Valid KDS Root Key exists (effective for at least 10 hours)." "Green"
        return $true
    } else {
        if ($kdsKeys) {
            Write-Warning "KDS Root Keys exist but none are effective for at least 10 hours."
        } else {
            Write-Warning "No KDS Root Key found."
        }
        $create = Read-Host "Create a backdated KDS Root Key now for immediate use? (Y/N)"
        if ($create -eq 'Y') {
            Write-ColorOutput "Creating backdated KDS Root Key (effective 10 hours ago)..." "Yellow"
            Invoke-Command -ComputerName $script:PDC -ScriptBlock { Add-KdsRootKey -EffectiveTime $args[0] } -ArgumentList ($now.AddHours(-10)) | Out-Null
            Write-ColorOutput "KDS Root Key created. Waiting 10 seconds for replication..." "Yellow"
            Start-Sleep -Seconds 10
            Write-ColorOutput "KDS Root Key created." "Green"
            return $true
        }
        return $false
    }
}

function New-SecurityGroupIfNotExists {
    param([string]$Name, [string]$Description)
    try {
        Get-ADGroup -Identity $Name -Server $script:PDC -ErrorAction Stop | Out-Null
        Write-ColorOutput " Group exists: $Name" "Gray"
    } catch {
        New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Description $Description -Server $script:PDC
        Write-ColorOutput " Created group: $Name" "Green"
    }
}

function New-gMSAWithAllProperties {
    param($Config)
   
    $name = $Config.Name
    $sam = $Config.SamAccountName
    Write-ColorOutput "`n$('='*70)" "Cyan"
    Write-ColorOutput "Creating gMSA: $name" "Cyan"
    Write-ColorOutput "$('='*70)" "Cyan"
   
    # Check if exists using SAM account name
    try {
        Get-ADServiceAccount -Identity $sam -Server $script:PDC -ErrorAction Stop | Out-Null
        Write-Warning "gMSA '$name' ($sam) already exists. Skipping."
        return
    } catch {}
   
    # Build parameters
    $params = @{
        Name = $name
        PassThru = $true
        Server = $script:PDC
    }
   
    # Core properties
    if ($Config.DNSHostName) { $params.DNSHostName = $Config.DNSHostName }
    if ($Config.DisplayName) { $params.DisplayName = $Config.DisplayName }
    if ($Config.Description) { $params.Description = $Config.Description }
    if ($Config.SamAccountName) { $params.SamAccountName = $Config.SamAccountName }
    if ($Config.HomePage) { $params.HomePage = $Config.HomePage }
    if ($Config.ContainsKey('Enabled')) { $params.Enabled = $Config.Enabled }
   
    # SPNs
    if ($Config.ServicePrincipalNames) {
        $params.ServicePrincipalNames = $Config.ServicePrincipalNames
    }
   
    # Principals - ensure groups exist
    if ($Config.PrincipalsAllowedToRetrieveManagedPassword) {
        foreach ($principal in $Config.PrincipalsAllowedToRetrieveManagedPassword) {
            $groupInfo = $securityGroups | Where-Object { $_.Name -eq $principal }
            if ($groupInfo) {
                New-SecurityGroupIfNotExists -Name $principal -Description $groupInfo.Description
            }
        }
        $params.PrincipalsAllowedToRetrieveManagedPassword = $Config.PrincipalsAllowedToRetrieveManagedPassword
    }
   
    if ($Config.PrincipalsAllowedToDelegateToAccount) {
        $params.PrincipalsAllowedToDelegateToAccount = $Config.PrincipalsAllowedToDelegateToAccount
    }
   
    # Kerberos and encryption
    if ($Config.KerberosEncryptionType) {
        $params.KerberosEncryptionType = $Config.KerberosEncryptionType
    }
   
    # Delegation settings
    if ($Config.ContainsKey('TrustedForDelegation')) {
        $params.TrustedForDelegation = $Config.TrustedForDelegation
    }
    if ($Config.ContainsKey('AccountNotDelegated')) {
        $params.AccountNotDelegated = $Config.AccountNotDelegated
    }
    if ($Config.ContainsKey('CompoundIdentitySupported')) {
        $params.CompoundIdentitySupported = $Config.CompoundIdentitySupported
    }
   
    # Password management
    if ($Config.ManagedPasswordIntervalInDays) {
        $params.ManagedPasswordIntervalInDays = $Config.ManagedPasswordIntervalInDays
    }
   
    # Account expiration
    if ($Config.AccountExpirationDate) {
        $params.AccountExpirationDate = $Config.AccountExpirationDate
    }
   
    # Special account types - different parameter sets
    if ($Config.RestrictToOutboundAuthenticationOnly) {
        $params.RestrictToOutboundAuthenticationOnly = $true
        # Remove ALL incompatible parameters for outbound-only parameter set
        @('DNSHostName', 'ServicePrincipalNames', 'PrincipalsAllowedToDelegateToAccount',
          'TrustedForDelegation', 'CompoundIdentitySupported', 'HomePage',
          'PrincipalsAllowedToRetrieveManagedPassword',
          'ManagedPasswordIntervalInDays') | ForEach-Object {
            if ($params.ContainsKey($_)) {
                $params.Remove($_)
                Write-ColorOutput " Removed incompatible parameter: $_" "DarkYellow"
            }
        }
    }
   
    # OtherAttributes
    if ($Config.OtherAttributes) {
        $params.OtherAttributes = $Config.OtherAttributes
    }
   
    # Display parameters
    Write-ColorOutput "`nConfiguration:" "White"
    $params.GetEnumerator() | Where-Object { $_.Key -ne 'PassThru' -and $_.Key -ne 'Server' } |
        Sort-Object Key | ForEach-Object {
            $value = if ($_.Value -is [Array]) { $_.Value -join ', ' }
                     elseif ($_.Value -is [DateTime]) { $_.Value.ToString('yyyy-MM-dd') }
                     else { $_.Value }
            Write-ColorOutput (" {0,-40}: {1}" -f $_.Key, $value) "Gray"
        }
   
    # Create gMSA
    try {
        $account = New-ADServiceAccount @params
        Write-ColorOutput "`nSUCCESS: Created $name" "Green"
    } catch {
        Write-Error "Failed to create '$name': $_"
        Write-ColorOutput "Error: $($_.Exception.Message)" "Red"
        return
    }
   
    # Retrieve and show details with retry for replication
    $details = $null
    $attempts = 0
    while (-not $details -and $attempts -lt 5) {
        try {
            Start-Sleep -Seconds (5 * $attempts)
            $details = Get-ADServiceAccount -Identity $sam -Properties * -Server $script:PDC -ErrorAction Stop
        } catch {
            $attempts++
        }
    }
    
    if ($details) {
        Write-ColorOutput "`nAccount Details:" "White"
        Write-ColorOutput " DN: $($details.DistinguishedName)" "Gray"
        Write-ColorOutput " Created: $($details.Created)" "Gray"
        Write-ColorOutput " Enabled: $($details.Enabled)" "Gray"
       
        if ($details.ServicePrincipalNames) {
            Write-ColorOutput " SPNs:" "Gray"
            $details.ServicePrincipalNames | ForEach-Object {
                Write-ColorOutput "   - $_" "DarkGray"
            }
        }
    } else {
        Write-ColorOutput "Could not retrieve details for $name after attempts. May need to wait for replication." "Yellow"
    }
}

# Main Execution
Write-ColorOutput "`n$('='*70)" "Cyan"
Write-ColorOutput "gMSA Creation Script - ALL Properties Demonstrated" "Cyan"
Write-ColorOutput "$('='*70)" "Cyan"

# Prerequisites
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module required. Install RSAT tools."
    exit 1
}
Import-Module ActiveDirectory

# Domain info and auto-configure
try {
    $domain = Get-ADDomain
    $DomainDNS = $domain.DNSRoot
    $DomainDN = $domain.DistinguishedName
    $script:PDC = $domain.PDCEmulator
   
    Write-ColorOutput "`nDomain: $DomainDNS" "Green"
    Write-ColorOutput "Domain DN: $DomainDN" "Green"
    Write-ColorOutput "PDC: $script:PDC" "Green"
   
    # Update all configs with correct domain
    Write-ColorOutput "Updating configurations for domain: $DomainDNS" "Gray"
    foreach ($config in $gMSAConfigs) {
        if ($config.DNSHostName) {
            $config.DNSHostName = $config.DNSHostName.Replace('contoso.com', $DomainDNS)
        }
        if ($config.HomePage) {
            $config.HomePage = $config.HomePage.Replace('contoso.com', $DomainDNS)
        }
        if ($config.ServicePrincipalNames) {
            $updatedSPNs = @()
            foreach ($spn in $config.ServicePrincipalNames) {
                $updatedSPNs += $spn.Replace('contoso.com', $DomainDNS)
            }
            $config.ServicePrincipalNames = $updatedSPNs
        }
    }
} catch {
    Write-Error "Cannot connect to AD domain."
    exit 1
}

# KDS Root Key
if (-not (Test-KDSRootKey)) {
    Write-Error "KDS Root Key required."
    exit 1
}

# Create groups
Write-ColorOutput "`nCreating security groups..." "Cyan"
foreach ($group in $securityGroups) {
    New-SecurityGroupIfNotExists -Name $group.Name -Description $group.Description
}

# Create gMSAs
Write-ColorOutput "`nCreating gMSA accounts..." "Cyan"
foreach ($config in $gMSAConfigs) {
    New-gMSAWithAllProperties -Config $config
    Start-Sleep -Milliseconds 500
}

# Summary
Write-ColorOutput "`n$('='*70)" "Cyan"
Write-ColorOutput "Completed!" "Green"
Write-ColorOutput "$('='*70)" "Cyan"
Write-ColorOutput "`nCreated Accounts:" "Yellow"
try {
    Get-ADServiceAccount -Filter {Name -like "gmsa-*"} -Properties DisplayName, Enabled, Created -Server $script:PDC -ErrorAction SilentlyContinue |
        Format-Table Name, DisplayName, Enabled, Created -AutoSize
} catch {
    Write-ColorOutput "Run: Get-ADServiceAccount -Filter {Name -like 'gmsa-*'}" "Gray"
}

Write-ColorOutput "`nNext Steps:" "Yellow"
Write-ColorOutput "1. Add computers to security groups:" "White"
Write-ColorOutput "   Add-ADGroupMember -Identity 'Group-FullFeatured' -Members 'SERVER01`$'" "Gray"
Write-ColorOutput "`n2. Install gMSA on target computers:" "White"
Write-ColorOutput "   Install-ADServiceAccount -Identity gmsa-Full-Featured" "Gray"
Write-ColorOutput "`n3. Test installation:" "White"
Write-ColorOutput "   Test-ADServiceAccount -Identity gmsa-Full-Featured" "Gray"
Write-ColorOutput "`n4. View all properties:" "White"
Write-ColorOutput "   Get-ADServiceAccount -Identity gmsa-Full-Featured -Properties * | FL *" "Gray"
