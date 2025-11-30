<#
.SYNOPSIS
Launches the Phoenix WPF user interface for orchestrating Active Directory forest
recovery and post-compromise remediation workflows.

.DESCRIPTION
Invoke-WinUI hosts the Phoenix Fluent WPF console, providing a guided interface
for:

* Forest discovery and domain controller inventory (via Get-ForestInfo).
* Task-driven Active Directory recovery operations (e.g. Sysvol restore, FSMO
  seizure, DNS cleanup, DC / krbtgt / DSRM / built-in admin password resets,
  GMSA rotation, and mass password reset orchestration).
* Per-task execution mode control (WhatIf vs Execute) with progress tracking and
  status output.
* Per-domain scoping of actions using only online domain controllers from the
  discovered inventory.

The window uses Wpf.Ui’s FluentWindow, supports light/dark theme switching, and
enforces a single active UI instance via the IDENTIR_UI_ACTIVE environment flag.
All operational logging is performed through Write-IdentIRLog, with additional
inline status updates in the UI.

.PARAMETER WinStyleHidden
Hides the hosting PowerShell console window when the UI is launched (SW_HIDE).
Intended for use from shortcuts or launchers where only the WPF experience
should be visible. Logging via Write-IdentIRLog continues as normal.

.EXAMPLE
# Launch the Phoenix recovery UI with the console visible
Invoke-WinUI

.EXAMPLE
# Launch the Phoenix recovery UI in a console-hidden mode
Invoke-WinUI -WinStyleHidden

.OUTPUTS
None

Invoke-WinUI presents a graphical interface and does not emit pipeline output.
Underlying recovery cmdlets may log or write their own progress as configured.

.NOTES
Author:  NightCityShogun
Version: 1.9
Requires: PowerShell 5.1+, .NET WPF, Wpf.Ui.dll
© 2025 NightCityShogun. All rights reserved.
#>

function Invoke-WinUI {
    [CmdletBinding()]
    param (
        [switch]$WinStyleHidden
    )

    if ($WinStyleHidden) {
        Add-Type -MemberDefinition @"
        [DllImport("Kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
"@ -Name Window -Namespace Console -PassThru

        $consolePtr = [ConsoleWindow]::GetConsoleWindow()
        [ConsoleWindow]::ShowWindow($consolePtr, 0) # SW_HIDE
    }

    Add-Type -LiteralPath (Join-Path $PSScriptRoot 'Wpf.Ui.dll')
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.DirectoryServices

    if ($env:IDENTIR_UI_ACTIVE) {
        $message = "UI already active. Aborting."
        Write-IdentIRLog -Message $message -TypeName 'Error'
        Write-Host $message -ForegroundColor Yellow
        Remove-Item Env:\IDENTIR_UI_ACTIVE -ErrorAction SilentlyContinue
        return
    }
    $env:IDENTIR_UI_ACTIVE = $true

    # Script-level vars
    $script:domainListView  = $null
    $script:progressBar     = $null
    $script:taskProgressBar = $null
    $script:statusText      = $null
    $script:selectedDCs     = @()
    $script:taskToggles     = @()
    $script:whatIfToggle    = $null
    $script:isProcessing    = $false
    $script:menuButtons     = @()
    $script:currentTheme    = 'Dark'

    # ---------- XAML ----------
    [xml]$xaml = @"
<ui:FluentWindow
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:ui="http://schemas.lepo.co/wpfui/2022/xaml"
    x:Name="Window"
    Width="1024" Height="740"
    WindowStartupLocation="CenterScreen"
    UseLayoutRounding="True"
    SnapsToDevicePixels="True">
  <ui:FluentWindow.Resources>
    <ResourceDictionary>
      <ResourceDictionary.MergedDictionaries>
        <ui:ThemesDictionary x:Name="ThemesDictionary" Theme="Dark" />
        <ui:ControlsDictionary />
      </ResourceDictionary.MergedDictionaries>
    </ResourceDictionary>
  </ui:FluentWindow.Resources>
  <Grid x:Name="MainGrid">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="220"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- Header Left -->
    <StackPanel Grid.Row="0" Grid.Column="0" Orientation="Horizontal" Margin="12,12,0,8">
      <Image x:Name="LogoImage" Width="48" Height="48" Margin="0,4,8,0"/>
      <TextBlock Text="Phoenix" VerticalAlignment="Center" FontWeight="Bold" FontSize="18"/>
    </StackPanel>

    <!-- Header Right -->
    <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,12,8">
      <ui:Button x:Name="ThemeToggle" Content="Light Mode" Width="100" Height="32"/>
    </StackPanel>

    <!-- Left menu -->
    <StackPanel x:Name="MenuPanel" Grid.Row="1" Grid.Column="0" Margin="12,0,12,12"/>

    <!-- Right content -->
    <Border Grid.Row="1" Grid.Column="1" Margin="0,0,12,12"
            BorderBrush="{DynamicResource ControlStrokeColorDefaultBrush}" BorderThickness="1" CornerRadius="6">
      <Grid x:Name="ContentPanel" Margin="16">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
      </Grid>
    </Border>

    <!-- Footer -->
    <TextBlock Grid.Row="2" Grid.ColumnSpan="2"
               Text="Copyright Praevia LLC 2025"
               HorizontalAlignment="Center" Margin="0,6,0,10" FontSize="10"/>
  </Grid>
</ui:FluentWindow>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $form   = [Windows.Markup.XamlReader]::Load($reader)

    [Wpf.Ui.Appearance.ApplicationThemeManager]::Apply(
        [Wpf.Ui.Appearance.ApplicationTheme]::Dark,
        [Wpf.Ui.Controls.WindowBackdropType]::None,
        $true
    )

    # Logo
    $logoPath = Join-Path $PSScriptRoot 'images/praevialogo.png'
    if (Test-Path $logoPath) {
        try {
            $bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
            $bitmap.BeginInit()
            $bitmap.UriSource = New-Object System.Uri -ArgumentList $logoPath, 'file:///'
            $bitmap.EndInit()
            ($form.FindName("LogoImage")).Source = $bitmap
        } catch {
            Write-IdentIRLog -Message "Failed to load logo: $($_.Exception.Message)" -TypeName 'Error'
            Write-Host "Failed to load logo: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    $form.Add_Closed({
        Remove-Item Env:\IDENTIR_UI_ACTIVE -ErrorAction SilentlyContinue
    })

    # Theme toggle
    $themeToggle = $form.FindName("ThemeToggle")
    $themeToggle.Add_Click({
        $newTheme = if ($script:currentTheme -eq 'Dark') { 'Light' } else { 'Dark' }
        $themesDictionary = $form.FindName("ThemesDictionary")
        $themesDictionary.Theme = $newTheme

        [Wpf.Ui.Appearance.ApplicationThemeManager]::Apply(
            [Wpf.Ui.Appearance.ApplicationTheme]::$newTheme,
            [Wpf.Ui.Controls.WindowBackdropType]::None,
            $true
        )

        $this.Content = if ($newTheme -eq 'Dark') { "Light Mode" } else { "Dark Mode" }
        $script:currentTheme = $newTheme

        $message = "Switched to $newTheme theme"
        Write-IdentIRLog -Message $message -TypeName 'Info'
        Write-Host $message -ForegroundColor Green
    })

    # Left menu
    $menuItems = @(
        'Active Directory',
        'AWS',
        'Executive Dashboards',
        'Microsoft Azure',
        'UAL Collection',
        'Velociraptor'
    )

    $menuPanel = $form.FindName("MenuPanel")
    foreach ($item in $menuItems) {
        $btn = New-Object Wpf.Ui.Controls.Button
        $btn.Content = $item
        $btn.Height  = 40
        $btn.Margin  = '0,6,0,0'
        $btn.Tag     = $item

        $btn.Add_Click({
            $script:menuButtons | ForEach-Object { $_.Appearance = 'Secondary' }
            $this.Appearance = 'Primary'
            Update-RightPane $this.Tag
        })

        if ($item -eq 'Active Directory') {
            $btn.Appearance = 'Primary'
        } else {
            $btn.Appearance = 'Secondary'
        }

        $menuPanel.Children.Add($btn) | Out-Null
        $script:menuButtons += $btn
    }

    # ==========================
    # Dialogs & helpers
    # ==========================

    function Show-PasswordDialog {
        $dialog = New-Object System.Windows.Window
        $dialog.Title = "Current User Password Reset"
        $dialog.Width = 420
        $dialog.Height = 210
        $dialog.WindowStartupLocation = 'CenterOwner'
        $dialog.Owner = $form
        $dialog.ResizeMode = 'NoResize'
        $dialog.WindowStyle = 'SingleBorderWindow'

        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = 20

        0..3 | ForEach-Object {
            $row = New-Object System.Windows.Controls.RowDefinition
            $row.Height = 'Auto'
            $grid.RowDefinitions.Add($row) | Out-Null
        }

        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null

        # New password label
        $grid.Children.Add(
            (New-Object System.Windows.Controls.TextBlock -Property @{
                Text   = 'New Password:'
                Margin = '0,0,8,6'
            })
        ) | Out-Null

        # New password
        $txtNew = New-Object System.Windows.Controls.PasswordBox
        $txtNew.Margin = '0,0,0,6'
        [System.Windows.Controls.Grid]::SetColumn($txtNew, 1)
        $grid.Children.Add($txtNew) | Out-Null

        # Confirm label
        $lbl2 = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Confirm Password:'
            Margin = '0,0,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lbl2, 1)
        $grid.Children.Add($lbl2) | Out-Null

        # Confirm password
        $txtConfirm = New-Object System.Windows.Controls.PasswordBox
        [System.Windows.Controls.Grid]::SetRow($txtConfirm, 1)
        [System.Windows.Controls.Grid]::SetColumn($txtConfirm, 1)
        $grid.Children.Add($txtConfirm) | Out-Null

        # Buttons
        $panel = New-Object System.Windows.Controls.StackPanel
        $panel.Orientation = 'Horizontal'
        $panel.HorizontalAlignment = 'Right'
        $panel.Margin = '0,10,0,0'
        [System.Windows.Controls.Grid]::SetRow($panel, 3)
        [System.Windows.Controls.Grid]::SetColumnSpan($panel, 2)

        $ok = New-Object System.Windows.Controls.Button -Property @{
            Content = 'OK'
            Width   = 80
        }
        $cancel = New-Object System.Windows.Controls.Button -Property @{
            Content = 'Cancel'
            Width   = 80
            Margin  = '8,0,0,0'
        }

        $panel.Children.Add($ok)     | Out-Null
        $panel.Children.Add($cancel) | Out-Null
        $grid.Children.Add($panel)   | Out-Null

        $dialog.Content = $grid

        $result = [PSCustomObject]@{
            Success  = $false
            Password = $null
        }

        $ok.Add_Click({
            if ($txtNew.Password -eq $txtConfirm.Password -and $txtNew.Password.Length -ge 8) {
                $result.Success  = $true
                $result.Password = ConvertTo-SecureString $txtNew.Password -AsPlainText -Force
                $dialog.DialogResult = $true
                $dialog.Close()
            } else {
                [System.Windows.MessageBox]::Show(
                    "Passwords do not match or are too short (min 8 chars).",
                    "Error",
                    'OK',
                    'Error'
                ) | Out-Null
            }
        })

        $cancel.Add_Click({
            $dialog.DialogResult = $false
            $dialog.Close()
        })

        $dialog.ShowDialog() | Out-Null
        return $result
    }

    function Show-AdCredentialDialog {
        $dialog = New-Object System.Windows.Window
        $dialog.Title = "Active Directory Credentials"
        $dialog.Width = 420
        $dialog.Height = 230
        $dialog.WindowStartupLocation = 'CenterOwner'
        $dialog.Owner = $form
        $dialog.ResizeMode = 'NoResize'
        $dialog.WindowStyle = 'SingleBorderWindow'

        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = 20

        0..4 | ForEach-Object {
            $row = New-Object System.Windows.Controls.RowDefinition
            $row.Height = 'Auto'
            $grid.RowDefinitions.Add($row) | Out-Null
        }

        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null

        # Note
        $lblNote = New-Object System.Windows.Controls.TextBlock -Property @{
            Text         = "Enter Enterprise Admin credentials for forest recovery."
            TextWrapping = 'Wrap'
            Margin       = '0,0,0,10'
        }
        [System.Windows.Controls.Grid]::SetRow($lblNote, 0)
        [System.Windows.Controls.Grid]::SetColumnSpan($lblNote, 2)
        $grid.Children.Add($lblNote) | Out-Null

        # Username label
        $lblUser = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'User (domain\user or user@domain):'
            Margin = '0,0,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblUser, 1)
        $grid.Children.Add($lblUser) | Out-Null

        # Username textbox
        $txtUser = New-Object System.Windows.Controls.TextBox
        $txtUser.Margin = '0,0,0,6'
        [System.Windows.Controls.Grid]::SetRow($txtUser, 1)
        [System.Windows.Controls.Grid]::SetColumn($txtUser, 1)
        $grid.Children.Add($txtUser) | Out-Null

        # Password label
        $lblPwd = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Password:'
            Margin = '0,0,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblPwd, 2)
        $grid.Children.Add($lblPwd) | Out-Null

        # Password box
        $txtPwd = New-Object System.Windows.Controls.PasswordBox
        [System.Windows.Controls.Grid]::SetRow($txtPwd, 2)
        [System.Windows.Controls.Grid]::SetColumn($txtPwd, 1)
        $grid.Children.Add($txtPwd) | Out-Null

        # Buttons
        $panel = New-Object System.Windows.Controls.StackPanel
        $panel.Orientation = 'Horizontal'
        $panel.HorizontalAlignment = 'Right'
        $panel.Margin = '0,12,0,0'
        [System.Windows.Controls.Grid]::SetRow($panel, 4)
        [System.Windows.Controls.Grid]::SetColumnSpan($panel, 2)

        $ok = New-Object System.Windows.Controls.Button -Property @{
            Content = 'OK'
            Width   = 80
        }
        $cancel = New-Object System.Windows.Controls.Button -Property @{
            Content = 'Cancel'
            Width   = 80
            Margin  = '8,0,0,0'
        }

        $panel.Children.Add($ok)     | Out-Null
        $panel.Children.Add($cancel) | Out-Null
        $grid.Children.Add($panel)   | Out-Null

        $dialog.Content = $grid

        $result = $null

        $ok.Add_Click({
            $userText = $txtUser.Text.Trim()
            if (-not $userText) {
                [System.Windows.MessageBox]::Show(
                    "Username is required.",
                    "Error",
                    'OK',
                    'Error'
                ) | Out-Null
                return
            }
            if (-not $txtPwd.SecurePassword -or $txtPwd.SecurePassword.Length -le 0) {
                [System.Windows.MessageBox]::Show(
                    "Password is required.",
                    "Error",
                    'OK',
                    'Error'
                ) | Out-Null
                return
            }

            try {
                $cred = New-Object System.Management.Automation.PSCredential ($userText, $txtPwd.SecurePassword)
                $result = $cred
                $dialog.DialogResult = $true
                $dialog.Close()
            } catch {
                [System.Windows.MessageBox]::Show(
                    "Failed to create credentials: $($_.Exception.Message)",
                    "Error",
                    'OK',
                    'Error'
                ) | Out-Null
            }
        })

        $cancel.Add_Click({
            $dialog.DialogResult = $false
            $dialog.Close()
        })

        $dialog.ShowDialog() | Out-Null
        return $result
    }

    function Get-CurrentUserPwdLastSet {
        try {
            $user = $env:USERNAME
            if (-not $user) { return $null }

            $logonServerNetBIOS = $env:LOGONSERVER -replace '^\\\\',''
            if (-not $logonServerNetBIOS) { return $null }

            try { $dcFqdn = [System.Net.Dns]::GetHostEntry($logonServerNetBIOS).HostName }
            catch { $dcFqdn = $logonServerNetBIOS }

            $rootDsePath = "LDAP://$dcFqdn/RootDSE"
            $rootDse = [ADSI]$rootDsePath
            $domainDN = $rootDse.Properties['defaultNamingContext'][0]
            if (-not $domainDN) { return $null }

            $searchRoot = [ADSI]"LDAP://$dcFqdn/$domainDN"
            $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
            $ds.Filter = "(&(objectClass=user)(sAMAccountName=$user))"
            $ds.PageSize = 1
            $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $ds.PropertiesToLoad.Add('pwdLastSet') | Out-Null

            $res = $ds.FindOne()
            if (-not $res -or -not $res.Properties['pwdlastset']) { return $null }

            $val = $res.Properties['pwdlastset'][0]

            # Handle IADsLargeInteger vs Int64
            if ($val -is [System.__ComObject]) {
                $hi = $val.HighPart
                $lo = $val.LowPart
                $fileTime = ([int64]$hi -shl 32) -bor ($lo -band 0xFFFFFFFFL)
            } else {
                $fileTime = [int64]$val
            }

            if ($fileTime -le 0) { return $null }

            return [datetime]::FromFileTime($fileTime)
        } catch {
            Write-IdentIRLog -Message "Get-CurrentUserPwdLastSet failed: $($_.Exception.Message)" -TypeName 'Warning' -ForegroundColor Yellow
            return $null
        }
    }

    # Enumerate OUs and containers for a given domain using discovered DCs (flat list)
    function Get-DomainOUsForDomain {
        param(
            [Parameter(Mandatory = $true)]
            [string] $DomainName,

            [Parameter(Mandatory = $true)]
            [object[]] $DcList
        )

        $domainDC = $DcList |
            Where-Object { $_.Domain -ieq $DomainName -and $_.Online } |
            Select-Object -First 1

        if (-not $domainDC) {
            return @()
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$($domainDC.FQDN)/$($domainDC.DefaultNamingContext)"
        # include both OU and container objects so everything like CN=Users, CN=Computers, etc. appears
        $searcher.Filter = "(|(objectClass=organizationalUnit)(objectClass=container))"
        $searcher.SearchScope = "Subtree"
        $searcher.PropertiesToLoad.Add("name")              | Out-Null
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $searcher.PageSize = 1000

        $results = $searcher.FindAll()

        $ous = foreach ($ou in $results) {
            $dn   = $ou.Properties["distinguishedname"][0]
            $name = $ou.Properties["name"][0]

            [PSCustomObject]@{
                Name              = $name
                DistinguishedName = $dn
            }
        }

        $results.Dispose()
        return ($ous | Sort-Object DistinguishedName)
    }

    function Show-MassResetDialog {
        $dialog = New-Object System.Windows.Window
        $dialog.Title = "Mass Password Reset Configuration"
        $dialog.Width = 760
        $dialog.Height = 480
        $dialog.WindowStartupLocation = 'CenterOwner'
        $dialog.Owner = $form
        $dialog.ResizeMode = 'NoResize'
        $dialog.WindowStyle = 'SingleBorderWindow'

        # Root grid: 2 rows (content + buttons), 2 columns (left config + right OUs)
        $root = New-Object System.Windows.Controls.Grid
        $root.Margin = 20

        $rowContent = New-Object System.Windows.Controls.RowDefinition
        $rowContent.Height = '*'
        $rowButtons = New-Object System.Windows.Controls.RowDefinition
        $rowButtons.Height = 'Auto'
        $root.RowDefinitions.Add($rowContent)  | Out-Null
        $root.RowDefinitions.Add($rowButtons)  | Out-Null

        $colLeft  = New-Object System.Windows.Controls.ColumnDefinition
        $colLeft.Width = '320'
        $colRight = New-Object System.Windows.Controls.ColumnDefinition
        $colRight.Width = '*'
        $root.ColumnDefinitions.Add($colLeft)  | Out-Null
        $root.ColumnDefinitions.Add($colRight) | Out-Null

        # LEFT GRID (domain + keywords + password count + note)
        $left = New-Object System.Windows.Controls.Grid
        0..5 | ForEach-Object {    # NOTE: now 0..5 to make room for password count row
            $row = New-Object System.Windows.Controls.RowDefinition
            $row.Height = 'Auto'
            $left.RowDefinitions.Add($row) | Out-Null
        }
        [System.Windows.Controls.Grid]::SetRow($left, 0)
        [System.Windows.Controls.Grid]::SetColumn($left, 0)
        $root.Children.Add($left) | Out-Null

        # RIGHT GRID (OU tree)
        $right = New-Object System.Windows.Controls.Grid
        0..1 | ForEach-Object {
            $row = New-Object System.Windows.Controls.RowDefinition
            $row.Height = 'Auto'
            $right.RowDefinitions.Add($row) | Out-Null
        }
        [System.Windows.Controls.Grid]::SetRow($right, 0)
        [System.Windows.Controls.Grid]::SetColumn($right, 1)
        $root.Children.Add($right) | Out-Null

        # ---------- LEFT: Domain ----------
        $lblDomain = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Select Domain:'
            Margin = '0,0,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblDomain, 0)
        $left.Children.Add($lblDomain) | Out-Null

        $cmbDomain = New-Object System.Windows.Controls.ComboBox -Property @{
            Margin = '0,0,0,6'
        }
        [System.Windows.Controls.Grid]::SetRow($cmbDomain, 0)
        [System.Windows.Controls.Grid]::SetColumn($cmbDomain, 1)
        $left.Children.Add($cmbDomain) | Out-Null

        # Populate domains from discovered DCs
        $uniqueDomains = $script:domainListView.Items |
            Select-Object -Property Domain -Unique |
            Sort-Object Domain

        if (-not $uniqueDomains) {
            $message = "No domains available for selection. Ensure forest discovery has completed."
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            [System.Windows.MessageBox]::Show($message, "Error", 'OK', 'Error') | Out-Null
            return [PSCustomObject]@{
                Success            = $false
                Domain             = $null
                ExcludedOUs        = @()
                KeywordRules       = @()
                PasswordResetCount = 1
            }
        }

        foreach ($dom in $uniqueDomains) {
            $cmbDomain.Items.Add($dom.Domain) | Out-Null
        }

        # ---------- LEFT: Keyword rules ----------
        $lblKeywords = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Keyword Exclusions (sAMAccountName):'
            Margin = '0,12,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblKeywords, 1)
        $left.Children.Add($lblKeywords) | Out-Null

        $keywordPanel = New-Object System.Windows.Controls.StackPanel
        $keywordPanel.Margin = '0,0,0,0'
        [System.Windows.Controls.Grid]::SetRow($keywordPanel, 2)
        $left.Children.Add($keywordPanel) | Out-Null

        $kwButtonPanel = New-Object System.Windows.Controls.StackPanel -Property @{
            Orientation         = 'Horizontal'
            HorizontalAlignment = 'Left'
            Margin              = '0,6,0,0'
        }
        [System.Windows.Controls.Grid]::SetRow($kwButtonPanel, 3)
        $left.Children.Add($kwButtonPanel) | Out-Null

        $btnAddRule = New-Object System.Windows.Controls.Button -Property @{
            Content = 'Add Rule'
            Width   = 80
        }
        $btnClearEmpty = New-Object System.Windows.Controls.Button -Property @{
            Content = 'Clear Empty'
            Width   = 90
            Margin  = '8,0,0,0'
        }

        $kwButtonPanel.Children.Add($btnAddRule)    | Out-Null
        $kwButtonPanel.Children.Add($btnClearEmpty) | Out-Null

        # Helper to add a keyword row
        $addRuleScriptBlock = {
            param($panel)

            $rowPanel = New-Object System.Windows.Controls.StackPanel
            $rowPanel.Orientation = 'Horizontal'
            $rowPanel.Margin = '0,2,0,2'

            $cmbType = New-Object System.Windows.Controls.ComboBox -Property @{
                Width  = 100
                Margin = '0,0,6,0'
            }
            'startswith','endswith','contains','equals' | ForEach-Object {
                [void]$cmbType.Items.Add($_)
            }
            $cmbType.SelectedIndex = 0

            $txtValue = New-Object System.Windows.Controls.TextBox -Property @{
                Width = 180
            }

            $rowPanel.Children.Add($cmbType)  | Out-Null
            $rowPanel.Children.Add($txtValue) | Out-Null

            $panel.Children.Add($rowPanel)    | Out-Null
        }

        & $addRuleScriptBlock $keywordPanel  # initial row

        $btnAddRule.Add_Click({
            & $addRuleScriptBlock $keywordPanel
        })

        $btnClearEmpty.Add_Click({
            $toKeep = New-Object System.Collections.Generic.List[object]
            foreach ($child in $keywordPanel.Children) {
                $txt = $child.Children[1]
                if ($txt.Text.Trim()) {
                    [void]$toKeep.Add($child)
                }
            }
            $keywordPanel.Children.Clear()
            foreach ($c in $toKeep) { $keywordPanel.Children.Add($c) | Out-Null }
            if ($keywordPanel.Children.Count -eq 0) {
                & $addRuleScriptBlock $keywordPanel
            }
        })

        # ---------- LEFT: Password reset count ----------
        $lblPwdCount = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Password Reset Count (per user):'
            Margin = '0,12,8,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblPwdCount, 4)
        $left.Children.Add($lblPwdCount) | Out-Null

        $cmbPwdCount = New-Object System.Windows.Controls.ComboBox -Property @{
            Margin = '0,12,0,6'
            Width  = 80
        }
        [System.Windows.Controls.Grid]::SetRow($cmbPwdCount, 4)
        [System.Windows.Controls.Grid]::SetColumn($cmbPwdCount, 1)
        $left.Children.Add($cmbPwdCount) | Out-Null

        1,2 | ForEach-Object { [void]$cmbPwdCount.Items.Add($_) }
        $cmbPwdCount.SelectedItem = 1   # default to 1

        # ---------- LEFT: Note ----------
        $note = New-Object System.Windows.Controls.TextBlock -Property @{
            Text = 'Note: Users in excluded OUs (including child OUs) and matching any ' +
                   'keyword rule on sAMAccountName will be excluded. Special accounts ' +
                   '(current user, MSOL, built-in admin, DSRM/DC/krbtgt/guest) are automatically excluded.'
            TextWrapping = 'Wrap'
            Margin       = '0,12,0,0'
        }
        [System.Windows.Controls.Grid]::SetRow($note, 5)
        $left.Children.Add($note) | Out-Null

        # ---------- RIGHT: OU TreeView with vertical scroll ----------
        $lblOUs = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Excluded OUs (check to exclude; child OUs included):'
            Margin = '0,0,0,6'
        }
        [System.Windows.Controls.Grid]::SetRow($lblOUs, 0)
        $right.Children.Add($lblOUs) | Out-Null

        $scrollOUs = New-Object System.Windows.Controls.ScrollViewer -Property @{
            VerticalScrollBarVisibility   = 'Auto'
            HorizontalScrollBarVisibility = 'Auto'
            Height = 280
        }
        [System.Windows.Controls.Grid]::SetRow($scrollOUs, 1)
        $right.Children.Add($scrollOUs) | Out-Null

        $tvOUs = New-Object System.Windows.Controls.TreeView
        $scrollOUs.Content = $tvOUs

        # Helper: build OU tree from flat list
        $buildOuTree = {
            param(
                [System.Windows.Controls.TreeView] $treeView,
                [System.Collections.IEnumerable]   $ous,
                [string]                          $domainNC
            )

            $treeView.Items.Clear()
            $nodeIndex = @{}

            # First create all nodes
            foreach ($ou in $ous) {
                $check = New-Object System.Windows.Controls.CheckBox
                $check.Content = "$($ou.Name) [$($ou.DistinguishedName)]"
                $check.Tag     = $ou.DistinguishedName

                $item = New-Object System.Windows.Controls.TreeViewItem
                $item.Header = $check
                $item.Tag    = $ou.DistinguishedName

                $nodeIndex[$ou.DistinguishedName] = $item
            }

            # Then attach them to parents
            foreach ($ou in $ous) {
                $item   = $nodeIndex[$ou.DistinguishedName]
                $dn     = $ou.DistinguishedName
                $dnParts = $dn -split ','

                if ($dnParts.Length -gt 1) {
                    # parent DN = everything after the first RDN (OU=/CN=)
                    $parentDn = ($dnParts[1..($dnParts.Length - 1)]) -join ','
                    if ($nodeIndex.ContainsKey($parentDn)) {
                        [void]$nodeIndex[$parentDn].Items.Add($item)
                    } else {
                        # Parent is domain root or non-OU/container; make this a top-level node
                        [void]$treeView.Items.Add($item)
                    }
                } else {
                    [void]$treeView.Items.Add($item)
                }
            }
        }

        # Domain change => reload OU tree
        $cmbDomain.Add_SelectionChanged({
            if (-not $cmbDomain.SelectedItem) { return }
            $domName = $cmbDomain.SelectedItem.ToString()
            $dcs     = @($script:domainListView.Items)

            $domainDC = $dcs |
                Where-Object { $_.Domain -ieq $domName -and $_.Online } |
                Select-Object -First 1

            if (-not $domainDC) {
                $tvOUs.Items.Clear()
                return
            }

            $ous = Get-DomainOUsForDomain -DomainName $domName -DcList $dcs
            & $buildOuTree $tvOUs $ous $domainDC.DefaultNamingContext
        })

        # Helper: recursively collect checked OU DNs
        function Get-CheckedOuDns {
            param(
                [System.Collections.IEnumerable] $items,
                [ref]$dnList
            )

            foreach ($it in $items) {
                $header = $it.Header
                if ($header -is [System.Windows.Controls.CheckBox]) {
                    if ($header.IsChecked -eq $true -and $header.Tag) {
                        $dnList.Value.Add([string]$header.Tag) | Out-Null
                    }
                }
                if ($it.Items -and $it.Items.Count -gt 0) {
                    Get-CheckedOuDns -items $it.Items -dnList $dnList
                }
            }
        }

        # ---------- Bottom buttons ----------
        $bottomPanel = New-Object System.Windows.Controls.StackPanel -Property @{
            Orientation         = 'Horizontal'
            HorizontalAlignment = 'Right'
            Margin              = '0,16,0,0'
        }
        [System.Windows.Controls.Grid]::SetRow($bottomPanel, 1)
        [System.Windows.Controls.Grid]::SetColumnSpan($bottomPanel, 2)
        $root.Children.Add($bottomPanel) | Out-Null

        $btnStart = New-Object Wpf.Ui.Controls.Button -Property @{
            Content = 'Start Reset'
            Width   = 120
        }
        $btnCancel = New-Object System.Windows.Controls.Button -Property @{
            Content = 'Cancel'
            Width   = 80
            Margin  = '8,0,0,0'
        }

        $bottomPanel.Children.Add($btnStart)  | Out-Null
        $bottomPanel.Children.Add($btnCancel) | Out-Null

        $dialog.Content = $root

        $result = [PSCustomObject]@{
            Success            = $false
            Domain             = $null
            ExcludedOUs        = @()
            KeywordRules       = @()
            PasswordResetCount = 1
        }

        $btnStart.Add_Click({
            if (-not $cmbDomain.SelectedItem) {
                $message = "No domain selected. Please select a domain."
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
                [System.Windows.MessageBox]::Show($message, "Error", 'OK', 'Error') | Out-Null
                return
            }

            $domainName = $cmbDomain.SelectedItem.ToString()

            # Collect OU DNs from checked TreeView nodes
            $dnList = New-Object System.Collections.Generic.List[string]
            Get-CheckedOuDns -items $tvOUs.Items -dnList ([ref]$dnList)
            $ouDns = $dnList.ToArray()

            # Collect keyword rules
            $rules = @()
            foreach ($row in $keywordPanel.Children) {
                $cmb = $row.Children[0]
                $txt = $row.Children[1]

                $type  = $cmb.SelectedItem
                $value = $txt.Text.Trim()

                if (-not $value) { continue }
                if (-not $type) { $type = 'contains' }

                $rules += @{
                    Type  = $type.ToLower()
                    Value = $value
                }
            }

            # Password reset count from combo
            $pwdCount = 1
            if ($cmbPwdCount.SelectedItem) {
                $pwdCount = [int]$cmbPwdCount.SelectedItem
            }

            $result.Domain             = $domainName.ToLower()
            $result.ExcludedOUs        = $ouDns
            $result.KeywordRules       = $rules
            $result.PasswordResetCount = $pwdCount
            $result.Success            = $true

            $message = "Mass Password Reset configured: Domain=$($result.Domain); " +
                       "ExcludedOUs=$($ouDns -join ','); " +
                       "KeywordRules=$($rules | ConvertTo-Json -Compress); " +
                       "PasswordResetCount=$pwdCount"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Green

            $dialog.DialogResult = $true
            $dialog.Close()
        })

        $btnCancel.Add_Click({
            $dialog.DialogResult = $false
            $dialog.Close()
        })

        $dialog.ShowDialog() | Out-Null
        return $result
    }

    # ==========================
    # Right pane / main content
    # ==========================

    function Update-RightPane($selectedItem) {
        $content = $form.FindName("ContentPanel")
        $content.Children.Clear()

        if ($selectedItem -ne 'Active Directory') {
            $label = New-Object System.Windows.Controls.TextBlock -Property @{
                Text = "$selectedItem - Coming soon..."
                FontSize = 14
            }
            [System.Windows.Controls.Grid]::SetRow($label, 0)
            $content.Children.Add($label) | Out-Null
            return
        }

        # Row 0: command bar (discover)
        $bar = New-Object System.Windows.Controls.StackPanel
        $bar.Orientation = 'Horizontal'
        $bar.Margin = '0,0,0,8'
        [System.Windows.Controls.Grid]::SetRow($bar, 0)

        $discoverBtn = New-Object Wpf.Ui.Controls.Button -Property @{
            Content = 'Start Forest Discovery'
            Tag     = 'DiscoverButton'
        }
        $progress = New-Object System.Windows.Controls.ProgressBar -Property @{
            IsIndeterminate = $true
            Visibility      = 'Collapsed'
            Width           = 200
            Margin          = '12,0,0,0'
        }

        $bar.Children.Add($discoverBtn) | Out-Null
        $bar.Children.Add($progress)    | Out-Null
        $content.Children.Add($bar)     | Out-Null
        $script:progressBar = $progress

        # Row 1: label
        $label = New-Object System.Windows.Controls.TextBlock -Property @{
            Text   = 'Discovered Domain Controllers:'
            Margin = '0,0,0,6'
        }
        [System.Windows.Controls.Grid]::SetRow($label, 1)
        $content.Children.Add($label) | Out-Null

        # Row 2: ListView of DCs
        $list = New-Object System.Windows.Controls.ListView
        $list.Margin = '0,0,0,12'
        $list.SelectionMode = 'Extended'
        $list.SetValue([System.Windows.Controls.ScrollViewer]::HorizontalScrollBarVisibilityProperty,
                       [System.Windows.Controls.ScrollBarVisibility]::Auto)
        $list.SetValue([System.Windows.Controls.ScrollViewer]::VerticalScrollBarVisibilityProperty,
                       [System.Windows.Controls.ScrollBarVisibility]::Auto)
        [System.Windows.Controls.Grid]::SetRow($list, 2)

        $gv = New-Object System.Windows.Controls.GridView
        $list.View = $gv

        foreach ($name in 'Type', 'Domain', 'FQDN', 'Site', 'NetBIOS', 'PDC', 'GC', 'Online') {
            $col = New-Object System.Windows.Controls.GridViewColumn
            $col.Header = $name
            $col.Width  = [double]::NaN
            $col.DisplayMemberBinding = New-Object System.Windows.Data.Binding($name)
            $gv.Columns.Add($col) | Out-Null
        }

        $content.Children.Add($list) | Out-Null
        $script:domainListView = $list

        # Discovery click handler with current-context-first, then credential dialog
        $discoverBtn.Add_Click({
            $this.IsEnabled = $false
            $this.Content   = "Discovering..."
            $script:progressBar.Visibility = 'Visible'

            try {
                $params = @{}
                if ($WinStyleHidden) {
                    $params['WinStyleHidden'] = $true
                }

                $dcList = $null

                # Check if we appear to be logged on to a domain
                $domainLoggedOn = $env:LOGONSERVER -and $env:USERDNSDOMAIN

                if ($domainLoggedOn) {
                    try {
                        $msg = "Attempting forest discovery using current logon context ($env:USERDOMAIN\$env:USERNAME)."
                        Write-IdentIRLog -Message $msg -TypeName 'Info'
                        Write-Host $msg -ForegroundColor Cyan

                        $dcList = Get-ForestInfo @params
                        if ($dcList) {
                            $dcList = @($dcList)
                        }
                    } catch {
                        $msg = "Initial forest discovery with current logon context failed: $($_.Exception.Message)"
                        Write-IdentIRLog -Message $msg -TypeName 'Warning'
                        Write-Host $msg -ForegroundColor Yellow
                        $dcList = $null
                    }
                }

                # If nothing found or not domain-logged-on, prompt for Enterprise Admin credentials
                if (-not $dcList -or $dcList.Count -eq 0) {
                    $msg = "Forest discovery requires Enterprise Admin credentials. Prompting for credentials."
                    Write-IdentIRLog -Message $msg -TypeName 'Info'
                    Write-Host $msg -ForegroundColor Cyan

                    $cred = Show-AdCredentialDialog
                    if (-not $cred) {
                        $cancelMsg = "Discovery canceled by user (no credentials provided)."
                        Write-IdentIRLog -Message $cancelMsg -TypeName 'Warning'
                        Write-Host $cancelMsg -ForegroundColor Yellow
                        $script:domainListView.ItemsSource = @()
                        $script:domainListView.Items.Refresh()
                        throw $cancelMsg
                    }

                    $params['Credential'] = $cred
                    $dcList = Get-ForestInfo @params
                    if ($dcList) {
                        $dcList = @($dcList)
                    }
                }

                if (-not $dcList -or $dcList.Count -eq 0) {
                    $message = "No domain controllers discovered. Ensure connectivity and Enterprise Admin permissions."
                    Write-IdentIRLog -Message $message -TypeName 'Error'
                    Write-Host $message -ForegroundColor Red
                    $script:domainListView.ItemsSource = @()
                    $script:domainListView.Items.Refresh()
                    throw $message
                }

                $newDcList = foreach ($dc in $dcList) {
                    [PSCustomObject]@{
                        Type                       = $dc.Type
                        Domain                     = $dc.Domain.ToLower()
                        DomainSid                  = $dc.DomainSid
                        Site                       = $dc.Site
                        SamAccountName             = $dc.SamAccountName
                        NetBIOS                    = $dc.NetBIOS
                        Name                       = $dc.NetBIOS
                        FQDN                       = $dc.FQDN
                        IsGC                       = $dc.IsGC
                        IsRODC                     = $dc.IsRODC
                        IPv4Address                = $dc.IPv4Address
                        Online                     = $dc.Online
                        DistinguishedName          = $dc.DistinguishedName
                        ServerReferenceBL          = $dc.ServerReferenceBL
                        IsPdcRoleOwner             = $dc.IsPdcRoleOwner
                        DefaultNamingContext       = $dc.DefaultNamingContext
                        ConfigurationNamingContext = $dc.ConfigurationNamingContext
                        DnsGuid                    = $dc.DnsGuid
                        ForestRootFQDN             = $dc.ForestRootFQDN
                        DomainDn                   = if ($dc.DistinguishedName -match '(DC=.*)$') { $Matches[1] } else { $dc.DefaultNamingContext }
                        PDC                        = $dc.IsPdcRoleOwner
                        GC                         = $dc.IsGC
                    }
                }

                $sorted = @(
                    $newDcList | Sort-Object {
                        switch ($_.Type) {
                            'Forest Root'  { 1 }
                            'Child Domain' { 2 }
                            'Tree Root'    { 3 }
                            default        { 4 }
                        }
                    }, Domain, { -[int]$_.IsPdcRoleOwner }, FQDN
                )

                $observable = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
                foreach ($item in $sorted) {
                    [void]$observable.Add($item)
                }

                $script:domainListView.ItemsSource = $observable
                $script:domainListView.IsEnabled   = $true
                $script:domainListView.Items.Refresh()

                $message = "Discovered $($dcList.Count) domain controllers: $($sorted.FQDN -join ', ')"
                Write-IdentIRLog -Message $message -TypeName 'Info'
                Write-Host $message -ForegroundColor Green
            } catch {
                $message = "Discovery error: $($_.Exception.Message)"
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
                [System.Windows.MessageBox]::Show("Error: $($_.Exception.Message)", "Discovery Error", 'OK', 'Error') | Out-Null
            } finally {
                $this.IsEnabled = $true
                $this.Content   = "Start Forest Discovery"
                $script:progressBar.Visibility = 'Collapsed'
            }
        })

        # Row 3: Tasks header
        $tasksHeader = New-Object System.Windows.Controls.TextBlock -Property @{
            Text      = 'Tasks'
            FontWeight = 'Bold'
            FontSize  = 16
            Margin    = '0,0,0,6'
        }
        [System.Windows.Controls.Grid]::SetRow($tasksHeader, 3)
        $content.Children.Add($tasksHeader) | Out-Null

        # Row 4: Tasks panel
        $tasksPanel = New-Object System.Windows.Controls.Primitives.UniformGrid
        $tasksPanel.Columns = 3
        $tasksPanel.Margin  = '0,0,0,12'
        [System.Windows.Controls.Grid]::SetRow($tasksPanel, 4)
        $content.Children.Add($tasksPanel) | Out-Null

        $tasks = @(
            'Authoritative Sysvol Restore',
            'Built-in Admin Password Reset',
            'Control Plane Disposition',
            'DNS Cleanup',
            'Domain Controller Password Reset',
            'DSRM Password Reset',
            'FSMO Seizure',
            'GMSA Account Rotation',
            'Krbtgt Password Reset',
            'Mass Password Reset',
            'MetaData Cleanup',
            'Trust Password Reset'
        )

        $script:taskToggles = @()
        foreach ($t in $tasks) {
            $chk = New-Object System.Windows.Controls.CheckBox -Property @{
                Content = $t
                Margin  = '0,2,12,2'
            }
            $tasksPanel.Children.Add($chk) | Out-Null
            $script:taskToggles += $chk
        }

        # Row 5: bottom bar (WhatIf, progress, start/exit)
        $bottom = New-Object System.Windows.Controls.Grid
        $bottom.Margin = '0,0,0,8'
        $bottom.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grow = New-Object System.Windows.Controls.ColumnDefinition
        $grow.Width = '*'
        $bottom.ColumnDefinitions.Add($grow) | Out-Null
        $bottom.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        [System.Windows.Controls.Grid]::SetRow($bottom, 5)
        $content.Children.Add($bottom) | Out-Null

        $script:whatIfToggle = New-Object Wpf.Ui.Controls.ToggleSwitch -Property @{
            OffContent = 'Mode: WhatIf'
            OnContent  = 'Mode: Execute'
        }
        $bottom.Children.Add($script:whatIfToggle) | Out-Null

        $script:taskProgressBar = New-Object System.Windows.Controls.ProgressBar -Property @{
            Visibility = 'Collapsed'
            Height     = 18
            Margin     = '12,0,12,0'
        }
        [System.Windows.Controls.Grid]::SetColumn($script:taskProgressBar, 1)
        $bottom.Children.Add($script:taskProgressBar) | Out-Null

        $btnStack = New-Object System.Windows.Controls.StackPanel
        $btnStack.Orientation = 'Horizontal'
        [System.Windows.Controls.Grid]::SetColumn($btnStack, 2)
        $bottom.Children.Add($btnStack) | Out-Null

        $startBtn = New-Object Wpf.Ui.Controls.Button -Property @{
            Content = 'Start'
        }
        $exitBtn = New-Object Wpf.Ui.Controls.Button -Property @{
            Content = 'Exit'
            Margin  = '8,0,0,0'
        }
        $btnStack.Children.Add($startBtn) | Out-Null
        $btnStack.Children.Add($exitBtn)  | Out-Null

        # Row 6: Status text
        $statusBorder = New-Object System.Windows.Controls.Border -Property @{
            CornerRadius   = 4
            Padding        = '8'
            BorderBrush    = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::DimGray))
            BorderThickness = 1
        }
        [System.Windows.Controls.Grid]::SetRow($statusBorder, 6)

        $sv = New-Object System.Windows.Controls.ScrollViewer -Property @{
            VerticalScrollBarVisibility = 'Auto'
            Height = 80
        }
        $script:statusText = New-Object System.Windows.Controls.TextBlock -Property @{
            Text         = ''
            TextWrapping = 'Wrap'
        }
        $sv.Content = $script:statusText
        $statusBorder.Child = $sv
        $content.Children.Add($statusBorder) | Out-Null

        # Start
        $startBtn.Add_Click({
            $allTasks = $script:taskToggles | Where-Object IsChecked | ForEach-Object Content
            $dcs      = @($script:domainListView.Items)

            # Only online DCs are used for tasks
            $onlineDcs  = @($dcs | Where-Object { $_.Online })
            $offlineDcs = @($dcs | Where-Object { -not $_.Online })

            if (-not $onlineDcs -or $onlineDcs.Count -eq 0) {
                $message = "No online domain controllers available. Tasks cannot proceed."
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
                [System.Windows.MessageBox]::Show($message, "Input Error", 'OK', 'Error') | Out-Null
                return
            }

            if ($offlineDcs.Count -gt 0) {
                $skipMsg = "Skipping $($offlineDcs.Count) offline DC(s): $($offlineDcs.FQDN -join ', ')"
                Write-IdentIRLog -Message $skipMsg -TypeName 'Warning'
                Write-Host $skipMsg -ForegroundColor Yellow
            }

            $message = "Available online DCs: $($onlineDcs.FQDN -join ', ')"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Cyan

            # Steps (current user + per-domain + metadata + DNS)
            $metadataCleanupSelected = $allTasks -contains 'MetaData Cleanup'
            $dnsCleanupSelected      = $allTasks -contains 'DNS Cleanup'
            $perDomainTasks = $allTasks | Where-Object { $_ -ne 'MetaData Cleanup' -and $_ -ne 'DNS Cleanup' }

            $totalSteps = 1 + $perDomainTasks.Count
            if ($metadataCleanupSelected) { $totalSteps++ }
            if ($dnsCleanupSelected)      { $totalSteps++ }

            $currentStep = 0
            $script:taskProgressBar.Maximum   = $totalSteps
            $script:taskProgressBar.Value     = 0
            $script:taskProgressBar.Visibility = 'Visible'
            $script:statusText.Text = 'Starting tasks...'

            # ------------------------------------------------------------------
            # Current user password reset: ONLY prompt if pwdLastSet >= 24 hours
            # ------------------------------------------------------------------
            $currentStep++
            $script:taskProgressBar.Value = $currentStep
            $percent = [math]::Round(($currentStep / $totalSteps) * 100, 0)

            $pwdLastSet = Get-CurrentUserPwdLastSet
            $needPrompt = $true

            if ($pwdLastSet) {
                $ageHours = ((Get-Date) - $pwdLastSet).TotalHours
                Write-IdentIRLog -Message ("Current user pwdLastSet={0} (age={1:N1}h)" -f $pwdLastSet, $ageHours) -TypeName 'Info'

                if ($ageHours -lt 24) {
                    # Password changed less than 24h ago -> skip dialog
                    $needPrompt = $false
                    $script:statusText.Text += "`nCurrent User Password Reset: Skipped (pwdLastSet < 24h)"
                }
            } else {
                Write-IdentIRLog -Message "Unable to retrieve pwdLastSet for current user; defaulting to prompting for password reset." -TypeName 'Warning' -ForegroundColor Yellow
            }

            if ($needPrompt) {
                $script:statusText.Text += "`nPrompting for Current User Password Reset ($percent%)"

                $pwdResult = Show-PasswordDialog
                if ($pwdResult.Success) {
                    try {
                        $success = Set-CurrentPassword -Password $pwdResult.Password -Execute:$script:whatIfToggle.IsChecked
                        if ($success) {
                            $message = "Current User Password Reset completed"
                            Write-IdentIRLog -Message $message -TypeName 'Info'
                            Write-Host $message -ForegroundColor Green
                            $script:statusText.Text += "`nCurrent User Password Reset: Success"
                        } else {
                            $message = "Current User Password Reset failed"
                            Write-IdentIRLog -Message $message -TypeName 'Error'
                            Write-Host $message -ForegroundColor Red
                            $script:statusText.Text += "`n$message"
                        }
                    } catch {
                        $message = "Current User Password Reset failed: $($_.Exception.Message)"
                        Write-IdentIRLog -Message $message -TypeName 'Error'
                        Write-Host $message -ForegroundColor Red
                        $script:statusText.Text += "`n$message"
                    }
                } else {
                    $script:statusText.Text += "`nCurrent User Password Reset: Skipped (canceled)"
                }
            }

            # Other tasks
            foreach ($task in $allTasks) {
                $currentStep++
                $script:taskProgressBar.Value = $currentStep
                $percent = [math]::Round(($currentStep / $totalSteps) * 100, 0)
                $script:statusText.Text += "`nRunning: $task ($percent%)"

                try {
                    switch ($task) {
                        'Authoritative Sysvol Restore' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Invoke-SysvolRestore -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Built-in Admin Password Reset' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-BuiltinAdminPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Control Plane Disposition' {
                            $dcInput = @($onlineDcs)
                            if ($script:whatIfToggle.IsChecked) {
                                Invoke-ControlDisposition -IsolatedDCList $dcInput -Execute
                            } else {
                                Invoke-ControlDisposition -IsolatedDCList $dcInput
                            }
                        }
                        'Domain Controller Password Reset' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-DcAccountPassword -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'DNS Cleanup' {
                            Invoke-DNSCleanup -IsolatedDCList $onlineDcs -Execute:$script:whatIfToggle.IsChecked
                        }
                        'DSRM Password Reset' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-DSRMPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'FSMO Seizure' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Invoke-FSMORoleSeizure -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'GMSA Account Rotation' {
                            Set-GMSA -IsolatedDCList $onlineDcs -Execute:$script:whatIfToggle.IsChecked
                        }
                        'Krbtgt Password Reset' {
                            $groups = $onlineDcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-KrbtgtPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Mass Password Reset' {
                            $dialogResult = Show-MassResetDialog
                            if ($dialogResult.Success) {
                                # Clean bool for Invoke-MassPasswordReset's [bool]$Execute
                                $execute        = [bool]$script:whatIfToggle.IsChecked
                                $selectedDomain = $dialogResult.Domain.ToLower()

                                # Only ONLINE DCs for the selected domain
                                $domainDCs      = $onlineDcs | Where-Object { $_.Domain.ToLower() -eq $selectedDomain }

                                if (-not $domainDCs -or $domainDCs.Count -eq 0) {
                                    $message = "No ONLINE domain controllers found for selected domain $selectedDomain. Available online domains: $($onlineDcs.Domain -join ', ')"
                                    Write-IdentIRLog -Message $message -TypeName 'Error'
                                    Write-Host $message -ForegroundColor Red
                                    $script:statusText.Text += "`n$message"
                                    throw $message
                                }

                                # Safely coerce PasswordResetCount
                                $pwdCount = if ($dialogResult.PasswordResetCount) {
                                    [int]$dialogResult.PasswordResetCount
                                } else {
                                    1
                                }

                                $message = "Selected domain: $selectedDomain, ONLINE DCs: $($domainDCs.FQDN -join ', '), PasswordResetCount=$pwdCount"
                                Write-IdentIRLog -Message $message -TypeName 'Info'
                                Write-Host $message -ForegroundColor Cyan

                                Invoke-MassPasswordReset `
                                    -Domain             $selectedDomain `
                                    -ExcludedOUs        $dialogResult.ExcludedOUs `
                                    -KeywordRules       $dialogResult.KeywordRules `
                                    -Execute            $execute `
                                    -IsolatedDCList     $domainDCs `
                                    -PasswordResetCount $pwdCount

                                $script:statusText.Text += "`nMass Password Reset: $(if ($execute) { 'Completed' } else { 'Simulated (WhatIf)' })"
                            } else {
                                $script:statusText.Text += "`nMass Password Reset: Skipped (canceled)"
                            }
                        }
                        'MetaData Cleanup' {
                            Invoke-MetadataCleanup -IsolatedDCList $onlineDcs -Execute:$script:whatIfToggle.IsChecked
                        }
                        'Trust Password Reset' {
                            Invoke-TrustPasswordReset -IsolatedDCList $onlineDcs -Execute:$script:whatIfToggle.IsChecked
                        }
                    }
                } catch {
                    $message = "$task failed: $($_.Exception.Message)"
                    Write-IdentIRLog -Message $message -TypeName 'Error'
                    Write-Host $message -ForegroundColor Red
                    $script:statusText.Text += "`n$message"
                }
            }

            $script:statusText.Text += "`nAll tasks completed."
            $script:taskProgressBar.Visibility = 'Collapsed'
            [System.Windows.MessageBox]::Show("Tasks completed.", "Success", 'OK', 'Information') | Out-Null
        })

        $exitBtn.Add_Click({ $form.Close() })
    }

    Update-RightPane 'Active Directory'

    # NOTE: Auto-discover forest on load intentionally removed.
    # User must click "Start Forest Discovery" to Initiate Discovery of Domains and DCs in Isolation.

    [void]$form.ShowDialog()
    $form = $null
}
