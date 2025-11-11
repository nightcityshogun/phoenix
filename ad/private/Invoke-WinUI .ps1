<#
.SYNOPSIS
Opens the Phoenix WPF console for IR/AD tasks with auto-discovery and WhatIf/Execute control.

.DESCRIPTION
Invoke-WinUI loads a Wpf.Ui window, discovers DCs (Get-ForestInfo), shows them PDC-first,
and lets you run tasks with a toggle: Authoritative SYSVOL, Built-in/DSRM/DC/krbtgt resets,
Control Plane Disposition, DNS Cleanup, FSMO Seizure, GMSA rotation, Mass Password Reset,
Metadata Cleanup, Trust Password Reset. Includes theme toggle and single-instance guard.
- Use -WinStyleHidden to hide the PowerShell console while the UI is open.

.PARAMETER WinStyleHidden
Hide the PowerShell console (windowed UI only).

.EXAMPLE
Invoke-WinUI

.EXAMPLE
Invoke-WinUI -WinStyleHidden

.OUTPUTS
None (modal UI; returns on window close).

.NOTES
Author: NightCityShogun  |  Version: 1.0
Requires: PowerShell 5+/7 (Windows), WPF/.NET, Wpf.Ui.dll, DirectoryServices
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
    $script:domainListView = $null
    $script:progressBar = $null
    $script:taskProgressBar = $null
    $script:statusText = $null
    $script:selectedDCs = @()
    $script:taskToggles = @()
    $script:whatIfToggle = $null
    $script:isProcessing = $false
    $script:menuButtons = @()
    $script:currentTheme = 'Dark'
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
    <StackPanel Grid.Row="0" Grid.Column="0" Orientation="Horizontal" Margin="12,12,0,8">
      <Image x:Name="LogoImage" Width="48" Height="48" Margin="0,4,8,0"/>
      <TextBlock Text="Phoenix" VerticalAlignment="Center" FontWeight="Bold" FontSize="18"/>
    </StackPanel>
    <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,12,8">
      <ui:Button x:Name="ThemeToggle" Content="Light Mode" Width="100" Height="32"/>
    </StackPanel>
    <StackPanel x:Name="MenuPanel" Grid.Row="1" Grid.Column="0" Margin="12,0,12,12"/>
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
    <TextBlock Grid.Row="2" Grid.ColumnSpan="2"
               Text="Copyright Praevia LLC 2025"
               HorizontalAlignment="Center" Margin="0,6,0,10" FontSize="10"/>
  </Grid>
</ui:FluentWindow>
"@
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $form = [Windows.Markup.XamlReader]::Load($reader)
    [Wpf.Ui.Appearance.ApplicationThemeManager]::Apply(
        [Wpf.Ui.Appearance.ApplicationTheme]::Dark,
        [Wpf.Ui.Controls.WindowBackdropType]::None,
        $true
    )
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
    # Menu
    $menuItems = @('Active Directory', 'AWS', 'Executive Dashboards', 'Microsoft Azure', 'UAL Collection', 'Velociraptor')
    $menuPanel = $form.FindName("MenuPanel")
    foreach ($item in $menuItems) {
        $btn = New-Object Wpf.Ui.Controls.Button
        $btn.Content = $item
        $btn.Height = 40
        $btn.Margin = '0,6,0,0'
        $btn.Tag = $item
        $btn.Add_Click({
            $script:menuButtons | ForEach-Object { $_.Appearance = 'Secondary' }
            $this.Appearance = 'Primary'
            Update-RightPane $this.Tag
        })
        if ($item -eq 'Active Directory') { $btn.Appearance = 'Primary' } else { $btn.Appearance = 'Secondary' }
        $menuPanel.Children.Add($btn) | Out-Null
        $script:menuButtons += $btn
    }
    function Show-PasswordDialog {
        $dialog = New-Object System.Windows.Window
        $dialog.Title = "Current User Password Reset"
        $dialog.Width = 420; $dialog.Height = 210
        $dialog.WindowStartupLocation = 'CenterOwner'; $dialog.Owner = $form
        $dialog.ResizeMode = 'NoResize'; $dialog.WindowStyle = 'SingleBorderWindow'
        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = 20
        0..3 | ForEach-Object { $row = New-Object System.Windows.Controls.RowDefinition; $row.Height = 'Auto'; $grid.RowDefinitions.Add($row) | Out-Null }
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grid.Children.Add((New-Object System.Windows.Controls.TextBlock -Property @{Text='New Password:'; Margin='0,0,8,6'})) | Out-Null
        $txtNew = New-Object System.Windows.Controls.PasswordBox
        $txtNew.Margin = '0,0,0,6'
        [System.Windows.Controls.Grid]::SetColumn($txtNew, 1); $grid.Children.Add($txtNew) | Out-Null
        $lbl2 = New-Object System.Windows.Controls.TextBlock -Property @{Text='Confirm Password:'; Margin='0,0,8,6'}
        [System.Windows.Controls.Grid]::SetRow($lbl2, 1); $grid.Children.Add($lbl2) | Out-Null
        $txtConfirm = New-Object System.Windows.Controls.PasswordBox
        [System.Windows.Controls.Grid]::SetRow($txtConfirm, 1); [System.Windows.Controls.Grid]::SetColumn($txtConfirm, 1)
        $grid.Children.Add($txtConfirm) | Out-Null
        $panel = New-Object System.Windows.Controls.StackPanel
        $panel.Orientation = 'Horizontal'; $panel.HorizontalAlignment = 'Right'; $panel.Margin = '0,10,0,0'
        [System.Windows.Controls.Grid]::SetRow($panel, 3); [System.Windows.Controls.Grid]::SetColumnSpan($panel, 2)
        $ok = New-Object System.Windows.Controls.Button -Property @{Content = 'OK'; Width = 80}
        $cancel = New-Object System.Windows.Controls.Button -Property @{Content = 'Cancel'; Width = 80; Margin = '8,0,0,0'}
        $panel.Children.Add($ok) | Out-Null; $panel.Children.Add($cancel) | Out-Null
        $grid.Children.Add($panel) | Out-Null
        $dialog.Content = $grid
        $result = [PSCustomObject]@{ Success = $false; Password = $null }
        $ok.Add_Click({
            if ($txtNew.Password -eq $txtConfirm.Password -and $txtNew.Password.Length -ge 8) {
                $result.Success = $true
                $result.Password = ConvertTo-SecureString $txtNew.Password -AsPlainText -Force
                $dialog.DialogResult = $true; $dialog.Close()
            } else {
                [System.Windows.MessageBox]::Show("Passwords do not match or are too short (min 8 chars).", "Error", 'OK', 'Error')
            }
        })
        $cancel.Add_Click({ $dialog.DialogResult = $false; $dialog.Close() })
        $dialog.ShowDialog() | Out-Null
        return $result
    }
    function Show-MassResetDialog {
        $dialog = New-Object System.Windows.Window
        $dialog.Title = "Mass Password Reset Configuration"
        $dialog.Width = 600; $dialog.Height = 400
        $dialog.WindowStartupLocation = 'CenterOwner'; $dialog.Owner = $form
        $dialog.ResizeMode = 'NoResize'; $dialog.WindowStyle = 'SingleBorderWindow'
        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = 20
        0..4 | ForEach-Object { $row = New-Object System.Windows.Controls.RowDefinition; $row.Height = 'Auto'; $grid.RowDefinitions.Add($row) | Out-Null }
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{Width = '200'})) | Out-Null
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        # Domain
        $lblDomain = New-Object System.Windows.Controls.TextBlock -Property @{Text = 'Select Domain:'; Margin = '0,0,8,6'}
        [System.Windows.Controls.Grid]::SetRow($lblDomain, 0)
        $grid.Children.Add($lblDomain) | Out-Null
        $cmbDomain = New-Object System.Windows.Controls.ComboBox
        [System.Windows.Controls.Grid]::SetRow($cmbDomain, 0); [System.Windows.Controls.Grid]::SetColumn($cmbDomain, 1)
        $uniqueDomains = $script:domainListView.Items | Select-Object -Property Domain -Unique | Sort-Object Domain
        if (-not $uniqueDomains) {
            $message = "No domains available for selection. Ensure forest discovery has completed."
            Write-IdentIRLog -Message $message -TypeName 'Error'
            Write-Host $message -ForegroundColor Red
            [System.Windows.MessageBox]::Show($message, "Error", 'OK', 'Error') | Out-Null
            return [PSCustomObject]@{ Success = $false; Domain = $null; ExcludedOUs = @(); KeywordRules = @() }
        }
        foreach ($dom in $uniqueDomains) {
            $cmbDomain.Items.Add($dom.Domain) | Out-Null
        }
        $grid.Children.Add($cmbDomain) | Out-Null
        # OUs
        $lblOUs = New-Object System.Windows.Controls.TextBlock -Property @{Text = 'Excluded OUs (comma-separated DNs):'; Margin = '0,12,8,6'}
        [System.Windows.Controls.Grid]::SetRow($lblOUs, 1)
        $grid.Children.Add($lblOUs) | Out-Null
        $txtOUs = New-Object System.Windows.Controls.TextBox -Property @{AcceptsReturn = $true; TextWrapping = 'Wrap'; Height = 80; Margin = '0,12,0,0'; VerticalScrollBarVisibility = 'Auto'}
        [System.Windows.Controls.Grid]::SetRow($txtOUs, 1); [System.Windows.Controls.Grid]::SetColumn($txtOUs, 1)
        $grid.Children.Add($txtOUs) | Out-Null
        # Keywords
        $lblKeywords = New-Object System.Windows.Controls.TextBlock -Property @{Text = 'Keyword Exclusions (comma-separated, e.g. startswith:admin,contains:svc):'; Margin = '0,12,8,6'}
        [System.Windows.Controls.Grid]::SetRow($lblKeywords, 2)
        $grid.Children.Add($lblKeywords) | Out-Null
        $txtKeywords = New-Object System.Windows.Controls.TextBox -Property @{AcceptsReturn = $true; TextWrapping = 'Wrap'; Height = 80; Margin = '0,12,0,0'; VerticalScrollBarVisibility = 'Auto'}
        [System.Windows.Controls.Grid]::SetRow($txtKeywords, 2); [System.Windows.Controls.Grid]::SetColumn($txtKeywords, 1)
        $grid.Children.Add($txtKeywords) | Out-Null
        # Note
        $note = New-Object System.Windows.Controls.TextBlock -Property @{Text = 'Note: Users in excluded OUs (including child OUs) and matching any keyword rule on sAMAccountName will be excluded. Special accounts (current user, MSOL, built-in admin, krbtgt, guest) are automatically excluded.'; TextWrapping = 'Wrap'; Margin = '0,12,0,0'}
        [System.Windows.Controls.Grid]::SetRow($note, 3); [System.Windows.Controls.Grid]::SetColumnSpan($note, 2)
        $grid.Children.Add($note) | Out-Null
        # Buttons
        $panel = New-Object System.Windows.Controls.StackPanel -Property @{Orientation = 'Horizontal'; HorizontalAlignment = 'Right'; Margin = '0,20,0,0'}
        [System.Windows.Controls.Grid]::SetRow($panel, 4); [System.Windows.Controls.Grid]::SetColumnSpan($panel, 2)
        $start = New-Object Wpf.Ui.Controls.Button -Property @{Content = 'Start Reset'; Width = 120}
        $cancel = New-Object System.Windows.Controls.Button -Property @{Content = 'Cancel'; Width = 80; Margin = '8,0,0,0'}
        $panel.Children.Add($start) | Out-Null
        $panel.Children.Add($cancel) | Out-Null
        $grid.Children.Add($panel) | Out-Null
        $dialog.Content = $grid
        $result = [PSCustomObject]@{ Success = $false; Domain = $null; ExcludedOUs = @(); KeywordRules = @() }
        $start.Add_Click({
            if (-not $cmbDomain.SelectedItem) {
                $message = "No domain selected. Please select a domain."
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
                [System.Windows.MessageBox]::Show($message, "Error", 'OK', 'Error') | Out-Null
                return
            }
            $ous = if ($txtOUs.Text) { $txtOUs.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } } else { @() }
            $keys = if ($txtKeywords.Text) { $txtKeywords.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } } else { @() }
            $rules = @()
            foreach ($key in $keys) {
                if ($key -match '^(\w+):(.*)$') {
                    $rules += @{ Type = $matches[1].Trim(); Value = $matches[2].Trim() }
                } else {
                    $message = "Invalid keyword format: $key. Use type:value (e.g., startswith:admin)"
                    Write-IdentIRLog -Message $message -TypeName 'Error'
                    Write-Host $message -ForegroundColor Red
                    [System.Windows.MessageBox]::Show($message, "Error", 'OK', 'Error') | Out-Null
                    return
                }
            }
            $result.Domain = $cmbDomain.SelectedItem.ToString().ToLower()
            $result.ExcludedOUs = $ous
            $result.KeywordRules = $rules
            $result.Success = $true
            $message = "Mass Password Reset configured: Domain=$($result.Domain), ExcludedOUs=$($ous -join ','), KeywordRules=$($rules | ConvertTo-Json -Compress)"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Green
            $dialog.Close()
        })
        $cancel.Add_Click({ $dialog.Close() })
        $dialog.ShowDialog() | Out-Null
        return $result
    }
    function Update-RightPane($selectedItem) {
        $content = $form.FindName("ContentPanel")
        $content.Children.Clear()
        if ($selectedItem -ne 'Active Directory') {
            $label = New-Object System.Windows.Controls.TextBlock -Property @{ Text = "$selectedItem - Coming soon..."; FontSize = 14 }
            [System.Windows.Controls.Grid]::SetRow($label, 0)
            $content.Children.Add($label) | Out-Null
            return
        }
        # Row 0: command bar
        $bar = New-Object System.Windows.Controls.StackPanel
        $bar.Orientation = 'Horizontal'
        $bar.Margin = '0,0,0,8'
        [System.Windows.Controls.Grid]::SetRow($bar, 0)
        $discoverBtn = New-Object Wpf.Ui.Controls.Button -Property @{ Content = 'Refresh Forest Discovery'; Tag = 'DiscoverButton' }
        $progress = New-Object System.Windows.Controls.ProgressBar -Property @{ IsIndeterminate = $true; Visibility = 'Collapsed'; Width = 200; Margin = '12,0,0,0' }
        $bar.Children.Add($discoverBtn) | Out-Null
        $bar.Children.Add($progress) | Out-Null
        $content.Children.Add($bar) | Out-Null
        $script:progressBar = $progress
        $label = New-Object System.Windows.Controls.TextBlock -Property @{
            Text = 'Discovered Domain Controllers:'
            Margin = '0,0,0,6'
        }
        [System.Windows.Controls.Grid]::SetRow($label, 1)
        $content.Children.Add($label) | Out-Null
        $list = New-Object System.Windows.Controls.ListView
        $list.Margin = '0,0,0,12'
        $list.SelectionMode = 'Extended'
        $list.SetValue([System.Windows.Controls.ScrollViewer]::HorizontalScrollBarVisibilityProperty, [System.Windows.Controls.ScrollBarVisibility]::Auto)
        $list.SetValue([System.Windows.Controls.ScrollViewer]::VerticalScrollBarVisibilityProperty, [System.Windows.Controls.ScrollBarVisibility]::Auto)
        [System.Windows.Controls.Grid]::SetRow($list, 2)
        $gv = New-Object System.Windows.Controls.GridView
        $list.View = $gv
        foreach ($name in 'Type', 'Domain', 'FQDN', 'Site', 'NetBIOS', 'PDC', 'GC', 'Online') {
            $col = New-Object System.Windows.Controls.GridViewColumn
            $col.Header = $name
            $col.Width = [double]::NaN
            $col.DisplayMemberBinding = New-Object System.Windows.Data.Binding($name)
            $gv.Columns.Add($col) | Out-Null
        }
        $content.Children.Add($list) | Out-Null
        $script:domainListView = $list
        # Discovery click
        $discoverBtn.Add_Click({
            $this.IsEnabled = $false
            $this.Content = "Discovering..."
            $script:progressBar.Visibility = 'Visible'
            try {
                $params = @{}; if ($WinStyleHidden) { $params['WinStyleHidden'] = $true }
                $dcList = Get-ForestInfo @params
                $dcList = @($dcList) # Ensure array even if single object
                if (-not $dcList -or $dcList.Count -eq 0) {
                    $message = "No domain controllers discovered."
                    Write-IdentIRLog -Message $message -TypeName 'Error'
                    Write-Host $message -ForegroundColor Red
                    $script:domainListView.ItemsSource = @()
                    $script:domainListView.Items.Refresh()
                    throw $message
                }
                $newDcList = foreach ($dc in $dcList) {
                    [PSCustomObject]@{
                        Type = $dc.Type
                        Domain = $dc.Domain.ToLower() # Normalize to lowercase
                        DomainSid = $dc.DomainSid
                        Site = $dc.Site
                        SamAccountName = $dc.SamAccountName
                        NetBIOS = $dc.NetBIOS
                        Name = $dc.NetBIOS
                        FQDN = $dc.FQDN
                        IsGC = $dc.IsGC
                        IsRODC = $dc.IsRODC
                        IPv4Address = $dc.IPv4Address
                        Online = $dc.Online
                        DistinguishedName = $dc.DistinguishedName
                        ServerReferenceBL = $dc.ServerReferenceBL
                        IsPdcRoleOwner = $dc.IsPdcRoleOwner
                        DefaultNamingContext = $dc.DefaultNamingContext
                        ConfigurationNamingContext = $dc.ConfigurationNamingContext
                        DnsGuid = $dc.DnsGuid
                        ForestRootFQDN = $dc.ForestRootFQDN
                        DomainDn = if ($dc.DistinguishedName -match '(DC=.*)$') { $Matches[1] } else { $dc.DefaultNamingContext }
                        PDC = $dc.IsPdcRoleOwner
                        GC = $dc.IsGC
                    }
                }
                # Sort with stable keys
                $sorted = @($newDcList | Sort-Object {
                    switch ($_.Type) {
                        'Forest Root' { 1 }
                        'Child Domain' { 2 }
                        'Tree Root' { 3 }
                        default { 4 }
                    }
                }, Domain, { -[int]$_.IsPdcRoleOwner }, FQDN)
                # Bind via ObservableCollection
                $observable = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
                foreach ($item in $sorted) { [void]$observable.Add($item) }
                $script:domainListView.ItemsSource = $observable
                $script:domainListView.IsEnabled = $true
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
                $this.Content = "Refresh Forest Discovery"
                $script:progressBar.Visibility = 'Collapsed'
            }
        })
        $tasksHeader = New-Object System.Windows.Controls.TextBlock -Property @{ Text = 'Tasks'; FontWeight = 'Bold'; FontSize = 16; Margin = '0,0,0,6' }
        [System.Windows.Controls.Grid]::SetRow($tasksHeader, 3)
        $content.Children.Add($tasksHeader) | Out-Null
        $tasksPanel = New-Object System.Windows.Controls.Primitives.UniformGrid
        $tasksPanel.Columns = 3
        $tasksPanel.Margin = '0,0,0,12'
        [System.Windows.Controls.Grid]::SetRow($tasksPanel, 4)
        $content.Children.Add($tasksPanel) | Out-Null
        $tasks = @(
            'Authoritative Sysvol Restore', 'Built-in Admin Password Reset', 'Control Plane Disposition', 'DNS Cleanup',
            'Domain Controller Password Reset', 'DSRM Password Reset', 'FSMO Seizure', 'GMSA Account Rotation',
            'Krbtgt Password Reset', 'Mass Password Reset', 'MetaData Cleanup', 'Trust Password Reset'
        )
        $script:taskToggles = @()
        foreach ($t in $tasks) {
            $chk = New-Object System.Windows.Controls.CheckBox -Property @{ Content = $t; Margin = '0,2,12,2' }
            $tasksPanel.Children.Add($chk) | Out-Null
            $script:taskToggles += $chk
        }
        # Row 5: bottom bar
        $bottom = New-Object System.Windows.Controls.Grid
        $bottom.Margin = '0,0,0,8'
        $bottom.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        $grow = New-Object System.Windows.Controls.ColumnDefinition; $grow.Width = '*'
        $bottom.ColumnDefinitions.Add($grow) | Out-Null
        $bottom.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition)) | Out-Null
        [System.Windows.Controls.Grid]::SetRow($bottom, 5)
        $content.Children.Add($bottom) | Out-Null
        $script:whatIfToggle = New-Object Wpf.Ui.Controls.ToggleSwitch -Property @{
            OffContent = 'Mode: WhatIf'; OnContent = 'Mode: Execute'
        }
        $bottom.Children.Add($script:whatIfToggle) | Out-Null
        $script:taskProgressBar = New-Object System.Windows.Controls.ProgressBar -Property @{ Visibility = 'Collapsed'; Height = 18; Margin = '12,0,12,0' }
        [System.Windows.Controls.Grid]::SetColumn($script:taskProgressBar, 1)
        $bottom.Children.Add($script:taskProgressBar) | Out-Null
        $btnStack = New-Object System.Windows.Controls.StackPanel
        $btnStack.Orientation = 'Horizontal'
        [System.Windows.Controls.Grid]::SetColumn($btnStack, 2)
        $startBtn = New-Object Wpf.Ui.Controls.Button -Property @{ Content = 'Start' }
        $exitBtn = New-Object Wpf.Ui.Controls.Button -Property @{ Content = 'Exit'; Margin = '8,0,0,0' }
        $btnStack.Children.Add($startBtn) | Out-Null
        $btnStack.Children.Add($exitBtn) | Out-Null
        $bottom.Children.Add($btnStack) | Out-Null
        # Row 6: status (scrollable)
        $statusBorder = New-Object System.Windows.Controls.Border -Property @{
            CornerRadius = 4; Padding = '8';
            BorderBrush = (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Colors]::DimGray));
            BorderThickness = 1
        }
        [System.Windows.Controls.Grid]::SetRow($statusBorder, 6)
        $sv = New-Object System.Windows.Controls.ScrollViewer -Property @{ VerticalScrollBarVisibility = 'Auto'; Height = 80 }
        $script:statusText = New-Object System.Windows.Controls.TextBlock -Property @{ Text = ''; TextWrapping = 'Wrap' }
        $sv.Content = $script:statusText
        $statusBorder.Child = $sv
        $content.Children.Add($statusBorder) | Out-Null
        # Start
        $startBtn.Add_Click({
            $allTasks = $script:taskToggles | Where-Object IsChecked | ForEach-Object Content
            $dcs = $script:domainListView.Items
            if (-not $dcs -or $dcs.Count -eq 0) {
                $message = "No domain controllers discovered."
                Write-IdentIRLog -Message $message -TypeName 'Error'
                Write-Host $message -ForegroundColor Red
                [System.Windows.MessageBox]::Show($message, "Input Error", 'OK', 'Error')
                return
            }
            $message = "Available DCs: $($dcs.FQDN -join ', ')"
            Write-IdentIRLog -Message $message -TypeName 'Info'
            Write-Host $message -ForegroundColor Cyan
            # Calculate total steps
            $metadataCleanupSelected = $allTasks -contains 'MetaData Cleanup'
            $dnsCleanupSelected = $allTasks -contains 'DNS Cleanup'
            $perDomainTasks = $allTasks | Where-Object { $_ -ne 'MetaData Cleanup' -and $_ -ne 'DNS Cleanup' }
            $totalSteps = 1 + $perDomainTasks.Count # Include Set-CurrentPassword as one step
            $totalSteps += if ($metadataCleanupSelected) { 1 } else { 0 }
            $totalSteps += if ($dnsCleanupSelected) { 1 } else { 0 }
            $currentStep = 0
            $script:taskProgressBar.Maximum = $totalSteps
            $script:taskProgressBar.Value = 0
            $script:taskProgressBar.Visibility = 'Visible'
            $script:statusText.Text = 'Starting tasks...'
            # Always run Set-CurrentPassword
            $currentStep++
            $script:taskProgressBar.Value = $currentStep
            $script:statusText.Text += "`nPrompting for Current User Password Reset ($([math]::Round(($currentStep/$totalSteps)*100))%)"
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
            # Process other tasks
            foreach ($task in $allTasks) {
                $currentStep++
                $script:taskProgressBar.Value = $currentStep
                $percent = [math]::Round(($currentStep / $totalSteps) * 100, 0)
                $script:statusText.Text += "`nRunning: $task ($percent%)"
                try {
                    switch ($task) {
                        'Authoritative Sysvol Restore' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Invoke-SysvolRestore -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Built-in Admin Password Reset' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-BuiltinAdminPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Control Plane Disposition' {
                            $dcInput = @($dcs)
                            if ($script:whatIfToggle.IsChecked) {
                                Invoke-ControlDisposition -IsolatedDCList $dcInput -Execute
                            } else {
                                Invoke-ControlDisposition -IsolatedDCList $dcInput
                            }
                        }
                        'Domain Controller Password Reset' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-DcAccountPassword -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'DNS Cleanup' {
                            Invoke-DNSCleanup -IsolatedDCList $dcs -Execute:$script:whatIfToggle.IsChecked
                        }
                        'DSRM Password Reset' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-DSRMPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'FSMO Seizure' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Invoke-FSMORoleSeizure -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'GMSA Account Rotation' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-GMSA -IsolatedDCList $group.Group -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Krbtgt Password Reset' {
                            $groups = $dcs | Group-Object Domain
                            foreach ($group in $groups) {
                                Set-KrbtgtPassword -IsolatedDCList $group.Group -Length 24 -Execute:$script:whatIfToggle.IsChecked
                            }
                        }
                        'Mass Password Reset' {
                            $dialogResult = Show-MassResetDialog
                            if ($dialogResult.Success) {
                                $execute = $script:whatIfToggle.IsChecked
                                $selectedDomain = $dialogResult.Domain.ToLower()
                                $domainDCs = $dcs | Where-Object { $_.Domain.ToLower() -eq $selectedDomain }
                                if (-not $domainDCs -or $domainDCs.Count -eq 0) {
                                    $message = "No domain controllers found for selected domain $selectedDomain. Available domains: $($dcs.Domain -join ', ')"
                                    Write-IdentIRLog -Message $message -TypeName 'Error'
                                    Write-Host $message -ForegroundColor Red
                                    $script:statusText.Text += "`n$message"
                                    throw $message
                                }
                                $message = "Selected domain: $selectedDomain, DCs: $($domainDCs.FQDN -join ', ')"
                                Write-IdentIRLog -Message $message -TypeName 'Info'
                                Write-Host $message -ForegroundColor Cyan
                                Invoke-MassPasswordReset -Domain $selectedDomain -ExcludedOUs $dialogResult.ExcludedOUs -KeywordRules $dialogResult.KeywordRules -Execute $execute -IsolatedDCList $domainDCs
                                $script:statusText.Text += "`nMass Password Reset: $(if ($execute) { 'Completed' } else { 'Simulated (WhatIf)' })"
                            } else {
                                $script:statusText.Text += "`nMass Password Reset: Skipped (canceled)"
                            }
                        }
                        'MetaData Cleanup' {
                            Invoke-MetadataCleanup -IsolatedDCList $dcs -Execute:$script:whatIfToggle.IsChecked
                        }
                        'Trust Password Reset' {
                            Invoke-TrustPasswordReset -IsolatedDCList $dcs -Execute:$script:whatIfToggle.IsChecked
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
    # Auto-discover on load
    $form.Add_Loaded({
        $contentPanel = $form.FindName("ContentPanel")
        $discoverBtn = ($contentPanel.Children | Where-Object { $_ -is [System.Windows.Controls.StackPanel] })[0].Children |
                       Where-Object { $_.Tag -eq 'DiscoverButton' }
        if ($discoverBtn) {
            $clickEvent = New-Object System.Windows.RoutedEventArgs -ArgumentList ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)
            $discoverBtn.RaiseEvent($clickEvent)
        }
    })
    [void]$form.ShowDialog()
    $form = $null
}

function Set-CurrentPassword {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [System.Management.Automation.PSCredential] $Credential,
        [switch] $Execute,
        [SecureString] $Password
    )
    $oldConfirm = $script:ConfirmPreference
    $script:ConfirmPreference = 'None'
    $oldWhatIf = $WhatIfPreference
    $WhatIfPreference = -not [bool]$Execute
    try {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest
        # Current session identity
        $currentUsername = $env:USERNAME
        if (-not $currentUsername) {
            Write-IdentIRLog -Message 'Unable to determine the currently logged-on username.' -TypeName 'Error' -ForegroundColor Red
            return $false
        }
        # Authenticating DC (LOGONSERVER)
        $logonServerNetBIOS = $env:LOGONSERVER -replace '^\\\\',''
        if (-not $logonServerNetBIOS) {
            Write-IdentIRLog -Message 'Unable to determine the authenticating domain controller (LOGONSERVER).' -TypeName 'Error' -ForegroundColor Red
            return $false
        }
        # FQDN (fallback to NetBIOS)
        try { $logonServerFQDN = [System.Net.Dns]::GetHostEntry($logonServerNetBIOS).HostName }
        catch { $logonServerFQDN = $logonServerNetBIOS; Write-IdentIRLog -Message "FQDN resolution failed for '$logonServerNetBIOS'; using NetBIOS." -TypeName 'Warning' -ForegroundColor Yellow }
        # RootDSE: ensure sync; get domain DN
        $rootDSEPath = "LDAP://$logonServerFQDN/RootDSE"
        $rootDSE = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($rootDSEPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else { [ADSI]$rootDSEPath }
        if ($rootDSE.Properties['isSynchronized'][0] -ne $true) {
            Write-IdentIRLog -Message "Authenticating DC '$logonServerFQDN' is not synchronized." -TypeName 'Error' -ForegroundColor Red
            return $false
        }
        $domainDN = $rootDSE.Properties['defaultNamingContext'][0]
        if (-not $domainDN) {
            Write-IdentIRLog -Message "defaultNamingContext missing on '$logonServerFQDN'." -TypeName 'Error' -ForegroundColor Red
            return $false
        }
        $domainName = ($domainDN -replace 'DC=','' -replace ',', '.')
        Write-IdentIRLog -Message "Identified session: User='$currentUsername', Domain='$domainName', DC='$logonServerFQDN' (WhatIf=$WhatIfPreference)" -TypeName 'Info' -ForegroundColor Cyan
        # Locate current user
        $searchRootPath = "LDAP://$logonServerFQDN/$domainDN"
        $searchRoot = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($searchRootPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else { [ADSI]$searchRootPath }
        $ds = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $ds.Filter = "(&(objectClass=user)(sAMAccountName=$currentUsername))"
        $ds.PageSize = 1
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $res = $ds.FindOne()
        if (-not $res) {
            Write-IdentIRLog -Message "User '$currentUsername' not found in '$domainName'." -TypeName 'Error' -ForegroundColor Red
            return $false
        }
        $userDN = $res.Properties['distinguishedName'][0]
        $userPath = "LDAP://$logonServerFQDN/$userDN"
        $userDE = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry($userPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        } else { [ADSI]$userPath }
        $confirmTarget = "$userDN on $logonServerFQDN"
        # WhatIf: emit native line but don't treat as cancel
        if ($WhatIfPreference) {
            $null = $PSCmdlet.ShouldProcess($confirmTarget, "Reset password for current user")
            Write-IdentIRLog -Message "[WhatIf] Would reset password for '$currentUsername' in '$domainName'." -TypeName 'Info' -ForegroundColor Green
            return $true
        }
        if (-not $PSCmdlet.ShouldProcess($confirmTarget, "Reset password for current user")) {
            Write-IdentIRLog -Message "Operation cancelled." -TypeName 'Warning' -ForegroundColor Yellow
            return $false
        }
        $newSecure = $null
        if ($Password) {
            $newSecure = $Password
        } else {
            while ($true) {
                $p1 = Read-Host "Enter a new password for '$currentUsername'" -AsSecureString
                $p2 = Read-Host "Re-enter the new password for '$currentUsername'" -AsSecureString
                $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
                $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
                $s1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b1)
                $s2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b2)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
                if ($s1 -ne $s2) { Write-Warning "Passwords do not match. Try again."; continue }
                $newSecure = $p1
                # Clear plaintext copies
                $s1 = $null; $s2 = $null
                break
            }
        }
        # Convert to plaintext ONLY for the call, then zero it
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($newSecure)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($b)
        $ok = $false
        for ($i=1; $i -le 2; $i++) {
            try {
                # IMPORTANT: Invoke SetPassword with a *string* argument
                $userDE.psbase.Invoke('SetPassword', @($plain))
                # Optional but harmless:
                $userDE.CommitChanges()
                $ok = $true
                break
            } catch {
                if ($i -eq 2) {
                    Write-IdentIRLog -Message "Password reset failed for '$currentUsername' on '$logonServerFQDN': $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
                    return $false
                }
                Start-Sleep -Milliseconds 400
            }
        }
        if ($b) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
        $plain = $null
        # Purge Kerberos tickets (best-effort)
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'klist'
            $psi.Arguments = 'purge'
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.CreateNoWindow = $true
            $p = [System.Diagnostics.Process]::Start($psi); $p.WaitForExit(); $p.Dispose()
            Write-IdentIRLog -Message 'Kerberos tickets purged.' -TypeName 'Info' -ForegroundColor Gray
        } catch {
            Write-IdentIRLog -Message 'Kerberos ticket purge encountered a non-critical error.' -TypeName 'Warning' -ForegroundColor Yellow
        }
        Write-IdentIRLog -Message "Password reset completed for '$currentUsername' in '$domainName'." -TypeName 'Info' -ForegroundColor Green
        return $true
    }
    catch {
        Write-IdentIRLog -Message "Set-CurrentPassword error: $($_.Exception.Message)" -TypeName 'Error' -ForegroundColor Red
        return $false
    }
    finally {
        $script:ConfirmPreference = $oldConfirm
        $WhatIfPreference = $oldWhatIf
    }
}
