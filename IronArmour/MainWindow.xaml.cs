using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace IronArmour;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window, INotifyPropertyChanged
{
    private VaultService? _vaultService;
    private SyncManager? _syncManager;
    private SyncSettings _syncSettings;
    private Visibility _masterPasswordVisibility = Visibility.Visible;
    private Visibility _mainContentVisibility = Visibility.Collapsed;
    private Visibility _statusVisibility = Visibility.Collapsed;
    private string _statusMessage = "";
    private Brush _statusColor = Brushes.Green;

    public Visibility MasterPasswordVisibility
    {
        get => _masterPasswordVisibility;
        set { _masterPasswordVisibility = value; OnPropertyChanged(); }
    }

    public Visibility MainContentVisibility
    {
        get => _mainContentVisibility;
        set { _mainContentVisibility = value; OnPropertyChanged(); }
    }

    public Visibility StatusVisibility
    {
        get => _statusVisibility;
        set { _statusVisibility = value; OnPropertyChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public Brush StatusColor
    {
        get => _statusColor;
        set { _statusColor = value; OnPropertyChanged(); }
    }

    public ObservableCollection<string> Accounts { get; } = new();
    public ObservableCollection<WifiEntry> WifiEntries { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _vaultService = new VaultService();

        // Load sync settings
        LoadSyncSettings();

        // Add password strength monitoring
        PasswordBox.PasswordChanged += PasswordBox_PasswordChanged;

        // Always show master password setup first - no auto-verification
        MasterPasswordVisibility = Visibility.Visible;
        MainContentVisibility = Visibility.Collapsed;
    }

    // Removed the second constructor that was causing double-loading

    private void SetMasterPassword_Click(object sender, RoutedEventArgs e)
    {
        SetMasterPassword();
    }

    private void MasterPasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            SetMasterPassword();
        }
    }

    private void SetMasterPassword()
    {
        var password = MasterPasswordBox.Password;
        if (string.IsNullOrEmpty(password))
        {
            ShowStatus("Please enter a master password", Brushes.Red);
            return;
        }

        // Remove demo restriction - allow any password

        if (_vaultService.SetMasterPassword(password))
        {
            MasterPasswordVisibility = Visibility.Collapsed;
            MainContentVisibility = Visibility.Visible;
            ShowStatus("Master password set successfully!", Brushes.Green);
        }
        else
        {
            ShowStatus("Failed to set master password", Brushes.Red);
        }
    }

    private void AddPassword_Click(object sender, RoutedEventArgs e)
    {
        var account = AccountNameBox.Text;
        var password = PasswordBox.Password;

        if (string.IsNullOrEmpty(account) || string.IsNullOrEmpty(password))
        {
            ShowStatus("Please fill in all fields", Brushes.Red);
            return;
        }

        if (_vaultService.AddPassword(account, password))
        {
            ShowStatus("Password added successfully!", Brushes.Green);
            AccountNameBox.Text = "";
            PasswordBox.Password = "";
        }
        else
        {
            ShowStatus("Failed to add password. Make sure master password is set.", Brushes.Red);
        }
    }

    private void ListAccounts_Click(object sender, RoutedEventArgs e)
    {
        Accounts.Clear();
        var accounts = _vaultService.ListAccounts();
        foreach (var account in accounts)
        {
            Accounts.Add(account);
        }
        AccountsListBox.ItemsSource = Accounts;
    }

    private void ViewPassword_Click(object sender, RoutedEventArgs e)
    {
        var account = (sender as Button)?.Tag as string;
        if (account != null)
        {
            var password = _vaultService.GetPassword(account);
            if (password != null)
            {
                ShowStatus($"Password for {account}: {password}", Brushes.Green);
            }
            else
            {
                ShowStatus("Failed to retrieve password", Brushes.Red);
            }
        }
    }

    private void GenerateOtp_Click(object sender, RoutedEventArgs e)
    {
        var account = OtpAccountBox.Text;
        var username = OtpUsernameBox.Text;
        var secret = OtpSecretBox.Password;
        var lengthText = OtpLengthBox.Text;

        if (string.IsNullOrEmpty(account) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(secret))
        {
            ShowStatus("Please fill in all fields", Brushes.Red);
            return;
        }

        if (!int.TryParse(lengthText, out var length) || length < 8 || length > 32)
        {
            ShowStatus("Password length must be between 8 and 32", Brushes.Red);
            return;
        }

        var otpPassword = _vaultService.GenerateOtp(account, username, secret, length);
        OtpResultText.Text = otpPassword;
        OtpResultText.Visibility = Visibility.Visible;
        ShowStatus("OTP password generated successfully!", Brushes.Green);
    }

    private void AnalyzeWifi_Click(object sender, RoutedEventArgs e)
    {
        WifiEntries.Clear();
        var wifiData = _vaultService.AnalyzeWifi();
        foreach (var (ssid, password, strength) in wifiData)
        {
            WifiEntries.Add(new WifiEntry { Ssid = ssid, Password = password, Strength = strength });
        }
        WifiListBox.ItemsSource = WifiEntries;
    }

    private void ExportWifiPdfReport_Click(object sender, RoutedEventArgs e)
    {
        var wifiData = _vaultService.AnalyzeWifi();
        if (wifiData.Count == 0)
        {
            ShowStatus("No Wi-Fi data to export", Brushes.Orange);
            return;
        }

        var saveDialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF Files (*.pdf)|*.pdf",
            DefaultExt = "pdf",
            FileName = $"WiFi_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                ReportGenerator.GenerateWifiReportPdf(wifiData, saveDialog.FileName);
                ShowStatus("Wi-Fi PDF report exported successfully!", Brushes.Green);
                ReportGenerator.OpenFile(saveDialog.FileName);
            }
            catch (Exception ex)
            {
                ShowStatus($"Failed to export PDF: {ex.Message}", Brushes.Red);
            }
        }
    }

    private void ExportWifiCsvReport_Click(object sender, RoutedEventArgs e)
    {
        var wifiData = _vaultService.AnalyzeWifi();
        if (wifiData.Count == 0)
        {
            ShowStatus("No Wi-Fi data to export", Brushes.Orange);
            return;
        }

        var saveDialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV Files (*.csv)|*.csv",
            DefaultExt = "csv",
            FileName = $"WiFi_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                ReportGenerator.GenerateWifiReportCsv(wifiData, saveDialog.FileName);
                ShowStatus("Wi-Fi CSV report exported successfully!", Brushes.Green);
                ReportGenerator.OpenFile(saveDialog.FileName);
            }
            catch (Exception ex)
            {
                ShowStatus($"Failed to export CSV: {ex.Message}", Brushes.Red);
            }
        }
    }

    private void ExportPasswordStrengthPdfReport_Click(object sender, RoutedEventArgs e)
    {
        var accounts = _vaultService.ListAccounts();
        if (accounts.Count == 0)
        {
            ShowStatus("No password data to export", Brushes.Orange);
            return;
        }

        var saveDialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "PDF Files (*.pdf)|*.pdf",
            DefaultExt = "pdf",
            FileName = $"Password_Strength_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                ReportGenerator.GeneratePasswordStrengthReportPdf(accounts, _vaultService, saveDialog.FileName);
                ShowStatus("Password strength PDF report exported successfully!", Brushes.Green);
                ReportGenerator.OpenFile(saveDialog.FileName);
            }
            catch (Exception ex)
            {
                ShowStatus($"Failed to export PDF: {ex.Message}", Brushes.Red);
            }
        }
    }

    private void ExportPasswordStrengthCsvReport_Click(object sender, RoutedEventArgs e)
    {
        var accounts = _vaultService.ListAccounts();
        if (accounts.Count == 0)
        {
            ShowStatus("No password data to export", Brushes.Orange);
            return;
        }

        var saveDialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "CSV Files (*.csv)|*.csv",
            DefaultExt = "csv",
            FileName = $"Password_Strength_Report_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                ReportGenerator.GeneratePasswordStrengthReportCsv(accounts, _vaultService, saveDialog.FileName);
                ShowStatus("Password strength CSV report exported successfully!", Brushes.Green);
                ReportGenerator.OpenFile(saveDialog.FileName);
            }
            catch (Exception ex)
            {
                ShowStatus($"Failed to export CSV: {ex.Message}", Brushes.Red);
            }
        }
    }

    private void ShowStatus(string message, Brush color)
    {
        StatusMessage = message;
        StatusColor = color;
        StatusVisibility = Visibility.Visible;

        var timer = new System.Timers.Timer(5000);
        timer.Elapsed += (s, e) => { Dispatcher.Invoke(() => StatusVisibility = Visibility.Collapsed); timer.Stop(); };
        timer.Start();
    }

    private void TextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (MasterPasswordVisibility == Visibility.Visible)
            {
                SetMasterPassword_Click(null, null);
            }
            else if (MainTabControl.SelectedIndex == 0) // Add Password tab
            {
                AddPassword_Click(null, null);
            }
            else if (MainTabControl.SelectedIndex == 2) // OTP tab
            {
                GenerateOtp_Click(null, null);
            }
        }
    }

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (MasterPasswordVisibility == Visibility.Visible)
            {
                SetMasterPassword_Click(null, null);
            }
            else if (MainTabControl.SelectedIndex == 0) // Add Password tab
            {
                AddPassword_Click(null, null);
            }
            else if (MainTabControl.SelectedIndex == 2) // OTP tab
            {
                GenerateOtp_Click(null, null);
            }
        }
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password;
        if (string.IsNullOrEmpty(password))
        {
            PasswordStrengthIndicator.Visibility = Visibility.Collapsed;
            return;
        }

        var strength = EvaluatePasswordStrength(password);
        PasswordStrengthIndicator.Visibility = Visibility.Visible;

        var (text, color) = strength switch
        {
            "Strong" => ("Strong Password ✓", "#00FF00"),
            "Medium" => ("Medium Password ⚠", "#FFA500"),
            "Weak" => ("Weak Password ✗", "#FF0000"),
            _ => ("Unknown", "#FFFFFF")
        };

        PasswordStrengthIndicator.Text = text;
        PasswordStrengthIndicator.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(color);
    }

    private string EvaluatePasswordStrength(string password)
    {
        if (string.IsNullOrEmpty(password)) return "Weak";

        var score = 0;
        if (password.Length >= 8) score++;
        if (password.Length >= 12) score++;
        if (password.Any(char.IsUpper)) score++;
        if (password.Any(char.IsLower)) score++;
        if (password.Any(char.IsDigit)) score++;
        if (password.Any(ch => !char.IsLetterOrDigit(ch))) score++;

        return score >= 5 ? "Strong" : score >= 3 ? "Medium" : "Weak";
    }

    private void LoadSyncSettings()
    {
        using var context = new VaultContext();
        context.Database.EnsureCreated(); // Ensure database is created with new tables

        var settings = context.SyncSettings.FirstOrDefault();
        if (settings != null)
        {
            // Handle migration for new fields
            if (string.IsNullOrEmpty(settings.DatabaseType))
            {
                settings.DatabaseType = "HTTP";
                settings.MySqlConnectionString = "";
                context.SaveChanges();
            }
            _syncSettings = settings;
        }
        else
        {
            _syncSettings = new SyncSettings();
            context.SyncSettings.Add(_syncSettings);
            context.SaveChanges();
        }

        // Update UI with loaded settings
        Dispatcher.Invoke(() =>
        {
            EnableSyncCheckBox.IsChecked = _syncSettings.IsSyncEnabled;
            ServerUrlBox.Text = _syncSettings.ServerUrl;
            AuthTokenBox.Password = _syncSettings.AuthToken;
            SyncDirectionCombo.SelectedIndex = (int)_syncSettings.SyncDirection;
            AutoSyncCheckBox.IsChecked = _syncSettings.AutoSyncEnabled;
            SyncIntervalBox.Text = _syncSettings.SyncIntervalMinutes.ToString();
            ExcludedAccountsBox.Text = string.Join(", ", _syncSettings.ExcludedAccounts);
            UpdateSyncStatus();
        });
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        _syncSettings.IsSyncEnabled = EnableSyncCheckBox.IsChecked ?? false;
        _syncSettings.ServerUrl = ServerUrlBox.Text;
        _syncSettings.AuthToken = AuthTokenBox.Password;
        _syncSettings.SyncDirection = (SyncDirection)SyncDirectionCombo.SelectedIndex;
        _syncSettings.AutoSyncEnabled = AutoSyncCheckBox.IsChecked ?? false;

        if (int.TryParse(SyncIntervalBox.Text, out var interval))
        {
            _syncSettings.SyncIntervalMinutes = interval;
        }

        _syncSettings.ExcludedAccounts = ExcludedAccountsBox.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        using var context = new VaultContext();
        var existing = context.SyncSettings.FirstOrDefault();
        if (existing == null)
        {
            context.SyncSettings.Add(_syncSettings);
        }
        else
        {
            existing.IsSyncEnabled = _syncSettings.IsSyncEnabled;
            existing.ServerUrl = _syncSettings.ServerUrl;
            existing.AuthToken = _syncSettings.AuthToken;
            existing.SyncDirection = _syncSettings.SyncDirection;
            existing.AutoSyncEnabled = _syncSettings.AutoSyncEnabled;
            existing.SyncIntervalMinutes = _syncSettings.SyncIntervalMinutes;
            existing.ExcludedAccounts = _syncSettings.ExcludedAccounts;
        }
        context.SaveChanges();

        // Reinitialize sync manager with new settings
        InitializeSyncManager();

        ShowStatus("Settings saved successfully!", Brushes.Green);
    }

    private void InitializeSyncManager()
    {
        if (_vaultService?.CurrentUser == null) return;

        ISyncProvider syncProvider;
        if (_syncSettings.DatabaseType == "MySQL")
        {
            syncProvider = new MySqlSyncProvider(_syncSettings.ServerUrl, _syncSettings.AuthToken);
        }
        else
        {
            syncProvider = new HttpSyncProvider(_syncSettings.ServerUrl, _syncSettings.AuthToken);
        }

        _syncManager = new SyncManager(_vaultService.Context, syncProvider, _syncSettings, _vaultService.CurrentUser);
    }

    private async void TestConnection_Click(object sender, RoutedEventArgs e)
    {
        if (_syncManager == null)
        {
            InitializeSyncManager();
        }

        if (_syncManager == null)
        {
            ShowStatus("Unable to initialize sync manager", Brushes.Red);
            return;
        }

        var success = await _syncManager.TestConnectionAsync();
        UpdateSyncStatus();

        if (success)
        {
            ShowStatus("Connection test successful!", Brushes.Green);
        }
        else
        {
            ShowStatus("Connection test failed. Check server URL and network.", Brushes.Red);
        }
    }

    private async void SyncNow_Click(object sender, RoutedEventArgs e)
    {
        if (_syncManager == null)
        {
            InitializeSyncManager();
        }

        if (_syncManager == null)
        {
            ShowStatus("Unable to initialize sync manager", Brushes.Red);
            return;
        }

        var response = await _syncManager.PerformSyncAsync();
        UpdateSyncStatus();

        if (response.Success)
        {
            ShowStatus($"Sync completed successfully! Processed {response.ServerPasswords.Count} items.", Brushes.Green);
        }
        else
        {
            ShowStatus($"Sync failed: {response.Message}", Brushes.Red);
        }
    }

    private void UpdateSyncStatus()
    {
        if (_syncManager?.Status == null) return;

        var status = _syncManager.Status;
        var statusColor = status.CurrentState switch
        {
            SyncState.Success => "#00FF00",
            SyncState.Error => "#FF0000",
            SyncState.Conflict => "#FFA500",
            SyncState.Syncing => "#FFFF00",
            _ => "#FFFFFF"
        };

        Dispatcher.Invoke(() =>
        {
            SyncStatusText.Text = $"Sync Status: {status.StatusMessage}";
            SyncStatusText.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(statusColor);
        });
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        // Close main window
        this.Close();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public class WifiEntry
{
    public string Ssid { get; set; } = "";
    public string Password { get; set; } = "";
    public string Strength { get; set; } = "";
    public Brush StrengthColor => Strength == "Strong" ? Brushes.Green : Brushes.Red;
}