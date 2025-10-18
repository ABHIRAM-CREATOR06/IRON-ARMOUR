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

        if (password.Length < 6)
        {
            ShowStatus("Master password must be at least 6 characters long", Brushes.Red);
            return;
        }

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