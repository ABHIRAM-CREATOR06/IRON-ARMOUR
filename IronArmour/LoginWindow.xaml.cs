using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;

namespace IronArmour;

public partial class LoginWindow : Window
{
    private VaultService _vaultService;

    public LoginWindow()
    {
        InitializeComponent();
        _vaultService = new VaultService();

        // Start fade-in animation
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.5)));

        // Add Enter key support
        UsernameBox.KeyDown += TextBox_KeyDown;
        PasswordBox.KeyDown += PasswordBox_KeyDown;
        NewUsernameBox.KeyDown += TextBox_KeyDown;
        NewPasswordBox.KeyDown += PasswordBox_KeyDown;
        ConfirmPasswordBox.KeyDown += PasswordBox_KeyDown;

        // Add focus hints
        UsernameBox.GotFocus += (s, e) => ShowHint(UsernameBox.Tag?.ToString() ?? "");
        UsernameBox.LostFocus += (s, e) => ClearHint();
        PasswordBox.GotFocus += (s, e) => ShowHint(PasswordBox.Tag?.ToString() ?? "");
        PasswordBox.LostFocus += (s, e) => ClearHint();
        NewUsernameBox.GotFocus += (s, e) => ShowHint(NewUsernameBox.Tag?.ToString() ?? "");
        NewUsernameBox.LostFocus += (s, e) => ClearHint();
        NewPasswordBox.GotFocus += (s, e) => ShowHint(NewPasswordBox.Tag?.ToString() ?? "");
        NewPasswordBox.LostFocus += (s, e) => ClearHint();
        ConfirmPasswordBox.GotFocus += (s, e) => ShowHint(ConfirmPasswordBox.Tag?.ToString() ?? "");
        ConfirmPasswordBox.LostFocus += (s, e) => ClearHint();
    }

    private void ShowHint(string hint)
    {
        // Could add a tooltip or status text here
    }

    private void ClearHint()
    {
        // Clear any hint display
    }

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        DragMove();
    }

    private void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        var username = UsernameBox.Text;
        var password = PasswordBox.Password;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            ShowStatus("Please fill in all fields", "#dc3545");
            return;
        }

        // This window is no longer used - login system removed
        else
        {
            ShowStatus("Invalid username or password", "#dc3545");
        }
    }

    private void CreateAccountButton_Click(object sender, RoutedEventArgs e)
    {
        // Animate transition to create account form
        var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.2));
        var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.2));

        fadeOut.Completed += (s, e) =>
        {
            LoginForm.Visibility = Visibility.Collapsed;
            CreateAccountForm.Visibility = Visibility.Visible;
            CreateAccountForm.BeginAnimation(OpacityProperty, fadeIn);
        };

        LoginForm.BeginAnimation(OpacityProperty, fadeOut);
    }

    private void CreateAccountSubmit_Click(object sender, RoutedEventArgs e)
    {
        var username = NewUsernameBox.Text;
        var password = NewPasswordBox.Password;
        var confirmPassword = ConfirmPasswordBox.Password;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirmPassword))
        {
            ShowStatus("Please fill in all fields", "#dc3545");
            return;
        }

        if (password != confirmPassword)
        {
            ShowStatus("Passwords do not match", "#dc3545");
            return;
        }

        if (password.Length < 6)
        {
            ShowStatus("Password must be at least 6 characters long", "#dc3545");
            return;
        }

        // Login system removed - this functionality is no longer needed
    }

    private void BackToLoginButton_Click(object sender, RoutedEventArgs e)
    {
        // Animate transition back to login form
        var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromSeconds(0.2));
        var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.2));

        fadeOut.Completed += (s, e) =>
        {
            CreateAccountForm.Visibility = Visibility.Collapsed;
            LoginForm.Visibility = Visibility.Visible;
            LoginForm.BeginAnimation(OpacityProperty, fadeIn);
            StatusTextBlock.Visibility = Visibility.Collapsed;
        };

        CreateAccountForm.BeginAnimation(OpacityProperty, fadeOut);
    }

    private void TextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (LoginForm.Visibility == Visibility.Visible)
            {
                LoginButton_Click(null, null);
            }
            else
            {
                CreateAccountSubmit_Click(null, null);
            }
        }
    }

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (LoginForm.Visibility == Visibility.Visible)
            {
                LoginButton_Click(null, null);
            }
            else
            {
                CreateAccountSubmit_Click(null, null);
            }
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Application.Current.Shutdown();
    }

    private void ShowStatus(string message, string colorHex)
    {
        StatusTextBlock.Text = message;
        StatusTextBlock.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(colorHex);
        StatusTextBlock.Visibility = Visibility.Visible;

        // Auto-hide after 3 seconds
        var timer = new System.Timers.Timer(3000);
        timer.Elapsed += (s, e) =>
        {
            Dispatcher.Invoke(() => StatusTextBlock.Visibility = Visibility.Collapsed);
            timer.Stop();
        };
        timer.Start();
    }
}