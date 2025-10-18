using System.Configuration;
using System.Data;
using System.Windows;

namespace IronArmour;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Show main window directly with master password setup
        var mainWindow = new MainWindow();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        base.OnExit(e);
        // Ensure all windows are closed
        foreach (Window window in Current.Windows)
        {
            window.Close();
        }
    }
}

