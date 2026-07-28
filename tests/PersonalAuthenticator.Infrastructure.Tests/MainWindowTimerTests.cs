namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class MainWindowTimerTests
{
    [Fact]
    public void CountdownTimer_RepeatsAndRefreshesCodesEverySecond()
    {
        string source = File.ReadAllText(FindMainWindowCodeBehind());

        Assert.Contains("_timer.Interval = TimeSpan.FromSeconds(1);", source);
        Assert.Contains("_timer.IsRepeating = true;", source);
        Assert.Contains("_timer.Tick += OnTimerTick;", source);
        Assert.Contains("ViewModel.RefreshCodes();", source);
    }

    private static string FindMainWindowCodeBehind()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(
                directory.FullName,
                "src",
                "PersonalAuthenticator.App",
                "MainWindow.xaml.cs");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("MainWindow.xaml.cs was not found.");
    }
}
