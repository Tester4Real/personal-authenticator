using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using PersonalAuthenticator.App.ViewModels;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Security;
using PersonalAuthenticator.Core.Services;
using PersonalAuthenticator.Infrastructure.Backup;
using PersonalAuthenticator.Infrastructure.Clipboard;
using PersonalAuthenticator.Infrastructure.Otp;
using PersonalAuthenticator.Infrastructure.Qr;
using PersonalAuthenticator.Infrastructure.Settings;
using PersonalAuthenticator.Infrastructure.Storage;
using PersonalAuthenticator.Infrastructure.Windows;

namespace PersonalAuthenticator.App;

public partial class App : Application
{
    private readonly ServiceProvider _services;
    private Window? _window;

    public App()
    {
        InitializeComponent();
        var services = new ServiceCollection();
        ConfigureServices(services);
        _services = services.BuildServiceProvider(validateScopes: true);
        UnhandledException += OnUnhandledException;
    }

    public static IServiceProvider Services =>
        ((App)Current)._services;

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = _services.GetRequiredService<MainWindow>();
        _window.Closed += OnWindowClosed;
        _window.Activate();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder =>
        {
#if DEBUG
            builder.AddDebug();
#endif
            builder.SetMinimumLevel(LogLevel.Information);
        });
        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IProvisioningUriParser, ProvisioningUriParser>();
        services.AddSingleton<ITotpGenerator, OtpNetTotpGenerator>();
        services.AddSingleton<DuplicateDetector>();
        services.AddSingleton<IVaultStore, DpapiVaultStore>();
        services.AddSingleton<IVaultService, VaultService>();
        services.AddSingleton<IBackupService, PasswordBackupService>();
        services.AddSingleton<IQrCodeDecoder, LocalQrCodeDecoder>();
        services.AddSingleton<ISecureClipboardService, SecureClipboardService>();
        services.AddSingleton<IUserVerificationService, WindowsUserVerificationService>();
        services.AddSingleton<IAutomaticLockMonitor, WindowsSessionLockMonitor>();
        services.AddSingleton<IAppSettingsStore, JsonAppSettingsStore>();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();
    }

    private async void OnWindowClosed(object sender, WindowEventArgs args)
    {
        try
        {
            await _services.GetRequiredService<ISecureClipboardService>().CancelPendingClearAsync();
            await _services.GetRequiredService<IVaultService>().LockAsync(CancellationToken.None);
        }
        finally
        {
            await _services.DisposeAsync();
        }
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        ILogger<App> logger = _services.GetRequiredService<ILogger<App>>();
        AppLog.UnhandledUiError(logger, args.Exception.GetType().Name);
        args.Handled = false;
    }
}
