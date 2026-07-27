using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Windowing;
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
    private MainWindow? _window;
    private Task? _shutdownTask;
    private bool _shutdownComplete;

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
        _window.AppWindow.Closing += OnWindowClosing;
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
        services.AddSingleton<VersionedVaultStore>();
        services.AddSingleton<IVaultStore>(
            provider => provider.GetRequiredService<VersionedVaultStore>());
        services.AddSingleton<IVaultMigrationCoordinator>(
            provider => provider.GetRequiredService<VersionedVaultStore>());
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

    private void OnWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_shutdownComplete)
        {
            return;
        }

        args.Cancel = true;
        _window?.BeginShutdown();
        sender.Hide();
        _shutdownTask ??= ShutdownAndCloseAsync();
    }

    private async Task ShutdownAndCloseAsync()
    {
        await Task.Yield();
        ILogger<App> logger = _services.GetRequiredService<ILogger<App>>();

        try
        {
            await _services.GetRequiredService<ISecureClipboardService>().CancelPendingClearAsync();
        }
        catch (Exception exception)
        {
            AppLog.UnhandledUiError(logger, exception.GetType().Name);
        }

        try
        {
            await _services.GetRequiredService<IVaultService>().LockAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            AppLog.UnhandledUiError(logger, exception.GetType().Name);
        }

        try
        {
            await _services.DisposeAsync();
        }
        catch (Exception exception)
        {
            AppLog.UnhandledUiError(logger, exception.GetType().Name);
        }

        _shutdownComplete = true;
        Window? window = _window;
        if (window is null)
        {
            Exit();
            return;
        }

        window.AppWindow.Closing -= OnWindowClosing;
        if (!window.DispatcherQueue.TryEnqueue(window.Close))
        {
            Exit();
        }
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        ILogger<App> logger = _services.GetRequiredService<ILogger<App>>();
        AppLog.UnhandledUiError(logger, args.Exception.GetType().Name);
        args.Handled = false;
    }
}
