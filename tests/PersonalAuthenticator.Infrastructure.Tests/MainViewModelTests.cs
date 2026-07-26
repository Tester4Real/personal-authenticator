using PersonalAuthenticator.App.ViewModels;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;
using PersonalAuthenticator.Core.Security;
using PersonalAuthenticator.Core.Services;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task SearchFavouritesAndSorting_FilterAccounts()
    {
        TestHarness harness = await TestHarness.CreateAsync();
        using (harness)
        {
            TotpAccount first = CreateAccount("GitHub", "alice", 1);
            TotpAccount second = CreateAccount("Microsoft", "work", 2);
            await harness.ViewModel.AddAsync(first, DuplicateResolution.Cancel, CancellationToken.None);
            await harness.ViewModel.AddAsync(second, DuplicateResolution.Cancel, CancellationToken.None);
            await harness.ViewModel.ToggleFavouriteAsync(second.Id, CancellationToken.None);

            harness.ViewModel.SearchText = "git";
            Assert.Equal("GitHub", Assert.Single(harness.ViewModel.VisibleAccounts).Issuer);

            harness.ViewModel.SearchText = string.Empty;
            harness.ViewModel.FavouritesOnly = true;
            Assert.Equal("Microsoft", Assert.Single(harness.ViewModel.VisibleAccounts).Issuer);
        }
    }

    [Fact]
    public async Task CopyHonoursVerificationAndLockState()
    {
        TestHarness harness = await TestHarness.CreateAsync();
        using (harness)
        {
            TotpAccount account = CreateAccount("Example", "user", 3);
            await harness.ViewModel.AddAsync(account, DuplicateResolution.Cancel, CancellationToken.None);
            await harness.ViewModel.CopyAsync(account.Id, CancellationToken.None);
            Assert.Equal("123456", harness.Clipboard.LastCode);

            await harness.ViewModel.LockAsync(CancellationToken.None);
            await Assert.ThrowsAsync<PersonalAuthenticator.Core.Exceptions.SafeApplicationException>(
                () => harness.ViewModel.CopyAsync(account.Id, CancellationToken.None));
        }
    }

    [Fact]
    public async Task AddEditDeleteAndTimerRefresh_UpdateViewState()
    {
        TestHarness harness = await TestHarness.CreateAsync();
        using (harness)
        {
            TotpAccount account = CreateAccount("Old", "name", 4);
            await harness.ViewModel.AddAsync(account, DuplicateResolution.Cancel, CancellationToken.None);
            await harness.ViewModel.EditAsync(account.Id, "New", "renamed", CancellationToken.None);
            Assert.Equal("New", Assert.Single(harness.ViewModel.VisibleAccounts).Issuer);

            harness.Clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(29);
            harness.ViewModel.RefreshCodes();
            AccountCardViewModel card = Assert.Single(harness.ViewModel.VisibleAccounts);
            Assert.Equal(1, card.SecondsRemaining);
            harness.Clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(30);
            harness.ViewModel.RefreshCodes();
            Assert.Equal(30, card.SecondsRemaining);

            await harness.ViewModel.DeleteAsync(account.Id, CancellationToken.None);
            Assert.Empty(harness.ViewModel.VisibleAccounts);
        }
    }

    private static TotpAccount CreateAccount(string issuer, string name, byte discriminator) =>
        new(
            Guid.NewGuid(),
            issuer,
            name,
            Enumerable.Range(1, 20).Select(value => (byte)(value + discriminator)).ToArray());

    private sealed class TestHarness : IDisposable
    {
        private readonly VaultService _vault;

        private TestHarness(
            VaultService vault,
            MainViewModel viewModel,
            MutableClock clock,
            FakeClipboard clipboard)
        {
            _vault = vault;
            ViewModel = viewModel;
            Clock = clock;
            Clipboard = clipboard;
        }

        public MainViewModel ViewModel { get; }

        public MutableClock Clock { get; }

        public FakeClipboard Clipboard { get; }

        public static async Task<TestHarness> CreateAsync()
        {
            var clock = new MutableClock { UtcNow = DateTimeOffset.FromUnixTimeSeconds(0) };
            var vault = new VaultService(new InMemoryStore(), clock, new DuplicateDetector());
            var clipboard = new FakeClipboard();
            var viewModel = new MainViewModel(
                vault,
                new FakeTotpGenerator(),
                clock,
                clipboard,
                new FakeVerification(),
                new FakeSettingsStore());
            await viewModel.InitialiseAsync(CancellationToken.None);
            return new TestHarness(vault, viewModel, clock, clipboard);
        }

        public void Dispose() => _vault.Dispose();
    }

    private sealed class MutableClock : IClock
    {
        public DateTimeOffset UtcNow { get; set; }
    }

    private sealed class FakeTotpGenerator : ITotpGenerator
    {
        public string Generate(TotpAccount account, DateTimeOffset timestamp) => "123456";

        public int GetSecondsRemaining(TotpAccount account, DateTimeOffset timestamp)
        {
            int elapsed = (int)(timestamp.ToUnixTimeSeconds() % account.Period);
            return elapsed == 0 ? account.Period : account.Period - elapsed;
        }

        public long GetTimeStep(TotpAccount account, DateTimeOffset timestamp) =>
            timestamp.ToUnixTimeSeconds() / account.Period;
    }

    private sealed class FakeClipboard : ISecureClipboardService
    {
        public string? LastCode { get; private set; }

        public Task CopyCodeAsync(string code, TimeSpan clearAfter, CancellationToken cancellationToken)
        {
            LastCode = code;
            return Task.CompletedTask;
        }

        public Task CancelPendingClearAsync() => Task.CompletedTask;

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeVerification : IUserVerificationService
    {
        public Task<UserVerificationAvailability> GetAvailabilityAsync() =>
            Task.FromResult(UserVerificationAvailability.Available);

        public Task<bool> RequestAsync(string message, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }

    private sealed class FakeSettingsStore : IAppSettingsStore
    {
        private AppSettings _settings = new() { StartUnlocked = true };

        public Task<AppSettings> LoadAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_settings);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken)
        {
            _settings = settings;
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryStore : IVaultStore
    {
        private readonly List<TotpAccount> _accounts = [];

        public string VaultPath => "memory";

        public Task<bool> ExistsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_accounts.Count > 0);

        public Task<IReadOnlyList<TotpAccount>> LoadAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<TotpAccount>>(_accounts.Select(Clone).ToList());

        public Task SaveAsync(IReadOnlyCollection<TotpAccount> accounts, CancellationToken cancellationToken)
        {
            foreach (TotpAccount account in _accounts)
            {
                account.Dispose();
            }

            _accounts.Clear();
            _accounts.AddRange(accounts.Select(Clone));
            return Task.CompletedTask;
        }

        private static TotpAccount Clone(TotpAccount account) =>
            new(
                account.Id,
                account.Issuer,
                account.AccountName,
                account.Secret,
                account.Algorithm,
                account.Digits,
                account.Period,
                account.Favourite,
                account.SortOrder,
                account.CreatedAtUtc,
                account.UpdatedAtUtc);
    }
}
