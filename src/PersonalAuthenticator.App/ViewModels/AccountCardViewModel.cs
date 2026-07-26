using CommunityToolkit.Mvvm.ComponentModel;
using PersonalAuthenticator.Core.Abstractions;
using PersonalAuthenticator.Core.Domain;

namespace PersonalAuthenticator.App.ViewModels;

public sealed partial class AccountCardViewModel : ObservableObject
{
    private readonly TotpAccount _account;
    private readonly ITotpGenerator _generator;
    private long _lastTimeStep = -1;
    private bool _hideByDefault;

    public AccountCardViewModel(
        TotpAccount account,
        ITotpGenerator generator,
        bool hideByDefault)
    {
        _account = account;
        _generator = generator;
        _hideByDefault = hideByDefault;
        Issuer = account.Issuer;
        AccountName = account.AccountName;
        Favourite = account.Favourite;
        SortOrder = account.SortOrder;
        Period = account.Period;
    }

    public Guid Id => _account.Id;

    public string Issuer { get; private set; }

    public string AccountName { get; private set; }

    public bool Favourite { get; private set; }

    public int SortOrder { get; private set; }

    public int Period { get; }

    public string FavouriteGlyph => Favourite ? "\uE735" : "\uE734";

    public string AccessibleCountdown => $"{SecondsRemaining} seconds remain before the code changes";

    public bool IsCodeHidden => _hideByDefault && !IsRevealed;

    [ObservableProperty]
    public partial string DisplayCode { get; set; } = "••• •••";

    [ObservableProperty]
    public partial int SecondsRemaining { get; set; }

    [ObservableProperty]
    public partial double CountdownValue { get; set; }

    [ObservableProperty]
    public partial bool IsRevealed { get; set; }

    public void Refresh(DateTimeOffset timestamp, bool vaultUnlocked)
    {
        SecondsRemaining = _generator.GetSecondsRemaining(_account, timestamp);
        CountdownValue = Period - SecondsRemaining;
        OnPropertyChanged(nameof(AccessibleCountdown));

        if (!vaultUnlocked || IsCodeHidden)
        {
            DisplayCode = _account.Digits == 8 ? "•••• ••••" : "••• •••";
            return;
        }

        long step = _generator.GetTimeStep(_account, timestamp);
        if (step == _lastTimeStep && !DisplayCode.Contains('•', StringComparison.Ordinal))
        {
            return;
        }

        string code = _generator.Generate(_account, timestamp);
        int split = code.Length / 2;
        DisplayCode = string.Concat(code.AsSpan(0, split), " ", code.AsSpan(split));
        _lastTimeStep = step;
    }

    public void SetRevealed(bool revealed)
    {
        IsRevealed = revealed;
        OnPropertyChanged(nameof(IsCodeHidden));
        _lastTimeStep = -1;
    }

    public void UpdateFromDomain(bool hideByDefault)
    {
        Issuer = _account.Issuer;
        AccountName = _account.AccountName;
        Favourite = _account.Favourite;
        SortOrder = _account.SortOrder;
        _hideByDefault = hideByDefault;
        OnPropertyChanged(nameof(Issuer));
        OnPropertyChanged(nameof(AccountName));
        OnPropertyChanged(nameof(Favourite));
        OnPropertyChanged(nameof(FavouriteGlyph));
        OnPropertyChanged(nameof(SortOrder));
        OnPropertyChanged(nameof(IsCodeHidden));
    }
}
