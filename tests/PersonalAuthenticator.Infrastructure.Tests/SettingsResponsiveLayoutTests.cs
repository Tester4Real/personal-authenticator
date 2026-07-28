using System.Xml.Linq;

namespace PersonalAuthenticator.Infrastructure.Tests;

public sealed class SettingsResponsiveLayoutTests
{
    [Fact]
    public void EverySettingsPage_UsesResponsiveNavigationAndVerticalScrolling()
    {
        XDocument document = XDocument.Load(FindSettingsXaml());
        XElement root = Assert.IsType<XElement>(document.Root);
        Assert.Equal("Window", root.Name.LocalName);
        Assert.DoesNotContain(
            root.Descendants(),
            element => element.Name.LocalName is "TabView" or "TabViewItem");

        XElement navigation = Assert.Single(
            root.Descendants(),
            element => element.Name.LocalName == "NavigationView");
        Assert.Equal("Auto", Attribute(navigation, "PaneDisplayMode"));
        Assert.Equal("220", Attribute(navigation, "OpenPaneLength"));
        Assert.Equal("500", Attribute(root.Elements().Single(), "MinWidth"));
        Assert.Equal("420", Attribute(root.Elements().Single(), "MinHeight"));

        string[] expectedPages =
        [
            "General & security",
            "Backup & recovery",
            "Sync",
            "Devices & advanced",
            "About",
        ];
        string[] actualPages = navigation.Descendants()
            .Where(element => element.Name.LocalName == "NavigationViewItem")
            .Select(element => Attribute(element, "Content"))
            .ToArray();
        Assert.Equal(expectedPages, actualPages);

        string[] pageNames =
        [
            "GeneralPage",
            "BackupRecoveryPage",
            "SyncPage",
            "DevicesPage",
            "AboutPage",
        ];
        foreach (string pageName in pageNames)
        {
            XElement page = FindNamed(root, pageName);
            XElement scroll = Assert.Single(
                page.Descendants(),
                element => element.Name.LocalName == "ScrollViewer");
            Assert.Equal(
                "Disabled",
                Attribute(scroll, "HorizontalScrollMode"));
            Assert.Equal(
                "Disabled",
                Attribute(scroll, "HorizontalScrollBarVisibility"));
            Assert.Equal(
                "Auto",
                Attribute(scroll, "VerticalScrollBarVisibility"));
        }

        Assert.DoesNotContain(
            root.DescendantsAndSelf(),
            element =>
                AttributeOrNull(element, "Width") == "660" ||
                AttributeOrNull(element, "MinWidth") == "560");
    }

    [Fact]
    public void ConsolidatedCategories_PreserveExistingSettingsControls()
    {
        XDocument document = XDocument.Load(FindSettingsXaml());
        XElement root = Assert.IsType<XElement>(document.Root);

        Assert.NotNull(FindNamed(root, "ClipboardDelayBox"));
        Assert.NotNull(FindNamed(root, "VaultModeText"));
        Assert.NotNull(FindNamed(root, "BackupPasswordBox"));
        Assert.NotNull(FindNamed(root, "RecoveryPasswordBox"));
        Assert.NotNull(FindNamed(root, "SyncFolderBox"));
        Assert.NotNull(FindNamed(root, "GitHubTokenBox"));
        Assert.NotNull(FindNamed(root, "DevicesList"));
        Assert.DoesNotContain(
            root.Descendants(),
            element =>
                AttributeOrNull(element, "Name") is
                    "SecurityPage" or
                    "VaultPage" or
                    "BackupPage" or
                    "RecoveryPage" or
                    "LocalSyncPage" or
                    "GitHubPage");

        string visibleText = string.Join(
            '\n',
            root.DescendantsAndSelf()
                .SelectMany(element => element.Attributes())
                .Select(attribute => attribute.Value));
        Assert.DoesNotContain("GitHub sync is not part of this phase.", visibleText);
        Assert.DoesNotContain("No analytics, telemetry, advertisements, GitHub integration", visibleText);

        string[] removedRepositoryInputs =
        [
            "GitHubOwnerBox",
            "GitHubRepositoryBox",
            "GitHubBranchBox",
            "GitHubPathBox",
        ];
        foreach (string inputName in removedRepositoryInputs)
        {
            Assert.DoesNotContain(
                root.DescendantsAndSelf(),
                element => AttributeOrNull(element, "Name") == inputName);
        }

        string codeBehind = File.ReadAllText(FindSettingsCodeBehind());
        Assert.Contains("PersonalGitHubOwner = \"Tester4Real\";", codeBehind);
        Assert.Contains("PersonalGitHubRepository = \"authenticator-sync\";", codeBehind);
        Assert.Contains("PersonalGitHubBranch = \"personal-authenticator-sync\";", codeBehind);
        Assert.Contains("PersonalGitHubPath = \".personal-authenticator\";", codeBehind);
    }

    [Fact]
    public void TechnicalAndDangerousControls_AreCollapsedByDefault()
    {
        XDocument document = XDocument.Load(FindSettingsXaml());
        XElement root = Assert.IsType<XElement>(document.Root);
        string[] technicalControls =
        [
            "ClipboardDelayBox",
            "BackupPasswordBox",
            "ImportModeBox",
            "RecoveryPasswordBox",
            "GitHubTokenBox",
            "SyncFolderBox",
            "SecurityRecoveryDirectoryBox",
            "PurgeAccountIdBox",
        ];

        foreach (string controlName in technicalControls)
        {
            XElement control = FindNamed(root, controlName);
            XElement? expander = control.Ancestors()
                .FirstOrDefault(element => element.Name.LocalName == "Expander");
            Assert.NotNull(expander);
            Assert.Equal("False", Attribute(expander, "IsExpanded"));
        }

        string[] expectedExpanders =
        [
            "Security & clipboard",
            "Encrypted backup",
            "Advanced restore options",
            "Recovery A/B",
            "GitHub sync",
            "Maintenance",
            "Local-folder sync (advanced)",
            "Conflict resolution",
            "Key rotation (advanced)",
            "Permanent purge (dangerous)",
        ];
        string[] actualExpanders = root.Descendants()
            .Where(element => element.Name.LocalName == "Expander")
            .Select(element => Attribute(element, "Header"))
            .ToArray();
        Assert.Equal(expectedExpanders, actualExpanders);
    }

    [Fact]
    public void WarningsStatusAndDeviceEmptyState_CannotClipSilently()
    {
        XDocument document = XDocument.Load(FindSettingsXaml());
        XElement root = Assert.IsType<XElement>(document.Root);
        foreach (XElement infoBar in root.Descendants().Where(element =>
                     element.Name.LocalName == "InfoBar" &&
                     AttributeOrNull(element, "IsOpen") == "True"))
        {
            Assert.Contains(
                infoBar.Descendants(),
                element =>
                    element.Name.LocalName == "TextBlock" &&
                    AttributeOrNull(element, "TextWrapping") == "Wrap");
        }

        XElement statusText = FindNamed(root, "SettingsStatusText");
        Assert.Equal("Wrap", Attribute(statusText, "TextWrapping"));
        XElement empty = FindNamed(root, "DevicesEmptyText");
        Assert.Equal("No authorised devices found.", Attribute(empty, "Text"));
        Assert.Equal("Wrap", Attribute(empty, "TextWrapping"));
        Assert.Null(AttributeOrNull(empty, "Visibility"));
        XElement list = FindNamed(root, "DevicesList");
        Assert.Equal("0", Attribute(list, "MinHeight"));
        Assert.Equal("Collapsed", Attribute(list, "Visibility"));
        Assert.True(
            int.Parse(
                Attribute(list, "MaxHeight"),
                System.Globalization.CultureInfo.InvariantCulture) <= 180);

        Assert.NotNull(root.Descendants().FirstOrDefault(element =>
            element.Name.LocalName == "Button" &&
            AttributeOrNull(element, "Content") == "Save settings"));
        Assert.NotNull(root.Descendants().FirstOrDefault(element =>
            element.Name.LocalName == "Button" &&
            AttributeOrNull(element, "Content") == "Close"));
    }

    [Fact]
    public void StandaloneWindow_IsResizableAndUsesScaleIndependentBreakpoints()
    {
        string codeBehind = File.ReadAllText(FindSettingsCodeBehind());

        Assert.Contains("presenter.IsResizable = true;", codeBehind);
        Assert.Contains("presenter.IsMaximizable = true;", codeBehind);
        Assert.Contains("presenter.PreferredMinimumWidth = 540;", codeBehind);
        Assert.Contains("presenter.PreferredMinimumHeight = 480;", codeBehind);
        Assert.Contains("args.NewSize.Width >= 680", codeBehind);
        Assert.Contains("NavigationViewPaneDisplayMode.LeftMinimal", codeBehind);
        Assert.Contains("NavigationViewPaneDisplayMode.Left", codeBehind);
        Assert.Contains("SettingsRoot.RequestedTheme", codeBehind);
    }

    private static string FindSettingsXaml()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(
                directory.FullName,
                "src",
                "PersonalAuthenticator.App",
                "Dialogs",
                "SettingsDialog.xaml");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("SettingsDialog.xaml was not found.");
    }

    private static string FindSettingsCodeBehind() =>
        Path.ChangeExtension(FindSettingsXaml(), ".xaml.cs");

    private static XElement FindNamed(XElement root, string name) =>
        root.DescendantsAndSelf().Single(element =>
            element.Attributes().Any(attribute =>
                attribute.Name.LocalName == "Name" &&
                attribute.Value == name));

    private static string Attribute(XElement element, string name) =>
        AttributeOrNull(element, name) ??
        throw new Xunit.Sdk.XunitException(
            $"{element.Name.LocalName} is missing {name}.");

    private static string? AttributeOrNull(XElement element, string name) =>
        element.Attributes().FirstOrDefault(attribute =>
            attribute.Name.LocalName == name)?.Value;
}
