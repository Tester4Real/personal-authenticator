[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("x64", "arm64", "all")]
    [string] $Architecture = "all",

    [Parameter()]
    [ValidateSet("Debug", "Release")]
    [string] $Configuration = "Release",

    [Parameter()]
    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-NoReparsePointInPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $AllowedRoot
    )

    $separators = [char[]] @(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $allowedRootPath = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd($separators)
    $allowedRootPrefix =
        $allowedRootPath + [System.IO.Path]::DirectorySeparatorChar
    $candidate = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Path))

    while ($null -ne $candidate) {
        $candidatePath = $candidate.FullName.TrimEnd($separators)
        $isAllowedRoot = $candidatePath.Equals(
            $allowedRootPath,
            [System.StringComparison]::OrdinalIgnoreCase
        )
        if (-not $isAllowedRoot -and -not $candidatePath.StartsWith(
                $allowedRootPrefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Path '$Path' escapes the generated artifacts directory."
        }

        if ($candidate.Exists) {
            $item = Get-Item -LiteralPath $candidate.FullName -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to publish through reparse point '$($candidate.FullName)'."
            }
        }

        if ($isAllowedRoot) {
            return
        }

        $candidate = $candidate.Parent
    }

    throw "Path '$Path' does not descend from '$AllowedRoot'."
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$projectPath = Join-Path $repositoryRoot "src\PersonalAuthenticator.App\PersonalAuthenticator.App.csproj"
$artifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot "artifacts"))

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $outputRootPath = Join-Path $repositoryRoot "artifacts\publish"
}
elseif ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    $outputRootPath = [System.IO.Path]::GetFullPath($OutputRoot)
}
else {
    $outputRootPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputRoot))
}

$trimCharacters = [char[]] @(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$artifactsRoot = $artifactsRoot.TrimEnd($trimCharacters)
$artifactsPrefix =
    $artifactsRoot + [System.IO.Path]::DirectorySeparatorChar
$outputRootPath = $outputRootPath.TrimEnd($trimCharacters)

$isArtifactsRoot = $outputRootPath.Equals(
    $artifactsRoot,
    [System.StringComparison]::OrdinalIgnoreCase
)
if (-not $isArtifactsRoot -and -not $outputRootPath.StartsWith(
        $artifactsPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
    throw "OutputRoot must resolve to the repository's generated artifacts directory."
}

Assert-NoReparsePointInPath -Path $outputRootPath -AllowedRoot $artifactsRoot

if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
    throw "Application project was not found at '$projectPath'."
}

$dotnetCommand = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue
if ($null -ne $dotnetCommand) {
    $dotnetPath = $dotnetCommand.Path
}
else {
    $dotnetPath = Join-Path $env:ProgramFiles "dotnet\dotnet.exe"
    if (-not (Test-Path -LiteralPath $dotnetPath -PathType Leaf)) {
        throw "dotnet.exe was not found on PATH or under Program Files."
    }
}

$targets = @(
    [pscustomobject] @{
        Architecture = "x64"
        Platform = "x64"
        RuntimeIdentifier = "win-x64"
        PublishProfile = "UnpackagedSelfContained-x64"
    },
    [pscustomobject] @{
        Architecture = "arm64"
        Platform = "ARM64"
        RuntimeIdentifier = "win-arm64"
        PublishProfile = "UnpackagedSelfContained-ARM64"
    }
)

$selectedTargets = @(
    if ($Architecture -eq "all") {
        $targets
    }
    else {
        $targets | Where-Object Architecture -EQ $Architecture
    }
)

foreach ($target in $selectedTargets) {
    $publishDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $outputRootPath $target.RuntimeIdentifier)
    )
    $outputRootPrefix =
        $outputRootPath.TrimEnd($trimCharacters) + [System.IO.Path]::DirectorySeparatorChar

    if (-not $publishDirectory.StartsWith(
            $outputRootPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Refusing to publish outside OutputRoot."
    }

    Assert-NoReparsePointInPath -Path $publishDirectory -AllowedRoot $artifactsRoot

    # Each architecture has a dedicated generated directory. Removing it avoids
    # stale binaries from an earlier SDK or package version.
    if (Test-Path -LiteralPath $publishDirectory) {
        Remove-Item -LiteralPath $publishDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Path $publishDirectory -Force | Out-Null

    $publishArguments = @(
        "publish"
        $projectPath
        "--configuration"
        $Configuration
        "--runtime"
        $target.RuntimeIdentifier
        "--self-contained"
        "true"
        "--output"
        $publishDirectory
        "--nologo"
        "-p:Platform=$($target.Platform)"
        "-p:PublishProfile=$($target.PublishProfile)"
        "-p:WindowsPackageType=None"
        "-p:WindowsAppSDKSelfContained=true"
        "-p:PublishSingleFile=false"
        "-p:PublishTrimmed=false"
    )

    Write-Host (
        "Publishing Personal Authenticator for {0} to '{1}'..." -f
        $target.Architecture,
        $publishDirectory
    )

    & $dotnetPath @publishArguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $($target.RuntimeIdentifier) with exit code $LASTEXITCODE."
    }

    $executablePath = Join-Path $publishDirectory "PersonalAuthenticator.App.exe"
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
        throw "Publish completed without the expected executable '$executablePath'."
    }

    $noticePath = Join-Path $publishDirectory "THIRD-PARTY-NOTICES.md"
    if (-not (Test-Path -LiteralPath $noticePath -PathType Leaf)) {
        throw "Publish completed without the required legal notice '$noticePath'."
    }

    if ((Get-Item -LiteralPath $noticePath).Length -eq 0) {
        throw "Published legal notice '$noticePath' is empty."
    }

    $requiredWinUiResources = @(
        "PersonalAuthenticator.App.pri",
        "App.xbf",
        "MainWindow.xbf",
        "Dialogs\AddAccountDialog.xbf",
        "Dialogs\SettingsDialog.xbf"
    )
    foreach ($relativeResourcePath in $requiredWinUiResources) {
        $resourcePath = Join-Path $publishDirectory $relativeResourcePath
        if (-not (Test-Path -LiteralPath $resourcePath -PathType Leaf)) {
            throw "Publish completed without required WinUI resource '$resourcePath'."
        }
    }

    $executable = Get-Item -LiteralPath $executablePath
    $executableHash = Get-FileHash -LiteralPath $executablePath -Algorithm SHA256
    Write-Host (
        "Created {0} ({1:N0} bytes, SHA-256 {2})." -f
        $executable.FullName,
        $executable.Length,
        $executableHash.Hash
    )
}

Write-Host "Publishing completed. Distribute each complete runtime folder, not only the executable."
