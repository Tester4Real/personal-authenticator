# Third-party notices

Personal Authenticator includes third-party software. This notice accompanies
self-contained builds and must remain beside the application executable. The
exact resolved dependency graph is recorded in
`PersonalAuthenticator.App.deps.json`.

This file is an attribution and licence index, not legal advice and not a
replacement for the governing terms. Release owners must review the exact
restored packages and preserve any upstream licence or notice files required by
those terms.

## Microsoft redistributables

| Component | Selected version | Terms |
| --- | ---: | --- |
| Microsoft Windows App SDK | `2.3.1` | [Microsoft Software License Terms](https://www.nuget.org/packages/Microsoft.WindowsAppSDK/2.3.1/License). The terms govern files binplaced with framework-dependent and self-contained applications; the package's bundled third-party notices also apply. |
| Microsoft Windows App SDK WinUI component | `2.3.2` (centrally pinned transitive servicing component) | The component's bundled `license.txt` is titled **Microsoft Windows App SDK Engineering Preview** and conflicts with the aggregate package's ordinary redistribution wording. See the caveat below. |
| Microsoft WebView2 SDK | `1.0.3719.77` (resolved transitively) | [Microsoft Software License Terms](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.3719.77/License) and the notice bundled with the resolved package. |

The application directly references aggregate `Microsoft.WindowsAppSDK` 2.3.1.
Its terms state that files binplaced by the WindowsAppSDK NuGet package may be
redistributed in self-contained applications, subject to its requirements and
restrictions. NuGet also resolves centrally pinned
`Microsoft.WindowsAppSDK.WinUI` 2.3.2 beneath that aggregate. Because the
component package carries conflicting **Engineering Preview** wording, release
owners must obtain Microsoft clarification or qualified legal review before
external distribution. This notice records the conflict; it does not resolve
which terms control.

Microsoft Windows, WinUI, Windows App SDK, and WebView2 are trademarks of the
Microsoft group of companies. Their inclusion does not imply Microsoft
endorsement of Personal Authenticator.

## Open-source dependencies

| Component | Selected version | Licence and attribution |
| --- | ---: | --- |
| CommunityToolkit.Mvvm | `8.4.2` | [MIT](https://licenses.nuget.org/MIT); copyright .NET Foundation and contributors |
| Microsoft.Extensions.DependencyInjection | `10.0.10` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| Microsoft.Extensions.Logging | `10.0.10` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| Microsoft.Extensions.Logging.Debug | `10.0.10` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| Microsoft.Win32.SystemEvents | `10.0.10` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| Konscious.Security.Cryptography.Argon2 | `1.3.1` | [MIT](https://licenses.nuget.org/MIT); copyright its contributors |
| Otp.NET | `1.4.1` | [MIT](https://licenses.nuget.org/MIT); copyright 2017 Kyle Spearrin |
| System.IO.FileSystem.AccessControl | `5.0.0` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| System.Security.Cryptography.ProtectedData | `10.0.10` | [MIT](https://licenses.nuget.org/MIT); copyright Microsoft Corporation |
| ZXing.Net | `0.16.11` | [Apache License 2.0](https://licenses.nuget.org/Apache-2.0); copyright its contributors |

The self-contained .NET runtime and its libraries are distributed under their
respective Microsoft and open-source terms. See the
[.NET repository licence](https://github.com/dotnet/runtime/blob/main/LICENSE.TXT)
and
[.NET third-party notices](https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT).

## MIT licence text

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The applicable copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
