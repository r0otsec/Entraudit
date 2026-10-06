<div align="center">
  
<img alt="entraudit-banner" src="https://raw.githubusercontent.com/r0otsec/Entraudit/refs/heads/main/assets/entraudit-banner.png" />

### A realistic, vulnerable CI/CD pipeline deployment lab lab for offensive and defensive training against CI/CD pipelines, DevOps and supply chains.

<br/>

[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br/>
</div>

# EntrAudit

Read-only Microsoft 365 / Entra ID configuration review automation for pentest engagements. Connects to whichever services are in scope for a given client, runs 64 checks pulled from real past engagement reports, and exports a client-ready Excel workbook, branded PDF, and/or HTML report (plus plain CSV/JSON) ready to drop into report writing.

**Only run this against a tenant you are authorized to assess** (your own, or a
client's under a signed engagement/scope agreement). It's read-only, but it
still authenticates as a real user against a real tenant and reads
configuration/security data.

MIT licensed: see [LICENSE](LICENSE). See [NOTICE.md](NOTICE.md) for a note on
the third-party service icons used in the PDF/HTML reports.

## Requirements

- PowerShell 7+ (`pwsh`)
- The account(s) you sign in with need, at minimum, **Global Reader + Security Reader** Entra ID directory roles for the Graph/Exchange/SharePoint/Teams/ Compliance checks. **Power BI** checks additionally need **Power BI Service Administrator** or **Fabric Administrator** — Global Reader/Security Reader does not cover Power BI/Fabric tenant settings.
- PowerShell modules (installed automatically by `Install-Prerequisites.ps1`): `Microsoft.Graph`, `ExchangeOnlineManagement`, `Microsoft.Online.SharePoint.PowerShell`, `MicrosoftTeams`, `MicrosoftPowerBIMgmt`, `ImportExcel`.
- **Only for `-OutputFormat Pdf`** (everything else needs nothing extra): Python 3 with `pyyaml jinja2 markdown pypdf playwright Pillow` + `playwright install chromium`, and the PowerShell `powershell-yaml` module. See [PDF output](#pdf-output) below.

## Setup

```powershell
# installs everything, CurrentUser scope
.\Install-Prerequisites.ps1     

# or, to only pull in what you'll actually use for this engagement:
.\Install-Prerequisites.ps1 -Services Graph,Exo,Spo,Excel

Import-Module .\EntrAudit.psd1
```

## Usage — CLI (recommended)

EntrAudit.ps1 is a single-command front end over Connect/Invoke/Export. Run it
with no arguments (or `-Help`) to see the full options screen:

```powershell
.\EntrAudit.ps1 -Help
.\EntrAudit.ps1 -ListCategories
.\EntrAudit.ps1 -ListChecks -Category 'Power BI'

.\EntrAudit.ps1 -ClientName 'Contoso Ltd' `
    -GraphUserPrincipalName alice@contoso.com -ExchangeUserPrincipalName alice@contoso.com `
    -SharePointAdminUrl https://contoso-admin.sharepoint.com -SharePointUserPrincipalName bob@contoso.com `
    -TeamsUserPrincipalName alice@contoso.com -OutputFormat Excel,Json

# Shorthand for connecting every service with one account:
.\EntrAudit.ps1 -All -AccountUpn alice@contoso.com -SharePointAdminUrl https://contoso-admin.sharepoint.com -ClientName 'Contoso Ltd'

# Report filtering/sorting
.\EntrAudit.ps1 -ClientName 'Contoso Ltd' -GraphUserPrincipalName alice@contoso.com -Status Fail -SortBy Severity -Reverse -OutputFormat Html
```

**Only connect the services this client's tenant actually has.** Anything you don't connect (or exclude via `-IgnoreCategory`) is automatically reported as NotApplicable in the output rather than attempted - how you tell the tool "this tenant doesn't use Power BI / Teams / Purview DLP / etc." Each service can
use a different account if the client has split access across multiple accounts.

## Usage — module functions directly

If you want finer control than the CLI exposes, use the underlying functions directly: `Import-Module .\EntrAudit.psd1`, then `Connect-EntrAudit`, `Invoke-EntrAudit`, `Export-EntrAuditReport` as below.

```powershell
Connect-EntrAudit `
    -GraphUserPrincipalName      alice@client.com `
    -ExchangeUserPrincipalName   alice@client.com `
    -SharePointAdminUrl          https://client-admin.sharepoint.com `
    -SharePointUserPrincipalName bob@client.com `
    -TeamsUserPrincipalName      alice@client.com `
    -ComplianceUserPrincipalName alice@client.com
    # -PowerBIUserPrincipalName carol@client.com   # omit entirely if this client has no Power BI/Fabric

$results = Invoke-EntrAudit -ClientName 'Client Ltd'

$results | Export-EntrAuditReport -ClientName 'Client Ltd' -OutputPath ..\Reports -OutputFormat Excel,Json
```

Each `Connect-*` call pops up the normal interactive sign-in for that service.

### Scoping to specific categories

```powershell
# Only run Identity + Exchange checks:
Invoke-EntrAudit -ClientName 'Client Ltd' -IncludeCategory 'Identity*','Exchange*'

# Run everything except Power BI (e.g. client has no Fabric capacity at all):
Invoke-EntrAudit -ClientName 'Client Ltd' -ExcludeCategory 'Power BI'
```

## Reading the output

Every check produces one of these `Status` values internally:

| Status | Meaning |
|---|---|
| `Pass` | Setting matches the recommended/secure value. |
| `Fail` | Setting does not match the recommended value — a candidate finding. |
| `ManualReview` | Data was retrieved but needs a human judgment call (no fixed threshold, or a nuanced multi-factor check), or no reliable API exists at all for this setting. |
| `NotApplicable` | The required service wasn't connected for this engagement. |
| `Error` | Something failed unexpectedly (wrong scope, throttling, etc.) — worth investigating, not just noise. |

Every row carries an `AdminCenterPath` (shown as **Path** in reports) — for `ManualReview`/`Error` rows, or anything you want to screenshot by hand, that's
exactly where to go look. The Excel Summary sheet's "Service scope" block shows which of the six connections were actually established for that run.

The **full JSON file** (`*-Full.json`) is always written regardless of `-OutputFormat`, and is the only output that includes each check's raw API
response (`RawData`) for deep-dives.

## PDF output

`-OutputFormat Pdf` renders a branded PDF via `PdfReport\generate_pdf.py` (Python + Playwright/Chromium). The `-OutputFormat Html` export mirrors the same
design in a single dependency-free HTML file.

```powershell
# one-time: pip packages + powershell-yaml + chromium
.\Install-Prerequisites.ps1 -Services Pdf
.\EntrAudit.ps1 -ClientName 'Contoso Ltd' -GraphUserPrincipalName alice@contoso.com -OutputFormat Pdf
```

Want to see what the output looks like before running a real engagement? Run `.\Demo\New-EntrAuditSampleData.ps1` - it generates a full realistic sample report set (all 5 formats) for a fictitious company into `SampleOutput\`.

## Known limitations (v1)

- **Defender for Cloud Apps**: lives in its own admin surface (not Microsoft Graph). Ships as a manual-review deployment checklist (Cloud Discovery, app connectors, OAuth app governance, Conditional Access App Control) rather than live checks.
- **Microsoft Forms**: no public admin Graph API exists for its tenant settings as of this writing. All three Forms checks are manual-review stubs.
- A handful of Entra ID/Office settings (custom banned password list, "restrict access to Entra admin center", idle session timeout, LinkedIn connections, Sway external sharing) have no confirmed stable Graph property and are manual-review stubs rather than guessed mappings.
- Power BI checks match tenant settings by their human-readable `title` text (the Admin REST API's `settingName` enum has shifted across versions) — if a match can't be confidently made, the check reports `ManualReview` rather than a possibly-wrong `Pass`.

## License

MIT — see [LICENSE](LICENSE).