#Requires -Version 7.0
<#
.SYNOPSIS
    RootSec M365 / Entra ID Security Review - single-command CLI front end for the
    EntrAudit module (Connect-EntrAudit / Invoke-EntrAudit / Export-EntrAuditReport).

.DESCRIPTION
    Read-only. Connects to whichever M365 services are in scope for this engagement,
    runs the check catalog, and exports a report. Only connect what the client's
    tenant actually has - anything you don't pass reports NotApplicable instead of
    being attempted (see -ListCategories / -ListChecks to see what's covered before
    connecting to anything).

    Run with no arguments to see this help screen (the same as -Help).

.PARAMETER All
    Shorthand for connecting every service. Needs -AccountUpn (used for Graph,
    Exchange, Teams, Compliance, and Power BI unless individually overridden) and
    -SharePointAdminUrl (SharePoint always needs its admin URL regardless).

.PARAMETER AccountUpn
    Account to use for every service when -All is given, unless a more specific
    -GraphUserPrincipalName / -ExchangeUserPrincipalName / etc. is also supplied,
    in which case the specific one wins for that service.

.PARAMETER Category
    Only run checks in these categories (wildcards OK, e.g. 'Identity*'). See
    -ListCategories for the exact category names.

.PARAMETER IgnoreCategory
    Skip checks in these categories (wildcards OK).

.PARAMETER Severity
    Only include results at these severities in the exported report (Critical,
    High, Medium, Low, Informational). Filters the report, not what runs.

.PARAMETER IgnoreSeverity
    Exclude results at these severities from the exported report.

.PARAMETER Status
    Only include results with these statuses (Pass, Fail, ManualReview,
    NotApplicable, Error) in the exported report. e.g. -Status Fail for a
    "just show me what's broken" report.

.PARAMETER IgnoreStatus
    Exclude results with these statuses from the exported report.

.PARAMETER SortBy
    Field to sort the exported report by: Severity, Category, CheckId, or Status.
    Default: Category.

.PARAMETER Reverse
    Reverse the sort order.

.PARAMETER OutputFormat
    One or more of: Excel, Csv, Json, Html, Pdf. Default: Excel. Pdf needs
    Python + powershell-yaml - see README.md; everything else needs nothing extra.

.PARAMETER OutputPath
    Directory to write the report into. Default: .\Reports

.PARAMETER ListCategories
    Print every check category and how many checks are in it, then exit. Doesn't
    connect to anything.

.PARAMETER ListChecks
    Print every check (CheckId, Category, Title, Severity, RequiredSource), then
    exit. Doesn't connect to anything. Combine with -Category/-Severity to filter
    the listing.

.PARAMETER Version
    Print the module version, then exit.

.PARAMETER Silent
    Suppress the tool's own status/progress output (Connect-EntrAudit,
    Invoke-EntrAudit, and Export-EntrAuditReport's Write-Host lines). Errors and
    warnings that matter still show.

.EXAMPLE
    .\EntrAudit.ps1 -Help

.EXAMPLE
    .\EntrAudit.ps1 -ListCategories

.EXAMPLE
    .\EntrAudit.ps1 -ListChecks -Category 'Power BI'

.EXAMPLE
    .\EntrAudit.ps1 -ClientName 'Contoso Ltd' `
        -GraphUserPrincipalName alice@contoso.com -ExchangeUserPrincipalName alice@contoso.com `
        -SharePointAdminUrl https://contoso-admin.sharepoint.com -SharePointUserPrincipalName bob@contoso.com `
        -TeamsUserPrincipalName alice@contoso.com -OutputFormat Excel,Json

.EXAMPLE
    .\EntrAudit.ps1 -All -AccountUpn alice@contoso.com -SharePointAdminUrl https://contoso-admin.sharepoint.com -ClientName 'Contoso Ltd'

.EXAMPLE
    .\EntrAudit.ps1 -ClientName 'Contoso Ltd' -GraphUserPrincipalName alice@contoso.com `
        -Status Fail -SortBy Severity -Reverse -OutputFormat Html
#>
[CmdletBinding()]
param(
    [Alias('h')][switch]$Help,
    [switch]$Version,
    [switch]$ListCategories,
    [switch]$ListChecks,

    [switch]$All,
    [string]$AccountUpn,

    [string]$ClientName = 'Unnamed Engagement',
    [string]$GraphUserPrincipalName,
    [string]$ExchangeUserPrincipalName,
    [string]$SharePointAdminUrl,
    [string]$SharePointUserPrincipalName,
    [string]$TeamsUserPrincipalName,
    [string]$ComplianceUserPrincipalName,
    [string]$PowerBIUserPrincipalName,

    [string[]]$Category = @('*'),
    [string[]]$IgnoreCategory = @(),
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
    [string[]]$Severity,
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
    [string[]]$IgnoreSeverity,
    [ValidateSet('Pass', 'Fail', 'ManualReview', 'NotApplicable', 'Error')]
    [string[]]$Status,
    [ValidateSet('Pass', 'Fail', 'ManualReview', 'NotApplicable', 'Error')]
    [string[]]$IgnoreStatus,

    [ValidateSet('Severity', 'Category', 'CheckId', 'Status')]
    [string]$SortBy = 'Category',
    [switch]$Reverse,

    [ValidateSet('Excel', 'Csv', 'Json', 'Html', 'Pdf')]
    [string[]]$OutputFormat = @('Excel'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Reports'),

    [switch]$Silent
)

# --help / --h are not native PowerShell syntax (single dash is) but tolerate the
# Linux muscle-memory spelling anyway rather than fail confusingly on it.
if ($args -contains '--help' -or $args -contains '--h' -or $args -contains '-h') { $Help = $true }

Import-Module (Join-Path $PSScriptRoot 'EntrAudit.psd1') -Force

function Write-M365BannerLine {
    param([string]$Text, [string]$Color, [int]$InnerWidth)
    $padded = $Text.PadRight($InnerWidth)
    Write-Host '|' -ForegroundColor DarkGray -NoNewline
    Write-Host $padded -ForegroundColor $Color -NoNewline
    Write-Host '|' -ForegroundColor DarkGray
}

function Show-EntrAuditBanner {
    $innerWidth = 68
    $line = '-' * $innerWidth
    Write-Host ''
    Write-Host "+$line+" -ForegroundColor DarkGray
    Write-M365BannerLine -Text '  ROOTSEC - M365 / Entra ID Security Review' -Color White -InnerWidth $innerWidth
    Write-M365BannerLine -Text '  Read-only configuration review automation for pentest engagements' -Color Gray -InnerWidth $innerWidth
    Write-Host "+$line+" -ForegroundColor DarkGray
}

function Show-EntrAuditHelp {
    Show-EntrAuditBanner
    $manifest = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'EntrAudit.psd1')
    Write-Host ''
    Write-Host "usage: .\EntrAudit.ps1 [-Help] [-Version] [-ListCategories] [-ListChecks]" -ForegroundColor White
    Write-Host "                        [-All] [-AccountUpn UPN] [-ClientName NAME]" -ForegroundColor White
    Write-Host "                        [-GraphUserPrincipalName UPN] [-ExchangeUserPrincipalName UPN]" -ForegroundColor White
    Write-Host "                        [-SharePointAdminUrl URL] [-SharePointUserPrincipalName UPN]" -ForegroundColor White
    Write-Host "                        [-TeamsUserPrincipalName UPN] [-ComplianceUserPrincipalName UPN]" -ForegroundColor White
    Write-Host "                        [-PowerBIUserPrincipalName UPN]" -ForegroundColor White
    Write-Host "                        [-Category CAT [CAT ...]] [-IgnoreCategory CAT [CAT ...]]" -ForegroundColor White
    Write-Host "                        [-Severity SEV [SEV ...]] [-IgnoreSeverity SEV [SEV ...]]" -ForegroundColor White
    Write-Host "                        [-Status STATUS [STATUS ...]] [-IgnoreStatus STATUS [STATUS ...]]" -ForegroundColor White
    Write-Host "                        [-SortBy FIELD] [-Reverse]" -ForegroundColor White
    Write-Host "                        [-OutputFormat FORMAT [FORMAT ...]] [-OutputPath PATH] [-Silent]" -ForegroundColor White
    Write-Host ''
    Write-Host "RootSec EntrAudit v$($manifest.ModuleVersion) - run with no arguments to see this screen." -ForegroundColor DarkGray
    Write-Host ''

    Write-Host 'INTROSPECTION (no connection needed)' -ForegroundColor Yellow
    Write-Host '  -Help, -h             Show this screen and exit.'
    Write-Host '  -Version              Show module version and exit.'
    Write-Host '  -ListCategories       List every check category + check count, then exit.'
    Write-Host '  -ListChecks           List every check (Id/Category/Title/Severity/Source), then exit.'
    Write-Host '                        Combine with -Category/-Severity to filter the listing.'
    Write-Host ''

    Write-Host 'CONNECTION - only pass what this client''s tenant actually has' -ForegroundColor Yellow
    Write-Host '  -All                  Connect every service. Needs -AccountUpn (+ -SharePointAdminUrl).'
    Write-Host '  -AccountUpn           Account used for every service under -All, unless overridden below.'
    Write-Host '  -ClientName           Engagement/client name for the report. Default: "Unnamed Engagement".'
    Write-Host '  -GraphUserPrincipalName        Account for Microsoft Graph (Entra ID, Defender, Intune).'
    Write-Host '  -ExchangeUserPrincipalName     Account for Exchange Online.'
    Write-Host '  -SharePointAdminUrl            Tenant SharePoint admin URL (needed together with below).'
    Write-Host '  -SharePointUserPrincipalName   Account for SharePoint Online.'
    Write-Host '  -TeamsUserPrincipalName        Account for Microsoft Teams.'
    Write-Host '  -ComplianceUserPrincipalName   Account for Security & Compliance (Purview DLP).'
    Write-Host '  -PowerBIUserPrincipalName      Account for Power BI (needs Power BI Service Admin/Fabric Admin).'
    Write-Host ''

    Write-Host 'FILTERING - what shows up in the exported report' -ForegroundColor Yellow
    Write-Host '  -Category / -IgnoreCategory    By category name, wildcards OK. Default: all categories.'
    Write-Host '  -Severity / -IgnoreSeverity    Critical | High | Medium | Low | Informational'
    Write-Host '  -Status / -IgnoreStatus        Pass | Fail | ManualReview | NotApplicable | Error'
    Write-Host '  -SortBy                        Severity | Category | CheckId | Status. Default: Category.'
    Write-Host '  -Reverse                       Reverse the sort order.'
    Write-Host ''

    Write-Host 'OUTPUT' -ForegroundColor Yellow
    Write-Host '  -OutputFormat         Excel | Csv | Json | Html | Pdf (multiple OK). Default: Excel.'
    Write-Host '                        Pdf needs Python + powershell-yaml (see README.md); the rest need nothing extra.'
    Write-Host '  -OutputPath           Output directory. Default: .\Reports'
    Write-Host '  -Silent               Suppress this tool''s own status/progress output.'
    Write-Host ''

    Write-Host 'EXAMPLES' -ForegroundColor Yellow
    Write-Host '  .\EntrAudit.ps1 -ListCategories'
    Write-Host '  .\EntrAudit.ps1 -ListChecks -Category "Power BI"'
    Write-Host '  .\EntrAudit.ps1 -ClientName "Contoso Ltd" -GraphUserPrincipalName alice@contoso.com -ExchangeUserPrincipalName alice@contoso.com'
    Write-Host '  .\EntrAudit.ps1 -All -AccountUpn alice@contoso.com -SharePointAdminUrl https://contoso-admin.sharepoint.com -ClientName "Contoso Ltd"'
    Write-Host '  .\EntrAudit.ps1 -ClientName "Contoso Ltd" -GraphUserPrincipalName alice@contoso.com -Status Fail -SortBy Severity -Reverse -OutputFormat Html'
    Write-Host ''
    Write-Host 'Full parameter help (PowerShell native): Get-Help .\EntrAudit.Core.ps1 -Full' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------------------------------------------------------------- Early exits ----
if ($Version) {
    $manifest = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'EntrAudit.psd1')
    Write-Host "EntrAudit v$($manifest.ModuleVersion)"
    exit 0
}

if ($Help) {
    Show-EntrAuditHelp
    exit 0
}

# Harvest real check metadata without connecting to anything - same technique the
# Demo\New-EntrAuditSampleData.ps1 generator uses (every check's NotApplicable
# fast path already returns CheckId/Category/Title/Severity/RequiredSource).
function Get-M365AllCheckMetadata {
    $disconnected = [PSCustomObject]@{
        GraphConnected = $false; ExoConnected = $false; SpoConnected = $false
        TeamsConnected = $false; ComplianceConnected = $false; PowerBIConnected = $false
    }
    Invoke-EntrAudit -ClientName 'introspection' -Context $disconnected -InformationAction SilentlyContinue 6>$null
}

if ($ListCategories) {
    Show-EntrAuditBanner
    $meta = Get-M365AllCheckMetadata
    Write-Host ''
    $meta | Group-Object Category | Sort-Object Name | ForEach-Object {
        Write-Host ('  {0,-35} {1,3} check(s)' -f $_.Name, $_.Count)
    }
    Write-Host ''
    Write-Host "$(@($meta).Count) checks total across $(($meta | Select-Object -ExpandProperty Category -Unique).Count) categories." -ForegroundColor DarkGray
    Write-Host ''
    exit 0
}

if ($ListChecks) {
    Show-EntrAuditBanner
    $meta = Get-M365AllCheckMetadata | Where-Object {
        $cat = $_.Category
        ($Category | Where-Object { $cat -like $_ }) -and (-not $Severity -or $_.Severity -in $Severity)
    }
    Write-Host ''
    $meta | Sort-Object Category, CheckId | Format-Table CheckId, Category, Title, Severity, RequiredSource -AutoSize | Out-Host
    Write-Host "$(@($meta).Count) check(s) matched." -ForegroundColor DarkGray
    Write-Host ''
    exit 0
}

# No connection info and no introspection flag -> show help rather than silently
# doing nothing or erroring unhelpfully.
$anyConnectionInfoGiven = $All -or $GraphUserPrincipalName -or $ExchangeUserPrincipalName -or $SharePointAdminUrl -or $TeamsUserPrincipalName -or $ComplianceUserPrincipalName -or $PowerBIUserPrincipalName
if (-not $anyConnectionInfoGiven) {
    Show-EntrAuditHelp
    exit 0
}

# ------------------------------------------------------------------ -All wiring --
if ($All) {
    if (-not $AccountUpn) {
        Write-Error '-All requires -AccountUpn (the account to use for Graph/Exchange/Teams/Compliance/Power BI, unless individually overridden).'
        exit 1
    }
    if (-not $GraphUserPrincipalName) { $GraphUserPrincipalName = $AccountUpn }
    if (-not $ExchangeUserPrincipalName) { $ExchangeUserPrincipalName = $AccountUpn }
    if (-not $TeamsUserPrincipalName) { $TeamsUserPrincipalName = $AccountUpn }
    if (-not $ComplianceUserPrincipalName) { $ComplianceUserPrincipalName = $AccountUpn }
    if (-not $PowerBIUserPrincipalName) { $PowerBIUserPrincipalName = $AccountUpn }
    if (-not $SharePointUserPrincipalName) { $SharePointUserPrincipalName = $AccountUpn }
    if (-not $SharePointAdminUrl) {
        Write-Warning '-All was given without -SharePointAdminUrl - SharePoint/OneDrive checks will report NotApplicable.'
    }
}

if (-not $Silent) { Show-EntrAuditBanner }

# ------------------------------------------------------------------- Connect -----
$connectParams = @{}
if ($GraphUserPrincipalName) { $connectParams.GraphUserPrincipalName = $GraphUserPrincipalName }
if ($ExchangeUserPrincipalName) { $connectParams.ExchangeUserPrincipalName = $ExchangeUserPrincipalName }
if ($SharePointAdminUrl) { $connectParams.SharePointAdminUrl = $SharePointAdminUrl }
if ($SharePointUserPrincipalName) { $connectParams.SharePointUserPrincipalName = $SharePointUserPrincipalName }
if ($TeamsUserPrincipalName) { $connectParams.TeamsUserPrincipalName = $TeamsUserPrincipalName }
if ($ComplianceUserPrincipalName) { $connectParams.ComplianceUserPrincipalName = $ComplianceUserPrincipalName }
if ($PowerBIUserPrincipalName) { $connectParams.PowerBIUserPrincipalName = $PowerBIUserPrincipalName }

if ($Silent) {
    $context = Connect-EntrAudit @connectParams 6>$null 3>$null
}
else {
    $context = Connect-EntrAudit @connectParams
}

# -------------------------------------------------------------------- Run --------
$runParams = @{
    ClientName      = $ClientName
    Context         = $context
    IncludeCategory = $Category
    ExcludeCategory = $IgnoreCategory
}
if ($Silent) {
    $results = Invoke-EntrAudit @runParams 6>$null
}
else {
    $results = Invoke-EntrAudit @runParams
}

# ------------------------------------------------------------------- Filter ------
if ($Status) { $results = $results | Where-Object { $_.Status -in $Status } }
if ($IgnoreStatus) { $results = $results | Where-Object { $_.Status -notin $IgnoreStatus } }
if ($Severity) { $results = $results | Where-Object { $_.Severity -in $Severity } }
if ($IgnoreSeverity) { $results = $results | Where-Object { $_.Severity -notin $IgnoreSeverity } }

# -------------------------------------------------------------------- Sort -------
$severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
$statusRank = @{ Fail = 0; Error = 1; ManualReview = 2; NotApplicable = 3; Pass = 4 }
$sortExpr = switch ($SortBy) {
    'Severity' { { $severityRank[$_.Severity] } }
    'Status' { { $statusRank[$_.Status] } }
    'CheckId' { { $_.CheckId } }
    default { { $_.Category } }
}
$results = if ($Reverse) { $results | Sort-Object -Property $sortExpr -Descending } else { $results | Sort-Object -Property $sortExpr }

if (@($results).Count -eq 0) {
    Write-Warning 'No results matched the given filters - nothing to export.'
    exit 0
}

# ------------------------------------------------------------------- Export ------
$exportParams = @{
    Results      = $results
    ClientName   = $ClientName
    OutputPath   = $OutputPath
    OutputFormat = $OutputFormat
    Context      = $context
}
if ($Silent) {
    $results | Export-EntrAuditReport @exportParams 6>$null
}
else {
    $results | Export-EntrAuditReport @exportParams
}
