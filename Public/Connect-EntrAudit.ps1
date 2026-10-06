function Connect-EntrAudit {
    <#
    .SYNOPSIS
        Interactively signs in to whichever M365 services are in scope for this
        engagement, each optionally as a different account.

    .DESCRIPTION
        Every service param is OPTIONAL. Only pass the ones the client's tenant
        actually uses / that you have Global Reader + Security Reader (or
        equivalent) access to. Anything you don't pass simply isn't connected,
        and every check that needs it will report Status = NotApplicable at
        report time instead of erroring — that's the mechanism for telling the
        tool "this tenant doesn't use Teams / Power BI / Purview DLP / etc."

        Each connection uses that module's normal interactive sign-in flow (a
        browser/WAM popup), so Microsoft Authenticator push and passkey/FIDO2
        work exactly as they would logging into the portal by hand. A failed
        connection for one service does not prevent connecting the others.

    .PARAMETER GraphUserPrincipalName
        Account to use for Microsoft Graph (Entra ID, Conditional Access, Defender
        Secure Score/incidents, Intune/Autopilot). Needs Global Reader + Security
        Reader directory roles.

    .PARAMETER ExchangeUserPrincipalName
        Account to use for Exchange Online PowerShell.

    .PARAMETER SharePointAdminUrl
        Tenant SharePoint admin URL, e.g. https://contoso-admin.sharepoint.com.
        Required together with -SharePointUserPrincipalName to check SharePoint
        Online / OneDrive tenant settings.

    .PARAMETER SharePointUserPrincipalName
        Account to use for SharePoint Online Management Shell.

    .PARAMETER TeamsUserPrincipalName
        Account to use for Microsoft Teams PowerShell. (Hint only — Connect-MicrosoftTeams
        itself prompts interactively; pass the account you intend to use so the
        prompt and this hint line up.)

    .PARAMETER ComplianceUserPrincipalName
        Account to use for Security & Compliance PowerShell (Connect-IPPSSession) —
        needed for the Purview DLP check.

    .PARAMETER PowerBIUserPrincipalName
        Account to use for the Power BI Admin REST API. (Hint only —
        Connect-PowerBIServiceAccount prompts interactively.) Needs Power BI Service
        Administrator or Fabric Administrator — Global Reader/Security Reader alone
        will not cover this.

    .EXAMPLE
        Connect-EntrAudit -GraphUserPrincipalName alice@client.com `
            -ExchangeUserPrincipalName alice@client.com `
            -SharePointAdminUrl https://client-admin.sharepoint.com -SharePointUserPrincipalName bob@client.com `
            -TeamsUserPrincipalName alice@client.com

        Connects Graph/EXO/Teams as alice, SharePoint as bob, and leaves Compliance
        and Power BI unconnected (their checks will report NotApplicable).
    #>
    [CmdletBinding()]
    param(
        [string]$GraphUserPrincipalName,
        [string]$ExchangeUserPrincipalName,
        [string]$SharePointAdminUrl,
        [string]$SharePointUserPrincipalName,
        [string]$TeamsUserPrincipalName,
        [string]$ComplianceUserPrincipalName,
        [string]$PowerBIUserPrincipalName,
        [string[]]$GraphScopes = @(
            'Policy.Read.All', 'Directory.Read.All', 'User.Read.All', 'Domain.Read.All',
            'RoleManagement.Read.Directory', 'IdentityGovernance.Read.All',
            'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All',
            'DeviceManagementManagedDevices.Read.All', 'SecurityEvents.Read.All',
            'AuditLog.Read.All', 'Organization.Read.All', 'Group.Read.All'
        )
    )

    $context = [ordered]@{
        GraphConnected      = $false
        ExoConnected        = $false
        SpoConnected        = $false
        TeamsConnected      = $false
        ComplianceConnected = $false
        PowerBIConnected    = $false
        TenantId            = $null
        TenantName          = $null
        ConnectedAt         = Get-Date
    }

    Write-Host ''
    Write-Host '=== M365 Review — connecting services in scope for this engagement ===' -ForegroundColor Cyan

    if ($GraphUserPrincipalName) {
        Write-Host "`n[Graph] Connecting as $GraphUserPrincipalName ..." -ForegroundColor Yellow
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            Connect-MgGraph -Scopes $GraphScopes -NoWelcome -ErrorAction Stop
            $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
            $context.GraphConnected = $true
            $context.TenantId = $org.Id
            $context.TenantName = $org.DisplayName
            Write-Host "  Connected. Tenant: $($org.DisplayName) ($($org.Id))" -ForegroundColor Green
        }
        catch {
            Write-Warning "[Graph] Connection failed: $($_.Exception.Message)"
            Write-Warning '[Graph] Identity / Conditional Access / Defender / Intune checks will report NotApplicable.'
        }
    }
    else {
        Write-Host "`n[Graph] Skipped (no -GraphUserPrincipalName) — Identity/Defender/Intune checks will be NotApplicable." -ForegroundColor DarkGray
    }

    if ($ExchangeUserPrincipalName) {
        Write-Host "`n[Exchange Online] Connecting as $ExchangeUserPrincipalName ..." -ForegroundColor Yellow
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            Connect-ExchangeOnline -UserPrincipalName $ExchangeUserPrincipalName -ShowBanner:$false -ErrorAction Stop
            $context.ExoConnected = $true
            Write-Host '  Connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "[Exchange Online] Connection failed: $($_.Exception.Message)"
            Write-Warning '[Exchange Online] Exchange mail-security checks will report NotApplicable.'
        }
    }
    else {
        Write-Host "`n[Exchange Online] Skipped (no -ExchangeUserPrincipalName) — Exchange checks will be NotApplicable." -ForegroundColor DarkGray
    }

    if ($SharePointAdminUrl -and $SharePointUserPrincipalName) {
        Write-Host "`n[SharePoint Online] Connecting to $SharePointAdminUrl as $SharePointUserPrincipalName ..." -ForegroundColor Yellow
        try {
            Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
            Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
            $context.SpoConnected = $true
            Write-Host '  Connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "[SharePoint Online] Connection failed: $($_.Exception.Message)"
            Write-Warning '[SharePoint Online] SharePoint/OneDrive checks will report NotApplicable.'
        }
    }
    elseif ($SharePointAdminUrl -or $SharePointUserPrincipalName) {
        Write-Warning 'Both -SharePointAdminUrl and -SharePointUserPrincipalName are required to connect to SharePoint Online — skipping, SharePoint/OneDrive checks will report NotApplicable.'
    }
    else {
        Write-Host "`n[SharePoint Online] Skipped (no -SharePointAdminUrl/-SharePointUserPrincipalName) — SharePoint/OneDrive checks will be NotApplicable." -ForegroundColor DarkGray
    }

    if ($TeamsUserPrincipalName) {
        Write-Host "`n[Teams] Connecting (sign in as $TeamsUserPrincipalName when prompted) ..." -ForegroundColor Yellow
        try {
            Import-Module MicrosoftTeams -ErrorAction Stop
            Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
            $context.TeamsConnected = $true
            Write-Host '  Connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "[Teams] Connection failed: $($_.Exception.Message)"
            Write-Warning '[Teams] Teams checks will report NotApplicable.'
        }
    }
    else {
        Write-Host "`n[Teams] Skipped (no -TeamsUserPrincipalName) — Teams checks will be NotApplicable." -ForegroundColor DarkGray
    }

    if ($ComplianceUserPrincipalName) {
        Write-Host "`n[Compliance] Connecting (Security & Compliance PowerShell) as $ComplianceUserPrincipalName ..." -ForegroundColor Yellow
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            Connect-IPPSSession -UserPrincipalName $ComplianceUserPrincipalName -ErrorAction Stop
            $context.ComplianceConnected = $true
            Write-Host '  Connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "[Compliance] Connection failed: $($_.Exception.Message)"
            Write-Warning '[Compliance] Purview DLP check will report NotApplicable.'
        }
    }
    else {
        Write-Host "`n[Compliance] Skipped (no -ComplianceUserPrincipalName) — Purview DLP check will be NotApplicable." -ForegroundColor DarkGray
    }

    if ($PowerBIUserPrincipalName) {
        Write-Host "`n[Power BI] Connecting (sign in as $PowerBIUserPrincipalName when prompted) ..." -ForegroundColor Yellow
        Write-Host '  Requires Power BI Service Administrator / Fabric Administrator — Global Reader/Security Reader alone will not work.' -ForegroundColor DarkGray
        try {
            Import-Module MicrosoftPowerBIMgmt -ErrorAction Stop
            Connect-PowerBIServiceAccount -ErrorAction Stop | Out-Null
            $context.PowerBIConnected = $true
            Write-Host '  Connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "[Power BI] Connection failed: $($_.Exception.Message)"
            Write-Warning '[Power BI] Power BI tenant-setting checks will report NotApplicable.'
        }
    }
    else {
        Write-Host "`n[Power BI] Skipped (no -PowerBIUserPrincipalName) — Power BI checks will be NotApplicable." -ForegroundColor DarkGray
    }

    $script:EntrAuditContext = $context

    Write-Host "`n=== Service scope for this run ===" -ForegroundColor Cyan
    foreach ($key in @('GraphConnected', 'ExoConnected', 'SpoConnected', 'TeamsConnected', 'ComplianceConnected', 'PowerBIConnected')) {
        $label = $key -replace 'Connected$', ''
        $status = if ($context[$key]) { 'Connected' } else { 'Not connected -> checks will report NotApplicable' }
        $color = if ($context[$key]) { 'Green' } else { 'DarkGray' }
        Write-Host ('  {0,-12} {1}' -f $label, $status) -ForegroundColor $color
    }
    Write-Host ''

    return [PSCustomObject]$context
}
