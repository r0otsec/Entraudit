#Requires -Version 7.0
<#
.SYNOPSIS
    Demo-only utility: generates a large, realistic-looking sample result set (one
    row per real check) for a fictitious tenant, for previewing report formatting
    (Cover/Summary/per-category tabs) without needing a live client engagement.

.DESCRIPTION
    This is NOT part of the engagement workflow - Connect-EntrAudit /
    Invoke-EntrAudit / Export-EntrAuditReport are the real path. This script:

      1. Harvests the real CheckId / Category / Title / Remediation /
         AdminCenterPath / Severity / RequiredSource straight from every actual
         Test-M365_* function (by calling each with every service "disconnected",
         which is the real NotApplicable fast path every check already has - so
         this is guaranteed to match the tool exactly, never a hand-copied,
         driftable duplicate).
      2. Overrides Status/Summary/Evidence/AffectedObjects per check with
         realistic, report-style narrative content for a fictitious company
         ("Fabrikam Retail Group") - grounded in the kinds of findings seen across
         the real past engagement reports this tool's checks were built from.

    Fabrikam Retail Group is entirely fictitious (Microsoft's standard sample
    company name) - not a real client, and not one of the five client reports in
    this folder.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\SampleOutput')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\EntrAudit.psd1') -Force

# ---- Step 1: harvest real metadata for every check (NotApplicable fast path) ----
$disconnected = [PSCustomObject]@{
    GraphConnected = $false; ExoConnected = $false; SpoConnected = $false
    TeamsConnected = $false; ComplianceConnected = $false; PowerBIConnected = $false
}
$baseline = Invoke-EntrAudit -ClientName 'Fabrikam Retail Group' -Context $disconnected
$byCheckId = @{}
foreach ($r in $baseline) { $byCheckId[$r.CheckId] = $r }

# ---- Step 2: per-check demo overrides (Status/Summary/Evidence/AffectedObjects) ----
# PowerBI is deliberately left out of $overrides and out of $connectedServices below
# -> demonstrates the "service not in use for this engagement" NotApplicable path.
$overrides = @{
    'ENTRA-01' = @{ Status = 'Fail'; Summary = 'Twelve accounts hold the Global Administrator role, well above the recommended 1-5.'; Evidence = '12 Global Administrators found (recommended range: 1-5).'; AffectedObjects = 'j.carter@fabrikamretail.com; s.ahmed@fabrikamretail.com; m.obrien@fabrikamretail.com; svc-globaladmin@fabrikamretail.com; r.nguyen@fabrikamretail.com; +7 more' }
    'ENTRA-02' = @{ Status = 'Fail'; Summary = 'Three Global Administrator accounts also hold a standard M365 license, widening the blast radius of those privileged identities.'; Evidence = '3 of 12 Global Administrator accounts hold an active M365 Business Premium license.'; AffectedObjects = 'j.carter@fabrikamretail.com; s.ahmed@fabrikamretail.com; svc-globaladmin@fabrikamretail.com' }
    'ENTRA-03' = @{ Status = 'ManualReview'; Summary = 'MFA is enforced for admins via Conditional Access, but no policy requires the phishing-resistant authentication strength.'; Evidence = "Found 1 enabled policy enforcing MFA for admins ('Require MFA for Admins'), but none require the built-in Phishing-resistant MFA authentication strength."; AffectedObjects = 'CA001-Require MFA for Admins' }
    'ENTRA-04' = @{ Status = 'Fail'; Summary = 'The device code authentication flow is not blocked, leaving the tenant exposed to device-code phishing.'; Evidence = 'No enabled Conditional Access policy blocks the device code authentication flow.' }
    'ENTRA-05' = @{ Status = 'Fail'; Summary = 'Standard users can create new Entra tenants and become Global Administrator of them, enabling shadow IT outside existing controls.'; Evidence = 'AllowedToCreateTenants = True' }
    'ENTRA-06' = @{ Status = 'Fail'; Summary = 'Standard users can create and manage security groups without administrative oversight.'; Evidence = 'AllowedToCreateSecurityGroups = True' }
    'ENTRA-07' = @{ Status = 'Fail'; Summary = 'Standard users can register new application registrations in Entra ID.'; Evidence = 'AllowedToCreateApps = True' }
    'ENTRA-08' = @{ Status = 'Fail'; Summary = 'Guest invite and guest access restrictions are both set to their most permissive options.'; Evidence = "AllowInvitesFrom = everyone (not restricted to admins); GuestUserRoleId does not match the most-restrictive built-in role." }
    'ENTRA-09' = @{ Status = 'ManualReview'; Summary = 'Security Defaults is disabled; coverage relies entirely on the tenant''s own Conditional Access policies.'; Evidence = 'Security Defaults IsEnabled = False - cross-check against ENTRA-03/ENTRA-04 Conditional Access results for equivalent coverage.' }
    'ENTRA-10' = @{ Status = 'ManualReview'; Summary = '47 guest user accounts exist in the tenant; several appear to date back more than two years with no recent sign-in.'; Evidence = '47 guest user accounts found. Flag for manual staleness review - no fixed numeric threshold applies generically.'; AffectedObjects = '47 guest accounts (see RawEvidence sidecar for full list)' }
    'ENTRA-11' = @{ Status = 'Fail'; Summary = 'The admin consent workflow is disabled, so users without consent rights cannot formally request review of third-party app permission grants.'; Evidence = 'Admin consent workflow IsEnabled = False' }
    'ENTRA-12' = @{ Status = 'Fail'; Summary = 'No dynamic group automatically captures guest accounts, so Conditional Access and other controls scoped to such a group will not automatically apply to new guests.'; Evidence = 'No dynamic group with a guest-scoped membership rule was found.' }
    'ENTRA-13' = @{ Status = 'Fail'; Summary = 'No recurring access reviews exist for privileged directory roles or for guest users across Microsoft 365 Groups.'; Evidence = '0 access review definitions exist in the tenant.' }
    'ENTRA-14' = @{ Status = 'Fail'; Summary = 'SMS and Voice Call remain enabled as allowed authentication methods, both phishable/SIM-swappable.'; Evidence = 'Enabled weak methods: Sms, Voice' }
    'ENTRA-15' = @{ Status = 'ManualReview' }
    'ENTRA-16' = @{ Status = 'ManualReview' }
    'ENTRA-17' = @{ Status = 'ManualReview' }

    'OFFICE-01' = @{ Status = 'Fail'; Summary = 'Users can access the Office Store and start trials on the organization''s behalf without administrative oversight.'; Evidence = 'isOfficeStoreEnabled = True, isAppAndServicesTrialEnabled = True' }
    'OFFICE-02' = @{ Status = 'Fail'; Summary = 'The Default Role Assignment Policy still includes the roles that let users install custom and marketplace Outlook add-ins.'; Evidence = "Default Role Assignment Policy includes: My Custom Apps, My Marketplace Apps, My ReadWriteMailboxApps" }
    'OFFICE-03' = @{ Status = 'Fail'; Summary = 'Outlook on the Web allows users to attach files from third-party, non-Microsoft storage providers.'; Evidence = 'Policies with third-party storage enabled: OwaMailboxPolicy-Default' }
    'OFFICE-04' = @{ Status = 'ManualReview' }
    'OFFICE-05' = @{ Status = 'ManualReview' }

    'EXO-01' = @{ Status = 'Fail'; Summary = 'DKIM signing is not enabled for the primary accepted domain, so outbound mail cannot be cryptographically verified.'; Evidence = 'DKIM disabled for: fabrikamretail.com'; AffectedObjects = 'fabrikamretail.com' }
    'EXO-02' = @{ Status = 'Fail'; Summary = 'Automatic mail forwarding is permitted rather than blocked, a common post-compromise exfiltration path.'; Evidence = 'AutoForwardingMode not Off on: Default=Automatic' }
    'EXO-03' = @{ Status = 'Pass'; Summary = 'External sender tagging is enabled, helping users recognize inbound mail originating outside the organization.'; Evidence = 'External sender tagging Enabled = True' }
    'EXO-04' = @{ Status = 'Fail'; Summary = 'Unified Audit Log ingestion is disabled, significantly impairing incident detection and forensic visibility.'; Evidence = 'UnifiedAuditLogIngestionEnabled = False' }
    'EXO-05' = @{ Status = 'Fail'; Summary = 'Neither the anti-malware nor the outbound anti-spam policy notifies administrators when an internal user is blocked, delaying detection of compromised accounts.'; Evidence = 'Anti-malware policies missing internal notification: 1; outbound-spam policies missing notification: 1' }
    'EXO-06' = @{ Status = 'Fail'; Summary = 'A sample of shared mailboxes shows interactive sign-in still enabled, allowing direct logon if credentials are compromised.'; Evidence = '6 of 14 shared mailboxes sampled have sign-in enabled.'; AffectedObjects = 'orders@fabrikamretail.com; returns@fabrikamretail.com; warehouse-alerts@fabrikamretail.com; payroll@fabrikamretail.com; facilities@fabrikamretail.com; marketing-shared@fabrikamretail.com' }
    'EXO-07' = @{ Status = 'Fail'; Summary = 'MailTips are disabled tenant-wide, increasing the risk of accidental information disclosure (e.g. replying externally without warning).'; Evidence = 'Disabled: MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled' }
    'EXO-08' = @{ Status = 'ManualReview'; Summary = 'The default sharing policy allows external calendar sharing; the configured domain scope needs manual confirmation.'; Evidence = "Sharing policies: Default[Enabled=True]. Review Domains on each for external exposure." }
    'EXO-09' = @{ Status = 'Fail'; Summary = 'The primary accepted domain does not publish a valid SPF record, risking legitimate mail being marked as spam or spoofed.'; Evidence = 'Domains missing a valid SPF record: fabrikamretail.com'; AffectedObjects = 'fabrikamretail.com' }
    'EXO-10' = @{ Status = 'Fail'; Summary = 'DMARC is published but set to p=none (monitor-only), so spoofed mail failing SPF/DKIM is still delivered rather than quarantined.'; Evidence = 'fabrikamretail.com: p=none'; AffectedObjects = 'fabrikamretail.com' }

    'SHAREPOINT-01' = @{ Status = 'Fail'; Summary = 'External sharing is set to allow any external user, with the default link scope set to Anyone/Edit rather than restricted and view-only.'; Evidence = 'SharingCapability=ExternalUserAndGuestSharing; DefaultLinkPermission=Edit' }
    'SHAREPOINT-02' = @{ Status = 'Fail'; Summary = 'Guest access to sites and OneDrive does not automatically expire.'; Evidence = 'ExternalUserExpirationRequired=False, ExternalUserExpireInDays=60' }
    'SHAREPOINT-03' = @{ Status = 'Fail'; Summary = 'Guests authenticating via a one-time verification code are not required to periodically reauthenticate.'; Evidence = 'EmailAttestationRequired=False, EmailAttestationReAuthDays=0' }
    'SHAREPOINT-04' = @{ Status = 'Fail'; Summary = 'Apps using legacy, non-modern authentication are still permitted to access SharePoint.'; Evidence = 'LegacyAuthProtocolsEnabled = True' }
    'SHAREPOINT-05' = @{ Status = 'Fail'; Summary = 'The OneDrive sync client is not restricted to devices joined to approved domains, allowing sync from unmanaged devices.'; Evidence = 'TenantRestrictionEnabled = False' }

    'TEAMS-01' = @{ Status = 'Fail'; Summary = 'Meeting recording is enabled in the Global (org-wide default) meeting policy, allowing any organizer to record meetings.'; Evidence = 'Global policy AllowCloudRecording = True' }
    'TEAMS-02' = @{ Status = 'Fail'; Summary = 'External/federated access is allowed for all domains with no allow-list, a vector abused in real-world Teams phishing campaigns.'; Evidence = 'AllowFederatedUsers=True, AllowedDomains configured=False' }
    'TEAMS-03' = @{ Status = 'ManualReview'; Summary = 'Teams channel email addresses can receive mail from any sender; confirm whether a domain restriction is layered on top.'; Evidence = 'AllowEmailIntoChannel = True' }
    'TEAMS-04' = @{ Status = 'Fail'; Summary = 'Several non-Microsoft cloud storage providers remain enabled for file sharing within Teams.'; Evidence = 'Enabled third-party providers: AllowDropBox, AllowGoogleDrive' }
    'TEAMS-05' = @{ Status = 'ManualReview'; Summary = 'The Global app permission policy does not restrict to an allow-list, permitting third-party and custom app installation.'; Evidence = 'DefaultCatalogAppsType=AllowedAppList, GlobalCatalogAppsType=AllAppsType' }

    'DEFENDER-01' = @{ Status = 'ManualReview'; Summary = 'Current Microsoft Secure Score is 61% of achievable - a point-in-time baseline, not itself a pass/fail finding.'; Evidence = 'Current Secure Score: 187 / 306 (61.1%).' }
    'DEFENDER-02' = @{ Status = 'ManualReview'; Summary = '3 open high/medium severity incidents at time of review - snapshot context for the SOC, not a configuration gap.'; Evidence = '3 open high/medium severity incident(s) at time of review.' }
    'DEFENDER-03' = @{ Status = 'ManualReview'; Summary = '214 Intune-managed devices found; onboarding health to Defender for Endpoint needs manual cross-check against the Defender device inventory.'; Evidence = '214 Intune-managed device(s) found.' }
    'DEFENDER-04' = @{ Status = 'ManualReview'; Summary = "Defender for Cloud Apps rollout is mid-deployment: Cloud Discovery log collector is configured and app connectors cover core SaaS (M365, Salesforce), but OAuth app governance policies and Conditional Access App Control sessions are not yet configured." }

    'INTUNE-01' = @{ Status = 'ManualReview' }
    'INTUNE-02' = @{ Status = 'ManualReview' }
    'INTUNE-03' = @{ Status = 'Pass'; Summary = 'Six device compliance policies are configured and assigned, covering Windows, iOS, and Android.'; Evidence = '6 device compliance policy/policies configured.'; AffectedObjects = 'Windows-Baseline; iOS-Baseline; Android-Enterprise-Baseline; Windows-Finance-Restricted; macOS-Baseline; Windows-Kiosk' }
    'INTUNE-04' = @{ Status = 'Fail'; Summary = 'No Windows Autopilot deployment profile exists, so new devices do not self-provision with the intended security baseline from first boot.'; Evidence = 'No Windows Autopilot deployment profiles exist in this tenant.' }
    'INTUNE-05' = @{ Status = 'Fail'; Summary = 'No Enrollment Status Page configuration exists, so users can reach the desktop before required apps/profiles finish installing.'; Evidence = 'No Enrollment Status Page configuration was found (default, non-blocking behavior applies).' }

    'FORMS-01' = @{ Status = 'ManualReview' }
    'FORMS-02' = @{ Status = 'ManualReview' }
    'FORMS-03' = @{ Status = 'ManualReview' }

    'COMPLIANCE-01' = @{ Status = 'Fail'; Summary = 'No Data Loss Prevention policies are configured anywhere in the tenant (Exchange, SharePoint, OneDrive, or Teams) - sensitive data can move or leave the organization with zero DLP controls or alerting.'; Evidence = 'No DLP policies exist anywhere in the tenant (Exchange/SharePoint/OneDrive/Teams).' }
}

# Services actually "connected" for this fictitious engagement - Power BI is
# deliberately excluded (client has no Premium/Fabric capacity), so every
# POWERBI-* check falls through to its real NotApplicable connection-check path
# untouched, exactly as it would for a real client that doesn't use the service.
$connectedServices = @('Graph', 'Exo', 'Spo', 'Teams', 'Compliance')

$sample = foreach ($base in $baseline) {
    $ov = $overrides[$base.CheckId]
    if (-not $ov) {
        # No override defined (shouldn't happen once all 64 are covered) - leave
        # the real NotApplicable/ManualReview baseline result untouched rather
        # than fabricate something.
        $base
        continue
    }
    if ($ov.Status -eq 'ManualReview' -and -not $ov.Summary -and $base.RequiredSource -eq 'Manual') {
        # Pure manual-review stub (banned password list, idle timeout, Forms, etc.)
        # - its real Summary/AdminCenterPath text already is the right demo content.
        $base
        continue
    }
    [PSCustomObject]@{
        PSTypeName      = 'EntrAudit.CheckResult'
        CheckId         = $base.CheckId
        Category        = $base.Category
        Title           = $base.Title
        Severity        = $base.Severity
        Status          = $ov.Status
        Summary         = $(if ($ov.Summary) { $ov.Summary } else { $base.Summary })
        Evidence        = $(if ($ov.Evidence) { $ov.Evidence } else { '' })
        AffectedObjects = $(if ($ov.AffectedObjects) { $ov.AffectedObjects } else { '' })
        Remediation     = $base.Remediation
        AdminCenterPath = $base.AdminCenterPath
        RequiredSource  = $base.RequiredSource
        RawData         = $null
        References      = $base.References
        Timestamp       = Get-Date
    }
}

$fakeContext = [PSCustomObject]@{
    GraphConnected      = 'Graph' -in $connectedServices
    ExoConnected        = 'Exo' -in $connectedServices
    SpoConnected        = 'Spo' -in $connectedServices
    TeamsConnected      = 'Teams' -in $connectedServices
    ComplianceConnected = 'Compliance' -in $connectedServices
    PowerBIConnected    = 'PowerBI' -in $connectedServices
    TenantId            = '8f3b2e4a-91c7-4a5e-b6d1-2c7e9a4f10b3'
    TenantName          = 'Fabrikam Retail Group'
}

$sample | Export-EntrAuditReport -ClientName 'Fabrikam Retail Group (DEMO)' -OutputPath $OutputPath -OutputFormat Excel, Html, Csv, Json, Pdf -Context $fakeContext

Write-Host "`n$(@($sample).Count) sample findings generated." -ForegroundColor Cyan
$sample | Group-Object Status | Select-Object Name, Count | Format-Table -AutoSize
