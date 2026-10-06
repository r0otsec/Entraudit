# Defender for Endpoint checks ride the Graph connection (Graph Security API + Intune
# device inventory). Defender for Cloud Apps is a separate admin surface with its own
# API/token (not Graph), so it ships as a manual-review deployment checklist — this
# client's Cloud Apps rollout is "in flight", so the output should tell the tester
# exactly what's configured vs. still outstanding rather than guess.

function Test-M365_Defender_SecureScore {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'DEFENDER-01'
        Category        = 'Defender'
        Title           = 'Microsoft Secure Score Below Target'
        Severity        = 'Informational'
        Remediation     = 'Review the Secure Score improvement action list in the Microsoft Defender portal and prioritize high-impact, low-effort actions relevant to this engagement''s scope.'
        AdminCenterPath = 'security.microsoft.com > Secure score'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' -ErrorAction Stop
        $latest = $resp.value | Select-Object -First 1
        if (-not $latest) {
            New-M365CheckResult @meta -Status ManualReview -Summary 'No Secure Score data returned — Secure Score may not yet be populated for this tenant.'
            return
        }
        $pct = [math]::Round(($latest.currentScore / $latest.maxScore) * 100, 1)
        New-M365CheckResult @meta -Status ManualReview `
            -Summary "Current Secure Score: $($latest.currentScore) / $($latest.maxScore) ($pct%) as of $($latest.createdDateTime). Review the improvement action list for specifics." `
            -RawData $latest
    }
}

function Test-M365_Defender_OpenHighSeverityIncidents {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'DEFENDER-02'
        Category        = 'Defender'
        Title           = 'Open High/Medium Severity Security Incidents'
        Severity        = 'Informational'
        Remediation     = 'Triage and action open high/medium severity incidents in the Microsoft Defender portal; this is point-in-time context for the review, not a standalone misconfiguration finding.'
        AdminCenterPath = 'security.microsoft.com > Incidents & alerts > Incidents'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/security/incidents?`$filter=status eq 'active' and (severity eq 'high' or severity eq 'medium')&`$top=50" -ErrorAction Stop
        $count = @($resp.value).Count
        New-M365CheckResult @meta -Status ManualReview `
            -Summary "$count open high/medium severity incident(s) at time of review. Snapshot only — reflects point-in-time SOC activity, not a configuration gap." `
            -RawData $resp.value
    }
}

function Test-M365_Defender_EndpointOnboardingGaps {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'DEFENDER-03'
        Category        = 'Defender'
        Title           = 'Intune-Managed Devices Not Onboarded to Defender for Endpoint'
        Severity        = 'Medium'
        Remediation     = 'Deploy/confirm the Defender for Endpoint onboarding configuration profile reaches every managed device; investigate devices reporting an unhealthy or missing onboarding state.'
        AdminCenterPath = 'Intune admin center > Endpoint security > Antivirus / Endpoint detection and response; security.microsoft.com > Device inventory'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop -Property DeviceName, DeviceHealthAttestationState, ManagedDeviceName, Id
        $total = @($devices).Count
        New-M365CheckResult @meta -Status ManualReview `
            -Summary "$total Intune-managed device(s) found. Defender for Endpoint onboarding health is not exposed on this Intune device property set — cross-check device counts against security.microsoft.com > Device inventory onboarding status by hand." `
            -RawData $devices
    }
}

function Test-M365_Defender_CloudAppsDeploymentChecklist {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'DEFENDER-04' -Category 'Defender' `
        -Title 'Defender for Cloud Apps Deployment Checklist (In-Flight Rollout)' -Severity 'Informational' -Status ManualReview `
        -Summary 'Defender for Cloud Apps configuration lives in its own admin surface (not Microsoft Graph) and this client''s deployment is mid-rollout. Confirm, item by item: (1) Cloud Discovery log collector/connector configured, (2) App connectors configured for in-use SaaS apps, (3) OAuth app governance policies configured, (4) Conditional Access App Control session policies configured for browser access to key apps.' `
        -Remediation 'Work through the four items above in order; each is independently checkable in the Defender for Cloud Apps portal and should be captured as its own sub-finding if incomplete.' `
        -AdminCenterPath 'security.microsoft.com > Cloud apps > Cloud Discovery / Connected apps / App governance / Conditional Access App Control' `
        -RequiredSource 'Manual'
}
