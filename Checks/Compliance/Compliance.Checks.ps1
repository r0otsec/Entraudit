# Purview compliance checks. Require Context.ComplianceConnected (Connect-IPPSSession).

function Test-M365_Compliance_NoDlpPoliciesConfigured {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'COMPLIANCE-01'
        Category        = 'Purview / Compliance'
        Title           = 'No Data Loss Prevention (DLP) Policies Configured'
        Severity        = 'High'
        Remediation     = 'Build DLP policies covering Exchange Online, SharePoint Online, OneDrive, and Teams, tailored to the organization''s sensitive data types (financial, PII, etc.) aligned to an industry-standard framework.'
        AdminCenterPath = 'Microsoft Purview compliance portal > Solutions > Data loss prevention > Policies'
        RequiredSource  = 'Compliance'
        References      = @('https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp')
    }
    if (-not $Context.ComplianceConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Security & Compliance PowerShell (Connect-IPPSSession) not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-DlpCompliancePolicy -ErrorAction Stop
        $status = if (@($policies).Count -eq 0) { 'Fail' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($policies).Count -eq 0) { 'No DLP policies exist anywhere in the tenant (Exchange/SharePoint/OneDrive/Teams).' } else { "$(@($policies).Count) DLP policy/policies exist — manually confirm coverage breadth and enforcement mode (test vs. enforce) per workload." }) `
            -Evidence (($policies | ForEach-Object { "$($_.Name) [Mode=$($_.Mode)]" }) -join ', ') -RawData $policies
    }
}
