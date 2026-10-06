# Microsoft Forms has no public admin Graph API as of this writing — every check
# here is a manual-review stub pointing at the exact admin center path. They always
# run (RequiredSource 'Manual') regardless of which services were connected.

function Test-M365_Forms_ExternalSharingDefault {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'FORMS-01' -Category 'Microsoft Forms' `
        -Title 'Microsoft Forms External Sharing Default Too Permissive' -Severity 'Low' -Status ManualReview `
        -Summary 'No public admin Graph API exposes Forms tenant settings — confirm by hand whether external (anyone-with-link) sharing is the default for new forms.' `
        -Remediation 'Set the default sharing scope for new forms to "within organization" and require users to explicitly opt in to external sharing per form.' `
        -AdminCenterPath 'Microsoft 365 admin center > Settings > Org settings > Microsoft Forms > Internal/external sharing' `
        -RequiredSource 'Manual'
}

function Test-M365_Forms_PhishingProtectionExternalRespondents {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'FORMS-02' -Category 'Microsoft Forms' `
        -Title 'Phishing Protection for External Respondents Not Confirmed' -Severity 'Low' -Status ManualReview `
        -Summary 'Confirm whether additional phishing/identity protections (e.g. requiring sign-in, blocking record-only-once bypass) are enabled for forms shared with external respondents.' `
        -Remediation 'Enable the available phishing-protection controls for forms accepting responses from people outside the organization.' `
        -AdminCenterPath 'Microsoft 365 admin center > Settings > Org settings > Microsoft Forms > Phishing protection' `
        -RequiredSource 'Manual'
}

function Test-M365_Forms_RecordRespondentNamesDefault {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'FORMS-03' -Category 'Microsoft Forms' `
        -Title 'Record Respondent Names Default Setting Not Confirmed' -Severity 'Informational' -Status ManualReview `
        -Summary 'Confirm the tenant default for recording respondent names aligns with the organization''s privacy expectations for internal forms/surveys.' `
        -Remediation 'Set the "record names of respondents" default per organizational privacy policy, and ensure form owners understand how to override it per form.' `
        -AdminCenterPath 'Microsoft 365 admin center > Settings > Org settings > Microsoft Forms' `
        -RequiredSource 'Manual'
}
