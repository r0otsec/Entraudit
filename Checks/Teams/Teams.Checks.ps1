# Microsoft Teams tenant policy checks. Require Context.TeamsConnected.

function Test-M365_Teams_MeetingRecordingDefaultOn {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'TEAMS-01'
        Category        = 'Teams'
        Title           = 'Meeting Recording Enabled by Default (Global Policy)'
        Severity        = 'Low'
        Remediation     = 'Disable meeting recording in the Global (org-wide default) Teams meeting policy unless broadly required: Set-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false'
        AdminCenterPath = 'Teams admin center > Meetings > Meeting policies > Global'
        RequiredSource  = 'Teams'
    }
    if (-not $Context.TeamsConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Teams not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
        $status = if ($policy.AllowCloudRecording) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status -Summary "Global policy AllowCloudRecording = $($policy.AllowCloudRecording)" -RawData $policy
    }
}

function Test-M365_Teams_ExternalAccessUnrestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'TEAMS-02'
        Category        = 'Teams'
        Title           = 'External/Federated Access Unrestricted (All Domains Allowed)'
        Severity        = 'Medium'
        Remediation     = 'Restrict external Teams/Skype federation to an explicit allow-list of domains rather than allowing all external organizations: Set-CsTenantFederationConfiguration -AllowedDomains <allow-list>.'
        AdminCenterPath = 'Teams admin center > Users > External access'
        RequiredSource  = 'Teams'
    }
    if (-not $Context.TeamsConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Teams not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-CsTenantFederationConfiguration -ErrorAction Stop
        $status = if ($cfg.AllowFederatedUsers -and -not $cfg.AllowedDomains) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "AllowFederatedUsers=$($cfg.AllowFederatedUsers), AllowedDomains configured=$([bool]$cfg.AllowedDomains)" `
            -RawData $cfg
    }
}

function Test-M365_Teams_ChannelEmailOpenToAnySender {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'TEAMS-03'
        Category        = 'Teams'
        Title           = 'Teams Channel Email Open to Any External Sender'
        Severity        = 'Low'
        Remediation     = 'Restrict channel email to an approved domain allow-list rather than accepting mail from any sender: Teams admin center > Teams > Teams settings > Email integration.'
        AdminCenterPath = 'Teams admin center > Teams > Teams settings > Email integration'
        RequiredSource  = 'Teams'
    }
    if (-not $Context.TeamsConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Teams not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-CsTeamsClientConfiguration -ErrorAction Stop
        $status = if ($cfg.AllowEmailIntoChannel) { 'ManualReview' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "AllowEmailIntoChannel = $($cfg.AllowEmailIntoChannel)$(if ($cfg.AllowEmailIntoChannel) { ' — confirm whether a domain restriction is layered on top (not exposed on this cmdlet).' })" `
            -RawData $cfg
    }
}

function Test-M365_Teams_ThirdPartyStorageProvidersEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'TEAMS-04'
        Category        = 'Teams'
        Title           = 'Third-Party Cloud Storage Providers Enabled in Teams'
        Severity        = 'Low'
        Remediation     = 'Disable non-approved third-party storage providers (DropBox, Box, Google Drive, ShareFile, Egnyte) in Teams client configuration, keeping only SharePoint/OneDrive.'
        AdminCenterPath = 'Teams admin center > Teams > Teams settings > Files, or Get-CsTeamsClientConfiguration'
        RequiredSource  = 'Teams'
    }
    if (-not $Context.TeamsConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Teams not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-CsTeamsClientConfiguration -ErrorAction Stop
        $providerProps = @('AllowDropBox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte')
        $enabled = $providerProps | Where-Object { $cfg.$_ -eq $true }
        $status = if ($enabled.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($enabled.Count -gt 0) { "Enabled third-party providers: $($enabled -join ', ')" } else { 'No third-party cloud storage providers are enabled.' }) `
            -RawData $cfg
    }
}

function Test-M365_Teams_ThirdPartyAppsAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'TEAMS-05'
        Category        = 'Teams'
        Title           = 'App Permission Policy Allows Third-Party / Custom Apps'
        Severity        = 'Informational'
        Remediation     = 'Restrict the Global app permission policy so users cannot install arbitrary third-party or custom (including preview) apps without review.'
        AdminCenterPath = 'Teams admin center > Teams apps > Permission policies > Global'
        RequiredSource  = 'Teams'
    }
    if (-not $Context.TeamsConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Teams not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policy = Get-CsTeamsAppPermissionPolicy -Identity Global -ErrorAction Stop
        $status = if ($policy.DefaultCatalogAppsType -eq 'AllowedAppList' -and $policy.GlobalCatalogAppsType -eq 'AllowedAppList') { 'Pass' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary "DefaultCatalogAppsType=$($policy.DefaultCatalogAppsType), GlobalCatalogAppsType=$($policy.GlobalCatalogAppsType)" `
            -RawData $policy
    }
}
