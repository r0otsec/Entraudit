# SharePoint Online & OneDrive tenant settings. Require Context.SpoConnected.

function Test-M365_Spo_ExternalSharingTooPermissive {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'SHAREPOINT-01'
        Category        = 'SharePoint Online & OneDrive'
        Title           = 'External Sharing / Default Link Settings Too Permissive'
        Severity        = 'Medium'
        Remediation     = 'Restrict external sharing to approved domains/security groups, require sign-in for sharing, prevent guest resharing, and set the default sharing link to "Specific people" with View permission rather than Anyone/Edit.'
        AdminCenterPath = 'SharePoint admin center > Policies > Sharing'
        RequiredSource  = 'Spo'
    }
    if (-not $Context.SpoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'SharePoint Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $tenant = Get-SPOTenant -ErrorAction Stop
        $issues = @()
        if ($tenant.SharingCapability -eq 'ExternalUserAndGuestSharing') { $issues += "SharingCapability=$($tenant.SharingCapability)" }
        if ($tenant.DefaultSharingLinkType -eq 'AnonymousAccess') { $issues += "DefaultSharingLinkType=$($tenant.DefaultSharingLinkType)" }
        if ($tenant.DefaultLinkPermission -eq 'Edit') { $issues += "DefaultLinkPermission=$($tenant.DefaultLinkPermission)" }
        if ($tenant.PreventExternalUsersFromResharing -eq $false) { $issues += 'PreventExternalUsersFromResharing=False' }
        if (-not $tenant.RequireAcceptingAccountMatchInvitedAccount) { $issues += 'RequireAcceptingAccountMatchInvitedAccount=False' }
        $status = if ($issues.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($issues.Count -gt 0) { $issues -join '; ' } else { 'External sharing / default link settings are at recommended values.' }) `
            -RawData $tenant
    }
}

function Test-M365_Spo_GuestAccessNoExpiration {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'SHAREPOINT-02'
        Category        = 'SharePoint Online & OneDrive'
        Title           = 'Guest Access Does Not Expire (>30 days or disabled)'
        Severity        = 'Low'
        Remediation     = 'Run: Set-SPOTenant -ExternalUserExpireInDays 30 -ExternalUserExpirationRequired $true'
        AdminCenterPath = 'SharePoint admin center > Policies > Sharing > More external sharing settings'
        RequiredSource  = 'Spo'
    }
    if (-not $Context.SpoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'SharePoint Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $tenant = Get-SPOTenant -ErrorAction Stop
        $ok = $tenant.ExternalUserExpirationRequired -and $tenant.ExternalUserExpireInDays -le 30
        $status = if ($ok) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status `
            -Summary "ExternalUserExpirationRequired=$($tenant.ExternalUserExpirationRequired), ExternalUserExpireInDays=$($tenant.ExternalUserExpireInDays)" `
            -RawData $tenant
    }
}

function Test-M365_Spo_GuestReauthNotEnforced {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'SHAREPOINT-03'
        Category        = 'SharePoint Online & OneDrive'
        Title           = 'Verification-Code Guest Reauthentication Not Enforced (>15 days or disabled)'
        Severity        = 'Low'
        Remediation     = 'Run: Set-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 15'
        AdminCenterPath = 'SharePoint admin center > Policies > Sharing > More external sharing settings'
        RequiredSource  = 'Spo'
    }
    if (-not $Context.SpoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'SharePoint Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $tenant = Get-SPOTenant -ErrorAction Stop
        $ok = $tenant.EmailAttestationRequired -and $tenant.EmailAttestationReAuthDays -le 15
        $status = if ($ok) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status `
            -Summary "EmailAttestationRequired=$($tenant.EmailAttestationRequired), EmailAttestationReAuthDays=$($tenant.EmailAttestationReAuthDays)" `
            -RawData $tenant
    }
}

function Test-M365_Spo_LegacyAuthAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'SHAREPOINT-04'
        Category        = 'SharePoint Online & OneDrive'
        Title           = 'Apps Using Legacy (Non-Modern) Authentication Allowed'
        Severity        = 'Medium'
        Remediation     = 'Set "Apps that don''t use modern authentication" to Block Access: SharePoint admin center > Policies > Access control > Apps that don''t use modern authentication.'
        AdminCenterPath = 'SharePoint admin center > Policies > Access control > Apps that don''t use modern authentication'
        RequiredSource  = 'Spo'
    }
    if (-not $Context.SpoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'SharePoint Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $tenant = Get-SPOTenant -ErrorAction Stop
        $status = if ($tenant.LegacyAuthProtocolsEnabled) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status -Summary "LegacyAuthProtocolsEnabled = $($tenant.LegacyAuthProtocolsEnabled)" -RawData $tenant
    }
}

function Test-M365_Spo_OneDriveSyncNotRestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'SHAREPOINT-05'
        Category        = 'SharePoint Online & OneDrive'
        Title           = 'OneDrive Sync Client Not Restricted to Managed Domains'
        Severity        = 'Medium'
        Remediation     = 'Restrict OneDrive sync to devices joined to specific (approved) AD/Entra domains: Set-SPOTenantSyncClientRestriction -DomainGuids <guid list> -BlockMacSync $true/$false as appropriate.'
        AdminCenterPath = 'SharePoint admin center > Policies > Device access, or Set-SPOTenantSyncClientRestriction'
        RequiredSource  = 'Spo'
    }
    if (-not $Context.SpoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'SharePoint Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $restriction = Get-SPOTenantSyncClientRestriction -ErrorAction Stop
        $status = if ($restriction.TenantRestrictionEnabled) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status -Summary "TenantRestrictionEnabled = $($restriction.TenantRestrictionEnabled)" -RawData $restriction
    }
}
