# Office Applications — Office Store/add-ins and related Office-app surface settings.

function Test-M365_Office_StoreNotRestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'OFFICE-01'
        Category        = 'Office Applications'
        Title           = 'Office Store Access / Trials Not Restricted'
        Severity        = 'Medium'
        Remediation     = 'Uncheck "Let users access the Office Store" and "Let users start trials on behalf of your organization" in M365 Admin Center > Org settings > Services > User owned apps and services.'
        AdminCenterPath = 'Microsoft 365 admin center > Settings > Org settings > Services > User owned apps and services'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/admin/appsAndServices/settings' -ErrorAction Stop
        $officeStore = [bool]$resp.isOfficeStoreEnabled
        $trials = [bool]$resp.isAppAndServicesTrialEnabled
        $status = if ($officeStore -or $trials) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "isOfficeStoreEnabled = $officeStore, isAppAndServicesTrialEnabled = $trials" -RawData $resp
    }
}

function Test-M365_Office_OutlookAddinRolesNotRestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'OFFICE-02'
        Category        = 'Office Applications'
        Title           = 'Outlook Add-in Installation Roles Not Restricted'
        Severity        = 'Medium'
        Remediation     = 'Remove "My Custom Apps", "My Marketplace Apps", and "My ReadWriteMailboxApps" from the Default Role Assignment Policy: Exchange admin center > Roles > User roles.'
        AdminCenterPath = 'Exchange admin center > Roles > User roles > Default Role Assignment Policy'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policy = Get-RoleAssignmentPolicy -Identity 'Default Role Assignment Policy' -ErrorAction Stop
        $risky = @('My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailboxApps')
        $present = $policy.AssignedRoles | Where-Object { $_ -in $risky }
        $status = if (@($present).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($present).Count -gt 0) { "Default Role Assignment Policy includes: $($present -join ', ')" } else { 'Default Role Assignment Policy does not include the add-in installation roles.' }) `
            -RawData $policy
    }
}

function Test-M365_Office_OwaThirdPartyStorageAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'OFFICE-03'
        Category        = 'Office Applications'
        Title           = 'Outlook on the Web Allows Third-Party Storage Providers'
        Severity        = 'Low'
        Remediation     = 'Run: Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false'
        AdminCenterPath = 'Exchange admin center > Settings > Mail > Customization, or Set-OwaMailboxPolicy'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-OwaMailboxPolicy -ErrorAction Stop
        $offenders = $policies | Where-Object { $_.AdditionalStorageProvidersAvailable }
        $status = if (@($offenders).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($offenders).Count -gt 0) { "Policies with third-party storage enabled: $(($offenders | ForEach-Object { $_.Identity }) -join ', ')" } else { 'No OWA mailbox policy allows third-party storage providers.' }) `
            -RawData $policies
    }
}

function Test-M365_Office_LinkedInConnections {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'OFFICE-04' -Category 'Office Applications' `
        -Title 'LinkedIn Account Connections Enabled' -Severity 'Informational' -Status ManualReview `
        -Summary 'No confirmed stable Graph API for this directory setting — confirm by hand.' `
        -Remediation 'Disable LinkedIn account connections unless there is a specific business need.' `
        -AdminCenterPath 'Entra admin center > Identity > Users > User settings > LinkedIn account connections' `
        -RequiredSource 'Manual'
}

function Test-M365_Office_SwayExternalSharing {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'OFFICE-05' -Category 'Office Applications' `
        -Title 'Sway External Sharing Enabled' -Severity 'Low' -Status ManualReview `
        -Summary 'No documented Graph/PowerShell cmdlet for this Sway tenant setting — confirm by hand.' `
        -Remediation 'Disable "Let people in your organization share their sways with people outside your organization" unless required.' `
        -AdminCenterPath 'Microsoft 365 admin center > Settings > Org settings > Sway' `
        -RequiredSource 'Manual'
}
