# Intune device management checks, including Autopilot. Ride the Graph connection.

function Test-M365_Intune_BYODEnrollmentAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'INTUNE-01'
        Category        = 'Intune'
        Title           = 'Personally-Owned (BYOD) Device Enrollment Allowed for All Platforms'
        Severity        = 'Informational'
        Remediation     = 'Block personally-owned device enrollment for platforms that are not explicitly supported for BYOD, via the default device-type restriction enrollment configuration.'
        AdminCenterPath = 'Intune admin center > Devices > Enrollment > Device type restrictions > Default Policy'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $configs = Get-MgDeviceManagementDeviceEnrollmentConfiguration -All -ErrorAction Stop
        $platformRestrictionConfigs = $configs | Where-Object { $_.'@odata.type' -match 'PlatformRestrictionsConfiguration' }
        New-M365CheckResult @meta -Status ManualReview `
            -Summary "$(@($platformRestrictionConfigs).Count) platform restriction configuration(s) found (of $(@($configs).Count) enrollment configurations total). Review the Default policy's per-platform personally-owned device enrollment block settings by hand." `
            -RawData $configs
    }
}

function Test-M365_Intune_DeviceJoinLocalAdminSettings {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'INTUNE-02'
        Category        = 'Intune'
        Title           = 'Device-Join Local Administrator Settings Too Broad'
        Severity        = 'Low'
        Remediation     = 'Set "Global administrator role is added as local administrator on the device during Microsoft Entra join" to No, and restrict registering-user local admin rights to Selected/None rather than All.'
        AdminCenterPath = 'Entra admin center > Devices > Device settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy' -ErrorAction Stop
        New-M365CheckResult @meta -Status ManualReview `
            -Summary 'Device registration policy retrieved — manually confirm local-admin-on-join settings against the Entra admin center UI, as the exact beta property names shift between Graph versions.' `
            -RawData $resp
    }
}

function Test-M365_Intune_CompliancePoliciesMissing {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'INTUNE-03'
        Category        = 'Intune'
        Title           = 'No Device Compliance Policies Configured'
        Severity        = 'Medium'
        Remediation     = 'Create and assign device compliance policies for every managed platform, feeding Conditional Access "compliant device" grant controls.'
        AdminCenterPath = 'Intune admin center > Devices > Compliance policies'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop
        $status = if (@($policies).Count -eq 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "$(@($policies).Count) device compliance policy/policies configured." `
            -Evidence (($policies | ForEach-Object { $_.DisplayName }) -join ', ') -RawData $policies
    }
}

function Test-M365_Intune_AutopilotProfileMissing {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'INTUNE-04'
        Category        = 'Intune'
        Title           = 'No Windows Autopilot Deployment Profile Assigned'
        Severity        = 'Informational'
        Remediation     = 'Create a Windows Autopilot deployment profile and assign it to the relevant device group(s) so new devices self-provision with intended security baseline from first boot.'
        AdminCenterPath = 'Intune admin center > Devices > Enrollment > Windows > Windows Autopilot Deployment Program > Deployment profiles'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles' -ErrorAction Stop
        $profiles = $resp.value
        $status = if (@($profiles).Count -eq 0) { 'Fail' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($profiles).Count -eq 0) { 'No Windows Autopilot deployment profiles exist in this tenant.' } else { "$(@($profiles).Count) Autopilot deployment profile(s) found — confirm assignment to the correct device groups by hand." }) `
            -Evidence (($profiles | ForEach-Object { $_.displayName }) -join ', ') -RawData $profiles
    }
}

function Test-M365_Intune_EnrollmentStatusPageNotBlocking {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'INTUNE-05'
        Category        = 'Intune'
        Title           = 'Enrollment Status Page Not Configured to Block Device Use'
        Severity        = 'Low'
        Remediation     = 'Configure the Enrollment Status Page to block device use until required apps and profiles finish installing, preventing users from reaching the desktop before security baseline is applied.'
        AdminCenterPath = 'Intune admin center > Devices > Enrollment > Windows > Enrollment Status Page'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $configs = Get-MgDeviceManagementDeviceEnrollmentConfiguration -All -ErrorAction Stop
        $espConfigs = $configs | Where-Object { $_.'@odata.type' -match 'windows10EnrollmentCompletionPageConfiguration' }
        $status = if (@($espConfigs).Count -eq 0) { 'Fail' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($espConfigs).Count -eq 0) { 'No Enrollment Status Page configuration was found (default, non-blocking behavior applies).' } else { "$(@($espConfigs).Count) Enrollment Status Page configuration(s) found — confirm 'block device use' / 'only show page to Autopilot-enrolled' settings by hand." }) `
            -RawData $espConfigs
    }
}
