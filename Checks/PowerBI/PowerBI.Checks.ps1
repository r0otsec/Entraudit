# Power BI / Fabric tenant settings, live via the Power BI Admin REST API.
# Require Context.PowerBIConnected (Power BI Service Administrator / Fabric Administrator).
# Each check matches on the setting's human-readable 'title' substring rather than an
# exact settingName enum, since those enum strings have shifted across API versions —
# ManualReview is returned if the setting can't be confidently located, so a missed
# match never silently reports a false Pass.

function Invoke-M365PowerBiTitleCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Meta,
        [Parameter(Mandatory)][string]$TitleMatch,
        [Parameter(Mandatory)][scriptblock]$Evaluate # receives $setting, returns @{Status=...; Summary=...}
    )
    $all = Get-M365PowerBiAllSettings
    $setting = $all | Where-Object { $_.title -match $TitleMatch } | Select-Object -First 1
    if (-not $setting) {
        New-M365CheckResult @Meta -Status ManualReview `
            -Summary "Could not confidently locate a tenant setting matching '$TitleMatch' in the Admin API response — confirm by hand in the Fabric admin portal." `
            -RawData $all
        return
    }
    $result = & $Evaluate $setting
    New-M365CheckResult @Meta -Status $result.Status -Summary $result.Summary -RawData $setting
}

function Test-M365_PowerBI_ShareableLinksEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-01'; Category = 'Power BI'
        Title           = 'Shareable Links Enabled Tenant-Wide'; Severity = 'Low'
        Remediation     = 'Restrict shareable links to a subset of the organization (specific security groups), or disable the setting entirely.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Export and sharing settings > Shareable links'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'Shareable link' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = "Enabled tenant-wide (enabled=$($s.enabled), scoped to security groups=$($s.canSpecifySecurityGroups))." } }
            elseif ($s.enabled) { @{ Status = 'ManualReview'; Summary = 'Enabled but appears scoped to specific security groups — confirm the group membership is appropriately narrow.' } }
            else { @{ Status = 'Pass'; Summary = 'Disabled.' } }
        }
    }
}

function Test-M365_PowerBI_ResourceKeyAuthAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-02'; Category = 'Power BI'
        Title           = 'Resource-Key Authentication Not Blocked'; Severity = 'Low'
        Remediation     = 'Enable "Block ResourceKey Authentication" under Fabric tenant settings > Developer settings.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Developer settings > Block ResourceKey Authentication'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'ResourceKey|Resource.?Key' -Evaluate {
            param($s)
            # This is a "Block" toggle, so enabled=true is the SECURE state.
            if ($s.enabled) { @{ Status = 'Pass'; Summary = 'Block ResourceKey Authentication is enabled.' } }
            else { @{ Status = 'Fail'; Summary = 'Block ResourceKey Authentication is disabled — resource-key auth to streaming datasets is allowed.' } }
        }
    }
}

function Test-M365_PowerBI_GuestFabricAccessUnrestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-03'; Category = 'Power BI'
        Title           = 'Guest/Everyone Fabric Access Unrestricted'; Severity = 'Low'
        Remediation     = 'Restrict Fabric access to a subset of the organization or disable guest access entirely, via Fabric tenant settings.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Fabric access settings'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'guest.*(access|use)|everyone.*Fabric' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = 'Enabled for the whole organization including guests, not scoped to specific security groups.' } }
            else { @{ Status = 'Pass'; Summary = "enabled=$($s.enabled), scoped=$($s.canSpecifySecurityGroups)." } }
        }
    }
}

function Test-M365_PowerBI_RPythonVisualsEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-04'; Category = 'Power BI'
        Title           = 'R and Python Visuals Enabled'; Severity = 'Low'
        Remediation     = 'Disable R/Python visuals integration unless there is a specific analytics requirement, reducing the risk of malicious code execution via custom visuals.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > R and Python visuals settings'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'R and Python|Python visuals' -Evaluate {
            param($s)
            if ($s.enabled) { @{ Status = 'Fail'; Summary = 'R and Python visuals are enabled tenant-wide.' } }
            else { @{ Status = 'Pass'; Summary = 'R and Python visuals are disabled.' } }
        }
    }
}

function Test-M365_PowerBI_PublishToWebEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-05'; Category = 'Power BI'
        Title           = 'Publish to Web Enabled'; Severity = 'Low'
        Remediation     = 'Disable "Publish to web" tenant-wide, or scope it to specific security groups, to prevent creation of public unauthenticated report links.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Export and sharing settings > Publish to web'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'Publish to web' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = 'Publish to web is enabled tenant-wide.' } }
            elseif ($s.enabled) { @{ Status = 'ManualReview'; Summary = 'Enabled but appears scoped — confirm group membership is appropriately narrow.' } }
            else { @{ Status = 'Pass'; Summary = 'Disabled.' } }
        }
    }
}

function Test-M365_PowerBI_ExternalDataSharingUnrestricted {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-06'; Category = 'Power BI'
        Title           = 'External Data Sharing Unrestricted'; Severity = 'Informational'
        Remediation     = 'Restrict external data sharing to specific security groups, or disable it, to prevent dataset sharing with guests from other tenants.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Export and sharing settings > External data sharing'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'external data sharing' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = 'Enabled for all users, not scoped to specific security groups.' } }
            else { @{ Status = 'Pass'; Summary = "enabled=$($s.enabled), scoped=$($s.canSpecifySecurityGroups)." } }
        }
    }
}

function Test-M365_PowerBI_ServicePrincipalFabricApiAccess {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-07'; Category = 'Power BI'
        Title           = 'Service Principals Can Access Fabric APIs Tenant-Wide'; Severity = 'Low'
        Remediation     = 'Disable this setting, or scope it to specific security groups, so a compromised service principal cannot call Fabric public APIs tenant-wide.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Developer settings > Service principals can use Fabric APIs'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'service principal.*Fabric API|Fabric API.*service principal' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = 'Enabled for all service principals tenant-wide.' } }
            else { @{ Status = 'Pass'; Summary = "enabled=$($s.enabled), scoped=$($s.canSpecifySecurityGroups)." } }
        }
    }
}

function Test-M365_PowerBI_SensitivityLabelsDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-08'; Category = 'Power BI'
        Title           = 'Sensitivity Labels Disabled for Power BI Content'; Severity = 'Informational'
        Remediation     = 'Enable sensitivity labeling for the organization (or specific security groups) so Power BI/Fabric content gets DLP/information-protection coverage.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Information protection'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'sensitivity label' -Evaluate {
            param($s)
            if (-not $s.enabled) { @{ Status = 'Fail'; Summary = 'Sensitivity labeling is disabled for Power BI content.' } }
            else { @{ Status = 'Pass'; Summary = 'Sensitivity labeling is enabled.' } }
        }
    }
}

function Test-M365_PowerBI_ExternalGuestInvitesAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'POWERBI-09'; Category = 'Power BI'
        Title           = 'Guest Invitations via Item Sharing Allowed for All Users'; Severity = 'Low'
        Remediation     = 'Disable the setting organization-wide, or scope it to specific security groups, so not every user can invite external guests via Fabric/Power BI item sharing.'
        AdminCenterPath = 'Fabric admin portal > Tenant settings > Export and sharing settings > Guest invitations'
        RequiredSource  = 'PowerBI'
    }
    if (-not $Context.PowerBIConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Power BI not connected for this engagement.' }
    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        Invoke-M365PowerBiTitleCheck -Meta $meta -TitleMatch 'invite guest users' -Evaluate {
            param($s)
            if ($s.enabled -and -not $s.canSpecifySecurityGroups) { @{ Status = 'Fail'; Summary = 'Enabled for all users tenant-wide.' } }
            else { @{ Status = 'Pass'; Summary = "enabled=$($s.enabled), scoped=$($s.canSpecifySecurityGroups)." } }
        }
    }
}
