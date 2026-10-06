# Identity / Entra ID — Conditional Access & MFA, and core directory settings.
# All checks here require Context.GraphConnected.

function Test-M365_Identity_ExcessiveGlobalAdmins {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-01'
        Category        = 'Identity / Entra ID'
        Title           = 'Excessive Number of Global Administrators'
        Severity        = 'Medium'
        Remediation     = 'Review every Global Administrator assignment and remove the role from accounts that do not operationally require it. Prefer scoped roles (User Administrator, SharePoint Administrator, etc.) and PIM-eligible rather than permanent assignment. Target 1-5 standing Global Administrators.'
        AdminCenterPath = 'Entra admin center > Identity > Roles and administrators > Global Administrator > Assignments'
        RequiredSource  = 'Graph'
        References      = @('https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference')
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $role = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
        if (-not $role) {
            New-M365CheckResult @meta -Status Error -Summary 'Global Administrator directory role object was not found (unexpected — the role may not be activated in this tenant).'
            return
        }
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
        $names = $members | ForEach-Object { $_.AdditionalProperties['displayName'] ?? $_.Id }
        $count = @($members).Count
        $status = if ($count -gt 5) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "Found $count account(s) holding the Global Administrator role (recommended range: 1-5)." `
            -Evidence ($names -join ', ') -AffectedObjects $names -RawData $members
    }
}

function Test-M365_Identity_LicensedGlobalAdmins {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-02'
        Category        = 'Identity / Entra ID'
        Title           = 'Licensed Global Administrator Accounts'
        Severity        = 'Informational'
        Remediation     = 'Keep privileged access on dedicated, unlicensed (or minimally licensed) admin accounts, ideally activated just-in-time via PIM, separate from the day-to-day licensed user account.'
        AdminCenterPath = 'Entra admin center > Identity > Roles and administrators > Global Administrator > Assignments; cross-reference with Microsoft 365 admin center > Users > Active users > Licenses'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $role = Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'" -ErrorAction Stop
        if (-not $role) { New-M365CheckResult @meta -Status Error -Summary 'Global Administrator directory role object was not found.'; return }
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
        $licensed = foreach ($m in $members) {
            try {
                $lic = Get-MgUserLicenseDetail -UserId $m.Id -ErrorAction Stop
                if (@($lic).Count -gt 0) { $m.AdditionalProperties['userPrincipalName'] ?? $m.Id }
            }
            catch { continue } # member may be a service principal, not a user — not licensable
        }
        $status = if (@($licensed).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "$(@($licensed).Count) of $(@($members).Count) Global Administrator account(s) hold an active M365 license." `
            -Evidence ($licensed -join ', ') -AffectedObjects $licensed -RawData $members
    }
}

function Test-M365_Identity_ConditionalAccessAdminMfa {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-03'
        Category        = 'Identity / Entra ID'
        Title           = 'Conditional Access Coverage for Administrative Roles'
        Severity        = 'High'
        Remediation     = 'Ensure an enabled Conditional Access policy requires MFA (ideally phishing-resistant authentication strength) for all administrative directory roles, with sign-in frequency and compliant/managed device requirements layered on top. Review any excluded users/groups for justification.'
        AdminCenterPath = 'Entra admin center > Protection > Conditional Access > Policies'
        RequiredSource  = 'Graph'
        References      = @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview')
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $enabled = @($policies | Where-Object { $_.State -eq 'enabled' })

        $adminMfaPolicies = $enabled | Where-Object {
            $_.Conditions.Users.IncludeRoles.Count -gt 0 -or $_.Conditions.Users.IncludeUsers -contains 'All'
        } | Where-Object {
            ($_.GrantControls.BuiltInControls -contains 'mfa') -or $_.GrantControls.AuthenticationStrength
        }

        $phishingResistant = $adminMfaPolicies | Where-Object {
            $_.GrantControls.AuthenticationStrength.Id -eq '00000000-0000-0000-0000-000000000004'
        }

        $names = $policies | ForEach-Object { "$($_.DisplayName) [$($_.State)]" }

        if (@($adminMfaPolicies).Count -eq 0) {
            New-M365CheckResult @meta -Status Fail `
                -Summary 'No enabled Conditional Access policy was found that enforces MFA for administrative roles or all users.' `
                -Evidence ($names -join "`n") -RawData $policies
        }
        elseif (@($phishingResistant).Count -eq 0) {
            New-M365CheckResult @meta -Status ManualReview `
                -Summary "Found $(@($adminMfaPolicies).Count) enabled policy/policies enforcing MFA for admins, but none require the built-in 'Phishing-resistant MFA' authentication strength. Review grant controls, excluded accounts, and sign-in frequency/compliant-device settings by hand." `
                -Evidence (($adminMfaPolicies | ForEach-Object { $_.DisplayName }) -join ', ') -RawData $policies
        }
        else {
            New-M365CheckResult @meta -Status Pass `
                -Summary "Found $(@($phishingResistant).Count) enabled policy/policies enforcing phishing-resistant MFA for admin/all-user scope." `
                -Evidence (($phishingResistant | ForEach-Object { $_.DisplayName }) -join ', ') -RawData $policies
        }
    }
}

function Test-M365_Identity_ConditionalAccessDeviceCodeBlocked {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-04'
        Category        = 'Identity / Entra ID'
        Title           = 'Device Code Authentication Flow Not Blocked'
        Severity        = 'Medium'
        Remediation     = 'Create/enable a Conditional Access policy that blocks the device code authentication flow for all users unless there is a specific, justified business need (e.g. a small set of headless devices), to close off device-code phishing.'
        AdminCenterPath = 'Entra admin center > Protection > Conditional Access > Policies (Conditions > Authentication flows > Device code flow)'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $blocking = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.AuthenticationFlows.TransferMethods -match 'deviceCodeFlow' -and
            $_.GrantControls.BuiltInControls -contains 'block'
        })
        $status = if (@($blocking).Count -gt 0) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($status -eq 'Pass') { "Device code flow is blocked by: $(($blocking | ForEach-Object { $_.DisplayName }) -join ', ')" } else { 'No enabled Conditional Access policy blocks the device code authentication flow.' }) `
            -RawData $policies
    }
}

function Test-M365_Identity_NonAdminCreateTenants {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-05'
        Category        = 'Identity / Entra ID'
        Title           = 'Non-Admin Users Allowed to Create Tenants'
        Severity        = 'Low'
        Remediation     = 'Set "Restrict non-admin users from creating tenants" to Yes: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateTenants = $false }'
        AdminCenterPath = 'Entra admin center > Identity > Users > User settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowed = [bool]$pol.DefaultUserRolePermissions.AllowedToCreateTenants
        $status = if ($allowed) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status -Summary "AllowedToCreateTenants = $allowed" -RawData $pol
    }
}

function Test-M365_Identity_NonAdminCreateSecurityGroups {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-06'
        Category        = 'Identity / Entra ID'
        Title           = 'Non-Admin Users Allowed to Create Security Groups'
        Severity        = 'Medium'
        Remediation     = 'Set "Users can create security groups" to No unless self-service group creation is an explicit business requirement: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateSecurityGroups = $false }'
        AdminCenterPath = 'Entra admin center > Identity > Groups > General settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowed = [bool]$pol.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
        $status = if ($allowed) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status -Summary "AllowedToCreateSecurityGroups = $allowed" -RawData $pol
    }
}

function Test-M365_Identity_UsersCanRegisterApps {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-07'
        Category        = 'Identity / Entra ID'
        Title           = 'Users Can Register Applications'
        Severity        = 'Low'
        Remediation     = 'Set "Users can register applications" to No unless there is a specific delegated-development need: Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateApps = $false }'
        AdminCenterPath = 'Entra admin center > Identity > Users > User settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowed = [bool]$pol.DefaultUserRolePermissions.AllowedToCreateApps
        $status = if ($allowed) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status -Summary "AllowedToCreateApps = $allowed" -RawData $pol
    }
}

function Test-M365_Identity_GuestInviteAndAccessRestrictions {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-08'
        Category        = 'Identity / Entra ID'
        Title           = 'Permissive Guest Invite / Guest Access Restrictions'
        Severity        = 'Medium'
        Remediation     = 'Set guest invite restrictions to "Only users assigned to specific admin roles can invite guest users" and guest access restrictions to "Guest user access is restricted to properties and memberships of their own directory objects".'
        AdminCenterPath = 'Entra admin center > Identity > External Identities > External collaboration settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowInvitesFrom = $pol.AllowInvitesFrom
        $guestRoleId = $pol.GuestUserRoleId
        # Well-known built-in directory role template IDs for the guest-user restriction levels.
        $restrictedRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b' # most restrictive
        $permissiveInvite = $allowInvitesFrom -in @('everyone', 'adminsGuestInvitersAndAllMembers')
        $permissiveAccess = $guestRoleId -ne $restrictedRoleId

        $issues = @()
        if ($permissiveInvite) { $issues += "AllowInvitesFrom = $allowInvitesFrom (not restricted to admins)" }
        if ($permissiveAccess) { $issues += "GuestUserRoleId = $guestRoleId (not the most-restrictive built-in role)" }

        $status = if ($issues.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($issues.Count -gt 0) { $issues -join '; ' } else { 'Guest invite and access restrictions are set to their most restrictive values.' }) `
            -RawData $pol
    }
}

function Test-M365_Identity_SecurityDefaultsState {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-09'
        Category        = 'Identity / Entra ID'
        Title           = 'Security Defaults Disabled Without Equivalent Conditional Access Coverage'
        Severity        = 'Informational'
        Remediation     = 'If Security Defaults is disabled, confirm Conditional Access policies provide at least equivalent MFA/legacy-auth-blocking coverage (see ENTRA-003/ENTRA-004). If no Conditional Access licensing is available, re-enable Security Defaults.'
        AdminCenterPath = 'Entra admin center > Identity > Properties > Manage Security defaults'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $status = if ($pol.IsEnabled) { 'Pass' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary "Security Defaults IsEnabled = $($pol.IsEnabled)$(if (-not $pol.IsEnabled) { ' — cross-check against ENTRA-003/ENTRA-004 Conditional Access results for equivalent coverage.' })" `
            -RawData $pol
    }
}

function Test-M365_Identity_ExcessiveGuestUsers {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-10'
        Category        = 'Identity / Entra ID'
        Title           = 'Excessive / Stale Guest User Accounts'
        Severity        = 'Low'
        Remediation     = 'Run a guest-user access review (see ENTRA-013) and remove or disable guest accounts that are no longer needed.'
        AdminCenterPath = 'Entra admin center > Identity > Users > All users (filter: User type = Guest)'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -ErrorAction Stop -Property Id, UserPrincipalName, CreatedDateTime
        $count = @($guests).Count
        New-M365CheckResult @meta -Status ManualReview `
            -Summary "$count guest user account(s) exist in the tenant. Flag for manual review of staleness/business justification — no fixed numeric threshold applies generically." `
            -RawData $guests
    }
}

function Test-M365_Identity_AdminConsentWorkflowDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-11'
        Category        = 'Identity / Entra ID'
        Title           = 'Admin Consent Workflow Disabled'
        Severity        = 'Informational'
        Remediation     = 'Enable the admin consent workflow and assign reviewers, so users without consent rights can formally request review of third-party app permission grants.'
        AdminCenterPath = 'Entra admin center > Identity > Applications > Enterprise applications > Consent and permissions > Admin consent settings'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction Stop
        $status = if ($pol.IsEnabled) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status -Summary "Admin consent workflow IsEnabled = $($pol.IsEnabled)" -RawData $pol
    }
}

function Test-M365_Identity_DynamicGuestGroupMissing {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-12'
        Category        = 'Identity / Entra ID'
        Title           = 'No Dynamic Group Captures Guest Users'
        Severity        = 'Informational'
        Remediation     = 'Create a dynamic security group with membership rule (user.userType -eq "Guest") so Conditional Access and other access controls can be reliably scoped to all guests automatically.'
        AdminCenterPath = 'Entra admin center > Identity > Groups > New group (Membership type: Dynamic User)'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $dynGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -All -ErrorAction Stop -Property Id, DisplayName, MembershipRule
        $guestGroup = $dynGroups | Where-Object { $_.MembershipRule -match 'userType' -and $_.MembershipRule -match 'Guest' }
        $status = if ($guestGroup) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($guestGroup) { "Found guest-scoped dynamic group: $($guestGroup.DisplayName)" } else { 'No dynamic group with a guest-scoped membership rule was found.' }) `
            -RawData $dynGroups
    }
}

function Test-M365_Identity_AccessReviewsForPrivilegedRolesAndGuests {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-13'
        Category        = 'Identity / Entra ID'
        Title           = 'Access Reviews Missing for Privileged Roles and Guest Users'
        Severity        = 'Low'
        Remediation     = 'Create recurring (monthly or more frequent) access reviews for privileged Entra roles (Global/Exchange/SharePoint/Teams/Security Administrator) via PIM, and a recurring review scoped to guest users across Microsoft 365 Groups.'
        AdminCenterPath = 'Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Access reviews; and Identity Governance > Access reviews'
        RequiredSource  = 'Graph'
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $definitions = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction Stop
        $count = @($definitions).Count
        $status = if ($count -eq 0) { 'Fail' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($count -eq 0) { 'No access review definitions exist in the tenant at all.' } else { "$count access review definition(s) exist — manually confirm scope/recurrence covers privileged roles and guest users specifically." }) `
            -Evidence (($definitions | ForEach-Object { $_.DisplayName }) -join ', ') -RawData $definitions
    }
}

function Test-M365_Identity_WeakAuthMethodsEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'ENTRA-14'
        Category        = 'Identity / Entra ID'
        Title           = 'Weak Authentication Methods Enabled (SMS / Voice / Email OTP)'
        Severity        = 'Medium'
        Remediation     = 'Disable SMS, Voice Call, and Email One-Time Passcode as allowed authentication methods; standardize on Microsoft Authenticator and FIDO2/passkeys.'
        AdminCenterPath = 'Entra admin center > Protection > Authentication methods > Policies'
        RequiredSource  = 'Graph'
        References      = @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods')
    }
    if (-not $Context.GraphConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Microsoft Graph not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $pol = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $weak = $pol.AuthenticationMethodConfigurations | Where-Object { $_.Id -in @('Sms', 'Voice', 'Email') -and $_.State -eq 'enabled' }
        $status = if (@($weak).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($weak).Count -gt 0) { "Enabled weak methods: $(($weak | ForEach-Object { $_.Id }) -join ', ')" } else { 'No weak (SMS/Voice/Email OTP) authentication methods are enabled.' }) `
            -RawData $pol
    }
}

function Test-M365_Identity_CustomBannedPasswordList {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'ENTRA-15' -Category 'Identity / Entra ID' `
        -Title 'Custom Banned Password List Not Confirmed' -Severity 'Low' -Status ManualReview `
        -Summary 'No stable Graph API exposes this setting reliably as of this writing — confirm by hand.' `
        -Remediation 'Enable "Enforce custom list" and populate it with brand names, product names, locations, and company-specific terms.' `
        -AdminCenterPath 'Entra admin center > Protection > Authentication methods > Password protection' `
        -RequiredSource 'Manual'
}

function Test-M365_Identity_RestrictEntraAdminCenterAccess {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'ENTRA-16' -Category 'Identity / Entra ID' `
        -Title 'Restrict Access to Microsoft Entra Admin Center Not Confirmed' -Severity 'Medium' -Status ManualReview `
        -Summary 'No confirmed stable Graph property maps to this toggle — confirm by hand rather than risk a wrong automated mapping.' `
        -Remediation 'Set "Restrict access to Microsoft Entra admin center" to Yes so standard users cannot browse directory settings.' `
        -AdminCenterPath 'Entra admin center > Identity > Users > User settings' `
        -RequiredSource 'Manual'
}

function Test-M365_Identity_IdleSessionTimeout {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    New-M365CheckResult -CheckId 'ENTRA-17' -Category 'Identity / Entra ID' `
        -Title 'Idle Session Timeout Not Confirmed' -Severity 'Low' -Status ManualReview `
        -Summary 'No confirmed stable Graph endpoint for the tenant-wide idle session timeout setting — confirm by hand.' `
        -Remediation 'Enable idle session timeout for M365 web apps at 3 hours or less, with a companion Conditional Access session control using "Use app enforced restrictions".' `
        -AdminCenterPath 'Microsoft 365 admin center > Settings > Org settings > Security & privacy > Idle session timeout' `
        -RequiredSource 'Manual'
}
