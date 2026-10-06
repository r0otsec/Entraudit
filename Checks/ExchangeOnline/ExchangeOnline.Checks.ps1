# Exchange Online mail security / hygiene checks. Require Context.ExoConnected.
# SPF/DMARC are plain DNS lookups (RequiredSource 'Dns') so they always attempt to run
# as long as Get-AcceptedDomain is reachable to enumerate domains.

function Test-M365_Exo_DkimNotEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-01'
        Category        = 'Exchange Online'
        Title           = 'DKIM Not Enabled for One or More Domains'
        Severity        = 'Medium'
        Remediation     = 'Enable DKIM signing for every accepted domain: Exchange admin center > Policies & rules > Threat policies > Email authentication settings > DKIM.'
        AdminCenterPath = 'Exchange admin center > Policies & rules > Threat policies > Email authentication settings > DKIM'
        RequiredSource  = 'Exo'
        References      = @('https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure')
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $configs = Get-DkimSigningConfig -ErrorAction Stop
        $disabled = $configs | Where-Object { -not $_.Enabled }
        $status = if (@($disabled).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($disabled).Count -gt 0) { "DKIM disabled for: $(($disabled | ForEach-Object { $_.Domain }) -join ', ')" } else { 'DKIM is enabled for all configured domains.' }) `
            -RawData $configs
    }
}

function Test-M365_Exo_AutoForwardingNotBlocked {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-02'
        Category        = 'Exchange Online'
        Title           = 'Automatic Mail Forwarding Not Blocked'
        Severity        = 'Informational'
        Remediation     = 'Set the outbound spam filter policy AutoForwardingMode to Off (or restrict via remote domain), reducing the risk of mailbox-rule-based exfiltration after account compromise.'
        AdminCenterPath = 'Exchange admin center > Policies & rules > Threat policies > Anti-spam policies > Outbound'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $offenders = $policies | Where-Object { $_.AutoForwardingMode -ne 'Off' }
        $status = if (@($offenders).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if (@($offenders).Count -gt 0) { "AutoForwardingMode not Off on: $(($offenders | ForEach-Object { "$($_.Identity)=$($_.AutoForwardingMode)" }) -join ', ')" } else { 'AutoForwardingMode is Off on all outbound spam filter policies.' }) `
            -RawData $policies
    }
}

function Test-M365_Exo_ExternalSenderTaggingDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-03'
        Category        = 'Exchange Online'
        Title           = 'External Sender Tagging Disabled'
        Severity        = 'Low'
        Remediation     = 'Run: Set-ExternalInOutlook -Enabled $true, so inbound external email is clearly labeled for end users.'
        AdminCenterPath = 'Exchange admin center, or Get-ExternalInOutlook / Set-ExternalInOutlook'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-ExternalInOutlook -ErrorAction Stop
        $status = if ($cfg.Enabled) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status -Summary "External sender tagging Enabled = $($cfg.Enabled)" -RawData $cfg
    }
}

function Test-M365_Exo_UnifiedAuditLogDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-04'
        Category        = 'Exchange Online'
        Title           = 'Unified Audit Log Ingestion Disabled'
        Severity        = 'Medium'
        Remediation     = 'Run: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true, to restore forensic/incident-response visibility.'
        AdminCenterPath = 'Microsoft Purview compliance portal > Audit, or Get-AdminAuditLogConfig / Set-AdminAuditLogConfig'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-AdminAuditLogConfig -ErrorAction Stop
        $status = if ($cfg.UnifiedAuditLogIngestionEnabled) { 'Pass' } else { 'Fail' }
        New-M365CheckResult @meta -Status $status -Summary "UnifiedAuditLogIngestionEnabled = $($cfg.UnifiedAuditLogIngestionEnabled)" -RawData $cfg
    }
}

function Test-M365_Exo_MalwareSpamAdminNotificationsDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-05'
        Category        = 'Exchange Online'
        Title           = 'Anti-Malware / Anti-Spam Admin Notifications Disabled'
        Severity        = 'Medium'
        Remediation     = 'Configure internal-sender admin notification recipients on the default anti-malware policy, and outbound-spam notification recipients on the outbound spam filter policy, so compromised accounts are flagged promptly.'
        AdminCenterPath = 'Exchange admin center > Policies & rules > Threat policies > Anti-malware / Anti-spam'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $malware = Get-MalwareFilterPolicy -ErrorAction Stop
        $spam = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
        $malwareOffenders = $malware | Where-Object { -not $_.EnableInternalSenderNotifications }
        $spamOffenders = $spam | Where-Object { -not $_.NotifyOutboundSpam }
        $status = if (@($malwareOffenders).Count -gt 0 -or @($spamOffenders).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "Anti-malware policies missing internal notification: $(@($malwareOffenders).Count); outbound-spam policies missing notification: $(@($spamOffenders).Count)" `
            -RawData @{ Malware = $malware; Spam = $spam }
    }
}

function Test-M365_Exo_SharedMailboxSignInEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-06'
        Category        = 'Exchange Online'
        Title           = 'Shared Mailboxes With Sign-In Enabled'
        Severity        = 'Low'
        Remediation     = 'Block sign-in on every shared mailbox account unless there is a specific reason to allow direct interactive login: Get-EXOMailbox -RecipientTypeDetails SharedMailbox | Update-MgUser -AccountEnabled:$false (per account ExternalDirectoryObjectId).'
        AdminCenterPath = 'Microsoft 365 admin center > Teams & groups > Shared mailboxes > [mailbox] > Account > Block sign-in'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $shared = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ErrorAction Stop -Properties ExternalDirectoryObjectId
        if (-not $Context.GraphConnected) {
            New-M365CheckResult @meta -Status ManualReview `
                -Summary "Found $(@($shared).Count) shared mailbox(es); Microsoft Graph is not connected so sign-in (AccountEnabled) status could not be cross-checked. Connect Graph too, or verify manually." `
                -RawData $shared
            return
        }
        $enabled = @()
        foreach ($mbx in $shared) {
            try {
                $u = Get-MgUser -UserId $mbx.ExternalDirectoryObjectId -Property AccountEnabled -ErrorAction Stop
                if ($u.AccountEnabled) { $enabled += $mbx.PrimarySmtpAddress }
            }
            catch { continue }
        }
        $status = if (@($enabled).Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary "$(@($enabled).Count) of $(@($shared).Count) shared mailbox(es) have sign-in enabled." `
            -Evidence ($enabled -join ', ') -AffectedObjects $enabled -RawData $shared
    }
}

function Test-M365_Exo_MailTipsDisabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-07'
        Category        = 'Exchange Online'
        Title           = 'MailTips Disabled for End Users'
        Severity        = 'Low'
        Remediation     = 'Run: Set-OrganizationConfig -MailTipsAllTipsEnabled $true -MailTipsExternalRecipientsTipsEnabled $true -MailTipsGroupMetricsEnabled $true'
        AdminCenterPath = 'Exchange admin center > Settings > Mail flow, or Get-OrganizationConfig / Set-OrganizationConfig'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $cfg = Get-OrganizationConfig -ErrorAction Stop
        $disabled = @()
        if (-not $cfg.MailTipsAllTipsEnabled) { $disabled += 'MailTipsAllTipsEnabled' }
        if (-not $cfg.MailTipsExternalRecipientsTipsEnabled) { $disabled += 'MailTipsExternalRecipientsTipsEnabled' }
        if (-not $cfg.MailTipsGroupMetricsEnabled) { $disabled += 'MailTipsGroupMetricsEnabled' }
        $status = if ($disabled.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($disabled.Count -gt 0) { "Disabled: $($disabled -join ', ')" } else { 'All relevant MailTips settings are enabled.' }) `
            -RawData $cfg
    }
}

function Test-M365_Exo_CalendarExternalSharingEnabled {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-08'
        Category        = 'Exchange Online'
        Title           = 'External Calendar Sharing Enabled'
        Severity        = 'Low'
        Remediation     = 'Disable the default sharing policy (or restrict its domains) so calendars cannot be shared with anyone outside the organization by default.'
        AdminCenterPath = 'Microsoft 365 admin center > Settings > Org settings > Calendar, or Get-SharingPolicy'
        RequiredSource  = 'Exo'
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement.' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $policies = Get-SharingPolicy -ErrorAction Stop
        $enabled = $policies | Where-Object { $_.Enabled -and $_.Domains -match 'Anonymous|\*' }
        $status = if (@($enabled).Count -gt 0) { 'Fail' } else { 'ManualReview' }
        New-M365CheckResult @meta -Status $status `
            -Summary "Sharing policies: $(($policies | ForEach-Object { "$($_.Name)[Enabled=$($_.Enabled)]" }) -join ', '). Review Domains on each for external exposure." `
            -RawData $policies
    }
}

function Test-M365_Exo_SpfMissing {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-09'
        Category        = 'Exchange Online'
        Title           = 'SPF Record Missing for an Accepted Domain'
        Severity        = 'Low'
        Remediation     = 'Publish an SPF TXT record for every accepted domain used to send mail, e.g. v=spf1 include:spf.protection.outlook.com -all (adjust include list for any other senders).'
        AdminCenterPath = 'DNS provider for each accepted domain'
        RequiredSource  = 'Dns'
        References      = @('https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure')
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement (needed to enumerate accepted domains).' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $domains = Get-AcceptedDomain -ErrorAction Stop
        $missing = @()
        foreach ($d in $domains) {
            try {
                $txt = Resolve-DnsName -Name $d.DomainName -Type TXT -ErrorAction Stop
                $spf = $txt | Where-Object { $_.Strings -match 'v=spf1' }
                if (-not $spf) { $missing += $d.DomainName }
            }
            catch { $missing += "$($d.DomainName) (DNS lookup failed)" }
        }
        $status = if ($missing.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($missing.Count -gt 0) { "Domains missing a valid SPF record: $($missing -join ', ')" } else { 'All accepted domains have an SPF TXT record.' }) `
            -AffectedObjects $missing -RawData $domains
    }
}

function Test-M365_Exo_DmarcMissingOrNone {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Context)
    $meta = @{
        CheckId         = 'EXO-10'
        Category        = 'Exchange Online'
        Title           = 'DMARC Record Missing or Policy Set to None'
        Severity        = 'Low'
        Remediation     = 'Publish a DMARC TXT record at _dmarc.<domain> with p=quarantine or p=reject once SPF/DKIM alignment is confirmed, rather than leaving p=none indefinitely.'
        AdminCenterPath = 'DNS provider for each accepted domain'
        RequiredSource  = 'Dns'
        References      = @('https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure')
    }
    if (-not $Context.ExoConnected) { return New-M365CheckResult @meta -Status NotApplicable -Summary 'Exchange Online not connected for this engagement (needed to enumerate accepted domains).' }

    Invoke-M365CheckSafely -Meta $meta -ScriptBlock {
        $domains = Get-AcceptedDomain -ErrorAction Stop
        $issues = @()
        foreach ($d in $domains) {
            try {
                $txt = Resolve-DnsName -Name "_dmarc.$($d.DomainName)" -Type TXT -ErrorAction Stop
                $record = ($txt | Where-Object { $_.Strings -match 'v=DMARC1' }).Strings -join ''
                if (-not $record) { $issues += "$($d.DomainName): no DMARC record" }
                elseif ($record -match 'p=none') { $issues += "$($d.DomainName): p=none" }
            }
            catch { $issues += "$($d.DomainName): DNS lookup failed" }
        }
        $status = if ($issues.Count -gt 0) { 'Fail' } else { 'Pass' }
        New-M365CheckResult @meta -Status $status `
            -Summary $(if ($issues.Count -gt 0) { $issues -join '; ' } else { 'All accepted domains publish a DMARC record enforcing quarantine/reject.' }) `
            -RawData $domains
    }
}
