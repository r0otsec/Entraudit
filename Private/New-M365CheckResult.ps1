function New-M365CheckResult {
    <#
    .SYNOPSIS
        Builds a standardized result object for a single M365 review check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'ManualReview', 'NotApplicable', 'Error')]
        [string]$Status,
        [Parameter(Mandatory)][string]$Summary,
        [string]$Evidence = '',
        [string[]]$AffectedObjects = @(),
        [Parameter(Mandatory)][string]$Remediation,
        [string]$AdminCenterPath = '',
        [Parameter(Mandatory)]
        [ValidateSet('Graph', 'Exo', 'Spo', 'Teams', 'Compliance', 'PowerBI', 'Dns', 'Manual')]
        [string]$RequiredSource,
        [object]$RawData = $null,
        # Opportunistic, not required: a Microsoft Learn (or similar) doc link
        # backing this check, used by the PDF/HTML report's Reference field
        # when present. Most checks won't set this yet - that's fine, the
        # report templates simply omit the block when empty.
        [string[]]$References = @()
    )

    [PSCustomObject]@{
        PSTypeName      = 'EntrAudit.CheckResult'
        CheckId         = $CheckId
        Category        = $Category
        Title           = $Title
        Severity        = $Severity
        Status          = $Status
        Summary         = $Summary
        Evidence        = $Evidence
        AffectedObjects = ($AffectedObjects -join '; ')
        Remediation     = $Remediation
        AdminCenterPath = $AdminCenterPath
        RequiredSource  = $RequiredSource
        RawData         = $RawData
        References      = $References
        Timestamp       = (Get-Date)
    }
}
