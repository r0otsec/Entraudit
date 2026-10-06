function ConvertTo-EntrAuditPdfData {
    <#
    .SYNOPSIS
        Transforms EntrAudit result objects into the plain hashtable shape
        PdfReport\generate_pdf.py expects (meta + sections[].findings[]).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [object[]]$NotConnected = @(),
        [Parameter(Mandatory)][string]$ClientName,
        [Parameter(Mandatory)][string]$Tenant
    )

    # Same preferred category order used by the Excel/HTML writers, so tab/
    # section order is consistent across every output format.
    $preferredOrder = @(
        'Identity / Entra ID', 'Office Applications', 'Exchange Online',
        'SharePoint Online & OneDrive', 'Teams', 'Defender', 'Intune',
        'Microsoft Forms', 'Power BI', 'Purview / Compliance'
    )
    $allCategories = $Results | Select-Object -ExpandProperty Category -Unique
    $orderedCategories = @($preferredOrder | Where-Object { $_ -in $allCategories })
    $orderedCategories += @($allCategories | Where-Object { $_ -notin $preferredOrder } | Sort-Object)

    $sections = foreach ($category in $orderedCategories) {
        $findings = $Results | Where-Object { $_.Category -eq $category } | ForEach-Object {
            $finding = [ordered]@{
                id             = $_.CheckId
                title          = $_.Title
                severity       = $_.Severity
                rationale      = $_.Summary
                recommendation = $_.Remediation
                config         = $_.AdminCenterPath
            }
            if ($_.Evidence) { $finding.evidence = $_.Evidence }
            if (@($_.References).Count -gt 0) { $finding.references = @($_.References) }
            $finding
        }
        [ordered]@{ title = $category; findings = @($findings) }
    }

    $notConnectedOut = @($NotConnected | ForEach-Object {
            [ordered]@{ category = $_.Category; reason = $_.Reason; check_count = $_.CheckCount }
        })

    [ordered]@{
        meta          = [ordered]@{
            client          = $ClientName
            tenant          = $Tenant
            firm            = 'RootSec'
            report_date     = (Get-Date -Format 'yyyy-MM-dd')
            classification  = 'Confidential'
        }
        sections      = @($sections)
        not_connected = $notConnectedOut
    }
}
