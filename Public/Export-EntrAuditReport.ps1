function Export-EntrAuditReport {
    <#
    .SYNOPSIS
        Writes M365 review results to disk as Excel (default), CSV, JSON, and/or HTML.

    .PARAMETER Results
        Result objects from Invoke-EntrAudit (pipeline-friendly).

    .PARAMETER ClientName
        Engagement/client name, used in the filename and the Excel Summary sheet.

    .PARAMETER OutputPath
        Directory to write into. Created if it doesn't exist. Default: .\Reports

    .PARAMETER OutputFormat
        One or more of: Excel, Csv, Json, Html, Pdf. Default: Excel.
        A full JSON dump (including RawData, for deep-dives) is always written
        alongside whatever formats you choose, since Excel/CSV intentionally omit
        RawData to stay readable. Pdf needs Python 3 (pyyaml/jinja2/markdown/
        pypdf/playwright + `playwright install chromium`) and the
        `powershell-yaml` module - see README.md. Everything else works with
        no extra dependencies.

    .PARAMETER Context
        Service-connection context, for the Summary sheet's "service scope" block.
        Defaults to whatever Connect-EntrAudit last produced in this session.

    .NOTES
        Results whose Status is NotApplicable mean the required service wasn't
        connected for this engagement - every check in this codebase returns that
        status exclusively for that reason, never for "feature confirmed absent."
        Those rows are never written into the findings list in any format; instead
        they're summarized once as a "Not Connected / Not Tested" section/column so
        a reader always knows what was in/out of scope, consistently across every
        output format (Excel/CSV/JSON/PDF/HTML).

    .EXAMPLE
        $results | Export-EntrAuditReport -ClientName 'Contoso Ltd' -OutputFormat Excel,Html
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Results,
        [Parameter(Mandatory)][string]$ClientName,
        [string]$OutputPath = '.\Reports',
        [ValidateSet('Excel', 'Csv', 'Json', 'Html', 'Pdf')]
        [string[]]$OutputFormat = @('Excel'),
        [PSCustomObject]$Context = $script:EntrAuditContext
    )

    begin {
        $all = [System.Collections.Generic.List[object]]::new()
    }
    process {
        foreach ($r in $Results) { $all.Add($r) }
    }
    end {
        if (@($all).Count -eq 0) {
            Write-Warning 'No results were supplied to Export-EntrAuditReport — nothing written.'
            return
        }

        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        $safeClientName = ($ClientName -replace '[\\/:*?"<>|]', '_')
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $basePath = Join-Path $OutputPath "$safeClientName-EntrAudit-$timestamp"

        $tenantLabel = if ($Context -and $Context.TenantName) { "$($Context.TenantName) ($($Context.TenantId))" } else { 'Unknown (Graph not connected)' }

        $serviceScope = if ($Context) {
            [PSCustomObject]@{
                Graph      = [bool]$Context.GraphConnected
                Exchange   = [bool]$Context.ExoConnected
                SharePoint = [bool]$Context.SpoConnected
                Teams      = [bool]$Context.TeamsConnected
                Compliance = [bool]$Context.ComplianceConnected
                PowerBI    = [bool]$Context.PowerBIConnected
            }
        }
        else {
            [PSCustomObject]@{ Note = 'No connection context was supplied — service scope unknown.' }
        }

        # NotApplicable == "the required service wasn't connected for this
        # engagement" (every check in this codebase uses that status exclusively
        # for that reason - confirmed across the whole Checks\ tree). Those rows
        # never appear as findings in any format; instead they're rolled up once
        # per category into $notConnected for a dedicated "not connected / not
        # tested" section/column, consistently across Excel/CSV/JSON/PDF/HTML.
        $findings = @($all | Where-Object { $_.Status -ne 'NotApplicable' })
        $notConnected = @(
            $all | Where-Object { $_.Status -eq 'NotApplicable' } | Group-Object Category | ForEach-Object {
                [PSCustomObject]@{
                    Category   = $_.Name
                    Reason     = $_.Group[0].Summary
                    CheckCount = $_.Count
                }
            }
        )

        # Full JSON (with RawData) always written, as the deep-dive sidecar. Status
        # is dropped here too, same as every other format - Severity is the only
        # rating surfaced anywhere, and NotApplicable rows never appear as findings.
        $jsonFullPath = "$basePath-Full.json"
        [PSCustomObject]@{
            ClientName   = $ClientName
            Tenant       = $tenantLabel
            RunDate      = Get-Date
            ServiceScope = $serviceScope
            NotConnected = $notConnected
            Results      = @($findings | Select-Object -ExcludeProperty Status)
        } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonFullPath -Encoding utf8
        Write-Host "[Export] Full JSON (with raw evidence): $jsonFullPath" -ForegroundColor Gray

        # Status (Fail/Pass/ManualReview/Error) is intentionally not surfaced in
        # any exported format - Severity is the single rating shown everywhere now.
        $flat = $findings | Select-Object CheckId, Category, Title, Severity, Summary, Evidence, AffectedObjects, Remediation, AdminCenterPath, RequiredSource, References, Timestamp

        if ('Csv' -in $OutputFormat) {
            $csvPath = "$basePath.csv"
            $flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
            Write-Host "[Export] CSV: $csvPath" -ForegroundColor Gray
        }

        if ('Json' -in $OutputFormat) {
            $jsonPath = "$basePath.json"
            [PSCustomObject]@{ Findings = $flat; NotConnected = $notConnected } |
                ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding utf8
            Write-Host "[Export] JSON: $jsonPath" -ForegroundColor Gray
        }

        if ('Html' -in $OutputFormat) {
            $htmlPath = "$basePath.html"
            Write-EntrAuditHtmlReport -Results $findings -NotConnected $notConnected -ClientName $ClientName -Tenant $tenantLabel -Path $htmlPath
            Write-Host "[Export] HTML: $htmlPath" -ForegroundColor Gray
        }

        if ('Excel' -in $OutputFormat) {
            $excelPath = "$basePath.xlsx"
            Write-EntrAuditExcelReport -Results $findings -Flat $flat -NotConnected $notConnected -ClientName $ClientName -Tenant $tenantLabel -ServiceScope $serviceScope -Path $excelPath
            Write-Host "[Export] Excel: $excelPath" -ForegroundColor Green
        }

        if ('Pdf' -in $OutputFormat) {
            $pdfPath = "$basePath.pdf"
            Write-EntrAuditPdfReport -Results $findings -NotConnected $notConnected -ClientName $ClientName -Tenant $tenantLabel -Path $pdfPath
            Write-Host "[Export] PDF: $pdfPath" -ForegroundColor Green
        }
    }
}
