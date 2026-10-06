function Write-EntrAuditExcelReport {
    <#
    .SYNOPSIS
        Builds the Excel workbook: a branded Cover sheet, a Summary sheet (run info,
        service scope, counts by status/severity/category), and one worksheet per
        check category (Entra ID, Exchange Online, Teams, etc.) — each with its own
        severity/status conditional formatting, autofilter, and frozen header.
        Requires the ImportExcel module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][object[]]$Flat,
        [Parameter(Mandatory)][object[]]$NotConnected,
        [Parameter(Mandatory)][string]$ClientName,
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][object]$ServiceScope,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        throw "The ImportExcel module is not installed. Run .\Install-Prerequisites.ps1 -Services Excel first, or choose a different -OutputFormat."
    }
    Import-Module ImportExcel -ErrorAction Stop

    if (Test-Path $Path) { Remove-Item $Path -Force }
    $excel = Open-ExcelPackage -Path $Path -Create -ErrorAction Stop

    # ---------------------------------------------------------------- Cover sheet
    $coverSheet = $excel.Workbook.Worksheets.Add('Cover')
    for ($c = 1; $c -le 8; $c++) { $coverSheet.Column($c).Width = 14 }

    $logoPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Assets\rootsec-logo.png'
    if (Test-Path $logoPath) {
        try {
            $pic = $coverSheet.Drawings.AddPicture('RootSecLogo', [System.IO.FileInfo]::new($logoPath))
            $pic.SetSize(420, 104)
            $pic.SetPosition(1, 10, 0, 10)
        }
        catch {
            Write-Warning "Could not embed the RootSec logo into the cover sheet: $($_.Exception.Message)"
        }
    }

    $coverSheet.Cells['A9:H9'].Merge = $true
    $coverSheet.Cells['A9'].Value = 'Microsoft 365 / Entra ID Security Review'
    $coverSheet.Cells['A9'].Style.Font.Size = 20
    $coverSheet.Cells['A9'].Style.Font.Bold = $true

    $coverSheet.Cells['A11:H11'].Merge = $true
    $coverSheet.Cells['A11'].Value = 'Prepared by RootSec'
    $coverSheet.Cells['A11'].Style.Font.Size = 12
    $coverSheet.Cells['A11'].Style.Font.Color.SetColor([System.Drawing.Color]::DimGray)

    # NOTE: deliberately PSCustomObjects, not nested @() arrays - PowerShell
    # flattens bare @(@(...); @(...)) into one long flat array (confirmed by
    # testing), which silently destroyed the label/value pairing here before.
    $coverFields = @(
        [PSCustomObject]@{ Label = 'Client'; Value = $ClientName }
        [PSCustomObject]@{ Label = 'Tenant'; Value = $Tenant }
        [PSCustomObject]@{ Label = 'Report generated'; Value = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
        [PSCustomObject]@{ Label = 'Total findings'; Value = (@($Results).Count) }
        [PSCustomObject]@{ Label = 'Critical / High severity findings'; Value = (@($Results | Where-Object { $_.Severity -in @('Critical', 'High') }).Count) }
        [PSCustomObject]@{ Label = 'Categories not connected / not tested'; Value = (@($NotConnected).Count) }
    )
    $row = 13
    foreach ($field in $coverFields) {
        $coverSheet.Cells["A$row"].Value = $field.Label
        $coverSheet.Cells["A$row"].Style.Font.Bold = $true
        $coverSheet.Cells["C$row"].Value = $field.Value
        $row++
    }

    $bannerRow = $row + 1
    $coverSheet.Cells["A${bannerRow}:H${bannerRow}"].Merge = $true
    $coverSheet.Cells["A$bannerRow"].Value = 'CONFIDENTIAL — for authorized recipients only. Contains sensitive security findings; do not distribute outside agreed parties.'
    $coverSheet.Cells["A$bannerRow"].Style.Font.Bold = $true
    $coverSheet.Cells["A$bannerRow"].Style.Font.Color.SetColor([System.Drawing.Color]::White)
    $coverSheet.Cells["A$bannerRow"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $coverSheet.Cells["A$bannerRow"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Black)
    $coverSheet.Cells["A$bannerRow"].Style.WrapText = $true
    $coverSheet.Row($bannerRow).Height = 30

    # --------------------------------------------------------------- Summary sheet
    # Built entirely with raw EPPlus (not Export-Excel's -Title table stacking) so
    # it reads as a dashboard — banner, KPI tiles, two colored charts, banded
    # reference tables — rather than a stack of plain grey tables.
    # Severity is the one rating surfaced everywhere now - Status (Fail/Pass/
    # ManualReview/Error) stays an internal-only field (still drives CLI
    # filtering/sorting) but is never rendered as its own column/chart/KPI.
    $severityOrder = 'Critical', 'High', 'Medium', 'Low', 'Informational'
    $severityColor = @{ Critical = 'E63946'; High = 'F4802B'; Medium = 'F5C518'; Low = '2196F3'; Informational = '8B949E' }
    $severityCounts = @($severityOrder | ForEach-Object {
            # Capture into a named variable before the nested Where-Object - its
            # own $_ (each result object) would otherwise shadow this severity name.
            $sev = $_
            [PSCustomObject]@{ Severity = $sev; Count = @($Results | Where-Object { $_.Severity -eq $sev }).Count }
        } | Where-Object { $_.Count -gt 0 })
    if ($severityCounts.Count -eq 0) { $severityCounts = @([PSCustomObject]@{ Severity = '(none)'; Count = 0 }) }
    $categoryCounts = @($Results | Group-Object Category | ForEach-Object {
            [PSCustomObject]@{ Category = $_.Name; Total = $_.Count }
        } | Sort-Object Total -Descending)
    $totalChecks = @($Results).Count

    $summarySheet = $excel.Workbook.Worksheets.Add('Summary')
    $summarySheet.Column(1).Width = 20
    2..3 | ForEach-Object { $summarySheet.Column($_).Width = 14 }
    4..14 | ForEach-Object { $summarySheet.Column($_).Width = 10 }

    function Set-M365Heading {
        param($Ws, [string]$Cell, [string]$Text)
        $Ws.Cells[$Cell].Value = $Text
        $Ws.Cells[$Cell].Style.Font.Size = 13
        $Ws.Cells[$Cell].Style.Font.Bold = $true
        $Ws.Cells[$Cell].Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb(0x33, 0x33, 0x33))
        $Ws.Cells[$Cell].Style.Border.Bottom.Style = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
        $Ws.Cells[$Cell].Style.Border.Bottom.Color.SetColor([System.Drawing.Color]::FromArgb(0xDD, 0xDD, 0xDD))
    }

    function New-M365KpiTile {
        param($Ws, [int]$StartCol, [int]$StartRow, [string]$HexColor, $Value, [string]$Label)
        # Plain integer-indexed range (row1,col1,row2,col2) - simpler and more
        # reliable than building address strings via ExcelCellAddress, which isn't
        # reliably resolvable as a bare type reference in this environment.
        #
        # Inline arithmetic inside the indexer's argument list (e.g.
        # Cells[$StartRow, $StartCol, $StartRow + 1, $StartCol + 1]) breaks
        # PowerShell's overload resolution here - it silently returns a plain
        # System.Object[] instead of an ExcelRange. Confirmed by isolated testing.
        # Precomputing every row/col into its own named int variable first avoids it.
        $endRow = $StartRow + 1
        $endCol = $StartCol + 1
        $lblRow = $StartRow + 2
        $numRange = $Ws.Cells[$StartRow, $StartCol, $endRow, $endCol]
        $lblRange = $Ws.Cells[$lblRow, $StartCol, $lblRow, $endCol]

        $numRange.Merge = $true
        $Ws.Cells[$StartRow, $StartCol].Value = $Value
        $Ws.Cells[$StartRow, $StartCol].Style.Font.Size = 24
        $Ws.Cells[$StartRow, $StartCol].Style.Font.Bold = $true
        $Ws.Cells[$StartRow, $StartCol].Style.Font.Color.SetColor([System.Drawing.Color]::White)
        $numRange.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
        $numRange.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $numRange.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml("#$HexColor"))

        $lblRange.Merge = $true
        $Ws.Cells[$lblRow, $StartCol].Value = $Label
        $lblRange.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
        $lblRange.Style.Font.Size = 10
        $lblRange.Style.Font.Bold = $true
        $lblRange.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $lblRange.Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml("#$HexColor"))
        $lblRange.Style.Font.Color.SetColor([System.Drawing.Color]::White)
        $Ws.Row($StartRow).Height = 28
        $Ws.Row($StartRow + 1).Height = 10
    }

    function Write-M365BandedTable {
        param($Ws, [int]$StartRow, [int]$StartCol, [string[]]$Headers, [object[]]$Rows, [string[]]$PropertyNames)
        for ($h = 0; $h -lt $Headers.Count; $h++) {
            $colNum = $StartCol + $h
            $cell = $Ws.Cells[$StartRow, $colNum]
            $cell.Value = $Headers[$h]
            $cell.Style.Font.Bold = $true
            $cell.Style.Font.Color.SetColor([System.Drawing.Color]::White)
            $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0x33, 0x33, 0x33))
        }
        for ($r = 0; $r -lt $Rows.Count; $r++) {
            $rowNum = $StartRow + 1 + $r
            for ($h = 0; $h -lt $PropertyNames.Count; $h++) {
                $colNum = $StartCol + $h
                $cell = $Ws.Cells[$rowNum, $colNum]
                $cell.Value = $Rows[$r].($PropertyNames[$h])
                if ($r % 2 -eq 1) {
                    $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(0xF5, 0xF5, 0xF5))
                }
                $cell.Style.Border.Bottom.Style = [OfficeOpenXml.Style.ExcelBorderStyle]::Hair
                $cell.Style.Border.Bottom.Color.SetColor([System.Drawing.Color]::FromArgb(0xE0, 0xE0, 0xE0))
            }
        }
        return $StartRow + $Rows.Count
    }

    # Title banner
    $summarySheet.Cells['A1:N2'].Merge = $true
    $summarySheet.Cells['A1'].Value = "ENGAGEMENT SUMMARY — $ClientName"
    $summarySheet.Cells['A1'].Style.Font.Size = 18
    $summarySheet.Cells['A1'].Style.Font.Bold = $true
    $summarySheet.Cells['A1'].Style.Font.Color.SetColor([System.Drawing.Color]::White)
    $summarySheet.Cells['A1'].Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $summarySheet.Cells['A1:N2'].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $summarySheet.Cells['A1:N2'].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Black)
    $summarySheet.Row(1).Height = 22
    $summarySheet.Row(2).Height = 14

    $summarySheet.Cells['A4:N4'].Merge = $true
    $summarySheet.Cells['A4'].Value = "Tenant: $Tenant   |   Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $summarySheet.Cells['A4'].Style.Font.Italic = $true
    $summarySheet.Cells['A4'].Style.Font.Color.SetColor([System.Drawing.Color]::DimGray)

    # KPI tiles
    New-M365KpiTile -Ws $summarySheet -StartCol 1 -StartRow 6 -HexColor '1A1A1A' -Value $totalChecks -Label 'TOTAL FINDINGS'
    New-M365KpiTile -Ws $summarySheet -StartCol 3 -StartRow 6 -HexColor $severityColor['Critical'] -Value ($severityCounts | Where-Object Severity -eq 'Critical' | Select-Object -ExpandProperty Count) -Label 'CRITICAL'
    New-M365KpiTile -Ws $summarySheet -StartCol 5 -StartRow 6 -HexColor $severityColor['High'] -Value ($severityCounts | Where-Object Severity -eq 'High' | Select-Object -ExpandProperty Count) -Label 'HIGH'
    New-M365KpiTile -Ws $summarySheet -StartCol 7 -StartRow 6 -HexColor $severityColor['Medium'] -Value ($severityCounts | Where-Object Severity -eq 'Medium' | Select-Object -ExpandProperty Count) -Label 'MEDIUM'
    New-M365KpiTile -Ws $summarySheet -StartCol 9 -StartRow 6 -HexColor $severityColor['Low'] -Value ($severityCounts | Where-Object Severity -eq 'Low' | Select-Object -ExpandProperty Count) -Label 'LOW'

    # Results by Severity: mini table + colored column chart (one series per
    # severity, each with its own Fill.Color - EPPlus doesn't expose per-datapoint
    # coloring on a single series in this version, confirmed by testing, so
    # distinct colors require distinct single-point series, not one multi-point one).
    Set-M365Heading -Ws $summarySheet -Cell 'A11' -Text 'Results by Severity'
    Write-M365BandedTable -Ws $summarySheet -StartRow 12 -StartCol 1 -Headers @('Severity', 'Count') -Rows $severityCounts -PropertyNames @('Severity', 'Count') | Out-Null

    $severityChart = $summarySheet.Drawings.AddChart('SeverityChart', [OfficeOpenXml.Drawing.Chart.eChartType]::ColumnClustered)
    for ($i = 0; $i -lt $severityCounts.Count; $i++) {
        $r = 12 + 1 + $i
        $s = $severityChart.Series.Add("B$r", "A$r")
        $s.Header = $severityCounts[$i].Severity
        $hex = $severityColor[$severityCounts[$i].Severity]; if (-not $hex) { $hex = '999999' }
        $s.Fill.Color = [System.Drawing.ColorTranslator]::FromHtml("#$hex")
    }
    $severityChart.Title.Text = 'Findings by Severity'
    $severityChart.SetPosition(10, 0, 3, 10)
    $severityChart.SetSize(460, 260)

    # Findings by Category: mini table + single-color horizontal bar chart, sorted
    # by total count descending (already sorted when $categoryCounts was built).
    Set-M365Heading -Ws $summarySheet -Cell 'A19' -Text 'Findings by Category'
    $catTableEnd = Write-M365BandedTable -Ws $summarySheet -StartRow 20 -StartCol 1 -Headers @('Category', 'Total') -Rows $categoryCounts -PropertyNames @('Category', 'Total')

    $catChart = $summarySheet.Drawings.AddChart('CategoryChart', [OfficeOpenXml.Drawing.Chart.eChartType]::BarClustered)
    $catFirstRow = 21
    $catLastRow = 20 + $categoryCounts.Count
    $catSeries = $catChart.Series.Add("B${catFirstRow}:B${catLastRow}", "A${catFirstRow}:A${catLastRow}")
    $catSeries.Header = 'Finding count'
    $catSeries.Fill.Color = [System.Drawing.ColorTranslator]::FromHtml("#$($severityColor['High'])")
    $catChart.Title.Text = 'Finding Count by Category'
    $catChart.Legend.Remove()
    $catChart.SetPosition(27, 0, 3, 10)
    $catChart.SetSize(460, 320)

    # Not Connected / Not Tested: which categories had no connected service for
    # this engagement, and so are entirely absent from the findings below.
    # Fixed, generous base row (same anchor the original layout used for Service
    # Scope) so this clears both floating charts above regardless of their exact
    # pixel height; pushed further down only if Not Connected needs more room.
    $notConnRow = $catTableEnd + 3
    if (@($NotConnected).Count -gt 0) {
        Set-M365Heading -Ws $summarySheet -Cell "A$notConnRow" -Text 'Not Connected / Not Tested'
        $notConnTableEnd = Write-M365BandedTable -Ws $summarySheet -StartRow ($notConnRow + 1) -StartCol 1 -Headers @('Category', 'Reason', 'Checks skipped') -Rows $NotConnected -PropertyNames @('Category', 'Reason', 'CheckCount')
        # "Reason" (column B) carries a full sentence - wrap it rather than let it
        # clip against column C, which always has a number so text can't overflow.
        $notConnReasonRange = $summarySheet.Cells[($notConnRow + 1), 2, $notConnTableEnd, 2]
        $notConnReasonRange.Style.WrapText = $true
        $summarySheet.Column(2).Width = 48
        $scopeRow = [Math]::Max(47, $notConnTableEnd + 3)
    }
    else {
        $summarySheet.Cells["A$notConnRow"].Value = 'Every in-scope service was connected for this engagement - nothing was skipped.'
        $summarySheet.Cells["A$notConnRow"].Style.Font.Italic = $true
        $summarySheet.Cells["A$notConnRow"].Style.Font.Color.SetColor([System.Drawing.Color]::DimGray)
        $scopeRow = 47
    }

    # Service scope: small colored badges, one per service, well clear of both charts.
    Set-M365Heading -Ws $summarySheet -Cell "A$scopeRow" -Text 'Service Scope (connected for this run)'
    $scopeCol = 1
    $badgeRow = $scopeRow + 1
    foreach ($prop in $ServiceScope.PSObject.Properties) {
        $cell = $summarySheet.Cells[$badgeRow, $scopeCol]
        $cell.Value = $(if ($prop.Value -eq $true) { "$($prop.Name): Connected" } elseif ($prop.Value -eq $false) { "$($prop.Name): Not used" } else { "$($prop.Name): $($prop.Value)" })
        $cell.Style.Font.Color.SetColor([System.Drawing.Color]::White)
        $cell.Style.Font.Bold = $true
        $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $bg = if ($prop.Value -eq $true) { [System.Drawing.Color]::FromArgb(0x27, 0xAE, 0x60) } elseif ($prop.Value -eq $false) { [System.Drawing.Color]::FromArgb(0x7F, 0x8C, 0x8D) } else { [System.Drawing.Color]::FromArgb(0x33, 0x33, 0x33) }
        $cell.Style.Fill.BackgroundColor.SetColor($bg)
        $scopeCol += 2
    }

    # ------------------------------------------------------- One sheet per category
    # Preferred tab order; anything not in this list (future categories) is appended
    # afterward, alphabetically, so new checks never silently lose their own tab.
    $preferredOrder = @(
        'Identity / Entra ID', 'Office Applications', 'Exchange Online',
        'SharePoint Online & OneDrive', 'Teams', 'Defender', 'Intune',
        'Microsoft Forms', 'Power BI', 'Purview / Compliance'
    )
    $allCategories = $Results | Select-Object -ExpandProperty Category -Unique
    $orderedCategories = @($preferredOrder | Where-Object { $_ -in $allCategories })
    $orderedCategories += @($allCategories | Where-Object { $_ -notin $preferredOrder } | Sort-Object)

    # Columns within each category sheet (Category itself is dropped — redundant
    # once the sheet is scoped to one category). Status is dropped too - Severity
    # (column C) is the only rating shown, consistent with every other format.
    $perCategoryColumns = 'CheckId', 'Title', 'Severity', 'Summary', 'Evidence', 'AffectedObjects', 'Remediation', 'AdminCenterPath', 'RequiredSource', 'Timestamp'

    # Building each category sheet (table + autofilter + conditional formatting)
    # directly via Export-Excel -ExcelPackage, back to back in the same open
    # package, hits a real ImportExcel/EPPlus bug in this environment: the second
    # and every subsequent sheet that uses -AutoFilter/-TableStyle in one package
    # fails to save ("Could not get worksheet <name>"), and ConditionalText rule
    # objects additionally can't be reused across sheets. Confirmed by isolated
    # testing before writing this - not a guess.
    #
    # Workaround: build each category sheet as its own single-sheet workbook (that
    # path is always reliable), copy the finished worksheet into the master
    # package (EPPlus's native cross-package worksheet copy), then apply
    # conditional formatting natively on the now-merged worksheet - conditional
    # formatting rules don't survive the cross-package copy itself (they reference
    # style/DXF indices scoped to the source package), so they have to be (re)built
    # directly against the destination package after merging, not before.
    function Add-M365SeverityFormatting {
        param([Parameter(Mandatory)]$Worksheet)
        $rules = @(
            @{ Col = 'C'; Text = 'Critical'; Bg = 'FF0000'; Fg = 'FFFFFF' }
            @{ Col = 'C'; Text = 'High'; Bg = 'FFC7CE'; Fg = '9C0006' }
            @{ Col = 'C'; Text = 'Medium'; Bg = 'FFEB9C'; Fg = '9C6500' }
            @{ Col = 'C'; Text = 'Low'; Bg = 'DDEBF7'; Fg = '1F4E78' }
            @{ Col = 'C'; Text = 'Informational'; Bg = 'F2F2F2'; Fg = '808080' }
        )
        foreach ($r in $rules) {
            $rule = $Worksheet.ConditionalFormatting.AddContainsText([OfficeOpenXml.ExcelAddress]::new("$($r.Col):$($r.Col)"))
            $rule.Text = $r.Text
            $rule.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $rule.Style.Fill.BackgroundColor.Color = [System.Drawing.ColorTranslator]::FromHtml("#$($r.Bg)")
            $rule.Style.Font.Color.Color = [System.Drawing.ColorTranslator]::FromHtml("#$($r.Fg)")
        }
    }

    $usedSheetNames = [System.Collections.Generic.HashSet[string]]::new()
    $tempFiles = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($category in $orderedCategories) {
            $sheetName = Get-M365SafeSheetName -Name $category
            $suffix = 2
            while (-not $usedSheetNames.Add($sheetName)) {
                $sheetName = (Get-M365SafeSheetName -Name $category).Substring(0, [Math]::Min(28, $category.Length)) + " $suffix"
                $suffix++
            }

            $categoryRows = $Results | Where-Object { $_.Category -eq $category } | Select-Object $perCategoryColumns

            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "m365review-$([guid]::NewGuid()).xlsx"
            $tempFiles.Add($tempPath)
            $categoryRows | Export-Excel -Path $tempPath -WorksheetName $sheetName -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -TableStyle Medium2 | Out-Null

            $tempPkg = Open-ExcelPackage -Path $tempPath
            $mergedWs = $excel.Workbook.Worksheets.Add($sheetName, $tempPkg.Workbook.Worksheets[$sheetName])
            Close-ExcelPackage $tempPkg -NoSave

            Add-M365SeverityFormatting -Worksheet $mergedWs
        }

        Close-ExcelPackage $excel
    }
    finally {
        foreach ($f in $tempFiles) { Remove-Item -Path $f -Force -ErrorAction SilentlyContinue }
    }
}
