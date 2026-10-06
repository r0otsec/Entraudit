function Write-EntrAuditHtmlReport {
    <#
    .SYNOPSIS
        Writes a single self-contained HTML file, styled to match the PDF report's
        Swiss-InfoSec-style layout: a plain logo-top-left cover with a two-tone
        title, a clickable contents page, plain numbered section headings, and
        one rounded grid-table card per finding (Rating/Summary/Remediation/
        Path/Reference rows separated by thin vertical/horizontal rules).
        NotConnected rows (services not connected for this engagement) are
        summarized in their own section, never mixed into the findings. No
        external assets required beyond the RootSec logo (embedded as base64) -
        falls back to system fonts offline - so it's safe to email/attach and
        needs no Python/dependency install.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [object[]]$NotConnected = @(),
        [Parameter(Mandatory)][string]$ClientName,
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$Path
    )

    function Esc([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }
    function SeverityKey([string]$s) { $s.ToLower() }
    function Slugify([string]$s) { ([regex]::Replace($s.ToLower(), '[^a-z0-9]+', '-')).Trim('-') }

    # Real per-service brand SVGs (Assets\ServiceIcons), one per CheckId prefix,
    # so a reader can tell at a glance which M365 surface a finding belongs to —
    # mirrors the Swiss InfoSec reference's per-finding service icon in the
    # header row of the card. Loaded from disk once and ID-namespaced the same
    # way the Python PDF engine does (PdfReport/generate_pdf.py) so HTML and PDF
    # use the identical icons.
    $iconsDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'Assets\ServiceIcons'
    $serviceIconFiles = @{
        ENTRA      = 'entra-id.svg'
        OFFICE     = 'office-365.svg'
        EXO        = 'microsoft-exchange.svg'
        SHAREPOINT = 'microsoft-sharepoint.svg'
        TEAMS      = 'microsoft-teams.svg'
        DEFENDER   = 'microsoft-defender.svg'
        INTUNE     = 'microsoft-intune.svg'
        FORMS      = 'microsoft-forms.svg'
        POWERBI    = 'powerbi.svg'
        COMPLIANCE = 'compliance-center.svg'
    }
    $defaultIcon = '<svg viewBox="0 0 28 28" xmlns="http://www.w3.org/2000/svg"><rect width="28" height="28" rx="6" fill="#6b7280"/><circle cx="14" cy="14" r="5.5" fill="none" stroke="#fff" stroke-width="1.8"/></svg>'
    $iconCache = @{}

    function NamespaceSvgIds([string]$svg, [string]$prefix) {
        $ids = [regex]::Matches($svg, 'id="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        $ids = $ids | Sort-Object { $_.Length } -Descending
        foreach ($old in $ids) {
            $esc = [regex]::Escape($old)
            $new = "$prefix-$old"
            $svg = [regex]::Replace($svg, "id=`"$esc`"", "id=`"$new`"")
            $svg = [regex]::Replace($svg, "url\(#$esc\)", "url(#$new)")
            $svg = [regex]::Replace($svg, "(xlink:href|href)=`"#$esc`"", "`$1=`"#$new`"")
        }
        return $svg
    }

    function EnsureViewBox([string]$svg) {
        # Some vendored icons (e.g. powerbi.svg) carry only width/height, no
        # viewBox. Stripping width/height from those would leave the SVG with
        # no coordinate system to scale by, collapsing it to a blank/clipped
        # corner inside our fixed-size icon box — synthesize one from
        # width/height first, before width/height get stripped below.
        $tagMatch = [regex]::Match($svg, '<svg\b([^>]*)>')
        if (-not $tagMatch.Success -or $tagMatch.Groups[1].Value -match 'viewBox') { return $svg }
        $w = [regex]::Match($tagMatch.Groups[1].Value, 'width="([\d.]+)"')
        $h = [regex]::Match($tagMatch.Groups[1].Value, 'height="([\d.]+)"')
        if ($w.Success -and $h.Success) {
            $viewBoxAttr = "viewBox=`"0 0 $($w.Groups[1].Value) $($h.Groups[1].Value)`""
            $svg = [regex]::Replace($svg, '<svg\b', "<svg $viewBoxAttr")
        }
        return $svg
    }

    function ServiceIcon([string]$checkId) {
        $prefix = ($checkId -split '-')[0].ToUpper()
        if ($iconCache.ContainsKey($prefix)) { return $iconCache[$prefix] }

        $svg = $defaultIcon
        if ($serviceIconFiles.ContainsKey($prefix)) {
            $iconPath = Join-Path $iconsDir $serviceIconFiles[$prefix]
            if (Test-Path $iconPath) {
                $raw = Get-Content -Path $iconPath -Raw
                $raw = [regex]::Replace($raw, '<\?xml[^>]*\?>\s*', '')
                $raw = EnsureViewBox $raw
                $raw = [regex]::Replace($raw, '(<svg\b[^>]*?)\swidth="[^"]*"', '$1')
                $raw = [regex]::Replace($raw, '(<svg\b[^>]*?)\sheight="[^"]*"', '$1')
                $svg = NamespaceSvgIds $raw $prefix.ToLower()
            }
        }
        $iconCache[$prefix] = $svg
        return $svg
    }

    $total = @($Results).Count
    # Severity is the one rating shown everywhere now - Status (Fail/Pass/
    # ManualReview/Error) stays an internal-only field, never rendered.
    $criticalCount = @($Results | Where-Object Severity -eq 'Critical').Count
    $highCount = @($Results | Where-Object Severity -eq 'High').Count
    $mediumCount = @($Results | Where-Object Severity -eq 'Medium').Count
    $lowCount = @($Results | Where-Object Severity -eq 'Low').Count
    $infoCount = @($Results | Where-Object Severity -eq 'Informational').Count
    $hasNotConnected = @($NotConnected).Count -gt 0
    $catOffset = if ($hasNotConnected) { 2 } else { 1 }

    $preferredOrder = @(
        'Identity / Entra ID', 'Office Applications', 'Exchange Online',
        'SharePoint Online & OneDrive', 'Teams', 'Defender', 'Intune',
        'Microsoft Forms', 'Power BI', 'Purview / Compliance'
    )
    $allCategories = $Results | Select-Object -ExpandProperty Category -Unique
    $orderedCategories = @($preferredOrder | Where-Object { $_ -in $allCategories })
    $orderedCategories += @($allCategories | Where-Object { $_ -notin $preferredOrder } | Sort-Object)

    $reportDate = Get-Date -Format 'yyyy-MM-dd'

    $logoPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Assets\rootsec-logo.png'
    $logoHtml = "<div class='cover-logo-text'>ROOTSEC</div>"
    if (Test-Path $logoPath) {
        $logoBytes = [System.IO.File]::ReadAllBytes($logoPath)
        $logoB64 = [System.Convert]::ToBase64String($logoBytes)
        $logoHtml = "<img class='cover-logo' src='data:image/png;base64,$logoB64' alt='RootSec'>"
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine(@'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 / Entra ID Security Review</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
:root{
  --navy:#1a2744; --navy-mid:#243352; --red:#e63946;
  --text:#111827; --text-sub:#374151; --text-muted:#6b7280;
  --bg-light:#f9fafb; --bg-accent:#f0f4ff; --border:#e5e7eb; --border-mid:#d1d5db;
  --crit:#e63946; --high:#f4802b; --med:#f5c518; --low:#2196f3; --info:#8b949e;
}
*{box-sizing:border-box}
body{margin:0;background:#fff;color:var(--text);font-family:'Inter','Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}

/* ── COVER — logo top-left, big bold title, numbered contents list sized to
   actually fill the page rather than centering in a sea of empty space;
   the leftover space collects below the content (margin-top:auto on the
   footer meta) instead of surrounding it on both sides ─────────────────── */
.cover-page{min-height:72vh;display:flex;flex-direction:column;border-bottom:1px solid var(--border)}
.cover-logo-row{padding:40px 48px 0}
.cover-logo{max-height:90px;max-width:320px;object-fit:contain}
.cover-logo-text{font-size:32px;font-weight:800;color:var(--navy);letter-spacing:.04em}
.cover-content{padding:56px 48px 0}
.cover-title{font-size:50px;font-weight:800;line-height:1.14;margin:0 0 36px}
.cover-title .accent{color:var(--red)} .cover-title .plain{color:var(--text)}
.cover-contents-label{font-size:19px;font-weight:800;color:var(--text);margin:0 0 14px}
.cover-contents-list{list-style:none;margin:0;padding:0 0 0 18px}
.cover-contents-list li{font-size:16.5px;color:var(--text);padding:6px 0}
.cover-footer-meta{margin-top:auto;padding:0 48px 16px;font-size:12px;color:var(--text-muted)}
.cover-bottom-bar{height:8px;background:var(--red);width:100%}

/* ── CONTENTS (TOC) — clickable jump-nav, since HTML has no page numbers ── */
.toc-page{max-width:760px;margin:0 auto;padding:44px 32px 24px;border-bottom:1px solid var(--border)}
.toc-heading{font-size:24px;font-weight:800;color:var(--text);margin:0 0 20px}
.toc-row{display:flex;align-items:baseline;gap:8px;padding:9px 0;color:var(--text);text-decoration:none}
.toc-row:first-child{padding-top:0}
.toc-number{font-weight:700;flex:0 0 auto}
.toc-label{font-weight:600;font-size:14px;flex:0 0 auto}
.toc-leader{flex:1;border-bottom:1px dotted var(--border-mid);margin:0 6px 3px}
.toc-count{font-size:12px;font-weight:700;color:var(--text-muted);flex:0 0 auto}
.toc-sub-row{display:flex;align-items:baseline;gap:6px;padding:3px 0 3px 26px;border-bottom:none;color:var(--text-sub);text-decoration:none}
.toc-sub-id{font-family:'JetBrains Mono',Consolas,monospace;font-size:10px;font-weight:700;color:var(--text-muted);flex:0 0 auto}
.toc-sub-title{font-size:11.5px;color:var(--text-sub)}

.content{max-width:980px;margin:0 auto;padding:36px 32px 64px}
.section-header{margin:40px 0 20px}
.section-header:first-child{margin-top:0}
.section-title{font-size:22px;font-weight:800;color:var(--text);margin:0}
.section-sub{font-size:11px;color:var(--text-muted);margin:4px 0 0}

/* ── NOT CONNECTED / NOT TESTED — which categories had no connected service
   for this engagement, so no findings appear for them below ────────────── */
.nc-table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 24px;border:1px solid var(--border-mid);box-shadow:0 1px 5px rgba(17,24,39,.08)}
.nc-table th{background:var(--navy);color:#fff;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:9px 14px;text-align:left}
.nc-table td{padding:9px 14px;color:var(--text-sub);border-bottom:1px solid var(--border);vertical-align:top}
.nc-table tr:last-child td{border-bottom:none}
.nc-table tr:nth-child(even) td{background:var(--bg-light)}

/* ── FINDING CARD — literal Swiss InfoSec table shape: one rounded card,
   a vertical rule between label/content columns, horizontal rules between
   rows, plain bold-black labels, no colored banner, very slight drop
   shadow ───────────────────────────────────────────────────────────── */
.finding-card{border:1px solid var(--border-mid);border-radius:14px;overflow:hidden;margin-bottom:18px;box-shadow:0 1px 5px rgba(17,24,39,.08);padding:12px 16px}
.fc-row{display:flex;align-items:stretch;border-bottom:1px solid var(--border-mid)}
.fc-row:last-child{border-bottom:none}
.fc-label{flex:0 0 150px;padding:10px 16px;font-weight:700;color:var(--text);border-right:1px solid var(--border-mid);display:flex;align-items:center}
.fc-content{flex:1;padding:10px 16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;color:var(--text-sub);font-size:13px;line-height:1.6}
.fc-row-header .fc-label{justify-content:center;padding:10px}
.fc-icon{width:64px;height:64px;flex:0 0 auto}
.fc-icon svg{width:100%;height:100%;display:block}
.fc-row-header .fc-content{font-size:15px;font-weight:700;color:var(--navy)}
.fc-id{font-family:'JetBrains Mono',Consolas,monospace;font-size:11px;font-weight:700;color:var(--text-muted)}
.fc-content.config{font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fc-evidence{flex-basis:100%;font-family:'JetBrains Mono',Consolas,monospace;font-size:11.5px;background:var(--bg-light);border:1px solid var(--border);border-radius:4px;padding:8px 12px;color:#1f2937;white-space:pre-wrap;word-break:break-word}
.fc-refs{list-style:none;margin:0;padding:0;flex-basis:100%}
.fc-refs li{font-size:12px;padding:1px 0}
.fc-refs a{color:#1a7dd9;word-break:break-all}

.sev-badge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:3px;color:#fff;white-space:nowrap}
.sev-badge.critical{background:var(--crit)} .sev-badge.high{background:var(--high)}
.sev-badge.medium{background:var(--med);color:#1a1a1a} .sev-badge.low{background:var(--low)}
.sev-badge.informational{background:var(--info)}

footer{text-align:center;color:#fff;background:var(--red);font-size:13px;font-weight:600;padding:22px 24px;letter-spacing:.02em}
</style>
</head>
<body>
'@)

    [void]$sb.AppendLine('<div class="cover-page">')
    [void]$sb.AppendLine("<div class='cover-logo-row'>$logoHtml</div>")
    [void]$sb.AppendLine('<div class="cover-content">')
    [void]$sb.AppendLine('<h1 class="cover-title"><span class="accent">M365 / Entra ID</span> <span class="plain">Security Review</span></h1>')
    [void]$sb.AppendLine('<p class="cover-contents-label">Contents</p><ul class="cover-contents-list">')
    [void]$sb.AppendLine('<li>1. Engagement Summary</li>')
    if ($hasNotConnected) { [void]$sb.AppendLine('<li>2. Not Connected / Not Tested</li>') }
    $coverIndex = $catOffset + 1
    foreach ($category in $orderedCategories) {
        [void]$sb.AppendLine("<li>$coverIndex. $(Esc $category)</li>")
        $coverIndex++
    }
    [void]$sb.AppendLine('</ul>')
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine("<p class='cover-footer-meta'>$(Esc $ClientName) &nbsp;&bull;&nbsp; $(Esc $Tenant) &nbsp;&bull;&nbsp; $reportDate &nbsp;&bull;&nbsp; Confidential</p>")
    [void]$sb.AppendLine('<div class="cover-bottom-bar"></div>')
    [void]$sb.AppendLine('</div>')

    # ── Contents (TOC) — clickable, since this is one continuous HTML page ──
    [void]$sb.AppendLine('<div class="toc-page"><h1 class="toc-heading">Contents</h1>')
    [void]$sb.AppendLine("<a class='toc-row' href='#summary'><span class='toc-number'>1.</span><span class='toc-label'>Engagement Summary</span><span class='toc-leader'></span><span class='toc-count'>$total check(s)</span></a>")
    if ($hasNotConnected) {
        [void]$sb.AppendLine("<a class='toc-row' href='#not-connected'><span class='toc-number'>2.</span><span class='toc-label'>Not Connected / Not Tested</span><span class='toc-leader'></span><span class='toc-count'>$($NotConnected.Count) categor$(if ($NotConnected.Count -eq 1) { 'y' } else { 'ies' })</span></a>")
    }
    $tocIndex = $catOffset + 1
    foreach ($category in $orderedCategories) {
        $group = @($Results | Where-Object { $_.Category -eq $category })
        $catSlug = Slugify $category
        [void]$sb.AppendLine("<a class='toc-row' href='#section-$catSlug'><span class='toc-number'>$tocIndex.</span><span class='toc-label'>$(Esc $category)</span><span class='toc-leader'></span><span class='toc-count'>$($group.Count) check(s)</span></a>")
        foreach ($r in $group) {
            [void]$sb.AppendLine("<a class='toc-sub-row' href='#finding-$($r.CheckId.ToLower())'><span class='toc-sub-id'>$(Esc $r.CheckId)</span><span class='toc-sub-title'>$(Esc $r.Title)</span></a>")
        }
        $tocIndex++
    }
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<div class="content">')
    [void]$sb.AppendLine("<div class='section-header' id='summary'><p class='section-title'>1. Engagement Summary</p><p class='section-sub'>$total total &bull; $criticalCount critical &bull; $highCount high &bull; $mediumCount medium &bull; $lowCount low &bull; $infoCount informational</p></div>")

    if ($hasNotConnected) {
        [void]$sb.AppendLine("<div class='section-header' id='not-connected'><p class='section-title'>2. Not Connected / Not Tested</p><p class='section-sub'>No findings are listed below for these categories</p></div>")
        [void]$sb.AppendLine("<table class='nc-table'><thead><tr><th>Category</th><th>Reason</th><th>Checks skipped</th></tr></thead><tbody>")
        foreach ($nc in $NotConnected) {
            [void]$sb.AppendLine("<tr><td>$(Esc $nc.Category)</td><td>$(Esc $nc.Reason)</td><td>$($nc.CheckCount)</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    $sectionIndex = $catOffset + 1
    foreach ($category in $orderedCategories) {
        $group = $Results | Where-Object { $_.Category -eq $category }
        $catSlug = Slugify $category
        [void]$sb.AppendLine("<div class='section-header' id='section-$catSlug'><p class='section-title'>$sectionIndex. $(Esc $category)</p><p class='section-sub'>$(@($group).Count) check(s)</p></div>")
        $sectionIndex++

        $sorted = $group | Sort-Object { @('Critical', 'High', 'Medium', 'Low', 'Informational').IndexOf($_.Severity) }
        foreach ($r in $sorted) {
            $sevKey = SeverityKey $r.Severity

            [void]$sb.AppendLine("<div class='finding-card' id='finding-$($r.CheckId.ToLower())'>")
            [void]$sb.AppendLine("<div class='fc-row fc-row-header'><div class='fc-label fc-icon'>$(ServiceIcon $r.CheckId)</div><div class='fc-content'><span class='fc-id'>$(Esc $r.CheckId)</span> &mdash; $(Esc $r.Title)</div></div>")
            [void]$sb.AppendLine("<div class='fc-row'><div class='fc-label'>Rating</div><div class='fc-content'><span class='sev-badge $sevKey'>$(Esc $r.Severity)</span></div></div>")

            if ($r.Summary) {
                [void]$sb.AppendLine("<div class='fc-row'><div class='fc-label'>Summary</div><div class='fc-content'><div>$(Esc $r.Summary)</div>")
                if ($r.Evidence) { [void]$sb.AppendLine("<div class='fc-evidence'>$(Esc $r.Evidence)</div>") }
                [void]$sb.AppendLine('</div></div>')
            }
            if ($r.Remediation) {
                [void]$sb.AppendLine("<div class='fc-row'><div class='fc-label'>Remediation</div><div class='fc-content'>$(Esc $r.Remediation)</div></div>")
            }
            if ($r.AdminCenterPath) {
                [void]$sb.AppendLine("<div class='fc-row'><div class='fc-label'>Path</div><div class='fc-content config'>$(Esc $r.AdminCenterPath)</div></div>")
            }
            if (@($r.References).Count -gt 0) {
                [void]$sb.AppendLine("<div class='fc-row'><div class='fc-label'>Reference</div><div class='fc-content'><ul class='fc-refs'>")
                foreach ($ref in $r.References) { [void]$sb.AppendLine("<li><a href='$(Esc $ref)'>$(Esc $ref)</a></li>") }
                [void]$sb.AppendLine('</ul></div></div>')
            }

            [void]$sb.AppendLine('</div>')
        }
    }

    [void]$sb.AppendLine("</div><footer>Prepared by RootSec &bull; Confidential &bull; Point-in-time assessment as of $reportDate</footer>")
    [void]$sb.AppendLine('</body></html>')
    Set-Content -Path $Path -Value $sb.ToString() -Encoding utf8
}
