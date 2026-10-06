function Write-EntrAuditPdfReport {
    <#
    .SYNOPSIS
        Renders results to a branded PDF via PdfReport\generate_pdf.py
        (Python + Playwright/Chromium). Requires: Python 3 with pyyaml, jinja2,
        markdown, pypdf installed, `playwright install chromium` run once, and
        the PowerShell `powershell-yaml` module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [object[]]$NotConnected = @(),
        [Parameter(Mandatory)][string]$ClientName,
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$Path
    )

    $pythonCmd = Get-Command -Name python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) { $pythonCmd = Get-Command -Name python3 -ErrorAction SilentlyContinue }
    if (-not $pythonCmd) {
        throw "PDF output needs Python 3, which wasn't found on PATH. Install it from https://python.org, then run: pip install pyyaml jinja2 markdown pypdf playwright Pillow && playwright install chromium. (Or choose a different -OutputFormat - Excel/Csv/Json/Html don't need Python.)"
    }

    if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
        throw "PDF output needs the 'powershell-yaml' PowerShell module. Install it with: Install-Module powershell-yaml -Scope CurrentUser"
    }
    Import-Module powershell-yaml -ErrorAction Stop

    $pdfReportDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'PdfReport'
    $generateScript = Join-Path $pdfReportDir 'generate_pdf.py'
    $logoPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Assets\rootsec-logo.png'
    if (-not (Test-Path $generateScript)) {
        throw "PDF render script not found at $generateScript - the EntrAudit\PdfReport folder may be missing or incomplete."
    }

    $data = ConvertTo-EntrAuditPdfData -Results $Results -NotConnected $NotConnected -ClientName $ClientName -Tenant $Tenant
    $yamlText = $data | ConvertTo-Yaml
    $yamlPath = Join-Path ([System.IO.Path]::GetTempPath()) "entraudit-$([guid]::NewGuid()).yaml"
    Set-Content -Path $yamlPath -Value $yamlText -Encoding utf8

    try {
        $pythonArgs = @($generateScript, $yamlPath, '--output', $Path)
        if (Test-Path $logoPath) { $pythonArgs += @('--logo', $logoPath) }

        $output = & $pythonCmd.Source @pythonArgs 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Path)) {
            throw "PDF generation failed (exit code $LASTEXITCODE). Python output:`n$($output -join "`n")`n`nIf this mentions 'playwright' or 'chromium', run: playwright install chromium"
        }
    }
    finally {
        Remove-Item -Path $yamlPath -Force -ErrorAction SilentlyContinue
    }
}
