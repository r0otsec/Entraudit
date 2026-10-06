#Requires -Version 7.0
<#
.SYNOPSIS
    Installs/updates the PowerShell modules EntrAudit depends on, for the
    current user only (no admin rights required).

.DESCRIPTION
    Only installs what you'll actually use: pass -Services to limit which module
    sets get installed, e.g. if a client doesn't have Power BI/Fabric or Teams,
    skip pulling those modules down at all.

.PARAMETER Services
    One or more of: Graph, Exo, Spo, Teams, Compliance, PowerBI, Excel, Pdf, All (default).
    'Compliance' re-uses ExchangeOnlineManagement (Connect-IPPSSession lives there).
    'Pdf' installs the powershell-yaml module and, if Python is found on PATH,
    pip-installs the Python packages PdfReport\generate_pdf.py needs (pyyaml,
    jinja2, markdown, pypdf, playwright, Pillow) plus `playwright install
    chromium`. If Python isn't installed at all, -OutputFormat Pdf just won't
    be available - every other format still works.

.EXAMPLE
    .\Install-Prerequisites.ps1
    .\Install-Prerequisites.ps1 -Services Graph,Exo,Excel
#>
[CmdletBinding()]
param(
    [ValidateSet('Graph', 'Exo', 'Spo', 'Teams', 'Compliance', 'PowerBI', 'Excel', 'Pdf', 'All')]
    [string[]]$Services = @('All')
)

$moduleMap = @{
    Graph      = @('Microsoft.Graph')
    Exo        = @('ExchangeOnlineManagement')
    Spo        = @('Microsoft.Online.SharePoint.PowerShell')
    Teams      = @('MicrosoftTeams')
    Compliance = @('ExchangeOnlineManagement') # Connect-IPPSSession ships in this module
    PowerBI    = @('MicrosoftPowerBIMgmt')
    Excel      = @('ImportExcel')
    Pdf        = @('powershell-yaml')
}

$targets = if ($Services -contains 'All') { $moduleMap.Keys } else { $Services }
$modulesToInstall = $targets | ForEach-Object { $moduleMap[$_] } | Select-Object -Unique

Write-Host "EntrAudit prerequisites - installing for CurrentUser scope only." -ForegroundColor Cyan
Write-Host "Modules to check: $($modulesToInstall -join ', ')" -ForegroundColor Gray
Write-Host ''

foreach ($moduleName in $modulesToInstall) {
    $existing = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
    if ($existing) {
        Write-Host "[OK] $moduleName already installed (v$($existing.Version))." -ForegroundColor Green
        continue
    }

    Write-Host "[..] Installing $moduleName (CurrentUser scope)..." -ForegroundColor Yellow
    try {
        Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        Write-Host "[OK] Installed $moduleName." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to install $moduleName : $($_.Exception.Message)"
        Write-Warning "You can retry manually with: Install-Module $moduleName -Scope CurrentUser"
    }
}

if ($targets -contains 'Pdf') {
    Write-Host ''
    Write-Host '[..] Checking Python for PDF output...' -ForegroundColor Yellow
    $pythonCmd = Get-Command -Name python -ErrorAction SilentlyContinue
    if (-not $pythonCmd) { $pythonCmd = Get-Command -Name python3 -ErrorAction SilentlyContinue }

    if (-not $pythonCmd) {
        Write-Warning 'Python 3 not found on PATH. Install it from https://python.org, then re-run: .\Install-Prerequisites.ps1 -Services Pdf'
        Write-Warning '(Every other -OutputFormat still works without Python.)'
    }
    else {
        Write-Host "[OK] Found Python at $($pythonCmd.Source)" -ForegroundColor Green
        $pipPackages = 'pyyaml', 'jinja2', 'markdown', 'pypdf', 'playwright', 'Pillow'
        Write-Host "[..] pip installing: $($pipPackages -join ', ') (--user scope)..." -ForegroundColor Yellow
        & $pythonCmd.Source -m pip install --user --quiet @pipPackages
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "pip install failed (exit $LASTEXITCODE). Run manually: python -m pip install --user $($pipPackages -join ' ')"
        }
        else {
            Write-Host '[OK] Python packages installed.' -ForegroundColor Green
        }

        Write-Host '[..] Installing Playwright Chromium (one-time, ~100-200MB download)...' -ForegroundColor Yellow
        & $pythonCmd.Source -m playwright install chromium
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'playwright install chromium failed. Run manually: python -m playwright install chromium'
        }
        else {
            Write-Host '[OK] Chromium installed.' -ForegroundColor Green
        }
    }
}

Write-Host ''
Write-Host 'Done. Checks whose required service module failed to install will report Status = NotApplicable at run time rather than crashing the whole review.' -ForegroundColor Cyan
