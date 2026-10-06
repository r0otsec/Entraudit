<#
.SYNOPSIS
    RootSec M365 / Entra ID Security Review - entry point. Auto-relaunches under
    PowerShell 7+ (pwsh) if invoked from Windows PowerShell 5.1, then runs
    EntrAudit.Core.ps1 with whatever arguments you gave.

.DESCRIPTION
    This file deliberately has no param() block of its own - that's what lets it
    inspect $PSVersionTable and relaunch under pwsh BEFORE any argument binding
    happens. (A version check placed before param() in the same file breaks
    parameter binding entirely - confirmed by testing, not a guess - hence the
    two-file split: this thin launcher, and EntrAudit.Core.ps1 for the real
    logic/parameters/help.)

    Run `.\EntrAudit.ps1 -Help` (or `-h` / `--help`) for the full options screen -
    that flows straight through to Core.ps1 either way.
#>

if ($PSVersionTable.PSVersion.Major -lt 7) {
    $pwshCmd = Get-Command -Name pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) {
        Write-Host "[EntrAudit] Currently running under Windows PowerShell $($PSVersionTable.PSVersion) - relaunching under pwsh..." -ForegroundColor DarkYellow
        & $pwshCmd.Source -NoProfile -File (Join-Path $PSScriptRoot 'EntrAudit.Core.ps1') @args
        exit $LASTEXITCODE
    }

    Write-Error @"
EntrAudit requires PowerShell 7 or later (currently running Windows PowerShell $($PSVersionTable.PSVersion)), and pwsh.exe could not be found on PATH.
Install PowerShell 7+ from https://aka.ms/powershell, then either:
  - run this script again (it will auto-relaunch under pwsh), or
  - run it explicitly via: pwsh .\EntrAudit.ps1 ...
"@
    exit 1
}

& (Join-Path $PSScriptRoot 'EntrAudit.Core.ps1') @args
exit $LASTEXITCODE
