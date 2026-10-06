function Invoke-EntrAudit {
    <#
    .SYNOPSIS
        Runs every discovered M365 review check and returns the standardized result
        objects. Call Connect-EntrAudit first.

    .PARAMETER ClientName
        Engagement/client name, used only for report metadata (passed through to
        Export-EntrAuditReport if you capture it separately).

    .PARAMETER Context
        Service-connection context object. Defaults to whatever Connect-EntrAudit
        last produced in this session.

    .PARAMETER IncludeCategory
        Only run checks whose Category matches one of these (wildcard-friendly,
        e.g. 'Identity*'). Default: all categories.

    .PARAMETER ExcludeCategory
        Skip checks whose Category matches one of these (wildcard-friendly).

    .EXAMPLE
        $results = Invoke-EntrAudit -ClientName 'Contoso Ltd'
        $results | Where-Object Status -eq Fail

    .EXAMPLE
        Invoke-EntrAudit -ExcludeCategory 'Power BI' | Export-EntrAuditReport -ClientName 'Contoso Ltd' -OutputPath .\Reports
    #>
    [CmdletBinding()]
    param(
        [string]$ClientName = 'Unnamed Engagement',
        [PSCustomObject]$Context = $script:EntrAuditContext,
        [string[]]$IncludeCategory = @('*'),
        [string[]]$ExcludeCategory = @()
    )

    if (-not $Context) {
        throw 'No connection context available. Run Connect-EntrAudit first (or pass -Context explicitly).'
    }
    $contextHash = @{}
    $Context.PSObject.Properties | ForEach-Object { $contextHash[$_.Name] = $_.Value }

    $checkFunctions = Get-Command -Name 'Test-M365_*' -CommandType Function | Sort-Object Name
    if (@($checkFunctions).Count -eq 0) {
        throw 'No checks were discovered (Test-M365_* functions). Is the module imported correctly?'
    }

    Write-Host ''
    Write-Host "=== Running M365 Review for '$ClientName' — $(@($checkFunctions).Count) checks discovered ===" -ForegroundColor Cyan

    $results = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($fn in $checkFunctions) {
        $i++
        Write-Progress -Activity 'M365 Review' -Status $fn.Name -PercentComplete (($i / @($checkFunctions).Count) * 100)

        try {
            $result = & $fn.Name -Context $contextHash
            if ($result) {
                foreach ($r in @($result)) {
                    if ($IncludeCategory | Where-Object { $r.Category -like $_ }) {
                        if (-not ($ExcludeCategory | Where-Object { $r.Category -like $_ })) {
                            $results.Add($r)
                        }
                    }
                }
            }
        }
        catch {
            # Safety net in case a check throws before reaching its own
            # Invoke-M365CheckSafely wrapper (e.g. a bug in the check itself).
            $results.Add(
                (New-M365CheckResult -CheckId $fn.Name -Category 'Unknown' -Title $fn.Name `
                        -Severity Informational -Status Error `
                        -Summary "Check function threw before producing a result: $($_.Exception.Message)" `
                        -Evidence $_.Exception.Message -Remediation 'Investigate the check implementation.' `
                        -RequiredSource Manual)
            )
        }
    }
    Write-Progress -Activity 'M365 Review' -Completed

    $summary = $results | Group-Object Status | Sort-Object Count -Descending
    Write-Host "`n=== Run complete: $(@($results).Count) results ===" -ForegroundColor Cyan
    foreach ($group in $summary) {
        Write-Host ('  {0,-15} {1}' -f $group.Name, $group.Count)
    }
    Write-Host ''

    return $results
}
