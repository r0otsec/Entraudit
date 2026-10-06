function Get-M365SafeSheetName {
    <#
    .SYNOPSIS
        Converts an arbitrary Category string into a valid, unique-enough Excel
        worksheet name: strips characters Excel forbids (\ / ? * [ ] :), collapses
        whitespace, and truncates to Excel's 31-character sheet-name limit.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $clean = $Name -replace '[\\/\?\*\[\]:]', '-'
    $clean = ($clean -replace '\s+', ' ').Trim()
    if ($clean.Length -gt 31) { $clean = $clean.Substring(0, 31).Trim() }
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Other' }
    return $clean
}
