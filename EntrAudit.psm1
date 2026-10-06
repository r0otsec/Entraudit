$here = $PSScriptRoot

# Private helpers first (checks and public functions depend on these).
Get-ChildItem -Path (Join-Path $here 'Private') -Filter '*.ps1' -File | ForEach-Object {
    . $_.FullName
}

# All check definitions (Test-M365_* functions), discovered by Invoke-EntrAudit at run time.
Get-ChildItem -Path (Join-Path $here 'Checks') -Filter '*.ps1' -File -Recurse | ForEach-Object {
    . $_.FullName
}

# Public entry points.
Get-ChildItem -Path (Join-Path $here 'Public') -Filter '*.ps1' -File | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function @(
    'Connect-EntrAudit',
    'Invoke-EntrAudit',
    'Export-EntrAuditReport',
    'Test-M365_*'
)
