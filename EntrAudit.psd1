@{
    RootModule        = 'EntrAudit.psm1'
    ModuleVersion      = '0.1.0'
    GUID               = '7b3b6b7a-6b9b-4b3a-9b1d-5e4c9f0a21aa'
    Author             = 'RootSec'
    CompanyName        = 'RootSec'
    Copyright          = '(c) RootSec. Licensed under the MIT License.'
    Description        = 'Read-only M365 / Entra ID configuration review automation for pentest engagements. Requires Global Reader + Security Reader (plus Power BI Service Administrator / Fabric Administrator for Power BI checks).'
    PowerShellVersion   = '7.0'
    # 'Test-M365_*' is a deliberate wildcard, not an oversight (PSScriptAnalyzer's
    # PSUseToExportFieldsInManifest will flag it): the whole point of the check
    # convention is that dropping a new Test-M365_* function into Checks/ makes it
    # discoverable with zero other changes. An explicit name list here would have
    # to be hand-maintained and would silently hide any check someone forgets to
    # add to it - exactly the maintenance burden this design avoids.
    FunctionsToExport   = @('Connect-EntrAudit', 'Invoke-EntrAudit', 'Export-EntrAuditReport', 'Test-M365_*')
    CmdletsToExport     = @()
    VariablesToExport   = @()
    AliasesToExport     = @()
}
