function Get-M365PowerBiAllSettings {
    <#
    .SYNOPSIS
        Flattens the Power BI Admin REST API's tenantSettingGroups response into a
        single list of individual settings, so each check can search by the
        human-readable 'title' text rather than guessing exact settingName strings
        (which have shifted across API versions).
    #>
    [CmdletBinding()]
    param()

    $raw = Invoke-PowerBIRestMethod -Url 'admin/tenantsettings' -Method Get -ErrorAction Stop | ConvertFrom-Json
    $all = foreach ($group in $raw.tenantSettingGroups) {
        # Documented schema uses 'tenantSettings'; fall back to 'settings' defensively
        # in case the API shape drifts.
        $settingList = if ($group.PSObject.Properties.Name -contains 'tenantSettings') { $group.tenantSettings } else { $group.settings }
        foreach ($setting in $settingList) {
            $setting
        }
    }
    return $all
}
