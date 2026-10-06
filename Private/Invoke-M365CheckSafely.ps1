function Invoke-M365CheckSafely {
    <#
    .SYNOPSIS
        Runs a check's script block and classifies failures so a run never hard-fails
        and licensing/feature-not-enabled gaps don't show up as noisy errors.

    .DESCRIPTION
        Three outcomes:
          - ScriptBlock completes normally -> its own returned result is passed through.
          - ScriptBlock throws something that looks like "feature/license not present"
            (heuristic match on common provider error text) -> Status = NotApplicable.
          - ScriptBlock throws anything else -> Status = Error, surfaced for investigation
            (wrong scope, throttling, transient API issue, etc.) rather than swallowed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Meta,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    # Heuristic signatures for "this tenant doesn't have the license/feature enabled"
    # rather than a genuine error worth flagging. Deliberately broad since every
    # service (Graph, Power BI, EXO, SPO, Teams) phrases this differently.
    $notLicensedPatterns = @(
        'PowerBINotAuthorizedException',
        'not authorized to call',
        'does not have a valid license',
        'is not enabled for this tenant',
        'FeatureNotAvailable',
        'PremiumPerUser',
        'no Fabric capacity',
        'tenant does not have.*capacity',
        'Forbidden',
        '403'
    )

    try {
        & $ScriptBlock
    }
    catch {
        $exceptionMessage = $_.Exception.Message
        $isNotApplicable = $false

        foreach ($pattern in $notLicensedPatterns) {
            if ($exceptionMessage -match $pattern) {
                $isNotApplicable = $true
                break
            }
        }

        if ($isNotApplicable) {
            New-M365CheckResult @Meta -Status NotApplicable `
                -Summary "Service or feature appears not licensed/enabled for this tenant: $exceptionMessage" `
                -Evidence $exceptionMessage -RawData $_.Exception
        }
        else {
            New-M365CheckResult @Meta -Status Error `
                -Summary "Check failed unexpectedly and should be investigated manually: $exceptionMessage" `
                -Evidence $exceptionMessage -RawData $_.Exception
        }
    }
}
