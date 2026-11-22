# PSScriptAnalyzer's rules for the scripts the agent runs (see
# check-powershell.ps1): errors and warnings, for Windows PowerShell 5.1.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # The scripts run non-interactively as LocalSystem and write their
        # progress for the job's output; there is no host to protect.
        'PSAvoidUsingWriteHost',
        # Function names are the scripts' own (Test-, Get-, Resolve-), not
        # cmdlets: none supports -WhatIf, and none is exported.
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }
}
