# The command-parameter check for the Windows management modules' scripts (ADR-0073, ADR-0083): for every command call in
# a script, every named parameter must exist on that command, read from the command's own metadata (Get-Command) in the
# running PowerShell. A parameter the command does not have is a runtime error that no domain is needed to see, and a
# script that passed -PassThru to Rename-GPO once reported it as "not found". Commands the script defines itself are
# checked against their own param blocks, and a splatted variable made from a hashtable literal is checked key by key.
#
# Also here: the 5.1 list rule. In Windows PowerShell 5.1, @(<List[object]>) of hashtables throws "Argument types do not
# match"; a generic List is turned into an array with .ToArray(), never wrapped in @().
Set-StrictMode -Version Latest

$script:WmcAst = 'System.Management.Automation.Language'
$script:WmcCommonParams = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable',
    'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm')
# Parameters a provider adds to a cmdlet while it runs (the file system's), which Get-Command cannot always list.
$script:WmcDynamic = @{
    'Get-ChildItem' = @('Directory', 'File', 'Attributes', 'Hidden', 'ReadOnly', 'System', 'FollowSymlink')
    'Get-Content'   = @('Delimiter', 'Wait', 'Stream')
    'Set-Content'   = @('Stream')
    'Add-Content'   = @('Stream')
    'Clear-Content' = @('Stream')
    'Get-Item'      = @('Stream')
    'Get-ItemProperty' = @('Stream')
    'Remove-Item'   = @('Stream')
}
$script:WmcCache = @{}

function Import-WinmodCheckModules([string[]]$Names) {
    foreach ($n in $Names) {
        if (Get-Module -Name $n) { continue }
        if (-not (Get-Module -ListAvailable -Name $n)) { continue }
        try { Import-Module -Name $n -ErrorAction Stop -WarningAction SilentlyContinue; continue } catch { Write-Verbose "import $n failed: $($_.Exception.Message)" }
        if ($PSVersionTable.PSEdition -eq 'Core') {
            try { Import-Module -Name $n -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue } catch { Write-Verbose "import $n (compat) failed: $($_.Exception.Message)" }
        }
    }
}

# The parameter names (and aliases) of a command, or $null when it cannot be resolved or has no metadata to check.
function Get-WinmodCommandParams([string]$Name) {
    if ($script:WmcCache.ContainsKey($Name)) { return $script:WmcCache[$Name] }
    $result = $null
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd -is [System.Management.Automation.AliasInfo]) { $cmd = $cmd.ResolvedCommand }
    if ($null -ne $cmd -and $cmd.CommandType -in @('Cmdlet', 'Function', 'Filter')) {
        try {
            $names = New-Object System.Collections.Generic.List[string]
            foreach ($kv in $cmd.Parameters.GetEnumerator()) {
                $names.Add([string]$kv.Key)
                foreach ($a in @($kv.Value.Aliases)) { $names.Add([string]$a) }
            }
            foreach ($d in @($script:WmcDynamic[[string]$cmd.Name])) { if ($d) { $names.Add($d) } }
            $result = @{ Name = [string]$cmd.Name; Params = $names.ToArray() }
        } catch { $result = $null }
    }
    $script:WmcCache[$Name] = $result
    return $result
}

# Does a written parameter name (a case-insensitive unique prefix is allowed) name one of these?
function Test-WinmodParamKnown([string]$Written, [string[]]$Known) {
    foreach ($k in $Known) { if ($k -ieq $Written) { return $true } }
    $hits = @($Known | Where-Object { $_.StartsWith($Written, [StringComparison]::OrdinalIgnoreCase) } | Sort-Object -Unique)
    return ($hits.Count -eq 1)
}

# Constant keys of the hashtable literals a variable is assigned in the file, by variable name ($q = @{...}; $q['k'] = ...).
function Get-WinmodSplatKeys($Ast) {
    $keys = @{}
    $assigns = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    foreach ($a in $assigns) {
        $left = $a.Left
        if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $right = $a.Right
            $expr = $null
            if ($right -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $right.Expression }
            if ($expr -is [System.Management.Automation.Language.HashtableAst]) {
                $name = $left.VariablePath.UserPath
                if (-not $keys.ContainsKey($name)) { $keys[$name] = New-Object System.Collections.Generic.List[string] }
                foreach ($kv in $expr.KeyValuePairs) {
                    if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $keys[$name].Add([string]$kv.Item1.Value) }
                }
            }
        } elseif ($left -is [System.Management.Automation.Language.IndexExpressionAst] -and $left.Target -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.Index -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $name = $left.Target.VariablePath.UserPath
            if (-not $keys.ContainsKey($name)) { $keys[$name] = New-Object System.Collections.Generic.List[string] }
            $keys[$name].Add([string]$left.Index.Value)
        }
    }
    return $keys
}

# The functions a parsed file defines, with their declared parameter names, added to $Own.
function Add-WinmodOwnFunctions([hashtable]$Own, $Ast) {
    foreach ($f in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        $names = New-Object System.Collections.Generic.List[string]
        $pars = @()
        if ($null -ne $f.Parameters) { $pars = @($f.Parameters) }
        elseif ($null -ne $f.Body.ParamBlock) { $pars = @($f.Body.ParamBlock.Parameters) }
        foreach ($pa in $pars) {
            $names.Add([string]$pa.Name.VariablePath.UserPath)
            foreach ($at in $pa.Attributes) {
                if ($at.TypeName.Name -eq 'Alias') { foreach ($x in $at.PositionalArguments) { $names.Add([string]$x.Value) } }
            }
        }
        $advanced = ($null -ne $f.Body.ParamBlock -and @($f.Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }).Count -gt 0)
        if ($advanced) { foreach ($c in $script:WmcCommonParams) { $names.Add($c) } }
        $Own[[string]$f.Name] = @{ Params = $names.ToArray(); Declared = ($pars.Count -gt 0) }
    }
}

# Findings for one script: "path:line: rule: message". Unresolved command names are added to $Unresolved (a hashtable).
function Test-WinmodCommandFile([string]$Path, [hashtable]$Unresolved) {
    $out = New-Object System.Collections.Generic.List[string]
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    foreach ($e in @($errs)) { $out.Add("${Path}:$($e.Extent.StartLineNumber): parse: $($e.Message)") }
    if (@($errs).Count -gt 0) { return @($out) }

    $own = @{}
    Add-WinmodOwnFunctions $own $ast
    # A library file next to the script (_common.ps1) is sent with it, so its functions are the script's own.
    foreach ($lib in @(Get-ChildItem -LiteralPath (Split-Path -Parent $Path) -Filter '_*.ps1' -ErrorAction SilentlyContinue)) {
        if ($lib.FullName -ne (Resolve-Path -LiteralPath $Path).Path) {
            $libAst = [System.Management.Automation.Language.Parser]::ParseFile($lib.FullName, [ref]$null, [ref]$null)
            Add-WinmodOwnFunctions $own $libAst
        }
    }
    $splats = Get-WinmodSplatKeys $ast

    foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $cmd.GetCommandName()
        if ([string]::IsNullOrEmpty($name)) { continue }
        $known = $null
        $shown = $name
        if ($own.ContainsKey($name)) {
            if (-not $own[$name].Declared) { continue }
            $known = $own[$name].Params
        } else {
            $info = Get-WinmodCommandParams $name
            if ($null -eq $info) {
                if (-not $Unresolved.ContainsKey($name)) { $Unresolved[$name] = 0 }
                $Unresolved[$name]++
                continue
            }
            $known = $info.Params
            $shown = $info.Name
        }
        foreach ($el in $cmd.CommandElements) {
            $line = $el.Extent.StartLineNumber
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                if (-not (Test-WinmodParamKnown $el.ParameterName $known)) {
                    $out.Add("${Path}:${line}: parameter: $shown has no parameter -$($el.ParameterName)")
                }
            } elseif ($el -is [System.Management.Automation.Language.VariableExpressionAst] -and $el.Splatted) {
                $v = $el.VariablePath.UserPath
                if ($splats.ContainsKey($v)) {
                    foreach ($k in ($splats[$v] | Sort-Object -Unique)) {
                        if (-not (Test-WinmodParamKnown $k $known)) { $out.Add("${Path}:${line}: parameter: $shown has no parameter -$k (splatted from `$$v)") }
                    }
                }
            }
        }
    }

    # The 5.1 list rule: @(<variable made from a generic List>) throws in Windows PowerShell 5.1.
    $listVars = @{}
    foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $a.Right.Extent.Text -match 'Collections\.Generic\.List|\[(System\.)?Collections\.Generic\.List') {
            $listVars[$a.Left.VariablePath.UserPath] = $true
        }
    }
    foreach ($arr in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ArrayExpressionAst] }, $true)) {
        $inner = $arr.SubExpression.Extent.Text.Trim()
        if ($inner -match '^\$([A-Za-z_][A-Za-z0-9_]*)$' -and $listVars.ContainsKey($Matches[1])) {
            $out.Add("${Path}:$($arr.Extent.StartLineNumber): list: @(`$$($Matches[1])) wraps a generic List, which throws in Windows PowerShell 5.1; use `$$($Matches[1]).ToArray()")
        }
    }
    return @($out)
}
