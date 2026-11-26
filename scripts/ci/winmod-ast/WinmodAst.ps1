# The PowerShell AST check for the Windows management modules' catalogue scripts (ADR-0073, "Tests"; ADR-0076 and
# ADR-0077 add to it). Dot-source this file, then call Test-WinmodScript on a file or Test-WinmodTree on a folder.
#
# A catalogue script receives its parameters on standard input, as one JSON document read into $p. This check parses
# each script with PowerShell's own parser and walks the syntax tree, so it sees through spacing, aliases, quoting
# and abbreviated parameter names, which a grep does not. A finding is "<file>:<line>: <rule>: <message>".
#
# Rules (the name is what a finding and a fixture's "# expect:" line use):
#   parse           the file parses.
#   iex             no Invoke-Expression or iex, and no [scriptblock]::Create, InvokeScript or ExpandString.
#   command-param   no -Command or -EncodedCommand on a command (and -c, -ec on powershell, pwsh and cmd).
#   add-type        Add-Type takes literal text only.
#   filter          -Filter, -LDAPFilter and -FilterXPath take a literal only (a user value is never put in a filter).
#   string-build    no expandable string, "+", "-f" or "-join" that includes $p or a variable assigned from it.
#   dynamic-command no call operator or dot-sourcing of anything but a literal name (or a script block literal).
#   remote-param    no -ComputerName, -CimSession, -Server or -Session from $p (ADR-0076).
#   plaintext       ConvertTo-SecureString -AsPlainText only inside a reviewed helper whose body matches its pinned
#                   SHA-256 (ADR-0077); ConvertFrom-SecureString -AsPlainText and Marshal.SecureStringTo* never.
#   strict-mode     Set-StrictMode -Version Latest and $ErrorActionPreference = 'Stop' (scripts, not libraries).
#   stdin           $p = [Console]::In.ReadToEnd() | ConvertFrom-Json, once; no script param block, $args, $input,
#                   $env:, $PSBoundParameters, Read-Host or Environment methods (scripts, not libraries).
#   library         a file named _*.ps1 is a shared library: function definitions only.
#   pin             a pinned helper is defined once, in a library, and exists.
#
# Taint: $p, and any variable assigned from an expression that uses a tainted variable (not a hashtable or array
# literal: those hold values, they do not build text). It does not follow a value through a function's parameter; the
# string-building rules are applied in the function too, to what it builds.

Set-StrictMode -Version Latest

function Get-WinmodTextHash([string]$Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.Replace("`r`n", "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

$script:Ast = [System.Management.Automation.Language.Ast]
function Get-WinmodNodes($Node, [scriptblock]$Where) {
    return @($Node.FindAll($Where, $true))
}

function Get-WinmodTaint($Root) {
    $set = @{ p = $true }
    do {
        $changed = $false
        $assigns = Get-WinmodNodes $Root { param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }
        foreach ($a in $assigns) {
            $rhs = $a.Right
            if ($rhs -is [System.Management.Automation.Language.CommandExpressionAst]) {
                $rhs = $rhs.Expression
                while ($rhs -is [System.Management.Automation.Language.ConvertExpressionAst]) { $rhs = $rhs.Child }
            }
            if ($rhs -is [System.Management.Automation.Language.HashtableAst] -or
                $rhs -is [System.Management.Automation.Language.ArrayLiteralAst]) { continue }
            if (@(Get-WinmodRefs $a.Right $set).Count -eq 0) { continue }
            foreach ($v in (Get-WinmodNodes $a.Left { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] })) {
                $name = $v.VariablePath.UserPath.ToLowerInvariant()
                if (-not $set.ContainsKey($name)) { $set[$name] = $true; $changed = $true }
            }
        }
        $loops = Get-WinmodNodes $Root { param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }
        foreach ($l in $loops) {
            if (@(Get-WinmodRefs $l.Condition $set).Count -gt 0) {
                $name = $l.Variable.VariablePath.UserPath.ToLowerInvariant()
                if (-not $set.ContainsKey($name)) { $set[$name] = $true; $changed = $true }
            }
        }
    } while ($changed)
    return $set
}

function Get-WinmodRefs($Node, $Taint) {
    return @(Get-WinmodNodes $Node { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] } |
        Where-Object { $Taint.ContainsKey($_.VariablePath.UserPath.ToLowerInvariant()) })
}

# The argument a command parameter takes: "-Name:value", or the element after it.
function Get-WinmodParamArgument($Cmd, $Param) {
    if ($Param.Argument) { return $Param.Argument }
    $els = @($Cmd.CommandElements)
    $i = [array]::IndexOf($els, $Param)
    if ($i -ge 0 -and $i + 1 -lt $els.Count -and $els[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { return $els[$i + 1] }
    return $null
}

function Test-WinmodParamName($Param, [string[]]$Names, [int]$MinLength = 2) {
    $n = $Param.ParameterName
    foreach ($want in $Names) {
        if ($n.Length -ge $MinLength -and $want.StartsWith($n, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Test-WinmodLiteral($Node) {
    if ($null -eq $Node) { return $false }
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $true }
    if ($Node -is [System.Management.Automation.Language.ConstantExpressionAst]) { return $true }
    if ($Node -is [System.Management.Automation.Language.ParenExpressionAst]) {
        $e = @($Node.Pipeline.PipelineElements)
        return ($e.Count -eq 1 -and $e[0] -is [System.Management.Automation.Language.CommandExpressionAst] -and (Test-WinmodLiteral $e[0].Expression))
    }
    return $false
}

# Pins: name -> SHA-256 of the helper function's body. Findings come back as strings.
function Test-WinmodScript {
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Pins = @{}, [hashtable]$PinsSeen = @{})
    $findings = New-Object System.Collections.Generic.List[string]
    $add = { param($node, $rule, $msg) $findings.Add(('{0}:{1}: {2}: {3}' -f $Path, $node.Extent.StartLineNumber, $rule, $msg)) }
    $tokens = $null; $errors = $null
    $root = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { $findings.Add(('{0}:{1}: parse: {2}' -f $Path, $e.Extent.StartLineNumber, $e.Message)) }
    if (@($errors).Count -gt 0) { return @($findings) }

    $library = (Split-Path -Leaf $Path).StartsWith('_')
    $taint = Get-WinmodTaint $root
    $T = 'System.Management.Automation.Language'

    # Reviewed helpers: functions whose pinned hash matches this body.
    $exempt = @()
    $fns = Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }
    foreach ($f in $fns) {
        if (-not $Pins.ContainsKey($f.Name)) { continue }
        if ($PinsSeen.ContainsKey($f.Name)) { & $add $f 'pin' "the pinned helper $($f.Name) is defined more than once"; continue }
        $PinsSeen[$f.Name] = $Path
        if (-not $library) { & $add $f 'pin' "the pinned helper $($f.Name) must be in a shared library file (a name starting with an underscore)"; continue }
        $got = Get-WinmodTextHash $f.Body.Extent.Text
        if ($got -ne $Pins[$f.Name]) { & $add $f 'pin' "the pinned helper $($f.Name) has SHA-256 $got, not the pinned $($Pins[$f.Name]); a change to it needs review and a new pin"; continue }
        $exempt += $f
    }
    $inExempt = {
        param($node)
        for ($p = $node.Parent; $null -ne $p; $p = $p.Parent) { if ($exempt -contains $p) { return $true } }
        return $false
    }

    if ($library) {
        foreach ($s in @($root.EndBlock.Statements)) {
            if ($s -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { & $add $s 'library' 'a shared library holds function definitions only' }
        }
    }

    foreach ($c in (Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.CommandAst] })) {
        $name = $c.GetCommandName()
        $first = $c.CommandElements[0]
        if ($null -eq $name) {
            if ($first -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                & $add $c 'dynamic-command' 'the command is not a literal name (call operator or dot-sourcing of a value)'
            }
            $lower = ''
        } else {
            $lower = $name.ToLowerInvariant()
            if ($lower -eq 'invoke-expression' -or $lower -eq 'iex') { & $add $c 'iex' 'Invoke-Expression runs text as code' }
        }
        $shell = @('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe', 'cmd', 'cmd.exe') -contains $lower
        foreach ($el in @($c.CommandElements)) {
            if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
            $pn = $el.ParameterName
            $isCommand = ($pn -ieq 'Command') -or ($pn -ieq 'EncodedCommand') -or ($shell -and (Test-WinmodParamName $el @('Command', 'EncodedCommand', 'ec') 1))
            if ($isCommand) { & $add $c 'command-param' "-$pn passes text to be run as code" }
            if (Test-WinmodParamName $el @('Filter', 'LDAPFilter', 'FilterXPath')) {
                if (-not (Test-WinmodLiteral (Get-WinmodParamArgument $c $el))) { & $add $c 'filter' "-$pn takes a literal only; a filter is never built from a value" }
            }
            if (Test-WinmodParamName $el @('ComputerName', 'CimSession', 'Server', 'Session') 3) {
                $arg = Get-WinmodParamArgument $c $el
                if ($null -ne $arg -and @(Get-WinmodRefs $arg $taint).Count -gt 0) { & $add $c 'remote-param' "-$pn must not come from the parameters" }
            }
            if ($lower -eq 'convertto-securestring' -and (Test-WinmodParamName $el @('AsPlainText') 2) -and -not (& $inExempt $c)) {
                & $add $c 'plaintext' 'ConvertTo-SecureString -AsPlainText is allowed only inside the pinned helper New-EasyRmmCredential'
            }
            if ($lower -eq 'convertfrom-securestring' -and (Test-WinmodParamName $el @('AsPlainText') 2)) {
                & $add $c 'plaintext' 'ConvertFrom-SecureString -AsPlainText is never allowed'
            }
        }
        if ($lower -eq 'add-type') {
            $nonLiteral = @($c.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] -and -not (Test-WinmodLiteral $_) })
            if ($nonLiteral.Count -gt 0) { & $add $c 'add-type' 'Add-Type takes literal text only' }
        }
        if ($lower -eq 'read-host' -and -not $library) { & $add $c 'stdin' 'Read-Host: parameters come from standard input only' }
    }

    foreach ($m in (Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] })) {
        $mn = if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $m.Member.Value } else { '' }
        $ex = $m.Expression.Extent.Text
        if (@('InvokeScript', 'ExpandString', 'NewScriptBlock', 'AddScript') -contains $mn -or ($mn -eq 'Create' -and $ex -match '^\[(System\.Management\.Automation\.)?ScriptBlock\]$')) {
            & $add $m 'iex' "$mn runs text as code"
        }
        if ($mn -like 'SecureStringTo*' -and $ex -match 'Marshal') { & $add $m 'plaintext' 'a SecureString is never turned back into text' }
        if (-not $library -and $ex -match '^\[(System\.)?Environment\]$' -and $mn -match '^(GetEnvironmentVariable|GetEnvironmentVariables|GetCommandLineArgs)$') {
            & $add $m 'stdin' "[Environment]::${mn}: parameters come from standard input only"
        }
    }

    foreach ($s in (Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] })) {
        if (@(Get-WinmodRefs $s $taint).Count -gt 0) { & $add $s 'string-build' 'an expandable string uses a parameter value' }
    }
    foreach ($b in (Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] })) {
        if (@('Plus', 'Format', 'Join') -contains $b.Operator.ToString() -and @(Get-WinmodRefs $b $taint).Count -gt 0) {
            & $add $b 'string-build' "the $($b.Operator) operator uses a parameter value"
        }
    }

    if (-not $library) {
        $vars = Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }
        foreach ($v in $vars) {
            $vp = $v.VariablePath
            $un = $vp.UserPath.ToLowerInvariant()
            if ($vp.IsDriveQualified -and $vp.DriveName -ieq 'env') { & $add $v 'stdin' 'an environment variable: parameters come from standard input only' }
            if (@('args', 'input', 'psboundparameters') -contains $un) { & $add $v 'stdin' "`$$($vp.UserPath): parameters come from standard input only" }
        }
        if ($null -ne $root.ParamBlock) { & $add $root.ParamBlock 'stdin' 'a script parameter block: parameters come from standard input only' }
        $reads = @(Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -eq 'ReadToEnd' })
        $good = @($reads | Where-Object {
            $_.Expression.Extent.Text -replace '\s', '' -match '^\[(System\.)?Console\]::In$' -and
            $_.Parent -is [System.Management.Automation.Language.CommandExpressionAst] -and
            $_.Parent.Parent -is [System.Management.Automation.Language.PipelineAst] -and
            $_.Parent.Parent.PipelineElements.Count -eq 2 -and
            $_.Parent.Parent.PipelineElements[1] -is [System.Management.Automation.Language.CommandAst] -and
            $_.Parent.Parent.PipelineElements[1].GetCommandName() -ieq 'ConvertFrom-Json' -and
            $_.Parent.Parent.Parent -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $_.Parent.Parent.Parent.Left.Extent.Text -ceq '$p' -and
            $_.Parent.Parent.Parent.Parent -is [System.Management.Automation.Language.NamedBlockAst]
        })
        if ($reads.Count -ne 1 -or $good.Count -ne 1) {
            & $add $root 'stdin' 'the script must read its parameters once, as: $p = [Console]::In.ReadToEnd() | ConvertFrom-Json'
        }
        $strict = @(Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ieq 'Set-StrictMode' })
        $latest = @($strict | Where-Object {
            $els = @($_.CommandElements)
            $vi = -1
            for ($i = 0; $i -lt $els.Count; $i++) { if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -ieq 'Version') { $vi = $i } }
            $vi -ge 0 -and $vi + 1 -lt $els.Count -and $els[$vi + 1].Extent.Text -ieq 'Latest'
        })
        if ($latest.Count -eq 0) { & $add $root 'strict-mode' 'the script must call Set-StrictMode -Version Latest' }
        $eap = @(Get-WinmodNodes $root { param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ieq '$ErrorActionPreference' })
        $stop = @($eap | Where-Object { $_.Right.Extent.Text -match "^['""]Stop['""]$" })
        if ($stop.Count -eq 0) { & $add $root 'strict-mode' "the script must set `$ErrorActionPreference = 'Stop'" }
    }
    return @($findings)
}

# Checks every .ps1 under a folder; a pin that no file defines is a finding too. Returns the findings.
function Test-WinmodTree {
    param([Parameter(Mandatory)][string]$Root, [hashtable]$Pins = @{})
    $all = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $files = @(Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.ps1' | Sort-Object FullName)
    foreach ($f in $files) { foreach ($x in (Test-WinmodScript -Path $f.FullName -Pins $Pins -PinsSeen $seen)) { $all.Add($x) } }
    foreach ($k in $Pins.Keys) { if (-not $seen.ContainsKey($k)) { $all.Add("${Root}: pin: the pinned helper $k is not defined in any library file") } }
    return @($all)
}
