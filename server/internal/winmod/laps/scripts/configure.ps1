Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1

function Write-Result($fn_ok, $fn_data, $fn_code, $fn_message) {
    $fn_r = [ordered]@{ ok = $fn_ok; version = $version; data = $fn_data; error = $null }
    if (-not $fn_ok) { $fn_r.error = [ordered]@{ code = $fn_code; message = $fn_message } }
    [Console]::Out.WriteLine('EASYRMM-WINMOD-RESULT-V1 ' + (ConvertTo-Json -InputObject $fn_r -Compress -Depth 8))
}
function Stop-With($fn_code, $fn_message) {
    Write-Result $false $null $fn_code $fn_message
    exit 0
}

try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $backupDir = [int]$p.backupDirectory
    $applied = [ordered]@{}

    Set-ItemProperty -Path $regPath -Name 'BackupDirectory' -Value $backupDir -Type DWord
    $applied['BackupDirectory'] = $backupDir

    $dwords = @{
        passwordAgeDays                    = 'PasswordAgeDays'
        passwordLength                     = 'PasswordLength'
        passwordComplexity                 = 'PasswordComplexity'
        passwordExpirationProtectionEnabled = 'PasswordExpirationProtectionEnabled'
        adPasswordEncryptionEnabled        = 'ADPasswordEncryptionEnabled'
        postAuthenticationResetDelay       = 'PostAuthenticationResetDelay'
        postAuthenticationActions          = 'PostAuthenticationActions'
    }
    foreach ($param in $dwords.GetEnumerator()) {
        if ($null -ne $p.PSObject.Properties[$param.Key]) {
            $val = [int]$p.($param.Key)
            Set-ItemProperty -Path $regPath -Name $param.Value -Value $val -Type DWord
            $applied[$param.Value] = $val
        }
    }

    $strings = @{
        administratorAccountName    = 'AdministratorAccountName'
        adPasswordEncryptionPrincipal = 'ADPasswordEncryptionPrincipal'
    }
    foreach ($param in $strings.GetEnumerator()) {
        if ($null -ne $p.PSObject.Properties[$param.Key]) {
            $val = [string]$p.($param.Key)
            Set-ItemProperty -Path $regPath -Name $param.Value -Value $val -Type String
            $applied[$param.Value] = $val
        }
    }

    $data = [ordered]@{
        summary  = 'LAPS policy configured'
        applied  = $applied
        count    = $applied.Count
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message)
}
