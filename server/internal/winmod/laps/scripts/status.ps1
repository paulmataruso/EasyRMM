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
    # Windows LAPS (the built-in version in Windows Server 2019+ and Windows 10 21H2+).
    $windowsLaps = $false
    $legacyLaps = $false
    $lapsPolicy = $null

    # Check for Windows LAPS (built-in, available via Get-LapsAADPassword / Get-LapsDiagnostics)
    try {
        $lapsCSE = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue
        if ($null -ne $lapsCSE) {
            $windowsLaps = $true
            $lapsPolicy = [ordered]@{}
            foreach ($prop in $lapsCSE.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS') {
                    $lapsPolicy[$prop.Name] = $prop.Value
                }
            }
        }
    } catch {}

    # Check for Windows LAPS via the new registry path
    if (-not $windowsLaps) {
        try {
            $lapsCSE2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue
            if ($null -ne $lapsCSE2) {
                $windowsLaps = $true
                $lapsPolicy = [ordered]@{}
                foreach ($prop in $lapsCSE2.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') {
                        $lapsPolicy[$prop.Name] = $prop.Value
                    }
                }
            }
        } catch {}
    }

    # Check for legacy Microsoft LAPS (the separate download)
    try {
        $legacyDll = Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
        if ($legacyDll) { $legacyLaps = $true }
    } catch {}

    # Check if the local admin account exists and its password age
    $adminAccount = $null
    try {
        $admin = Get-LocalUser -SID 'S-1-5-21-*-500' -ErrorAction SilentlyContinue
        if ($null -eq $admin) {
            $admin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
        }
        if ($null -ne $admin) {
            $adminAccount = [ordered]@{
                name           = [string]$admin.Name
                enabled        = [bool]$admin.Enabled
                lastLogon      = $null
                passwordLastSet = $null
                passwordExpires = $null
            }
            if ($null -ne $admin.LastLogon) {
                $adminAccount.lastLogon = $admin.LastLogon.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            if ($null -ne $admin.PasswordLastSet) {
                $adminAccount.passwordLastSet = $admin.PasswordLastSet.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            if ($null -ne $admin.PasswordExpires) {
                $adminAccount.passwordExpires = $admin.PasswordExpires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
        }
    } catch {}

    # Read the LAPS password expiration from AD if domain-joined
    $adPasswordExpiry = $null
    $domainJoined = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property PartOfDomain -ErrorAction SilentlyContinue
        if ($null -ne $cs -and $cs.PartOfDomain) {
            $domainJoined = $true
            # Windows LAPS stores expiry in msLAPS-PasswordExpirationTime
            # Legacy LAPS stores it in ms-Mcs-AdmPwdExpirationTime
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)$))"
                [void]$searcher.PropertiesToLoad.Add('msLAPS-PasswordExpirationTime')
                [void]$searcher.PropertiesToLoad.Add('ms-Mcs-AdmPwdExpirationTime')
                $result = $searcher.FindOne()
                if ($null -ne $result) {
                    $newExpiry = $result.Properties['mslaps-passwordexpirationtime']
                    $oldExpiry = $result.Properties['ms-mcs-admpwdexpirationtime']
                    if ($null -ne $newExpiry -and $newExpiry.Count -gt 0) {
                        $ft = [long]$newExpiry[0]
                        $adPasswordExpiry = [datetime]::FromFileTimeUtc($ft).ToString('yyyy-MM-ddTHH:mm:ssZ')
                    } elseif ($null -ne $oldExpiry -and $oldExpiry.Count -gt 0) {
                        $ft = [long]$oldExpiry[0]
                        $adPasswordExpiry = [datetime]::FromFileTimeUtc($ft).ToString('yyyy-MM-ddTHH:mm:ssZ')
                    }
                }
            } catch {}
        }
    } catch {}

    $data = [ordered]@{
        windowsLaps       = $windowsLaps
        legacyLaps        = $legacyLaps
        domainJoined      = $domainJoined
        policy            = $lapsPolicy
        adminAccount      = $adminAccount
        adPasswordExpiry  = $adPasswordExpiry
    }
    Write-Result $true $data $null $null
} catch {
    Stop-With 'command_failed' ('The action failed: ' + $_.Exception.GetType().Name)
}
