Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$version = 1
#@library common
try {
    Assert-Smb
    $out = @()
    foreach ($s in @(Get-SmbShare | Select-Object -First 500)) {
        $name = [string]$s.Name
        $out += [ordered]@{
            name = $name
            path = [string](Get-Prop $s 'Path')
            description = [string](Get-Prop $s 'Description')
            special = [bool](Get-Prop $s 'Special')
            protected = (Test-ProtectedShare $name)
            scoped = ([string](Get-Prop $s 'ScopeName') -ne '*' -and [string](Get-Prop $s 'ScopeName') -ne '')
            continuouslyAvailable = [bool](Get-Prop $s 'ContinuouslyAvailable')
            encrypted = [bool](Get-Prop $s 'EncryptData')
            caching = [string](Get-Prop $s 'CachingMode')
            folderEnumeration = [string](Get-Prop $s 'FolderEnumerationMode')
            concurrentUserLimit = [int64](Get-Number (Get-Prop $s 'ConcurrentUserLimit'))
        }
    }
    Write-Result $true ([ordered]@{ shares = @($out); truncated = (@(Get-SmbShare).Count -gt 500) }) $null $null
} catch {
    Write-Result $false $null 'command_failed' ('Listing the shares failed: ' + $_.Exception.GetType().Name)
}
