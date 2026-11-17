#Requires -Version 5.1
<#
.SYNOPSIS
  Builds and tests the EasyPatch agent and, on Windows, produces the MSI installer(s).

.EXAMPLE
  pwsh scripts/build-agent.ps1 -Version 1.10.0
  pwsh scripts/build-agent.ps1 -Version 1.10.0 -Architecture x64,arm64 -RequireSigning -RequireReleaseKey

.NOTES
  The release public key (EASYPATCH_RELEASE_PUBLIC_KEY, default ~/.easypatch/easypatch-release-key.pub.pem) is built
  into the agent, and the MSIs are signed with the private key (EASYPATCH_RELEASE_KEY) for agent self-update. See
  agent/Installer/build-installer.ps1.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,5}$')][string]$Version = '1.10.0',
    [ValidateSet('x64', 'arm64')][string[]]$Architecture = @('x64'),
    [switch]$SkipTests,
    [switch]$SkipInstaller,
    [switch]$RequireSigning,
    [switch]$RequireReleaseKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repoRoot
try {
    $projects = @(
        'agent/EasyPatch.Communication/EasyPatch.Communication.csproj',
        'agent/EasyPatch.Agent.Core/EasyPatch.Agent.Core.csproj',
        'agent/EasyPatch.WindowsUpdate/EasyPatch.WindowsUpdate.csproj',
        'agent/EasyPatch.Inventory/EasyPatch.Inventory.csproj',
        'agent/EasyPatch.Agent/EasyPatch.Agent.csproj',
        'agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj'
    )

    $publicKey = if ($env:EASYPATCH_RELEASE_PUBLIC_KEY) { $env:EASYPATCH_RELEASE_PUBLIC_KEY } else { Join-Path (Join-Path $HOME '.easypatch') 'easypatch-release-key.pub.pem' }
    $keyArguments = @()
    if (Test-Path $publicKey) { $keyArguments = @("-p:EasyPatchReleasePublicKey=$((Resolve-Path $publicKey).Path)") }
    elseif ($RequireReleaseKey) { throw "No release public key at $publicKey." }
    else { Write-Warning "No release public key at ${publicKey}: this agent will not be able to update itself." }

    Write-Host "==> Building agent projects ($Version, warnings are errors)"
    foreach ($project in $projects) {
        dotnet build $project -c Release "-p:Version=$Version" @keyArguments
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
    }

    if (-not $SkipTests) {
        Write-Host '==> Running agent tests'
        dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj -c Release --no-build
        if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed.' }
    }

    $onWindows = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
    foreach ($arch in $Architecture) {
        if (-not $SkipInstaller -and $onWindows) {
            & (Join-Path $repoRoot 'agent/Installer/build-installer.ps1') -Version $Version -Architecture $arch -RequireSigning:$RequireSigning `
                -RequireReleaseKey:$RequireReleaseKey
        }
        else {
            $rid = "win-$arch"
            Write-Host "==> Publishing $rid (MSI requires Windows)"
            dotnet publish agent/EasyPatch.Agent/EasyPatch.Agent.csproj -c Release -r $rid -o "artifacts/agent/$rid" "-p:Version=$Version" @keyArguments
            if ($LASTEXITCODE -ne 0) { throw "Publish failed: $rid" }
        }
    }
}
finally {
    Pop-Location
}
