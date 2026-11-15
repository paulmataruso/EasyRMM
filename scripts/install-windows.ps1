#Requires -RunAsAdministrator
<#
.SYNOPSIS
    EasyRMM Unified Agent Installer for Windows
.DESCRIPTION
    Downloads and installs all three agent components:
    1. MeshCentral Agent (remote desktop, terminal, file transfer)
    2. EasyRMM Agent (monitoring, scripting, telemetry)
    3. EasyPatch Agent (optional, Windows patch management)
.PARAMETER ServerURL
    The EasyRMM server URL (e.g., https://rmm.example.com)
.PARAMETER EnrollmentToken
    One-time enrollment token from the EasyRMM console
.PARAMETER MeshID
    MeshCentral mesh/device group ID for this device
.PARAMETER SkipEasyPatch
    Skip EasyPatch agent installation
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerURL,

    [Parameter(Mandatory=$true)]
    [string]$EnrollmentToken,

    [Parameter(Mandatory=$true)]
    [string]$MeshID,

    [switch]$SkipEasyPatch
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramFiles\EasyRMM"
$AgentBin = "$InstallDir\easyrmmagent.exe"
$ConfigFile = "$InstallDir\agent.json"
$ServiceName = "EasyRMMAgent"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  EasyRMM Unified Agent Installer"     -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Create install directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# ── Step 1: Install MeshCentral Agent ──────────────────────────
Write-Host "[1/3] Installing MeshCentral Agent..." -ForegroundColor Yellow

$MeshAgentURL = "$ServerURL/meshagents?id=3&meshid=$MeshID&installflags=2"
$MeshInstaller = "$env:TEMP\meshagent.exe"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $MeshAgentURL -OutFile $MeshInstaller -UseBasicParsing
    Start-Process -FilePath $MeshInstaller -ArgumentList "-install" -Wait -NoNewWindow
    Write-Host "  MeshCentral Agent installed." -ForegroundColor Green
} catch {
    Write-Host "  WARNING: MeshCentral Agent installation failed: $_" -ForegroundColor Red
    Write-Host "  Continuing with EasyRMM agent..." -ForegroundColor Yellow
} finally {
    if (Test-Path $MeshInstaller) { Remove-Item $MeshInstaller -Force }
}

# ── Step 2: Install EasyRMM Agent ─────────────────────────────
Write-Host "[2/3] Installing EasyRMM Agent..." -ForegroundColor Yellow

$AgentURL = "$ServerURL/downloads/easyrmmagent-windows-amd64.exe"

try {
    Invoke-WebRequest -Uri $AgentURL -OutFile $AgentBin -UseBasicParsing
} catch {
    Write-Host "  ERROR: Failed to download EasyRMM agent: $_" -ForegroundColor Red
    exit 1
}

# Enroll the agent
Write-Host "  Enrolling agent with server..." -ForegroundColor Gray
& $AgentBin --server $ServerURL --enroll $EnrollmentToken --config $ConfigFile

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Enrollment failed" -ForegroundColor Red
    exit 1
}

# Install as Windows service
Write-Host "  Installing Windows service..." -ForegroundColor Gray
$binPath = "`"$AgentBin`" --server $ServerURL --config `"$ConfigFile`""

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

New-Service -Name $ServiceName `
    -DisplayName "EasyRMM Agent" `
    -Description "EasyRMM Remote Monitoring and Management Agent" `
    -BinaryPathName $binPath `
    -StartupType Automatic | Out-Null

Start-Service -Name $ServiceName
Write-Host "  EasyRMM Agent installed and started." -ForegroundColor Green

# ── Step 3: Install EasyPatch Agent (optional) ─────────────────
if (!$SkipEasyPatch) {
    Write-Host "[3/3] Installing EasyPatch Agent..." -ForegroundColor Yellow

    $EasyPatchURL = "$ServerURL/downloads/easypatch-agent-windows.msi"
    $EasyPatchInstaller = "$env:TEMP\easypatch-agent.msi"

    try {
        Invoke-WebRequest -Uri $EasyPatchURL -OutFile $EasyPatchInstaller -UseBasicParsing
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$EasyPatchInstaller`" /qn SERVER_URL=$ServerURL" -Wait -NoNewWindow
        Write-Host "  EasyPatch Agent installed." -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: EasyPatch Agent installation failed: $_" -ForegroundColor Red
        Write-Host "  EasyPatch can be installed later from the console." -ForegroundColor Yellow
    } finally {
        if (Test-Path $EasyPatchInstaller) { Remove-Item $EasyPatchInstaller -Force }
    }
} else {
    Write-Host "[3/3] Skipping EasyPatch Agent (--SkipEasyPatch)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Installation Complete"               -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Server:  $ServerURL"
Write-Host "  Config:  $ConfigFile"
Write-Host "  Service: $ServiceName"
Write-Host ""
