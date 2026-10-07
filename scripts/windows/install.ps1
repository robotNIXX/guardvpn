<#
.SYNOPSIS
  Installs VPN Guard as a Windows service (Windows 11).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1 -Config .\config.json

.PARAMETER Binary
  Path to vpn-guard.exe (default: next to this script, or bin\windows-amd64).
.PARAMETER Config
  Config to install when none exists yet (default: config.json, else config.example.json).
.PARAMETER ForceConfig
  Overwrite an existing %ProgramData%\VPNGuard\config.json.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$Config = "",
    [switch]$ForceConfig
)
$ErrorActionPreference = 'Stop'

$ServiceName = 'VPNGuard'
$InstallDir  = Join-Path $env:ProgramFiles 'VPNGuard'
$DataDir     = Join-Path $env:ProgramData 'VPNGuard'
$LogDir      = Join-Path $DataDir 'logs'
$ExePath     = Join-Path $InstallDir 'vpn-guard.exe'
$CfgPath     = Join-Path $DataDir 'config.json'
$Root        = Resolve-Path (Join-Path $PSScriptRoot '..\..') -ErrorAction SilentlyContinue

# Well-known SIDs (locale independent)
$SYSTEM = '*S-1-5-18'
$ADMINS = '*S-1-5-32-544'
$USERS  = '*S-1-5-32-545'

function First-Existing([string[]]$paths) {
    foreach ($p in $paths) { if ($p -and (Test-Path $p -PathType Leaf)) { return (Resolve-Path $p).Path } }
    return $null
}

# 1. OS
if ($env:OS -ne 'Windows_NT') { throw 'This installer is for Windows.' }
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt 22000) { throw "Windows 11 is required (build $build found)." }
# 2. admin rights are enforced by #Requires -RunAsAdministrator

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
if (-not $Binary) {
    $Binary = First-Existing @((Join-Path $PSScriptRoot 'vpn-guard.exe'), "$Root\bin\windows-$arch\vpn-guard.exe")
    if (-not $Binary) { throw 'vpn-guard.exe not found; pass -Binary.' }
}
if (-not $Config) {
    $Config = First-Existing @((Join-Path $PSScriptRoot 'config.json'), "$Root\config.json",
                               (Join-Path $PSScriptRoot 'config.example.json'), "$Root\config.example.json")
}

# Stop a running instance before replacing the binary.
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
}

# 3. binary
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path $Binary -Destination $ExePath -Force
Unblock-File -Path $ExePath -ErrorAction SilentlyContinue

# 4. data directory, 5. config
New-Item -ItemType Directory -Force -Path $DataDir, $LogDir | Out-Null
if (-not (Test-Path $CfgPath) -or $ForceConfig) {
    if (-not $Config) { throw 'No config to install; pass -Config.' }
    Copy-Item -Path $Config -Destination $CfgPath -Force
    Write-Host "installed config: $CfgPath"
} else {
    Write-Host "keeping existing config: $CfgPath"
}

# 7. permissions: binary is read/execute for users; config (holds the GeoIP
# token) is SYSTEM/Administrators only; logs are readable by users.
& icacls $InstallDir /inheritance:r /grant:r "${SYSTEM}:(OI)(CI)F" "${ADMINS}:(OI)(CI)F" "${USERS}:(OI)(CI)RX" | Out-Null
& icacls $DataDir    /inheritance:r /grant:r "${SYSTEM}:(OI)(CI)F" "${ADMINS}:(OI)(CI)F" | Out-Null
& icacls $LogDir     /grant "${USERS}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }

& $ExePath validate -config $CfgPath
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Configuration is invalid; the service will run fail-closed (application blocked) until it is fixed.'
}

# 6/8. register the service: automatic start at boot, runs as LocalSystem.
$binPath = "`"$ExePath`" run -config `"$CfgPath`""
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'VPN Guard' `
        -Description 'Terminates the controlled application unless the external IP belongs to an allowed country.' `
        -StartupType Automatic | Out-Null
} else {
    & sc.exe config $ServiceName binPath= $binPath start= auto | Out-Null
}
# Restart after a crash (and after a non-zero exit) - 1 s, 1 s, then 5 s.
& sc.exe failure $ServiceName reset= 86400 actions= restart/1000/restart/1000/restart/5000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc.exe failed to configure recovery actions' }

# 9. start
Start-Service -Name $ServiceName

# 10. verify
$svc = Get-Service -Name $ServiceName
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
Write-Host 'vpn-guard is running'
Start-Sleep -Seconds 2
& $ExePath status
