<#
.SYNOPSIS
  Removes the VPN Guard service and binary.
.PARAMETER Purge
  Also delete %ProgramData%\VPNGuard (configuration and logs).
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Purge)
$ErrorActionPreference = 'Stop'

$ServiceName = 'VPNGuard'
$InstallDir  = Join-Path $env:ProgramFiles 'VPNGuard'
$DataDir     = Join-Path $env:ProgramData 'VPNGuard'

Get-Process -Name 'vpn-guard-agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'VPNGuardAgent' -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\VPN Guard.lnk') -ErrorAction SilentlyContinue

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    }
    & sc.exe delete $ServiceName | Out-Null
}
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }

if ($Purge) {
    if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
    Write-Host 'vpn-guard removed (configuration and logs purged)'
} else {
    Write-Host "vpn-guard removed (kept $DataDir; use -Purge to delete)"
}
