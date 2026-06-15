# Requires -RunAsAdministrator

# Asterism Scheduled Task uninstallation script for Windows.
# Stops and deletes the scheduled task, and cleans up the installation directory.

$ErrorActionPreference = "Stop"

# Check Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as an Administrator."
    Exit
}

Write-Host "=== Asterism Windows Task Uninstaller ==="
Write-Host "Choose what to uninstall:"
Write-Host "1) Relay Mode (AsterismRelay)"
Write-Host "2) Agent Mode (AsterismAgent)"
Write-Host "3) Both"
$choice = Read-Host "Select option (1, 2 or 3, default: 3)"
if ($null -eq $choice -or $choice -eq "") { $choice = "3" }

$tasks_to_delete = @()
if ($choice -eq "1") {
    $tasks_to_delete += "AsterismRelay"
} elseif ($choice -eq "2") {
    $tasks_to_delete += "AsterismAgent"
} elseif ($choice -eq "3") {
    $tasks_to_delete += "AsterismRelay"
    $tasks_to_delete += "AsterismAgent"
} else {
    Write-Error "Invalid selection. Exiting."
    Exit
}

$INSTALL_DIR = "C:\Program Files\Asterism"

foreach ($name in $tasks_to_delete) {
    Write-Host "`nUninstalling $name..."
    Write-Host "  Stopping scheduled task..."
    schtasks.exe /End /TN $name 2>$null
    Write-Host "  Deleting scheduled task..."
    schtasks.exe /Delete /TN $name /F 2>$null
    Write-Host "  $name uninstalled successfully."
}

# Only delete the binary and installation directory if neither task remains registered
schtasks.exe /Query /TN "AsterismRelay" >$null 2>&1
$relayExists = ($LASTEXITCODE -eq 0)

schtasks.exe /Query /TN "AsterismAgent" >$null 2>&1
$agentExists = ($LASTEXITCODE -eq 0)

if (-not $relayExists -and -not $agentExists) {
    if (Test-Path $INSTALL_DIR) {
        Write-Host "`nRemoving installed files at $INSTALL_DIR..."
        Remove-Item $INSTALL_DIR -Recurse -Force
    }
} else {
    Write-Host "`nOther tasks still exist. Keeping installed files at $INSTALL_DIR."
}

Write-Host "`n=== Uninstallation Complete ==="
