# Requires -RunAsAdministrator

# Asterism Scheduled Task installation script for Windows.
# Copies the built binary to a system directory and registers a scheduled task
# to run as SYSTEM at startup.

$ErrorActionPreference = "Stop"

# Check Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as an Administrator."
    Exit
}

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT = Split-Path -Parent $SCRIPT_DIR
$DEFAULT_BIN_SOURCE = Join-Path $REPO_ROOT "build\src\asterism\Debug\asterism.exe"

# If Debug build is missing, try Release
if (-not (Test-Path $DEFAULT_BIN_SOURCE)) {
    $DEFAULT_BIN_SOURCE = Join-Path $REPO_ROOT "build\src\asterism\Release\asterism.exe"
}

# Allow passing bin path as argument
$BIN_SOURCE = $args[0]
if ($null -eq $BIN_SOURCE) {
    $BIN_SOURCE = $DEFAULT_BIN_SOURCE
}

Write-Host "=== Asterism Windows Task Installer ==="
Write-Host "Binary Source: $BIN_SOURCE"
Write-Host ""

if (-not (Test-Path $BIN_SOURCE)) {
    Write-Error "Executable not found at $BIN_SOURCE. Please build the project first."
    Exit
}

# Ask for mode
Write-Host "Choose installation mode:"
Write-Host "1) Server Mode (Relay server)"
Write-Host "2) Client Mode (Connector)"
$mode = Read-Host "Select mode (1 or 2, default: 1)"
if ($null -eq $mode -or $mode -eq "") { $mode = "1" }

$args_list = @()
$BASE_INSTALL_DIR = "C:\Program Files"

if ($mode -eq "1") {
    $SERVICE_NAME = "AsterismServer"
    $INSTALL_DIR = Join-Path $BASE_INSTALL_DIR "Asterism"
    $BIN_DEST = Join-Path $INSTALL_DIR "asterism.exe"

    Write-Host "`n=== Server Mode Configuration ==="
    $outer_port = Read-Host "Enter outer TCP port for client connections (default: 8010)"
    if ($null -eq $outer_port -or $outer_port -eq "") { $outer_port = "8010" }

    $http_port = Read-Host "Enter HTTP proxy listen port (default: 8011)"
    if ($null -eq $http_port -or $http_port -eq "") { $http_port = "8011" }

    $socks_port = Read-Host "Enter SOCKS5 proxy listen port (default: 8012)"
    if ($null -eq $socks_port -or $socks_port -eq "") { $socks_port = "8012" }

    $args_list += "-i"
    $args_list += "http://0.0.0.0:$http_port"
    $args_list += "-i"
    $args_list += "socks5://0.0.0.0:$socks_port"
    $args_list += "-o"
    $args_list += "tcp://0.0.0.0:$outer_port"

    $enable_auth = Read-Host "Enable HTTP basic authentication for sessions list (/sessions)? (y/N)"
    if ($enable_auth -match "^[Yy]$") {
        while ($true) {
            $auth_user = Read-Host "Enter HTTP sessions username"
            if (-not [string]::IsNullOrEmpty($auth_user)) { break }
            Write-Host "Error: Username cannot be empty." -ForegroundColor Red
        }
        while ($true) {
            $auth_pass = Read-Host "Enter HTTP sessions password"
            if (-not [string]::IsNullOrEmpty($auth_pass)) { break }
            Write-Host "Error: Password cannot be empty." -ForegroundColor Red
        }
        $args_list += "-A"
        $args_list += "-U"
        $args_list += $auth_user
        $args_list += "-P"
        $args_list += $auth_pass
    }
} elseif ($mode -eq "2") {
    $SERVICE_NAME = "AsterismClient"
    $INSTALL_DIR = Join-Path $BASE_INSTALL_DIR "Asterism"
    $BIN_DEST = Join-Path $INSTALL_DIR "asterism.exe"

    Write-Host "`n=== Client Mode Configuration ==="
    while ($true) {
        $remote_addr = Read-Host "Enter remote server address (e.g. tcp://1.2.3.4:1234)"
        if (-not [string]::IsNullOrEmpty($remote_addr)) { break }
        Write-Host "Error: Remote server address cannot be empty." -ForegroundColor Red
    }
    while ($true) {
        $username = Read-Host "Enter client username"
        if (-not [string]::IsNullOrEmpty($username)) { break }
        Write-Host "Error: Username cannot be empty." -ForegroundColor Red
    }
    while ($true) {
        $password = Read-Host "Enter client password"
        if (-not [string]::IsNullOrEmpty($password)) { break }
        Write-Host "Error: Password cannot be empty." -ForegroundColor Red
    }

    $args_list += "-r"
    $args_list += $remote_addr
    $args_list += "-u"
    $args_list += $username
    $args_list += "-p"
    $args_list += $password
} else {
    Write-Error "Invalid selection. Exiting."
    Exit
}

# Always enable verbose logging for service
$args_list += "-v"

# Create directories and copy binary
Write-Host "`n[1/3] Copying binary to install directory..."
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
}
Copy-Item $BIN_SOURCE $BIN_DEST -Force
Write-Host "Binary copied to $BIN_DEST"

# Register Scheduled Task
Write-Host "[2/3] Registering Windows Scheduled Task..."

# Delete if exists
schtasks.exe /Delete /TN $SERVICE_NAME /F 2>$null

# Build arguments string and properly escape the TR path for schtasks
$arguments_str = [string]::Join(" ", $args_list)
$tr_argument = '\"' + $BIN_DEST + '\" ' + $arguments_str

# Register using schtasks via Start-Process to avoid PowerShell argument splitting/escaping bugs
# /RU "SYSTEM" - runs as SYSTEM (no user login needed)
# /SC ONSTART - runs when system starts
# /NP - no password needed for SYSTEM
Start-Process -FilePath "schtasks.exe" -ArgumentList "/Create /TN $SERVICE_NAME /TR `"$tr_argument`" /SC ONSTART /RU SYSTEM /RL HIGHEST /NP /F" -NoNewWindow -Wait

Write-Host "Task successfully registered."

# Start the task
Write-Host "[3/3] Starting task..."
schtasks.exe /Run /TN $SERVICE_NAME

Write-Host "`n=== Installation Complete ==="
Write-Host "Task name: $SERVICE_NAME"
Write-Host "To view task status:"
Write-Host "  schtasks /Query /TN $SERVICE_NAME"
Write-Host "To stop the task:"
Write-Host "  schtasks /End /TN $SERVICE_NAME"
Write-Host "To start the task:"
Write-Host "  schtasks /Run /TN $SERVICE_NAME"
