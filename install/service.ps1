# Requires -RunAsAdministrator

# Asterism Unified Scheduled Task Manager for Windows.
# Handles installation and uninstallation of Relay, Agent, or Portal services (Scheduled Tasks).

param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action
)

$ErrorActionPreference = "Stop"

# Helper function to print colored logs
function Log-Info ($msg) {
    Write-Host "[INFO] $msg" -ForegroundColor Green
}

function Log-Error ($msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
}

# Check Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Error "Please run this script as an Administrator (Right-click PowerShell -> Run as Administrator)."
    Exit
}

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT = Split-Path -Parent $SCRIPT_DIR

# Determine default compiled binary path
$DEFAULT_BIN_SOURCE = Join-Path $REPO_ROOT "build\src\asterism\Debug\asterism.exe"
if (-not (Test-Path $DEFAULT_BIN_SOURCE)) {
    $DEFAULT_BIN_SOURCE = Join-Path $REPO_ROOT "build\src\asterism\Release\asterism.exe"
}
if (-not (Test-Path $DEFAULT_BIN_SOURCE)) {
    $DEFAULT_BIN_SOURCE = ""
}

# ==================== Action Chooser ====================
if ([string]::IsNullOrEmpty($Action)) {
    Write-Host "=== Asterism Unified Task Manager ==="
    Write-Host "Please choose action:"
    Write-Host "1) Install Service (Scheduled Task)"
    Write-Host "2) Uninstall Service (Scheduled Task)"
    $choice = Read-Host "Select option (1 or 2, default: 1)"
    if ($null -eq $choice -or $choice -eq "") { $choice = "1" }
    
    if ($choice -eq "1") {
        $Action = "Install"
    } elseif ($choice -eq "2") {
        $Action = "Uninstall"
    } else {
        Log-Error "Invalid selection. Exiting."
        Exit
    }
}

# ==========================================================
# INSTALLATION FLOW
# ==========================================================
if ($Action -eq "Install") {
    Write-Host "=== Asterism Windows Task Installer ==="

    # Locate binary source
    while ($true) {
        $bin_source = Read-Host "Enter path to compiled asterism.exe [default: $DEFAULT_BIN_SOURCE]"
        if ([string]::IsNullOrEmpty($bin_source)) {
            $bin_source = $DEFAULT_BIN_SOURCE
        }
        if ([string]::IsNullOrEmpty($bin_source)) {
            Log-Error "No default binary found. Please build the project or specify a valid path."
            continue
        }
        if (Test-Path $bin_source) {
            break
        }
        Log-Error "File not found at: $bin_source. Please specify a valid binary path."
    }

    Log-Info "Using binary: $bin_source"

    # Select Mode
    Write-Host "`nChoose mode to install:"
    Write-Host "1) Relay Mode  (Public Relay Bridge)"
    Write-Host "2) Agent Mode  (Intranet Client Agent)"
    Write-Host "3) Portal Mode (Local Port Forwarding)"
    $mode = Read-Host "Select mode (1, 2, or 3, default: 1)"
    if ($null -eq $mode -or $mode -eq "") { $mode = "1" }

    $args_list = @()
    $INSTALL_DIR = "C:\Program Files\Asterism"
    $BIN_DEST = Join-Path $INSTALL_DIR "asterism.exe"

    if ($mode -eq "1") {
        # RELAY MODE CONFIGURATION
        Write-Host "`n=== Configure Relay Mode ==="
        $taskName = Read-Host "Enter task name [default: AsterismRelay]"
        if ([string]::IsNullOrEmpty($taskName)) { $taskName = "AsterismRelay" }

        $outer_port = Read-Host "Enter outer TCP port for agent connections [default: 8010]"
        if ([string]::IsNullOrEmpty($outer_port)) { $outer_port = "8010" }

        $http_port = Read-Host "Enter HTTP proxy listen port [default: 8011]"
        if ([string]::IsNullOrEmpty($http_port)) { $http_port = "8011" }

        $socks_port = Read-Host "Enter SOCKS5 proxy listen port [default: 8012]"
        if ([string]::IsNullOrEmpty($socks_port)) { $socks_port = "8012" }

        $args_list += "-i"
        $args_list += "http://0.0.0.0:$http_port"
        $args_list += "-i"
        $args_list += "socks5://0.0.0.0:$socks_port"
        $args_list += "-o"
        $args_list += "tcp://0.0.0.0:$outer_port"

        $enable_auth = Read-Host "Enable HTTP Session List (/sessions) Basic Authentication? (y/N)"
        if ($enable_auth -match "^[Yy]$") {
            while ($true) {
                $auth_user = Read-Host "Enter basic auth username"
                if (-not [string]::IsNullOrEmpty($auth_user)) { break }
                Log-Error "Username cannot be empty."
            }
            while ($true) {
                $auth_pass = Read-Host "Enter basic auth password"
                if (-not [string]::IsNullOrEmpty($auth_pass)) { break }
                Log-Error "Password cannot be empty."
            }
            $args_list += "-A"
            $args_list += "-U"
            $args_list += $auth_user
            $args_list += "-P"
            $args_list += $auth_pass
        }

    } elseif ($mode -eq "2") {
        # AGENT MODE CONFIGURATION
        Write-Host "`n=== Configure Agent Mode ==="
        $taskName = Read-Host "Enter task name [default: AsterismAgent]"
        if ([string]::IsNullOrEmpty($taskName)) { $taskName = "AsterismAgent" }

        while ($true) {
            $remote_addr = Read-Host "Enter remote Relay address (e.g. tcp://1.2.3.4:8010)"
            if (-not [string]::IsNullOrEmpty($remote_addr)) { break }
            Log-Error "Relay address cannot be empty."
        }
        while ($true) {
            $agent_user = Read-Host "Enter Agent authentication username"
            if (-not [string]::IsNullOrEmpty($agent_user)) { break }
            Log-Error "Username cannot be empty."
        }
        while ($true) {
            $agent_pass = Read-Host "Enter Agent authentication password"
            if (-not [string]::IsNullOrEmpty($agent_pass)) { break }
            Log-Error "Password cannot be empty."
        }

        $args_list += "-r"
        $args_list += $remote_addr
        $args_list += "-u"
        $args_list += $agent_user
        $args_list += "-p"
        $args_list += $agent_pass

    } elseif ($mode -eq "3") {
        # PORTAL MODE CONFIGURATION
        Write-Host "`n=== Configure Portal Mode ==="
        $taskName = Read-Host "Enter task name [default: AsterismPortal]"
        if ([string]::IsNullOrEmpty($taskName)) { $taskName = "AsterismPortal" }

        while ($true) {
            $portal_rule = Read-Host "Enter Portal forwarding rule (local_addr:local_port#relay_addr#remote_addr:remote_port)"
            if (-not [string]::IsNullOrEmpty($portal_rule)) {
                if ($portal_rule -notmatch "#") {
                    Log-Error "Invalid format. Rule must contain '#' dividers."
                    continue
                }
                break
            }
            Log-Error "Forwarding rule cannot be empty."
        }

        $args_list += "-L"
        $args_list += $portal_rule

    } else {
        Log-Error "Invalid selection. Exiting."
        Exit
    }

    # Create directories and copy binary
    Log-Info "`n[1/3] Copying binary to installation directory..."
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
    }
    $needCopy = $true
    if (Test-Path $BIN_DEST) {
        $srcHash = (Get-FileHash $bin_source -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash $BIN_DEST -Algorithm SHA256).Hash
        if ($srcHash -eq $dstHash) {
            Log-Info "Binary already up-to-date at $BIN_DEST, skipping copy."
            $needCopy = $false
        }
    }
    if ($needCopy) {
        try {
            Copy-Item $bin_source $BIN_DEST -Force -ErrorAction Stop
            Log-Info "Binary copied to $BIN_DEST"
        } catch {
            Log-Error "Failed to copy binary: $_"
            Log-Error "The file may be locked by a running service. Please stop the running scheduled task first, then re-run this installer."
            Exit
        }
    }

    # Register Scheduled Task
    Log-Info "[2/3] Registering Windows Scheduled Task..."
    
    # Delete task if it already exists
    schtasks.exe /Delete /TN $taskName /F 2>$null

    # Build arguments string and escape quotes properly for schtasks
    $arguments_str = [string]::Join(" ", $args_list)
    $tr_argument = '\"' + $BIN_DEST + '\" ' + $arguments_str

    # Register via Start-Process to bypass powershell argument parsing bugs
    Start-Process -FilePath "schtasks.exe" -ArgumentList "/Create /TN $taskName /TR `"$tr_argument`" /SC ONSTART /RU SYSTEM /RL HIGHEST /NP /F" -NoNewWindow -Wait

    # Verify task creation
    schtasks.exe /Query /TN $taskName >$null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Log-Info "Task '$taskName' registered successfully."
    } else {
        Log-Error "Failed to register Scheduled Task '$taskName'."
        Exit
    }

    # Start the task
    Log-Info "[3/3] Starting task..."
    schtasks.exe /Run /TN $taskName

    Log-Info "`n=== Installation Complete ==="
    Write-Host "Task Name: $taskName"
    Write-Host "Management Commands:"
    Write-Host "  Check status:  schtasks /Query /TN $taskName"
    Write-Host "  Stop task:     schtasks /End /TN $taskName"
    Write-Host "  Start task:    schtasks /Run /TN $taskName"
}

# ==========================================================
# UNINSTALLATION FLOW
# ==========================================================
if ($Action -eq "Uninstall") {
    Write-Host "=== Asterism Windows Task Uninstaller ==="
    
    Write-Host "Select uninstallation option:"
    Write-Host "1) Uninstall Specific Task"
    Write-Host "2) Uninstall All Asterism Tasks"
    $choice = Read-Host "Select option (1 or 2, default: 1)"
    if ($null -eq $choice -or $choice -eq "") { $choice = "1" }

    $tasks_to_delete = @()

    if ($choice -eq "1") {
        $taskName = Read-Host "Enter task name to uninstall (e.g. AsterismRelay)"
        if (-not [string]::IsNullOrEmpty($taskName)) {
            $tasks_to_delete += $taskName
        } else {
            Log-Error "No task name entered. Exiting."
            Exit
        }
    } else {
        Log-Info "Searching for registered Asterism tasks..."
        # Query task scheduler for tasks matching Asterism
        $taskList = schtasks.exe /Query /FO CSV 2>$null | ConvertFrom-Csv
        foreach ($task in $taskList) {
            $tName = $task.TaskName
            if ($null -ne $tName -and ($tName -match "Asterism" -or $tName -eq "\AsterismRelay" -or $tName -eq "\AsterismAgent" -or $tName -eq "\AsterismPortal")) {
                $tasks_to_delete += $tName.TrimStart('\')
            }
        }

        # Fallback defaults if none queried
        if ($tasks_to_delete.Count -eq 0) {
            $tasks_to_delete += "AsterismRelay"
            $tasks_to_delete += "AsterismAgent"
            $tasks_to_delete += "AsterismPortal"
        }
    }

    $INSTALL_DIR = "C:\Program Files\Asterism"

    foreach ($name in $tasks_to_delete) {
        # Check if task actually exists
        schtasks.exe /Query /TN $name >$null 2>&1
        if ($LASTEXITCODE -eq 0) {
            Log-Info "`nUninstalling scheduled task: $name..."
            schtasks.exe /End /TN $name 2>$null | Out-Null
            schtasks.exe /Delete /TN $name /F 2>$null | Out-Null
            Log-Info "Task '$name' deleted successfully."
        }
    }

    # Delete installation directory only if no Asterism task remains registered
    $remainingTasks = 0
    $taskList = schtasks.exe /Query /FO CSV 2>$null | ConvertFrom-Csv
    foreach ($task in $taskList) {
        $tName = $task.TaskName
        if ($null -ne $tName -and ($tName -match "Asterism" -or $tName -eq "\AsterismRelay" -or $tName -eq "\AsterismAgent" -or $tName -eq "\AsterismPortal")) {
            $remainingTasks++
        }
    }

    if ($remainingTasks -eq 0) {
        if (Test-Path $INSTALL_DIR) {
            Log-Info "`nNo other active asterism tasks found. Removing installation folder at $INSTALL_DIR..."
            Remove-Item $INSTALL_DIR -Recurse -Force
        }
    } else {
        Log-Info "`nOther active scheduled tasks exist. Keeping shared files at $INSTALL_DIR."
    }

    Log-Info "`n=== Uninstallation Complete ==="
}
