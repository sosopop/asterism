#!/bin/bash

# Asterism Unified Service Manager for Linux (systemd) and macOS (launchd).
# Handles installation, update, and uninstallation of Relay, Agent, or Portal services.

set -euo pipefail

# Ensure running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: Please run this script as root (use sudo)." >&2
    exit 1
    fi

# Auto-detect OS type
OS_TYPE="$(uname -s)"
if [[ "${OS_TYPE}" != "Linux" && "${OS_TYPE}" != "Darwin" ]]; then
    echo "Error: Unsupported operating system: ${OS_TYPE}." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

# Find default compiled binary path
if [[ -f "${REPO_ROOT}/build/src/asterism/asterism" ]]; then
    DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
else
    DEFAULT_BIN_SOURCE=""
fi

# ==================== Utility Functions ====================
log_info() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

prompt_input() {
    local prompt_msg="$1"
    local default_val="$2"
    local var_name="$3"
    local user_input
    
    read -p "${prompt_msg} [default: ${default_val}]: " user_input
    user_input="${user_input:-${default_val}}"
    eval "${var_name}=\"${user_input}\""
}

validate_not_empty() {
    local val="$1"
    local error_msg="$2"
    if [[ -z "${val}" ]]; then
        log_error "${error_msg}"
        return 1
    fi
    return 0
}

# ==================== Action Chooser ====================
ACTION="${1:-}"
if [[ -z "${ACTION}" ]]; then
    echo "=== Asterism Unified Service Manager ==="
    echo "Please choose action:"
    echo "1) Install Service"
    echo "2) Uninstall Service"
    echo "3) Update Service (stop, replace binary, restart)"
    read -p "Select action (1, 2 or 3, default: 1): " CHOICE
    CHOICE=${CHOICE:-1}
    if [[ "${CHOICE}" == "1" ]]; then
        ACTION="install"
    elif [[ "${CHOICE}" == "2" ]]; then
        ACTION="uninstall"
    elif [[ "${CHOICE}" == "3" ]]; then
        ACTION="update"
    else
        log_error "Invalid selection. Exiting."
        exit 1
    fi
fi

if [[ "${ACTION}" != "install" && "${ACTION}" != "--install" && "${ACTION}" != "-i" && \
      "${ACTION}" != "uninstall" && "${ACTION}" != "--uninstall" && "${ACTION}" != "-u" && \
      "${ACTION}" != "update" && "${ACTION}" != "--update" ]]; then
    log_error "Invalid action: ${ACTION}."
    echo "Usage: sudo $0 [install|uninstall|update]"
    exit 1
fi

# ==========================================================
# INSTALLATION FLOW
# ==========================================================
if [[ "${ACTION}" =~ ^(install|--install|-i)$ ]]; then
    echo "=== Asterism Service Installer ==="
    
    # Locate binary source
    while true; do
        read -p "Enter path to compiled asterism binary [default: ${DEFAULT_BIN_SOURCE}]: " BIN_SOURCE
        BIN_SOURCE="${BIN_SOURCE:-${DEFAULT_BIN_SOURCE}}"
        
        if [[ -z "${BIN_SOURCE}" ]]; then
            log_error "No default binary found. Please build the project or specify a valid path."
            continue
        fi
        
        if [[ -f "${BIN_SOURCE}" ]]; then
            break
        fi
        log_error "File not found at: ${BIN_SOURCE}. Please specify a valid binary path."
    done
    
    log_info "Using binary: ${BIN_SOURCE}"
    
    # Select Mode
    echo
    echo "Choose mode to install:"
    echo "1) Relay Mode  (Public Relay Bridge)"
    echo "2) Agent Mode  (Intranet Client Agent)"
    echo "3) Portal Mode (Local Port Forwarding)"
    read -p "Select mode (1, 2, or 3, default: 1): " MODE
    MODE="${MODE:-1}"
    
    EXEC_ARGS=()
    
    if [[ "${MODE}" == "1" ]]; then
        # RELAY MODE CONFIGURATION
        echo
        echo "=== Configure Relay Mode ==="
        prompt_input "Enter service name" "asterism-relay" "SVC_NAME"
        prompt_input "Enter outer TCP port for agent connections" "8010" "OUTER_PORT"
        prompt_input "Enter HTTP proxy listen port" "8011" "HTTP_PORT"
        prompt_input "Enter SOCKS5 proxy listen port" "8012" "SOCKS5_PORT"
        
        EXEC_ARGS+=("-i" "http://0.0.0.0:${HTTP_PORT}" "-i" "socks5://0.0.0.0:${SOCKS5_PORT}" "-o" "tcp://0.0.0.0:${OUTER_PORT}")
        
        read -p "Enable HTTP Session List (/sessions) Basic Authentication? (y/N): " ENABLE_AUTH
        ENABLE_AUTH="${ENABLE_AUTH:-n}"
        if [[ "${ENABLE_AUTH}" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Enter basic auth username: " AUTH_USER
                if validate_not_empty "${AUTH_USER}" "Username cannot be empty."; then break; fi
            done
            while true; do
                read -p "Enter basic auth password: " AUTH_PASS
                if validate_not_empty "${AUTH_PASS}" "Password cannot be empty."; then break; fi
            done
            EXEC_ARGS+=("-A" "-U" "${AUTH_USER}" "-P" "${AUTH_PASS}")
        fi

        read -p "Enable SOCKS5 UDP support? (y/N): " ENABLE_UDP
        ENABLE_UDP="${ENABLE_UDP:-n}"
        if [[ "${ENABLE_UDP}" =~ ^[Yy]$ ]]; then
            EXEC_ARGS+=("-d")
            read -p "Enter UDP idle timeout in seconds (0 to disable, default: 60): " UDP_TIMEOUT
            UDP_TIMEOUT="${UDP_TIMEOUT:-60}"
            EXEC_ARGS+=("-t" "${UDP_TIMEOUT}")
        fi

    elif [[ "${MODE}" == "2" ]]; then
        # AGENT MODE CONFIGURATION
        echo
        echo "=== Configure Agent Mode ==="
        prompt_input "Enter service name" "asterism-agent" "SVC_NAME"
        while true; do
            read -p "Enter remote Relay address (e.g. tcp://1.2.3.4:8010): " REMOTE_ADDR
            if validate_not_empty "${REMOTE_ADDR}" "Relay address cannot be empty."; then break; fi
        done
        while true; do
            read -p "Enter Agent authentication username: " AGENT_USER
            if validate_not_empty "${AGENT_USER}" "Username cannot be empty."; then break; fi
        done
        while true; do
            read -p "Enter Agent authentication password: " AGENT_PASS
            if validate_not_empty "${AGENT_PASS}" "Password cannot be empty."; then break; fi
        done
        
        EXEC_ARGS+=("-r" "${REMOTE_ADDR}" "-u" "${AGENT_USER}" "-p" "${AGENT_PASS}")
        
    elif [[ "${MODE}" == "3" ]]; then
        # PORTAL MODE CONFIGURATION
        echo
        echo "=== Configure Portal Mode ==="
        prompt_input "Enter service name" "asterism-portal" "SVC_NAME"
        while true; do
            read -p "Enter Portal forwarding rule (local_addr:local_port#relay_addr#remote_addr:remote_port): " PORTAL_RULE
            if validate_not_empty "${PORTAL_RULE}" "Forwarding rule cannot be empty."; then
                if [[ "${PORTAL_RULE}" != *#* ]]; then
                    log_error "Invalid format. Rule must contain '#' dividers."
                    continue
                fi
                break
            fi
        done
        
        EXEC_ARGS+=("-L" "${PORTAL_RULE}")
        
    else
        log_error "Invalid selection. Exiting."
        exit 1
    fi
    

    
    # ------------------ PLATFORM DEPLOYMENT ------------------
    if [[ "${OS_TYPE}" == "Linux" ]]; then
        log_info "Configuring systemd service on Linux..."
        
        USER_NAME="asterism"
        GROUP_NAME="asterism"
        INSTALL_DIR="/opt/asterism"
        BIN_DEST="${INSTALL_DIR}/bin/asterism"
        LOG_DIR="${INSTALL_DIR}/logs/${SVC_NAME}"
        SERVICE_FILE="/etc/systemd/system/${SVC_NAME}.service"
        
        log_info "Creating service user and group..."
        if ! getent group "${GROUP_NAME}" > /dev/null; then
            groupadd --system "${GROUP_NAME}"
        fi
        if ! id "${USER_NAME}" > /dev/null 2>&1; then
            useradd --system --gid "${GROUP_NAME}" --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin \
                --comment "Asterism Tunnel Service" "${USER_NAME}"
        fi
        
        log_info "Creating directories..."
        mkdir -p "${INSTALL_DIR}/bin" "${LOG_DIR}"
        chmod 750 "${LOG_DIR}"
        
        log_info "Installing binary to ${BIN_DEST}..."
        install -m 755 "${BIN_SOURCE}" "${BIN_DEST}"
        chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}"
        
        log_info "Writing systemd unit file at ${SERVICE_FILE}..."
        cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=Asterism Reverse Proxy Service (${SVC_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
Group=${GROUP_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_DEST} ${EXEC_ARGS[@]}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SVC_NAME}
Environment=ASTERISM_LOG_DIR=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "${SERVICE_FILE}"
        
        log_info "Reloading systemd, enabling and starting service..."
        systemctl daemon-reload
        systemctl enable "${SVC_NAME}.service"
        systemctl restart "${SVC_NAME}.service"
        
        # Verify status
        sleep 1
        systemctl status "${SVC_NAME}.service" --no-pager -l || true
        
        log_info "=== Service Installed Successfully ==="
        echo "Management Commands:"
        echo "  Check status:  sudo systemctl status ${SVC_NAME}"
        echo "  Stop service:  sudo systemctl stop ${SVC_NAME}"
        echo "  Start service: sudo systemctl start ${SVC_NAME}"
        echo "  View logs:     sudo journalctl -u ${SVC_NAME} -f"
        
    elif [[ "${OS_TYPE}" == "Darwin" ]]; then
        log_info "Configuring launchd daemon on macOS..."
        
        # Format service name into reverse DNS label format if not already formatted
        if [[ "${SVC_NAME}" != com.asterism.* ]]; then
            SERVICE_LABEL="com.asterism.${SVC_NAME#asterism-}"
        else
            SERVICE_LABEL="${SVC_NAME}"
        fi
        
        INSTALL_BIN="/usr/local/bin/asterism"
        LOG_DIR="/usr/local/var/log/${SERVICE_LABEL}"
        PLIST_DEST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
        
        log_info "Creating log directory..."
        mkdir -p "${LOG_DIR}"
        
        log_info "Installing binary to ${INSTALL_BIN}..."
        cp "${BIN_SOURCE}" "${INSTALL_BIN}"
        chmod 755 "${INSTALL_BIN}"
        
        log_info "Writing launchd plist configuration at ${PLIST_DEST}..."
        if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
            launchctl unload "${PLIST_DEST}" 2>/dev/null || true
        fi
        
        cat <<EOF > "${PLIST_DEST}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_BIN}</string>
EOF
        for arg in "${EXEC_ARGS[@]}"; do
            echo "        <string>${arg}</string>" >> "${PLIST_DEST}"
        done
        
        cat <<EOF >> "${PLIST_DEST}"
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/asterism.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/asterism.err</string>
</dict>
</plist>
EOF
        chmod 644 "${PLIST_DEST}"
        
        log_info "Loading launchd daemon..."
        launchctl load -w "${PLIST_DEST}"
        
        # Verify status
        sleep 1
        if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
            log_info "Service is running normally"
        else
            log_error "Service failed to start. Check logs at ${LOG_DIR} for details."
        fi
        
        log_info "=== Service Installed Successfully ==="
        echo "Management Commands:"
        echo "  Check status:  sudo launchctl list ${SERVICE_LABEL}"
        echo "  Stop service:  sudo launchctl unload ${PLIST_DEST}"
        echo "  Start service: sudo launchctl load -w ${PLIST_DEST}"
        echo "  View logs:     tail -f ${LOG_DIR}/asterism.log"
    fi
fi

# ==========================================================
# UNINSTALLATION FLOW
# ==========================================================
if [[ "${ACTION}" =~ ^(uninstall|--uninstall|-u)$ ]]; then
    echo "=== Asterism Service Uninstaller ==="
    
    # Platform-specific uninstallation
    if [[ "${OS_TYPE}" == "Linux" ]]; then
        echo "Select uninstallation option:"
        echo "1) Uninstall Specific Service"
        echo "2) Uninstall All Asterism Services"
        read -p "Select option (1 or 2, default: 1): " CHOICE
        CHOICE="${CHOICE:-1}"
        
        SVC_LIST=()
        
        if [[ "${CHOICE}" == "1" ]]; then
            read -p "Enter service name to uninstall (e.g. asterism-relay): " SVC_NAME
            if [[ -n "${SVC_NAME}" ]]; then
                SVC_LIST+=("${SVC_NAME}")
            else
                log_error "No service name entered. Exiting."
                exit 1
            fi
        else
            # Find all service units starting with asterism
            log_info "Searching for registered asterism services..."
            while read -r svc_file; do
                svc_basename="$(basename "${svc_file}" .service)"
                SVC_LIST+=("${svc_basename}")
            done < <(find /etc/systemd/system/ -name "asterism*.service" 2>/dev/null || true)
            
            if [[ ${#SVC_LIST[@]} -eq 0 ]]; then
                log_info "No systemd unit files matching 'asterism*.service' found."
                SVC_LIST+=("asterism-relay" "asterism-agent")
            fi
        fi
        
        for SERVICE_NAME in "${SVC_LIST[@]}"; do
            SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
            log_info "Uninstalling systemd service: ${SERVICE_NAME}..."

            # Always stop the service first — systemctl stop works even
            # when the unit file is already gone (it finds the running
            # process by service name).  Ignore errors so a missing or
            # already-stopped service does not abort the script.
            log_info "Stopping and disabling service..."
            systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
            systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true

            if [[ -f "${SERVICE_FILE}" ]]; then
                rm -f "${SERVICE_FILE}"
                log_info "Service file removed: ${SERVICE_FILE}"
            fi

            # Clean up service logs
            LOG_DIR="/opt/asterism/logs/${SERVICE_NAME}"
            if [[ -d "${LOG_DIR}" ]]; then
                rm -rf "${LOG_DIR}"
            fi
        done
        
        systemctl daemon-reload
        
        # Perform global directory and user cleanup if no services remain
        REMAINING_SERVICES=$(find /etc/systemd/system/ -name "asterism*.service" 2>/dev/null | wc -l)
        if [[ "${REMAINING_SERVICES}" -eq 0 ]]; then
            log_info "No other active asterism services found. Removing global files and accounts..."
            
            INSTALL_DIR="/opt/asterism"
            if [[ -d "${INSTALL_DIR}" ]]; then
                rm -rf "${INSTALL_DIR}"
                log_info "Removed directory: ${INSTALL_DIR}"
            fi
            
            USER_NAME="asterism"
            GROUP_NAME="asterism"
            if id "${USER_NAME}" >/dev/null 2>&1; then
                userdel --remove "${USER_NAME}" 2>/dev/null || userdel "${USER_NAME}" || true
                log_info "Deleted user: ${USER_NAME}"
            fi
            if getent group "${GROUP_NAME}" >/dev/null; then
                groupdel "${GROUP_NAME}" 2>/dev/null || true
                log_info "Deleted group: ${GROUP_NAME}"
            fi
        else
            log_info "Other active asterism services are still registered. Keeping shared binary and directories."
        fi
        
        log_info "=== Uninstallation Complete ==="

    elif [[ "${OS_TYPE}" == "Darwin" ]]; then
        echo "Select uninstallation option:"
        echo "1) Uninstall Specific Service Label"
        echo "2) Uninstall All Asterism Services"
        read -p "Select option (1 or 2, default: 1): " CHOICE
        CHOICE="${CHOICE:-1}"
        
        LABELS_LIST=()
        
        if [[ "${CHOICE}" == "1" ]]; then
            read -p "Enter service label to uninstall (e.g. com.asterism.relay): " SVC_LABEL
            if [[ -n "${SVC_LABEL}" ]]; then
                if [[ "${SVC_LABEL}" != com.asterism.* ]]; then
                    SVC_LABEL="com.asterism.${SVC_LABEL#asterism-}"
                fi
                LABELS_LIST+=("${SVC_LABEL}")
            else
                log_error "No service label entered. Exiting."
                exit 1
            fi
        else
            log_info "Searching for registered launchd plist files..."
            while read -r plist_file; do
                plist_basename="$(basename "${plist_file}" .plist)"
                LABELS_LIST+=("${plist_basename}")
            done < <(find /Library/LaunchDaemons/ -name "com.asterism*.plist" 2>/dev/null || true)
            
            if [[ ${#LABELS_LIST[@]} -eq 0 ]]; then
                log_info "No plist files matching 'com.asterism*.plist' found."
                LABELS_LIST+=("com.asterism.relay" "com.asterism.agent")
            fi
        fi
        
        for LABEL in "${LABELS_LIST[@]}"; do
            PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
            log_info "Uninstalling launchd daemon: ${LABEL}..."
            
            if launchctl list "${LABEL}" &>/dev/null; then
                log_info "Stopping and unloading daemon..."
                launchctl unload "${PLIST_DEST}" 2>/dev/null || true
            fi
            
            if [[ -f "${PLIST_DEST}" ]]; then
                rm -f "${PLIST_DEST}"
                log_info "Plist file removed: ${PLIST_DEST}"
            fi
            
            LOG_DIR="/usr/local/var/log/${LABEL}"
            if [[ -d "${LOG_DIR}" ]]; then
                rm -rf "${LOG_DIR}"
            fi
        done
        
        # Clean up binary if no plist configuration remains
        REMAINING_PLISTS=$(find /Library/LaunchDaemons/ -name "com.asterism*.plist" 2>/dev/null | wc -l)
        if [[ "${REMAINING_PLISTS}" -eq 0 ]]; then
            INSTALL_BIN="/usr/local/bin/asterism"
            if [[ -f "${INSTALL_BIN}" ]]; then
                rm -f "${INSTALL_BIN}"
                log_info "Removed shared executable: ${INSTALL_BIN}"
            fi
        else
            log_info "Other active launchd daemons are still registered. Keeping shared executable."
        fi
        
        log_info "=== Uninstallation Complete ==="
    fi
fi

# ==========================================================
# UPDATE FLOW
# Stop the installed service(s), replace the shared compiled
# binary with a freshly built one, then start them again.
# Existing service configuration (mode/args) is preserved.
# ==========================================================
if [[ "${ACTION}" =~ ^(update|--update)$ ]]; then
    echo "=== Asterism Service Updater ==="

    # Locate the new compiled binary (same discovery as install)
    while true; do
        read -p "Enter path to the newly compiled asterism binary [default: ${DEFAULT_BIN_SOURCE}]: " BIN_SOURCE
        BIN_SOURCE="${BIN_SOURCE:-${DEFAULT_BIN_SOURCE}}"
        if [[ -z "${BIN_SOURCE}" ]]; then
            log_error "No default binary found. Please build the project or specify a valid path."
            continue
        fi
        if [[ -f "${BIN_SOURCE}" ]]; then
            break
        fi
        log_error "File not found at: ${BIN_SOURCE}. Please specify a valid binary path."
    done
    log_info "Using new binary: ${BIN_SOURCE}"

    if [[ "${OS_TYPE}" == "Linux" ]]; then
        USER_NAME="asterism"
        GROUP_NAME="asterism"
        INSTALL_DIR="/opt/asterism"
        BIN_DEST="${INSTALL_DIR}/bin/asterism"

        if [[ ! -f "${BIN_DEST}" ]]; then
            log_error "Asterism does not appear to be installed (${BIN_DEST} not found)."
            log_error "Run the installer first."
            exit 1
        fi

        # Discover installed asterism services (the binary is shared by all)
        SVC_LIST=()
        while read -r svc_file; do
            [[ -z "${svc_file}" ]] && continue
            SVC_LIST+=("$(basename "${svc_file}" .service)")
        done < <(find /etc/systemd/system/ -name "asterism*.service" 2>/dev/null || true)

        if [[ ${#SVC_LIST[@]} -eq 0 ]]; then
            log_error "No installed asterism services found under /etc/systemd/system/."
            exit 1
        fi

        log_info "Services to update: ${SVC_LIST[*]}"

        log_info "Stopping services..."
        for SERVICE_NAME in "${SVC_LIST[@]}"; do
            systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        done

        log_info "Replacing binary at ${BIN_DEST}..."
        install -m 755 "${BIN_SOURCE}" "${BIN_DEST}"
        chown "${USER_NAME}:${GROUP_NAME}" "${BIN_DEST}"

        log_info "Starting services..."
        for SERVICE_NAME in "${SVC_LIST[@]}"; do
            systemctl start "${SERVICE_NAME}.service"
        done

        sleep 1
        for SERVICE_NAME in "${SVC_LIST[@]}"; do
            log_info "Status of ${SERVICE_NAME}:"
            systemctl is-active "${SERVICE_NAME}.service" || true
        done

        log_info "=== Update Complete ==="

    elif [[ "${OS_TYPE}" == "Darwin" ]]; then
        INSTALL_BIN="/usr/local/bin/asterism"

        if [[ ! -f "${INSTALL_BIN}" ]]; then
            log_error "Asterism does not appear to be installed (${INSTALL_BIN} not found)."
            log_error "Run the installer first."
            exit 1
        fi

        # Discover installed launchd daemons (the binary is shared by all)
        LABELS_LIST=()
        while read -r plist_file; do
            [[ -z "${plist_file}" ]] && continue
            LABELS_LIST+=("$(basename "${plist_file}" .plist)")
        done < <(find /Library/LaunchDaemons/ -name "com.asterism*.plist" 2>/dev/null || true)

        if [[ ${#LABELS_LIST[@]} -eq 0 ]]; then
            log_error "No installed asterism daemons found under /Library/LaunchDaemons/."
            exit 1
        fi

        log_info "Daemons to update: ${LABELS_LIST[*]}"

        log_info "Unloading daemons..."
        for LABEL in "${LABELS_LIST[@]}"; do
            launchctl unload "/Library/LaunchDaemons/${LABEL}.plist" 2>/dev/null || true
        done

        log_info "Replacing binary at ${INSTALL_BIN}..."
        cp "${BIN_SOURCE}" "${INSTALL_BIN}"
        chmod 755 "${INSTALL_BIN}"

        log_info "Loading daemons..."
        for LABEL in "${LABELS_LIST[@]}"; do
            launchctl load -w "/Library/LaunchDaemons/${LABEL}.plist"
        done

        sleep 1
        for LABEL in "${LABELS_LIST[@]}"; do
            if launchctl list "${LABEL}" &>/dev/null; then
                log_info "${LABEL} is running."
            else
                log_error "${LABEL} failed to start. Check its logs."
            fi
        done

        log_info "=== Update Complete ==="
    fi
fi
