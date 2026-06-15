#!/bin/bash

# Asterism service uninstallation script for macOS (launchd).
# Stops the launchd daemon, deletes the plist file, and removes the installed binary and logs.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

echo "=== macOS Uninstall Asterism Service ==="
echo "Choose what to uninstall:"
echo "1) Relay Mode (com.asterism.relay)"
echo "2) Agent Mode (com.asterism.agent)"
echo "3) Both"
read -p "Select option (1, 2 or 3, default: 3): " CHOICE
CHOICE=${CHOICE:-3}

LABELS=()
if [[ "${CHOICE}" == "1" ]]; then
    LABELS+=("com.asterism.relay")
elif [[ "${CHOICE}" == "2" ]]; then
    LABELS+=("com.asterism.agent")
elif [[ "${CHOICE}" == "3" ]]; then
    LABELS+=("com.asterism.relay" "com.asterism.agent")
else
    echo "Invalid selection. Exiting."
    exit 1
fi

# Also check for legacy com.asterism service
if launchctl list com.asterism &>/dev/null || [[ -f "/Library/LaunchDaemons/com.asterism.plist" ]]; then
    echo "Legacy com.asterism service detected. It will be cleaned up..."
    LABELS+=("com.asterism")
fi

for LABEL in "${LABELS[@]}"; do
    PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
    
    echo
    echo "--- Uninstalling ${LABEL} ---"
    
    if launchctl list "${LABEL}" &>/dev/null; then
        echo "Stopping and unloading launchd service..."
        launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    else
        echo "No active ${LABEL} found in launchctl"
    fi
    
    if [[ -f "${PLIST_DEST}" ]]; then
        echo "Removing plist file..."
        rm -f "${PLIST_DEST}"
    fi
    
    INSTALL_BIN="/usr/local/bin/asterism"
    LOG_DIR="/usr/local/var/log/${LABEL}"
    
    if [[ -d "${LOG_DIR}" ]]; then
        echo "Removing log directory ${LOG_DIR}..."
        rm -rf "${LOG_DIR}"
    fi

    # Only delete the binary if no asterism services are left registered in launchd plists
    if [[ ! -f "/Library/LaunchDaemons/com.asterism.relay.plist" && ! -f "/Library/LaunchDaemons/com.asterism.agent.plist" && ! -f "/Library/LaunchDaemons/com.asterism.plist" ]]; then
        if [[ -f "${INSTALL_BIN}" ]]; then
            echo "No other active asterism services detected. Removing executable ${INSTALL_BIN}..."
            rm -f "${INSTALL_BIN}"
        fi
    else
        echo "Other asterism services still installed. Keeping shared executable ${INSTALL_BIN}"
    fi
    
    echo "${LABEL} uninstalled successfully."
done

echo
echo "=== All uninstallation steps complete ==="
