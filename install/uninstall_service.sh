#!/bin/bash

# Asterism service uninstallation script.
# Stops the systemd unit, unregisters it, and removes the dedicated account.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

echo "=== Uninstall Asterism Service ==="
echo "Choose what to uninstall:"
echo "1) Relay Mode (asterism-relay)"
echo "2) Agent Mode (asterism-agent)"
echo "3) Both"
read -p "Select option (1, 2 or 3, default: 3): " CHOICE
CHOICE=${CHOICE:-3}

SERVICES=()
if [[ "${CHOICE}" == "1" ]]; then
    SERVICES+=("asterism-relay")
elif [[ "${CHOICE}" == "2" ]]; then
    SERVICES+=("asterism-agent")
elif [[ "${CHOICE}" == "3" ]]; then
    SERVICES+=("asterism-relay" "asterism-agent")
else
    echo "Invalid selection. Exiting."
    exit 1
fi

# Also check for legacy asterism service
if systemctl list-unit-files | grep -q "^asterism.service"; then
    echo "Legacy asterism.service detected. It will be cleaned up..."
    SERVICES+=("asterism")
fi

for SVC in "${SERVICES[@]}"; do
    SERVICE_NAME="${SVC}"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    echo
    echo "--- Uninstalling service ${SERVICE_NAME} ---"

    if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
        echo "Stopping and disabling service..."
        systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
    else
        echo "${SERVICE_NAME}.service not found in systemd"
    fi

    if [[ -f "${SERVICE_FILE}" ]]; then
        echo "Removing systemd service file..."
        rm -f "${SERVICE_FILE}"
        echo "Service file removed"
    else
        echo "${SERVICE_FILE} not found"
    fi

    echo "Reloading systemd configuration..."
    systemctl daemon-reload
    systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
done

# Check if any asterism service still remains registered in systemd
REMAINS_SERVICES=0
for check_svc in "asterism-relay" "asterism-agent" "asterism"; do
    if systemctl list-unit-files | grep -q "^${check_svc}.service"; then
        REMAINS_SERVICES=1
        break
    fi
done

INSTALL_DIR="/opt/asterism"
USER_NAME="asterism"
GROUP_NAME="asterism"

if [[ "${REMAINS_SERVICES}" -eq 0 ]]; then
    echo
    echo "--- No other active asterism services detected. Cleaning up shared files and account ---"
    
    if [[ -d "${INSTALL_DIR}" ]]; then
        echo "Removing install directory ${INSTALL_DIR}..."
        rm -rf "${INSTALL_DIR}"
        echo "Install directory removed"
    else
        echo "Install directory ${INSTALL_DIR} not found"
    fi

    echo "Cleaning up system user and group..."
    if id "${USER_NAME}" > /dev/null 2>&1; then
        userdel --remove "${USER_NAME}" 2>/dev/null || userdel "${USER_NAME}" || true
        echo "User ${USER_NAME} deleted"
    else
        echo "User ${USER_NAME} does not exist"
    fi

    if getent group "${GROUP_NAME}" > /dev/null; then
        groupdel "${GROUP_NAME}" 2>/dev/null || true
        echo "Group ${GROUP_NAME} deleted"
    else
        echo "Group ${GROUP_NAME} does not exist"
    fi
else
    echo
    echo "--- Other asterism services still installed. Keeping shared files at ${INSTALL_DIR} and account ${USER_NAME} ---"
fi

echo
echo "=== Uninstallation Complete ==="
