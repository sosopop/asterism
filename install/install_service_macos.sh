#!/bin/bash

# Asterism service installation script for macOS (launchd).
# Copies the built binary and registers a launchd daemon so the
# proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism macOS Service Installer ==="
echo "Binary source: ${BIN_SOURCE}"
echo

if [[ ! -f "${BIN_SOURCE}" ]]; then
    cat <<EOF
Error: Executable not found at ${BIN_SOURCE}
Please build the project first, for example:
  cmake -S ${REPO_ROOT} -B ${REPO_ROOT}/build
  cmake --build ${REPO_ROOT}/build
Or pass the path to the compiled asterism binary as the first argument to this script.
EOF
    exit 1
fi

# ==================== Configuration ====================
echo "Choose installation mode:"
echo "1) Relay Mode"
echo "2) Agent Mode"
read -p "Select mode (1 or 2, default: 1): " MODE
MODE=${MODE:-1}

if [[ "${MODE}" == "1" ]]; then
    SERVICE_LABEL="com.asterism.relay"

    echo
    echo "=== Relay Mode Configuration ==="
    read -p "Enter outer TCP port for agent connections (default: 8010): " OUTER_PORT
    OUTER_PORT=${OUTER_PORT:-8010}

    read -p "Enter HTTP proxy listen port (default: 8011): " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-8011}

    read -p "Enter SOCKS5 proxy listen port (default: 8012): " SOCKS5_PORT
    SOCKS5_PORT=${SOCKS5_PORT:-8012}

    echo
    echo "=== Configure HTTP Sessions Authentication ==="
    read -p "Enable HTTP Sessions username/password authentication? (y/N): " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-n}

    EXEC_ARGS=("-i" "http://0.0.0.0:${HTTP_PORT}" "-i" "socks5://0.0.0.0:${SOCKS5_PORT}" "-o" "tcp://0.0.0.0:${OUTER_PORT}")

    if [[ "${ENABLE_AUTH}" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter HTTP Sessions authentication username: " AUTH_USER
            if [[ -n "${AUTH_USER}" ]]; then
                break
            fi
            echo "Error: Username cannot be empty. Please try again."
        done

        while true; do
            read -p "Enter HTTP Sessions authentication password: " AUTH_PASS
            if [[ -n "${AUTH_PASS}" ]]; then
                break
            fi
            echo "Error: Password cannot be empty. Please try again."
        done

        EXEC_ARGS+=("-A" "-U" "${AUTH_USER}" "-P" "${AUTH_PASS}")
    fi

elif [[ "${MODE}" == "2" ]]; then
    SERVICE_LABEL="com.asterism.agent"

    echo
    echo "=== Agent Mode Configuration ==="
    while true; do
        read -p "Enter remote relay address (e.g. tcp://1.2.3.4:8010): " REMOTE_ADDR
        if [[ -n "${REMOTE_ADDR}" ]]; then
            break
        fi
        echo "Error: Remote address cannot be empty. Please try again."
    done

    while true; do
        read -p "Enter agent authentication username: " CLIENT_USER
        if [[ -n "${CLIENT_USER}" ]]; then
            break
        fi
        echo "Error: Username cannot be empty. Please try again."
    done

    while true; do
        read -p "Enter agent authentication password: " CLIENT_PASS
        if [[ -n "${CLIENT_PASS}" ]]; then
            break
        fi
        echo "Error: Password cannot be empty. Please try again."
    done

    EXEC_ARGS=("-r" "${REMOTE_ADDR}" "-u" "${CLIENT_USER}" "-p" "${CLIENT_PASS}")

else
    echo "Invalid selection. Exiting."
    exit 1
fi

EXEC_ARGS+=("-v")

INSTALL_BIN="/usr/local/bin/asterism"
LOG_DIR="/usr/local/var/log/${SERVICE_LABEL}"
PLIST_DEST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"

echo "Install location: ${INSTALL_BIN}"
echo "Log directory:    ${LOG_DIR}"
echo "Service label:    ${SERVICE_LABEL}"
echo
# ==================================================

echo "[1/4] Creating log directory..."
mkdir -p "${LOG_DIR}"
echo "Log directory ready"

echo "[2/4] Installing executable..."
cp "${BIN_SOURCE}" "${INSTALL_BIN}"
chmod 755 "${INSTALL_BIN}"
echo "Executable installed to ${INSTALL_BIN}"

echo "[3/4] Deploying launchd plist..."
if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
    echo "Existing service detected, unloading first..."
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
fi

# Dynamically construct the plist
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
echo "plist deployed to ${PLIST_DEST}"

echo "[4/4] Loading and starting service..."
launchctl load -w "${PLIST_DEST}"
echo "Service loaded"

# Check status
sleep 1
if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
    echo "Service is running normally"
else
    echo "Warning: Service may not have started correctly. Please check logs."
fi

cat <<EOF

=== Installation Complete ===
Common commands:
  Check status: sudo launchctl list ${SERVICE_LABEL}
  Stop service: sudo launchctl unload ${PLIST_DEST}
  Start service: sudo launchctl load -w ${PLIST_DEST}
  View logs: tail -f ${LOG_DIR}/asterism.log
  View errors: tail -f ${LOG_DIR}/asterism.err
EOF
