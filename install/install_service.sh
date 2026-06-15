#!/bin/bash

# Asterism service installation script for Ubuntu systemd environments.
# Copies the built binary, sets up a restricted service account, and registers
# the systemd unit so the reverse proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism Service Installer ==="
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
    SERVICE_NAME="asterism-relay"
    USER_NAME="asterism"
    GROUP_NAME="asterism"
    INSTALL_DIR="/opt/asterism"
    BIN_DIR="${INSTALL_DIR}/bin"
    LOG_DIR="${INSTALL_DIR}/logs"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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

    EXEC_ARGS="-i http://0.0.0.0:${HTTP_PORT} -i socks5://0.0.0.0:${SOCKS5_PORT} -o tcp://0.0.0.0:${OUTER_PORT}"

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

        EXEC_ARGS="${EXEC_ARGS} -A -U ${AUTH_USER} -P ${AUTH_PASS}"
    fi

elif [[ "${MODE}" == "2" ]]; then
    SERVICE_NAME="asterism-agent"
    USER_NAME="asterism"
    GROUP_NAME="asterism"
    INSTALL_DIR="/opt/asterism"
    BIN_DIR="${INSTALL_DIR}/bin"
    LOG_DIR="${INSTALL_DIR}/logs"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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

    EXEC_ARGS="-r ${REMOTE_ADDR} -u ${CLIENT_USER} -p ${CLIENT_PASS}"

else
    echo "Invalid selection. Exiting."
    exit 1
fi

EXEC_ARGS="${EXEC_ARGS} -v"

echo
echo "Install directory: ${INSTALL_DIR}"
echo "Service name: ${SERVICE_NAME}"
echo
# ==================================================

echo "[1/6] Creating user and group..."
if ! getent group "${GROUP_NAME}" > /dev/null; then
    groupadd --system "${GROUP_NAME}"
    echo "Group ${GROUP_NAME} created"
else
    echo "Group ${GROUP_NAME} already exists"
fi

if ! id "${USER_NAME}" > /dev/null 2>&1; then
    useradd --system --gid "${GROUP_NAME}" --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin \
        --comment "Asterism Reverse Proxy Service" "${USER_NAME}"
    echo "User ${USER_NAME} created"
else
    echo "User ${USER_NAME} already exists"
fi

echo "[2/6] Creating install directories..."
mkdir -p "${BIN_DIR}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
echo "Directories created"

echo "[3/6] Installing executable..."
install -m 755 "${BIN_SOURCE}" "${BIN_DIR}/asterism"
chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}"
echo "Executable installed"

echo "[4/6] Deploying systemd service file..."
cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=Asterism Reverse Proxy Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
Group=${GROUP_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_DIR}/asterism ${EXEC_ARGS}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
Environment=ASTERISM_LOG_DIR=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "${SERVICE_FILE}"
echo "Service file deployed"

echo "[5/6] Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
echo "Service enabled"

echo "[6/6] Starting service..."
systemctl restart "${SERVICE_NAME}.service"
systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

cat <<EOF

=== Installation Complete ===
Common commands:
  Check status: sudo systemctl status ${SERVICE_NAME}
  Start service: sudo systemctl start ${SERVICE_NAME}
  Stop service: sudo systemctl stop ${SERVICE_NAME}
  Restart service: sudo systemctl restart ${SERVICE_NAME}
Logs are written to journal by default. Use sudo journalctl -u ${SERVICE_NAME} -f to view in real time.
EOF
