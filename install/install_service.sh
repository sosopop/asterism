#!/bin/bash

# Asterism service installation script for Ubuntu systemd environments.
# Copies the built binary, sets up a restricted service account, and registers
# the systemd unit so the reverse proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism 服务安装程序 ==="
echo "二进制来源: ${BIN_SOURCE}"
echo

if [[ ! -f "${BIN_SOURCE}" ]]; then
    cat <<EOF
错误: 未找到可执行文件 ${BIN_SOURCE}
请先构建项目，例如:
  cmake -S ${REPO_ROOT} -B ${REPO_ROOT}/build
  cmake --build ${REPO_ROOT}/build
或将编译出的asterism二进制路径作为本脚本的第一个参数传入。
EOF
    exit 1
fi

# ==================== 配置交互 ====================
echo "请选择安装模式:"
echo "1) 服务端模式 (Server Mode)"
echo "2) 客户端模式 (Client Mode)"
read -p "选择模式 (1 或 2, 默认: 1): " MODE
MODE=${MODE:-1}

if [[ "${MODE}" == "1" ]]; then
    SERVICE_NAME="asterism-server"
    USER_NAME="asterism"
    GROUP_NAME="asterism"
    INSTALL_DIR="/opt/asterism"
    BIN_DIR="${INSTALL_DIR}/bin"
    LOG_DIR="${INSTALL_DIR}/logs"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    echo
    echo "=== 服务端模式配置 ==="
    read -p "请输入外部监听端口 (供客户端连接，默认: 8010): " OUTER_PORT
    OUTER_PORT=${OUTER_PORT:-8010}

    read -p "请输入 HTTP 代理监听端口 (默认: 8011): " HTTP_PORT
    HTTP_PORT=${HTTP_PORT:-8011}

    read -p "请输入 SOCKS5 代理监听端口 (默认: 8012): " SOCKS5_PORT
    SOCKS5_PORT=${SOCKS5_PORT:-8012}

    echo
    echo "=== 配置 HTTP Sessions 接口验证 ==="
    read -p "是否开启 HTTP Sessions 接口 of the username password validation? (y/N): " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-n}

    EXEC_ARGS="-i http://0.0.0.0:${HTTP_PORT} -i socks5://0.0.0.0:${SOCKS5_PORT} -o tcp://0.0.0.0:${OUTER_PORT}"

    if [[ "${ENABLE_AUTH}" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "请输入 HTTP Sessions 认证用户名: " AUTH_USER
            if [[ -n "${AUTH_USER}" ]]; then
                break
            fi
            echo "错误: 用户名不能为空，请重新输入。"
        done

        while true; do
            read -p "请输入 HTTP Sessions 认证密码: " AUTH_PASS
            if [[ -n "${AUTH_PASS}" ]]; then
                break
            fi
            echo "错误: 密码不能为空，请重新输入。"
        done

        EXEC_ARGS="${EXEC_ARGS} -A -U ${AUTH_USER} -P ${AUTH_PASS}"
    fi

elif [[ "${MODE}" == "2" ]]; then
    SERVICE_NAME="asterism-client"
    USER_NAME="asterism"
    GROUP_NAME="asterism"
    INSTALL_DIR="/opt/asterism"
    BIN_DIR="${INSTALL_DIR}/bin"
    LOG_DIR="${INSTALL_DIR}/logs"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    echo
    echo "=== 客户端模式配置 ==="
    while true; do
        read -p "请输入远程服务端连接地址 (例如: tcp://1.2.3.4:8010): " REMOTE_ADDR
        if [[ -n "${REMOTE_ADDR}" ]]; then
            break
        fi
        echo "错误: 远程连接地址不能为空，请重新输入。"
    done

    while true; do
        read -p "请输入客户端认证用户名: " CLIENT_USER
        if [[ -n "${CLIENT_USER}" ]]; then
            break
        fi
        echo "错误: 用户名不能为空，请重新输入。"
    done

    while true; do
        read -p "请输入客户端认证密码: " CLIENT_PASS
        if [[ -n "${CLIENT_PASS}" ]]; then
            break
        fi
        echo "错误: 密码不能为空，请重新输入。"
    done

    EXEC_ARGS="-r ${REMOTE_ADDR} -u ${CLIENT_USER} -p ${CLIENT_PASS}"

else
    echo "无效的选择，退出。"
    exit 1
fi

EXEC_ARGS="${EXEC_ARGS} -v"

echo
echo "安装目录: ${INSTALL_DIR}"
echo "服务名称: ${SERVICE_NAME}"
echo
# ==================================================

echo "[1/6] 创建用户与用户组..."
if ! getent group "${GROUP_NAME}" > /dev/null; then
    groupadd --system "${GROUP_NAME}"
    echo "用户组 ${GROUP_NAME} 已创建"
else
    echo "用户组 ${GROUP_NAME} 已存在"
fi

if ! id "${USER_NAME}" > /dev/null 2>&1; then
    useradd --system --gid "${GROUP_NAME}" --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin \
        --comment "Asterism Reverse Proxy Service" "${USER_NAME}"
    echo "用户 ${USER_NAME} 已创建"
else
    echo "用户 ${USER_NAME} 已存在"
fi

echo "[2/6] 创建安装目录..."
mkdir -p "${BIN_DIR}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
echo "目录创建完成"

echo "[3/6] 安装可执行文件..."
install -m 755 "${BIN_SOURCE}" "${BIN_DIR}/asterism"
chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}"
echo "可执行文件已安装"

echo "[4/6] 部署 systemd 服务文件..."
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
echo "服务文件已部署"

echo "[5/6] 刷新 systemd 配置并启用服务..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
echo "服务已启用"

echo "[6/6] 启动服务..."
systemctl restart "${SERVICE_NAME}.service"
systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

cat <<EOF

=== 安装完成 ===
常用命令:
  查看状态: sudo systemctl status ${SERVICE_NAME}
  启动服务: sudo systemctl start ${SERVICE_NAME}
  停止服务: sudo systemctl stop ${SERVICE_NAME}
  重启服务: sudo systemctl restart ${SERVICE_NAME}
日志输出默认写入 journal，可使用 sudo journalctl -u ${SERVICE_NAME} -f 实时查看。
EOF
