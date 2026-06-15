#!/bin/bash

# Asterism service installation script for macOS (launchd).
# Copies the built binary and registers a launchd daemon so the
# proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism macOS 服务安装程序 ==="
echo "二进制来源: ${BIN_SOURCE}"
echo

if [[ ! -f "${BIN_SOURCE}" ]]; then
    cat <<EOF
错误: 未找到可执行文件 ${BIN_SOURCE}
请先构建项目，例如:
  cmake -S ${REPO_ROOT} -B ${REPO_ROOT}/build
  cmake --build ${REPO_ROOT}/build
或将编译出的 asterism 二进制路径作为本脚本的第一个参数传入。
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
    SERVICE_LABEL="com.asterism.server"

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

    EXEC_ARGS=("-i" "http://0.0.0.0:${HTTP_PORT}" "-i" "socks5://0.0.0.0:${SOCKS5_PORT}" "-o" "tcp://0.0.0.0:${OUTER_PORT}")

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

        EXEC_ARGS+=("-A" "-U" "${AUTH_USER}" "-P" "${AUTH_PASS}")
    fi

elif [[ "${MODE}" == "2" ]]; then
    SERVICE_LABEL="com.asterism.client"

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

    EXEC_ARGS=("-r" "${REMOTE_ADDR}" "-u" "${CLIENT_USER}" "-p" "${CLIENT_PASS}")

else
    echo "无效的选择，退出。"
    exit 1
fi

EXEC_ARGS+=("-v")

INSTALL_BIN="/usr/local/bin/asterism"
LOG_DIR="/usr/local/var/log/${SERVICE_LABEL}"
PLIST_DEST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"

echo "安装位置:   ${INSTALL_BIN}"
echo "日志目录:   ${LOG_DIR}"
echo "服务标签:   ${SERVICE_LABEL}"
echo
# ==================================================

echo "[1/4] 创建日志目录..."
mkdir -p "${LOG_DIR}"
echo "日志目录已就绪"

echo "[2/4] 安装可执行文件..."
cp "${BIN_SOURCE}" "${INSTALL_BIN}"
chmod 755 "${INSTALL_BIN}"
echo "可执行文件已安装到 ${INSTALL_BIN}"

echo "[3/4] 部署 launchd plist..."
if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
    echo "检测到已有服务，先卸载..."
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
echo "plist 已部署到 ${PLIST_DEST}"

echo "[4/4] 加载并启动服务..."
launchctl load -w "${PLIST_DEST}"
echo "服务已加载"

# 检查状态
sleep 1
if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
    echo "服务运行正常"
else
    echo "警告: 服务可能未正常启动，请检查日志"
fi

cat <<EOF

=== 安装完成 ===
常用命令:
  查看状态: sudo launchctl list ${SERVICE_LABEL}
  停止服务: sudo launchctl unload ${PLIST_DEST}
  启动服务: sudo launchctl load -w ${PLIST_DEST}
  查看日志: tail -f ${LOG_DIR}/asterism.log
  查看错误: tail -f ${LOG_DIR}/asterism.err
EOF
