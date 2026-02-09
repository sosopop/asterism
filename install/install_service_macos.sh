#!/bin/bash

# Asterism service installation script for macOS (launchd).
# Copies the built binary and registers a launchd daemon so the
# reverse proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

SERVICE_LABEL="com.asterism"
PLIST_NAME="${SERVICE_LABEL}.plist"
INSTALL_BIN="/usr/local/bin/asterism"
LOG_DIR="/usr/local/var/log/asterism"
PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism macOS 服务安装程序 ==="
echo "二进制来源: ${BIN_SOURCE}"
echo "安装位置:   ${INSTALL_BIN}"
echo "日志目录:   ${LOG_DIR}"
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

if [[ ! -f "${SCRIPT_DIR}/${PLIST_NAME}" ]]; then
    echo "错误: 找不到 plist 文件 ${SCRIPT_DIR}/${PLIST_NAME}"
    exit 1
fi

echo "[1/4] 创建日志目录..."
mkdir -p "${LOG_DIR}"
echo "日志目录已就绪"

echo "[2/4] 安装可执行文件..."
cp "${BIN_SOURCE}" "${INSTALL_BIN}"
chmod 755 "${INSTALL_BIN}"
echo "可执行文件已安装到 ${INSTALL_BIN}"

echo "[3/4] 部署 launchd plist..."
# 如果服务已加载，先卸载
if launchctl list "${SERVICE_LABEL}" &>/dev/null; then
    echo "检测到已有服务，先卸载..."
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
fi
cp "${SCRIPT_DIR}/${PLIST_NAME}" "${PLIST_DEST}"
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

cat <<'EOF'

=== 安装完成 ===
常用命令:
  查看状态: sudo launchctl list com.asterism
  停止服务: sudo launchctl unload /Library/LaunchDaemons/com.asterism.plist
  启动服务: sudo launchctl load -w /Library/LaunchDaemons/com.asterism.plist
  查看日志: tail -f /usr/local/var/log/asterism/asterism.log
  查看错误: tail -f /usr/local/var/log/asterism/asterism.err
EOF
