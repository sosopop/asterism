#!/bin/bash

# Asterism service uninstallation script.
# Stops the systemd unit, unregisters it, and removes the dedicated account.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

SERVICE_NAME="asterism"
USER_NAME="asterism"
GROUP_NAME="asterism"
INSTALL_DIR="/opt/${SERVICE_NAME}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "=== 卸载 Asterism 服务 ==="

if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo "[1/5] 停止并禁用服务..."
    systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
else
    echo "[1/5] 未在 systemd 中检测到 ${SERVICE_NAME}.service"
fi

if [[ -f "${SERVICE_FILE}" ]]; then
    echo "[2/5] 移除 systemd 服务文件..."
    rm -f "${SERVICE_FILE}"
    echo "服务文件已移除"
else
    echo "[2/5] 未找到 ${SERVICE_FILE}"
fi

echo "[3/5] 刷新 systemd 配置..."
systemctl daemon-reload
systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true

if [[ -d "${INSTALL_DIR}" ]]; then
    echo "[4/5] 移除安装目录 ${INSTALL_DIR}..."
    rm -rf "${INSTALL_DIR}"
    echo "安装目录已移除"
else
    echo "[4/5] 未找到安装目录 ${INSTALL_DIR}"
fi

echo "[5/5] 清理系统用户和用户组..."
if id "${USER_NAME}" > /dev/null 2>&1; then
    userdel --remove "${USER_NAME}" 2>/dev/null || userdel "${USER_NAME}" || true
    echo "用户 ${USER_NAME} 已删除"
else
    echo "用户 ${USER_NAME} 不存在"
fi

if getent group "${GROUP_NAME}" > /dev/null; then
    groupdel "${GROUP_NAME}" 2>/dev/null || true
    echo "用户组 ${GROUP_NAME} 已删除"
else
    echo "用户组 ${GROUP_NAME} 不存在"
fi

echo
echo "=== 卸载完成 ==="
