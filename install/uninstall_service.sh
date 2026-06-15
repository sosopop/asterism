#!/bin/bash

# Asterism service uninstallation script.
# Stops the systemd unit, unregisters it, and removes the dedicated account.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

echo "=== 卸载 Asterism 服务 ==="
echo "请选择要卸载的模式:"
echo "1) 服务端模式 (asterism-server)"
echo "2) 客户端模式 (asterism-client)"
echo "3) 两者都卸载"
read -p "请选择 (1, 2 或 3, 默认: 3): " CHOICE
CHOICE=${CHOICE:-3}

SERVICES=()
if [[ "${CHOICE}" == "1" ]]; then
    SERVICES+=("asterism-server")
elif [[ "${CHOICE}" == "2" ]]; then
    SERVICES+=("asterism-client")
elif [[ "${CHOICE}" == "3" ]]; then
    SERVICES+=("asterism-server" "asterism-client")
else
    echo "无效选择，退出。"
    exit 1
fi

# Also check for legacy asterism service
if systemctl list-unit-files | grep -q "^asterism.service"; then
    echo "检测到遗留的 asterism.service，将对其进行卸载清理..."
    SERVICES+=("asterism")
fi

for SVC in "${SERVICES[@]}"; do
    SERVICE_NAME="${SVC}"
    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    echo
    echo "--- 正在卸载服务 ${SERVICE_NAME} ---"

    if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
        echo "停止并禁用服务..."
        systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
        systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
    else
        echo "未在 systemd 中检测到 ${SERVICE_NAME}.service"
    fi

    if [[ -f "${SERVICE_FILE}" ]]; then
        echo "移除 systemd 服务文件..."
        rm -f "${SERVICE_FILE}"
        echo "服务文件已移除"
    else
        echo "未找到 ${SERVICE_FILE}"
    fi

    echo "刷新 systemd 配置..."
    systemctl daemon-reload
    systemctl reset-failed "${SERVICE_NAME}.service" 2>/dev/null || true
done

# Check if any asterism service still remains registered in systemd
REMAINS_SERVICES=0
for check_svc in "asterism-server" "asterism-client" "asterism"; do
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
    echo "--- 没有检测到其他活跃的 asterism 服务，清理共享文件和账户 ---"
    
    if [[ -d "${INSTALL_DIR}" ]]; then
        echo "移除安装目录 ${INSTALL_DIR}..."
        rm -rf "${INSTALL_DIR}"
        echo "安装目录已移除"
    else
        echo "未找到安装目录 ${INSTALL_DIR}"
    fi

    echo "清理系统用户和用户组..."
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
else
    echo
    echo "--- 仍有其他安装的 asterism 服务，保留共享文件于 ${INSTALL_DIR} 和账户 ${USER_NAME} ---"
fi

echo
echo "=== 卸载完成 ==="
