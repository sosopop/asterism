#!/bin/bash

# Asterism service uninstallation script for macOS (launchd).
# Stops the launchd daemon, deletes the plist file, and removes the installed binary and logs.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

echo "=== macOS 卸载 Asterism 服务 ==="
echo "请选择要卸载的模式:"
echo "1) 服务端模式 (com.asterism.server)"
echo "2) 客户端模式 (com.asterism.client)"
echo "3) 两者都卸载"
read -p "请选择 (1, 2 或 3, 默认: 3): " CHOICE
CHOICE=${CHOICE:-3}

LABELS=()
if [[ "${CHOICE}" == "1" ]]; then
    LABELS+=("com.asterism.server")
elif [[ "${CHOICE}" == "2" ]]; then
    LABELS+=("com.asterism.client")
elif [[ "${CHOICE}" == "3" ]]; then
    LABELS+=("com.asterism.server" "com.asterism.client")
else
    echo "无效选择，退出。"
    exit 1
fi

# Also check for legacy com.asterism service
if launchctl list com.asterism &>/dev/null || [[ -f "/Library/LaunchDaemons/com.asterism.plist" ]]; then
    echo "检测到遗留的 com.asterism 服务，将进行卸载清理..."
    LABELS+=("com.asterism")
fi

for LABEL in "${LABELS[@]}"; do
    PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
    
    echo
    echo "--- 正在卸载 ${LABEL} ---"
    
    if launchctl list "${LABEL}" &>/dev/null; then
        echo "停止并卸载 launchd 服务..."
        launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    else
        echo "未在 launchctl 中检测到 active 的 ${LABEL}"
    fi
    
    if [[ -f "${PLIST_DEST}" ]]; then
        echo "移除 plist 文件..."
        rm -f "${PLIST_DEST}"
    fi
    
    INSTALL_BIN="/usr/local/bin/asterism"
    LOG_DIR="/usr/local/var/log/${LABEL}"
    
    if [[ -d "${LOG_DIR}" ]]; then
        echo "移除日志目录 ${LOG_DIR}..."
        rm -rf "${LOG_DIR}"
    fi

    # Only delete the binary if no asterism services are left registered in launchd plists
    if [[ ! -f "/Library/LaunchDaemons/com.asterism.server.plist" && ! -f "/Library/LaunchDaemons/com.asterism.client.plist" && ! -f "/Library/LaunchDaemons/com.asterism.plist" ]]; then
        if [[ -f "${INSTALL_BIN}" ]]; then
            echo "没有检测到其他活跃的 asterism 服务，移除可执行文件 ${INSTALL_BIN}..."
            rm -f "${INSTALL_BIN}"
        fi
    else
        echo "检测到仍有其他安装的 asterism 服务，保留共享的可执行文件 ${INSTALL_BIN}"
    fi
    
    echo "${LABEL} 卸载完成。"
done

echo
echo "=== 所有卸载步骤已完成 ==="
