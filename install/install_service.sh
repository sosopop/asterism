#!/bin/bash

# Asterism service installation script for Ubuntu systemd environments.
# Copies the built binary, sets up a restricted service account, and registers
# the systemd unit so the reverse proxy starts on boot.

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "请以 root 权限运行此脚本 (使用 sudo)"
    exit 1
fi

SERVICE_NAME="asterism"
USER_NAME="asterism"
GROUP_NAME="asterism"
INSTALL_DIR="/opt/${SERVICE_NAME}"
BIN_DIR="${INSTALL_DIR}/bin"
LOG_DIR="${INSTALL_DIR}/logs"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
DEFAULT_BIN_SOURCE="${REPO_ROOT}/build/src/asterism/asterism"
BIN_SOURCE="${1:-${DEFAULT_BIN_SOURCE}}"

echo "=== Asterism 服务安装程序 ==="
echo "二进制来源: ${BIN_SOURCE}"
echo "安装目录: ${INSTALL_DIR}"
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

if [[ ! -f "${SCRIPT_DIR}/${SERVICE_NAME}.service" ]]; then
    echo "错误: 找不到服务配置文件 ${SCRIPT_DIR}/${SERVICE_NAME}.service"
    exit 1
fi

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
install -m 755 "${BIN_SOURCE}" "${BIN_DIR}/${SERVICE_NAME}"
chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}"
echo "可执行文件已安装"

echo "[4/6] 部署 systemd 服务文件..."
cp "${SCRIPT_DIR}/${SERVICE_NAME}.service" "${SERVICE_FILE}"
chmod 644 "${SERVICE_FILE}"
echo "服务文件已部署"

echo "[5/6] 刷新 systemd 配置并启用服务..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
echo "服务已启用"

echo "[6/6] 启动服务..."
systemctl restart "${SERVICE_NAME}.service"
systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

cat <<'EOF'

=== 安装完成 ===
常用命令:
  查看状态: sudo systemctl status asterism
  启动服务: sudo systemctl start asterism
  停止服务: sudo systemctl stop asterism
  重启服务: sudo systemctl restart asterism
日志输出默认写入 journal，可使用 sudo journalctl -u asterism -f 实时查看。
EOF
