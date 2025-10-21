#!/bin/bash

# =================================================================
# WSTunnel-Go (TCP + SOCKS5 UDP Proxy Mode) 全自动一键安装/更新脚本
# 作者: xiaoguidays & Gemini
# 更新时间: 2025-10-21
# 版本: 5.0 (SOCKS5 UDP Final)
# 更新内容:
#   - 适配全新的SOCKS5 UDP代理架构 (main.go, socks5_udp_handler.go)。
#   - [移除] 不再需要TUN/NAT相关的Go文件 (ip_tunnel, session_manager, nat_setup)。
#   - [移除] 不再需要系统依赖 iproute2, iptables。
#   - [简化权限] systemd服务不再需要CAP_NET_ADMIN等高权限。
#   - 更新所有描述文本以匹配新功能。
# =================================================================

set -e # 任何命令失败，脚本立即退出

# --- 脚本设置 ---
# 颜色代码
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 项目配置
GO_VERSION="1.22.3"
PROJECT_DIR="/usr/local/src/go_wstunnel"
GITHUB_REPO="xiaoguiday/xiyang110" # 您的GitHub仓库
BRANCH="main" # 您的代码所在的分支
SERVICE_NAME="wstunnel"
BINARY_NAME="wstunnel-go"
# 部署目录，所有相关文件都将放在这里
DEPLOY_DIR="/etc/wstunnel"

# --- 函数定义 ---
info() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error_exit() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# --- 脚本主逻辑 ---

# 1. 权限检查
info "第 1 步: 正在检查运行权限..."
if [ "$(id -u)" != "0" ]; then
   error_exit "此脚本需要以 root 权限运行。请使用 'sudo' 或以 root 用户执行。"
fi
info "权限检查通过。"
echo " "

# 2. 安装必要的工具
info "第 2 步: 正在安装必要的系统工具..."
if command -v apt-get &> /dev/null; then
    apt-get update -y > /dev/null
    apt-get install -y wget curl tar git > /dev/null || error_exit "使用 apt-get 安装必要工具失败！"
elif command -v yum &> /dev/null; then
    yum install -y wget curl tar git > /dev/null || error_exit "使用 yum 安装必要工具失败！"
else
    error_exit "未知的包管理器。请手动安装 wget, curl, tar, git。"
fi
info "系统工具已准备就绪。"
echo " "

# 3. 安装 Go 语言环境
info "第 3 步: 正在检查并安装 Go 语言环境..."
if ! command -v go &> /dev/null || [[ ! $(go version) == *"go${GO_VERSION}"* ]]; then
    warn "未找到 Go 环境或版本不匹配。正在安装 Go ${GO_VERSION}..."
    wget -q -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" || error_exit "下载 Go 安装包失败！"
    rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz || error_exit "解压 Go 安装包失败！"
    rm go.tar.gz
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    # 立即生效
    export PATH=$PATH:/usr/local/go/bin
    info "Go ${GO_VERSION} 安装成功！"
else
    info "Go 环境已存在且版本正确。"
fi
if ! command -v go &> /dev/null; then
    error_exit "Go 命令在当前会话中不可用。请尝试运行 'source /etc/profile' 然后重新运行脚本。"
fi
go version
echo " "

# 4. 创建项目目录并拉取所有必需文件
info "第 4 步: 正在准备项目目录并拉取最新代码..."
# 清理旧目录，确保全新编译
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || error_exit "进入项目目录 '$PROJECT_DIR' 失败！"

# 定义文件列表 (2个Go文件 + 3个网页/配置文件)
FILES=("main.go" "socks5_udp_handler.go" "admin.html" "login.html" "config.json")

for file in "${FILES[@]}"; do
    info "  -> 正在下载 ${file}..."
    wget -q -O "${file}" "https://raw.githubusercontent.com/${GITHUB_REPO}/${BRANCH}/${file}" || error_exit "下载 ${file} 失败！"
done
info "所有必需文件已成功拉取。"
echo " "

# 5. 编译项目
info "第 5 步: 正在编译项目 (位于 ${PROJECT_DIR})..."
if [ ! -f "go.mod" ]; then
    go mod init wstunnel || error_exit "go mod init 失败！"
fi
# 安装依赖
info "  -> 正在整理 Go 依赖..."
# go mod tidy 会自动处理所有需要的依赖
go mod tidy || error_exit "go mod tidy 失败！"

# 编译
info "  -> 正在编译 Go 程序..."
# 使用 -ldflags "-s -w" 减小编译后文件的大小
go build -ldflags "-s -w" -o ${BINARY_NAME} . || error_exit "编译失败！请检查 Go 代码和环境。"
info "项目编译成功，生成可执行文件: ${BINARY_NAME}"
echo " "

# 6. 部署文件
info "第 6 步: 正在部署所有文件到 ${DEPLOY_DIR}/ ..."
if systemctl is-active --quiet ${SERVICE_NAME}; then
    info "  -> 正在停止现有服务..."
    systemctl stop ${SERVICE_NAME}
fi
mkdir -p ${DEPLOY_DIR}
mv ./${BINARY_NAME} ${DEPLOY_DIR}/ || error_exit "移动 ${BINARY_NAME} 失败！"
mv ./admin.html ${DEPLOY_DIR}/ || error_exit "移动 admin.html 失败！"
mv ./login.html ${DEPLOY_DIR}/ || error_exit "移动 login.html 失败！"
# 只有当目标位置不存在config.json时才移动，防止覆盖用户修改过的配置
if [ ! -f "${DEPLOY_DIR}/config.json" ]; then
    mv ./config.json ${DEPLOY_DIR}/ || error_exit "移动 config.json 失败！"
    info "已部署默认的 config.json，请根据需要修改它。"
else
    info "已存在 config.json，跳过覆盖以保留您的设置。"
fi
info "文件部署成功。"
echo " "

# 7. 创建并启用 systemd 服务 (简化版权限)
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "第 7 步: 正在配置 systemd 服务..."
cat > "$SERVICE_FILE" <<EOT
[Unit]
Description=WSTunnel-Go Service (TCP + SOCKS5 UDP Proxy Mode)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${DEPLOY_DIR}
ExecStart=${DEPLOY_DIR}/${BINARY_NAME}
Restart=always
RestartSec=3
LimitNOFILE=65536

# --- [权限简化] ---
# TCP/UDP代理模式不再需要网络管理权限 (CAP_NET_ADMIN)
# User=root 已足以绑定低位端口 (如 80)
# 如需更高安全性，可改为非root用户并添加 CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload || error_exit "systemctl daemon-reload 失败！"
systemctl enable ${SERVICE_NAME}.service || error_exit "systemctl enable 失败！"
info "服务配置完成并已启用。"
echo " "

# 8. 启动/重启服务并检查状态
info "第 8 步: 正在启动服务..."
systemctl start ${SERVICE_NAME}.service || error_exit "服务启动失败！"
info "操作成功。"
echo " "

# 最终确认
info "🎉 全部成功！WSTunnel-Go 已安装/更新并正在运行。"
echo " "
info "您可以通过以下命令检查服务状态:"
info "  systemctl status ${SERVICE_NAME}.service"
echo "您可以通过以下命令查看实时日志:"
info "  journalctl -u ${SERVICE_NAME}.service -f"
echo " "
info "所有相关文件都位于: ${DEPLOY_DIR}/"
info "请务必检查并修改您的配置文件: ${DEPLOY_DIR}/config.json"
echo " "

sleep 2
systemctl status ${SERVICE_NAME}.service --no-pager -n 20
