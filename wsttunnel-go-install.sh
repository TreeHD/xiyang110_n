#!/bin/bash

# =================================================================
# WSTunnel-Go (TCP + UdpGw Proxy Mode) 全自动一键安装/更新脚本
# 作者: xiaoguidays & Gemini
# 版本: 8.0 (Final UdpGw)
# =================================================================

set -e

# --- 脚本设置 ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
GO_VERSION="1.22.3"
PROJECT_DIR="/usr/local/src/go_wstunnel"
GITHUB_REPO="xiaoguiday/xiyang110"
BRANCH="main"
SERVICE_NAME="wstunnel"
BINARY_NAME="wstunnel-go"
DEPLOY_DIR="/usr/local/bin"

info() { echo -e "${GREEN}[INFO] $1${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
error_exit() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# --- 脚本主逻辑 ---

echo "--- WSTunnel-Go Installer ---"
echo ""

# 1. 权限检查
info "步骤 1: 检查Root权限..."
if [ "$(id -u)" != "0" ]; then
   error_exit "此脚本需要以 root 权限运行。请使用 'sudo' 或以 root 用户执行。"
fi
info "权限检查通过。"
echo ""

# 2. 安装必要的工具
info "步骤 2: 安装系统依赖 (wget, curl, tar, git)..."
if command -v apt-get &> /dev/null; then
    (apt-get update -y && apt-get install -y wget curl tar git) > /dev/null 2>&1 || error_exit "使用 apt-get 安装依赖失败！"
elif command -v yum &> /dev/null; then
    yum install -y wget curl tar git > /dev/null 2>&1 || error_exit "使用 yum 安装依赖失败！"
else
    error_exit "未知的包管理器。请手动安装 wget, curl, tar, git。"
fi
info "系统依赖安装完毕。"
echo ""

# 3. 安装 Go 语言环境
info "步骤 3: 检查并安装 Go 语言环境 (版本 ${GO_VERSION})..."
if ! command -v go &> /dev/null || [[ ! $(go version) == *"go${GO_VERSION}"* ]]; then
    warn "未找到 Go 环境或版本不匹配。正在安装..."
    (wget -q -O go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz) || error_exit "下载或解压 Go 安装包失败！"
    
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    export PATH=$PATH:/usr/local/go/bin
    info "Go 安装成功！"
else
    info "Go 环境已就绪。"
fi
go version
echo ""

# 4. 拉取代码
info "步骤 4: 准备项目目录并拉取最新代码..."
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || error_exit "无法进入项目目录 '$PROJECT_DIR'！"

FILES=("main.go" "admin.html" "login.html" "config.json")
for file in "${FILES[@]}"; do
    echo "  -> 正在下载 ${file}..."
    wget -q -O "${file}" "https://raw.githubusercontent.com/${GITHUB_REPO}/${BRANCH}/${file}" || error_exit "下载 ${file} 失败！"
done
info "所有代码文件已拉取。"
echo ""

# 5. 编译项目
info "步骤 5: 编译Go程序..."
if [ ! -f "go.mod" ]; then
    go mod init wstunnel >/dev/null 2>&1
fi
info "  -> 正在整理 Go 依赖..."
go mod tidy || error_exit "go mod tidy 失败！"
info "  -> 正在编译..."
go build -ldflags "-s -w" -o ${BINARY_NAME} . || error_exit "编译失败！请检查 Go 代码和环境。"
info "项目编译成功！"
echo ""

# 6. 部署文件
info "步骤 6: 部署文件到 ${DEPLOY_DIR}/ ..."
if systemctl is-active --quiet ${SERVICE_NAME}; then
    info "  -> 正在停止现有服务..."
    systemctl stop ${SERVICE_NAME}
fi
mkdir -p ${DEPLOY_DIR}
mv ./${BINARY_NAME} ${DEPLOY_DIR}/
mv ./admin.html ${DEPLOY_DIR}/
mv ./login.html ${DEPLOY_DIR}/
if [ ! -f "${DEPLOY_DIR}/config.json" ]; then
    mv ./config.json ${DEPLOY_DIR}/
    info "  -> 已部署默认的 config.json，请根据需要修改。"
else
    info "  -> 检测到已存在的 config.json，跳过覆盖。"
fi
info "文件部署成功。"
echo ""

# 7. 配置 systemd 服务
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "步骤 7: 配置 systemd 服务..."
cat > "$SERVICE_FILE" <<EOT
[Unit]
Description=WSTunnel-Go Service (TCP + UdpGw Proxy Mode)
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
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOT
systemctl daemon-reload && systemctl enable ${SERVICE_NAME}.service || error_exit "systemd 配置失败！"
info "服务配置完成并已启用。"
echo ""

# 8. 启动服务
info "步骤 8: 启动服务..."
systemctl start ${SERVICE_NAME}.service || error_exit "服务启动失败！"
info "操作成功。"
echo ""

# 最终确认
info "🎉 全部成功！WSTunnel-Go 已安装/更新并正在运行。"
echo ""
info "您可以通过以下命令检查服务状态:"
info "  systemctl status ${SERVICE_NAME}.service"
echo "您可以通过以下命令查看实时日志:"
info "  journalctl -u ${SERVICE_NAME}.service -f"
echo ""
info "所有相关文件都位于: ${DEPLOY_DIR}/"
info "请务必检查并修改您的配置文件: ${DEPLOY_DIR}/config.json"
echo ""
sleep 2
systemctl status ${SERVICE_NAME}.service --no-pager -n 20
