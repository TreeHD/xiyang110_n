#!/bin/sh

# ======================================================
#  WSTunnel 容器啟動腳本
#  負責啟動所有 sidecar 服務與主程式
# ======================================================

# --- 1. UDPGW (tun2proxy) ---
echo "[entrypoint] 啟動 udpgw-server on 0.0.0.0:7300..."
udpgw -l 0.0.0.0:7300 --daemonize
sleep 1

# --- 2. DNSTT (DNS 隧道，條件式啟動) ---
if [ -n "$DNSTT_DOMAIN" ]; then
    echo "[entrypoint] 偵測到 DNSTT_DOMAIN=${DNSTT_DOMAIN}，準備啟動 DNS 隧道..."

    # 確保金鑰目錄存在
    mkdir -p /app/data/dnstt

    # 首次啟動自動產生金鑰對
    if [ ! -f /app/data/dnstt/server.key ]; then
        echo "[entrypoint] 首次啟動，產生 DNSTT 金鑰對..."
        dnstt-server -gen-key \
            -privkey-file /app/data/dnstt/server.key \
            -pubkey-file /app/data/dnstt/server.pub
        echo "=================================================="
        echo "  [重要] DNSTT 公鑰 (請提供給客戶端):"
        cat /app/data/dnstt/server.pub
        echo "=================================================="
    fi

    # 設定 iptables: UDP 53 → 5300
    echo "[entrypoint] 設定 iptables: UDP 53 → 5300..."
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true

    # 背景啟動 dnstt-server
    # 轉發至 127.0.0.1:80 (HTTP Upgrade 入口)
    echo "[entrypoint] 啟動 dnstt-server (UDP :5300 → 127.0.0.1:80)..."
    dnstt-server \
        -udp :5300 \
        -privkey-file /app/data/dnstt/server.key \
        "$DNSTT_DOMAIN" \
        127.0.0.1:80 &

    sleep 1
    echo "[entrypoint] DNSTT DNS 隧道已啟動！"
else
    echo "[entrypoint] 未設定 DNSTT_DOMAIN，跳過 DNS 隧道。"
fi

# --- 3. 主程式 (wstunnel-go) ---
echo "[entrypoint] 啟動 wstunnel-go..."
exec ./wstunnel-go
