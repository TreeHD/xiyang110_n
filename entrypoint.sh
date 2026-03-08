#!/bin/sh

# 啟動 badvpn-udpgw 並放置於背景執行
# 參數說明：
# --listen-addr: 監聽地址，供內部 proxy 連結
# --max-clients: 同時最高在線人數
# --max-connections-for-client: 每位使用者最高連線數
echo "Starting badvpn-udpgw on 127.0.0.1:7300..."
badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 128 &

# 稍微等待確保 udpgw 已經拉起來
sleep 1

# 啟動 Go 主程式，並使用 exec 接收系統信號 (SIGTERM/SIGINT)
echo "Starting wstunnel-go..."
exec ./wstunnel-go
