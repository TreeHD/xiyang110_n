# WSTunnel-Go 開發與架構指南 (給未來的 Agent)

哈囉！未來的 AI Agent，當你被派來修改或擴充這個專案時，請務必先閱讀這封指南，了解本專案的核心架構以及我們的開發習慣。

## 1. 核心觀念 (Architecture Overview)

這是一個高度客製化的「免流代理 (Free-Flow Proxy)」與多重通訊協定分發器：
* **核心檔案配置**： 
  * `main.go`: 程式進入點、設定 `config.json` 解析、路由分配中心 (包含 80 HTTP Upgrade 與 443 TLS Multiplexer)。
  * `proxy_server.go`: SOCKS5 與 HTTP Proxy 的雙協定處理器。
  * `entrypoint.sh`: Docker 入口腳本，負責同時啟動 `udpgw-server` (port 7300) 與主程式 `wstunnel-go`。
  * `frontend/`: 存放控制面板的網頁前端 (HTML)。
* **UDP 支援 (UDPGW)**：已捨棄舊有的 Go 實作 (`udpgw_handler.go` 等)，改採 `tun2proxy` 專案的 `udpgw-server`。這是在 Dockerfile 中根據架構下載對應的 musl 二進位檔，並在背景獨立運行。
* **流量統計**：所有傳輸流量（包含 SSH Forwarding 與 SOCKS5/HTTP Proxy）都會統計進 `globalTraffic` 這個 goroutine-safe 的 `sync.Map` 中，並且會由背景常式定期存入 `traffic.json` 以達永久保存。
* **Port 複用 (Port Multiplexing)**：`443` 埠口不只是單純的 HTTPS，裡面做了一層 Peek 來判斷進來的是 SSH Payload、單純的 TLS HTTP 還是其他偽裝流量。**在修改這一塊時請特別注意不要破壞原有的 Peek 邏輯。**

## 2. 開發習慣與指導原則

### 2.1 修改與編譯
這個專案依賴 `go mod` 進行套件管理，若你新增或修改了 import，請務必執行：
```bash
go mod tidy
go build -ldflags "-s -w" -o wstunnel-go
```
*註：目前 Dockerfile 內的 Builder 已經升級至 `golang:1.24` 以滿足新版 `golang.org/x/crypto` 的需求。*

### 2.2 命名風格與用語
* **變數名稱**：請遵守標準的 Go CamelCase 命名法，例如 `proxyServer` 而非 `proxy_server`。
* **文件或對話用語**：我們預設使用**台灣正體中文用語**，例如：
  * 「伺服器」 (不要用 服務器)
  * 「設定檔」 (不要用 配置文件)
  * 「支援」 (不要用 支持)
  * 「平臺」 (不要用 平台/平臺)
  * 「連線」 (不要用 鏈接)
  * 「預設」 (不要用 默認)

### 2.3 功能擴充注意事項
當你需要為系統新增一個功能（例如新的代理協議）時：
1. **認證整合**：請重複利用 `globalConfig.Accounts` 的機制。所有帳號限流、限期與停用狀態都統一由這組資料結構控制，請善用 `globalConfig.lock.RLock()` 確保執行緒安全。
2. **流量統計**：任何代理功能只要消耗了流量，都應該透過 `atomic.AddUint64(&traffic.Sent, bytes)` 與 `atomic.AddUint64(&traffic.Received, bytes)` 把流量加入 `globalTraffic` 中。
3. **優雅關閉 (Graceful Shutdown)**：我們在 `main.go` 有捕捉 `syscall.SIGINT` 與 `syscall.SIGTERM`，如果要起新的 Server 常駐邏輯（像是 Proxy），記得要加入 `sync.WaitGroup` 並在結束前優雅釋放資源與存檔。

## 3. Docker 化部署與多架構
我們使用 Docker 的多階段建置 (Multi-stage build)：
1. `go-builder`: 編譯 Go 程式。
2. `udpgw-downloader`: 根據 `TARGETARCH` (amd64/arm64) 從 GitHub 下載對應的 `tun2proxy` 專案 `udpgw-server` musl 二進位檔。
3. `runner`: 最終運行的 Alpine 鏡像，包含所有二進位檔與 `entrypoint.sh`。
* 當有 push event 到 `main` 分支時，GitHub Action 會自動啟動並推送雙架構鏡像至 `ghcr.io`。

-- 祝你開發順利！
