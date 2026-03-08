# wstunnel-go (免流代理伺服器)

這是一個基於 Go（Golang） 語言開發的代理工具，專門用於**流量卡免流**場景。支援多種連線方式與傳輸邏輯，兼顧效能、穩定性與部署便捷性，適用於多種複雜網路環境。

## ✨ 專案特性

*   **Go 語言編寫**：資源佔用極低，執行效能佳。
*   **多模式支援**：支援 Direct, Direct TLS, HTTP Payload, SNI Fronted (TLS + HTTP Payload), SOCKS5 / HTTP Proxy 等模式。
*   **開箱即用**：提供 Docker Compose 部署方式，免編譯、免繁雜設定。
*   **跨平臺**：結合 GitHub Actions 提供預先建置的 Docker 映像檔 (`ghcr.io`)，支援多種系統和架構部署。

## 🚀 快速部署 (Docker Compose)

我們推薦使用 Docker Compose 進行部署，以確保環境乾淨與後續維護的便利性。

### 1. 下載並執行 `docker-compose.yml`

在您的伺服器上建立一個新資料夾並寫入 `docker-compose.yml` 檔案 (請將 `<您的GitHub帳號/專案名稱>` 替換為實際的路徑，例如 `treehd/xiyang110_n`):

```yaml
services:
  wstunnel:
    image: ghcr.io/treehd/xiyang110_n:latest
    container_name: wstunnel
    restart: always
    ports:
      - "80:80"       # HTTP Proxy (免流入口)
      - "443:443"     # TLS Multiplexer (加密入口)
      - "9090:9090"   # 管理後台
      - "1080:1080"   # SOCKS5 / HTTP Proxy 入口
    volumes:
      # 持久化資料夾: 所有帳號設定與流量紀錄都會儲存在此資料夾內
      - ./data:/app/data
```

執行以下命令啟動：

```bash
docker-compose up -d
```

啟動後，你可以透過以下網址存取管理後台：
`http://<您的伺服器IP>:9090/login.html` 

**初始設定與持久化：**
第一次啟動後，系統會自動在同一個資料夾內生成 `./data/config.json` 與 `./data/traffic.json`。
請打開 `data/config.json` 修改您的預設管理員帳號(`admin_accounts`)與一般使用者帳號密碼，以確保安全性！後續所有在網頁後台進行的修改，都會即時且永久地寫入這個 `data/` 資料夾，完全不受 Docker 重啟影響。

## 🛠 進階：自行編譯 (不推薦，建議使用 Docker)

如果您真的需要直接在本地編譯執行，請確保安裝了 Go 1.24+：

```bash
go mod tidy
go build -ldflags "-s -w" -o wstunnel-go
./wstunnel-go
```

## 代理功能指南 (SOCKS5 / HTTP Proxy)
啟動專案後，您能透過 預設的 `1080` 埠口連線至本服務，享受完整的代理上網經驗。
- **支援協定**：SOCKS5 與 HTTP (皆支援 Auth 驗證與 CONNECT 方法)
- **認證方式**：請使用 `data/config.json` 裡設定的 `accounts` 作為連線的帳號與密碼。您可以打開管理後台 `9090` 即時新增修改。
- **流量計算**：您在 Proxy 所消耗的所有傳輸量，皆會同步統計至 `traffic.json`，支援後台限流機制。

測試指令（請替換伺服器IP與帳號密碼）：
```bash
# 測試 HTTP Basic Auth 代理
curl -x http://帳號:密碼@您的伺服器IP:1080 http://ipinfo.io
# 測試 SOCKS5 代理
curl -x socks5://帳號:密碼@您的伺服器IP:1080 http://ipinfo.io
```

---

歡迎測試、回饋問題與提交建議，一起完善專案 🙌
