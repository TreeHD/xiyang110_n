FROM golang:1.24-alpine AS go-builder
WORKDIR /app
COPY . .
# 如果 go.mod 不存在則初始化，並安裝 git 以便獲取相依模組
RUN apk add --no-cache git
RUN [ -f go.mod ] || go mod init wstunnel
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o wstunnel-go

# 階段 2: 編譯 badvpn-udpgw
FROM alpine:latest AS badvpn-builder
RUN apk add --no-cache git cmake make gcc g++ musl-dev linux-headers
RUN git clone https://github.com/ambrop72/badvpn.git /badvpn
WORKDIR /badvpn/build
RUN cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
RUN make

# 階段 3: 最終運行環境
FROM alpine:latest
# 安裝必要的運行時套件 (tzdata)
RUN apk add --no-cache tzdata
WORKDIR /app

# 複製編譯好的主程式與前端檔案
COPY --from=go-builder /app/wstunnel-go .
COPY --from=go-builder /app/frontend ./frontend

# 複製編譯好的 badvpn-udpgw 到系統路徑
COPY --from=badvpn-builder /badvpn/build/udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw

# 複製並處理啟動腳本
COPY entrypoint.sh .
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

# 暴露必要的埠口
EXPOSE 80 443 9090 1080 7300

# 啟動腳本
CMD ["./entrypoint.sh"]
