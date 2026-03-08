# Stage 1: Go Builder
FROM golang:1.24-alpine AS go-builder
WORKDIR /app
COPY . .
RUN apk add --no-cache git
RUN [ -f go.mod ] || go mod init wstunnel
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o wstunnel-go

# Stage 2: UDPGW Downloader (Multi-arch)
FROM debian:bookworm-slim AS udpgw-downloader
ARG TARGETARCH
RUN apt-get update && apt-get install -y curl unzip
RUN set -x && \
    case "${TARGETARCH}" in \
        "amd64") ARCH="x86_64" ;; \
        "arm64") ARCH="aarch64" ;; \
        *) ARCH="x86_64" ;; \
    esac && \
    URL="https://github.com/tun2proxy/tun2proxy/releases/latest/download/tun2proxy-${ARCH}-unknown-linux-gnu.zip" && \
    curl -L -o udpgw.zip "$URL" && \
    unzip udpgw.zip udpgw-server && \
    chmod +x udpgw-server

# Stage 3: Final Runner
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y tzdata ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Copy binaries
COPY --from=go-builder /app/wstunnel-go .
COPY --from=go-builder /app/frontend ./frontend
COPY --from=udpgw-downloader /udpgw-server /usr/local/bin/udpgw

# Entrypoint setup
COPY entrypoint.sh .
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

EXPOSE 80 443 9090 1080 7300
CMD ["./entrypoint.sh"]
