FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go mod init wstunnel && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o wstunnel-go

FROM alpine:latest
RUN apk add --no-cache tzdata
WORKDIR /app
COPY --from=builder /app/wstunnel-go .
COPY --from=builder /app/frontend ./frontend

EXPOSE 80 443 9090 1080 7300
CMD ["./wstunnel-go"]
