// main.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 ---
type AccountInfo struct {
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"`
}
type Config struct {
	ListenAddr         string                 `json:"listen_addr"`
	AdminAddr          string                 `json:"admin_addr"`
	AdminAccounts      map[string]string      `json:"admin_accounts"`
	Accounts           map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout   int                    `json:"handshake_timeout,omitempty"`
	ConnectUA          string                 `json:"connect_ua,omitempty"`
	BufferSizeKB       int                    `json:"buffer_size_kb,omitempty"`
	IdleTimeoutSeconds int                    `json:"idle_timeout_seconds,omitempty"`
	lock               sync.RWMutex
}
var globalConfig *Config
var activeConn int64
type OnlineUser struct {
	ConnID, Username, RemoteAddr string
	ConnectTime                  time.Time
	sshConn                      ssh.Conn
}
var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex

// --- 辅助函数 ---
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie { /* ... */ }
func validateSession(r *http.Request) bool { /* ... */ }
func sendJSON(w http.ResponseWriter, code int, payload interface{}) { /* ... */ }

// --- 核心数据转发逻辑 ---
var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}
func timedCopy(dst io.Writer, src io.Reader, timeout time.Duration) (written int64, err error) { /* ... */ }
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr) {
	atomic.AddInt64(&activeConn, 1); defer atomic.AddInt64(&activeConn, -1)

	// --- 协议分发 ---
	if destPort == 7300 {
		log.Printf("Detected UDP proxy request on port 7300 from %s", remoteAddr.String())
		handleUDPProxy(ch, remoteAddr) // 交给 Full Cone NAT 处理器
		return
	}
	
	// --- TCP 转发逻辑 ---
	var destAddr string
	if strings.Contains(destHost, ":") {
		destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort)
	} else {
		destAddr = fmt.Sprintf("%s:%d", destHost, destPort)
	}
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to directly connect to %s: %v", destAddr, err); ch.Close(); return
	}
	defer destConn.Close()
	if tcpConn, ok := destConn.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
	done := make(chan struct{})
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	go func() {
		defer func() { if tcpConn, ok := destConn.(*net.TCPConn); ok { tcpConn.CloseWrite() }; close(done) }()
		timedCopy(destConn, ch, idleTimeout)
	}()
	timedCopy(ch, destConn, idleTimeout)
	<-done
}

// --- SSH & HTTP 握手与连接管理 ---
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) { /* ... */ }
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) { /* ... */ }
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	handshakedConn, err := httpHandshake(c); if err != nil { log.Printf("HTTP handshake failed for %s: %v", c.RemoteAddr(), err); return }
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg); if err != nil { log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err); return }
	defer sshConn.Close()
	done := make(chan struct{}); defer close(done); go sendKeepAlives(sshConn, done)
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID()); onlineUser := &OnlineUser{ ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn, }; addOnlineUser(onlineUser)
	log.Printf("SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User()); defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip is allowed"); continue }
		ch, _, err := newChan.Accept(); if err != nil { log.Printf("Failed to accept channel: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("Invalid direct-tcpip payload: %v", err); ch.Close(); continue }
		go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr())
	}
}

// --- Web服务器逻辑 ---
// ... (为了简洁，省略这部分代码，您可以直接使用之前版本中的)

// --- main ---
func main() {
	// ... (main函数的前半部分，配置加载等，保持不变) ...
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configFile, err := os.ReadFile("config.json"); if err != nil { log.Fatalf("FATAL: 无法读取 config.json: %v", err) }
	globalConfig = &Config{}; err = json.Unmarshal(configFile, globalConfig); if err != nil { log.Fatalf("FATAL: 解析 config.json 失败: %v", err) }
	if globalConfig.ListenAddr == "" || len(globalConfig.AdminAccounts) == 0 { log.Fatalf("FATAL: config.json 缺少 listen_addr 或 admin_accounts") }
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 128 }
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 90 }
	bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, globalConfig.BufferSizeKB*1024); return &b }}
	
	log.Println("====== WSTUNNEL (TCP + UDP FullCone NAT Mode) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds", globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)
	
	go func() { /* ... Web Panel 逻辑 ... */ }()
	
	sshCfg := &ssh.ServerConfig{ /* ... SSH Config 逻辑 ... */ }
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s. UDP traffic will be handled via FullCone NAT on port 7300.", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept(); if err != nil { log.Printf("Accept failed: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true); tcpConn.SetKeepAlivePeriod(1 * time.Minute); tcpConn.SetNoDelay(true)
		}
		go func(c net.Conn) { 
			defer func() { if r := recover(); r != nil { log.Printf("FATAL: Panic recovered for %s: %v", c.RemoteAddr(), r) }; c.Close() }()
			handleSshConnection(c, sshCfg) 
		}(conn)
	}
}
