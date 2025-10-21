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

// --- 结构体及全局变量 (保持不变) ---
type AccountInfo struct { Password string `json:"password"`; Enabled bool `json:"enabled"`; ExpiryDate string `json:"expiry_date"` }
type Config struct { ListenAddr string `json:"listen_addr"`; AdminAddr string `json:"admin_addr"`; AdminAccounts map[string]string `json:"admin_accounts"`; Accounts map[string]AccountInfo `json:"accounts"`; HandshakeTimeout int `json:"handshake_timeout,omitempty"`; ConnectUA string `json:"connect_ua,omitempty"`; BufferSizeKB int `json:"buffer_size_kb,omitempty"`; IdleTimeoutSeconds int `json:"idle_timeout_seconds,omitempty"`; lock sync.RWMutex }
var globalConfig *Config
var activeConn int64
type OnlineUser struct { ConnID string `json:"conn_id"`; Username string `json:"username"`; RemoteAddr string `json:"remote_addr"`; ConnectTime time.Time `json:"connect_time"`; sshConn ssh.Conn }
var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex

// --- 辅助函数 (保持不变) ---
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes); sessionToken := hex.EncodeToString(sessionTokenBytes); expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}
func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName); if err != nil { return false }
	sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) { if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }; return false }
	return true
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) { response, _ := json.Marshal(payload); w.Header().Set("Content-Type", "application/json"); w.WriteHeader(code); w.Write(response) }

// --- 核心数据转发逻辑 ---
var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}
func timedCopy(dst io.Writer, src io.Reader, timeout time.Duration) (written int64, err error) {
	bufPtr := bufferPool.Get().(*[]byte); defer bufferPool.Put(bufPtr); buf := *bufPtr
	for {
		if srcConn, ok := src.(net.Conn); ok { if err := srcConn.SetReadDeadline(time.Now().Add(timeout)); err != nil { return written, err } }
		nr, er := src.Read(buf)
		if nr > 0 {
			if dstConn, ok := dst.(net.Conn); ok { if err := dstConn.SetWriteDeadline(time.Now().Add(timeout)); err != nil { return written, err } }
			nw, ew := dst.Write(buf[0:nr]); if nw < 0 || nr < nw { nw = 0; if ew == nil { ew = io.ErrShortWrite } }; written += int64(nw)
			if ew != nil { err = ew; break }; if nr != nw { err = io.ErrShortWrite; break }
		}
		if er != nil { if netErr, ok := er.(net.Error); ok && netErr.Timeout() { err = nil } else if er != io.EOF { err = er }; break }
	}
	return written, err
}
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr) {
	atomic.AddInt64(&activeConn, 1); defer atomic.AddInt64(&activeConn, -1)
	var destAddr string
	if strings.Contains(destHost, ":") { destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort) } else { destAddr = fmt.Sprintf("%s:%d", destHost, destPort) }
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil { log.Printf("TCP Proxy: Failed to connect to %s: %v", destAddr, err); ch.Close(); return }
	defer destConn.Close()
	if tcpConn, ok := destConn.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
	done := make(chan struct{})
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	go func() { defer func() { if tcpConn, ok := destConn.(*net.TCPConn); ok { tcpConn.CloseWrite() }; close(done) }(); timedCopy(destConn, ch, idleTimeout) }()
	timedCopy(ch, destConn, idleTimeout); <-done
}

// --- SSH & HTTP 握手与连接管理 (保持不变) ---
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) { /* ... (完整实现) ... */ }
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) { /* ... (完整实现) ... */ }
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) { /* ... (完整实现) ... */ }

// --- Web服务器逻辑 (保持不变) ---
func safeSaveConfig() error { /* ... (完整实现) ... */ }
func authMiddleware(next http.HandlerFunc) http.HandlerFunc { /* ... (完整实现) ... */ }
func loginHandler(w http.ResponseWriter, r *http.Request) { /* ... (完整实现) ... */ }
func logoutHandler(w http.ResponseWriter, r *http.Request) { /* ... (完整实现) ... */ }
func apiHandler(w http.ResponseWriter, r *http.Request) { /* ... (完整实现) ... */ }


// --- main ---
func main() {
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

	log.Println("====== WSTUNNEL (Pure TCP Proxy Mode) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds",
		globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)

	go func() {
		mux := http.NewServeMux(); mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") }); mux.HandleFunc("/login", loginHandler); mux.HandleFunc("/logout", authMiddleware(logoutHandler)); mux.HandleFunc("/api/", authMiddleware(apiHandler)); adminHandler := func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }; mux.HandleFunc("/admin.html", authMiddleware(adminHandler)); mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { if r.URL.Path != "/" { http.NotFound(w, r); return }; if validateSession(r) { http.Redirect(w, r, "/admin.html", http.StatusFound) } else { http.Redirect(w, r, "/login.html", http.StatusFound) } })
		log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr)
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { log.Fatalf("FATAL: 无法启动Admin panel: %v", err) }
	}()

	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			globalConfig.lock.RLock(); accountInfo, userExists := globalConfig.Accounts[c.User()]; globalConfig.lock.RUnlock()
			if !userExists { return nil, fmt.Errorf("user not found") }; if !accountInfo.Enabled { return nil, fmt.Errorf("user disabled") }
			if accountInfo.ExpiryDate != "" { expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate); if err != nil || time.Now().After(expiry.Add(24*time.Hour)) { return nil, fmt.Errorf("user expired") } }
			if string(p) == accountInfo.Password { log.Printf("Auth successful for user: '%s'", c.User()); return nil, nil }
			log.Printf("Auth failed for user: '%s'", c.User()); return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s. All traffic will be forwarded via TCP.", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept(); if err != nil { log.Printf("Accept failed: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok { tcpConn.SetKeepAlive(true); tcpConn.SetKeepAlivePeriod(1 * time.Minute); tcpConn.SetNoDelay(true) }
		go handleSshConnection(conn, sshCfg)
	}
}
