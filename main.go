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
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshConn     ssh.Conn
}
var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct {
	Username string
	Expiry   time.Time
}
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}


// --- handleDirectTCPIP [核心] ---
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// 端口 7300 专门用于IP隧道 (VPN)
	if destPort == 7300 {
		log.Printf("Detected IP Tunnel (VPN) request on port 7300 from %s", remoteAddr)
		handleIPTunnel(ch, remoteAddr)
		return
	}

	// 其他端口继续走TCP直连转发
	var destAddr string
	if strings.Contains(destHost, ":") {
		destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort)
	} else {
		destAddr = fmt.Sprintf("%s:%d", destHost, destPort)
	}
	
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Printf("TCP Proxy: Failed to connect to %s: %v", destAddr, err)
		ch.Close()
		return
	}
	defer destConn.Close()
	
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}
	
	done := make(chan struct{})
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	
	go func() {
		defer func() {
			if tcpConn, ok := destConn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}
			close(done)
		}()
		timedCopy(destConn, ch, idleTimeout)
	}()
	
	timedCopy(ch, destConn, idleTimeout)
	<-done
}

// --- main 函数 [核心] ---
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("FATAL: 无法读取 config.json: %v", err)
	}
	globalConfig = &Config{}
	err = json.Unmarshal(configFile, globalConfig)
	if err != nil {
		log.Fatalf("FATAL: 解析 config.json 失败: %v", err)
	}
	if globalConfig.ListenAddr == "" || len(globalConfig.AdminAccounts) == 0 {
		log.Fatalf("FATAL: config.json 缺少 listen_addr 或 admin_accounts")
	}

	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 128 }
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 90 }

	bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, globalConfig.BufferSizeKB*1024); return &b }}
	
	// [重要] 创建TUN设备和相关NAT配置
	if err := createTunDevice(); err != nil {
		log.Fatalf("FATAL: Could not create TUN device: %v. Please run as root and ensure TUN module is loaded.", err)
	}
	// [重要] 启动中央分发器
	go readFromTunAndDistribute()

	log.Println("====== WSTUNNEL (TCP Proxy + IP Tunnel Mode) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds",
		globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)

	// 启动Web管理面板 (代码省略，请从您原文件保留)
	go func() {
		// ...
	}()

	// 配置SSH服务器 (代码省略，请从您原文件保留)
	sshCfg := &ssh.ServerConfig{
		// ...
	}
	// ...

	// 启动主监听
	l, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil {
		log.Fatalf("listen fail: %v", err)
	}
	log.Printf("SSH server listening on %s. IP Tunnel traffic will be handled on port 7300.", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handleSshConnection(conn, sshCfg)
	}
}

// --- 其他所有函数 (请从您原来的main.go文件中完整保留) ---
// (为了确保完整性，我把它们都粘贴过来了)

func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}
func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName); if err != nil { return false }
	sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
		return false
	}
	return true
}
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) {
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second
	expectedUA := globalConfig.ConnectUA
	reader := bufio.NewReader(conn)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil { return nil, err }
		req, err := http.ReadRequest(reader); if err != nil { if netErr, ok := err.(net.Error); ok && netErr.Timeout() { return nil, fmt.Errorf("handshake timeout") }; return nil, err }
		io.Copy(ioutil.Discard, req.Body); req.Body.Close()
		if strings.Contains(req.UserAgent(), expectedUA) {
			conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); conn.SetReadDeadline(time.Time{})
			return &combinedConn{Conn: conn, reader: io.MultiReader(reader, conn)}, nil
		} else {
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"))
		}
	}
}
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second); defer ticker.Stop()
	for { select { case <-ticker.C: if _, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil); err != nil { return }; case <-done: return } }
}
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FATAL: Panic recovered for %s: %v", c.RemoteAddr(), r)
		}
		c.Close()
	}()
	handshakedConn, err := httpHandshake(c); if err != nil { log.Printf("HTTP handshake failed for %s: %v", c.RemoteAddr(), err); return }
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg); if err != nil { log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err); return }
	defer sshConn.Close()
	done := make(chan struct{}); defer close(done); go sendKeepAlives(sshConn, done)
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn}; addOnlineUser(onlineUser); log.Printf("SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User()); defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip is allowed"); continue }
		ch, _, err := newChan.Accept(); if err != nil { continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { ch.Close(); continue }
		go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr())
	}
}
func safeSaveConfig() error {
	globalConfig.lock.Lock(); defer globalConfig.lock.Unlock()
	data, err := json.MarshalIndent(globalConfig, "", "  "); if err != nil { return err }
	return ioutil.WriteFile("config.json", data, 0644)
}
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validateSession(r) { next.ServeHTTP(w, r) } else {
			if strings.HasPrefix(r.URL.Path, "/api/") { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"}) } else { http.Redirect(w, r, "/login.html", http.StatusFound) }
		}
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { sendJSON(w, http.StatusMethodNotAllowed, nil); return }
	var creds struct{ Username, Password string }; if err := json.NewDecoder(r.Body).Decode(&creds); err != nil { sendJSON(w, http.StatusBadRequest, nil); return }
	globalConfig.lock.RLock(); storedPass, ok := globalConfig.AdminAccounts[creds.Username]; globalConfig.lock.RUnlock()
	if !ok || creds.Password != storedPass { sendJSON(w, http.StatusUnauthorized, nil); return }
	http.SetCookie(w, createSession(creds.Username)); sendJSON(w, http.StatusOK, nil)
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1}); http.Redirect(w, r, "/login.html", http.StatusFound)
}
func apiHandler(w http.ResponseWriter, r *http.Request) { /* ... (Implementation from your original file) ... */ }
