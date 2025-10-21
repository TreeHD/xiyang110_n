package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath" // *** 新增导入 ***
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 (无变化) ---
type AccountInfo struct { Password, ExpiryDate string; Enabled bool }
type Config struct {
	ListenAddr, UdpgwAddr, AdminAddr, ConnectUA string
	SocksAddrs []string
	AdminAccounts map[string]string
	Accounts map[string]AccountInfo
	HandshakeTimeout, BufferSizeKB, IdleTimeoutSeconds, HealthCheckInterval, ConnectionPoolSize int
	lock sync.RWMutex
}
var globalConfig *Config
var activeConn int64
type OnlineUser struct { ConnID, Username, RemoteAddr string; ConnectTime time.Time; sshConn ssh.Conn }
var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
const ( StatusUp int32 = iota; StatusDown )
type pooledProxy struct { addr string; activeConns int64; status int32; pool chan net.Conn; lock sync.Mutex }
var proxyPool []*pooledProxy
var poolLock sync.RWMutex
var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}


// ==============================================================================
// === 核心修正: 健壮的配置文件加载逻辑 ===
// ==============================================================================
func findAndReadConfig() ([]byte, error) {
	// 方案1: 检查标准绝对路径
	const absolutePath = "/etc/wstunnel/config.json"
	if _, err := os.Stat(absolutePath); err == nil {
		log.Printf("Found config file at standard location: %s", absolutePath)
		return os.ReadFile(absolutePath)
	}

	// 方案2: 寻找可执行文件同目录下的配置文件
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("could not determine executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	relativePath := filepath.Join(exeDir, "config.json")
	if _, err := os.Stat(relativePath); err == nil {
		log.Printf("Found config file relative to executable: %s", relativePath)
		return os.ReadFile(relativePath)
	}

	return nil, fmt.Errorf("config.json not found in %s or %s", absolutePath, relativePath)
}


// ... (所有其他函数，如 handleSshConnection, forwardToUdpgw 等，都保持上一份方案一的代码不变)
// ... 我将粘贴完整的、正确的代码在下面 ...

// forwardToUdpgw 将流量透明转发给 udpgw 服务
func forwardToUdpgw(ch ssh.Channel, udpgwAddr string) {
	defer ch.Close()
	
	udpgwConn, err := net.Dial("tcp", udpgwAddr)
	if err != nil {
		log.Printf("Failed to connect to udpgw at %s: %v", udpgwAddr, err)
		return
	}
	defer udpgwConn.Close()

	done := make(chan struct{})
	go func() {
		defer func() {
			if tcpConn, ok := udpgwConn.(*net.TCPConn); ok { tcpConn.CloseWrite() }
			close(done)
		}()
		io.Copy(udpgwConn, ch)
	}()
	io.Copy(ch, udpgwConn)
	<-done
}

// handleSshConnection (采用方案一: 模仿旧架构)
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	handshakedConn, err := httpHandshake(c)
	if err != nil { log.Printf("http handshake failed for %s: %v", c.RemoteAddr(), err); return }
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg)
	if err != nil { log.Printf("ssh handshake failed for %s: %v", c.RemoteAddr(), err); return }
	defer sshConn.Close()
	done := make(chan struct{}); defer close(done); go sendKeepAlives(sshConn, done)
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn, }
	addOnlineUser(onlineUser)
	log.Printf("SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User())
	defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed"); continue }
		ch, _, err := newChan.Accept()
		if err != nil { log.Printf("accept channel fail: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("bad payload: %v", err); ch.Close(); continue }
		
		if payload.Host == "127.0.0.1" && payload.Port == 7300 {
			if globalConfig.UdpgwAddr == "" {
				log.Printf("ERROR: Hijacked UDP stream but 'udpgw_addr' is not configured. Closing connection for user '%s'.", sshConn.User())
				ch.Close()
				continue
			}
			log.Printf("Hijacking and forwarding stream to udpgw for user '%s'", sshConn.User())
			go forwardToUdpgw(ch, globalConfig.UdpgwAddr)
		} else {
			log.Printf("Handling standard direct-tcpip to %s:%d for user '%s'", payload.Host, payload.Port, sshConn.User())
			go handleDirectTCPIP(ch, payload.Host, payload.Port)
		}
	}
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1); defer atomic.AddInt64(&activeConn, -1)
	var bestProxy *pooledProxy; minConns := int64(math.MaxInt64)
	poolLock.RLock()
	healthyProxies := []*pooledProxy{}
	for _, p := range proxyPool { if p.isHealthy() { healthyProxies = append(healthyProxies, p) } }
	if len(healthyProxies) == 0 { poolLock.RUnlock(); log.Printf("error: no healthy SOCKS5 proxies available"); ch.Close(); return }
	for _, p := range healthyProxies { conns := p.getActiveConns(); if conns < minConns { minConns = conns; bestProxy = p } }
	poolLock.RUnlock()
	if bestProxy == nil { log.Printf("error: could not select a best proxy"); ch.Close(); return }
	bestProxy.incrConnections(); defer bestProxy.decrConnections()
	socksConn, err := socks5Connect(bestProxy.addr, destHost, uint16(destPort), false)
	if err != nil { log.Printf("connect to SOCKS5 proxy %s fail: %v", bestProxy.addr, err); ch.Close(); return }
	defer socksConn.Close()
	done := make(chan struct{})
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	go func() {
		defer func() { if tcpConn, ok := socksConn.(*net.TCPConn); ok { tcpConn.CloseWrite() }; close(done) }();
		timedCopy(socksConn, ch, idleTimeout)
	}()
	timedCopy(ch, socksConn, idleTimeout)
	<-done
}
func NewPooledProxy(addr string, poolSize int) *pooledProxy {
	return &pooledProxy{ addr: addr, status: StatusUp, pool: make(chan net.Conn, poolSize), }
}
func (p *pooledProxy) checkHealth() {
	conn, err := net.DialTimeout("tcp", p.addr, 2*time.Second)
	if err != nil { if atomic.CompareAndSwapInt32(&p.status, StatusUp, StatusDown) { log.Printf("Health Check: SOCKS5 proxy %s is DOWN", p.addr) }; return }
	conn.Close()
	if atomic.CompareAndSwapInt32(&p.status, StatusDown, StatusUp) { log.Printf("Health Check: SOCKS5 proxy %s is UP again", p.addr) }
}
func (p *pooledProxy) isHealthy() bool { return atomic.LoadInt32(&p.status) == StatusUp }
func (p *pooledProxy) incrConnections() { atomic.AddInt64(&p.activeConns, 1) }
func (p *pooledProxy) decrConnections() { atomic.AddInt64(&p.activeConns, -1) }
func (p *pooledProxy) getActiveConns() int64 { return atomic.LoadInt64(&p.activeConns) }
func startHealthChecks(interval time.Duration) {
	log.Printf("Starting health checks for SOCKS5 proxies every %s", interval)
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			poolLock.RLock()
			for _, p := range proxyPool { go p.checkHealth() }
			poolLock.RUnlock()
		}
	}()
}
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes); sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour); sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
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
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload); w.Header().Set("Content-Type", "application/json"); w.WriteHeader(code); w.Write(response)
}
func socks5Connect(socksAddr, destHost string, destPort uint16, dialOnly bool) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
	if tcpConn, ok := c.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
	if dialOnly { return c, nil }
	_, err = c.Write([]byte{0x05, 0x01, 0x00}); if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2); if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}; req = append(req, []byte(destHost)...); req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err = c.Write(req); err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4); if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed") }
	switch rep[3] {
	case 0x01: io.CopyN(io.Discard, c, 4+2); case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2); case 0x04: io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}
func timedCopy(dst io.Writer, src io.Reader, timeout time.Duration) (written int64, err error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		if conn, ok := src.(net.Conn); ok { conn.SetReadDeadline(time.Now().Add(timeout)) }
		nr, er := src.Read(buf)
		if nr > 0 {
			if nconn, ok := dst.(net.Conn); ok { nconn.SetWriteDeadline(time.Now().Add(timeout)) }
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw { nw = 0; if ew == nil { ew = io.ErrShortWrite } }
			written += int64(nw)
			if ew != nil { err = ew; break }
			if nr != nw { err = io.ErrShortWrite; break }
		}
		if er != nil {
			if er != io.EOF { err = er }; break
		}
	}
	return written, err
}
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) {
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second; expectedUA := globalConfig.ConnectUA; reader := bufio.NewReader(conn)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil { return nil, fmt.Errorf("failed to set read deadline: %v", err) }
		req, err := http.ReadRequest(reader); if err != nil { if netErr, ok := err.(net.Error); ok && netErr.Timeout() { return nil, fmt.Errorf("handshake timeout: %v", timeoutDuration) }; return nil, fmt.Errorf("read http request fail: %v", err) }
		io.Copy(ioutil.Discard, req.Body); req.Body.Close()
		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); if err != nil { return nil, fmt.Errorf("write http response fail: %v", err) }
			conn.SetReadDeadline(time.Time{}); return &combinedConn{ Conn: conn, reader: io.MultiReader(reader, conn), }, nil
		} else {
			log.Printf("Incorrect handshake payload from %s (UA: %s). Waiting.", conn.RemoteAddr(), req.UserAgent())
			_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")); if err != nil { return nil, fmt.Errorf("write fake 200 OK response fail: %v", err) }
		}
	}
}
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil { log.Printf("Keepalive to %s failed: %v. Connection closed.", sshConn.RemoteAddr(), err); return }
		case <-done:
			log.Printf("Keepalive for %s stopped, connection closed.", sshConn.RemoteAddr()); return
		}
	}
}
func safeSaveConfig() error {
	globalConfig.lock.Lock(); defer globalConfig.lock.Unlock()
	data, err := json.MarshalIndent(globalConfig, "", "  "); if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	return ioutil.WriteFile("config.json", data, 0644)
}
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { if validateSession(r) { next.ServeHTTP(w, r) } else { if strings.HasPrefix(r.URL.Path, "/api/") { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"}) } else { http.Redirect(w, r, "/login.html", http.StatusFound) } } }
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"}); return }; var creds struct { Username, Password string }; if err := json.NewDecoder(r.Body).Decode(&creds); err != nil { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"}); return }; globalConfig.lock.RLock(); storedPass, ok := globalConfig.AdminAccounts[creds.Username]; globalConfig.lock.RUnlock(); if !ok || creds.Password != storedPass { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return }; cookie := createSession(creds.Username); http.SetCookie(w, cookie); sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName); if err == nil { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }; http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1}); http.Redirect(w, r, "/login.html", http.StatusFound)
}
func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/online-users" && r.Method == "GET":
		var users []*OnlineUser; onlineUsers.Range(func(key, value interface{}) bool { users = append(users, value.(*OnlineUser)); return true }); json.NewEncoder(w).Encode(users)
	case r.URL.Path == "/api/accounts" && r.Method == "GET":
		globalConfig.lock.RLock(); defer globalConfig.lock.RUnlock(); json.NewEncoder(w).Encode(globalConfig.Accounts)
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); var accInfo AccountInfo; if err := json.NewDecoder(r.Body).Decode(&accInfo); err != nil { http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest); return }; globalConfig.lock.Lock(); globalConfig.Accounts[username] = accInfo; globalConfig.lock.Unlock(); if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 添加成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); globalConfig.lock.Lock(); delete(globalConfig.Accounts, username); globalConfig.lock.Unlock(); if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 删除成功", username)})
	case strings.HasSuffix(r.URL.Path, "/status") && r.Method == "PUT":
		pathParts := strings.Split(r.URL.Path, "/"); username := pathParts[3]; var payload struct { Enabled bool }; if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest); return }
		globalConfig.lock.Lock();
		if acc, ok := globalConfig.Accounts[username]; ok { acc.Enabled = payload.Enabled; globalConfig.Accounts[username] = acc }
		globalConfig.lock.Unlock();
		if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 状态更新成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		connID := strings.TrimPrefix(r.URL.Path, "/api/connections/"); if user, ok := onlineUsers.Load(connID); ok { user.(*OnlineUser).sshConn.Close(); removeOnlineUser(connID); sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"}) } else { sendJSON(w, http.StatusNotFound, map[string]string{"message": "连接未找到"}) }
	default:
		http.NotFound(w, r)
	}
}
func main() {
	configFile, err := findAndReadConfig() // *** 使用健壮的配置加载逻辑 ***
	if err != nil { log.Fatalf("FATAL: 无法找到或读取配置文件: %v", err) }

	globalConfig = &Config{}; err = json.Unmarshal(configFile, globalConfig); if err != nil { log.Fatalf("FATAL: 解析 config.json 失败: %v", err) }
	if globalConfig.ListenAddr == "" || len(globalConfig.SocksAddrs) == 0 || len(globalConfig.AdminAccounts) == 0 { log.Fatalf("FATAL: config.json 缺少 listen_addr, socks_addrs 或 admin_accounts") }
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 3 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 64 }
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 60 }
	if globalConfig.HealthCheckInterval <= 0 { globalConfig.HealthCheckInterval = 15 }
	if globalConfig.ConnectionPoolSize <= 0 { globalConfig.ConnectionPoolSize = 10 }
	bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, globalConfig.BufferSizeKB*1024); return &b }}
	poolLock.Lock()
	for _, addr := range globalConfig.SocksAddrs { proxyPool = append(proxyPool, NewPooledProxy(addr, globalConfig.ConnectionPoolSize)) }
	poolLock.Unlock()
	startHealthChecks(time.Duration(globalConfig.HealthCheckInterval) * time.Second)
	log.Printf("Loaded %d SOCKS5 proxies for 'Least Connections' load balancing.", len(proxyPool))
	log.Printf("Handshake: timeout=%ds, UA='%s'. Forwarding buffer: %d KB. Idle Timeout: %ds", globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)
	go func() {
		mux := http.NewServeMux(); mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") }); mux.HandleFunc("/login", loginHandler); mux.HandleFunc("/logout", authMiddleware(logoutHandler)); mux.HandleFunc("/api/", authMiddleware(apiHandler)); adminHandler := func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }; mux.HandleFunc("/admin.html", authMiddleware(adminHandler)); mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { if r.URL.Path != "/" { http.NotFound(w, r); return }; if validateSession(r) { http.Redirect(w, r, "/admin.html", http.StatusFound) } else { http.Redirect(w, r, "/login.html", http.StatusFound) } }); log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr); 
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { 
			log.Fatalf("FATAL: 无法启动Admin panel: %v", err) 
		}
	}()
	sshCfg := &ssh.ServerConfig{ PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		globalConfig.lock.RLock(); accountInfo, userExists := globalConfig.Accounts[c.User()]; globalConfig.lock.RUnlock(); if !userExists { return nil, fmt.Errorf("invalid credentials") }; if !accountInfo.Enabled { return nil, fmt.Errorf("user disabled") }; if accountInfo.ExpiryDate != "" { expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate); if err != nil || time.Now().After(expiry.Add(24*time.Hour)) { return nil, fmt.Errorf("user expired") } }; if string(p) == accountInfo.Password { log.Printf("Auth successful for user: '%s'", c.User()); return nil, nil }; log.Printf("Auth failed for user '%s'", c.User()); return nil, fmt.Errorf("invalid credentials")
	} }
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)
	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s, forwarding to SOCKS5 pool", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept(); if err != nil { log.Printf("accept fail: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(1 * time.Minute)
			tcpConn.SetNoDelay(true)
		}
		go func(c net.Conn) { defer func() { if r := recover(); r != nil { log.Printf("FATAL: Panic recovered for %s: %v", c.RemoteAddr(), r) }; c.Close() }(); handleSshConnection(c, sshCfg) }(conn)
	}
}
