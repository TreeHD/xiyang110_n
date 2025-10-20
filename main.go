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
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 (部分新增) ---
type AccountInfo struct {
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"`
}

type Config struct {
	ListenAddr       string                 `json:"listen_addr"`
	SocksAddrs       []string               `json:"socks_addrs"` // 从 socks_addr 改为 socks_addrs 数组
	AdminAddr        string                 `json:"admin_addr"`
	AdminAccounts    map[string]string      `json:"admin_accounts"`
	Accounts         map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout int                    `json:"handshake_timeout,omitempty"`
	ConnectUA        string                 `json:"connect_ua,omitempty"`
	BufferSizeKB     int                    `json:"buffer_size_kb,omitempty"`
	lock             sync.RWMutex
}

var globalConfig *Config
var activeConn int64 // 用于Web面板统计的全局连接数

type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshConn     ssh.Conn
}

var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex


// ==============================================================================
// === 架构升级: 为“最少连接数”模式定义新的结构体和全局变量 ===
// ==============================================================================

// managedProxy 用于管理单个代理的状态
type managedProxy struct {
	addr        string      // 代理地址
	activeConns int64       // 当前活动连接数
	lock        sync.Mutex  // 用于保护 activeConns 的互斥锁
}

// incrConnections 增加连接数 (线程安全)
func (p *managedProxy) incrConnections() { p.lock.Lock(); p.activeConns++; p.lock.Unlock() }
// decrConnections 减少连接数 (线程安全)
func (p *managedProxy) decrConnections() { p.lock.Lock(); p.activeConns--; p.lock.Unlock() }
// getActiveConns 获取当前连接数 (线程安全)
func (p *managedProxy) getActiveConns() int64 { p.lock.Lock(); defer p.lock.Unlock(); return p.activeConns }

// 全局的代理池
var proxyPool []*managedProxy
var poolLock sync.RWMutex // 用于保护 proxyPool 本身的读写锁


// --- 辅助函数 (无改动) ---
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie { /* ...内容不变... */
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes); sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour); sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}
func validateSession(r *http.Request) bool { /* ...内容不变... */
	cookie, err := r.Cookie(sessionCookieName); if err != nil { return false }
	sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
		return false
	}
	return true
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) { /* ...内容不变... */
	response, _ := json.Marshal(payload); w.Header().Set("Content-Type", "application/json"); w.WriteHeader(code); w.Write(response)
}


// --- socks5Connect (无改动) ---
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) { /* ...内容不变... */ 
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
	if tcpConn, ok := c.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
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


// ==============================================================================
// === 架构升级: 实现“最少连接数”负载均衡算法 ===
// ==============================================================================
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// --- 核心改动: 选择连接数最少的代理 ---
	var bestProxy *managedProxy
	minConns := int64(math.MaxInt64)

	poolLock.RLock() // 以只读方式锁定代理池
	if len(proxyPool) == 0 {
		poolLock.RUnlock()
		log.Printf("error: no SOCKS5 proxies available in the pool")
		ch.Close()
		return
	}
	for _, p := range proxyPool {
		conns := p.getActiveConns()
		if conns < minConns {
			minConns = conns
			bestProxy = p
		}
	}
	poolLock.RUnlock()

	if bestProxy != nil {
		bestProxy.incrConnections()
		defer bestProxy.decrConnections() // 关键！确保连接断开时计数器-1
	} else {
		log.Printf("error: could not select a best proxy from the pool")
		ch.Close()
		return
	}
	socksServerAddr := bestProxy.addr
	// --- 改动结束 ---

	socksConn, err := socks5Connect(socksServerAddr, destHost, uint16(destPort))
	if err != nil {
		log.Printf("connect to SOCKS5 proxy %s fail: %v", socksServerAddr, err)
		ch.Close()
		return
	}
	defer socksConn.Close()

	bufferPool := sync.Pool{
		New: func() interface{} {
			b := make([]byte, globalConfig.BufferSizeKB*1024)
			return &b
		},
	}
	done := make(chan struct{})
	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		defer func() {
			bufferPool.Put(bufPtr)
			if tcpConn, ok := socksConn.(*net.TCPConn); ok { tcpConn.CloseWrite() }
			close(done)
		}()
		io.CopyBuffer(socksConn, ch, *bufPtr)
	}()
	bufPtr := bufferPool.Get().(*[]byte)
	defer func() {
		bufferPool.Put(bufPtr)
		ch.CloseWrite()
	}()
	io.CopyBuffer(ch, socksConn, *bufPtr)
	<-done
}


type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }

// --- httpHandshake (无改动) ---
func httpHandshake(conn net.Conn) (net.Conn, error) { /* ...内容不变... */
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second; expectedUA := globalConfig.ConnectUA; reader := bufio.NewReader(conn)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil { return nil, fmt.Errorf("failed to set read deadline: %v", err) }
		req, err := http.ReadRequest(reader); if err != nil { if netErr, ok := err.(net.Error); ok && netErr.Timeout() { return nil, fmt.Errorf("handshake timeout: no correct payload received within %v", timeoutDuration) }; return nil, fmt.Errorf("read http request fail: %v", err) }
		io.Copy(ioutil.Discard, req.Body); req.Body.Close()
		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); if err != nil { return nil, fmt.Errorf("write http response fail: %v", err) }
			conn.SetReadDeadline(time.Time{}); return &combinedConn{ Conn: conn, reader: io.MultiReader(reader, conn), }, nil
		} else {
			log.Printf("Incorrect handshake payload from %s (UA: %s). Sending 200 OK and waiting.", conn.RemoteAddr(), req.UserAgent())
			_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")); if err != nil { return nil, fmt.Errorf("write fake 200 OK response fail: %v", err) }
		}
	}
}

// --- handleSshConnection (无改动) ---
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) { /* ...内容不变... */
	handshakedConn, err := httpHandshake(c); if err != nil { log.Printf("http handshake failed for %s: %v", c.RemoteAddr(), err); return }
	log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg); if err != nil { log.Printf("ssh handshake failed for %s: %v", c.RemoteAddr(), err); return }
	defer sshConn.Close()
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn, }; addOnlineUser(onlineUser)
	log.Printf("Phase 2: SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User()); defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed"); continue }
		ch, _, err := newChan.Accept(); if err != nil { log.Printf("accept channel fail: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("bad payload: %v", err); ch.Close(); continue }
		go handleDirectTCPIP(ch, payload.Host, payload.Port)
	}
}

// --- Web服务器逻辑 (无改动) ---
func safeSaveConfig() error { /* ...内容不变... */
	globalConfig.lock.Lock(); defer globalConfig.lock.Unlock(); data, err := json.MarshalIndent(globalConfig, "", "  "); if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }; return ioutil.WriteFile("config.json", data, 0644)
}
func authMiddleware(next http.HandlerFunc) http.HandlerFunc { /* ...内容不变... */
	return func(w http.ResponseWriter, r *http.Request) { if validateSession(r) { next.ServeHTTP(w, r) } else { if strings.HasPrefix(r.URL.Path, "/api/") { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"}) } else { http.Redirect(w, r, "/login.html", http.StatusFound) } } }
}
func loginHandler(w http.ResponseWriter, r *http.Request) { /* ...内容不变... */
	if r.Method != http.MethodPost { sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"}); return }; var creds struct { Username string `json:"username"`; Password string `json:"password"` }; if err := json.NewDecoder(r.Body).Decode(&creds); err != nil { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的请求格式"}); return }; globalConfig.lock.RLock(); storedPass, ok := globalConfig.AdminAccounts[creds.Username]; globalConfig.lock.RUnlock(); if !ok || creds.Password != storedPass { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return }; cookie := createSession(creds.Username); http.SetCookie(w, cookie); sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) { /* ...内容不变... */
	cookie, err := r.Cookie(sessionCookieName); if err == nil { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }; http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1}); http.Redirect(w, r, "/login.html", http.StatusFound)
}
func apiHandler(w http.ResponseWriter, r *http.Request) { /* ...内容不变... */
	w.Header().Set("Content-Type", "application/json"); switch { case r.URL.Path == "/api/online-users" && r.Method == "GET": var users []*OnlineUser; onlineUsers.Range(func(key, value interface{}) bool { users = append(users, value.(*OnlineUser)); return true }); json.NewEncoder(w).Encode(users); case r.URL.Path == "/api/accounts" && r.Method == "GET": globalConfig.lock.RLock(); defer globalConfig.lock.RUnlock(); json.NewEncoder(w).Encode(globalConfig.Accounts); case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST": username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); var accInfo AccountInfo; if err := json.NewDecoder(r.Body).Decode(&accInfo); err != nil { http.Error(w, `{"message":"无效的请求体"}`, http.StatusBadRequest); return }; globalConfig.lock.Lock(); globalConfig.Accounts[username] = accInfo; globalConfig.lock.Unlock(); if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置文件失败"}`, http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 添加成功", username)}); case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE": username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); globalConfig.lock.Lock(); delete(globalConfig.Accounts, username); globalConfig.lock.Unlock(); if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置文件失败"}` , http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 删除成功", username)}); case strings.HasSuffix(r.URL.Path, "/status") && r.Method == "PUT": pathParts := strings.Split(r.URL.Path, "/"); username := pathParts[3]; var payload struct { Enabled bool `json:"enabled"` }; if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { http.Error(w, `{"message":"无效的请求体"}`, http.StatusBadRequest); return }; globalConfig.lock.Lock(); if acc, ok := globalConfig.Accounts[username]; ok { acc.Enabled = payload.Enabled; globalConfig.Accounts[username] = acc }; globalConfig.lock.Unlock(); if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置文件失败"}`, http.StatusInternalServerError); return }; sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 状态更新成功", username)}); case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE": connID := strings.TrimPrefix(r.URL.Path, "/api/connections/"); if user, ok := onlineUsers.Load(connID); ok { user.(*OnlineUser).sshConn.Close(); removeOnlineUser(connID); sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"}) } else { sendJSON(w, http.StatusNotFound, map[string]string{"message": "连接未找到"}) }; default: http.NotFound(w, r) }
}

// main 函数
func main() {
	configFile, err := os.ReadFile("config.json"); if err != nil { log.Fatalf("FATAL: 无法读取 config.json 文件: %v", err) }
	globalConfig = &Config{}; err = json.Unmarshal(configFile, globalConfig); if err != nil { log.Fatalf("FATAL: 解析 config.json 文件失败: %v", err) }
	
	// --- 配置项检查和设置默认值 ---
	if globalConfig.ListenAddr == "" || len(globalConfig.AdminAccounts) == 0 { log.Fatalf("FATAL: config.json 缺少 'listen_addr' 或 'admin_accounts' 配置项") }
	if len(globalConfig.SocksAddrs) == 0 { log.Fatalf("FATAL: config.json 缺少 'socks_addrs' 配置项") }
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 3 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 64 }

	// --- 核心改动: 初始化代理池 ---
	poolLock.Lock()
	for _, addr := range globalConfig.SocksAddrs {
		proxyPool = append(proxyPool, &managedProxy{ addr: addr, activeConns: 0 })
	}
	poolLock.Unlock()

	log.Printf("Loaded %d SOCKS5 proxies into the pool for 'Least Connections' load balancing.", len(proxyPool))
	log.Printf("Handshake config: timeout=%ds, required UA='%s'", globalConfig.HandshakeTimeout, globalConfig.ConnectUA)
	log.Printf("Forwarding buffer size set to %d KB", globalConfig.BufferSizeKB)
	
	// --- 启动 Admin Web Panel ---
	go func() { /* ...内容不变... */
		mux := http.NewServeMux(); mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") }); mux.HandleFunc("/login", loginHandler); mux.HandleFunc("/logout", authMiddleware(logoutHandler)); mux.HandleFunc("/api/", authMiddleware(apiHandler)); adminHandler := func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }; mux.HandleFunc("/admin.html", authMiddleware(adminHandler)); mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { if r.URL.Path != "/" { http.NotFound(w, r); return }; if validateSession(r) { http.Redirect(w, r, "/admin.html", http.StatusFound) } else { http.Redirect(w, r, "/login.html", http.StatusFound) } }); log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr); if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { log.Fatalf("FATAL: 无法启动Admin panel: %v", err) }
	}()
	
	// --- SSH 服务器配置 ---
	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) { /* ...内容不变... */
			globalConfig.lock.RLock(); accountInfo, userExists := globalConfig.Accounts[c.User()]; globalConfig.lock.RUnlock(); if !userExists { log.Printf("Auth failed: user '%s' not found.", c.User()); return nil, fmt.Errorf("invalid credentials") }; if !accountInfo.Enabled { log.Printf("Auth failed: user '%s' is disabled.", c.User()); return nil, fmt.Errorf("invalid credentials") }; if accountInfo.ExpiryDate != "" { expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate); if err != nil { log.Printf("Auth failed: parse expiry date for user '%s'.", c.User()); return nil, fmt.Errorf("invalid credentials") }; if time.Now().After(expiry.Add(24 * time.Hour)) { log.Printf("Auth failed: user '%s' has expired.", c.User()); return nil, fmt.Errorf("invalid credentials") } }; if string(p) == accountInfo.Password { log.Printf("Auth successful for user: '%s'", c.User()); return nil, nil }; log.Printf("Auth failed: incorrect password for user '%s'", c.User()); return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)

	// --- 启动主监听服务 ---
	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s, forwarding to SOCKS5 pool", globalConfig.ListenAddr)

	for {
		conn, err := l.Accept()
		if err != nil { log.Printf("accept fail: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil { log.Printf("FATAL: Panic recovered in connection handler for %s: %v", c.RemoteAddr(), r) }
				c.Close()
			}()
			handleSshConnection(c, sshCfg)
		}(conn)
	}
}
