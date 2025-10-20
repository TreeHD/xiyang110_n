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

// --- 结构体等定义 (无改动) ---
type AccountInfo struct { Password   string `json:"password"`; Enabled    bool   `json:"enabled"`; ExpiryDate string `json:"expiry_date"` }
type Config struct { ListenAddr string `json:"listen_addr"`; SocksAddr string `json:"socks_addr"`; AdminAddr string `json:"admin_addr"`; AdminAccounts map[string]string `json:"admin_accounts"`; Accounts map[string]AccountInfo `json:"accounts"`; lock sync.RWMutex }
var globalConfig *Config
var activeConn int64
type OnlineUser struct { ConnID string `json:"conn_id"`; Username string `json:"username"`; RemoteAddr string `json:"remote_addr"`; ConnectTime time.Time `json:"connect_time"`; sshConn ssh.Conn }
var onlineUsers sync.Map
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
func createSession(username string) *http.Cookie { /* ...内容不变... */
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes); sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour); sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}
func validateSession(r *http.Request) bool { /* ...内容不变... */
	cookie, err := r.Cookie(sessionCookieName); if err != nil { return false }
	sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) { if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }; return false }
	return true
}

// --- 网络核心逻辑 (无改动) ---
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) { /* ...内容不变... */
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
	_, err = c.Write([]byte{0x05, 0x01, 0x00}); if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2); if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}; req = append(req, []byte(destHost)...); req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err = c.Write(req); err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4); if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed") }
	switch rep[3] { case 0x01: io.CopyN(io.Discard, c, 4+2); case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2); case 0x04: io.CopyN(io.Discard, c, 16+2) }
	return c, nil
}
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) { /* ...内容不变... */
	atomic.AddInt64(&activeConn, 1); defer atomic.AddInt64(&activeConn, -1)
	globalConfig.lock.RLock(); socksServerAddr := globalConfig.SocksAddr; globalConfig.lock.RUnlock()
	socksConn, err := socks5Connect(socksServerAddr, destHost, uint16(destPort)); if err != nil { log.Printf("connect to SOCKS5 fail: %v", err); ch.Close(); return }
	defer socksConn.Close()
	done := make(chan struct{}, 2); go func() { io.Copy(socksConn, ch); socksConn.Close(); done <- struct{}{} }(); go func() { io.Copy(ch, socksConn); ch.Close(); done <- struct{}{} }(); <-done
}
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) { /* ...内容不变... */
	reader := bufio.NewReader(conn); req, err := http.ReadRequest(reader); if err != nil { return nil, fmt.Errorf("read http request fail: %v", err) }
	io.Copy(ioutil.Discard, req.Body); req.Body.Close()
	if strings.Contains(req.UserAgent(), "26.4.0") {
		_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); if err != nil { return nil, fmt.Errorf("write http response fail: %v", err) }
		return &combinedConn{ Conn: conn, reader: io.MultiReader(reader, conn), }, nil
	}
	return nil, fmt.Errorf("invalid user-agent")
}
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) { /* ...内容不变... */
	handshakedConn, err := httpHandshake(c); if err != nil { log.Printf("http handshake failed: %v", err); c.Close(); return }
	log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg); if err != nil { log.Printf("ssh handshake failed for %s: %v", c.RemoteAddr(), err); c.Close(); return }
	defer sshConn.Close()
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn, }; addOnlineUser(onlineUser)
	log.Printf("Phase 2: SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User()); defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed"); continue }
		ch, _, err := newChan.Accept(); if err != nil { log.Printf("accept channel fail: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }; if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("bad payload: %v", err); ch.Close(); continue }
		go handleDirectTCPIP(ch, payload.Host, payload.Port)
	}
}
func safeSaveConfig() error { /* ...内容不变... */
	globalConfig.lock.Lock(); defer globalConfig.lock.Unlock()
	data, err := json.MarshalIndent(globalConfig, "", "  "); if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	return ioutil.WriteFile("config.json", data, 0644)
}

// 辅助函数，用于发送JSON响应
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// ==============================================================================
// === 核心修改点 1: 修改 Web 服务器逻辑 ===
// ==============================================================================

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validateSession(r) {
			next.ServeHTTP(w, r)
		} else {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
			} else {
				// [修改点] 对于页面请求，直接返回登录页，而不是重定向，这样更清晰
				http.ServeFile(w, r, "login.html")
			}
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"}); return
	}
	
	var creds struct { Username string `json:"username"`; Password string `json:"password"` }
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的请求格式"}); return
	}

	globalConfig.lock.RLock()
	storedPass, ok := globalConfig.AdminAccounts[creds.Username]
	globalConfig.lock.RUnlock()

	if !ok || creds.Password != storedPass {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return
	}

	cookie := createSession(creds.Username)
	http.SetCookie(w, cookie)
	// [修改点] 登录成功也返回一个明确的JSON响应
	sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}

// 登出处理器 (无改动)
func logoutHandler(w http.ResponseWriter, r *http.Request) { /* ...内容不变... */
	cookie, err := r.Cookie(sessionCookieName); if err == nil { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1}); http.Redirect(w, r, "/login.html", http.StatusFound) // 改为重定向到login.html
}

// API处理器 (无改动)
func apiHandler(w http.ResponseWriter, r *http.Request) { /* ...内容不变... */
	// ...
}

func main() {
	configFile, err := os.ReadFile("config.json"); if err != nil { log.Fatalf("FATAL: 无法读取 config.json 文件: %v", err) }
	globalConfig = &Config{}; err = json.Unmarshal(configFile, globalConfig); if err != nil { log.Fatalf("FATAL: 解析 config.json 文件失败: %v", err) }
	if globalConfig.ListenAddr == "" || globalConfig.SocksAddr == "" || len(globalConfig.AdminAccounts) == 0 { log.Fatalf("FATAL: config.json 缺少必要配置项") }
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	
	go func() {
		mux := http.NewServeMux()
		
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", authMiddleware(logoutHandler))

		// [修改点] 更明确的路由规则
		// 根路径 "/" 由中间件处理，如果未登录会显示 login.html
		rootHandler := func(w http.ResponseWriter, r *http.Request) {
			// 如果已经登录，直接显示 admin.html
			http.ServeFile(w, r, "admin.html")
		}
		mux.HandleFunc("/", authMiddleware(rootHandler))

		// 为 admin.html 也添加一个明确的路由，同样受保护
		mux.HandleFunc("/admin.html", authMiddleware(rootHandler))
		
		mux.HandleFunc("/api/", authMiddleware(apiHandler))

		log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr)
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil {
			log.Fatalf("FATAL: 无法启动Admin panel: %v", err)
		}
	}()

	
	sshCfg := &ssh.ServerConfig{ /* ...内容不变... */
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) { 
			globalConfig.lock.RLock(); accountInfo, userExists := globalConfig.Accounts[c.User()]; globalConfig.lock.RUnlock()
			if !userExists { log.Printf("Auth failed: user '%s' not found.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			if !accountInfo.Enabled { log.Printf("Auth failed: user '%s' is disabled.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			if accountInfo.ExpiryDate != "" {
				expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate); if err != nil { log.Printf("Auth failed: parse expiry date for user '%s'.", c.User()); return nil, fmt.Errorf("invalid credentials") }
				if time.Now().After(expiry.Add(24 * time.Hour)) { log.Printf("Auth failed: user '%s' has expired.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			}
			if string(p) == accountInfo.Password { log.Printf("Auth successful for user: '%s'", c.User()); return nil, nil }
			log.Printf("Auth failed: incorrect password for user '%s'", c.User()); return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s, forwarding to SOCKS5 %s", globalConfig.ListenAddr, globalConfig.SocksAddr)

	for {
		conn, err := l.Accept(); if err != nil { log.Printf("accept fail: %v", err); continue }
		go handleSshConnection(conn, sshCfg)
	}
}
