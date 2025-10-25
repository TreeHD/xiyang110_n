// main.go
package main

import (
	"bufio"
	"bytes"
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

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 ---

// AccountInfo 定义了每个隧道用户的详细信息
type AccountInfo struct {
	Password     string  `json:"password"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`  // 最大会话数
	FriendlyName string  `json:"friendly_name"` // 友好名称
}

// Config 定义了整个应用的配置
type Config struct {
	ListenAddr                  string                 `json:"listen_addr"`
	AdminAddr                   string                 `json:"admin_addr"`
	AdminAccounts               map[string]string      `json:"admin_accounts"`
	Accounts                    map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout            int                    `json:"handshake_timeout,omitempty"`
	ConnectUA                   string                 `json:"connect_ua,omitempty"`
	BufferSizeKB                int                    `json:"buffer_size_kb,omitempty"`
	IdleTimeoutSeconds          int                    `json:"idle_timeout_seconds,omitempty"`
	TolerantCopyMaxRetries      int                    `json:"tolerant_copy_max_retries,omitempty"`
	TolerantCopyRetryDelayMs    int                    `json:"tolerant_copy_retry_delay_ms,omitempty"`
	TargetConnectTimeoutSeconds int                    `json:"target_connect_timeout_seconds,omitempty"`
	DefaultExpiryDays           int                    `json:"default_expiry_days,omitempty"`
	DefaultLimitGB              float64                `json:"default_limit_gb,omitempty"`
	lock                        sync.RWMutex
}

var globalConfig *Config
var serverStartTime = time.Now()

// OnlineUser 存储了当前在线用户的信息
type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshConn     ssh.Conn
}

var onlineUsers sync.Map
var userConnectionCount sync.Map // map[string]*int32

// TrafficInfo 存储了用户的流量使用情况
type TrafficInfo struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

var globalTraffic sync.Map // map[string]*TrafficInfo

// LogCollector 用于在内存中收集日志
type LogCollector struct {
	mu     sync.RWMutex
	logs   []string
	maxCap int
}

func (lc *LogCollector) Write(p []byte) (n int, err error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	logLine := time.Now().Format("2006/01/02 15:04:05 ") + string(p)
	lc.logs = append(lc.logs, logLine)
	if len(lc.logs) > lc.maxCap {
		lc.logs = lc.logs[len(lc.logs)-lc.maxCap:]
	}
	// 同时将格式化后的日志输出到标准错误流（控制台）
	return os.Stderr.Write([]byte(logLine))
}
func (lc *LogCollector) GetLogs() []string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	// 返回副本以保证线程安全
	logsCopy := make([]string, len(lc.logs))
	copy(logsCopy, lc.logs)
	return logsCopy
}
var globalLog = &LogCollector{maxCap: 200}

// Session 管理
const sessionCookieName = "wstunnel_admin_session"
type Session struct{ Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
var bufferPool sync.Pool

// --- 辅助函数 ---

func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32)
	rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock()
	sessions[sessionToken] = Session{Username: username, Expiry: expiry}
	sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
}
func validateSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil { return "", false }
	sessionsLock.RLock()
	session, ok := sessions[cookie.Value]
	sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
		return "", false
	}
	return session.Username, true
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
func safeSaveConfig() error {
	globalConfig.lock.Lock()
	defer globalConfig.lock.Unlock()
	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	return ioutil.WriteFile("config.json", data, 0644)
}

// --- 核心数据转发逻辑 ---

type handshakeConn struct{ net.Conn; r io.Reader }
func (hc *handshakeConn) Read(p []byte) (n int, err error) { return hc.r.Read(p) }

func tolerantCopy(dst io.Writer, src io.Reader, direction string, remoteAddr net.Addr, username string) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
	traffic := val.(*TrafficInfo)

	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			nw, wErr := dst.Write(buf[0:nr])
			if nw > 0 {
				if direction == "Client->Target" {
					atomic.AddUint64(&traffic.Sent, uint64(nw))
				} else {
					atomic.AddUint64(&traffic.Received, uint64(nw))
				}
			}
			if wErr != nil { if wErr != io.EOF { globalLog.Write([]byte(fmt.Sprintf("Write error %s: %v\n", direction, wErr))) }; break }
			if nr != nw { globalLog.Write([]byte(fmt.Sprintf("Short write %s\n", direction))); break }
		}
		if rErr != nil { if rErr != io.EOF { globalLog.Write([]byte(fmt.Sprintf("Read error %s: %v\n", direction, rErr))) }; break }
	}
}
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr, username string) {
	destAddr := fmt.Sprintf("%s:%d", destHost, destPort)
	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil { ch.Close(); return }
	defer destConn.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer ch.CloseWrite(); tolerantCopy(destConn, ch, "Client->Target", remoteAddr, username) }()
	go func() { defer wg.Done(); defer destConn.Close(); tolerantCopy(ch, destConn, "Target->Client", remoteAddr, username) }()
	wg.Wait()
}

// --- SSH & HTTP 握手与连接管理 ---

func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Duration(globalConfig.HandshakeTimeout) * time.Second))
	reader := bufio.NewReader(c)
	req, err := http.ReadRequest(reader)
	if err != nil { return }
	io.Copy(ioutil.Discard, req.Body)
	req.Body.Close()
	if !strings.Contains(req.UserAgent(), globalConfig.ConnectUA) { return }
	c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))

	var preReadData []byte
	if reader.Buffered() > 0 { preReadData, _ = ioutil.ReadAll(reader) }
	finalReader := io.MultiReader(bytes.NewReader(preReadData), c)
	connForSSH := &handshakeConn{Conn: c, r: finalReader}
	
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(connForSSH, sshCfg)
	if err != nil { globalLog.Write([]byte(fmt.Sprintf("SSH handshake failed for %s: %v\n", c.RemoteAddr(), err))); return }
	c.SetReadDeadline(time.Time{})
	defer sshConn.Close()
	
	username := sshConn.User()
	defer func() {
		if val, ok := userConnectionCount.Load(username); ok {
			atomic.AddInt32(val.(*int32), -1)
		}
	}()

	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ConnID: connID, Username: username, RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn}
	onlineUsers.Store(onlineUser.ConnID, onlineUser)
	globalLog.Write([]byte(fmt.Sprintf("Auth success for user '%s' from %s\n", username, sshConn.RemoteAddr())))
	defer onlineUsers.Delete(onlineUser.ConnID)
	
	go ssh.DiscardRequests(reqs)
	
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "unsupported"); continue }
		ch, _, err := newChan.Accept()
		if err != nil { continue }
		var payload struct { Host string; Port uint32 }
		ssh.Unmarshal(newChan.ExtraData(), &payload)
		go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr(), username)
	}
}


// --- Web服务器逻辑 ---

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := validateSession(r); ok { next.ServeHTTP(w, r); return }
		if strings.HasPrefix(r.URL.Path, "/api/") { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		} else { http.Redirect(w, r, "/login.html", http.StatusFound) }
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct{ Username, Password string }
	json.NewDecoder(r.Body).Decode(&creds)
	globalConfig.lock.RLock()
	p, ok := globalConfig.AdminAccounts[creds.Username]
	globalConfig.lock.RUnlock()
	if !ok || p != creds.Password { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"}); return }
	http.SetCookie(w, createSession(creds.Username))
	sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionCookieName)
	if cookie != nil { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login.html", http.StatusFound)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/server_status":
		var globalSent, globalRcvd uint64
		globalTraffic.Range(func(_, v interface{}) bool {
			t := v.(*TrafficInfo)
			globalSent += atomic.LoadUint64(&t.Sent)
			globalRcvd += atomic.LoadUint64(&t.Received)
			return true
		})
		var activeConns int
		onlineUsers.Range(func(_, _ interface{}) bool { activeConns++; return true })
		cpuPercent, _ := cpu.Percent(0, false)
		memInfo, _ := mem.VirtualMemory()
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"uptime": time.Since(serverStartTime).Round(time.Second).String(), "active_conns": activeConns,
			"global_sent": globalSent, "global_rcvd": globalRcvd, "cpu_percent": cpuPercent[0],
			"mem_percent": memInfo.UsedPercent, "mem_used_bytes": memInfo.Used, "mem_total_bytes": memInfo.Total,
		})
	case r.URL.Path == "/api/connections":
		var conns []map[string]interface{}
		onlineUsers.Range(func(_, v interface{}) bool {
			u := v.(*OnlineUser)
			globalConfig.lock.RLock()
			acc, ok := globalConfig.Accounts[u.Username]
			globalConfig.lock.RUnlock()
			if !ok { return true }
			t_val, _ := globalTraffic.LoadOrStore(u.Username, &TrafficInfo{})
			t := t_val.(*TrafficInfo)
			usedBytes := atomic.LoadUint64(&t.Sent) + atomic.LoadUint64(&t.Received)
			var remainingBytes int64 = -1
			if acc.LimitGB > 0 { remainingBytes = int64(acc.LimitGB*1e9) - int64(usedBytes); if remainingBytes < 0 { remainingBytes = 0 } }
			conns = append(conns, map[string]interface{}{ "conn_id": u.ConnID, "username": u.Username, "ip": u.RemoteAddr, "connect_time": u.ConnectTime, "expiry_date": acc.ExpiryDate, "used_bytes": usedBytes, "remaining_bytes": remainingBytes })
			return true
		})
		sendJSON(w, http.StatusOK, conns)
	case r.URL.Path == "/api/accounts":
		globalConfig.lock.RLock(); defer globalConfig.lock.RUnlock(); sendJSON(w, http.StatusOK, globalConfig.Accounts)
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); var accInfo AccountInfo; json.NewDecoder(r.Body).Decode(&accInfo)
		globalConfig.lock.Lock(); globalConfig.Accounts[username] = accInfo; globalConfig.lock.Unlock(); safeSaveConfig()
		sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 更新成功"})
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/"); globalConfig.lock.Lock(); delete(globalConfig.Accounts, username); globalConfig.lock.Unlock(); safeSaveConfig()
		sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 删除成功"})
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		connID := strings.TrimPrefix(r.URL.Path, "/api/connections/");
		if user, ok := onlineUsers.Load(connID); ok { user.(*OnlineUser).sshConn.Close(); sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"}) }
	case r.URL.Path == "/api/accounts/set_status" && r.Method == "POST":
		var p struct { Username string; Enabled bool }; json.NewDecoder(r.Body).Decode(&p)
		globalConfig.lock.Lock()
		if acc, ok := globalConfig.Accounts[p.Username]; ok {
			acc.Enabled = p.Enabled; globalConfig.Accounts[p.Username] = acc
			if !p.Enabled { onlineUsers.Range(func(_, v interface{}) bool { u := v.(*OnlineUser); if u.Username == p.Username { u.sshConn.Close() }; return true }) }
		}
		globalConfig.lock.Unlock(); safeSaveConfig(); sendJSON(w, http.StatusOK, map[string]string{"message": "状态更新成功"})
	case r.URL.Path == "/api/admin/update_password" && r.Method == "POST":
		var p struct { OldPassword, NewPassword string }; json.NewDecoder(r.Body).Decode(&p)
		user, _ := validateSession(r); globalConfig.lock.Lock()
		if globalConfig.AdminAccounts[user] == p.OldPassword { globalConfig.AdminAccounts[user] = p.NewPassword; safeSaveConfig(); sendJSON(w, http.StatusOK, map[string]string{"message": "密码更新成功"})
		} else { sendJSON(w, http.StatusForbidden, map[string]string{"message": "旧密码错误"}) }
		globalConfig.lock.Unlock()
	case r.URL.Path == "/api/settings":
		if r.Method == "GET" { globalConfig.lock.RLock(); defer globalConfig.lock.RUnlock(); sendJSON(w, http.StatusOK, globalConfig) }
		if r.Method == "POST" { var newSettings Config; json.NewDecoder(r.Body).Decode(&newSettings)
			globalConfig.lock.Lock()
			// Update only UI-editable fields
			globalConfig.HandshakeTimeout = newSettings.HandshakeTimeout; globalConfig.ConnectUA = newSettings.ConnectUA; globalConfig.BufferSizeKB = newSettings.BufferSizeKB; globalConfig.IdleTimeoutSeconds = newSettings.IdleTimeoutSeconds; globalConfig.TolerantCopyMaxRetries = newSettings.TolerantCopyMaxRetries; globalConfig.TolerantCopyRetryDelayMs = newSettings.TolerantCopyRetryDelayMs; globalConfig.TargetConnectTimeoutSeconds = newSettings.TargetConnectTimeoutSeconds; globalConfig.DefaultExpiryDays = newSettings.DefaultExpiryDays; globalConfig.DefaultLimitGB = newSettings.DefaultLimitGB
			globalConfig.lock.Unlock(); safeSaveConfig(); bufferPool = sync.Pool{New: func() interface{} { buf := make([]byte, globalConfig.BufferSizeKB*1024); return &buf }}; sendJSON(w, http.StatusOK, map[string]string{"message": "设置已保存"})
		}
	case r.URL.Path == "/api/logs": sendJSON(w, http.StatusOK, globalLog.GetLogs())
	case r.URL.Path == "/api/traffic":
		trafficData := make(map[string]*TrafficInfo); globalTraffic.Range(func(k, v interface{}) bool { trafficData[k.(string)] = v.(*TrafficInfo); return true }); sendJSON(w, http.StatusOK, trafficData)
	case r.URL.Path == "/api/accounts/reset-traffic":
		var p struct { Username string }; json.NewDecoder(r.Body).Decode(&p)
		if v, ok := globalTraffic.Load(p.Username); ok { t := v.(*TrafficInfo); atomic.StoreUint64(&t.Sent, 0); atomic.StoreUint64(&t.Received, 0); sendJSON(w, http.StatusOK, map[string]string{"message": "流量已重置"}) }
	case r.URL.Path == "/api/whoami":
		if user, ok := validateSession(r); ok { sendJSON(w, http.StatusOK, map[string]string{"username": user}) }
	default: http.NotFound(w, r)
	}
}

// --- main ---
func main() {
	log.SetOutput(globalLog)
	log.SetFlags(0)
	configFile, err := os.ReadFile("config.json"); if err != nil { log.Fatalf("FATAL: Cannot read config.json: %v", err) }
	globalConfig = &Config{}; if json.Unmarshal(configFile, globalConfig) != nil { log.Fatalf("FATAL: Cannot parse config.json") }
	
	// Set defaults
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "wstunnel" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 32 }
	if globalConfig.DefaultExpiryDays <= 0 { globalConfig.DefaultExpiryDays = 30 }

	bufferPool = sync.Pool{New: func() interface{} { buf := make([]byte, globalConfig.BufferSizeKB*1024); return &buf }}
	
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") })
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", logoutHandler)
		mux.HandleFunc("/api/", authMiddleware(apiHandler))
		mux.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) { 
			if r.URL.Path == "/" {
				http.ServeFile(w, r, "admin.html")
				return
			}
			http.NotFound(w,r)
		}))
		log.Printf("Admin panel listening on http://%s\n", globalConfig.AdminAddr)
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { log.Fatalf("FATAL: Cannot start admin panel: %v", err) }
	}()
	
	sshCfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-WSTunnel_Pro",
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			user := c.User()
			globalConfig.lock.RLock()
			acc, ok := globalConfig.Accounts[user]
			globalConfig.lock.RUnlock()
			if !ok || !acc.Enabled { return nil, fmt.Errorf("auth failed") }
			if acc.ExpiryDate != "" {
				exp, err := time.Parse("2006-01-02", acc.ExpiryDate)
				if err != nil || time.Now().After(exp.Add(24*time.Hour)) { return nil, fmt.Errorf("user expired") }
			}
			if acc.LimitGB > 0 {
				v, _ := globalTraffic.LoadOrStore(user, &TrafficInfo{}); t := v.(*TrafficInfo)
				if atomic.LoadUint64(&t.Sent)+atomic.LoadUint64(&t.Received) >= uint64(acc.LimitGB*1e9) { return nil, fmt.Errorf("traffic limit exceeded") }
			}
			if acc.MaxSessions > 0 {
				v, _ := userConnectionCount.LoadOrStore(user, new(int32)); countPtr := v.(*int32)
				if atomic.LoadInt32(countPtr) >= int32(acc.MaxSessions) { return nil, fmt.Errorf("max sessions exceeded") }
				atomic.AddInt32(countPtr, 1)
			}
			if string(p) == acc.Password { return nil, nil }
			if acc.MaxSessions > 0 {
				if v, ok := userConnectionCount.Load(user); ok { atomic.AddInt32(v.(*int32), -1) }
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader); key, _ := ssh.NewSignerFromKey(priv); sshCfg.AddHostKey(key)

	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("FATAL: Cannot listen on %s: %v", globalConfig.ListenAddr, err) }
	log.Printf("SSH server listening on %s\n", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept(); if err != nil { continue }
		go handleSshConnection(conn, sshCfg)
	}
}
