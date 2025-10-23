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

	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 ---
type AccountInfo struct {
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"`
}

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
	lock                        sync.RWMutex
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

// [核心优化 1/3] 定义一个全局的缓冲区池
var bufferPool sync.Pool

type handshakeConn struct {
	net.Conn
	r io.Reader
}
func (hc *handshakeConn) Read(p []byte) (n int, err error) {
	return hc.r.Read(p)
}

// --- 辅助函数 ---
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }

func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32)
	rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock()
	sessions[sessionToken] = Session{Username: username, Expiry: expiry}
	sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}

func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil { return false }
	sessionsLock.RLock()
	session, ok := sessions[cookie.Value]
	sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok {
			sessionsLock.Lock()
			delete(sessions, cookie.Value)
			sessionsLock.Unlock()
		}
		return false
	}
	return true
}

func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// --- 核心数据转发逻辑 (最终优化版) ---
func tolerantCopy(dst io.Writer, src io.Reader, direction string, remoteAddr net.Addr) {
	// [核心优化 2/3] 从池中获取缓冲区，并在函数结束时归还
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr
	
	maxRetries := globalConfig.TolerantCopyMaxRetries
	retryDelay := time.Duration(globalConfig.TolerantCopyRetryDelayMs) * time.Millisecond
	consecutiveTempErrors := 0

	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			nw, wErr := dst.Write(buf[0:nr])
			if wErr != nil {
				// [健壮性优化] 如果写入时遇到EOF，说明对端关闭了写，是正常情况，直接退出
				if wErr == io.EOF {
					break
				}
				log.Printf("TCP Proxy (%s): Permanent write error for %s, closing connection: %v", direction, remoteAddr, wErr)
				break
			}
			if nr != nw {
				log.Printf("TCP Proxy (%s): Short write for %s, closing connection", direction, remoteAddr)
				break
			}
			consecutiveTempErrors = 0
		}

		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			if netErr, ok := rErr.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				consecutiveTempErrors++
				if consecutiveTempErrors > maxRetries {
					log.Printf("TCP Proxy (%s): Too many consecutive temporary errors for %s, giving up. Last error: %v", direction, remoteAddr, rErr)
					break
				}
				log.Printf("TCP Proxy (%s): Temporary network error for %s: %v. Retrying in %v... (Attempt %d/%d)", direction, remoteAddr, rErr, retryDelay, consecutiveTempErrors, maxRetries)
				time.Sleep(retryDelay)
				continue
			}
			log.Printf("TCP Proxy (%s): Unrecoverable read error for %s, closing connection: %v", direction, remoteAddr, rErr)
			break
		}
	}
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)
	var destAddr string
	if strings.Contains(destHost, ":") {
		destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort)
	} else {
		destAddr = fmt.Sprintf("%s:%d", destHost, destPort)
	}
	connectTimeout := time.Duration(globalConfig.TargetConnectTimeoutSeconds) * time.Second
	destConn, err := net.DialTimeout("tcp", destAddr, connectTimeout)
	if err != nil {
		log.Printf("TCP Proxy: Failed to connect to %s: %v", destAddr, err)
		ch.Close()
		return
	}
	defer destConn.Close()
	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(1 * time.Minute)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if tcpConn, ok := destConn.(*net.TCPConn); ok {
			defer tcpConn.CloseWrite()
		} else {
			// 对于非TCPConn，例如ssh.Channel，我们只能完全关闭
			defer destConn.Close()
		}
		tolerantCopy(destConn, ch, "Client->Target", remoteAddr)
	}()
	go func() {
		defer wg.Done()
		defer ch.CloseWrite()
		tolerantCopy(ch, destConn, "Target->Client", remoteAddr)
	}()
	wg.Wait()
}


// --- SSH & HTTP 握手与连接管理 ---
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				log.Printf("Keepalive to %s failed: %v.", sshConn.RemoteAddr(), err)
				return
			}
		case <-done:
			return
		}
	}
}
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer c.Close()

	// [修复] 从配置中获取总的握手超时时长
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second
	
	// [修复] 记录整个握手过程的开始时间，用于设置一个绝对的超时
	handshakeStartTime := time.Now()

	expectedUA := globalConfig.ConnectUA
	reader := bufio.NewReader(c)

	for {
		// [修复] 检查是否超过了绝对的超时时间
		if time.Since(handshakeStartTime) > timeoutDuration {
			log.Printf("Absolute handshake timeout for %s after %v", c.RemoteAddr(), timeoutDuration)
			return // 超过总时长，直接返回并关闭连接
		}

		// [保留] 为本次读取操作设置一个相对的空闲超时
		// 这可以防止客户端连接后什么都不发，导致I/O一直阻塞
		if err := c.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil {
			log.Printf("Failed to set read deadline for %s: %v", c.RemoteAddr(), err)
			return
		}

		for {
			peekBytes, err := reader.Peek(1)
			if err != nil {
				if err != io.EOF { log.Printf("Peek error from %s: %v", c.RemoteAddr(), err) }
				return
			}
			if peekBytes[0] == '\r' || peekBytes[0] == '\n' {
				reader.ReadByte()
				continue
			}
			break
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF { log.Printf("Handshake read error from %s: %v", c.RemoteAddr(), err) }
			return
		}
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()
		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if err != nil { log.Printf("Write 101 response fail for %s: %v", c.RemoteAddr(), err); return }
			break // 握手成功，跳出循环
		} else {
			log.Printf("Incorrect handshake payload from %s (UA: %s). Waiting.", c.RemoteAddr(), req.UserAgent())
			_, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"))
			if err != nil { log.Printf("Write fake 200 OK response fail for %s: %v", c.RemoteAddr(), err); return }
			continue // 握手失败，继续循环等待，但会受到顶部的绝对超时检查的限制
		}
	}

	// 从这里开始是握手成功后的逻辑，和之前保持一致
	log.Printf("HTTP handshake successful for %s. Delaying for 500ms before starting SSH.", c.RemoteAddr())
	time.Sleep(500 * time.Millisecond)
	var preReadData []byte
	if reader.Buffered() > 0 {
		preReadData = make([]byte, reader.Buffered())
		n, _ := reader.Read(preReadData)
		preReadData = preReadData[:n]
		log.Printf("Drained %d bytes of pre-read data from %s", n, c.RemoteAddr())
	}
	finalReader := io.MultiReader(bytes.NewReader(preReadData), c)
	connForSSH := &handshakeConn{Conn: c, r: finalReader}
	sshHandshakeTimeout := 15 * time.Second
	if err := connForSSH.SetDeadline(time.Now().Add(sshHandshakeTimeout)); err != nil {
		log.Printf("Failed to set SSH handshake deadline for %s: %v", c.RemoteAddr(), err)
		return
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(connForSSH, sshCfg)
	if err != nil {
		log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err)
		return
	}
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	if idleTimeout > 0 {
		if err := connForSSH.SetDeadline(time.Time{}); err != nil {
			log.Printf("Failed to clear SSH handshake deadline for %s: %v", c.RemoteAddr(), err)
			sshConn.Close()
			return
		}
		doneDeadline := make(chan struct{})
		defer close(doneDeadline)
		go func() {
			ticker := time.NewTicker(idleTimeout / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					err := c.SetReadDeadline(time.Now().Add(idleTimeout))
					if err != nil {
						log.Printf("Failed to set idle timeout for %s, stopping deadline updates: %v", c.RemoteAddr(), err)
						return
					}
				case <-doneDeadline:
					return
				}
			}
		}()
	} else {
		if err := connForSSH.SetDeadline(time.Time{}); err != nil {
			log.Printf("Failed to clear SSH handshake deadline for %s: %v", c.RemoteAddr(), err)
			sshConn.Close()
			return
		}
	}
	defer sshConn.Close()
	done := make(chan struct{})
	defer close(done)
	go sendKeepAlives(sshConn, done)
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn}
	addOnlineUser(onlineUser)
	log.Printf("SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User())
	defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip is allowed")
			continue
		}
		ch, _, err := newChan.Accept()
		if err != nil { log.Printf("Failed to accept channel: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			log.Printf("Invalid direct-tcpip payload: %v", err)
			ch.Close()
			continue
		}
		go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr())
	}
}

// --- Web服务器逻辑 ---
func safeSaveConfig() error {
	globalConfig.lock.Lock()
	defer globalConfig.lock.Unlock()
	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	return ioutil.WriteFile("config.json", data, 0644)
}
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validateSession(r) { next.ServeHTTP(w, r)
		} else {
			if strings.HasPrefix(r.URL.Path, "/api/") { sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
			} else { http.Redirect(w, r, "/login.html", http.StatusFound) }
		}
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var creds struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	globalConfig.lock.RLock()
	storedPass, ok := globalConfig.AdminAccounts[creds.Username]
	globalConfig.lock.RUnlock()
	if !ok || creds.Password != storedPass {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	cookie := createSession(creds.Username)
	http.SetCookie(w, cookie)
	sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionsLock.Lock()
		delete(sessions, cookie.Value)
		sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login.html", http.StatusFound)
}
func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/online-users" && r.Method == "GET":
		var users []*OnlineUser
		onlineUsers.Range(func(key, value interface{}) bool {
			u := value.(*OnlineUser)
			users = append(users, &OnlineUser{ ConnID: u.ConnID, Username: u.Username, RemoteAddr: u.RemoteAddr, ConnectTime: u.ConnectTime, })
			return true
		})
		json.NewEncoder(w).Encode(users)
	case r.URL.Path == "/api/accounts" && r.Method == "GET":
		globalConfig.lock.RLock()
		defer globalConfig.lock.RUnlock()
		json.NewEncoder(w).Encode(globalConfig.Accounts)
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
		var accInfo AccountInfo
		if err := json.NewDecoder(r.Body).Decode(&accInfo); err != nil { http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest); return }
		globalConfig.lock.Lock()
		globalConfig.Accounts[username] = accInfo
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 添加成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
		globalConfig.lock.Lock()
		delete(globalConfig.Accounts, username)
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 删除成功", username)})
	case strings.HasSuffix(r.URL.Path, "/status") && r.Method == "PUT":
		pathParts := strings.Split(r.URL.Path, "/")
		username := pathParts[3]
		var payload struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest); return }
		globalConfig.lock.Lock()
		if acc, ok := globalConfig.Accounts[username]; ok {
			acc.Enabled = payload.Enabled
			globalConfig.Accounts[username] = acc
		}
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil { http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError); return }
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 状态更新成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		connID := strings.TrimPrefix(r.URL.Path, "/api/connections/")
		if user, ok := onlineUsers.Load(connID); ok {
			user.(*OnlineUser).sshConn.Close()
			removeOnlineUser(connID)
			sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"})
		} else { sendJSON(w, http.StatusNotFound, map[string]string{"message": "连接未找到"}) }
	default:
		http.NotFound(w, r)
	}
}

// --- main ---
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configFile, err := os.ReadFile("config.json")
	if err != nil { log.Fatalf("FATAL: 无法读取 config.json: %v", err) }
	globalConfig = &Config{}
	err = json.Unmarshal(configFile, globalConfig)
	if err != nil { log.Fatalf("FATAL: 解析 config.json 失败: %v", err) }
	if globalConfig.ListenAddr == "" || len(globalConfig.AdminAccounts) == 0 { log.Fatalf("FATAL: config.json 缺少 listen_addr 或 admin_accounts") }

	// 设置默认值
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 32 } // 默认32KB
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 120 }
	if globalConfig.TolerantCopyMaxRetries <= 0 { globalConfig.TolerantCopyMaxRetries = 100 }
	if globalConfig.TolerantCopyRetryDelayMs <= 0 { globalConfig.TolerantCopyRetryDelayMs = 500 }
	if globalConfig.TargetConnectTimeoutSeconds <= 0 { globalConfig.TargetConnectTimeoutSeconds = 10 }
	
	// [核心优化 3/3] 在 main 函数中，根据配置文件的大小初始化 bufferPool
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, globalConfig.BufferSizeKB*1024)
			return &buf
		},
	}

	log.Println("====== WSTUNNEL (Pure TCP Proxy Mode with Buffer Pool) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds",
		globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)
	log.Printf("Config: TolerantCopy(MaxRetries=%d, RetryDelay=%dms), TargetConnectTimeout=%ds",
		globalConfig.TolerantCopyMaxRetries, globalConfig.TolerantCopyRetryDelayMs, globalConfig.TargetConnectTimeoutSeconds)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") })
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", authMiddleware(logoutHandler))
		mux.HandleFunc("/api/", authMiddleware(apiHandler))
		adminHandler := func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }
		mux.HandleFunc("/admin.html", authMiddleware(adminHandler))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" { http.NotFound(w, r); return }
			if validateSession(r) { http.Redirect(w, r, "/admin.html", http.StatusFound) } else { http.Redirect(w, r, "/login.html", http.StatusFound) }
		})
		log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr)
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { log.Fatalf("FATAL: 无法启动Admin panel: %v", err) }
	}()
	
	sshCfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-WSTunnel_v3.1_by_xiaoguiday", // Minor version bump
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			globalConfig.lock.RLock()
			accountInfo, userExists := globalConfig.Accounts[c.User()]
			globalConfig.lock.RUnlock()
			if !userExists { return nil, fmt.Errorf("user not found") }
			if !accountInfo.Enabled { return nil, fmt.Errorf("user disabled") }
			if accountInfo.ExpiryDate != "" {
				expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate)
				if err != nil || time.Now().After(expiry.Add(24*time.Hour)) { return nil, fmt.Errorf("user expired") }
			}
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
		conn, err := l.Accept()
		if err != nil { log.Printf("Accept failed: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(1 * time.Minute)
			tcpConn.SetNoDelay(true)
		}
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("FATAL: Panic recovered for %s: %v", c.RemoteAddr(), r)
				}
			}()
			handleSshConnection(c, sshCfg)
		}(conn)
	}
}
