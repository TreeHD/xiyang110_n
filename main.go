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
	if err != nil {
		return false
	}
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

// --- 核心数据转发逻辑 ---
var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, 64*1024); return &b }}

func timedCopy(dst io.Writer, src io.Reader, timeout time.Duration) (written int64, err error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		if srcConn, ok := src.(net.Conn); ok {
			if err := srcConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return written, err
			}
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if dstConn, ok := dst.(net.Conn); ok {
				if err := dstConn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
					return written, err
				}
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrShortWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if netErr, ok := er.(net.Error); ok && netErr.Timeout() {
				err = nil
			} else if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// [最终修正] 确保调用的是 handleSocks5UDP
	if destPort == 7300 {
		log.Printf("Detected UDP request on port 7300 from %s", remoteAddr)
		handleSocks5UDP(ch, remoteAddr) 
		return
	}

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

// --- SSH & HTTP 握手与连接管理 ---
type combinedConn struct {
	net.Conn
	reader io.Reader
}

func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }

func httpHandshake(conn net.Conn) (net.Conn, error) {
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second
	expectedUA := globalConfig.ConnectUA
	reader := bufio.NewReader(conn)
	
	for {
		if err := conn.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil {
			return nil, fmt.Errorf("failed to set read deadline: %v", err)
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, fmt.Errorf("handshake timeout: %v", timeoutDuration)
			}
			return nil, fmt.Errorf("read http request fail: %v", err)
		}
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()
		
		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if err != nil {
				return nil, fmt.Errorf("write http response fail: %v", err)
			}
			conn.SetReadDeadline(time.Time{})
			return &combinedConn{Conn: conn, reader: io.MultiReader(reader, conn)}, nil
		} else {
			log.Printf("Incorrect handshake payload from %s (UA: %s). Waiting.", conn.RemoteAddr(), req.UserAgent())
			_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"))
			if err != nil {
				return nil, fmt.Errorf("write fake 200 OK response fail: %v", err)
			}
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
			if err != nil {
				log.Printf("Keepalive to %s failed: %v.", sshConn.RemoteAddr(), err)
				return
			}
		case <-done:
			log.Printf("Keepalive for %s stopped.", sshConn.RemoteAddr())
			return
		}
	}
}

func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
	defer c.Close()
	handshakedConn, err := httpHandshake(c)
	if err != nil {
		log.Printf("HTTP handshake failed for %s: %v", c.RemoteAddr(), err)
		return
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg)
	if err != nil {
		log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err)
		return
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
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			continue
		}
		var payload struct {
			Host       string
			Port       uint32
			OriginAddr string
			OriginPort uint32
		}
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
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return ioutil.WriteFile("config.json", data, 0644)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if validateSession(r) {
			next.ServeHTTP(w, r)
		} else {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
			} else {
				http.Redirect(w, r, "/login.html", http.StatusFound)
			}
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var creds struct {
		Username, Password string
	}
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
			users = append(users, value.(*OnlineUser))
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
		if err := json.NewDecoder(r.Body).Decode(&accInfo); err != nil {
			http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest)
			return
		}
		globalConfig.lock.Lock()
		globalConfig.Accounts[username] = accInfo
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil {
			http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError)
			return
		}
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 添加成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
		globalConfig.lock.Lock()
		delete(globalConfig.Accounts, username)
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil {
			http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError)
			return
		}
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 删除成功", username)})
	case strings.HasSuffix(r.URL.Path, "/status") && r.Method == "PUT":
		pathParts := strings.Split(r.URL.Path, "/")
		username := pathParts[3]
		var payload struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"message":"无效请求体"}`, http.StatusBadRequest)
			return
		}
		globalConfig.lock.Lock()
		if acc, ok := globalConfig.Accounts[username]; ok {
			acc.Enabled = payload.Enabled
			globalConfig.Accounts[username] = acc
		}
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil {
			http.Error(w, `{"message":"保存配置失败"}`, http.StatusInternalServerError)
			return
		}
		sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账户 %s 状态更新成功", username)})
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		connID := strings.TrimPrefix(r.URL.Path, "/api/connections/")
		if user, ok := onlineUsers.Load(connID); ok {
			user.(*OnlineUser).sshConn.Close()
			removeOnlineUser(connID)
			sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"})
		} else {
			sendJSON(w, http.StatusNotFound, map[string]string{"message": "连接未找到"})
		}
	default:
		http.NotFound(w, r)
	}
}


// --- main ---
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

	log.Println("====== WSTUNNEL (TCP Proxy + Custom UDP Proxy Mode) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds",
		globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)

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
		if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil {
			log.Fatalf("FATAL: 无法启动Admin panel: %v", err)
		}
	}()

	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			globalConfig.lock.RLock()
			accountInfo, userExists := globalConfig.Accounts[c.User()]
			globalConfig.lock.RUnlock()
			if !userExists {
				return nil, fmt.Errorf("user not found")
			}
			if !accountInfo.Enabled {
				return nil, fmt.Errorf("user disabled")
			}
			if accountInfo.ExpiryDate != "" {
				expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate)
				if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
					return nil, fmt.Errorf("user expired")
				}
			}
			if string(p) == accountInfo.Password {
				log.Printf("Auth successful for user: '%s'", c.User())
				return nil, nil
			}
			log.Printf("Auth failed for user: '%s'", c.User())
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate host key fail: %v", err)
	}
	privateKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("create signer fail: %v", err)
	}
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil {
		log.Fatalf("listen fail: %v", err)
	}
	log.Printf("SSH server listening on %s. UDP traffic will be handled on port 7300.", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
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
