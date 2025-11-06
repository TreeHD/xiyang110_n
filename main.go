// main.go (重构为 charmbracelet/ssh 框架)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	gossh "golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 (保持不变) ---

type AccountInfo struct {
	Password     string  `json:"password"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

type Config struct {
	ListenAddr                  string                 `json:"listen_addr"`
	ListenTLSAddr               string                 `json:"listen_tls_addr"`
	AllowedSNI                  []string               `json:"allowed_sni"`
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
	TrafficSaveIntervalSeconds  int                    `json:"traffic_save_interval_seconds,omitempty"`
	lock                        sync.RWMutex
}

var globalConfig *Config
var serverStartTime = time.Now()

type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshSession  ssh.Session
}

var onlineUsers sync.Map
var userConnectionCount sync.Map

type TrafficInfo struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

var globalTraffic sync.Map

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
	fmt.Fprint(os.Stderr, logLine)
	return len(p), nil
}
func (lc *LogCollector) GetLogs() []string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	logsCopy := make([]string, len(lc.logs))
	copy(logsCopy, lc.logs)
	return logsCopy
}

var globalLog = &LogCollector{maxCap: 200}

const sessionCookieName = "wstunnel_admin_session"
const trafficFileName = "traffic.json"
const certFile = "cert.pem"
const keyFile = "key.pem"

type Session struct{ Username string; Expiry time.Time }

var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex
var bufferPool sync.Pool

// --- 辅助函数 (大部分保持不变) ---

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
	if err != nil {
		return "", false
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
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return ioutil.WriteFile("config.json", data, 0644)
}

func saveTrafficData() error {
	trafficToSave := make(map[string]*TrafficInfo)
	globalTraffic.Range(func(key, value interface{}) bool {
		trafficToSave[key.(string)] = value.(*TrafficInfo)
		return true
	})
	data, err := json.MarshalIndent(trafficToSave, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal traffic data: %w", err)
	}
	if err := ioutil.WriteFile(trafficFileName, data, 0644); err != nil {
		return fmt.Errorf("failed to write traffic data to file: %w", err)
	}
	log.Printf("System: Traffic data successfully saved to %s", trafficFileName)
	return nil
}

func loadTrafficData() {
	data, err := ioutil.ReadFile(trafficFileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("System: Traffic data file (%s) not found, starting with empty records.", trafficFileName)
			return
		}
		log.Printf("System: Error reading traffic data file: %v", err)
		return
	}
	var trafficFromFile map[string]*TrafficInfo
	if err := json.Unmarshal(data, &trafficFromFile); err != nil {
		log.Printf("System: Error parsing traffic data file: %v", err)
		return
	}
	for username, trafficInfo := range trafficFromFile {
		globalTraffic.Store(username, &TrafficInfo{
			Sent:     atomic.LoadUint64(&trafficInfo.Sent),
			Received: atomic.LoadUint64(&trafficInfo.Received),
		})
	}
	log.Printf("System: Successfully loaded %d user traffic records from %s", len(trafficFromFile), trafficFileName)
}

func isSNIAllowed(sni string) bool {
	globalConfig.lock.RLock()
	defer globalConfig.lock.RUnlock()
	for _, allowed := range globalConfig.AllowedSNI {
		if strings.EqualFold(allowed, sni) {
			return true
		}
	}
	return false
}

func generateOrLoadTLSConfig() (*tls.Config, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("System: TLS certificate not found. Generating a new self-signed certificate...")
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil { return nil, fmt.Errorf("failed to generate private key: %w", err) }
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil { return nil, fmt.Errorf("failed to generate serial number: %w", err) }
		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{Organization: []string{"WSTunnel Self-Signed"}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil { return nil, fmt.Errorf("failed to create certificate: %w", err) }
		certOut, err := os.Create(certFile)
		if err != nil { return nil, fmt.Errorf("failed to open cert.pem for writing: %w", err) }
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
		log.Printf("System: Saved certificate to %s", certFile)
		keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil { return nil, fmt.Errorf("failed to open key.pem for writing: %w", err) }
		privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
		pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		keyOut.Close()
		log.Printf("System: Saved private key to %s", keyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil { return nil, fmt.Errorf("failed to load TLS key pair: %w", err) }
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// --- 核心数据转发逻辑 (重构) ---

// handshakeConn 保持不变，用于处理HTTP Upgrade后的连接
type handshakeConn struct {
	net.Conn
	r io.Reader
}

func (hc *handshakeConn) Read(p []byte) (n int, err error) { return hc.r.Read(p) }

// countingReader 是一个辅助类型，用于在io.Copy时统计流量
type countingReader struct {
	io.Reader
	counter *uint64
}

func (r *countingReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	atomic.AddUint64(r.counter, uint64(n))
	return
}

// proxyData 是新的、更高效的数据转发函数，替代了tolerantCopy
func proxyData(dst io.Writer, src io.Reader, trafficCounter *uint64) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	
	readerWithCounter := &countingReader{Reader: src, counter: trafficCounter}
	io.CopyBuffer(dst, readerWithCounter, *bufPtr)
}

// directTCPIPHandler 是新的处理 direct-tcpip 请求的函数
func directTCPIPHandler(srv *ssh.Server, conn gossh.Conn, newChan gossh.NewChannel, ctx ssh.Context) {
	var payload struct {
		Host string
		Port uint32
	}
	if err := gossh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		log.Printf("TCP Proxy: Failed to parse direct-tcpip payload: %v", err)
		newChan.Reject(gossh.ConnectionFailed, "failed to parse payload")
		return
	}

	destAddr := net.JoinHostPort(payload.Host, fmt.Sprintf("%d", payload.Port))
	username := conn.User()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		log.Printf("TCP Proxy: Failed to accept channel for %s: %v", username, err)
		return
	}
	go gossh.DiscardRequests(reqs)
	defer ch.Close()

	connectTimeout := time.Duration(globalConfig.TargetConnectTimeoutSeconds) * time.Second
	destConn, err := net.DialTimeout("tcp", destAddr, connectTimeout)
	if err != nil {
		log.Printf("TCP Proxy: Failed to connect to %s for user %s: %v", destAddr, username, err)
		return
	}
	defer destConn.Close()

	val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
	traffic := val.(*TrafficInfo)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		proxyData(destConn, ch, &traffic.Sent)
	}()
	go func() {
		defer wg.Done()
		if tcpConn, ok := destConn.(net.Conn); ok {
			tcpConn.Close()
		}
		proxyData(ch, destConn, &traffic.Received)
	}()

	wg.Wait()
}


// --- SSH & HTTP 握手与连接管理 (外部逻辑保持不变) ---

// dispatchConnection 和 handleHttpUpgrade 保持不变
// 它们是外部的“剥壳”逻辑，最后将连接交给新的SSH框架处理

// 443端口的智能分发器
func dispatchConnection(c net.Conn, server *ssh.Server) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FATAL: Panic recovered during dispatch for %s: %v", c.RemoteAddr(), r)
		}
		c.Close()
	}()

	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		log.Printf("System: Dispatcher expected a TLS connection, but got something else.")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		//log.Printf("System: TLS handshake failed for %s: %v", c.RemoteAddr(), err)
		return
	}

	sni := tlsConn.ConnectionState().ServerName
	if !isSNIAllowed(sni) {
		log.Printf("System: Denied connection from %s due to invalid SNI: '%s'", c.RemoteAddr(), sni)
		return
	}

	reader := bufio.NewReader(c)
	peekedBytes, err := reader.Peek(8)
	if err != nil {
		if err != io.EOF {
			//log.Printf("System: Protocol sniffing failed for %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	if bytes.HasPrefix(peekedBytes, []byte("SSH-2.0")) {
		log.Printf("System: Detected direct SSH connection via TLS for %s (SNI: %s)", c.RemoteAddr(), sni)
		time.Sleep(500 * time.Millisecond)
		server.Handle(c) // 交给 charm/ssh 框架处理
	} else {
		log.Printf("System: Detected HTTP-based connection via TLS for %s (SNI: %s), attempting Upgrade.", c.RemoteAddr(), sni)
		
		timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second
		for {
			if err := c.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil { return }

			req, err := http.ReadRequest(reader)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("System: Timeout waiting for valid HTTP Upgrade on TLS for %s", c.RemoteAddr())
				} else if err != io.EOF {
					//log.Printf("System: Failed to read HTTP request from TLS stream for %s: %v", c.RemoteAddr(), err)
				}
				return
			}
			io.Copy(ioutil.Discard, req.Body)
			req.Body.Close()

			if strings.Contains(req.UserAgent(), globalConfig.ConnectUA) {
				_, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
				if err != nil { return }
				break
			} else {
				log.Printf("System: Ignored invalid HTTP request via TLS for %s (UA: %s)", c.RemoteAddr(), req.UserAgent())
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\nOK"))
				continue
			}
		}

		time.Sleep(500 * time.Millisecond)
		
		wrappedConn := &handshakeConn{Conn: c, r: reader}
		server.Handle(wrappedConn) // 交给 charm/ssh 框架处理
	}
}

// 80端口的HTTP Upgrade处理器
func handleHttpUpgrade(c net.Conn, server *ssh.Server) {
	defer c.Close()
	timeoutDuration := time.Duration(globalConfig.HandshakeTimeout) * time.Second
	expectedUA := globalConfig.ConnectUA
	reader := bufio.NewReader(c)

	for {
		if err := c.SetReadDeadline(time.Now().Add(timeoutDuration)); err != nil { return }
		
		req, err := http.ReadRequest(reader)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("System: Timeout waiting for valid HTTP Upgrade on port 80 for %s", c.RemoteAddr())
			} else if err != io.EOF {
				//log.Printf("System: Failed to read HTTP request on port 80 for %s: %v", c.RemoteAddr(), err)
			}
			return
		}
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()

		if strings.Contains(req.UserAgent(), expectedUA) {
			_, err := c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if err != nil { return }
			break
		} else {
			log.Printf("System: Ignored invalid HTTP request on port 80 from %s (UA: %s)", c.RemoteAddr(), req.UserAgent())
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\nOK"))
			continue
		}
	}
	
	time.Sleep(500 * time.Millisecond)
	
	wrappedConn := &handshakeConn{Conn: c, r: reader}
	server.Handle(wrappedConn) // 交给 charm/ssh 框架处理
}


// --- Web服务器逻辑 (保持不变) ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := validateSession(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		} else {
			http.Redirect(w, r, "/login.html", http.StatusFound)
		}
	}
}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	globalConfig.lock.RLock()
	p, ok := globalConfig.AdminAccounts[creds.Username]
	globalConfig.lock.RUnlock()
	if !ok || p != creds.Password {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	http.SetCookie(w, createSession(creds.Username))
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
	case r.URL.Path == "/api/server_status":
		var globalSent, globalRcvd uint64
		globalTraffic.Range(func(_, v interface{}) bool {
			t := v.(*TrafficInfo)
			globalSent += atomic.LoadUint64(&t.Sent)
			globalRcvd += atomic.LoadUint64(&t.Received)
			return true
		})
		var activeConns int
		onlineUsers.Range(func(_, _ interface{}) bool {
			activeConns++
			return true
		})
		cpuPercent, _ := cpu.Percent(0, false)
		memInfo, _ := mem.VirtualMemory()
		sendJSON(w, http.StatusOK, map[string]interface{}{"uptime": time.Since(serverStartTime).Round(time.Second).String(), "active_conns": activeConns, "global_sent": globalSent, "global_rcvd": globalRcvd, "cpu_percent": cpuPercent[0], "mem_percent": memInfo.UsedPercent, "mem_used_bytes": memInfo.Used, "mem_total_bytes": memInfo.Total})
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
			sentBytes := atomic.LoadUint64(&t.Sent)
			receivedBytes := atomic.LoadUint64(&t.Received)
			usedBytes := sentBytes + receivedBytes
			var remainingBytes int64 = -1
			if acc.LimitGB > 0 {
				remainingBytes = int64(acc.LimitGB*1e9) - int64(usedBytes)
				if remainingBytes < 0 { remainingBytes = 0 }
			}
			conns = append(conns, map[string]interface{}{"conn_id": u.ConnID, "username": u.Username, "ip": u.RemoteAddr, "connect_time": u.ConnectTime, "sent_bytes": sentBytes, "received_bytes": receivedBytes, "expiry_date": acc.ExpiryDate, "used_bytes": usedBytes, "remaining_bytes": remainingBytes})
			return true
		})
		sendJSON(w, http.StatusOK, conns)
	case r.URL.Path == "/api/accounts":
		globalConfig.lock.RLock()
		defer globalConfig.lock.RUnlock()
		sendJSON(w, http.StatusOK, globalConfig.Accounts)
	case r.URL.Path == "/api/accounts/set_status" && r.Method == "POST":
		var payload struct { Username string `json:"username"`; Enabled bool `json:"enabled"` }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"}); return }
		if payload.Username == "" { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"}); return }
		globalConfig.lock.Lock()
		acc, ok := globalConfig.Accounts[payload.Username]
		if !ok { globalConfig.lock.Unlock(); sendJSON(w, http.StatusNotFound, map[string]string{"message": "错误：用户不存在"}); return }
		acc.Enabled = payload.Enabled
		globalConfig.Accounts[payload.Username] = acc
		if !payload.Enabled {
			var connsToClose []ssh.Session
			onlineUsers.Range(func(_, v interface{}) bool {
				u := v.(*OnlineUser)
				if u.Username == payload.Username { connsToClose = append(connsToClose, u.sshSession) }
				return true
			})
			for _, sess := range connsToClose { sess.Close() }
		}
		globalConfig.lock.Unlock()
		safeSaveConfig()
		actionStr := "封禁"; if payload.Enabled { actionStr = "解封" }; successMessage := fmt.Sprintf("账号 %s 已成功%s", payload.Username, actionStr)
		sendJSON(w, http.StatusOK, map[string]string{"message": successMessage})
	case r.URL.Path == "/api/accounts/reset-traffic" && r.Method == "POST":
		var p struct{ Username string `json:"username"` }
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"}); return }
		if p.Username == "" { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"}); return }
		if v, ok := globalTraffic.Load(p.Username); ok {
			t := v.(*TrafficInfo)
			atomic.StoreUint64(&t.Sent, 0); atomic.StoreUint64(&t.Received, 0)
			sendJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("账号 %s 的流量已重置", p.Username)})
		} else { sendJSON(w, http.StatusNotFound, map[string]string{"message": "未找到该用户的流量记录，无法重置"}) }
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
		if username == "" { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"}); return }
		var newInfo AccountInfo
		bodyBytes, _ := ioutil.ReadAll(r.Body); r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		tempInfo := struct { Password *string `json:"password"` }{}; json.Unmarshal(bodyBytes, &tempInfo); json.Unmarshal(bodyBytes, &newInfo)
		globalConfig.lock.Lock()
		existingInfo, isUpdate := globalConfig.Accounts[username]
		if isUpdate { if tempInfo.Password == nil { newInfo.Password = existingInfo.Password } } else if newInfo.Password == "" { globalConfig.lock.Unlock(); sendJSON(w, http.StatusBadRequest, map[string]string{"message": "新用户必须提供密码"}); return }
		globalConfig.Accounts[username] = newInfo
		globalConfig.lock.Unlock()
		if err := safeSaveConfig(); err != nil { sendJSON(w, http.StatusInternalServerError, map[string]string{"message": "保存配置失败"}); return }
		sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 更新成功"})
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
		if username == "" { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：不能删除空用户名的账户"}); return }
		globalConfig.lock.Lock(); delete(globalConfig.Accounts, username); globalConfig.lock.Unlock(); safeSaveConfig()
		sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 删除成功"})
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		connID := strings.TrimPrefix(r.URL.Path, "/api/connections/")
		if user, ok := onlineUsers.Load(connID); ok { user.(*OnlineUser).sshSession.Close() }
	case r.URL.Path == "/api/admin/update_password" && r.Method == "POST":
		var payload struct { OldPassword string `json:"oldPassword"`; NewPassword string `json:"newPassword"`}
		if json.NewDecoder(r.Body).Decode(&payload) != nil { sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"}); return }
		user, _ := validateSession(r)
		globalConfig.lock.Lock()
		if globalConfig.AdminAccounts[user] == payload.OldPassword {
			globalConfig.AdminAccounts[user] = payload.NewPassword
			globalConfig.lock.Unlock(); safeSaveConfig(); sendJSON(w, http.StatusOK, map[string]string{"message": "密码更新成功"})
		} else { globalConfig.lock.Unlock(); sendJSON(w, http.StatusForbidden, map[string]string{"message": "旧密码错误"}) }
	case r.URL.Path == "/api/settings":
		if r.Method == "GET" { 
			globalConfig.lock.RLock()
			defer globalConfig.lock.RUnlock()
			sendJSON(w, http.StatusOK, globalConfig) 
		}
		if r.Method == "POST" {
			var newSettings Config
			if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
				sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的设置格式"})
				return
			}
			globalConfig.lock.Lock()
			globalConfig.HandshakeTimeout = newSettings.HandshakeTimeout
			globalConfig.ConnectUA = newSettings.ConnectUA
			globalConfig.BufferSizeKB = newSettings.BufferSizeKB
			globalConfig.IdleTimeoutSeconds = newSettings.IdleTimeoutSeconds
			globalConfig.TolerantCopyMaxRetries = newSettings.TolerantCopyMaxRetries
			globalConfig.TolerantCopyRetryDelayMs = newSettings.TolerantCopyRetryDelayMs
			globalConfig.TargetConnectTimeoutSeconds = newSettings.TargetConnectTimeoutSeconds
			globalConfig.DefaultExpiryDays = newSettings.DefaultExpiryDays
			globalConfig.DefaultLimitGB = newSettings.DefaultLimitGB
			globalConfig.AllowedSNI = newSettings.AllowedSNI
			globalConfig.lock.Unlock()
			if err := safeSaveConfig(); err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{"message": "保存配置失败: " + err.Error()})
				return
			}
			bufferPool = sync.Pool{New: func() interface{} { 
				buf := make([]byte, globalConfig.BufferSizeKB*1024)
				return &buf 
			}}
			sendJSON(w, http.StatusOK, map[string]string{"message": "设置已保存"})
		}
	case r.URL.Path == "/api/logs": sendJSON(w, http.StatusOK, globalLog.GetLogs())
	case r.URL.Path == "/api/traffic":
		trafficData := make(map[string]*TrafficInfo); globalTraffic.Range(func(k, v interface{}) bool { trafficData[k.(string)] = v.(*TrafficInfo); return true }); sendJSON(w, http.StatusOK, trafficData)
	case r.URL.Path == "/api/whoami": if user, ok := validateSession(r); ok { sendJSON(w, http.StatusOK, map[string]string{"username": user}) }
	default: http.NotFound(w, r)
	}
}


// --- main ---
func main() {
	log.SetOutput(globalLog)
	log.SetFlags(0)
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("FATAL: Cannot read config.json: %v", err)
	}
	globalConfig = &Config{}
	if err := json.Unmarshal(configFile, globalConfig); err != nil {
		log.Fatalf("FATAL: Cannot parse config.json: %v", err)
	}

	if globalConfig.ListenTLSAddr == "" { globalConfig.ListenTLSAddr = ":443" }
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "wstunnel" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 32 }
	if globalConfig.DefaultExpiryDays <= 0 { globalConfig.DefaultExpiryDays = 30 }
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 120 }
	if globalConfig.TolerantCopyMaxRetries <= 0 { globalConfig.TolerantCopyMaxRetries = 100 }
	if globalConfig.TolerantCopyRetryDelayMs <= 0 { globalConfig.TolerantCopyRetryDelayMs = 500 }
	if globalConfig.TargetConnectTimeoutSeconds <= 0 { globalConfig.TargetConnectTimeoutSeconds = 10 }
    if globalConfig.TrafficSaveIntervalSeconds <= 0 { globalConfig.TrafficSaveIntervalSeconds = 300 }

    log.Println("==================================================")
    log.Println("          WSTunnel Service Starting Up (charmbracelet/ssh)")
    log.Println("==================================================")
    log.Printf("  Listen Addr (HTTP Upgrade): %s", globalConfig.ListenAddr)
	log.Printf("  Listen Addr (TLS Multiplexer): %s  <-- SUPER PORT", globalConfig.ListenTLSAddr)
	log.Printf("  Allowed SNI Hosts: %v", globalConfig.AllowedSNI)
    log.Printf("  Admin Panel Addr: %s", globalConfig.AdminAddr)
    log.Println("------------------ Behaviors ---------------------")
    log.Printf("  Handshake Timeout: %d seconds", globalConfig.HandshakeTimeout)
    log.Printf("  Required User-Agent: %s", globalConfig.ConnectUA)
    log.Printf("  Connection Idle Timeout: %d seconds", globalConfig.IdleTimeoutSeconds)
    log.Printf("  Target Connect Timeout: %d seconds", globalConfig.TargetConnectTimeoutSeconds)
    log.Println("------------------- Performance ------------------")
    log.Printf("  Buffer Size: %d KB", globalConfig.BufferSizeKB)
    log.Println("--------------------- Defaults -------------------")
    log.Printf("  New User Default Expiry: %d days", globalConfig.DefaultExpiryDays)
    log.Printf("  New User Default Traffic: %.2f GB", globalConfig.DefaultLimitGB)
    log.Println("------------------ Persistence -------------------")
    log.Printf("  Traffic Save Interval: %d seconds", globalConfig.TrafficSaveIntervalSeconds)
    log.Println("==================================================")
	
	loadTrafficData()

	go func() {
		saveInterval := time.Duration(globalConfig.TrafficSaveIntervalSeconds) * time.Second
		log.Printf("System: Traffic data will be saved every %v.", saveInterval)
		ticker := time.NewTicker(saveInterval)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := saveTrafficData(); err != nil {
				log.Printf("System: Error during periodic traffic data save: %v", err)
			}
		}
	}()

	bufferPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, globalConfig.BufferSizeKB*1024)
		return &buf
	}}

	var wg sync.WaitGroup

	adminServer := &http.Server{Addr: globalConfig.AdminAddr}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") })
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", logoutHandler)
		mux.HandleFunc("/api/", authMiddleware(apiHandler))
		mux.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" { http.ServeFile(w, r, "admin.html"); return }
			http.NotFound(w, r)
		}))
		adminServer.Handler = mux
		log.Printf("System: Admin panel listening on http://%s", globalConfig.AdminAddr)
		if err := adminServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("FATAL: Cannot start admin panel: %v", err)
		}
	}()
	
	// --- 新的 charmbracelet/ssh 服务器设置 ---
	
	// 1. 创建一个新的 wish Server，这是 charm/ssh 的核心
	server, err := wish.NewServer(
		// 2. 设置服务器版本号
		ssh.ServerVersion("SSH-2.0-WSTunnel_Pro"),

		// 3. 设置主机密钥 (使用内存中生成的密钥，与旧代码逻辑相同)
		wish.WithHostKeyCallback(func(ctx ssh.Context) (ssh.Signer, error) {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			return gossh.NewSignerFromKey(priv)
		}),

		// 4. 设置密码认证和前置检查
		wish.WithPasswordAuth(func(ctx ssh.Context, password string) bool {
			user := ctx.User()
			
			globalConfig.lock.RLock()
			acc, ok := globalConfig.Accounts[user]
			globalConfig.lock.RUnlock()

			if !ok || !acc.Enabled {
				log.Printf("Auth failed for user '%s': not found or disabled", user)
				return false
			}

			if acc.ExpiryDate != "" {
				exp, err := time.Parse("2006-01-02", acc.ExpiryDate)
				if err != nil || time.Now().After(exp.Add(24*time.Hour)) {
					log.Printf("Auth failed for user '%s': expired", user)
					return false
				}
			}

			if acc.LimitGB > 0 {
				v, _ := globalTraffic.LoadOrStore(user, &TrafficInfo{})
				t := v.(*TrafficInfo)
				if atomic.LoadUint64(&t.Sent)+atomic.LoadUint64(&t.Received) >= uint64(acc.LimitGB*1e9) {
					log.Printf("Auth failed for user '%s': traffic limit exceeded", user)
					return false
				}
			}

			if acc.MaxSessions > 0 {
				v, _ := userConnectionCount.LoadOrStore(user, new(int32))
				countPtr := v.(*int32)
				if atomic.LoadInt32(countPtr) >= int32(acc.MaxSessions) {
					log.Printf("Auth failed for user '%s': max sessions exceeded", user)
					return false
				}
			}

			if password == acc.Password {
				return true
			}

			log.Printf("Auth failed for user '%s': invalid credentials", user)
			return false
		}),

		// 5. 设置我们想要的、高性能的加密套件
		wish.WithServerConfig(func(cfg *gossh.ServerConfig) {
			// 这个回调让我们能访问底层的 gossh.ServerConfig
			// 我们在这里设置加密算法，可以100%确定它能正常工作
			cfg.Config.Ciphers = []string{
				"chacha20-poly1305@openssh.com",
				"aes128-gcm@openssh.com", // 保留一个作为兼容性后备
				"aes128-ctr",
			}
			cfg.Config.KeyExchanges = []string{
				"curve25519-sha256@libssh.org", // 性能和安全性俱佳
				"ecdh-sha2-nistp256",
			}
		}),
		
		// 6. 添加一个中间件来处理连接生命周期 (上线/下线)
		wish.WithMiddleware(func(h ssh.Handler) ssh.Handler {
			return func(s ssh.Session) {
				// 用户认证成功后，这里会执行
				user := s.User()
				connID := s.RemoteAddr().String() + "-" + hex.EncodeToString(s.SessionID())

				// --- 用户上线逻辑 ---
				if val, ok := userConnectionCount.Load(user); ok {
					atomic.AddInt32(val.(*int32), 1)
				}
				onlineUser := &OnlineUser{ConnID: connID, Username: user, RemoteAddr: s.RemoteAddr().String(), ConnectTime: time.Now(), sshSession: s}
				onlineUsers.Store(onlineUser.ConnID, onlineUser)
				log.Printf("Auth success for user '%s' from %s", user, s.RemoteAddr())

				// --- 用户下线逻辑 ---
				defer func() {
					if val, ok := userConnectionCount.Load(user); ok {
						atomic.AddInt32(val.(*int32), -1)
					}
					onlineUsers.Delete(onlineUser.ConnID)
					log.Printf("Session closed for user '%s' from %s", user, s.RemoteAddr())
				}()

				h(s)
			}
		}),
	)
	if err != nil {
		log.Fatalf("FATAL: could not create ssh server: %v", err)
	}

	// 7. 设置 direct-tcpip 处理器
	server.HandleDirectTCPIP(directTCPIPHandler)

	// 8. 设置默认的会话处理器 (因为我们是纯隧道，所以这里什么都不做)
	server.Handler = func(s ssh.Session) {
		// 纯隧道服务器，交互式会话直接关闭
		io.WriteString(s, "This is a tunnel-only server. Interactive session is not supported.\n")
		s.Close()
	}

	// --- 启动监听器 (和旧代码逻辑一样) ---

	// 普通TCP监听器 (HTTP Upgrade)
	sshListener, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on %s: %v", globalConfig.ListenAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: HTTP Upgrade server listening on %s", globalConfig.ListenAddr)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				log.Printf("System: SSH listener (HTTP Upgrade) stopped. %v", err)
				return
			}
			go handleHttpUpgrade(conn, server)
		}
	}()

	// “超级 443 端口”
	tlsConfig, err := generateOrLoadTLSConfig()
	if err != nil {
		log.Fatalf("FATAL: Could not configure TLS: %v", err)
	}
	tlsListener, err := tls.Listen("tcp", globalConfig.ListenTLSAddr, tlsConfig)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on TLS %s: %v", globalConfig.ListenTLSAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: Super TLS multiplexing server listening on %s", globalConfig.ListenTLSAddr)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				log.Printf("System: Super TLS listener stopped. %v", err)
				return
			}
			go dispatchConnection(conn, server)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("==================================================")
	log.Println("         WSTunnel Service Shutting Down...")
	log.Println("==================================================")

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil { log.Printf("System: Error closing SSH server: %v", err) } else { log.Println("System: SSH server gracefully shut down.")}

	if err := adminServer.Close(); err != nil { log.Printf("System: Error closing admin panel: %v", err) } else { log.Println("System: Admin panel gracefully shut down.") }
	if err := sshListener.Close(); err != nil { log.Printf("System: Error closing SSH listener (HTTP Upgrade): %v", err) }
	if err := tlsListener.Close(); err != nil { log.Printf("System: Error closing SSH listener (TLS): %v", err) }
	
	log.Println("System: Performing final traffic data save...")
	if err := saveTrafficData(); err != nil { log.Printf("System: Error during final traffic data save: %v", err) }
	
	wg.Wait()
	log.Println("Shutdown complete.")
}
