// main.go (最终完整版 - 集成所有功能和修正)
package main

import (
	"bufio"
	"bytes"
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

	"github.comcom/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 ---

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
	sshConn     ssh.Conn
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

// --- 核心数据转发逻辑 ---

type handshakeConn struct {
	net.Conn
	r io.Reader
}

func (hc *handshakeConn) Read(p []byte) (n int, err error) { return hc.r.Read(p) }

func tolerantCopy(dst io.Writer, src io.Reader, direction string, remoteAddr net.Addr, username string) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr
	maxRetries := globalConfig.TolerantCopyMaxRetries
	retryDelay := time.Duration(globalConfig.TolerantCopyRetryDelayMs) * time.Millisecond
	consecutiveTempErrors := 0
	val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
	traffic := val.(*TrafficInfo)
	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			if consecutiveTempErrors > 0 {
				log.Printf("TCP Proxy (%s): Network recovery for %s after %d failed attempts.", direction, remoteAddr, consecutiveTempErrors)
			}
			consecutiveTempErrors = 0
			nw, wErr := dst.Write(buf[0:nr])
			if nw > 0 {
				if direction == "Client->Target" {
					atomic.AddUint64(&traffic.Sent, uint64(nw))
				} else {
					atomic.AddUint64(&traffic.Received, uint64(nw))
				}
			}
			if wErr != nil {
				if wErr != io.EOF {
					log.Printf("TCP Proxy (%s): Permanent write error for %s: %v", direction, remoteAddr, wErr)
				}
				break
			}
			if nr != nw {
				log.Printf("TCP Proxy (%s): Short write for %s, closing", direction, remoteAddr)
				break
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			if netErr, ok := rErr.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				consecutiveTempErrors++
				if consecutiveTempErrors > maxRetries {
					log.Printf("TCP Proxy (%s): Too many errors for %s, giving up. Last error: %v", direction, remoteAddr, rErr)
					break
				}
				log.Printf("TCP Proxy (%s): Temporary error for %s: %v. Retrying in %v... (Attempt %d/%d)", direction, remoteAddr, rErr, retryDelay, consecutiveTempErrors, maxRetries)
				time.Sleep(retryDelay)
				continue
			}
			log.Printf("TCP Proxy (%s): Unrecoverable read error for %s: %v", direction, remoteAddr, rErr)
			break
		}
	}
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr, username string) {
	var destAddr string
	if strings.Contains(destHost, ":") {
		destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort)
	} else {
		destAddr = fmt.Sprintf("%s:%d", destHost, destPort)
	}
	connectTimeout := time.Duration(globalConfig.TargetConnectTimeoutSeconds) * time.Second
	destConn, err := net.DialTimeout("tcp", destAddr, connectTimeout)
	if err != nil {
		log.Printf("TCP Proxy: Failed to connect to %s for user %s: %v", destAddr, username, err)
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
			defer destConn.Close()
		}
		tolerantCopy(destConn, ch, "Client->Target", remoteAddr, username)
	}()
	go func() {
		defer wg.Done()
		defer ch.CloseWrite()
		tolerantCopy(ch, destConn, "Target->Client", remoteAddr, username)
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
				return
			}
		case <-done:
			return
		}
	}
}

// 核心SSH处理器
func handleSshConnection(c net.Conn, r io.Reader, sshCfg *ssh.ServerConfig) {
	connForSSH := &handshakeConn{Conn: c, r: r}
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(connForSSH, sshCfg)
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "connection reset by peer") {
			//log.Printf("SSH handshake failed for %s: client closed connection.", c.RemoteAddr())
		} else {
			log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err)
		}
		return
	}
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	if idleTimeout > 0 {
		c.SetReadDeadline(time.Time{})
		doneDeadline := make(chan struct{})
		defer close(doneDeadline)
		go func() {
			ticker := time.NewTicker(idleTimeout / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c.SetReadDeadline(time.Now().Add(idleTimeout))
				case <-doneDeadline:
					return
				}
			}
		}()
	} else {
		c.SetReadDeadline(time.Time{})
	}
	defer sshConn.Close()
	username := sshConn.User()
	defer func() {
		if val, ok := userConnectionCount.Load(username); ok {
			atomic.AddInt32(val.(*int32), -1)
		}
	}()
	log.Printf("Auth success for user '%s' from %s", username, sshConn.RemoteAddr())

	done := make(chan struct{})
	defer close(done)
	go sendKeepAlives(sshConn, done)
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ConnID: connID, Username: username, RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn}
	onlineUsers.Store(onlineUser.ConnID, onlineUser)
	defer onlineUsers.Delete(onlineUser.ConnID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, _, err := newChan.Accept()
		if err != nil {
			continue
		}
		var payload struct {
			Host string
			Port uint32
		}
		ssh.Unmarshal(newChan.ExtraData(), &payload)
		go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr(), username)
	}
}

// 443端口的智能分发器
func dispatchConnection(c net.Conn, sshCfg *ssh.ServerConfig) {
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
		handleSshConnection(c, reader, sshCfg)
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

		var finalReader io.Reader
		if reader.Buffered() > 0 {
			preReadData, _ := ioutil.ReadAll(reader)
			finalReader = io.MultiReader(bytes.NewReader(preReadData), c)
		} else {
			finalReader = c
		}
		handleSshConnection(c, finalReader, sshCfg)
	}
}

// 80端口的HTTP Upgrade处理器
func handleHttpUpgrade(c net.Conn, sshCfg *ssh.ServerConfig) {
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
	
	var finalReader io.Reader
	if reader.Buffered() > 0 {
		preReadData, _ := ioutil.ReadAll(reader)
		finalReader = io.MultiReader(bytes.NewReader(preReadData), c)
	} else {
		finalReader = c
	}
	handleSshConnection(c, finalReader, sshCfg)
}

// --- Web服务器逻辑 ---
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
			var connsToClose []ssh.Conn
			onlineUsers.Range(func(_, v interface{}) bool {
				u := v.(*OnlineUser)
				if u.Username == payload.Username { connsToClose = append(connsToClose, u.sshConn) }
				return true
			})
			for _, conn := range connsToClose { conn.Close() }
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
		if user, ok := onlineUsers.Load(connID); ok { user.(*OnlineUser).sshConn.Close(); sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"}) }
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
    log.Println("          WSTunnel Service Starting Up")
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
    log.Printf("  Network Error Retries: %d times", globalConfig.TolerantCopyMaxRetries)
    log.Printf("  Retry Delay: %d ms", globalConfig.TolerantCopyRetryDelayMs)
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
				v, _ := globalTraffic.LoadOrStore(user, &TrafficInfo{})
				t := v.(*TrafficInfo)
				if atomic.LoadUint64(&t.Sent)+atomic.LoadUint64(&t.Received) >= uint64(acc.LimitGB*1e9) { return nil, fmt.Errorf("traffic limit exceeded") }
			}
			if acc.MaxSessions > 0 {
				v, _ := userConnectionCount.LoadOrStore(user, new(int32))
				countPtr := v.(*int32)
				if atomic.LoadInt32(countPtr) >= int32(acc.MaxSessions) { return nil, fmt.Errorf("max sessions exceeded") }
				atomic.AddInt32(countPtr, 1)
			}
			if string(p) == acc.Password { return nil, nil }
			if acc.MaxSessions > 0 { if v, ok := userConnectionCount.Load(user); ok { atomic.AddInt32(v.(*int32), -1) } }
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(priv)
	sshCfg.AddHostKey(key)

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
			go handleHttpUpgrade(conn, sshCfg)
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
			go dispatchConnection(conn, sshCfg)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("==================================================")
	log.Println("         WSTunnel Service Shutting Down...")
	log.Println("==================================================")

	if err := adminServer.Close(); err != nil { log.Printf("System: Error closing admin panel: %v", err) } else { log.Println("System: Admin panel gracefully shut down.") }
	if err := sshListener.Close(); err != nil { log.Printf("System: Error closing SSH listener (HTTP Upgrade): %v", err) } else { log.Println("System: SSH listener (HTTP Upgrade) gracefully shut down.") }
	if err := tlsListener.Close(); err != nil { log.Printf("System: Error closing SSH listener (TLS): %v", err) } else { log.Println("System: SSH listener (TLS) gracefully shut down.") }
	
	log.Println("System: Performing final traffic data save...")
	if err := saveTrafficData(); err != nil { log.Printf("System: Error during final traffic data save: %v", err) }
	
	wg.Wait()
	log.Println("Shutdown complete.")
}
