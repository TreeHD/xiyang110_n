package main

import (
	"bufio"
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
	"crypto/ed25519"
	"crypto/rand"
)

// --- 从您的复杂项目中移植过来的配置结构 (已简化) ---

type Settings struct {
	HTTPPort             int      `json:"http_port"`
	DefaultTargetHost    string   `json:"default_target_host"` // 保留用于日志，但不再直接连接
	DefaultTargetPort    int      `json:"default_target_port"`
	Timeout              int      `json:"timeout"`
	UAKeywordWS          string   `json:"ua_keyword_ws"`
	UAKeywordProbe       string   `json:"ua_keyword_probe"`
	IPWhitelist          []string `json:"ip_whitelist"`
	IPBlacklist          []string `json:"ip_blacklist"`
	EnableIPWhitelist    bool     `json:"enable_ip_whitelist"`
	EnableIPBlacklist    bool     `json:"enable_ip_blacklist"`
	EnableDeviceIDAuth   bool     `json:"enable_device_id_auth"`
}

type DeviceInfo struct {
	FriendlyName string `json:"friendly_name"`
	Expiry       string `json:"expiry"`
	LimitGB      int    `json:"limit_gb"`
	UsedBytes    int64  `json:"used_bytes"`
	Enabled      bool   `json:"enabled"`
}

type Config struct {
	Settings  Settings                `json:"settings"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	lock      sync.RWMutex
}

var globalConfig *Config
var deviceUsage sync.Map // 用于在内存中跟踪流量使用

// 加载配置
func loadConfig(file string) (*Config, error) {
	cfg := &Config{
		DeviceIDs: make(map[string]DeviceInfo),
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("无法读取配置文件 %s: %w", file, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败: %w", file, err)
	}
	
	// 初始化内存中的流量计数器
	for id, info := range cfg.DeviceIDs {
		initialUsage := info.UsedBytes
		deviceUsage.Store(id, &initialUsage)
	}
	return cfg, nil
}


// --- 解决 `bufio.Reader` 预读问题的关键 ---
// bufferedConn 包装了 net.Conn 和一个已经预读了数据的 bufio.Reader
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// 重写 Read 方法，确保优先从缓冲区读取
func (c *bufferedConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}


// --- SSH 和 SOCKS5 核心逻辑 (来自您的第一个项目) ---

var (
	socksAddr = "127.0.0.1:1080" // SOCKS5地址可以硬编码或加入配置
	sshUser   = "a555"             // SSH用户名
	sshPass   = "a444"             // SSH密码
)

func socks5Connect(destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr)
	if err != nil { return nil, err }

	// 省略SOCKS5握手细节，与原代码相同...
	_, err = c.Write([]byte{0x05, 0x01, 0x00})
	if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}
	req = append(req, []byte(destHost)...)
	req = append(req, byte(destPort>>8), byte(destPort&0xff))
	_, err = c.Write(req)
	if err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed") }
	switch rep[3] {
	case 0x01: io.CopyN(io.Discard, c, 4+2)
	case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2)
	case 0x04: io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	log.Printf("[SSH] Forwarding request to %s:%d through SOCKS5", destHost, destPort)
	socksConn, err := socks5Connect(destHost, uint16(destPort))
	if err != nil {
		log.Printf("[SOCKS5] Connect failed: %v", err)
		ch.Close()
		return
	}
	defer socksConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(socksConn, ch) }()
	go func() { defer wg.Done(); io.Copy(ch, socksConn) }()
	wg.Wait()
	log.Printf("[SSH] Forwarding finished for %s:%d", destHost, destPort)
}


// --- 移植并改造后的核心握手处理器 ---

func handleSshOverWs(conn net.Conn, sshConfig *ssh.ServerConfig) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	log.Printf("[+] Connection opened from %s", remoteIP)
	defer func() {
		log.Printf("[-] Connection closed for %s", remoteIP)
		conn.Close()
	}()

	settings := globalConfig.Settings
	
	// IP 黑白名单检查
	if settings.EnableIPBlacklist && isIPInList(remoteIP, settings.IPBlacklist) {
		log.Printf("[-] Connection from blacklisted IP %s rejected.", remoteIP)
		return
	}
	if settings.EnableIPWhitelist && !isIPInList(remoteIP, settings.IPWhitelist) {
		log.Printf("[-] Connection from non-whitelisted IP %s rejected.", remoteIP)
		return
	}

	reader := bufio.NewReader(conn)
	forwardingStarted := false

	// 循环处理握手，支持Probe探测模式
	for !forwardingStarted {
		_ = conn.SetReadDeadline(time.Now().Add(time.Duration(settings.Timeout) * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF { log.Printf("[-] Handshake read error from %s: %v", remoteIP, err) }
			return
		}

		// 使用 Sec-WebSocket-Key 作为设备凭证
		credential := req.Header.Get("Sec-WebSocket-Key")
		var finalDeviceID string
		
		if settings.EnableDeviceIDAuth {
			globalConfig.lock.RLock()
			deviceInfo, found := globalConfig.DeviceIDs[credential]
			globalConfig.lock.RUnlock()

			if !found {
				log.Printf("[!] Auth Failed: Invalid Sec-WebSocket-Key from %s. Rejecting.", remoteIP)
				conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
				return
			}
			finalDeviceID = deviceInfo.FriendlyName

			// 检查设备启用状态
			if !deviceInfo.Enabled {
				log.Printf("[!] Auth Failed: Device '%s' is disabled. Rejecting.", finalDeviceID)
				conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
			// 检查设备有效期
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err != nil || time.Now().After(expiry.Add(24*time.Hour)) {
				log.Printf("[!] Auth Failed: Device '%s' has expired. Rejecting.", finalDeviceID)
				conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
			// 检查流量限制
			var deviceUsagePtr *int64
			if val, ok := deviceUsage.Load(credential); ok { deviceUsagePtr = val.(*int64) }
			if deviceInfo.LimitGB > 0 && atomic.LoadInt64(deviceUsagePtr) >= int64(deviceInfo.LimitGB)*1024*1024*1024 {
				log.Printf("[!] Auth Failed: Traffic limit reached for '%s'. Rejecting.", finalDeviceID)
				conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				return
			}
		} else {
			finalDeviceID = remoteIP // 如果禁用认证，就用IP作为标识
		}

		// 根据 User-Agent 决定行为
		ua := req.UserAgent()
		if settings.UAKeywordProbe != "" && strings.Contains(ua, settings.UAKeywordProbe) {
			log.Printf("[*] Received probe from %s for device '%s'. Awaiting WS handshake.", remoteIP, finalDeviceID)
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nOK"))
			continue // 继续等待下一次请求
		}

		if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
			log.Printf("[*] Handshake for device '%s' successful. Switching to SSH protocol.", finalDeviceID)
			conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			forwardingStarted = true
		} else {
			log.Printf("[!] Unrecognized User-Agent from %s: '%s'. Rejecting.", remoteIP, ua)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
	}

	// 握手成功，取消超时
	_ = conn.SetReadDeadline(time.Time{})

	//
	// --- 这是核心衔接点 ---
	//
	// 使用 bufferedConn 包装器来确保SSH服务能读到被预读的数据
	bConn := &bufferedConn{
		Conn:   conn,
		reader: reader,
	}
	
	// 在通过验证的连接上，启动SSH服务
	sshConn, chans, reqs, err := ssh.NewServerConn(bConn, sshConfig)
	if err != nil {
		log.Printf("[SSH] Handshake failed for %s: %v", remoteIP, err)
		return
	}
	defer sshConn.Close()
	log.Printf("[SSH] Session started for %s (%s)", sshConn.User(), sshConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
			continue
		}
		ch, _, err := newChan.Accept()
		if err != nil {
			log.Printf("[SSH] Accept channel failed: %v", err)
			continue
		}

		var payload struct{ Host string; Port uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			log.Printf("[SSH] Invalid payload: %v", err)
			ch.Close()
			continue
		}

		go handleDirectTCPIP(ch, payload.Host, payload.Port)
	}
}

func isIPInList(ip string, list []string) bool {
	for _, item := range list { if item == ip { return true } }
	return false
}


// --- 主函数 ---

func main() {
	var configFile = "ws_config.json"
	var err error
	
	// 加载配置
	globalConfig, err = loadConfig(configFile)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	
	// 配置SSH服务器
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == sshUser && string(p) == sshPass {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv)
	if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshConfig.AddHostKey(privateKey)

	// 启动监听
	addr := fmt.Sprintf("0.0.0.0:%d", globalConfig.Settings.HTTPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("FATAL: Failed to listen on %s: %v", addr, err)
	}
	log.Printf("[*] Server listening on %s. Forwarding to SOCKS5 at %s", addr, socksAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[!] Accept error: %v", err)
			continue
		}
		go handleSshOverWs(conn, sshConfig)
	}
}
