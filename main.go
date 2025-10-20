package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync" // [1] 新增：引入 sync 包用于读写锁
	"sync/atomic"
	"time" // [2] 新增：引入 time 包用于日期比较
)

import "golang.org/x/crypto/ssh"

// ==============================================================================
// === 核心修改点 1: 定义新的 AccountInfo 和 Config 结构体 ===
// ==============================================================================

// AccountInfo 存储每个用户的详细信息
type AccountInfo struct {
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"` // 格式: "YYYY-MM-DD"
}

// Config 结构体现在使用 AccountInfo
type Config struct {
	ListenAddr string                 `json:"listen_addr"`
	SocksAddr  string                 `json:"socks_addr"`
	Accounts   map[string]AccountInfo `json:"accounts"`
	lock       sync.RWMutex           // [3] 新增：读写锁，为将来的热重载做准备
}

var globalConfig *Config

var activeConn int64

// SOCKS5 connect (无任何改动)
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
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

// handleDirectTCPIP (无任何改动)
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)
	
	globalConfig.lock.RLock() // 加读锁以安全地读取配置
	socksServerAddr := globalConfig.SocksAddr
	globalConfig.lock.RUnlock()

	socksConn, err := socks5Connect(socksServerAddr, destHost, uint16(destPort))
	if err != nil { log.Printf("connect to SOCKS5 fail: %v", err); ch.Close(); return }
	defer socksConn.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(socksConn, ch); socksConn.Close(); done <- struct{}{} }()
	go func() { io.Copy(ch, socksConn); ch.Close(); done <- struct{}{} }()
	<-done
}

// httpHandshake (无任何改动)
type combinedConn struct {
	net.Conn
	reader io.Reader
}
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }
func httpHandshake(conn net.Conn) (net.Conn, error) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil { return nil, fmt.Errorf("read http request fail: %v", err) }
	io.Copy(ioutil.Discard, req.Body); req.Body.Close()
	if strings.Contains(req.UserAgent(), "26.4.0") {
		_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		if err != nil { return nil, fmt.Errorf("write http response fail: %v", err) }
		finalConn := &combinedConn{
			Conn:   conn,
			reader: io.MultiReader(reader, conn),
		}
		return finalConn, nil
	}
	return nil, fmt.Errorf("invalid user-agent")
}

// main 函数
func main() {
	configFile, err := os.ReadFile("config.json")
	if err != nil { log.Fatalf("FATAL: 无法读取 config.json 文件: %v", err) }
	
	globalConfig = &Config{}
	err = json.Unmarshal(configFile, globalConfig)
	if err != nil { log.Fatalf("FATAL: 解析 config.json 文件失败: %v", err) }
	
	if globalConfig.ListenAddr == "" || globalConfig.SocksAddr == "" || len(globalConfig.Accounts) == 0 {
		log.Fatalf("FATAL: config.json 文件中缺少必要的配置项 (listen_addr, socks_addr, 或 accounts 列表为空)")
	}

	// ==============================================================================
	// === 核心修改点 2: 升级 PasswordCallback 以检查 enabled 和 expiry_date ===
	// ==============================================================================
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			
			globalConfig.lock.RLock() // 加读锁以安全地读取配置
			accountInfo, userExists := globalConfig.Accounts[c.User()]
			globalConfig.lock.RUnlock()

			// 1. 检查用户是否存在
			if !userExists {
				log.Printf("Auth failed: user '%s' not found.", c.User())
				return nil, fmt.Errorf("invalid credentials")
			}

			// 2. 检查账户是否被禁用
			if !accountInfo.Enabled {
				log.Printf("Auth failed: user '%s' is disabled.", c.User())
				return nil, fmt.Errorf("invalid credentials")
			}

			// 3. 检查账户是否过期
			// 如果 expiry_date 字段为空，则永不过期
			if accountInfo.ExpiryDate != "" {
				expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate)
				if err != nil {
					log.Printf("Auth failed: could not parse expiry date for user '%s'. Please check format (YYYY-MM-DD).", c.User())
					return nil, fmt.Errorf("invalid credentials")
				}
				// 检查是否在有效期内 (有效期当天也算有效)
				if time.Now().After(expiry.Add(24 * time.Hour)) {
					log.Printf("Auth failed: user '%s' has expired (expiry date: %s).", c.User(), accountInfo.ExpiryDate)
					return nil, fmt.Errorf("invalid credentials")
				}
			}

			// 4. 检查密码是否匹配
			if string(p) == accountInfo.Password {
				log.Printf("Auth successful for user: '%s'", c.User())
				return nil, nil // 所有检查通过，认证成功
			}

			log.Printf("Auth failed: incorrect password for user '%s'", c.User())
			return nil, fmt.Errorf("invalid credentials") // 密码错误
		},
	}
	
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	config.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("Listening on %s, forwarding to SOCKS5 %s", globalConfig.ListenAddr, globalConfig.SocksAddr)

	for {
		conn, err := l.Accept()
		if err != nil { log.Printf("accept fail: %v", err); continue }

		go func(c net.Conn) {
			atomic.AddInt64(&activeConn, 1)
			defer atomic.AddInt64(&activeConn, -1)
			handshakedConn, err := httpHandshake(c)
			if err != nil { log.Printf("http handshake failed: %v", err); c.Close(); return }
			log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")
			sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, config)
			if err != nil { log.Printf("ssh handshake failed for %s: %v", c.RemoteAddr(), err); c.Close(); return }
			defer sshConn.Close()
			log.Printf("Phase 2: SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User())
			go ssh.DiscardRequests(reqs)

			for newChan := range chans {
				if newChan.ChannelType() != "direct-tcpip" {
					newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed"); continue
				}
				ch, _, err := newChan.Accept(); if err != nil { log.Printf("accept channel fail: %v", err); continue }
				var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
				if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("bad payload: %v", err); ch.Close(); continue }
				go handleDirectTCPIP(ch, payload.Host, payload.Port)
			}
		}(conn)
	}
}
