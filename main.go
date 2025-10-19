// wstunnel_full_reuse_socks.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

var (
	listenAddr = flag.String("addr", ":2222", "Listen address")
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 address")
	user       = flag.String("user", "a555", "SSH username")
	pass       = flag.String("pass", "a444", "SSH password")
)

var (
	activeConn int64
	socksConn  net.Conn
	socksLock  = &sync.Mutex{}
)

func handleDirectTCPIP(ch ssh.Channel) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	done := make(chan struct{}, 2)
	go func() {
		socksLock.Lock()
		io.Copy(socksConn, ch)
		socksLock.Unlock()
		done <- struct{}{}
	}()
	go func() {
		socksLock.Lock()
		io.Copy(ch, socksConn)
		socksLock.Unlock()
		done <- struct{}{}
	}()
	<-done
	ch.Close()
}

// HTTP 阶段 User-Agent 验证
func httpHandshake(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read http header fail: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" { // headers end
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			if strings.Contains(line, "26.4.0") {
				_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				if err != nil {
					return fmt.Errorf("write http response fail: %v", err)
				}
				return nil
			}
			return fmt.Errorf("invalid user-agent")
		}
	}
	return fmt.Errorf("user-agent not found")
}

func main() {
	flag.Parse()

	// SSH Server 配置
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == *user && string(p) == *pass {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	// 生成 Ed25519 host key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate host key fail: %v", err)
	}
	privateKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("create signer fail: %v", err)
	}
	config.AddHostKey(privateKey)

	// 建立持久 SOCKS5 连接
	socksConn, err = net.Dial("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("connect to SOCKS5 fail: %v", err)
	}
	defer socksConn.Close()
	log.Printf("Using persistent SOCKS5 connection to %s", *socksAddr)

	// 监听端口
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen fail: %v", err)
	}
	log.Printf("Listening on %s, forwarding to SOCKS5 %s", *listenAddr, *socksAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept fail: %v", err)
			continue
		}

		go func(c net.Conn) {
			atomic.AddInt64(&activeConn, 1)
			defer atomic.AddInt64(&activeConn, -1)

			// HTTP 阶段握手
			if err := httpHandshake(c); err != nil {
				log.Printf("http handshake failed: %v", err)
				c.Close()
				return
			}
			log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")

			// SSH 握手
			sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
			if err != nil {
				log.Printf("ssh handshake failed: %v", err)
				c.Close()
				return
			}
			defer sshConn.Close()
			log.Printf("Phase 2: SSH handshake success from %s", sshConn.RemoteAddr())
			go ssh.DiscardRequests(reqs)

			for newChan := range chans {
				if newChan.ChannelType() != "direct-tcpip" {
					newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
					continue
				}
				ch, _, err := newChan.Accept()
				if err != nil {
					log.Printf("accept channel fail: %v", err)
					continue
				}

				// 直接透传，不解析 ExtraData
				go handleDirectTCPIP(ch)
			}

		}(conn)
	}
}
