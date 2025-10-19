// wstunnel_multi.go完整版
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
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

var (
	listenAddr = flag.String("addr", ":2222", "Listen address")
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "Local SOCKS5 address")
	user       = flag.String("user", "a555", "SSH username")
	pass       = flag.String("pass", "a444", "SSH password")
)

var activeConn int64

func handleDirectTCPIP(ch ssh.Channel) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// TCP 透传到 SOCKS5
	socksConn, err := net.Dial("tcp", *socksAddr)
	if err != nil {
		log.Printf("connect to SOCKS5 fail: %v", err)
		ch.Close()
		return
	}
	defer socksConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(socksConn, ch)
		socksConn.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(ch, socksConn)
		ch.Close()
		done <- struct{}{}
	}()
	<-done
}

// 检查 HTTP 请求头 User-Agent
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
				// 返回 200 OK
				_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				if err != nil {
					return fmt.Errorf("write http response fail: %v", err)
				}
				return nil
			} else {
				return fmt.Errorf("invalid user-agent")
			}
		}
	}
	return fmt.Errorf("user-agent not found")
}

func handleSSHConnection(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// HTTP 阶段握手
	if err := httpHandshake(c); err != nil {
		log.Printf("http handshake failed: %v", err)
		return
	}
	log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")

	// SSH 握手
	sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("Phase 2: SSH handshake success from %s", sshConn.RemoteAddr())
	go ssh.DiscardRequests(reqs)

	// 多 channel 循环
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

		go handleDirectTCPIP(ch)
	}
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

		go handleSSHConnection(conn, config)
	}
}
