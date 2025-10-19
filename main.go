package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

var (
	addr       = flag.String("addr", ":2222", "listen address")
	hostKey    = flag.String("hostkey", "/etc/ssh_relay/host_ed25519", "SSH host key path")
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 address")
)

// loadHostKey 加载 SSH host key
func loadHostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

// handleConnection 处理单个客户端连接
func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// === 阶段 1: HTTP头认证 ===
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("read http header failed: %v", err)
			return
		}
		line = line[:len(line)-1] // 去掉 \n
		if line == "" {           // HTTP header 结束
			break
		}
		// 可以在这里验证 User-Agent 或其他 header
		if line == "User-Agent: 1.0" {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}
	}

	// === 阶段 2: 等待 SSH payload ===
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("read http phase2 failed: %v", err)
			return
		}
		if line == "User-Agent: 26.4.0\n" {
			log.Printf("Phase2: HTTP auth done, start SSH handshake")
			break
		}
	}

	// 用 reader 包装 conn 避免丢掉已读数据
	sshConn, chans, reqs, err := ssh.NewServerConn(struct {
		net.Conn
		io.Reader
	}{conn, reader}, config)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("New SSH connection from %s", sshConn.RemoteAddr())

	// 丢弃 global requests
	go ssh.DiscardRequests(reqs)

	// 这里只处理 direct-tcpip channel
	for newChan := range chans {
		if newChan.ChannelType() == "direct-tcpip" {
			ch, _, err := newChan.Accept()
			if err != nil {
				log.Printf("accept channel failed: %v", err)
				continue
			}
			go func(ch ssh.Channel) {
				defer ch.Close()
				// 直接转发到 SOCKS5
				sockConn, err := net.Dial("tcp", *socksAddr)
				if err != nil {
					log.Printf("socks connect failed: %v", err)
					return
				}
				defer sockConn.Close()
				go io.Copy(sockConn, ch)
				io.Copy(ch, sockConn)
			}(ch)
		} else {
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
		}
	}
}

func main() {
	flag.Parse()
	hostSigner, err := loadHostKey(*hostKey)
	if err != nil {
		log.Fatalf("load host key failed: %v", err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password auth disabled")
		},
	}
	config.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("Listening on %s, using SOCKS5 %s", *addr, *socksAddr)

	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept failed: %v", err)
			continue
		}
		go handleConnection(c, config)
	}
}
