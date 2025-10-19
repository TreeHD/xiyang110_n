package main

import (
	"bufio"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	addr        = flag.String("addr", ":2222", "listen address")
	hostKeyPath = flag.String("hostkey", "./host_ed25519", "host key file (PEM/openssh)")
	localSocks  = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 address (v2ray inbound)")
)

var activeConnCount int64

// loadHostKey 读取 PEM 或 OpenSSH 格式私钥
func loadHostKey(path string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err == nil {
		return signer, nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	return ssh.ParsePrivateKey(b)
}

// socks5Connect minimal SOCKS5 CONNECT
func socks5Connect(socksAddr, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	_, err = c.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		c.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 auth failed")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03}
	req = append(req, byte(len(destHost)))
	req = append(req, []byte(destHost)...)
	req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		c.Close()
		return nil, err
	}
	if h[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect failed, rep=%d", h[1])
	}
	switch h[3] {
	case 0x01:
		_, _ = io.CopyN(ioutil.Discard, c, 4+2)
	case 0x03:
		alen := make([]byte, 1)
		_, _ = io.ReadFull(c, alen)
		_, _ = io.CopyN(ioutil.Discard, c, int64(alen[0])+2)
	case 0x04:
		_, _ = io.CopyN(ioutil.Discard, c, 16+2)
	}
	return c, nil
}

// handleDirectTCPIP 处理 direct-tcpip channel
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConnCount, 1)
	defer atomic.AddInt64(&activeConnCount, -1)

	sockConn, err := socks5Connect(*localSocks, destHost, uint16(destPort))
	if err != nil {
		log.Printf("socks connect fail: %v", err)
		ch.Close()
		return
	}
	defer sockConn.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(sockConn, ch); sockConn.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, sockConn); ch.Close(); done <- struct{}{} }()
	<-done
}

// handleConnWithHTTPAuth 处理握手阶段 HTTP + SSH
func handleConnWithHTTPAuth(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()

	reader := bufio.NewReader(c)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println("read header error:", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			ua := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if ua == "1.0" {
				// 阶段1：返回200 OK，保持连接
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				log.Println("Phase 1 OK: waiting for next payload")
				continue
			} else if ua == "26.4.0" {
				log.Println("Phase 2: received User-Agent 26.4.0, start SSH handshake")
				break
			} else {
				log.Println("Unknown User-Agent, close")
				return
			}
		}
	}

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		log.Println("ssh handshake failed:", err)
		return
	}
	log.Printf("SSH authenticated from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() == "direct-tcpip" {
			var payload struct {
				Host       string
				Port       uint32
				OriginAddr string
				OriginPort uint32
			}
			if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
				newChan.Reject(ssh.ConnectionFailed, "bad payload")
				continue
			}
			ch, err := newChan.Accept()
			if err != nil {
				log.Println("accept channel err:", err)
				continue
			}
			go handleDirectTCPIP(ch, payload.Host, payload.Port)
		} else {
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
		}
	}
}

func main() {
	flag.Parse()

	hostSigner, err := loadHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("load host key error: %v", err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// 自定义账号密码 a555:a444
			if conn.User() == "a555" && string(pass) == "a444" {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	config.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	log.Printf("listening on %s, using socks %s", *addr, *localSocks)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go handleConnWithHTTPAuth(conn, config)
	}
}
