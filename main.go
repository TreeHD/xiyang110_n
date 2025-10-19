// ssh_http_relay.go
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
	addr      = flag.String("addr", ":2222", "listen address")
	hostKey   = flag.String("hostkey", "/etc/ssh_relay/host_ed25519", "SSH host key path")
	socksAddr = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 address")
)

// loadHostKey 加载 SSH host key
func loadHostKey(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

// connWithReader 包装 net.Conn 并使用自定义 Reader
type connWithReader struct {
	net.Conn
	r io.Reader
}

func (c *connWithReader) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// socks5Connect 简单直连到 SOCKS5
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	// minimal SOCKS5 handshake: no auth
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
	// build CONNECT request
	req := []byte{0x05, 0x01, 0x00}
	req = append(req, 0x03)                 // domain
	req = append(req, byte(len(destHost)))  // host len
	req = append(req, []byte(destHost)...)
	req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// read reply
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		c.Close()
		return nil, err
	}
	if h[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect failed, rep=%d", h[1])
	}
	// read addr/port
	switch h[3] {
	case 0x01:
		_, _ = io.CopyN(io.Discard, c, 4+2)
	case 0x03:
		alen := make([]byte, 1)
		if _, err := io.ReadFull(c, alen); err != nil {
			c.Close()
			return nil, err
		}
		_, _ = io.CopyN(io.Discard, c, int64(alen[0])+2)
	case 0x04:
		_, _ = io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}

// handleDirectTCPIP 转发 direct-tcpip channel 到 SOCKS5
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	defer ch.Close()
	sockConn, err := socks5Connect(*socksAddr, destHost, uint16(destPort))
	if err != nil {
		log.Printf("socks connect failed: %v", err)
		return
	}
	defer sockConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(sockConn, ch)
		sockConn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ch, sockConn)
		ch.Close()
		done <- struct{}{}
	}()
	<-done
}

// handleConnection 处理每个客户端连接
func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// ===== HTTP 阶段认证 =====
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
		if line == "User-Agent: 1.0" {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}
	}

	// ===== 等待 SSH payload =====
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

	// ===== SSH handshake =====
	cwrap := &connWithReader{
		Conn: conn,
		r:    reader,
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(cwrap, config)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("New SSH connection from %s", sshConn.RemoteAddr())

	// 丢弃全局请求
	go ssh.DiscardRequests(reqs)

	// 只处理 direct-tcpip channel
	for newChan := range chans {
		if newChan.ChannelType() == "direct-tcpip" {
			ch, req, err := newChan.Accept()
			if err != nil {
				log.Printf("accept channel failed: %v", err)
				continue
			}
			go handleDirectTCPIP(ch, string(newChan.ExtraData()), 0)
			_ = req
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
