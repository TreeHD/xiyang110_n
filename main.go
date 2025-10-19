// wstunnel-http-ssh.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	addr        = flag.String("addr", ":2222", "listen address")
	hostKeyPath = flag.String("hostkey", "/etc/ssh_relay/host_ed25519", "host key file (PEM/openssh)")
	socksAddr   = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 address")
)

var activeConnCount int64

func loadHostKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyData)
}

// minimal SOCKS5 connect
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// no-auth handshake
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
	// CONNECT request
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}
	req = append(req, []byte(destHost)...)
	req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// read reply
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, err
	}
	if rep[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect failed, rep=%d", rep[1])
	}
	// discard remaining addr/port
	switch rep[3] {
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

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConnCount, 1)
	defer atomic.AddInt64(&activeConnCount, -1)
	sockConn, err := socks5Connect(*socksAddr, destHost, uint16(destPort))
	if err != nil {
		log.Printf("socks connect failed: %v", err)
		ch.Close()
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

func handleConn(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()

	reader := bufio.NewReader(c)

	// HTTP 阶段（可选认证）
	c.SetReadDeadline(time.Now().Add(3 * time.Second)) // 超时防止客户端不发数据阻塞
	peek, err := reader.Peek(4)
	c.SetReadDeadline(time.Time{}) // 取消超时
	if err == nil && (string(peek) == "GET " || string(peek) == "POST") {
		// 简单读取 HTTP 请求行和 User-Agent
		reqLine, _ := reader.ReadString('\n')
		for {
			line, _ := reader.ReadString('\n')
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		// 返回 200 OK
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}

	// 进入 SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(reader, config)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("new ssh conn from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// discard global requests
	go ssh.DiscardRequests(reqs)

	// handle channels
	for newChan := range chans {
		if newChan.ChannelType() == "direct-tcpip" {
			var payload struct {
				Host string
				Port uint32
			}
			if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
				newChan.Reject(ssh.ConnectionFailed, "bad payload")
				continue
			}
			ch, _, err := newChan.Accept()
			if err != nil {
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
		NoClientAuth: true,
	}
	config.AddHostKey(hostSigner)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
	log.Printf("Listening on %s, using SOCKS5 %s", *addr, *socksAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}
