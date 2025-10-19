// wstunnel-go-auth-pass.go
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
	// no-auth negotiation
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

	// CONNECT request (domain)
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

// wrapper to combine net.Conn and buffered reader
type connWithReader struct {
	net.Conn
	io.Reader
}

func (c *connWithReader) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func handleConn(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()

	reader := bufio.NewReader(c)

	// Optional HTTP phase detection: peek first bytes with a short timeout
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	peek, err := reader.Peek(4)
	c.SetReadDeadline(time.Time{})

	var preReader io.Reader = reader
	if err == nil && (string(peek) == "GET " || string(peek) == "POST") {
		// simple consume headers until blank line
		_, _ = reader.ReadString('\n') // ignore request line
		for {
			line, _ := reader.ReadString('\n')
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		// reply OK and continue waiting for SSH
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		// preReader already set to reader so remaining bytes are preserved
	}

	// SSH handshake: wrap conn so Read uses buffered reader (preserves already-read bytes)
	sshConn, chans, reqs, err := ssh.NewServerConn(&connWithReader{Conn: c, Reader: preReader}, config)
	if err != nil {
		log.Printf("ssh handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	log.Printf("new ssh conn from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// discard global requests
	go ssh.DiscardRequests(reqs)

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

	// ---- 修改处：使用密码认证 ----
	config := &ssh.ServerConfig{
		NoClientAuth: false, // 允许认证
		PasswordCallback: func(connMetadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// 这里使用你指定的账号密码 a555 / a444
			if connMetadata.User() == "a555" && string(password) == "a444" {
				return nil, nil
			}
			// 如果需要限制来源 IP / 做日志，可以在此添加
			return nil, fmt.Errorf("password rejected for %s", connMetadata.User())
		},
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
