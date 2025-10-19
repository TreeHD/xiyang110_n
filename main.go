// wstunnel_full.go
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

// SOCKS5 connect
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		return nil, err
	}

	// NO AUTH
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
	if buf[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 auth failed")
	}

	// CONNECT request
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}
	req = append(req, []byte(destHost)...)
	req = append(req, byte(destPort>>8), byte(destPort&0xff))
	_, err = c.Write(req)
	if err != nil {
		c.Close()
		return nil, err
	}

	// reply
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, err
	}
	if rep[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 connect failed")
	}

	// read remaining address info
	switch rep[3] {
	case 0x01:
		io.CopyN(io.Discard, c, 4+2)
	case 0x03:
		alen := make([]byte, 1)
		io.ReadFull(c, alen)
		io.CopyN(io.Discard, c, int64(alen[0])+2)
	case 0x04:
		io.CopyN(io.Discard, c, 16+2)
	}

	return c, nil
}

func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) {
	atomic.AddInt64(&activeConn, 1)
	defer atomic.AddInt64(&activeConn, -1)

	// TCP 透传到 SOCKS5
	socksConn, err := socks5Connect(*socksAddr, destHost, uint16(destPort))
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

func main() {
	flag.Parse()

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

			if err := httpHandshake(c); err != nil {
				log.Printf("http handshake failed: %v", err)
				c.Close()
				return
			}
			log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")

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

				var payload struct {
					Host       string
					Port       uint32
					OriginAddr string
					OriginPort uint32
				}
				if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
					log.Printf("bad payload: %v", err)
					ch.Close()
					continue
				}

				go handleDirectTCPIP(ch, payload.Host, payload.Port)
			}

		}(conn)
	}
}
