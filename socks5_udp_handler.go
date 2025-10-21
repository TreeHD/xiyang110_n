// socks5_udp_handler.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

    // [核心修正] 将 golang.orgx 改为 golang.org
	"golang.org/x/crypto/ssh" 
)

// udpSession a udp session (struct name changed for clarity)
type udpSession struct {
	sshChan    ssh.Channel
	remoteAddr net.Addr
	udpConn    *net.UDPConn
}

// udpSessions for udp forward (variable name changed to avoid conflict)
var udpSessions = struct {
	sync.RWMutex
	m map[string]*udpSession // key: client remote address
}{
	m: make(map[string]*udpSession),
}

func addUDPSession(s *udpSession) {
	udpSessions.Lock()
	defer udpSessions.Unlock()
	udpSessions.m[s.remoteAddr.String()] = s
}

func getUDPSession(clientAddr string) *udpSession {
	udpSessions.RLock()
	defer udpSessions.RUnlock()
	return udpSessions.m[clientAddr]
}

func delUDPSession(clientAddr string) {
	udpSessions.Lock()
	defer udpSessions.Unlock()
	delete(udpSessions.m, clientAddr)
}


// handleSocks5UDP 是新的、健壮的SOCKS5 UDP处理器
func handleSocks5UDP(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("SOCKS5 UDP: New session for %s", clientKey)
	defer log.Printf("SOCKS5 UDP: Session for %s closed", clientKey)
	defer ch.Close()

	// 1. 创建一个用于和外部通信的UDP套接字
	s, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("SOCKS5 UDP: failed to listen on UDP port: %v", err)
		return
	}
	defer s.Close()
	
	sess := &udpSession{ // Use the new struct name
		sshChan:    ch,
		remoteAddr: remoteAddr,
		udpConn:    s,
	}
	addUDPSession(sess)
	defer delUDPSession(clientKey)
	
	done := make(chan struct{})

	// Goroutine 1: 从SSH通道读取客户端数据，解析并发送到外部
	go func() {
		defer close(done)
		for {
			// SOCKS5 UDP Request format:
			// +----+------+------+----------+----------+----------+
			// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
			// +----+------+------+----------+----------+----------+
			// | 2  |  1   |  1   | Variable |    2     | Variable |
			// +----+------+------+----------+----------+----------+
			
			header := make([]byte, 3)
			if _, err := io.ReadFull(ch, header); err != nil {
				return
			}
			if header[2] != 0x00 {
				log.Printf("SOCKS5 UDP: Unsupported FRAG value: %d", header[2])
				return
			}

			addrType := make([]byte, 1)
			if _, err := io.ReadFull(ch, addrType); err != nil {
				return
			}

			var host string
			switch addrType[0] {
			case 0x01: // IPv4
				addr := make([]byte, 4)
				if _, err := io.ReadFull(ch, addr); err != nil { return }
				host = net.IP(addr).String()
			case 0x03: // Domain
				lenByte := make([]byte, 1)
				if _, err := io.ReadFull(ch, lenByte); err != nil { return }
				domain := make([]byte, lenByte[0])
				if _, err := io.ReadFull(ch, domain); err != nil { return }
				host = string(domain)
			case 0x04: // IPv6
				addr := make([]byte, 16)
				if _, err := io.ReadFull(ch, addr); err != nil { return }
				host = net.IP(addr).String()
			default:
				log.Printf("SOCKS5 UDP: Unsupported address type: %d", addrType[0])
				return
			}

			portBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, portBytes); err != nil { return }
			port := binary.BigEndian.Uint16(portBytes)

			payload := make([]byte, 1500) // MTU size
			n, err := ch.Read(payload)
			if err != nil { return }

			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				log.Printf("SOCKS5 UDP: Failed to resolve %s:%d: %v", host, port, err)
				continue
			}
			_, err = s.WriteTo(payload[:n], destAddr)
			if err != nil {
				log.Printf("SOCKS5 UDP: Failed to write to %s: %v", destAddr, err)
			}
		}
	}()

	// Goroutine 2: 从公网UDP套接字读取返回数据，封装并发送回客户端
	go func() {
		buf := make([]byte, 2048)
		for {
			s.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, remote, err := s.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					close(done)
				}
				continue
			}

			var socks5Header []byte
			socks5Header = append(socks5Header, []byte{0x00, 0x00, 0x00}...) // RSV + FRAG

			if remote.IP.To4() != nil {
				socks5Header = append(socks5Header, 0x01) // ATYP IPv4
				socks5Header = append(socks5Header, remote.IP.To4()...)
			} else { // IPv6
				socks5Header = append(socks5Header, 0x04) // ATYP IPv6
				socks5Header = append(socks5Header, remote.IP.To16()...)
			}
			
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(remote.Port))
			socks5Header = append(socks5Header, portBytes...)

			fullFrame := append(socks5Header, buf[:n]...)

			select {
			case <-done:
				return
			default:
				if _, err := ch.Write(fullFrame); err != nil {
					return
				}
			}
		}
	}()

	<-done
}
