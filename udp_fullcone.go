// udp_fullcone.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const udpSessionTimeout = 2 * time.Minute // UDP会话超时时间，2分钟

// fullConeSession 维护一个Full Cone NAT会话
type fullConeSession struct {
	clientChannel ssh.Channel  // 回写给客户端的SSH信道
	publicConn    net.PacketConn // 服务器对外暴露的UDP "专属外线"
	lastActive    time.Time
}

// sessionManager 管理所有UDP会话
var sessionManager = struct {
	sync.RWMutex
	sessions map[string]*fullConeSession // key是客户端的SSH连接的远程地址
}{
	sessions: make(map[string]*fullConeSession),
}

// init 用于启动后台的超时会话清理任务
func init() {
	go func() {
		for {
			time.Sleep(30 * time.Second) // 每30秒检查一次
			now := time.Now()
			sessionManager.Lock()
			for key, session := range sessionManager.sessions {
				if now.Sub(session.lastActive) > udpSessionTimeout {
					log.Printf("FullCone NAT: Closing stale UDP session for %s", key)
					session.clientChannel.Close() // 这会导致 tcpToUDP 结束
					session.publicConn.Close()    // 这会导致 udpToTCP 结束
					delete(sessionManager.sessions, key)
				}
			}
			sessionManager.Unlock()
		}
	}()
}

// handleUDPProxy 是7300端口的总入口，实现了Full Cone NAT
func handleUDPProxy(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()

	defer func() {
		log.Printf("FullCone NAT: Closing client connection and UDP session for %s", clientKey)
		sessionManager.Lock()
		if session, ok := sessionManager.sessions[clientKey]; ok {
			session.publicConn.Close()
			delete(sessionManager.sessions, clientKey)
		}
		sessionManager.Unlock()
		ch.Close()
	}()

	// 为这个客户端创建一个对外暴露的UDP Socket
	publicConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		log.Printf("FullCone NAT: Failed to listen on UDP port for %s: %v", clientKey, err)
		return
	}
	log.Printf("FullCone NAT: New session for %s, public endpoint is %s", clientKey, publicConn.LocalAddr())

	session := &fullConeSession{
		clientChannel: ch,
		publicConn:    publicConn,
		lastActive:    time.Now(),
	}

	sessionManager.Lock()
	sessionManager.sessions[clientKey] = session
	sessionManager.Unlock()

	// 启动goroutine，负责从“外网”接收数据并回传给客户端
	go udpToTCP(session)

	// 在当前goroutine中，负责从“客户端”接收数据并转发到外网
	tcpToUDP(session)
}

// tcpToUDP 从客户端的SSH信道读取SOCKS5 UDP帧，并发送到外网
func tcpToUDP(s *fullConeSession) {
	clientKey := s.clientChannel.RemoteAddr().String()
	for {
		// SOCKS5 UDP Frame: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA_LEN(2) DATA
		header := make([]byte, 4)
		if _, err := io.ReadFull(s.clientChannel, header); err != nil {
			// 连接断开或出错，结束goroutine
			return
		}

		var host string
		// ATYP (Address Type)
		switch header[3] {
		case 0x01: // IPv4
			addrBytes := make([]byte, 4); if _, err := io.ReadFull(s.clientChannel, addrBytes); err != nil { return }; host = net.IP(addrBytes).String()
		case 0x03: // Domain
			lenBytes := make([]byte, 1); if _, err := io.ReadFull(s.clientChannel, lenBytes); err != nil { return }; domainBytes := make([]byte, lenBytes[0]); if _, err := io.ReadFull(s.clientChannel, domainBytes); err != nil { return }; host = string(domainBytes)
		case 0x04: // IPv6
			addrBytes := make([]byte, 16); if _, err := io.ReadFull(s.clientChannel, addrBytes); err != nil { return }; host = fmt.Sprintf("[%s]", net.IP(addrBytes).String())
		default:
			log.Printf("FullCone NAT: Unsupported ATYP %d from %s", header[3], clientKey); return
		}

		portBytes := make([]byte, 2); if _, err := io.ReadFull(s.clientChannel, portBytes); err != nil { return }
		port := binary.BigEndian.Uint16(portBytes)
		
		destAddrStr := fmt.Sprintf("%s:%d", host, port)
		if strings.HasPrefix(host, "[") { // Handle IPv6 case where brackets are already added
			destAddrStr = fmt.Sprintf("%s:%d", host, port)
		}

		dataLenBytes := make([]byte, 2)
		if _, err := io.ReadFull(s.clientChannel, dataLenBytes); err != nil { return }
		dataLen := binary.BigEndian.Uint16(dataLenBytes)

		// 保护措施，防止过大的dataLen耗尽内存
		if dataLen > 2048 {
			log.Printf("FullCone NAT: Received oversized UDP packet (%d bytes) from %s", dataLen, clientKey)
			return
		}
		
		buf := make([]byte, dataLen)
		if _, err := io.ReadFull(s.clientChannel, buf); err != nil { return }
		
		udpAddr, err := net.ResolveUDPAddr("udp", destAddrStr)
		if err != nil {
			log.Printf("FullCone NAT: Failed to resolve destination %s for %s: %v", destAddrStr, clientKey, err)
			continue
		}
		
		_, err = s.publicConn.WriteTo(buf, udpAddr)
		if err != nil {
			// 在连接关闭后继续写入是正常错误，无需打印
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("FullCone NAT: Error writing UDP packet to %s for %s: %v", destAddrStr, clientKey, err)
			}
		}

		sessionManager.Lock(); s.lastActive = time.Now(); sessionManager.Unlock()
	}
}

// udpToTCP 从服务器的“专属外线”接收UDP包，打包成SOCKS5 UDP帧并发回客户端
func udpToTCP(s *fullConeSession) {
	clientKey := s.clientChannel.RemoteAddr().String()
	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := s.publicConn.ReadFrom(buf)
		if err != nil {
			// publicConn被关闭，说明会话结束
			return
		}

		udpRemoteAddr, ok := remoteAddr.(*net.UDPAddr)
		if !ok { continue }

		var frame []byte
		header := []byte{0x00, 0x00, 0x00} // RSV, FRAG

		var addrBytes []byte
		if ip4 := udpRemoteAddr.IP.To4(); ip4 != nil {
			header = append(header, 0x01); addrBytes = ip4
		} else {
			header = append(header, 0x04); addrBytes = udpRemoteAddr.IP
		}
		
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(udpRemoteAddr.Port))
		
		dataLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLenBytes, uint16(n))
		
		frame = append(frame, header...)
		frame = append(frame, addrBytes...)
		frame = append(frame, portBytes...)
		frame = append(frame, dataLenBytes...)
		frame = append(frame, buf[:n]...)
		
		if _, err := s.clientChannel.Write(frame); err != nil {
			// 写入失败，说明客户端SSH信道已关闭
			return
		}

		sessionManager.Lock(); s.lastActive = time.Now(); sessionManager.Unlock()
	}
}
