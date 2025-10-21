// simple_udp_handler.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// activeUDPConnections 跟踪每个客户端的UDP连接
var activeUDPConnections = struct {
	sync.RWMutex
	conns map[string]net.PacketConn
}{
	conns: make(map[string]net.PacketConn),
}

func addUDPConn(clientKey string, conn net.PacketConn) {
	activeUDPConnections.Lock()
	defer activeUDPConnections.Unlock()
	activeUDPConnections.conns[clientKey] = conn
}

func getUDPConn(clientKey string) net.PacketConn {
	activeUDPConnections.RLock()
	defer activeUDPConnections.RUnlock()
	return activeUDPConnections.conns[clientKey]
}

func delUDPConn(clientKey string) {
	activeUDPConnections.Lock()
	defer activeUDPConnections.Unlock()
	if conn, ok := activeUDPConnections.conns[clientKey]; ok {
		conn.Close()
		delete(activeUDPConnections.conns, clientKey)
	}
}

// handleCustomUDP 是最终的、最简化的UDP处理器
func handleCustomUDP(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Custom UDP Proxy: New session for %s", clientKey)
	defer log.Printf("Custom UDP Proxy: Session for %s closed", clientKey)
	defer ch.Close()

	// 为每个客户端创建一个独立的UDP套接字
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Custom UDP Proxy: Failed to listen on UDP port for %s: %v", clientKey, err)
		return
	}
	defer udpConn.Close()
	addUDPConn(clientKey, udpConn)
	defer delUDPConn(clientKey)

	done := make(chan struct{})

	// Goroutine 1: 从SSH读取，解析，并发送UDP包
	go func() {
		defer func() {
			close(done) // 关闭done chan通知另一个goroutine退出
		}()
		for {
			// 1. 读取地址类型 (1 byte)
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
			case 0x03: // 域名
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
				log.Printf("Custom UDP Proxy: Unsupported address type from %s: %d", clientKey, addrType[0])
				return
			}

			// 2. 读取端口 (2 bytes)
			portBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, portBytes); err != nil { return }
			port := binary.BigEndian.Uint16(portBytes)
			
			// 3. 读取数据 (最关键的部分)
			// 假设数据包以一个2字节的长度开头
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)

			if dataLen > 4096 { // 增加一个合理的限制
				log.Printf("Custom UDP Proxy: Oversized payload (%d) from %s", dataLen, clientKey)
				return
			}

			payload := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, payload); err != nil {
				return
			}
			
			destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
			if err != nil {
				continue
			}
			
			_, err = udpConn.WriteTo(payload, destAddr)
			if err != nil {
				log.Printf("Custom UDP Proxy: Failed to write to %s: %v", destAddr, err)
			}
		}
	}()

	// Goroutine 2: 从UDP套接字读取返回数据，封装并发送回客户端
	go func() {
		buf := make([]byte, 4096)
		for {
			// 检查是否应该退出
			select {
			case <-done:
				return
			default:
			}
			
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, remote, err := udpConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			udpRemote := remote.(*net.UDPAddr)
			
			// 封装回包
			var header []byte
			if ip4 := udpRemote.IP.To4(); ip4 != nil {
				header = append(header, 0x01)
				header = append(header, ip4...)
			} else if ip16 := udpRemote.IP.To16(); ip16 != nil {
				header = append(header, 0x04)
				header = append(header, ip16...)
			} else {
				continue // 不支持的地址类型
			}

			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(udpRemote.Port))
			header = append(header, portBytes...)

			lenBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBytes, uint16(n))
			header = append(header, lenBytes...)
			
			fullFrame := append(header, buf[:n]...)

			if _, err := ch.Write(fullFrame); err != nil {
				return
			}
		}
	}()
	
	<-done
}
