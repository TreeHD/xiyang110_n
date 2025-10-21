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

	"golang.org/x/crypto/ssh"
)

// udpConnections 跟踪每个客户端的UDP连接
var udpConnections = struct {
	sync.RWMutex
	m map[string]net.PacketConn
}{
	m: make(map[string]net.PacketConn),
}

func addConn(clientKey string, conn net.PacketConn) {
	udpConnections.Lock()
	defer udpConnections.Unlock()
	udpConnections.m[clientKey] = conn
}

func delConn(clientKey string) {
	udpConnections.Lock()
	defer udpConnections.Unlock()
	if conn, ok := udpConnections.m[clientKey]; ok {
		conn.Close()
		delete(udpConnections.m, clientKey)
	}
}

// handleSocks5UDP 的最终实现，匹配最简化的协议
func handleSocks5UDP(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Final UDP Proxy: New session for %s", clientKey)
	defer log.Printf("Final UDP Proxy: Session for %s closed", clientKey)
	defer ch.Close()

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Final UDP Proxy: Failed to listen on UDP port for %s: %v", clientKey, err)
		return
	}
	defer udpConn.Close()
	addConn(clientKey, udpConn)
	defer delConn(clientKey)

	done := make(chan struct{})
	
	// Goroutine 1: 从SSH读取、解析、发送
	go func() {
		defer close(done)
		for {
			// 最终协议格式: [4字节目标IPv4地址][2字节目标端口][UDP真实数据]

			// 1. 读取6字节的目标地址头
			header := make([]byte, 6)
			if _, err := io.ReadFull(ch, header); err != nil {
				return
			}
			
			// 2. 解析IP和端口
			destIP := net.IP(header[0:4])
			destPort := binary.BigEndian.Uint16(header[4:6])

			destAddrStr := fmt.Sprintf("%s:%d", destIP.String(), destPort)
			destAddr, err := net.ResolveUDPAddr("udp", destAddrStr)
			if err != nil {
				continue
			}

			// 3. 读取剩余的数据作为UDP负载
			// 假设一个Read调用能读完一个UDP包的数据，这是合理的。
			payload := make([]byte, 2048) // 分配足够大的缓冲区
			n, err := ch.Read(payload)
			if err != nil {
				return // 任何错误都关闭会话
			}

			// 4. 发送UDP包
			if _, err := udpConn.WriteTo(payload[:n], destAddr); err != nil {
				// 忽略发送错误
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回，封装并发送回客户端
	go func() {
		buf := make([]byte, 4096)
		for {
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
				ch.Close()
				return
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil {
				continue // 只处理IPv4回包
			}

			// 封装回包: [4字节源IP][2字节源端口][数据]
			payload := buf[:n]
			
			frame := make([]byte, 6+len(payload))
			
			copy(frame[0:4], remoteIP)
			binary.BigEndian.PutUint16(frame[4:6], uint16(udpRemote.Port))
			copy(frame[6:], payload)

			if _, err := ch.Write(frame); err != nil {
				return
			}
		}
	}()

	<-done
}
