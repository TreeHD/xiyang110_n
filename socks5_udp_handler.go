// socks5_udp_handler.go
package main

import (
	"encoding/binary"
	"fmt" // [核心修正] 添加回 fmt 包的导入
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

// handleSocks5UDP 的最终实现，匹配客户端的真实协议
func handleSocks5UDP(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Custom UDP Proxy: New session for %s", clientKey)
	defer log.Printf("Custom UDP Proxy: Session for %s closed", clientKey)
	defer ch.Close()

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Custom UDP Proxy: Failed to listen on UDP port for %s: %v", clientKey, err)
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
			// 协议格式: [2字节总长度][4字节目标IPv4地址][2字节目标端口][UDP真实数据]

			// 1. 读取2字节的总长度
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			totalLen := int(binary.BigEndian.Uint16(lenBytes))

			// 2. 读取剩余的全部数据
			if totalLen < 6 { // 长度至少要包含 IP(4) + Port(2)
				log.Printf("Custom UDP Proxy: Invalid packet length %d from %s. Closing session.", totalLen, clientKey)
				return
			}
			
			data := make([]byte, totalLen)
			if _, err := io.ReadFull(ch, data); err != nil {
				return
			}

			// 3. 从数据中解析出地址、端口和负载
			destIP := net.IP(data[0:4])
			destPort := binary.BigEndian.Uint16(data[4:6])
			payload := data[6:]

			destAddrStr := fmt.Sprintf("%s:%d", destIP.String(), destPort)
			destAddr, err := net.ResolveUDPAddr("udp", destAddrStr)
			if err != nil {
				continue
			}
			
			// 4. 发送UDP包
			if _, err := udpConn.WriteTo(payload, destAddr); err != nil {
				// 忽略单个包的发送错误，继续处理下一个
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
				// 真正的错误发生，通过关闭SSH通道来通知另一个goroutine退出
				ch.Close()
				return
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil {
				continue // 只处理IPv4回包
			}

			// 封装回包: [2字节总长][4字节源IP][2字节源端口][数据]
			payload := buf[:n]
			totalLen := 4 + 2 + len(payload)
			
			frame := make([]byte, 2+totalLen)
			
			binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
			copy(frame[2:6], remoteIP)
			binary.BigEndian.PutUint16(frame[6:8], uint16(udpRemote.Port))
			copy(frame[8:], payload)

			if _, err := ch.Write(frame); err != nil {
				return
			}
		}
	}()

	<-done
}
