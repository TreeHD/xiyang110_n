// final_udp_handler.go
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

func getConn(clientKey string) net.PacketConn {
	udpConnections.RLock()
	defer udpConnections.RUnlock()
	return udpConnections.m[clientKey]
}

func delConn(clientKey string) {
	udpConnections.Lock()
	defer udpConnections.Unlock()
	if conn, ok := udpConnections.m[clientKey]; ok {
		conn.Close()
		delete(udpConnections.m, clientKey)
	}
}

func handleFinalUDP(ch ssh.Channel, remoteAddr net.Addr) {
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
			// 1. 读取2字节的总长度
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			totalLen := binary.BigEndian.Uint16(lenBytes)

			if totalLen < 6 { // 至少要有 IP(4) + Port(2)
				log.Printf("Final UDP Proxy: Invalid packet length %d from %s", totalLen, clientKey)
				return
			}

			// 2. 读取剩余的全部数据
			data := make([]byte, totalLen)
			if _, err := io.ReadFull(ch, data); err != nil {
				return
			}

			// 3. 从数据中解析出地址、端口和负载
			destIP := net.IP(data[0:4])
			destPort := binary.BigEndian.Uint16(data[4:6])
			payload := data[6:]

			destAddr := &net.UDPAddr{IP: destIP, Port: int(destPort)}

			// 4. 发送UDP包
			if _, err := udpConn.WriteTo(payload, destAddr); err != nil {
				log.Printf("Final UDP Proxy: Error writing to %s for %s: %v", destAddr, clientKey, err)
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
				return
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil {
				continue // 只处理IPv4
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
