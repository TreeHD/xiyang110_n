// udpgw_handler.go
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

// clientState 用于存储每个客户端会话的状态
type clientState struct {
	udpConn    net.PacketConn
	targetAddr *net.UDPAddr
	dnsAddr    *net.UDPAddr
	sshChan    ssh.Channel
	done       chan struct{}
	key        string
}

// ClientManager 定义
type ClientManager struct {
	sync.RWMutex
	clients map[string]*clientState
}

var clientManager = &ClientManager{
	clients: make(map[string]*clientState),
}

// Add, Get, Delete 方法保持不变
func (cm *ClientManager) Add(key string, state *clientState) {
	cm.Lock()
	defer cm.Unlock()
	cm.clients[key] = state
}
func (cm *ClientManager) Delete(key string) {
	cm.Lock()
	defer cm.Unlock()
	if state, ok := cm.clients[key]; ok {
		state.udpConn.Close()
		delete(cm.clients, key)
	}
}

// handleUdpGw 的最终实现
func handleUdpGw(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Hybrid UDP Proxy: New session for %s", clientKey)
	
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Hybrid UDP Proxy: Failed to listen on UDP for %s: %v", clientKey, err)
		ch.Close()
		return
	}

	defaultDNSAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")

	state := &clientState{
		udpConn: udpConn,
		dnsAddr: defaultDNSAddr,
		sshChan: ch,
		done:    make(chan struct{}),
		key:     clientKey,
	}
	clientManager.Add(clientKey, state)

	defer func() {
		log.Printf("Hybrid UDP Proxy: Session for %s closed", clientKey)
		clientManager.Delete(clientKey)
	//	ch.Close() // ch 由上层调用者关闭
	}()

	// Goroutine 1: 从SSH读取、智能解析、发送
	go func() {
		defer close(state.done)
		header := make([]byte, 2)
		for {
			if _, err := io.ReadFull(ch, header); err != nil {
				return
			}
			firstTwoBytes := binary.BigEndian.Uint16(header)

			if firstTwoBytes > 0 && firstTwoBytes < 2048 {
				// UdpGw 协议
				dataLen := firstTwoBytes
				fullData := make([]byte, dataLen)
				if _, err := io.ReadFull(ch, fullData); err != nil { return }
				
				packetType := fullData[0]
				payload := fullData[1:]

				if packetType != 0 { // 控制帧
					addrStr := string(payload)
					if !strings.Contains(addrStr, ":") { addrStr = fmt.Sprintf("%s:7300", addrStr) }
					destAddr, err := net.ResolveUDPAddr("udp", addrStr)
					if err != nil {
						log.Printf("Hybrid UDP Proxy: Failed to resolve UdpGw destination '%s': %v", addrStr, err)
						continue
					}
					state.targetAddr = destAddr
					log.Printf("Hybrid UDP Proxy: Set UdpGw destination to %s for %s", destAddr, clientKey)
				} else { // 数据帧
					if state.targetAddr == nil { continue }
					udpConn.WriteTo(payload, state.targetAddr)
				}
			} else {
				// 原始DNS包
				restOfPacket := make([]byte, 1024)
				n, err := ch.Read(restOfPacket)
				if err != nil { return }
				
				dnsPacket := append(header, restOfPacket[:n]...)
				udpConn.WriteTo(dnsPacket, state.dnsAddr)
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-state.done:
				return
			default:
			}
			
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, remote, err := udpConn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() { continue }
				return 
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil { continue }
			
			payload := buf[:n]
			
			// [核心修复] 对所有回包都使用同一种最简单的格式
			// 客户端既然能发两种格式，大概率也能接收一种统一的格式
			// 格式: [4字节源IP][2字节源端口][数据]
			frame := make([]byte, 6+len(payload))
			
			copy(frame[0:4], remoteIP)
			binary.BigEndian.PutUint16(frame[4:6], uint16(udpRemote.Port))
			copy(frame[6:], payload)

			if _, err := ch.Write(frame); err != nil {
				return
			}
		}
	}()

	<-state.done
}
