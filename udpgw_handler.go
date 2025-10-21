// udpgw_handler.go (最终智能识别版)
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
	targetAddr *net.UDPAddr      // UdpGw的目标地址
	dnsAddr    *net.UDPAddr      // DNS的固定地址
}

// clientManager 统一管理所有客户端会话
var clientManager = struct {
	sync.RWMutex
	clients map[string]*clientState
}{
	clients: make(map[string]*clientState),
}

// ... (Add, Delete 函数保持不变)

// handleUdpGw 最终版，能同时处理 UdpGw 和 原始DNS 流量
func handleUdpGw(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("Hybrid UDP Proxy: New session for %s", clientKey)
	defer log.Printf("Hybrid UDP Proxy: Session for %s closed", clientKey)
	defer ch.Close()

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("Hybrid UDP Proxy: Failed to listen on UDP for %s: %v", clientKey, err)
		return
	}
	
	// 为DNS查询预设一个默认的目标地址
	defaultDNSAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")

	state := &clientState{
		udpConn: udpConn,
		dnsAddr: defaultDNSAddr, // 设置默认DNS服务器
	}
	clientManager.Add(clientKey, state)
	defer clientManager.Delete(clientKey)

	done := make(chan struct{})

	// Goroutine 1: 从SSH读取、智能解析、发送
	go func() {
		defer close(done)
		
		header := make([]byte, 2)
		for {
			// 1. 读取开头的2个字节
			if _, err := io.ReadFull(ch, header); err != nil {
				return
			}

			// 2. 智能判断协议类型
			firstTwoBytes := binary.BigEndian.Uint16(header)

			// 这是一个启发式规则：UdpGw 的长度通常不会超过 MTU (1500)
			// 而 DNS 的 Transaction ID 是随机的，可能会很大。
			// 我们设置一个阈值，比如 2048。
			if firstTwoBytes > 0 && firstTwoBytes < 2048 {
				// *** 很可能是 UdpGw 协议 ***
				dataLen := firstTwoBytes
				fullData := make([]byte, dataLen)
				if _, err := io.ReadFull(ch, fullData); err != nil {
					return
				}

				packetType := fullData[0]
				payload := fullData[1:]

				if packetType != 0 { // 控制帧
					addrStr := string(payload)
					if !strings.Contains(addrStr, ":") {
						addrStr = fmt.Sprintf("%s:7300", addrStr)
					}
					destAddr, err := net.ResolveUDPAddr("udp", addrStr)
					if err != nil {
						log.Printf("Hybrid UDP Proxy: Failed to resolve UdpGw destination '%s' for %s: %v", addrStr, clientKey, err)
						continue // 解析失败，继续等待下一个包
					}
					state.targetAddr = destAddr
					log.Printf("Hybrid UDP Proxy: Set UdpGw destination to %s for %s", destAddr, clientKey)
				} else { // UdpGw 数据帧
					if state.targetAddr == nil { continue }
					udpConn.WriteTo(payload, state.targetAddr)
				}
			} else {
				// *** 很可能是原始DNS包 ***
				// 我们已经读了DNS ID的前两个字节 (header)
				// 现在需要读取DNS包的剩余部分
				// DNS查询通常不大，我们可以一次性多读一些
				restOfPacket := make([]byte, 1024)
				n, err := ch.Read(restOfPacket)
				if err != nil {
					return
				}
				
				// 拼接成完整的DNS包
				dnsPacket := append(header, restOfPacket[:n]...)
				log.Printf("Hybrid UDP Proxy: Detected raw DNS query (len %d) for %s", len(dnsPacket), clientKey)
				
				// 将这个DNS包发往预设的DNS服务器
				udpConn.WriteTo(dnsPacket, state.dnsAddr)
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回，需要判断是给谁的
	go func() {
		buf := make([]byte, 4096)
		for {
			// ... (这部分逻辑需要更复杂的设计来区分回包，我们先简化)
			// 为了快速验证，我们假设所有回包都按UdpGw格式封装
			// 这是一个不完美的简化，但足以验证我们的解析是否正确
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
			if remoteIP == nil { continue }
			
			payload := buf[:n]

			// 检查这个回包是不是DNS响应
			if udpRemote.Port == 53 && len(payload) > 2 {
				// 假设这是一个DNS回包，我们用简化格式发回
				// [4字节源IP=0][2字节源端口=0][DNS数据]
				// 很多客户端在这种情况下不检查源地址
				frame := make([]byte, 6+len(payload))
				// header留空，后面直接跟数据
				copy(frame[6:], payload)
				ch.Write(frame)
			} else {
				// 否则，认为是UdpGw的回包
				totalLen := 4 + 2 + len(payload)
				frame := make([]byte, 2+totalLen)
				binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
				copy(frame[2:6], remoteIP)
				binary.BigEndian.PutUint16(frame[6:8], uint16(udpRemote.Port))
				copy(frame[8:], payload)
				ch.Write(frame)
			}
		}
	}()

	<-done
}

// ... (ClientManager 的 Add, Get, Delete 函数)
