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
	udpConn    net.PacketConn    // 每个客户端独享一个UDP套接字
	targetAddr *net.UDPAddr      // 客户端指定的目标地址
	sshChan    ssh.Channel       // 回传数据的SSH通道
	done       chan struct{}       // 用于同步关闭的channel
	key        string            // 客户端的唯一标识
}

// clientManager 统一管理所有客户端会话
var clientManager = struct {
	sync.RWMutex
	clients map[string]*clientState
}{
	clients: make(map[string]*clientState),
}

func (cm *clientManager) Add(key string, state *clientState) {
	cm.Lock()
	defer cm.Unlock()
	cm.clients[key] = state
}

func (cm *clientManager) Get(key string) *clientState {
	cm.RLock()
	defer cm.RUnlock()
	return cm.clients[key]
}

func (cm *clientManager) Delete(key string) {
	cm.Lock()
	defer cm.Unlock()
	if state, ok := cm.clients[key]; ok {
		state.udpConn.Close() // 关闭UDP连接
		delete(cm.clients, key)
	}
}

// handleUdpGw 严格复刻 badvpn-udpgw 的协议逻辑
func handleUdpGw(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("UdpGw Handler: New session for %s", clientKey)
	
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Printf("UdpGw Handler: Failed to listen on UDP for %s: %v", clientKey, err)
		ch.Close()
		return
	}

	state := &clientState{
		udpConn: udpConn,
		sshChan: ch,
		done:    make(chan struct{}),
		key:     clientKey,
	}
	clientManager.Add(clientKey, state)

	defer func() {
		log.Printf("UdpGw Handler: Session for %s closed", clientKey)
		clientManager.Delete(clientKey)
		ch.Close()
	}()

	// Goroutine 1: 从SSH读取、解析、发送 (这是核心逻辑)
	go func() {
		defer close(state.done) // 此goroutine结束，通知另一个goroutine
		for {
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(ch, lenBytes); err != nil {
				return
			}
			dataLen := binary.BigEndian.Uint16(lenBytes)
			if dataLen == 0 || dataLen > 4096 {
				return
			}
			
			fullData := make([]byte, dataLen)
			if _, err := io.ReadFull(ch, fullData); err != nil {
				return
			}
			
			packetType := fullData[0]
			payload := fullData[1:]

			if packetType != 0 { // 控制帧: 设置/更新目标地址
				addrStr := string(payload)
				if !strings.Contains(addrStr, ":") {
					addrStr = fmt.Sprintf("%s:7300", addrStr)
				}
				destAddr, err := net.ResolveUDPAddr("udp", addrStr)
				if err != nil {
					log.Printf("UdpGw Handler: Failed to resolve destination '%s' for %s: %v", addrStr, clientKey, err)
					return
				}
				state.targetAddr = destAddr // 更新会话状态
				log.Printf("UdpGw Handler: Set UDP destination to %s for %s", destAddr, clientKey)

			} else { // 数据帧: 发送UDP数据
				if state.targetAddr == nil {
					continue // 如果目标地址还没设置，就忽略数据包
				}
				if _, err := udpConn.WriteTo(payload, state.targetAddr); err != nil {
					// 忽略发送错误
				}
			}
		}
	}()
	
	// Goroutine 2: 从UDP套接字读取返回，封装并发送回客户端
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
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return 
			}
			
			udpRemote := remote.(*net.UDPAddr)
			remoteIP := udpRemote.IP.To4()
			if remoteIP == nil { continue }
			
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

	// 等待会话结束
	<-state.done
}
