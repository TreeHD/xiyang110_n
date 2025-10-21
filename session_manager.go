// session_manager.go
package main

import (
	"log"
	"net"
	"sync"
)

// clientSession 代表一个已连接的客户端的隧道会话
type clientSession struct {
	// 用于从中央分发器向此客户端的goroutine发送数据包
	packetChan chan<- []byte
}

// SessionManager 负责管理所有客户端的会话 (这是修正后的具名类型)
type SessionManager struct {
	sync.RWMutex
	// key: 客户端在TUN网络中的IP地址 (例如 "10.0.0.2")
	sessions map[string]*clientSession
}

// 创建一个全局的 SessionManager 实例
var sessionManager = &SessionManager{
	sessions: make(map[string]*clientSession),
}

// Register 注册一个新的客户端会话 (现在是 SessionManager 类型的方法)
func (sm *SessionManager) Register(clientIP string, session *clientSession) {
	sm.Lock()
	defer sm.Unlock()
	log.Printf("Session Manager: Registering session for IP %s", clientIP)
	sm.sessions[clientIP] = session
}

// Unregister 注销一个客户端会话 (现在是 SessionManager 类型的方法)
func (sm *SessionManager) Unregister(clientIP string) {
	sm.Lock()
	defer sm.Unlock()
	// 只有当IP不为空时才注销，防止空IP导致错误
	if clientIP != "" {
		log.Printf("Session Manager: Unregistering session for IP %s", clientIP)
		delete(sm.sessions, clientIP)
	}
}

// GetSession 根据IP地址查找对应的客户端会话 (现在是 SessionManager 类型的方法)
func (sm *SessionManager) GetSession(clientIP string) *clientSession {
	sm.RLock()
	defer sm.RUnlock()
	return sm.sessions[clientIP]
}

// readFromTunAndDistribute 是中央读取和分发器。
// 它在一个单独的goroutine中运行，是整个VPN功能的核心。
func readFromTunAndDistribute() {
	log.Println("Central packet distributor started. Reading from TUN device...")
	// 创建一个可复用的缓冲区来接收数据包
	packet := make([]byte, 4096)
	for {
		// 从TUN设备读取一个IP包。这里的读操作是阻塞的。
		// 由于只有一个goroutine在读，所以不需要锁。
		n, err := tunInterface.Read(packet)
		if err != nil {
			log.Printf("Central distributor: Error reading from TUN device: %v", err)
			continue
		}

		if n == 0 {
			continue
		}

		// --- IP包解析和路由 ---
		if n < 20 {
			continue // 包太小，不是有效的IPv4包
		}
		// 从IP头中提取目标IP地址
		destIP := net.IP(packet[16:20]).String()

		// 根据目标IP查找对应的客户端会话
		session := sessionManager.GetSession(destIP)
		if session != nil {
			packetCopy := make([]byte, n)
			copy(packetCopy, packet[:n])

			select {
			case session.packetChan <- packetCopy:
			default:
				log.Printf("WARN: Client channel for %s is full. Packet dropped.", destIP)
			}
		}
	}
}
