// ip_tunnel.go
package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com.songgao/water"
	"golang.org/x/crypto/ssh"
)

var tunInterface *water.Interface
var tunMutex sync.Mutex // 仅用于保护TUN接口的并发写入

// createTunDevice - 回归到最简单的默认配置
func createTunDevice() error {
	const (
		ifaceName = "tun0"
		ifaceAddr = "10.0.0.1/24"
	)
	// 使用 water 库的默认配置，让它自动处理PI头
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = ifaceName

	// [重要] 删除所有关于 Pi = false 的设置，使用库的默认行为
	// water 库会为我们处理好一切

	ifce, err := water.New(config)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	if err := runIPCommand("link", "set", "dev", ifce.Name(), "up"); err != nil {
		return fmt.Errorf("failed to set TUN device up: %w", err)
	}
	if err := runIPCommand("addr", "add", ifaceAddr, "dev", ifce.Name()); err != nil {
		return fmt.Errorf("failed to set TUN device IP: %w", err)
	}
	if err := enableIPForwarding(); err != nil {
		log.Printf("WARN: Failed to enable IP forwarding: %v. NAT might not work.", err)
	}
	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.Printf("WARN: Could not detect default network interface: %v. You may need to set the iptables rule manually.", err)
	} else {
		if err := setupNAT(defaultIface); err != nil {
			log.Printf("WARN: Failed to set up iptables NAT rule for interface %s: %v.", defaultIface, err)
		}
	}
	log.Printf("TUN device %s created and configured at %s", ifce.Name(), ifaceAddr)
	tunInterface = ifce
	return nil
}

// handleIPTunnel - 简化到只处理纯粹的IP包
func handleIPTunnel(ch ssh.Channel, remoteAddr net.Addr) {
	clientKey := remoteAddr.String()
	log.Printf("IP Tunnel: New session for %s. Waiting for first packet to determine client IP.", clientKey)
	defer log.Printf("IP Tunnel: Session for %s closed", clientKey)
	defer ch.Close()

	packetChan := make(chan []byte, 100)
	session := &clientSession{packetChan: packetChan}
	var clientTunIP string
	defer func() {
		sessionManager.Unregister(clientTunIP)
	}()

	done := make(chan struct{})

	// Goroutine 1: 从自己的packet channel读取纯IP包，直接写入SSH信道 (TUN -> SSH)
	go func() {
		for ipPacket := range packetChan {
			if _, err := ch.Write(ipPacket); err != nil {
				log.Printf("IP Tunnel: Error writing to SSH channel for %s: %v", clientKey, err)
				return
			}
		}
	}()

	// Goroutine 2: 从SSH信道读取纯IP包，直接写入TUN设备 (SSH -> TUN)
	go func() {
		defer close(done)

		packet := make([]byte, 4096)
		isRegistered := false

		for {
			n, err := ch.Read(packet)
			if err != nil {
				return
			}

			if n > 0 {
				// 假设从SSH读到的就是纯IP包
				ipPacket := packet[:n]

				if !isRegistered {
					if len(ipPacket) < 20 {
						continue // 不是有效的IPv4包
					}
					// 从纯IP包中提取源IP地址
					srcIP := net.IP(ipPacket[12:16]).String()
					// 增加一个IP有效性检查
					if srcIP == "0.0.0.0" {
						log.Printf("WARN: Received packet with invalid source IP 0.0.0.0 from %s. Ignoring.", clientKey)
						continue
					}
					clientTunIP = srcIP
					sessionManager.Register(clientTunIP, session)
					isRegistered = true
				}

				tunMutex.Lock()
				// 将纯IP包交给water库，它会处理好与内核的交互
				_, writeErr := tunInterface.Write(ipPacket)
				tunMutex.Unlock()
				if writeErr != nil {
					log.Printf("IP Tunnel: Error writing to TUN device: %v", writeErr)
					return
				}
			}
		}
	}()

	<-done
}
