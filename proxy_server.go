package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// handleProxyServer starts the multiplexed HTTP / SOCKS5 proxy server
func handleProxyServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on proxy addr %s: %v", addr, err)
	}

	log.Printf("System: Mixed SOCKS5 / HTTP Proxy server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Proxy Server: Error accepting connection: %v", err)
			continue
		}
		go handleProxyConnection(conn)
	}
}

func handleProxyConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Peek first byte to determine protocol
	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(1)
	if err != nil {
		return
	}

	// SOCKS5 starts with 0x05
	if peek[0] == 0x05 {
		conn.SetReadDeadline(time.Time{})
		handleSocks5Proxy(conn, reader)
		return
	}

	// Otherwise, assume HTTP Proxy Request
	conn.SetReadDeadline(time.Time{})
	handleHttpProxy(conn, reader)
}

func authenticateProxyUser(username, password string) (bool, string) {
	globalConfig.lock.RLock()
	acc, ok := globalConfig.Accounts[username]
	globalConfig.lock.RUnlock()

	if !ok || !acc.Enabled {
		return false, "auth failed"
	}
	if acc.ExpiryDate != "" {
		exp, err := time.Parse("2006-01-02", acc.ExpiryDate)
		if err != nil || time.Now().After(exp.Add(24*time.Hour)) {
			return false, "user expired"
		}
	}
	if acc.LimitGB > 0 {
		v, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
		t := v.(*TrafficInfo)
		if atomic.LoadUint64(&t.Sent)+atomic.LoadUint64(&t.Received) >= uint64(acc.LimitGB*1e9) {
			return false, "traffic limit exceeded"
		}
	}
	// Note: Proxy sessions might not perfectly map to max_sessions count as easily as long-lived SSH, but we verify credentials here.
	if password == acc.Password {
		return true, ""
	}
	return false, "invalid credentials"
}

func handleHttpProxy(conn net.Conn, reader *bufio.Reader) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Basic Auth check
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		sendProxyAuthenticateChallenge(conn)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		sendProxyAuthenticateChallenge(conn)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		sendProxyAuthenticateChallenge(conn)
		return
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		sendProxyAuthenticateChallenge(conn)
		return
	}

	username, password := creds[0], creds[1]
	if ok, reason := authenticateProxyUser(username, password); !ok {
		log.Printf("HTTP Proxy: Auth failed for %s: %s", username, reason)
		sendProxyAuthenticateChallenge(conn)
		return
	}

	// Connection allowed
	if req.Method == http.MethodConnect {
		handleHttpConnectMethod(conn, req, username)
	} else {
		// Normal HTTP proxy request
		handleStandardHttpProxyRequest(conn, req, username)
	}
}

func sendProxyAuthenticateChallenge(conn net.Conn) {
	resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"WSTunnel Proxy\"\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(resp))
}

func handleHttpConnectMethod(client net.Conn, req *http.Request, username string) {
	destConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	proxyCopy(client, destConn, username)
}

func handleStandardHttpProxyRequest(client net.Conn, req *http.Request, username string) {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	destConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()

	if err := req.Write(destConn); err != nil {
		return
	}
	proxyCopy(client, destConn, username)
}

func handleSocks5Proxy(conn net.Conn, reader *bufio.Reader) {
	// Protocol version and NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}

	// We only support Username/Password authentication (0x02)
	supportsAuth := false
	for _, m := range methods {
		if m == 0x02 {
			supportsAuth = true
			break
		}
	}

	if !supportsAuth {
		conn.Write([]byte{0x05, 0xFF}) // No acceptable methods
		return
	}

	// Send Username/Password Auth selected
	conn.Write([]byte{0x05, 0x02})

	// Read Username/Password Auth Request
	authVer := make([]byte, 2)
	if _, err := io.ReadFull(reader, authVer); err != nil {
		return
	}
	if authVer[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01}) // Auth version not supported
		return
	}

	ulen := int(authVer[1])
	userBytes := make([]byte, ulen)
	if _, err := io.ReadFull(reader, userBytes); err != nil {
		return
	}

	plenBytes := make([]byte, 1)
	if _, err := io.ReadFull(reader, plenBytes); err != nil {
		return
	}
	plen := int(plenBytes[0])
	passBytes := make([]byte, plen)
	if _, err := io.ReadFull(reader, passBytes); err != nil {
		return
	}

	username := string(userBytes)
	password := string(passBytes)

	if ok, reason := authenticateProxyUser(username, password); !ok {
		log.Printf("SOCKS5 Proxy: Auth failed for %s: %s", username, reason)
		conn.Write([]byte{0x01, 0x01}) // Auth failure
		return
	}

	// Auth success
	conn.Write([]byte{0x01, 0x00})

	// Read connection request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, reqHeader); err != nil {
		return
	}

	if reqHeader[1] != 0x01 { // Only support CONNECT command
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destHost string
	switch reqHeader[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return
		}
		destHost = net.IP(buf).String()
	case 0x03: // FQDN
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			return
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return
		}
		destHost = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return
		}
		destHost = fmt.Sprintf("[%s]", net.IP(buf).String())
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return
	}
	destPort := (int(portBuf[0]) << 8) | int(portBuf[1])
	var destAddr string
	if strings.Contains(destHost, ":") {
		destAddr = fmt.Sprintf("[%s]:%d", destHost, destPort)
	} else {
		destAddr = fmt.Sprintf("%s:%d", destHost, destPort)
	}

	destConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}

	// Success reply
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	proxyCopy(conn, destConn, username)
}

func proxyCopy(client, target net.Conn, username string) {
	defer client.Close()
	defer target.Close()

	chDone := make(chan struct{})

	// This is slightly simpler than tolerantCopy since general proxies usually don't have deep packet recovery requirements
	go func() {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
		traffic := val.(*TrafficInfo)
		for {
			nr, err := target.Read(buf)
			if nr > 0 {
				atomic.AddUint64(&traffic.Received, uint64(nr))
				client.Write(buf[:nr])
			}
			if err != nil {
				break
			}
		}
		bufferPool.Put(bufPtr)
		chDone <- struct{}{}
	}()

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
	traffic := val.(*TrafficInfo)
	for {
		nr, err := client.Read(buf)
		if nr > 0 {
			atomic.AddUint64(&traffic.Sent, uint64(nr))
			target.Write(buf[:nr])
		}
		if err != nil {
			break
		}
	}
	bufferPool.Put(bufPtr)

	<-chDone
}
