package client

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"xpenetration/internal/config"
	"xpenetration/internal/protocol"
)

// Client 客户端结构
type Client struct {
	config        *config.ClientConnConfig
	conn          net.Conn
	clientID      string
	tunnels       []protocol.Tunnel
	localConns    map[string]net.Conn  // connID -> local connection (TCP)
	udpConns      map[int]*UDPConnInfo // clientPort -> UDP connection info
	nativeUDPConn *net.UDPConn         // 与服务端的原生UDP传输连接
	serverUDPAddr *net.UDPAddr         // 服务端UDP地址
	mu            sync.RWMutex
	udpMu         sync.RWMutex // UDP专用锁，减少锁竞争
	running       bool
	connected     bool
	stopChan      chan struct{}
}

// UDPConnInfo UDP连接信息
type UDPConnInfo struct {
	Conn           *net.UDPConn
	TunnelName     string
	ClientPort     int
	ServerPort     int    // 服务端暴露端口
	UDPMode        string // UDP传输模式
	lastRemoteAddr string // 最后一个请求的远程地址
	mu             sync.RWMutex
}

// NewClient 创建新的客户端
func NewClient(cfg *config.ClientConnConfig) *Client {
	return &Client{
		config:     cfg,
		localConns: make(map[string]net.Conn),
		udpConns:   make(map[int]*UDPConnInfo),
		stopChan:   make(chan struct{}),
	}
}

// Start 启动客户端
func (c *Client) Start() error {
	c.running = true

	for c.running {
		if err := c.connect(); err != nil {
			log.Printf("[Client] Connection failed: %v", err)
			if !c.config.Client.AutoReconnect {
				return err
			}
			log.Printf("[Client] Reconnecting in %d seconds...", c.config.Client.ReconnectInterval)
			time.Sleep(time.Duration(c.config.Client.ReconnectInterval) * time.Second)
			continue
		}

		// 处理消息
		c.handleMessages()

		// 连接断开
		c.connected = false
		c.cleanup()

		if !c.running {
			break
		}

		if c.config.Client.AutoReconnect {
			log.Printf("[Client] Reconnecting in %d seconds...", c.config.Client.ReconnectInterval)
			time.Sleep(time.Duration(c.config.Client.ReconnectInterval) * time.Second)
		} else {
			break
		}
	}

	return nil
}

// connect 连接到服务端
func (c *Client) connect() error {
	addr := fmt.Sprintf("%s:%d", c.config.Client.ServerAddr, c.config.Client.ServerPort)
	log.Printf("[Client] Connecting to %s...", addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	c.conn = conn

	// 发送认证请求
	authMsg, err := protocol.NewAuthRequest(c.config.Client.SecretKey, c.config.Client.ClientName)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create auth request: %v", err)
	}

	if err := protocol.SendMessage(conn, authMsg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send auth request: %v", err)
	}

	// 接收认证响应
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	msg, err := protocol.DecodeMessage(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive auth response: %v", err)
	}

	if msg.Type != protocol.MsgTypeAuthResp {
		conn.Close()
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	authResp, err := protocol.ParseAuthResponse(msg.Payload)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to parse auth response: %v", err)
	}

	if !authResp.Success {
		conn.Close()
		return fmt.Errorf("authentication failed: %s", authResp.Message)
	}

	c.clientID = authResp.ClientID
	log.Printf("[Client] Authentication successful, client ID: %s", c.clientID)

	// 接收隧道配置
	msg, err = protocol.DecodeMessage(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive tunnel config: %v", err)
	}

	if msg.Type != protocol.MsgTypeTunnelConfig {
		conn.Close()
		return fmt.Errorf("unexpected message type: %d", msg.Type)
	}

	tunnelConfig, err := protocol.ParseTunnelConfig(msg.Payload)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to parse tunnel config: %v", err)
	}

	c.tunnels = tunnelConfig.Tunnels
	conn.SetReadDeadline(time.Time{})

	log.Printf("[Client] Received %d tunnel configurations:", len(c.tunnels))
	for _, t := range c.tunnels {
		udpMode := protocol.GetUDPMode(t.UDPMode)
		if t.Protocol == "udp" {
			log.Printf("[Client]   - %s: local port %d -> server port %d (UDP mode: %s)", t.Name, t.ClientPort, t.ServerPort, udpMode)
		} else {
			log.Printf("[Client]   - %s: local port %d -> server port %d", t.Name, t.ClientPort, t.ServerPort)
		}
	}

	c.connected = true

	// 检查是否有原生UDP隧道，如果有则启动原生UDP传输
	hasNativeUDP := false
	for _, t := range c.tunnels {
		if t.Protocol == "udp" && protocol.GetUDPMode(t.UDPMode) == protocol.UDPModeNative {
			hasNativeUDP = true
			break
		}
	}
	if hasNativeUDP {
		if err := c.startNativeUDPTransport(); err != nil {
			log.Printf("[Client] Warning: Failed to start native UDP transport: %v", err)
		}
	}

	// 启动心跳
	go c.heartbeatLoop()

	return nil
}

// heartbeatLoop 心跳循环
func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !c.connected {
				return
			}
			c.sendHeartbeat()
		case <-c.stopChan:
			return
		}
	}
}

// sendHeartbeat 发送心跳
func (c *Client) sendHeartbeat() {
	msg, err := protocol.NewHeartbeat(time.Now().Unix())
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		protocol.SendMessage(c.conn, msg)
	}
}

// handleMessages 处理服务端消息
func (c *Client) handleMessages() {
	for c.running && c.connected {
		msg, err := protocol.DecodeMessage(c.conn)
		if err != nil {
			log.Printf("[Client] Failed to read message: %v", err)
			return
		}

		switch msg.Type {
		case protocol.MsgTypeNewConnection:
			go c.handleNewConnection(msg)
		case protocol.MsgTypeData:
			c.handleData(msg)
		case protocol.MsgTypeDisconnect:
			c.handleDisconnect(msg)
		case protocol.MsgTypeHeartbeatAck:
			// 心跳确认，忽略
		case protocol.MsgTypeError:
			c.handleError(msg)
		case protocol.MsgTypeUDPData:
			go c.handleUDPData(msg)
		default:
			log.Printf("[Client] Unknown message type: %d", msg.Type)
		}
	}
}

// handleNewConnection 处理新连接请求
func (c *Client) handleNewConnection(msg *protocol.Message) {
	nc, err := protocol.ParseNewConnection(msg.Payload)
	if err != nil {
		log.Printf("[Client] Failed to parse new connection: %v", err)
		return
	}

	log.Printf("[Client] New connection request: %s -> local port %d", nc.ConnID, nc.ClientPort)

	// 连接到本地服务（或局域网内其他设备）
	targetIP := nc.TargetIP
	if targetIP == "" {
		targetIP = "127.0.0.1"
	}
	localAddr := fmt.Sprintf("%s:%d", targetIP, nc.ClientPort)
	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to connect to local service %s: %v", localAddr, err)
		log.Printf("[Client] %s", errMsg)
		c.sendConnReady(nc.ConnID, false, err.Error())
		c.ReportError("connection", errMsg)
		return
	}

	// 保存本地连接
	c.mu.Lock()
	c.localConns[nc.ConnID] = localConn
	c.mu.Unlock()

	// 发送连接就绪消息
	c.sendConnReady(nc.ConnID, true, "")

	// 启动本地连接数据转发
	go c.forwardFromLocal(nc.ConnID, localConn)
}

// sendConnReady 发送连接就绪消息
func (c *Client) sendConnReady(connID string, success bool, message string) {
	msg, err := protocol.NewConnReadyMessage(connID, success, message)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		protocol.SendMessage(c.conn, msg)
	}
}

// forwardFromLocal 从本地连接转发数据到服务端
func (c *Client) forwardFromLocal(connID string, localConn net.Conn) {
	defer func() {
		localConn.Close()
		c.mu.Lock()
		delete(c.localConns, connID)
		c.mu.Unlock()

		// 通知服务端断开连接
		c.sendDisconnect(connID, "local connection closed")
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := localConn.Read(buf)
		if err != nil {
			return
		}

		// 发送数据给服务端
		msg, err := protocol.NewDataMessage(connID, buf[:n])
		if err != nil {
			return
		}

		c.mu.Lock()
		err = protocol.SendMessage(c.conn, msg)
		c.mu.Unlock()

		if err != nil {
			return
		}
	}
}

// sendDisconnect 发送断开连接消息
func (c *Client) sendDisconnect(connID, reason string) {
	msg, err := protocol.NewDisconnectMessage(connID, reason)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		protocol.SendMessage(c.conn, msg)
	}
}

// handleData 处理服务端发来的数据
func (c *Client) handleData(msg *protocol.Message) {
	dm, err := protocol.ParseDataMessage(msg.Payload)
	if err != nil {
		log.Printf("[Client] Failed to parse data message: %v", err)
		return
	}

	c.mu.RLock()
	localConn, exists := c.localConns[dm.ConnID]
	c.mu.RUnlock()

	if !exists {
		return
	}

	// 转发数据到本地连接
	_, err = localConn.Write(dm.Data)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to write to local connection: %v", err)
		log.Printf("[Client] %s", errMsg)
		localConn.Close()
		c.ReportError("data_forward", errMsg)
	}
}

// handleDisconnect 处理断开连接消息
func (c *Client) handleDisconnect(msg *protocol.Message) {
	dm, err := protocol.ParseDisconnectMessage(msg.Payload)
	if err != nil {
		return
	}

	c.mu.Lock()
	if localConn, exists := c.localConns[dm.ConnID]; exists {
		localConn.Close()
		delete(c.localConns, dm.ConnID)
	}
	c.mu.Unlock()
}

// handleError 处理错误消息
func (c *Client) handleError(msg *protocol.Message) {
	em, err := protocol.ParseErrorMessage(msg.Payload)
	if err != nil {
		return
	}
	log.Printf("[Client] Server error: [%d] %s", em.Code, em.Message)
}

// startNativeUDPTransport 启动原生UDP传输
func (c *Client) startNativeUDPTransport() error {
	// 解析服务端UDP地址
	serverUDPAddr := fmt.Sprintf("%s:%d", c.config.Client.ServerAddr, c.config.Client.ServerUDPPort)
	udpAddr, err := net.ResolveUDPAddr("udp", serverUDPAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve server UDP address: %v", err)
	}

	// 创建本地UDP连接
	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to resolve local UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %v", err)
	}

	c.mu.Lock()
	c.nativeUDPConn = conn
	c.serverUDPAddr = udpAddr
	c.mu.Unlock()

	log.Printf("[Client] Native UDP transport connected to %s", serverUDPAddr)

	// 启动定期发送注册包的goroutine（每30分钟发送一次，因为IP和端口可能会变化）
	go c.udpRegisterLoop()

	// 启动接收服务端UDP数据的goroutine
	go c.handleNativeUDPFromServer()

	return nil
}

// udpRegisterLoop 定期发送UDP注册包
func (c *Client) udpRegisterLoop() {
	// 先立即发送一次注册包
	c.sendUDPRegisterPacket()

	// 每30分钟发送一次注册包
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !c.running || !c.connected {
				return
			}
			c.sendUDPRegisterPacket()
		case <-c.stopChan:
			return
		}
	}
}

// sendUDPRegisterPacket 发送UDP注册包
func (c *Client) sendUDPRegisterPacket() {
	c.mu.RLock()
	conn := c.nativeUDPConn
	addr := c.serverUDPAddr
	c.mu.RUnlock()

	if conn == nil || addr == nil {
		return
	}

	registerPkt := protocol.EncodeNativeUDPRegisterPacket(c.config.Client.ClientName)
	_, err := conn.WriteToUDP(registerPkt, addr)
	if err != nil {
		log.Printf("[Client] Warning: Failed to send UDP register packet: %v", err)
	} else {
		log.Printf("[Client] Sent UDP register packet to server")
	}
}

// handleNativeUDPFromServer 处理来自服务端的原生UDP数据
func (c *Client) handleNativeUDPFromServer() {
	buf := make([]byte, 65535)

	for c.running && c.connected {
		c.nativeUDPConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, _, err := c.nativeUDPConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if c.running && c.connected {
				log.Printf("[Client] Native UDP read error: %v", err)
			}
			return
		}

		if n < 1 {
			continue
		}

		// 检查数据包类型
		pktType := buf[0]
		if pktType != protocol.NativeUDPTypeData {
			// 忽略非数据包
			continue
		}

		// 解析数据包（带类型前缀）
		pkt, err := protocol.DecodeNativeUDPDataPacket(buf[:n])
		if err != nil {
			log.Printf("[Client] Failed to decode native UDP packet: %v", err)
			continue
		}

		// 处理数据，转发到本地服务
		c.handleNativeUDPData(pkt)
	}
}

// handleNativeUDPData 处理原生UDP数据
func (c *Client) handleNativeUDPData(pkt *protocol.NativeUDPPacket) {
	// 获取或创建本地UDP连接
	c.udpMu.RLock()
	connInfo, exists := c.udpConns[pkt.ClientPort]
	c.udpMu.RUnlock()

	if !exists {
		c.udpMu.Lock()
		// 双重检查
		connInfo, exists = c.udpConns[pkt.ClientPort]
		if !exists {
			// 查找对应的隧道配置
			var tunnel *protocol.Tunnel
			for i := range c.tunnels {
				if c.tunnels[i].ClientPort == pkt.ClientPort {
					tunnel = &c.tunnels[i]
					break
				}
			}
			if tunnel == nil {
				c.udpMu.Unlock()
				log.Printf("[Client] Tunnel not found for client port: %d", pkt.ClientPort)
				return
			}

			// 创建新的UDP连接到本地服务（或局域网内其他设备）
			targetIP := tunnel.TargetIP
			if targetIP == "" {
				targetIP = "127.0.0.1"
			}
			localAddr := fmt.Sprintf("%s:%d", targetIP, pkt.ClientPort)
			udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
			if err != nil {
				c.udpMu.Unlock()
				log.Printf("[Client] Failed to resolve UDP address %s: %v", localAddr, err)
				return
			}

			localConn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				c.udpMu.Unlock()
				log.Printf("[Client] Failed to connect to local UDP service %s: %v", localAddr, err)
				return
			}

			connInfo = &UDPConnInfo{
				Conn:       localConn,
				TunnelName: tunnel.Name,
				ClientPort: pkt.ClientPort,
				ServerPort: pkt.ServerPort,
				UDPMode:    protocol.GetUDPMode(tunnel.UDPMode),
			}
			c.udpConns[pkt.ClientPort] = connInfo
			log.Printf("[Client] Created UDP connection to local port %d (native mode)", pkt.ClientPort)

			// 启动UDP响应监听
			go c.forwardUDPFromLocal(connInfo)
		}
		c.udpMu.Unlock()
	}

	// 保存远程地址信息
	connInfo.mu.Lock()
	connInfo.lastRemoteAddr = pkt.RemoteAddr
	connInfo.mu.Unlock()

	// 发送数据到本地UDP服务
	_, err := connInfo.Conn.Write(pkt.Data)
	if err != nil {
		log.Printf("[Client] Failed to write native UDP data to local service: %v", err)
	}
}

// handleUDPData 处理服务端发来的UDP数据（TCP封装模式，备用方法）
func (c *Client) handleUDPData(msg *protocol.Message) {
	udm, err := protocol.ParseUDPDataMessage(msg.Payload)
	if err != nil {
		log.Printf("[Client] Failed to parse UDP data message: %v", err)
		return
	}

	// 获取或创建本地UDP连接
	c.udpMu.RLock()
	connInfo, exists := c.udpConns[udm.ClientPort]
	c.udpMu.RUnlock()

	if !exists {
		c.udpMu.Lock()
		// 双重检查
		connInfo, exists = c.udpConns[udm.ClientPort]
		if !exists {
			// 查找对应的隧道配置
			var tunnel *protocol.Tunnel
			for i := range c.tunnels {
				if c.tunnels[i].Name == udm.TunnelName {
					tunnel = &c.tunnels[i]
					break
				}
			}

			// 创建新的UDP连接到本地服务（或局域网内其他设备）
			targetIP := ""
			if tunnel != nil {
				targetIP = tunnel.TargetIP
			}
			if targetIP == "" {
				targetIP = "127.0.0.1"
			}
			localAddr := fmt.Sprintf("%s:%d", targetIP, udm.ClientPort)
			udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
			if err != nil {
				c.udpMu.Unlock()
				errMsg := fmt.Sprintf("Failed to resolve UDP address %s: %v", localAddr, err)
				log.Printf("[Client] %s", errMsg)
				c.ReportError("udp_resolve", errMsg)
				return
			}

			localConn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				c.udpMu.Unlock()
				errMsg := fmt.Sprintf("Failed to connect to local UDP service %s: %v", localAddr, err)
				log.Printf("[Client] %s", errMsg)
				c.ReportError("udp_connection", errMsg)
				return
			}

			serverPort := 0
			udpMode := protocol.UDPModeTCP
			if tunnel != nil {
				serverPort = tunnel.ServerPort
				udpMode = protocol.GetUDPMode(tunnel.UDPMode)
			}

			connInfo = &UDPConnInfo{
				Conn:       localConn,
				TunnelName: udm.TunnelName,
				ClientPort: udm.ClientPort,
				ServerPort: serverPort,
				UDPMode:    udpMode,
			}
			c.udpConns[udm.ClientPort] = connInfo
			log.Printf("[Client] Created UDP connection to local port %d (TCP fallback mode)", udm.ClientPort)

			// 启动UDP响应监听
			go c.forwardUDPFromLocal(connInfo)
		}
		c.udpMu.Unlock()
	}

	// 发送数据到本地UDP服务（带上远程地址信息，用于响应时携带）
	// 在发送前先保存当前的remoteAddr到连接状态
	connInfo.mu.Lock()
	connInfo.lastRemoteAddr = udm.RemoteAddr
	connInfo.mu.Unlock()

	_, err = connInfo.Conn.Write(udm.Data)
	if err != nil {
		log.Printf("[Client] Failed to write UDP data to local service: %v", err)
	}
}

// forwardUDPFromLocal 从本地UDP连接转发响应数据到服务端
func (c *Client) forwardUDPFromLocal(connInfo *UDPConnInfo) {
	buf := make([]byte, 65535)

	for c.running && c.connected {
		connInfo.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := connInfo.Conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[Client] UDP read from local error: %v", err)
			return
		}

		// 获取最后的远程地址和UDP模式
		connInfo.mu.RLock()
		remoteAddr := connInfo.lastRemoteAddr
		udpMode := connInfo.UDPMode
		serverPort := connInfo.ServerPort
		connInfo.mu.RUnlock()

		if remoteAddr == "" {
			continue
		}

		// 根据UDP模式选择发送方式
		// 计算编码后的数据包大小，检查是否超过MTU
		pktData := protocol.EncodeNativeUDPDataPacket(
			serverPort,
			connInfo.ClientPort,
			remoteAddr,
			buf[:n],
		)
		useNativeUDP := udpMode == protocol.UDPModeNative && c.nativeUDPConn != nil && c.serverUDPAddr != nil
		// 如果数据包超过安全MTU大小，自动回退到TCP传输
		if useNativeUDP && len(pktData) > protocol.UDPSafeMTU {
			useNativeUDP = false
		}

		if useNativeUDP {
			// 原生UDP传输：直接通过UDP发送给服务端（使用带类型前缀的数据包）
			c.mu.RLock()
			_, err = c.nativeUDPConn.WriteToUDP(pktData, c.serverUDPAddr)
			c.mu.RUnlock()
			if err != nil {
				// 发送失败时回退到TCP
				useNativeUDP = false
			}
		}

		if !useNativeUDP {
			// TCP封装传输（备用方法或MTU超限回退）：通过TCP控制通道发送
			msg, err := protocol.NewUDPDataMessage(connInfo.TunnelName, connInfo.ClientPort, remoteAddr, buf[:n])
			if err != nil {
				log.Printf("[Client] Failed to create UDP response message: %v", err)
				continue
			}

			c.mu.Lock()
			err = protocol.SendMessage(c.conn, msg)
			c.mu.Unlock()

			if err != nil {
				log.Printf("[Client] Failed to send UDP response to server: %v", err)
				return
			}
		}
	}
}

// cleanup 清理资源
func (c *Client) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 关闭所有本地TCP连接
	for _, conn := range c.localConns {
		conn.Close()
	}
	c.localConns = make(map[string]net.Conn)

	// 关闭所有本地UDP连接
	c.udpMu.Lock()
	for _, connInfo := range c.udpConns {
		connInfo.Conn.Close()
	}
	c.udpConns = make(map[int]*UDPConnInfo)
	c.udpMu.Unlock()

	// 关闭原生UDP传输连接
	if c.nativeUDPConn != nil {
		c.nativeUDPConn.Close()
		c.nativeUDPConn = nil
	}
	c.serverUDPAddr = nil

	// 关闭服务端连接
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Stop 停止客户端
func (c *Client) Stop() {
	c.running = false
	close(c.stopChan)
	c.cleanup()
}

// IsConnected 是否已连接
func (c *Client) IsConnected() bool {
	return c.connected
}

// GetTunnels 获取隧道配置
func (c *Client) GetTunnels() []protocol.Tunnel {
	return c.tunnels
}

// GetClientID 获取客户端ID
func (c *Client) GetClientID() string {
	return c.clientID
}

// ReportError 上报错误到服务端
func (c *Client) ReportError(errorType, message string) {
	if !c.connected || c.conn == nil {
		return
	}

	msg, err := protocol.NewClientErrorReport(
		c.config.Client.ClientName,
		errorType,
		message,
		time.Now().Unix(),
	)
	if err != nil {
		log.Printf("[Client] Failed to create error report: %v", err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		if err := protocol.SendMessage(c.conn, msg); err != nil {
			log.Printf("[Client] Failed to send error report: %v", err)
		}
	}
}
