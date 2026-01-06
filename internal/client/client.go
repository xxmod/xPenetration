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
	localConns    map[string]*TCPConnInfo // connID -> local TCP connection info
	udpConns      map[int]*UDPConnInfo    // clientPort -> UDP connection info
	nativeUDPConn *net.UDPConn            // 与服务端的原生UDP传输连接
	serverUDPAddr *net.UDPAddr            // 服务端UDP地址
	mu            sync.RWMutex
	udpMu         sync.RWMutex // UDP专用锁，减少锁竞争
	running       bool
	connected     bool
	stopChan      chan struct{}
}

// TCPConnInfo TCP连接信息，支持异步数据处理
type TCPConnInfo struct {
	Conn     net.Conn
	DataChan chan []byte // 数据通道，用于异步发送数据
	closed   bool
	mu       sync.Mutex
}

// UDPConnInfo UDP连接信息
type UDPConnInfo struct {
	TunnelName string
	ClientPort int
	ServerPort int    // 服务端暴露端口
	UDPMode    string // UDP传输模式
	TargetIP   string // 目标IP地址
	// 为每个远程地址维护独立的本地UDP连接，支持多用户并发
	sessions map[string]*UDPSession // remoteAddr -> session
	mu       sync.RWMutex
}

// UDPSession 单个UDP会话，对应一个外部用户
type UDPSession struct {
	Conn       *net.UDPConn // 本地UDP连接
	RemoteAddr string       // 外部用户地址
	LastActive time.Time    // 最后活跃时间
}

// NewClient 创建新的客户端
func NewClient(cfg *config.ClientConnConfig) *Client {
	return &Client{
		config:     cfg,
		localConns: make(map[string]*TCPConnInfo),
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

	// 创建连接信息，带数据通道
	connInfo := &TCPConnInfo{
		Conn:     localConn,
		DataChan: make(chan []byte, 256), // 缓冲通道，支持异步数据处理
	}

	// 保存本地连接
	c.mu.Lock()
	c.localConns[nc.ConnID] = connInfo
	c.mu.Unlock()

	// 发送连接就绪消息
	c.sendConnReady(nc.ConnID, true, "")

	// 启动本地连接数据写入协程（从通道读取数据写入本地）
	go c.writeToLocal(nc.ConnID, connInfo)

	// 启动本地连接数据读取协程（从本地读取数据发送到服务端）
	go c.forwardFromLocal(nc.ConnID, connInfo)
}

// writeToLocal 从数据通道读取数据并写入本地连接
func (c *Client) writeToLocal(connID string, connInfo *TCPConnInfo) {
	for data := range connInfo.DataChan {
		_, err := connInfo.Conn.Write(data)
		if err != nil {
			connInfo.mu.Lock()
			if !connInfo.closed {
				errMsg := fmt.Sprintf("Failed to write to local connection %s: %v", connID, err)
				log.Printf("[Client] %s", errMsg)
				connInfo.closed = true
				connInfo.Conn.Close()
			}
			connInfo.mu.Unlock()
			// 排空通道
			for range connInfo.DataChan {
			}
			return
		}
	}
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
func (c *Client) forwardFromLocal(connID string, connInfo *TCPConnInfo) {
	defer func() {
		// 标记连接已关闭，关闭通道
		connInfo.mu.Lock()
		if !connInfo.closed {
			connInfo.closed = true
			connInfo.Conn.Close()
		}
		close(connInfo.DataChan)
		connInfo.mu.Unlock()

		c.mu.Lock()
		delete(c.localConns, connID)
		c.mu.Unlock()

		// 通知服务端断开连接
		c.sendDisconnect(connID, "local connection closed")
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := connInfo.Conn.Read(buf)
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
	connInfo, exists := c.localConns[dm.ConnID]
	c.mu.RUnlock()

	if !exists {
		return
	}

	// 复制数据并异步发送到通道
	dataCopy := make([]byte, len(dm.Data))
	copy(dataCopy, dm.Data)

	// 非阻塞发送到通道
	connInfo.mu.Lock()
	if !connInfo.closed {
		select {
		case connInfo.DataChan <- dataCopy:
			// 成功发送
		default:
			// 通道已满，同步写入（避免丢数据）
			connInfo.mu.Unlock()
			_, err = connInfo.Conn.Write(dataCopy)
			if err != nil {
				errMsg := fmt.Sprintf("Failed to write to local connection: %v", err)
				log.Printf("[Client] %s", errMsg)
				connInfo.mu.Lock()
				if !connInfo.closed {
					connInfo.closed = true
					connInfo.Conn.Close()
				}
				connInfo.mu.Unlock()
				c.ReportError("data_forward", errMsg)
			}
			return
		}
	}
	connInfo.mu.Unlock()
}

// handleDisconnect 处理断开连接消息
func (c *Client) handleDisconnect(msg *protocol.Message) {
	dm, err := protocol.ParseDisconnectMessage(msg.Payload)
	if err != nil {
		return
	}

	c.mu.Lock()
	if connInfo, exists := c.localConns[dm.ConnID]; exists {
		connInfo.mu.Lock()
		if !connInfo.closed {
			connInfo.closed = true
			connInfo.Conn.Close()
		}
		connInfo.mu.Unlock()
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

	// 设置UDP缓冲区大小，减少高流量时的丢包
	conn.SetReadBuffer(protocol.UDPReadBufferSize)
	conn.SetWriteBuffer(protocol.UDPWriteBufferSize)

	c.mu.Lock()
	c.nativeUDPConn = conn
	c.serverUDPAddr = udpAddr
	c.mu.Unlock()

	log.Printf("[Client] Native UDP transport connected to %s (buffer: %dKB)", serverUDPAddr, protocol.UDPReadBufferSize/1024)

	// 启动定期发送注册包的goroutine（每30分钟发送一次，因为IP和端口可能会变化）
	go c.udpRegisterLoop()

	// 启动接收服务端UDP数据的goroutine
	go c.handleNativeUDPFromServer()

	return nil
}

// udpRegisterLoop 定期发送UDP注册包（NAT保活）
func (c *Client) udpRegisterLoop() {
	// 先立即发送一次注册包
	c.sendUDPRegisterPacket()

	// 每30秒发送一次注册包，保持NAT穿透状态
	// 大多数NAT设备的UDP映射超时时间在30秒-2分钟之间
	ticker := time.NewTicker(protocol.UDPKeepaliveInterval)
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
	// 获取或创建隧道的UDP连接管理器
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

			targetIP := tunnel.TargetIP
			if targetIP == "" {
				targetIP = "127.0.0.1"
			}

			connInfo = &UDPConnInfo{
				TunnelName: tunnel.Name,
				ClientPort: pkt.ClientPort,
				ServerPort: pkt.ServerPort,
				UDPMode:    protocol.GetUDPMode(tunnel.UDPMode),
				TargetIP:   targetIP,
				sessions:   make(map[string]*UDPSession),
			}
			c.udpConns[pkt.ClientPort] = connInfo
			log.Printf("[Client] Created UDP tunnel manager for port %d (native mode)", pkt.ClientPort)

			// 启动会话清理协程
			go c.cleanupUDPSessions(connInfo)
		}
		c.udpMu.Unlock()
	}

	// 获取或创建此远程地址对应的会话
	session := c.getOrCreateUDPSession(connInfo, pkt.RemoteAddr)
	if session == nil {
		return
	}

	// 发送数据到本地UDP服务
	_, err := session.Conn.Write(pkt.Data)
	if err != nil {
		log.Printf("[Client] Failed to write native UDP data to local service: %v", err)
	}
}

// getOrCreateUDPSession 获取或创建UDP会话
func (c *Client) getOrCreateUDPSession(connInfo *UDPConnInfo, remoteAddr string) *UDPSession {
	connInfo.mu.RLock()
	session, exists := connInfo.sessions[remoteAddr]
	connInfo.mu.RUnlock()

	if exists {
		// 更新最后活跃时间
		connInfo.mu.Lock()
		session.LastActive = time.Now()
		connInfo.mu.Unlock()
		return session
	}

	connInfo.mu.Lock()
	defer connInfo.mu.Unlock()

	// 双重检查
	session, exists = connInfo.sessions[remoteAddr]
	if exists {
		session.LastActive = time.Now()
		return session
	}

	// 为此远程地址创建新的本地UDP连接
	localAddr := fmt.Sprintf("%s:%d", connInfo.TargetIP, connInfo.ClientPort)
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Printf("[Client] Failed to resolve UDP address %s: %v", localAddr, err)
		return nil
	}

	localConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("[Client] Failed to connect to local UDP service %s: %v", localAddr, err)
		return nil
	}

	session = &UDPSession{
		Conn:       localConn,
		RemoteAddr: remoteAddr,
		LastActive: time.Now(),
	}
	connInfo.sessions[remoteAddr] = session
	log.Printf("[Client] Created UDP session for remote %s -> local port %d", remoteAddr, connInfo.ClientPort)

	// 启动此会话的响应转发
	go c.forwardUDPSessionResponse(connInfo, session)

	return session
}

// forwardUDPSessionResponse 转发单个UDP会话的响应
func (c *Client) forwardUDPSessionResponse(connInfo *UDPConnInfo, session *UDPSession) {
	buf := make([]byte, 65535)

	for c.running && c.connected {
		session.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := session.Conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查会话是否仍然有效
				connInfo.mu.RLock()
				_, exists := connInfo.sessions[session.RemoteAddr]
				connInfo.mu.RUnlock()
				if !exists {
					return // 会话已被清理
				}
				continue
			}
			log.Printf("[Client] UDP session read error for %s: %v", session.RemoteAddr, err)
			return
		}

		// 更新最后活跃时间
		connInfo.mu.Lock()
		session.LastActive = time.Now()
		connInfo.mu.Unlock()

		// 发送响应给服务端
		c.sendUDPResponse(connInfo, session.RemoteAddr, buf[:n])
	}
}

// sendUDPResponse 发送UDP响应到服务端
func (c *Client) sendUDPResponse(connInfo *UDPConnInfo, remoteAddr string, data []byte) {
	// 根据UDP模式选择发送方式
	pktData := protocol.EncodeNativeUDPDataPacket(
		connInfo.ServerPort,
		connInfo.ClientPort,
		remoteAddr,
		data,
	)
	useNativeUDP := connInfo.UDPMode == protocol.UDPModeNative && c.nativeUDPConn != nil && c.serverUDPAddr != nil
	// 如果数据包超过安全MTU大小，自动回退到TCP传输
	if useNativeUDP && len(pktData) > protocol.UDPSafeMTU {
		useNativeUDP = false
	}

	if useNativeUDP {
		// 原生UDP传输
		c.mu.RLock()
		_, err := c.nativeUDPConn.WriteToUDP(pktData, c.serverUDPAddr)
		c.mu.RUnlock()
		if err != nil {
			useNativeUDP = false
		}
	}

	if !useNativeUDP {
		// TCP封装传输（备用方法或MTU超限回退）
		msg, err := protocol.NewUDPDataMessage(connInfo.TunnelName, connInfo.ClientPort, remoteAddr, data)
		if err != nil {
			log.Printf("[Client] Failed to create UDP response message: %v", err)
			return
		}

		c.mu.Lock()
		err = protocol.SendMessage(c.conn, msg)
		c.mu.Unlock()

		if err != nil {
			log.Printf("[Client] Failed to send UDP response to server: %v", err)
		}
	}
}

// cleanupUDPSessions 定期清理过期的UDP会话
func (c *Client) cleanupUDPSessions(connInfo *UDPConnInfo) {
	ticker := time.NewTicker(protocol.UDPCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !c.running || !c.connected {
				return
			}
			now := time.Now()
			connInfo.mu.Lock()
			for addr, session := range connInfo.sessions {
				if now.Sub(session.LastActive) > protocol.UDPRemoteAddrExpiry {
					session.Conn.Close()
					delete(connInfo.sessions, addr)
					log.Printf("[Client] Cleaned up expired UDP session for %s", addr)
				}
			}
			connInfo.mu.Unlock()
		case <-c.stopChan:
			return
		}
	}
}

// handleUDPData 处理服务端发来的UDP数据（TCP封装模式，备用方法）
func (c *Client) handleUDPData(msg *protocol.Message) {
	udm, err := protocol.ParseUDPDataMessage(msg.Payload)
	if err != nil {
		log.Printf("[Client] Failed to parse UDP data message: %v", err)
		return
	}

	// 获取或创建隧道的UDP连接管理器
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

			// 创建新的UDP隧道管理器
			targetIP := ""
			if tunnel != nil {
				targetIP = tunnel.TargetIP
			}
			if targetIP == "" {
				targetIP = "127.0.0.1"
			}

			serverPort := 0
			udpMode := protocol.UDPModeTCP
			if tunnel != nil {
				serverPort = tunnel.ServerPort
				udpMode = protocol.GetUDPMode(tunnel.UDPMode)
			}

			connInfo = &UDPConnInfo{
				TunnelName: udm.TunnelName,
				ClientPort: udm.ClientPort,
				ServerPort: serverPort,
				UDPMode:    udpMode,
				TargetIP:   targetIP,
				sessions:   make(map[string]*UDPSession),
			}
			c.udpConns[udm.ClientPort] = connInfo
			log.Printf("[Client] Created UDP tunnel manager for port %d (TCP fallback mode)", udm.ClientPort)

			// 启动会话清理协程
			go c.cleanupUDPSessions(connInfo)
		}
		c.udpMu.Unlock()
	}

	// 获取或创建此远程地址对应的会话
	session := c.getOrCreateUDPSession(connInfo, udm.RemoteAddr)
	if session == nil {
		return
	}

	// 发送数据到本地UDP服务
	_, err = session.Conn.Write(udm.Data)
	if err != nil {
		log.Printf("[Client] Failed to write UDP data to local service: %v", err)
	}
}

// cleanup 清理资源
func (c *Client) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 关闭所有本地TCP连接
	for _, connInfo := range c.localConns {
		connInfo.mu.Lock()
		if !connInfo.closed {
			connInfo.closed = true
			connInfo.Conn.Close()
		}
		connInfo.mu.Unlock()
	}
	c.localConns = make(map[string]*TCPConnInfo)

	// 关闭所有本地UDP连接和会话
	c.udpMu.Lock()
	for _, connInfo := range c.udpConns {
		connInfo.mu.Lock()
		for _, session := range connInfo.sessions {
			session.Conn.Close()
		}
		connInfo.sessions = nil
		connInfo.mu.Unlock()
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
