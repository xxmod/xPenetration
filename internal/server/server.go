package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"xpenetration/internal/config"
	"xpenetration/internal/protocol"
)

// Server 服务端结构
type Server struct {
	config          *config.ServerConfig
	clients         map[string]*ClientConn  // clientID -> client connection
	clientsByName   map[string]*ClientConn  // clientName -> client connection
	tunnelListeners map[int]net.Listener    // serverPort -> listener (TCP)
	udpListeners    map[int]*UDPListener    // serverPort -> UDP listener
	connections     map[string]*ProxyConn   // connID -> proxy connection
	controlListener net.Listener            // 控制端口监听器
	nativeUDPConn   *net.UDPConn            // 原生UDP传输连接（用于与客户端之间的UDP数据传输）
	clientUDPAddrs  map[string]*net.UDPAddr // clientName -> client UDP address
	mu              sync.RWMutex
	running         bool
}

// UDPListener UDP监听器信息
type UDPListener struct {
	Conn       *net.UDPConn
	Tunnel     protocol.Tunnel
	ClientName string
	// 保存远程地址到响应通道的映射，用于UDP响应
	remoteAddrs map[string]*net.UDPAddr
	mu          sync.RWMutex
}

// ClientConn 客户端连接信息
type ClientConn struct {
	ID            string
	Name          string
	Conn          net.Conn
	Tunnels       []protocol.Tunnel
	ConnectedAt   time.Time
	LastHeartbeat time.Time
	mu            sync.Mutex
}

// ProxyConn 代理连接信息
type ProxyConn struct {
	ID           string
	ClientID     string
	TunnelName   string
	ClientPort   int
	ServerPort   int
	ExternalConn net.Conn
	RemoteAddr   string
	CreatedAt    time.Time
	Ready        chan bool // 等待客户端连接就绪
}

// NewServer 创建新的服务端
func NewServer(cfg *config.ServerConfig) *Server {
	return &Server{
		config:          cfg,
		clients:         make(map[string]*ClientConn),
		clientsByName:   make(map[string]*ClientConn),
		tunnelListeners: make(map[int]net.Listener),
		udpListeners:    make(map[int]*UDPListener),
		connections:     make(map[string]*ProxyConn),
		clientUDPAddrs:  make(map[string]*net.UDPAddr),
	}
}

// Start 启动服务端
func (s *Server) Start() error {
	s.running = true

	// 启动控制端口监听
	controlAddr := fmt.Sprintf("%s:%d", s.config.Server.ListenAddr, s.config.Server.ControlPort)
	listener, err := net.Listen("tcp", controlAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on control port: %v", err)
	}

	s.mu.Lock()
	s.controlListener = listener
	s.mu.Unlock()

	log.Printf("[Server] Control server listening on %s", controlAddr)

	// 启动原生UDP传输监听器（用于与客户端之间的UDP数据传输）
	if err := s.startNativeUDPListener(); err != nil {
		log.Printf("[Server] Warning: Failed to start native UDP listener: %v", err)
	}

	// 启动所有隧道端口监听
	for _, client := range s.config.Clients {
		for _, tunnel := range client.Tunnels {
			if tunnel.Protocol == "udp" {
				if err := s.startUDPTunnelListener(tunnel, client.Name); err != nil {
					log.Printf("[Server] Failed to start UDP tunnel listener for %s:%d: %v", tunnel.Name, tunnel.ServerPort, err)
				}
			} else {
				if err := s.startTunnelListener(tunnel, client.Name); err != nil {
					log.Printf("[Server] Failed to start tunnel listener for %s:%d: %v", tunnel.Name, tunnel.ServerPort, err)
				}
			}
		}
	}

	// 接受客户端连接
	go s.acceptClients(listener)

	return nil
}

// startNativeUDPListener 启动原生UDP传输监听器
func (s *Server) startNativeUDPListener() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.ListenAddr, s.config.Server.UDPPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.nativeUDPConn = conn
	s.mu.Unlock()

	log.Printf("[Server] Native UDP transport listening on %s", addr)

	go s.handleNativeUDPTransport()
	return nil
}

// handleNativeUDPTransport 处理原生UDP传输数据
func (s *Server) handleNativeUDPTransport() {
	buf := make([]byte, 65535)

	for s.running {
		n, clientUDPAddr, err := s.nativeUDPConn.ReadFromUDP(buf)
		if err != nil {
			if s.running {
				log.Printf("[Server] Native UDP read error: %v", err)
			}
			continue
		}

		if n < 1 {
			continue
		}

		// 检查数据包类型
		pktType := buf[0]

		if pktType == protocol.NativeUDPTypeRegister {
			// 处理注册包
			regPkt, err := protocol.DecodeNativeUDPRegisterPacket(buf[:n])
			if err != nil {
				log.Printf("[Server] Failed to decode UDP register packet: %v", err)
				continue
			}

			// 保存客户端的UDP地址
			s.mu.Lock()
			s.clientUDPAddrs[regPkt.ClientName] = clientUDPAddr
			s.mu.Unlock()

			log.Printf("[Server] Registered UDP address for client %s: %s", regPkt.ClientName, clientUDPAddr.String())
			continue
		}

		if pktType == protocol.NativeUDPTypeData {
			// 处理数据包
			pkt, err := protocol.DecodeNativeUDPDataPacket(buf[:n])
			if err != nil {
				log.Printf("[Server] Failed to decode native UDP data packet: %v", err)
				continue
			}

			// 查找对应的UDP监听器
			s.mu.RLock()
			udpListener, exists := s.udpListeners[pkt.ServerPort]
			s.mu.RUnlock()

			if !exists {
				log.Printf("[Server] UDP listener not found for server port: %d", pkt.ServerPort)
				continue
			}

			// 更新客户端的UDP地址（用于发送响应）
			s.mu.Lock()
			s.clientUDPAddrs[udpListener.ClientName] = clientUDPAddr
			s.mu.Unlock()

			// 查找原始请求的远程地址
			udpListener.mu.RLock()
			remoteAddr, exists := udpListener.remoteAddrs[pkt.RemoteAddr]
			udpListener.mu.RUnlock()

			if !exists {
				log.Printf("[Server] Remote address not found: %s", pkt.RemoteAddr)
				continue
			}

			// 发送响应给外部客户端
			_, err = udpListener.Conn.WriteToUDP(pkt.Data, remoteAddr)
			if err != nil {
				log.Printf("[Server] Failed to send UDP response to external client: %v", err)
			}
		}
	}
}

// startTunnelListener 启动隧道监听器
func (s *Server) startTunnelListener(tunnel protocol.Tunnel, clientName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查端口是否已被监听
	if _, exists := s.tunnelListeners[tunnel.ServerPort]; exists {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.ListenAddr, tunnel.ServerPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.tunnelListeners[tunnel.ServerPort] = listener
	log.Printf("[Server] Tunnel %s listening on port %d -> client %s port %d",
		tunnel.Name, tunnel.ServerPort, clientName, tunnel.ClientPort)

	go s.acceptTunnelConnections(listener, tunnel, clientName)
	return nil
}

// startUDPTunnelListener 启动UDP隧道监听器
func (s *Server) startUDPTunnelListener(tunnel protocol.Tunnel, clientName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查端口是否已被监听
	if _, exists := s.udpListeners[tunnel.ServerPort]; exists {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.Server.ListenAddr, tunnel.ServerPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	udpListener := &UDPListener{
		Conn:        conn,
		Tunnel:      tunnel,
		ClientName:  clientName,
		remoteAddrs: make(map[string]*net.UDPAddr),
	}

	s.udpListeners[tunnel.ServerPort] = udpListener

	udpMode := protocol.GetUDPMode(tunnel.UDPMode)
	log.Printf("[Server] UDP Tunnel %s listening on port %d -> client %s port %d (mode: %s)",
		tunnel.Name, tunnel.ServerPort, clientName, tunnel.ClientPort, udpMode)

	go s.handleUDPTunnel(udpListener)
	return nil
}

// handleUDPTunnel 处理UDP隧道数据
func (s *Server) handleUDPTunnel(udpListener *UDPListener) {
	buf := make([]byte, 65535) // UDP最大包大小
	udpMode := protocol.GetUDPMode(udpListener.Tunnel.UDPMode)

	for s.running {
		n, remoteAddr, err := udpListener.Conn.ReadFromUDP(buf)
		if err != nil {
			if s.running {
				log.Printf("[Server] UDP read error: %v", err)
			}
			continue
		}

		// 保存远程地址用于响应
		remoteAddrStr := remoteAddr.String()
		udpListener.mu.Lock()
		udpListener.remoteAddrs[remoteAddrStr] = remoteAddr
		udpListener.mu.Unlock()

		// 查找客户端
		s.mu.RLock()
		client, exists := s.clientsByName[udpListener.ClientName]
		clientUDPAddr := s.clientUDPAddrs[udpListener.ClientName]
		s.mu.RUnlock()

		if !exists {
			log.Printf("[Server] UDP: Client not connected: %s", udpListener.ClientName)
			continue
		}

		// 根据udp_mode选择传输方式
		if udpMode == protocol.UDPModeNative && s.nativeUDPConn != nil && clientUDPAddr != nil {
			// 原生UDP传输：直接通过UDP发送给客户端（使用带类型前缀的数据包）
			pktData := protocol.EncodeNativeUDPDataPacket(
				udpListener.Tunnel.ServerPort,
				udpListener.Tunnel.ClientPort,
				remoteAddrStr,
				buf[:n],
			)
			_, err = s.nativeUDPConn.WriteToUDP(pktData, clientUDPAddr)
			if err != nil {
				log.Printf("[Server] Failed to send native UDP data to client: %v", err)
			}
		} else {
			// TCP封装传输（备用方法）：通过TCP控制通道发送UDP数据
			msg, err := protocol.NewUDPDataMessage(
				udpListener.Tunnel.Name,
				udpListener.Tunnel.ClientPort,
				remoteAddrStr,
				buf[:n],
			)
			if err != nil {
				log.Printf("[Server] Failed to create UDP data message: %v", err)
				continue
			}

			client.mu.Lock()
			err = protocol.SendMessage(client.Conn, msg)
			client.mu.Unlock()

			if err != nil {
				log.Printf("[Server] Failed to send UDP data to client: %v", err)
			}
		}
	}
}

// handleUDPDataFromClient 处理来自客户端的UDP数据响应
func (s *Server) handleUDPDataFromClient(client *ClientConn, msg *protocol.Message) {
	udm, err := protocol.ParseUDPDataMessage(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse UDP data message: %v", err)
		return
	}

	// 查找对应的UDP监听器
	var udpListener *UDPListener
	s.mu.RLock()
	for _, ul := range s.udpListeners {
		if ul.Tunnel.Name == udm.TunnelName {
			udpListener = ul
			break
		}
	}
	s.mu.RUnlock()

	if udpListener == nil {
		log.Printf("[Server] UDP listener not found for tunnel: %s", udm.TunnelName)
		return
	}

	// 获取远程地址
	udpListener.mu.RLock()
	remoteAddr, exists := udpListener.remoteAddrs[udm.RemoteAddr]
	udpListener.mu.RUnlock()

	if !exists {
		log.Printf("[Server] Remote address not found: %s", udm.RemoteAddr)
		return
	}

	// 发送UDP响应
	_, err = udpListener.Conn.WriteToUDP(udm.Data, remoteAddr)
	if err != nil {
		log.Printf("[Server] Failed to send UDP response: %v", err)
	}
}

// acceptClients 接受客户端控制连接
func (s *Server) acceptClients(listener net.Listener) {
	for s.running {
		conn, err := listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("[Server] Accept error: %v", err)
			}
			continue
		}

		go s.handleClientConnection(conn)
	}
}

// handleClientConnection 处理客户端连接
func (s *Server) handleClientConnection(conn net.Conn) {
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取认证消息
	msg, err := protocol.DecodeMessage(conn)
	if err != nil {
		log.Printf("[Server] Failed to read auth message: %v", err)
		return
	}

	if msg.Type != protocol.MsgTypeAuth {
		log.Printf("[Server] Expected auth message, got type %d", msg.Type)
		s.sendError(conn, 1, "Expected authentication message")
		return
	}

	// 解析认证请求
	authReq, err := protocol.ParseAuthRequest(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse auth request: %v", err)
		s.sendError(conn, 2, "Invalid authentication request")
		return
	}

	// 验证密钥
	clientConfig := s.findClientConfig(authReq.ClientName)
	if clientConfig == nil {
		log.Printf("[Server] Unknown client: %s", authReq.ClientName)
		s.sendAuthResponse(conn, false, "Unknown client", "")
		return
	}

	// 检查密钥
	expectedKey := clientConfig.SecretKey
	if expectedKey == "" {
		expectedKey = s.config.Server.SecretKey
	}

	if authReq.SecretKey != expectedKey {
		log.Printf("[Server] Invalid secret key from client: %s", authReq.ClientName)
		s.sendAuthResponse(conn, false, "Invalid secret key", "")
		return
	}

	// 生成客户端ID
	clientID := fmt.Sprintf("%s-%d", authReq.ClientName, time.Now().UnixNano())

	// 清除读取超时
	conn.SetReadDeadline(time.Time{})

	// 创建客户端连接记录
	clientConn := &ClientConn{
		ID:            clientID,
		Name:          authReq.ClientName,
		Conn:          conn,
		Tunnels:       clientConfig.Tunnels,
		ConnectedAt:   time.Now(),
		LastHeartbeat: time.Now(),
	}

	// 注册客户端
	s.mu.Lock()
	// 断开同名的旧连接
	if oldClient, exists := s.clientsByName[authReq.ClientName]; exists {
		log.Printf("[Server] Disconnecting old connection for client: %s", authReq.ClientName)
		oldClient.Conn.Close()
		delete(s.clients, oldClient.ID)
	}
	s.clients[clientID] = clientConn
	s.clientsByName[authReq.ClientName] = clientConn
	s.mu.Unlock()

	log.Printf("[Server] Client authenticated: %s (ID: %s)", authReq.ClientName, clientID)

	// 发送认证成功响应
	if err := s.sendAuthResponse(conn, true, "Authentication successful", clientID); err != nil {
		log.Printf("[Server] Failed to send auth response: %v", err)
		return
	}

	// 发送隧道配置
	if err := s.sendTunnelConfig(conn, clientConfig.Tunnels); err != nil {
		log.Printf("[Server] Failed to send tunnel config: %v", err)
		return
	}

	// 处理客户端消息
	s.handleClientMessages(clientConn)

	// 清理客户端
	s.mu.Lock()
	delete(s.clients, clientID)
	if s.clientsByName[authReq.ClientName] == clientConn {
		delete(s.clientsByName, authReq.ClientName)
	}
	s.mu.Unlock()

	log.Printf("[Server] Client disconnected: %s", authReq.ClientName)
}

// findClientConfig 查找客户端配置
func (s *Server) findClientConfig(clientName string) *config.ClientSettings {
	for i := range s.config.Clients {
		if s.config.Clients[i].Name == clientName {
			return &s.config.Clients[i]
		}
	}
	return nil
}

// sendAuthResponse 发送认证响应
func (s *Server) sendAuthResponse(conn net.Conn, success bool, message, clientID string) error {
	msg, err := protocol.NewAuthResponse(success, message, clientID)
	if err != nil {
		return err
	}
	return protocol.SendMessage(conn, msg)
}

// sendTunnelConfig 发送隧道配置
func (s *Server) sendTunnelConfig(conn net.Conn, tunnels []protocol.Tunnel) error {
	msg, err := protocol.NewTunnelConfig(tunnels)
	if err != nil {
		return err
	}
	return protocol.SendMessage(conn, msg)
}

// sendError 发送错误消息
func (s *Server) sendError(conn net.Conn, code int, message string) {
	msg, err := protocol.NewErrorMessage(code, message)
	if err != nil {
		return
	}
	protocol.SendMessage(conn, msg)
}

// handleClientMessages 处理客户端消息
func (s *Server) handleClientMessages(client *ClientConn) {
	for s.running {
		msg, err := protocol.DecodeMessage(client.Conn)
		if err != nil {
			log.Printf("[Server] Failed to read message from client %s: %v", client.Name, err)
			return
		}

		switch msg.Type {
		case protocol.MsgTypeHeartbeat:
			s.handleHeartbeat(client, msg)
		case protocol.MsgTypeConnReady:
			s.handleConnReady(client, msg)
		case protocol.MsgTypeData:
			s.handleDataFromClient(client, msg)
		case protocol.MsgTypeDisconnect:
			s.handleDisconnectFromClient(client, msg)
		case protocol.MsgTypeUDPData:
			s.handleUDPDataFromClient(client, msg)
		default:
			log.Printf("[Server] Unknown message type from client %s: %d", client.Name, msg.Type)
		}
	}
}

// handleHeartbeat 处理心跳
func (s *Server) handleHeartbeat(client *ClientConn, msg *protocol.Message) {
	hb, err := protocol.ParseHeartbeat(msg.Payload)
	if err != nil {
		return
	}

	client.mu.Lock()
	client.LastHeartbeat = time.Now()
	client.mu.Unlock()

	// 发送心跳确认
	ackMsg, _ := protocol.NewHeartbeatAck(hb.Timestamp)
	client.mu.Lock()
	protocol.SendMessage(client.Conn, ackMsg)
	client.mu.Unlock()
}

// handleConnReady 处理连接就绪消息
func (s *Server) handleConnReady(client *ClientConn, msg *protocol.Message) {
	cr, err := protocol.ParseConnReady(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse conn ready: %v", err)
		return
	}

	s.mu.RLock()
	proxyConn, exists := s.connections[cr.ConnID]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[Server] Connection not found: %s", cr.ConnID)
		return
	}

	if !cr.Success {
		log.Printf("[Server] Client failed to connect to local service: %s", cr.Message)
		// 发送失败信号
		select {
		case proxyConn.Ready <- false:
		default:
		}
		return
	}

	log.Printf("[Server] Connection ready: %s", cr.ConnID)
	// 发送就绪信号
	select {
	case proxyConn.Ready <- true:
	default:
	}
}

// handleDataFromClient 处理来自客户端的数据
func (s *Server) handleDataFromClient(client *ClientConn, msg *protocol.Message) {
	dm, err := protocol.ParseDataMessage(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse data message: %v", err)
		return
	}

	s.mu.RLock()
	proxyConn, exists := s.connections[dm.ConnID]
	s.mu.RUnlock()

	if !exists {
		return
	}

	// 转发数据到外部连接
	_, err = proxyConn.ExternalConn.Write(dm.Data)
	if err != nil {
		log.Printf("[Server] Failed to write to external connection: %v", err)
		proxyConn.ExternalConn.Close()
	}
}

// handleDisconnectFromClient 处理来自客户端的断开连接消息
func (s *Server) handleDisconnectFromClient(client *ClientConn, msg *protocol.Message) {
	dm, err := protocol.ParseDisconnectMessage(msg.Payload)
	if err != nil {
		return
	}

	s.mu.Lock()
	if proxyConn, exists := s.connections[dm.ConnID]; exists {
		proxyConn.ExternalConn.Close()
		delete(s.connections, dm.ConnID)
	}
	s.mu.Unlock()
}

// acceptTunnelConnections 接受隧道连接
func (s *Server) acceptTunnelConnections(listener net.Listener, tunnel protocol.Tunnel, clientName string) {
	for s.running {
		conn, err := listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("[Server] Tunnel accept error: %v", err)
			}
			continue
		}

		go s.handleTunnelConnection(conn, tunnel, clientName)
	}
}

// handleTunnelConnection 处理隧道连接
func (s *Server) handleTunnelConnection(conn net.Conn, tunnel protocol.Tunnel, clientName string) {
	// 查找客户端
	s.mu.RLock()
	client, exists := s.clientsByName[clientName]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[Server] Client not connected: %s", clientName)
		conn.Close()
		return
	}

	// 生成连接ID
	connID := fmt.Sprintf("conn-%d", time.Now().UnixNano())

	// 创建代理连接记录
	proxyConn := &ProxyConn{
		ID:           connID,
		ClientID:     client.ID,
		TunnelName:   tunnel.Name,
		ClientPort:   tunnel.ClientPort,
		ServerPort:   tunnel.ServerPort,
		ExternalConn: conn,
		RemoteAddr:   conn.RemoteAddr().String(),
		CreatedAt:    time.Now(),
		Ready:        make(chan bool, 1),
	}

	s.mu.Lock()
	s.connections[connID] = proxyConn
	s.mu.Unlock()

	log.Printf("[Server] New connection %s: %s -> tunnel %s", connID, conn.RemoteAddr().String(), tunnel.Name)

	// 通知客户端有新连接
	msg, err := protocol.NewConnectionMessage(connID, tunnel.Name, tunnel.ClientPort, conn.RemoteAddr().String())
	if err != nil {
		log.Printf("[Server] Failed to create new connection message: %v", err)
		conn.Close()
		return
	}

	client.mu.Lock()
	err = protocol.SendMessage(client.Conn, msg)
	client.mu.Unlock()

	if err != nil {
		log.Printf("[Server] Failed to send new connection message: %v", err)
		conn.Close()
		s.mu.Lock()
		delete(s.connections, connID)
		s.mu.Unlock()
		return
	}

	// 等待客户端连接就绪
	select {
	case ready := <-proxyConn.Ready:
		if !ready {
			log.Printf("[Server] Client failed to connect to local service for %s", connID)
			conn.Close()
			s.mu.Lock()
			delete(s.connections, connID)
			s.mu.Unlock()
			return
		}
	case <-time.After(10 * time.Second):
		log.Printf("[Server] Timeout waiting for client ready: %s", connID)
		conn.Close()
		s.mu.Lock()
		delete(s.connections, connID)
		s.mu.Unlock()
		return
	}

	// 客户端已就绪，开始读取外部连接数据并转发给客户端
	s.forwardFromExternal(proxyConn, client)
}

// forwardFromExternal 从外部连接转发数据到客户端
func (s *Server) forwardFromExternal(proxyConn *ProxyConn, client *ClientConn) {
	defer func() {
		proxyConn.ExternalConn.Close()
		s.mu.Lock()
		delete(s.connections, proxyConn.ID)
		s.mu.Unlock()

		// 通知客户端断开连接
		msg, _ := protocol.NewDisconnectMessage(proxyConn.ID, "external connection closed")
		client.mu.Lock()
		protocol.SendMessage(client.Conn, msg)
		client.mu.Unlock()
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := proxyConn.ExternalConn.Read(buf)
		if err != nil {
			return
		}

		// 发送数据给客户端
		msg, err := protocol.NewDataMessage(proxyConn.ID, buf[:n])
		if err != nil {
			return
		}

		client.mu.Lock()
		err = protocol.SendMessage(client.Conn, msg)
		client.mu.Unlock()

		if err != nil {
			return
		}
	}
}

// GetConfig 获取当前配置
func (s *Server) GetConfig() *config.ServerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// Reload 重载配置
func (s *Server) Reload(newConfig *config.ServerConfig) error {
	log.Printf("[Server] Reloading configuration...")

	// 停止当前服务
	s.Stop()

	// 更新配置
	s.mu.Lock()
	s.config = newConfig
	s.mu.Unlock()

	// 重新启动服务
	return s.Start()
}

// Stop 停止服务端
func (s *Server) Stop() {
	s.running = false

	s.mu.Lock()
	defer s.mu.Unlock()

	// 关闭控制端口监听器
	// 注意：这里需要保存控制端口的listener才能关闭它
	// 由于之前的实现没有保存，这里需要修改Start方法来保存它
	if s.controlListener != nil {
		s.controlListener.Close()
	}

	// 关闭原生UDP传输监听器
	if s.nativeUDPConn != nil {
		s.nativeUDPConn.Close()
		s.nativeUDPConn = nil
	}

	// 清空客户端UDP地址映射
	s.clientUDPAddrs = make(map[string]*net.UDPAddr)

	// 关闭所有隧道监听器
	for _, listener := range s.tunnelListeners {
		listener.Close()
	}
	// 清空监听器map
	s.tunnelListeners = make(map[int]net.Listener)

	// 关闭所有UDP监听器
	for _, udpListener := range s.udpListeners {
		udpListener.Conn.Close()
	}
	s.udpListeners = make(map[int]*UDPListener)

	// 关闭所有客户端连接
	for _, client := range s.clients {
		client.Conn.Close()
	}
	// 清空客户端map
	s.clients = make(map[string]*ClientConn)
	s.clientsByName = make(map[string]*ClientConn)

	// 关闭所有代理连接
	for _, conn := range s.connections {
		conn.ExternalConn.Close()
	}
	// 清空连接map
	s.connections = make(map[string]*ProxyConn)
}

// GetClients 获取所有客户端信息（用于Web API）
func (s *Server) GetClients() []ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]ClientInfo, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, ClientInfo{
			ID:            client.ID,
			Name:          client.Name,
			ConnectedAt:   client.ConnectedAt,
			LastHeartbeat: client.LastHeartbeat,
			Tunnels:       client.Tunnels,
		})
	}
	return clients
}

// ClientInfo 客户端信息（用于API响应）
type ClientInfo struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	ConnectedAt   time.Time         `json:"connected_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	Tunnels       []protocol.Tunnel `json:"tunnels"`
}

// GetConnections 获取所有活跃连接（用于Web API）
func (s *Server) GetConnections() []ConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	connections := make([]ConnectionInfo, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, ConnectionInfo{
			ID:         conn.ID,
			ClientID:   conn.ClientID,
			TunnelName: conn.TunnelName,
			ClientPort: conn.ClientPort,
			ServerPort: conn.ServerPort,
			RemoteAddr: conn.RemoteAddr,
			CreatedAt:  conn.CreatedAt,
		})
	}
	return connections
}

// ConnectionInfo 连接信息（用于API响应）
type ConnectionInfo struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"client_id"`
	TunnelName string    `json:"tunnel_name"`
	ClientPort int       `json:"client_port"`
	ServerPort int       `json:"server_port"`
	RemoteAddr string    `json:"remote_addr"`
	CreatedAt  time.Time `json:"created_at"`
}

// GetStats 获取统计信息
func (s *Server) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Stats{
		ClientCount:     len(s.clients),
		ConnectionCount: len(s.connections),
		TunnelCount:     len(s.tunnelListeners),
	}
}

// Stats 统计信息
type Stats struct {
	ClientCount     int `json:"client_count"`
	ConnectionCount int `json:"connection_count"`
	TunnelCount     int `json:"tunnel_count"`
}

// ToJSON 转换为JSON
func (s Stats) ToJSON() []byte {
	data, _ := json.Marshal(s)
	return data
}
