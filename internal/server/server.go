package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"xpenetration/internal/config"
	"xpenetration/internal/protocol"
	"xpenetration/internal/secure"
)

// LogWriter 自定义日志写入器，同时输出到控制台和收集到内存
type LogWriter struct {
	server    *Server
	original  io.Writer
	logRegexp *regexp.Regexp
}

// NewLogWriter 创建新的日志写入器
func NewLogWriter(server *Server, original io.Writer) *LogWriter {
	// 匹配日志格式: [Source] message 或普通文本
	return &LogWriter{
		server:    server,
		original:  original,
		logRegexp: regexp.MustCompile(`^\[([^\]]+)\]\s+(.*)$`),
	}
}

// Write 实现 io.Writer 接口
func (w *LogWriter) Write(p []byte) (n int, err error) {
	// 先输出到原始控制台
	n, err = w.original.Write(p)

	// 然后收集到内存日志
	if w.server != nil {
		w.collectLog(string(p))
	}

	return n, err
}

// collectLog 收集日志到内存
func (w *LogWriter) collectLog(logLine string) {
	// 移除时间戳前缀 (log 包默认格式: 2006/01/02 15:04:05 message)
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return
	}

	// 尝试移除标准时间戳前缀
	if len(logLine) > 20 {
		// 检查是否以日期时间开头 (YYYY/MM/DD HH:MM:SS)
		if logLine[4] == '/' && logLine[7] == '/' && logLine[10] == ' ' {
			spaceIdx := strings.Index(logLine[11:], " ")
			if spaceIdx > 0 {
				logLine = strings.TrimSpace(logLine[11+spaceIdx+1:])
			}
		}
	}

	// 解析日志来源
	source := "server"
	clientName := ""
	logType := "general"
	level := "info"
	message := logLine

	// 解析 [Source] 格式
	matches := w.logRegexp.FindStringSubmatch(logLine)
	if len(matches) == 3 {
		source = strings.ToLower(matches[1])
		message = matches[2]
	}

	// 判断日志级别
	lowerMsg := strings.ToLower(message)
	if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "failed") {
		level = "error"
	} else if strings.Contains(lowerMsg, "warning") || strings.Contains(lowerMsg, "warn") {
		level = "warn"
	}

	// 添加到日志列表
	w.server.addLogEntry(level, source, clientName, logType, message)
}

// addLogEntry 内部添加日志记录（不触发 log.Printf 避免循环）
func (s *Server) addLogEntry(level, source, clientName, logType, message string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	entry := LogEntry{
		Time:       time.Now(),
		Level:      level,
		Source:     source,
		ClientName: clientName,
		Type:       logType,
		Message:    message,
	}

	s.logs = append(s.logs, entry)

	// 限制日志数量，最多保留5000条
	if len(s.logs) > 5000 {
		s.logs = s.logs[len(s.logs)-5000:]
	}
}

// SetupLogCapture 设置日志捕获
func (s *Server) SetupLogCapture() {
	logWriter := NewLogWriter(s, os.Stderr)
	log.SetOutput(logWriter)
}

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
	metrics         *Metrics                // 运行时观测指标
	logs            []LogEntry              // 日志记录
	connIDCounter   atomic.Uint64           // 连接ID计数器，确保唯一性
	mu              sync.RWMutex
	logMu           sync.RWMutex // 日志专用锁
	running         bool
	stopChan        chan struct{} // 停止信号通道
}

// LogEntry 日志条目
type LogEntry struct {
	Time       time.Time `json:"time"`
	Level      string    `json:"level"`
	Source     string    `json:"source"`      // 来源: server/client
	ClientName string    `json:"client_name"` // 客户端名称（如果来自客户端）
	Type       string    `json:"type"`        // 日志类型
	Message    string    `json:"message"`
}

// UDPListener UDP监听器信息
type UDPListener struct {
	Conn       *net.UDPConn
	Tunnel     protocol.Tunnel
	ClientName string
	// 保存远程地址到响应通道的映射，用于UDP响应
	remoteAddrs map[string]*UDPRemoteAddrEntry
	mu          sync.RWMutex
	stopCleanup chan struct{}
}

// UDPRemoteAddrEntry UDP远程地址条目（包含时间戳）
type UDPRemoteAddrEntry struct {
	Addr     *net.UDPAddr
	LastSeen time.Time
	ConnID   string
}

// ClientConn 客户端连接信息
type ClientConn struct {
	ID                string
	Name              string
	Conn              net.Conn
	Session           *yamux.Session // yamux多路复用会话
	ControlStream     net.Conn       // 控制流（心跳、UDP数据等）
	Tunnels           []protocol.Tunnel
	ConnectedAt       time.Time
	LastHeartbeat     time.Time
	EncryptionEnabled bool
	EncryptionKey     []byte
	mu                sync.Mutex // 用于一般操作
}

// SendControl 发送控制消息到控制流
func (c *ClientConn) SendControl(msg *protocol.Message) bool {
	c.mu.Lock()
	stream := c.ControlStream
	c.mu.Unlock()
	if stream == nil {
		return false
	}
	return protocol.SendMessage(stream, msg) == nil
}

// OpenStream 打开新的数据流用于TCP连接
func (c *ClientConn) OpenStream() (net.Conn, error) {
	if c.Session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	return c.Session.Open()
}

// Close 关闭客户端连接
func (c *ClientConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ControlStream != nil {
		c.ControlStream.Close()
		c.ControlStream = nil
	}
	if c.Session != nil {
		c.Session.Close()
		c.Session = nil
	}
	if c.Conn != nil {
		c.Conn.Close()
	}
}

// ProxyConn 代理连接信息
type ProxyConn struct {
	ID           string
	ClientID     string
	TunnelName   string
	ClientPort   int
	ServerPort   int
	Tunnel       protocol.Tunnel
	ExternalConn net.Conn
	RemoteAddr   string
	CreatedAt    time.Time
	Ready        chan bool // 等待客户端连接就绪
	Protocol     string
	LastSeen     time.Time
}

// addConnection registers a new active connection for Web/API visibility.
func (s *Server) addConnection(pc *ProxyConn) {
	s.mu.Lock()
	s.connections[pc.ID] = pc
	s.mu.Unlock()
}

// updateConnectionLastSeen refreshes the timestamp of an active connection.
func (s *Server) updateConnectionLastSeen(id string) {
	s.mu.Lock()
	if pc, ok := s.connections[id]; ok {
		pc.LastSeen = time.Now()
	}
	s.mu.Unlock()
}

// removeConnection deletes an active connection entry.
func (s *Server) removeConnection(id string) {
	s.mu.Lock()
	delete(s.connections, id)
	s.mu.Unlock()
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
		metrics:         newMetrics(),
		logs:            make([]LogEntry, 0),
		stopChan:        make(chan struct{}),
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

	// 设置UDP缓冲区大小，减少高流量时的丢包
	conn.SetReadBuffer(protocol.UDPReadBufferSize)
	conn.SetWriteBuffer(protocol.UDPWriteBufferSize)

	s.mu.Lock()
	s.nativeUDPConn = conn
	s.mu.Unlock()

	log.Printf("[Server] Native UDP transport listening on %s (buffer: %dKB)", addr, protocol.UDPReadBufferSize/1024)

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

		// 复制数据以便并发处理
		pktData := make([]byte, n)
		copy(pktData, buf[:n])
		addrCopy := &net.UDPAddr{
			IP:   make(net.IP, len(clientUDPAddr.IP)),
			Port: clientUDPAddr.Port,
			Zone: clientUDPAddr.Zone,
		}
		copy(addrCopy.IP, clientUDPAddr.IP)

		// 并发处理数据包
		go s.processNativeUDPPacket(pktData, addrCopy)
	}
}

// processNativeUDPPacket 处理单个原生UDP数据包
func (s *Server) processNativeUDPPacket(data []byte, clientUDPAddr *net.UDPAddr) {
	if len(data) < 1 {
		return
	}

	// 检查数据包类型
	pktType := data[0]

	if pktType == protocol.NativeUDPTypeRegister {
		// 处理注册包
		regPkt, err := protocol.DecodeNativeUDPRegisterPacket(data)
		if err != nil {
			log.Printf("[Server] Failed to decode UDP register packet: %v", err)
			return
		}

		// 保存客户端的UDP地址
		s.mu.Lock()
		s.clientUDPAddrs[regPkt.ClientName] = clientUDPAddr
		s.mu.Unlock()

		log.Printf("[Server] Registered UDP address for client %s: %s", regPkt.ClientName, clientUDPAddr.String())
		return
	}

	if pktType == protocol.NativeUDPTypeData {
		// 处理数据包
		pkt, err := protocol.DecodeNativeUDPDataPacket(data)
		if err != nil {
			log.Printf("[Server] Failed to decode native UDP data packet: %v", err)
			return
		}

		// 查找对应的UDP监听器
		s.mu.RLock()
		udpListener, ok := s.udpListeners[pkt.ServerPort]
		s.mu.RUnlock()
		if !ok || udpListener == nil {
			log.Printf("[Server] UDP listener not found for port: %d", pkt.ServerPort)
			return
		}

		s.mu.RLock()
		clientConn := s.clientsByName[udpListener.ClientName]
		s.mu.RUnlock()
		if clientConn == nil {
			log.Printf("[Server] UDP listener client not connected: %s", udpListener.ClientName)
			return
		}

		// 查找原始请求的远程地址
		udpListener.mu.Lock()
		entry, exists := udpListener.remoteAddrs[pkt.RemoteAddr]
		if exists {
			entry.LastSeen = time.Now()
		}
		udpListener.mu.Unlock()
		// 更新客户端的UDP地址（用于发送响应）
		s.mu.Lock()
		s.clientUDPAddrs[udpListener.ClientName] = clientUDPAddr
		s.mu.Unlock()

		if !exists {
			log.Printf("[Server] Remote address not found: %s", pkt.RemoteAddr)
			return
		}

		s.updateConnectionLastSeen(entry.ConnID)

		payload := pkt.Data
		if clientConn.EncryptionEnabled {
			plain, err := secure.DecryptBytes(pkt.Data, clientConn.EncryptionKey)
			if err != nil {
				log.Printf("[Server] Failed to decrypt UDP payload: %v", err)
				return
			}
			payload = plain
		}

		// 发送响应给外部客户端
		_, err = udpListener.Conn.WriteToUDP(payload, entry.Addr)
		if err != nil {
			log.Printf("[Server] Failed to send UDP response to external client: %v", err)
		} else {
			s.metrics.recordUDPOutbound(udpListener.Tunnel, len(payload), false)
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

	// 设置UDP缓冲区大小，减少高流量时的丢包
	conn.SetReadBuffer(protocol.UDPReadBufferSize)
	conn.SetWriteBuffer(protocol.UDPWriteBufferSize)

	udpListener := &UDPListener{
		Conn:        conn,
		Tunnel:      tunnel,
		ClientName:  clientName,
		remoteAddrs: make(map[string]*UDPRemoteAddrEntry),
		stopCleanup: make(chan struct{}),
	}

	s.udpListeners[tunnel.ServerPort] = udpListener

	udpMode := protocol.GetUDPMode(tunnel.UDPMode)
	log.Printf("[Server] UDP Tunnel %s listening on port %d -> client %s port %d (mode: %s, buffer: %dKB)",
		tunnel.Name, tunnel.ServerPort, clientName, tunnel.ClientPort, udpMode, protocol.UDPReadBufferSize/1024)

	// 启动远程地址清理线程
	go s.cleanupRemoteAddrs(udpListener)
	go s.handleUDPTunnel(udpListener)
	return nil
}

// cleanupRemoteAddrs 定期清理过期的远程地址映射
func (s *Server) cleanupRemoteAddrs(udpListener *UDPListener) {
	ticker := time.NewTicker(protocol.UDPCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			staleIDs := make([]string, 0)
			udpListener.mu.Lock()
			for addr, entry := range udpListener.remoteAddrs {
				if now.Sub(entry.LastSeen) > protocol.UDPRemoteAddrExpiry {
					staleIDs = append(staleIDs, entry.ConnID)
					delete(udpListener.remoteAddrs, addr)
				}
			}
			udpListener.mu.Unlock()
			for _, id := range staleIDs {
				s.removeConnection(id)
			}
		case <-udpListener.stopCleanup:
			return
		case <-s.stopChan:
			return
		}
	}
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

		// 复制数据以便并发处理
		pktData := make([]byte, n)
		copy(pktData, buf[:n])
		addrCopy := &net.UDPAddr{
			IP:   make(net.IP, len(remoteAddr.IP)),
			Port: remoteAddr.Port,
			Zone: remoteAddr.Zone,
		}
		copy(addrCopy.IP, remoteAddr.IP)

		// 并发处理数据包
		go s.processUDPTunnelPacket(udpListener, pktData, addrCopy, udpMode)
	}
}

// processUDPTunnelPacket 处理单个UDP隧道数据包
func (s *Server) processUDPTunnelPacket(udpListener *UDPListener, data []byte, remoteAddr *net.UDPAddr, udpMode string) {
	// 保存远程地址用于响应（带时间戳）
	remoteAddrStr := remoteAddr.String()
	clientID := ""

	// 查找客户端
	s.mu.RLock()
	client, exists := s.clientsByName[udpListener.ClientName]
	clientUDPAddr := s.clientUDPAddrs[udpListener.ClientName]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[Server] UDP: Client not connected: %s", udpListener.ClientName)
		return
	}
	clientID = client.ID

	udpListener.mu.Lock()
	if entry, ok := udpListener.remoteAddrs[remoteAddrStr]; ok {
		entry.LastSeen = time.Now()
		udpListener.mu.Unlock()
		s.updateConnectionLastSeen(entry.ConnID)
	} else {
		connID := fmt.Sprintf("udp-%s-%d-%s", udpListener.ClientName, udpListener.Tunnel.ServerPort, remoteAddrStr)
		udpListener.remoteAddrs[remoteAddrStr] = &UDPRemoteAddrEntry{
			Addr:     remoteAddr,
			LastSeen: time.Now(),
			ConnID:   connID,
		}
		udpListener.mu.Unlock()
		s.addConnection(&ProxyConn{
			ID:         connID,
			ClientID:   clientID,
			TunnelName: udpListener.Tunnel.Name,
			ClientPort: udpListener.Tunnel.ClientPort,
			ServerPort: udpListener.Tunnel.ServerPort,
			Tunnel:     udpListener.Tunnel,
			RemoteAddr: remoteAddrStr,
			CreatedAt:  time.Now(),
			LastSeen:   time.Now(),
			Protocol:   "udp",
		})
	}

	// 记录入口指标（外部 -> 服务端）
	s.metrics.recordUDPInbound(udpListener.Tunnel, len(data))

	payload := data
	if client.EncryptionEnabled {
		encrypted, err := secure.EncryptBytes(data, client.EncryptionKey)
		if err != nil {
			log.Printf("[Server] Failed to encrypt UDP payload: %v", err)
			return
		}
		payload = encrypted
	}

	// 根据udp_mode选择传输方式
	// 计算编码后的数据包大小，检查是否超过MTU
	pktData := protocol.EncodeNativeUDPDataPacket(
		udpListener.Tunnel.ServerPort,
		udpListener.Tunnel.ClientPort,
		remoteAddrStr,
		payload,
	)
	useNativeUDP := udpMode == protocol.UDPModeNative && s.nativeUDPConn != nil && clientUDPAddr != nil
	// 如果数据包超过安全MTU大小，自动回退到TCP传输
	if useNativeUDP && len(pktData) > protocol.UDPSafeMTU {
		useNativeUDP = false
	}

	if useNativeUDP {
		// 原生UDP传输：直接通过UDP发送给客户端（使用带类型前缀的数据包）
		_, err := s.nativeUDPConn.WriteToUDP(pktData, clientUDPAddr)
		if err != nil {
			// 发送失败时也回退到TCP
			useNativeUDP = false
		}
	}

	if !useNativeUDP {
		// TCP封装传输（备用方法或MTU超限回退）：通过控制流发送UDP数据
		msg, err := protocol.NewUDPDataMessage(
			udpListener.Tunnel.Name,
			udpListener.Tunnel.ClientPort,
			remoteAddrStr,
			payload,
		)
		if err != nil {
			log.Printf("[Server] Failed to create UDP data message: %v", err)
			return
		}

		if !client.SendControl(msg) {
			log.Printf("[Server] Failed to send UDP data to client: control stream error")
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

	payload := udm.Data
	if client.EncryptionEnabled {
		plain, err := secure.DecryptBytes(udm.Data, client.EncryptionKey)
		if err != nil {
			log.Printf("[Server] Failed to decrypt UDP payload: %v", err)
			return
		}
		payload = plain
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
	udpListener.mu.Lock()
	entry, exists := udpListener.remoteAddrs[udm.RemoteAddr]
	if exists {
		entry.LastSeen = time.Now()
	}
	udpListener.mu.Unlock()

	if !exists {
		log.Printf("[Server] Remote address not found: %s", udm.RemoteAddr)
		return
	}

	s.updateConnectionLastSeen(entry.ConnID)

	// 发送UDP响应
	_, err = udpListener.Conn.WriteToUDP(payload, entry.Addr)
	if err != nil {
		log.Printf("[Server] Failed to send UDP response: %v", err)
	} else {
		// 该数据通过TCP回退通道抵达，视为一次回退发送
		s.metrics.recordUDPOutbound(udpListener.Tunnel, len(payload), true)
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
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取认证消息
	msg, err := protocol.DecodeMessage(conn)
	if err != nil {
		log.Printf("[Server] Failed to read auth message: %v", err)
		conn.Close()
		return
	}

	if msg.Type != protocol.MsgTypeAuth {
		log.Printf("[Server] Expected auth message, got type %d", msg.Type)
		s.sendError(conn, 1, "Expected authentication message")
		conn.Close()
		return
	}

	// 解析认证请求
	authReq, err := protocol.ParseAuthRequest(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse auth request: %v", err)
		s.sendError(conn, 2, "Invalid authentication request")
		conn.Close()
		return
	}

	// 验证密钥
	clientConfig := s.findClientConfig(authReq.ClientName)
	if clientConfig == nil {
		log.Printf("[Server] Unknown client: %s", authReq.ClientName)
		s.sendAuthResponse(conn, false, "Unknown client", "", false)
		conn.Close()
		return
	}

	// 检查密钥
	expectedKey := clientConfig.SecretKey
	if expectedKey == "" {
		expectedKey = s.config.Server.SecretKey
	}

	if authReq.SecretKey != expectedKey {
		log.Printf("[Server] Invalid secret key from client: %s", authReq.ClientName)
		s.sendAuthResponse(conn, false, "Invalid secret key", "", false)
		conn.Close()
		return
	}

	// 生成客户端ID
	clientID := fmt.Sprintf("%s-%d", authReq.ClientName, time.Now().UnixNano())

	// 清除读取超时
	conn.SetReadDeadline(time.Time{})

	log.Printf("[Server] Client authenticated: %s (ID: %s)", authReq.ClientName, clientID)

	encryptionEnabled := s.config.Server.Encryption.Enabled

	// 发送认证成功响应
	if err := s.sendAuthResponse(conn, true, "Authentication successful", clientID, encryptionEnabled); err != nil {
		log.Printf("[Server] Failed to send auth response: %v", err)
		conn.Close()
		return
	}

	// 发送隧道配置
	if err := s.sendTunnelConfig(conn, clientConfig.Tunnels); err != nil {
		log.Printf("[Server] Failed to send tunnel config: %v", err)
		conn.Close()
		return
	}

	// 创建yamux服务端会话（服务端作为yamux服务端）
	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.AcceptBacklog = 256
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 30 * time.Second
	yamuxConfig.ConnectionWriteTimeout = 30 * time.Second
	yamuxConfig.StreamOpenTimeout = 30 * time.Second
	yamuxConfig.StreamCloseTimeout = 5 * time.Minute
	yamuxConfig.MaxStreamWindowSize = 16 * 1024 * 1024 // 16MB窗口大小，支持高带宽

	session, err := yamux.Server(conn, yamuxConfig)
	if err != nil {
		log.Printf("[Server] Failed to create yamux session: %v", err)
		conn.Close()
		return
	}

	// 接受客户端打开的控制流
	controlStream, err := session.Accept()
	if err != nil {
		log.Printf("[Server] Failed to accept control stream: %v", err)
		session.Close()
		return
	}

	encryptionKey := secure.DeriveKey(expectedKey)

	// 创建客户端连接记录
	clientConn := &ClientConn{
		ID:                clientID,
		Name:              authReq.ClientName,
		Conn:              conn,
		Session:           session,
		ControlStream:     controlStream,
		Tunnels:           clientConfig.Tunnels,
		ConnectedAt:       time.Now(),
		LastHeartbeat:     time.Now(),
		EncryptionEnabled: encryptionEnabled,
		EncryptionKey:     encryptionKey,
	}

	// 注册客户端
	s.mu.Lock()
	// 断开同名的旧连接
	if oldClient, exists := s.clientsByName[authReq.ClientName]; exists {
		log.Printf("[Server] Disconnecting old connection for client: %s", authReq.ClientName)
		oldClient.Close()
		delete(s.clients, oldClient.ID)
	}
	s.clients[clientID] = clientConn
	s.clientsByName[authReq.ClientName] = clientConn
	s.mu.Unlock()

	log.Printf("[Server] Client yamux session established: %s", authReq.ClientName)

	// 处理控制流消息（心跳等）
	s.handleControlStream(clientConn)

	// 清理客户端
	clientConn.Close()
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
func (s *Server) sendAuthResponse(conn net.Conn, success bool, message, clientID string, encryptionEnabled bool) error {
	msg, err := protocol.NewAuthResponse(success, message, clientID, encryptionEnabled)
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

// handleControlStream 处理控制流消息（心跳、UDP数据等）
func (s *Server) handleControlStream(client *ClientConn) {
	for s.running {
		msg, err := protocol.DecodeMessage(client.ControlStream)
		if err != nil {
			log.Printf("[Server] Failed to read control message from client %s: %v", client.Name, err)
			return
		}

		switch msg.Type {
		case protocol.MsgTypeHeartbeat:
			s.handleHeartbeat(client, msg)
		case protocol.MsgTypeUDPData:
			s.handleUDPDataFromClient(client, msg)
		case protocol.MsgTypeClientError:
			s.handleClientError(client, msg)
		default:
			log.Printf("[Server] Unknown control message type from client %s: %d", client.Name, msg.Type)
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
	client.SendControl(ackMsg)
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

// handleTunnelConnection 处理隧道连接（使用yamux stream）
func (s *Server) handleTunnelConnection(conn net.Conn, tunnel protocol.Tunnel, clientName string) {
	defer conn.Close()

	// 查找客户端
	s.mu.RLock()
	client, exists := s.clientsByName[clientName]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[Server] Client not connected: %s", clientName)
		return
	}

	// 生成连接ID（使用原子计数器确保唯一性）
	connID := fmt.Sprintf("conn-%d-%d", time.Now().Unix(), s.connIDCounter.Add(1))

	log.Printf("[Server] New connection %s: %s -> tunnel %s", connID, conn.RemoteAddr().String(), tunnel.Name)

	// 打开一个新的yamux stream用于此连接
	stream, err := client.OpenStream()
	if err != nil {
		log.Printf("[Server] Failed to open stream for connection %s: %v", connID, err)
		return
	}
	defer stream.Close()

	// 发送连接信息到客户端
	msg, err := protocol.NewConnectionMessage(connID, tunnel.Name, tunnel.ClientPort, conn.RemoteAddr().String(), tunnel.TargetIP)
	if err != nil {
		log.Printf("[Server] Failed to create new connection message: %v", err)
		return
	}

	if err := protocol.SendMessage(stream, msg); err != nil {
		log.Printf("[Server] Failed to send new connection message: %v", err)
		return
	}

	// 等待客户端就绪响应
	readyMsg, err := protocol.DecodeMessage(stream)
	if err != nil {
		log.Printf("[Server] Failed to receive ready message for %s: %v", connID, err)
		return
	}

	if readyMsg.Type != protocol.MsgTypeConnReady {
		log.Printf("[Server] Expected conn ready message, got type %d", readyMsg.Type)
		return
	}

	cr, err := protocol.ParseConnReady(readyMsg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse conn ready: %v", err)
		return
	}

	if !cr.Success {
		log.Printf("[Server] Client failed to connect to local service: %s", cr.Message)
		return
	}

	log.Printf("[Server] Connection established: %s", connID)

	// 在数据转发前包装加密流（可选）
	securedStream := stream
	if client.EncryptionEnabled {
		wrapped, err := secure.WrapConn(stream, client.EncryptionKey)
		if err != nil {
			log.Printf("[Server] Failed to enable encryption for %s: %v", connID, err)
			return
		}
		securedStream = wrapped
	}

	// 注册活跃连接，便于Web查看
	s.addConnection(&ProxyConn{
		ID:           connID,
		ClientID:     client.ID,
		TunnelName:   tunnel.Name,
		ClientPort:   tunnel.ClientPort,
		ServerPort:   tunnel.ServerPort,
		Tunnel:       tunnel,
		ExternalConn: conn,
		RemoteAddr:   conn.RemoteAddr().String(),
		CreatedAt:    time.Now(),
		LastSeen:     time.Now(),
		Protocol:     "tcp",
	})
	defer s.removeConnection(connID)

	// 双向数据转发（使用io.Copy，高效且不会阻塞其他连接）
	done := make(chan struct{}, 2)

	// 从外部连接读取数据，写入stream
	go func() {
		n, _ := io.Copy(securedStream, conn)
		// 记录TCP入站流量
		s.metrics.recordTCPInbound(tunnel, int(n))
		// 关闭stream的写端
		securedStream.Close()
		done <- struct{}{}
	}()

	// 从stream读取数据，写入外部连接
	go func() {
		n, _ := io.Copy(conn, securedStream)
		// 记录TCP出站流量
		s.metrics.recordTCPOutbound(tunnel, int(n))
		// 关闭外部连接的写端
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- struct{}{}
	}()

	// 等待双向传输完成
	<-done
	<-done

	log.Printf("[Server] Connection closed: %s", connID)
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

	// 发送停止信号
	select {
	case <-s.stopChan:
		// 已经关闭
	default:
		close(s.stopChan)
	}

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

	// 关闭所有UDP监听器（同时会停止清理goroutine）
	for _, udpListener := range s.udpListeners {
		// 发送停止清理信号
		select {
		case <-udpListener.stopCleanup:
		default:
			close(udpListener.stopCleanup)
		}
		udpListener.Conn.Close()
	}
	s.udpListeners = make(map[int]*UDPListener)

	// 关闭所有客户端连接
	for _, client := range s.clients {
		client.Close()
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

	// 重新创建stopChan用于下次启动
	s.stopChan = make(chan struct{})
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

// Metrics 运行时观测指标
type Metrics struct {
	startTime     time.Time
	udpPacketsIn  atomic.Uint64
	udpPacketsOut atomic.Uint64
	udpBytesIn    atomic.Uint64
	udpBytesOut   atomic.Uint64
	udpFallbacks  atomic.Uint64
	tcpPacketsIn  atomic.Uint64
	tcpPacketsOut atomic.Uint64
	tcpBytesIn    atomic.Uint64
	tcpBytesOut   atomic.Uint64
	lastPacketAt  atomic.Int64

	tunnelMu sync.RWMutex
	tunnels  map[string]*TunnelMetrics
}

// TunnelMetrics 单隧道维度指标
type TunnelMetrics struct {
	TunnelName string
	Protocol   string
	ServerPort int
	ClientPort int

	udpPacketsIn  atomic.Uint64
	udpPacketsOut atomic.Uint64
	udpBytesIn    atomic.Uint64
	udpBytesOut   atomic.Uint64
	udpFallbacks  atomic.Uint64
	tcpPacketsIn  atomic.Uint64
	tcpPacketsOut atomic.Uint64
	tcpBytesIn    atomic.Uint64
	tcpBytesOut   atomic.Uint64
	lastPacketAt  atomic.Int64
}

// MetricsSnapshot 可序列化的指标快照
type MetricsSnapshot struct {
	StartTime     time.Time               `json:"start_time"`
	UDPPacketsIn  uint64                  `json:"udp_packets_in"`
	UDPPacketsOut uint64                  `json:"udp_packets_out"`
	UDPBytesIn    uint64                  `json:"udp_bytes_in"`
	UDPBytesOut   uint64                  `json:"udp_bytes_out"`
	UDPFallbacks  uint64                  `json:"udp_fallbacks"`
	TCPPacketsIn  uint64                  `json:"tcp_packets_in"`
	TCPPacketsOut uint64                  `json:"tcp_packets_out"`
	TCPBytesIn    uint64                  `json:"tcp_bytes_in"`
	TCPBytesOut   uint64                  `json:"tcp_bytes_out"`
	LastPacketAt  time.Time               `json:"last_packet_at"`
	Tunnels       []TunnelMetricsSnapshot `json:"tunnels"`
}

// TunnelMetricsSnapshot 单隧道指标快照
type TunnelMetricsSnapshot struct {
	TunnelName    string    `json:"tunnel_name"`
	Protocol      string    `json:"protocol"`
	ServerPort    int       `json:"server_port"`
	ClientPort    int       `json:"client_port"`
	UDPPacketsIn  uint64    `json:"udp_packets_in"`
	UDPPacketsOut uint64    `json:"udp_packets_out"`
	UDPBytesIn    uint64    `json:"udp_bytes_in"`
	UDPBytesOut   uint64    `json:"udp_bytes_out"`
	UDPFallbacks  uint64    `json:"udp_fallbacks"`
	TCPPacketsIn  uint64    `json:"tcp_packets_in"`
	TCPPacketsOut uint64    `json:"tcp_packets_out"`
	TCPBytesIn    uint64    `json:"tcp_bytes_in"`
	TCPBytesOut   uint64    `json:"tcp_bytes_out"`
	LastPacketAt  time.Time `json:"last_packet_at"`
}

func newMetrics() *Metrics {
	return &Metrics{
		startTime: time.Now(),
		tunnels:   make(map[string]*TunnelMetrics),
	}
}

func (m *Metrics) getTunnelMetrics(tunnel protocol.Tunnel) *TunnelMetrics {
	m.tunnelMu.RLock()
	if tm, ok := m.tunnels[tunnel.Name]; ok {
		m.tunnelMu.RUnlock()
		return tm
	}
	m.tunnelMu.RUnlock()

	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	if tm, ok := m.tunnels[tunnel.Name]; ok {
		return tm
	}
	tm := &TunnelMetrics{
		TunnelName: tunnel.Name,
		Protocol:   tunnel.Protocol,
		ServerPort: tunnel.ServerPort,
		ClientPort: tunnel.ClientPort,
	}
	m.tunnels[tunnel.Name] = tm
	return tm
}

func (m *Metrics) recordUDPInbound(tunnel protocol.Tunnel, size int) {
	m.udpPacketsIn.Add(1)
	m.udpBytesIn.Add(uint64(size))
	m.updateLastPacket(nil)
	tm := m.getTunnelMetrics(tunnel)
	tm.udpPacketsIn.Add(1)
	tm.udpBytesIn.Add(uint64(size))
	m.updateLastPacket(tm)
}

func (m *Metrics) recordUDPOutbound(tunnel protocol.Tunnel, size int, fallback bool) {
	m.udpPacketsOut.Add(1)
	m.udpBytesOut.Add(uint64(size))
	if fallback {
		m.udpFallbacks.Add(1)
	}
	m.updateLastPacket(nil)
	tm := m.getTunnelMetrics(tunnel)
	tm.udpPacketsOut.Add(1)
	tm.udpBytesOut.Add(uint64(size))
	if fallback {
		tm.udpFallbacks.Add(1)
	}
	m.updateLastPacket(tm)
}

func (m *Metrics) recordTCPInbound(tunnel protocol.Tunnel, size int) {
	m.tcpPacketsIn.Add(1)
	m.tcpBytesIn.Add(uint64(size))
	m.updateLastPacket(nil)
	tm := m.getTunnelMetrics(tunnel)
	tm.tcpPacketsIn.Add(1)
	tm.tcpBytesIn.Add(uint64(size))
	m.updateLastPacket(tm)
}

func (m *Metrics) recordTCPOutbound(tunnel protocol.Tunnel, size int) {
	m.tcpPacketsOut.Add(1)
	m.tcpBytesOut.Add(uint64(size))
	m.updateLastPacket(nil)
	tm := m.getTunnelMetrics(tunnel)
	tm.tcpPacketsOut.Add(1)
	tm.tcpBytesOut.Add(uint64(size))
	m.updateLastPacket(tm)
}

func (m *Metrics) updateLastPacket(tm *TunnelMetrics) {
	now := time.Now().UnixNano()
	m.lastPacketAt.Store(now)
	if tm != nil {
		tm.lastPacketAt.Store(now)
	}
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	lastPkt := m.lastPacketAt.Load()
	snap := MetricsSnapshot{
		StartTime:     m.startTime,
		UDPPacketsIn:  m.udpPacketsIn.Load(),
		UDPPacketsOut: m.udpPacketsOut.Load(),
		UDPBytesIn:    m.udpBytesIn.Load(),
		UDPBytesOut:   m.udpBytesOut.Load(),
		UDPFallbacks:  m.udpFallbacks.Load(),
		TCPPacketsIn:  m.tcpPacketsIn.Load(),
		TCPPacketsOut: m.tcpPacketsOut.Load(),
		TCPBytesIn:    m.tcpBytesIn.Load(),
		TCPBytesOut:   m.tcpBytesOut.Load(),
	}
	if lastPkt > 0 {
		snap.LastPacketAt = time.Unix(0, lastPkt)
	}

	m.tunnelMu.RLock()
	snap.Tunnels = make([]TunnelMetricsSnapshot, 0, len(m.tunnels))
	for _, tm := range m.tunnels {
		tLast := tm.lastPacketAt.Load()
		snap.Tunnels = append(snap.Tunnels, TunnelMetricsSnapshot{
			TunnelName:    tm.TunnelName,
			Protocol:      tm.Protocol,
			ServerPort:    tm.ServerPort,
			ClientPort:    tm.ClientPort,
			UDPPacketsIn:  tm.udpPacketsIn.Load(),
			UDPPacketsOut: tm.udpPacketsOut.Load(),
			UDPBytesIn:    tm.udpBytesIn.Load(),
			UDPBytesOut:   tm.udpBytesOut.Load(),
			UDPFallbacks:  tm.udpFallbacks.Load(),
			TCPPacketsIn:  tm.tcpPacketsIn.Load(),
			TCPPacketsOut: tm.tcpPacketsOut.Load(),
			TCPBytesIn:    tm.tcpBytesIn.Load(),
			TCPBytesOut:   tm.tcpBytesOut.Load(),
			LastPacketAt:  time.Unix(0, tLast),
		})
	}
	m.tunnelMu.RUnlock()

	return snap
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

// GetMetrics 获取运行时指标快照
func (s *Server) GetMetrics() MetricsSnapshot {
	if s.metrics == nil {
		return MetricsSnapshot{}
	}
	return s.metrics.Snapshot()
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

// handleClientError 处理客户端错误上报
func (s *Server) handleClientError(client *ClientConn, msg *protocol.Message) {
	cer, err := protocol.ParseClientErrorReport(msg.Payload)
	if err != nil {
		log.Printf("[Server] Failed to parse client error report: %v", err)
		return
	}

	// 记录到日志
	logMsg := fmt.Sprintf("[%s] %s", cer.ErrorType, cer.Message)
	log.Printf("[Server] Client error from %s: %s", cer.ClientName, logMsg)

	// 添加到日志列表
	s.AddLog("error", "client", cer.ClientName, cer.ErrorType, cer.Message)
}

// AddLog 添加日志记录（同时输出到控制台）
func (s *Server) AddLog(level, source, clientName, logType, message string) {
	// 输出到控制台（这会同时被 LogWriter 捕获并收集）
	log.Printf("[%s] %s", source, message)
}

// GetLogs 获取日志列表
func (s *Server) GetLogs(limit int) []LogEntry {
	s.logMu.RLock()
	defer s.logMu.RUnlock()

	if limit <= 0 || limit > len(s.logs) {
		limit = len(s.logs)
	}

	// 返回最新的日志（倒序）
	result := make([]LogEntry, limit)
	start := len(s.logs) - limit
	for i := 0; i < limit; i++ {
		result[i] = s.logs[start+limit-1-i]
	}
	return result
}

// HasRecentErrors 检查最近指定秒数内是否有ERROR日志
func (s *Server) HasRecentErrors(seconds int) bool {
	s.logMu.RLock()
	defer s.logMu.RUnlock()

	cutoffTime := time.Now().Add(-time.Duration(seconds) * time.Second)

	// 从最新的日志开始检查（因为日志是按时间顺序存储的）
	for i := len(s.logs) - 1; i >= 0; i-- {
		log := s.logs[i]
		// 如果日志时间早于截止时间，后面的更早，可以停止检查
		if log.Time.Before(cutoffTime) {
			break
		}
		// 检查是否是ERROR级别
		if log.Level == "ERROR" {
			return true
		}
	}
	return false
}

// HasDisconnectedClients 检查是否有已配置但未连接的客户端
func (s *Server) HasDisconnectedClients() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 获取配置的客户端数量
	if s.config == nil {
		return false
	}

	// 检查每个配置的客户端是否已连接
	for _, configClient := range s.config.Clients {
		// 检查该客户端是否在已连接的客户端列表中
		if _, exists := s.clientsByName[configClient.Name]; !exists {
			return true
		}
	}
	return false
}
