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

	"xpenetration/internal/config"
	"xpenetration/internal/protocol"
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
}

// ClientConn 客户端连接信息
type ClientConn struct {
	ID            string
	Name          string
	Conn          net.Conn
	Tunnels       []protocol.Tunnel
	ConnectedAt   time.Time
	LastHeartbeat time.Time
	controlQueue  chan *protocol.Message // 控制消息队列（优先）
	dataQueue     chan *protocol.Message // 数据消息队列
	sendDone      chan struct{}          // 发送协程退出信号
	mu            sync.Mutex             // 用于一般操作
}

// sendLoop 发送循环，优先发送控制消息，再发送数据消息
func (c *ClientConn) sendLoop() {
	for {
		// 优先处理控制消息
		select {
		case msg, ok := <-c.controlQueue:
			if !ok {
				c.controlQueue = nil
				goto checkExit
			}
			if err := protocol.SendMessage(c.Conn, msg); err != nil {
				log.Printf("[Server] Failed to send control message to client %s: %v", c.Name, err)
				goto exit
			}
			continue
		default:
		}

		// 没有控制消息，处理数据消息
		select {
		case msg, ok := <-c.controlQueue:
			if ok {
				if err := protocol.SendMessage(c.Conn, msg); err != nil {
					log.Printf("[Server] Failed to send control message to client %s: %v", c.Name, err)
					goto exit
				}
				continue
			}
			c.controlQueue = nil
		case msg, ok := <-c.dataQueue:
			if ok {
				if err := protocol.SendMessage(c.Conn, msg); err != nil {
					log.Printf("[Server] Failed to send data message to client %s: %v", c.Name, err)
					goto exit
				}
				continue
			}
			c.dataQueue = nil
		}

	checkExit:
		if c.controlQueue == nil && c.dataQueue == nil {
			break
		}
	}

exit:
	close(c.sendDone)
}

// SendControl 同步发送控制消息（关键消息），若已关闭返回false
func (c *ClientConn) SendControl(msg *protocol.Message) bool {
	select {
	case c.controlQueue <- msg:
		return true
	case <-c.sendDone:
		return false
	}
}

// SendData 异步发送数据消息，队列满则返回false并丢弃
func (c *ClientConn) SendData(msg *protocol.Message) bool {
	select {
	case c.dataQueue <- msg:
		return true
	default:
		return false
	}
}

// SendDataWithTimeout 尝试在超时时间内发送数据消息，避免瞬时队列满导致断连
func (c *ClientConn) SendDataWithTimeout(msg *protocol.Message, timeout time.Duration) bool {
	if timeout <= 0 {
		return c.SendData(msg)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case c.dataQueue <- msg:
		return true
	case <-c.sendDone:
		return false
	case <-timer.C:
		return false
	}
}

// Close 关闭客户端连接
func (c *ClientConn) Close() {
	c.Conn.Close()
	// 关闭发送队列以结束 sendLoop
	select {
	case <-c.sendDone:
		// 已经关闭
	default:
		if c.controlQueue != nil {
			close(c.controlQueue)
		}
		if c.dataQueue != nil {
			close(c.dataQueue)
		}
		<-c.sendDone
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
		udpListener, exists := s.udpListeners[pkt.ServerPort]
		s.mu.RUnlock()

		if !exists {
			log.Printf("[Server] UDP listener not found for server port: %d", pkt.ServerPort)
			return
		}

		// 更新客户端的UDP地址（用于发送响应）
		s.mu.Lock()
		s.clientUDPAddrs[udpListener.ClientName] = clientUDPAddr
		s.mu.Unlock()

		// 查找原始请求的远程地址
		udpListener.mu.RLock()
		entry, exists := udpListener.remoteAddrs[pkt.RemoteAddr]
		udpListener.mu.RUnlock()

		if !exists {
			log.Printf("[Server] Remote address not found: %s", pkt.RemoteAddr)
			return
		}

		// 发送响应给外部客户端
		_, err = udpListener.Conn.WriteToUDP(pkt.Data, entry.Addr)
		if err != nil {
			log.Printf("[Server] Failed to send UDP response to external client: %v", err)
		} else {
			s.metrics.recordUDPOutbound(udpListener.Tunnel, len(pkt.Data), false)
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
			udpListener.mu.Lock()
			for addr, entry := range udpListener.remoteAddrs {
				if now.Sub(entry.LastSeen) > protocol.UDPRemoteAddrExpiry {
					delete(udpListener.remoteAddrs, addr)
				}
			}
			udpListener.mu.Unlock()
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
	udpListener.mu.Lock()
	udpListener.remoteAddrs[remoteAddrStr] = &UDPRemoteAddrEntry{
		Addr:     remoteAddr,
		LastSeen: time.Now(),
	}
	udpListener.mu.Unlock()

	// 记录入口指标（外部 -> 服务端）
	s.metrics.recordUDPInbound(udpListener.Tunnel, len(data))

	// 查找客户端
	s.mu.RLock()
	client, exists := s.clientsByName[udpListener.ClientName]
	clientUDPAddr := s.clientUDPAddrs[udpListener.ClientName]
	s.mu.RUnlock()

	if !exists {
		log.Printf("[Server] UDP: Client not connected: %s", udpListener.ClientName)
		return
	}

	// 根据udp_mode选择传输方式
	// 计算编码后的数据包大小，检查是否超过MTU
	pktData := protocol.EncodeNativeUDPDataPacket(
		udpListener.Tunnel.ServerPort,
		udpListener.Tunnel.ClientPort,
		remoteAddrStr,
		data,
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
		// TCP封装传输（备用方法或MTU超限回退）：通过TCP控制通道发送UDP数据
		msg, err := protocol.NewUDPDataMessage(
			udpListener.Tunnel.Name,
			udpListener.Tunnel.ClientPort,
			remoteAddrStr,
			data,
		)
		if err != nil {
			log.Printf("[Server] Failed to create UDP data message: %v", err)
			return
		}

		if !client.SendDataWithTimeout(msg, 200*time.Millisecond) {
			log.Printf("[Server] Failed to send UDP data to client: queue congested")
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
	entry, exists := udpListener.remoteAddrs[udm.RemoteAddr]
	udpListener.mu.RUnlock()

	if !exists {
		log.Printf("[Server] Remote address not found: %s", udm.RemoteAddr)
		return
	}

	// 发送UDP响应
	_, err = udpListener.Conn.WriteToUDP(udm.Data, entry.Addr)
	if err != nil {
		log.Printf("[Server] Failed to send UDP response: %v", err)
	} else {
		// 该数据通过TCP回退通道抵达，视为一次回退发送
		s.metrics.recordUDPOutbound(udpListener.Tunnel, len(udm.Data), true)
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
		controlQueue:  make(chan *protocol.Message, 128),  // 控制消息小队列，优先级高
		dataQueue:     make(chan *protocol.Message, 4096), // 数据消息大队列
		sendDone:      make(chan struct{}),
	}

	// 启动发送协程
	go clientConn.sendLoop()

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
		case protocol.MsgTypeClientError:
			s.handleClientError(client, msg)
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
	client.SendControl(ackMsg)
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
		return
	}

	// 记录TCP出站（内网->外部）
	s.metrics.recordTCPOutbound(proxyConn.Tunnel, len(dm.Data))
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

	// 生成连接ID（使用原子计数器确保唯一性）
	connID := fmt.Sprintf("conn-%d-%d", time.Now().Unix(), s.connIDCounter.Add(1))

	// 创建代理连接记录
	proxyConn := &ProxyConn{
		ID:           connID,
		ClientID:     client.ID,
		TunnelName:   tunnel.Name,
		ClientPort:   tunnel.ClientPort,
		ServerPort:   tunnel.ServerPort,
		Tunnel:       tunnel,
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
	msg, err := protocol.NewConnectionMessage(connID, tunnel.Name, tunnel.ClientPort, conn.RemoteAddr().String(), tunnel.TargetIP)
	if err != nil {
		log.Printf("[Server] Failed to create new connection message: %v", err)
		conn.Close()
		return
	}

	if !client.SendControl(msg) {
		log.Printf("[Server] Failed to send new connection message: client disconnected")
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
		client.SendControl(msg)
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

		if !client.SendDataWithTimeout(msg, 500*time.Millisecond) {
			// 队列持续拥堵，客户端处理不过来，断开连接
			log.Printf("[Server] Send queue congested for connection %s, closing", proxyConn.ID)
			return
		}

		// 记录TCP入站（外部->内网）
		s.metrics.recordTCPInbound(proxyConn.Tunnel, n)
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
