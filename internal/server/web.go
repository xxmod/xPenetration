package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xpenetration/internal/config"
)

// acmeProvider is implemented in build-tagged files to optionally include ACME support.
// In non-ACME builds, a stub keeps the server/web UI functional without the ACME module.
type acmeProvider interface {
	registerRoutes(mux *http.ServeMux)
	init(cfg *config.ServerConfig)
	stop()
}

//go:embed web/*
var webFS embed.FS

// WebServer Web管理服务
type WebServer struct {
	server     *Server
	addr       string
	mux        *http.ServeMux
	configPath string
	mu         sync.Mutex
	httpServer *http.Server
	redirect   *http.Server
	listener   net.Listener
	acme       acmeProvider
}

// NewWebServer 创建Web服务器
func NewWebServer(server *Server, addr string, configPath string) *WebServer {
	ws := &WebServer{
		server:     server,
		addr:       addr,
		mux:        http.NewServeMux(),
		configPath: configPath,
	}
	ws.acme = newACMEProvider(ws)
	ws.setupRoutes()
	return ws
}

// setupRoutes 设置路由
func (ws *WebServer) setupRoutes() {
	// API路由
	ws.mux.HandleFunc("/api/stats", ws.handleStats)
	ws.mux.HandleFunc("/api/clients", ws.handleClients)
	ws.mux.HandleFunc("/api/connections", ws.handleConnections)
	ws.mux.HandleFunc("/api/metrics", ws.handleMetrics)
	ws.mux.HandleFunc("/api/health", ws.handleHealth)
	ws.mux.HandleFunc("/api/config", ws.handleConfig)
	ws.mux.HandleFunc("/api/webtls/upload/cert", ws.handleUploadCert)
	ws.mux.HandleFunc("/api/webtls/upload/key", ws.handleUploadKey)
	ws.mux.HandleFunc("/api/logs", ws.handleLogs)
	ws.acme.registerRoutes(ws.mux)
	// 兼容 /status 与 /status/（部分监控探针不一定带尾部斜杠）
	ws.mux.HandleFunc("/status", ws.handleStatus)
	ws.mux.HandleFunc("/status/", ws.handleStatus)

	// 静态文件（前端）
	// 从 embed.FS 中获取 web 子目录
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("Failed to create sub FS: %v", err)
	}

	fileServer := http.FileServer(http.FS(subFS))
	ws.mux.Handle("/", fileServer)
}

// Start 启动Web服务器
func (ws *WebServer) Start() error {
	cfg := ws.server.GetConfig()
	ws.acme.init(cfg)
	return ws.startWithConfig(cfg)
}

// corsMiddleware CORS中间件
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// basicAuthMiddleware Basic Auth认证中间件
func (ws *WebServer) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /status/ 路径豁免认证
		if strings.HasPrefix(r.URL.Path, "/status/") || r.URL.Path == "/status" {
			next.ServeHTTP(w, r)
			return
		}

		// 获取当前配置的认证信息
		cfg := ws.server.GetConfig()
		if cfg == nil || cfg.Server.WebAuth == nil || cfg.Server.WebAuth.Username == "" {
			// 未配置认证，直接放行
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != cfg.Server.WebAuth.Username || pass != cfg.Server.WebAuth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="xPenetration Admin"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleStats 处理统计信息请求
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := ws.server.GetStats()
	ws.writeJSON(w, stats)
}

// handleMetrics 处理运行时指标请求
func (ws *WebServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := ws.server.GetMetrics()
	ws.writeJSON(w, metrics)
}

// handleClients 处理客户端列表请求
func (ws *WebServer) handleClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients := ws.server.GetClients()
	ws.writeJSON(w, clients)
}

// handleConnections 处理连接列表请求
func (ws *WebServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	connections := ws.server.GetConnections()
	ws.writeJSON(w, connections)
}

// handleHealth 健康检查
func (ws *WebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ws.writeJSON(w, map[string]string{"status": "ok"})
}

// handleConfig 处理配置请求
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if r.Method == "GET" {
		// 获取当前配置
		cfg := ws.server.GetConfig()
		ws.writeJSON(w, cfg)
		return
	}

	if r.Method == "POST" {
		// 保存新配置
		var newConfig config.ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "Invalid config format", http.StatusBadRequest)
			return
		}

		// 验证配置合法性
		if validationErrors := config.ValidateServerConfig(&newConfig); len(validationErrors) > 0 {
			log.Printf("[WebServer] Config validation failed: %v", validationErrors)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "配置验证失败",
				"errors":  validationErrors,
			})
			return
		}

		// 检查端口是否被系统其他程序占用
		currentCfg := ws.server.GetConfig()
		if portConflicts := config.CheckPortsAvailability(&newConfig, currentCfg); len(portConflicts) > 0 {
			log.Printf("[WebServer] Port availability check failed: %v", portConflicts)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "端口被占用",
				"errors":  portConflicts,
			})
			return
		}

		// 保存到文件
		if err := config.SaveServerConfig(ws.configPath, &newConfig); err != nil {
			log.Printf("[WebServer] Failed to save config: %v", err)
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		log.Printf("[WebServer] Config saved to %s", ws.configPath)

		// 重载服务核心
		go func() {
			if err := ws.server.Reload(&newConfig); err != nil {
				log.Printf("[WebServer] Failed to reload server: %v", err)
			}
		}()

		// 重启 Web 服务以应用新的端口/TLS 设置
		go ws.Restart(&newConfig)

		ws.writeJSON(w, map[string]string{"status": "ok", "message": "Config saved and server reloading"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleUploadCert 处理证书上传（.cer/.crt）
func (ws *WebServer) handleUploadCert(w http.ResponseWriter, r *http.Request) {
	ws.handleUploadFile(w, r, []string{".cer", ".crt"}, "webui-cert")
}

// handleUploadKey 处理私钥上传（.key）
func (ws *WebServer) handleUploadKey(w http.ResponseWriter, r *http.Request) {
	ws.handleUploadFile(w, r, []string{".key"}, "webui-key")
}

func (ws *WebServer) handleUploadFile(w http.ResponseWriter, r *http.Request, allowedExt []string, targetBase string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB limit
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File not found", http.StatusBadRequest)
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowed := false
	for _, e := range allowedExt {
		if ext == e {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "Unsupported file type", http.StatusBadRequest)
		return
	}

	destDir := filepath.Dir(ws.configPath)
	if destDir == "" || destDir == "." {
		destDir = "."
	}
	targetName := targetBase + ext
	destPath := filepath.Join(destDir, targetName)

	ws.mu.Lock()
	defer ws.mu.Unlock()
	out, err := os.Create(destPath)
	if err != nil {
		log.Printf("[WebServer] Failed to create file %s: %v", destPath, err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		log.Printf("[WebServer] Failed to save file %s: %v", destPath, err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	if err := out.Close(); err != nil {
		log.Printf("[WebServer] Failed to close file %s: %v", destPath, err)
	}

	log.Printf("[WebServer] Uploaded %s to %s", header.Filename, destPath)
	ws.writeJSON(w, map[string]string{
		"path": destPath,
		"name": header.Filename,
	})
}

// 停止并按新配置重启 Web 服务（用于端口/TLS 切换）
func (ws *WebServer) Restart(cfg *config.ServerConfig) {
	ws.Stop()
	go func() {
		if err := ws.startWithConfig(cfg); err != nil {
			log.Printf("[WebServer] Failed to restart: %v", err)
		}
	}()
}

// 关闭当前 Web 服务
func (ws *WebServer) Stop() {
	ws.mu.Lock()
	srv := ws.httpServer
	redir := ws.redirect
	ln := ws.listener
	ws.httpServer = nil
	ws.redirect = nil
	ws.listener = nil
	ws.mu.Unlock()

	ws.acme.stop()

	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		log.Printf("[WebServer] Shutdown error: %v", err)
	}
	if redir != nil {
		redir.Shutdown(ctx)
	}
	if ln != nil {
		ln.Close()
	}
}

// startWithConfig 根据给定配置启动 Web 服务（阻塞直到关闭）
func (ws *WebServer) startWithConfig(cfg *config.ServerConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.Server.ListenAddr == "0.0.0.0" {
		if cfg.Server.WebAuth == nil || cfg.Server.WebAuth.Username == "" || cfg.Server.WebAuth.Password == "" {
			log.Printf("[WebServer] Warning: Web UI is exposed on 0.0.0.0 without web_auth; configure web_auth or set listen_addr=127.0.0.1")
		}
	}
	handler := ws.basicAuthMiddleware(ws.corsMiddleware(ws.mux))
	addr := fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.WebPort)

	ws.mu.Lock()
	ws.addr = addr
	ws.httpServer = &http.Server{Addr: addr, Handler: handler}
	ws.redirect = nil
	ws.listener = nil
	ws.mu.Unlock()

	if cfg.Server.WebTLS != nil && cfg.Server.WebTLS.Enabled {
		certFile := strings.TrimSpace(cfg.Server.WebTLS.CertFile)
		keyFile := strings.TrimSpace(cfg.Server.WebTLS.KeyFile)
		if certFile != "" && keyFile != "" {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			ws.mu.Lock()
			ws.listener = ln
			// Redirect server (plain HTTP -> HTTPS)
			ws.redirect = &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					target := "https://" + r.Host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				}),
			}
			ws.mu.Unlock()

			tlsCfg, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				ln.Close()
				return err
			}
			return ws.serveTLSWithRedirect(ln, &tlsCfg, handler)
		}
		log.Printf("[WebServer] TLS enabled but cert/key missing, fallback to HTTP")
	}

	log.Printf("[WebServer] Starting on http://%s", addr)
	err := ws.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// serveTLSWithRedirect 在同一端口上同时提供 TLS 和 HTTP->HTTPS 重定向。
func (ws *WebServer) serveTLSWithRedirect(ln net.Listener, cert *tls.Certificate, handler http.Handler) error {
	log.Printf("[WebServer] Starting on https://%s (TLS with redirect)", ws.addr)

	// TLS server
	ws.mu.Lock()
	httpsSrv := ws.httpServer
	redirSrv := ws.redirect
	ws.mu.Unlock()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Accept loop with simple TLS sniffing
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "closed network connection") {
				return nil
			}
			return err
		}

		go func(c net.Conn) {
			br := bufio.NewReader(c)
			first, err := br.Peek(1)
			if err != nil {
				c.Close()
				return
			}
			// TLS ClientHello starts with 0x16
			if first[0] == 0x16 {
				tlsConn := tls.Server(newPeekConn(c, br), tlsCfg)
				httpsSrv.Serve(&singleConnListener{tlsConn})
				return
			}
			// Otherwise treat as plain HTTP and redirect
			redirSrv.Serve(&singleConnListener{newPeekConn(c, br)})
		}(conn)
	}
}

// singleConnListener 适配单连接给 http.Server 使用。
type singleConnListener struct {
	net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.Conn == nil {
		return nil, fmt.Errorf("listener closed")
	}
	c := l.Conn
	l.Conn = nil
	return c, nil
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.Conn.LocalAddr() }

// peekConn 在读之前先返回已经 peek 的数据。
type peekConn struct {
	net.Conn
	reader *bufio.Reader
}

func newPeekConn(c net.Conn, br *bufio.Reader) net.Conn {
	return &peekConn{Conn: c, reader: br}
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

// handleLogs 处理日志请求
func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取 limit 参数，默认100条
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	logs := ws.server.GetLogs(limit)
	ws.writeJSON(w, logs)
}

// handleStatus 处理状态检查请求
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// 检查最近20分钟是否有ERROR日志
	hasError := ws.server.HasRecentErrors(20 * 60)

	// 检查是否有已配置但未连接的客户端
	hasDisconnected := ws.server.HasDisconnectedClients()

	if hasError || hasDisconnected {
		w.WriteHeader(220)
		if r.Method != http.MethodHead {
			w.Write([]byte("Some Services Wrong"))
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write([]byte("All Services OK"))
	}
}

// writeJSON 写入JSON响应
func (ws *WebServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
