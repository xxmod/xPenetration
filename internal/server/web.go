package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"sync"

	"xpenetration/internal/config"
)

//go:embed web/*
var webFS embed.FS

// WebServer Web管理服务
type WebServer struct {
	server     *Server
	addr       string
	mux        *http.ServeMux
	configPath string
	mu         sync.Mutex
}

// NewWebServer 创建Web服务器
func NewWebServer(server *Server, addr string, configPath string) *WebServer {
	ws := &WebServer{
		server:     server,
		addr:       addr,
		mux:        http.NewServeMux(),
		configPath: configPath,
	}
	ws.setupRoutes()
	return ws
}

// setupRoutes 设置路由
func (ws *WebServer) setupRoutes() {
	// API路由
	ws.mux.HandleFunc("/api/stats", ws.handleStats)
	ws.mux.HandleFunc("/api/clients", ws.handleClients)
	ws.mux.HandleFunc("/api/connections", ws.handleConnections)
	ws.mux.HandleFunc("/api/health", ws.handleHealth)
	ws.mux.HandleFunc("/api/config", ws.handleConfig)
	ws.mux.HandleFunc("/api/logs", ws.handleLogs)
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
	log.Printf("[WebServer] Starting on %s", ws.addr)
	return http.ListenAndServe(ws.addr, ws.basicAuthMiddleware(ws.corsMiddleware(ws.mux)))
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

		// 保存到文件
		if err := config.SaveServerConfig(ws.configPath, &newConfig); err != nil {
			log.Printf("[WebServer] Failed to save config: %v", err)
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		log.Printf("[WebServer] Config saved to %s", ws.configPath)

		// 重载服务
		go func() {
			if err := ws.server.Reload(&newConfig); err != nil {
				log.Printf("[WebServer] Failed to reload server: %v", err)
			}
		}()

		ws.writeJSON(w, map[string]string{"status": "ok", "message": "Config saved and server reloading"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查最近5分钟是否有ERROR日志
	hasError := ws.server.HasRecentErrors(5 * 60) // 5分钟 = 300秒

	// 检查是否有已配置但未连接的客户端
	hasDisconnected := ws.server.HasDisconnectedClients()

	if hasError || hasDisconnected {
		w.WriteHeader(220)
		w.Write([]byte("Some Services Wrong"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("All Services OK"))
	}
}

// writeJSON 写入JSON响应
func (ws *WebServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
