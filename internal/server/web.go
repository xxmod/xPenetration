package server

import (
	"encoding/json"
	"log"
	"net/http"
	"fmt"
)

// WebServer Web管理服务
type WebServer struct {
	server   *Server
	addr     string
	mux      *http.ServeMux
}

// NewWebServer 创建Web服务器
func NewWebServer(server *Server, addr string) *WebServer {
	ws := &WebServer{
		server: server,
		addr:   addr,
		mux:    http.NewServeMux(),
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

	// 静态文件（前端）
	ws.mux.HandleFunc("/", ws.handleIndex)
}

// Start 启动Web服务器
func (ws *WebServer) Start() error {
	log.Printf("[WebServer] Starting on %s", ws.addr)
	return http.ListenAndServe(ws.addr, ws.corsMiddleware(ws.mux))
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

// handleIndex 处理首页请求
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// 返回简单的占位页面，等待前端开发
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>xPenetration - 内网穿透管理</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .api-list { background: #f8f9fa; padding: 20px; border-radius: 4px; margin-top: 20px; }
        .api-item { margin: 10px 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔗 xPenetration</h1>
        <p>内网穿透管理系统 - 后端API已就绪，前端界面开发中...</p>
        
        <div class="api-list">
            <h3>可用API接口：</h3>
            <div class="api-item">📊 <code>GET /api/stats</code> - 获取统计信息</div>
            <div class="api-item">👥 <code>GET /api/clients</code> - 获取客户端列表</div>
            <div class="api-item">🔌 <code>GET /api/connections</code> - 获取活跃连接列表</div>
            <div class="api-item">❤️ <code>GET /api/health</code> - 健康检查</div>
        </div>
    </div>
</body>
</html>`)
}

// writeJSON 写入JSON响应
func (ws *WebServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
