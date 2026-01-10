package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xpenetration/internal/config"
	"xpenetration/internal/server"
)

var (
	configPath string
	version    = "dev" // 通过 -ldflags "-X main.version=xxx" 注入，版本号定义在 .env 文件中
	showHelp   bool
	showVer    bool
)

func init() {
	flag.StringVar(&configPath, "c", "server.yaml", "配置文件路径")
	flag.StringVar(&configPath, "config", "server.yaml", "配置文件路径")
	flag.BoolVar(&showHelp, "h", false, "显示帮助信息")
	flag.BoolVar(&showHelp, "help", false, "显示帮助信息")
	flag.BoolVar(&showVer, "v", false, "显示版本信息")
	flag.BoolVar(&showVer, "version", false, "显示版本信息")
}

func main() {
	flag.Parse()

	if showHelp {
		printHelp()
		return
	}

	if showVer {
		fmt.Printf("xPenetration Server %s\n", version)
		return
	}

	log.Printf("===========================================")
	log.Printf("  xPenetration Server %s", version)
	log.Printf("===========================================")

	// 尝试加载配置
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file not found at %s, using default settings.", configPath)
			log.Printf("Please configure the server via Web UI.")
			// 默认配置
			cfg = &config.ServerConfig{
				Server: config.ServerSettings{
					ListenAddr:  "0.0.0.0",
					ControlPort: 7000,
					UDPPort:     7001,
					WebPort:     7500,
					WebTLS:      &config.WebTLS{},
					Encryption:  config.EncryptionSettings{Enabled: false},
				},
				Log: config.LogSettings{
					Level:  "info",
					Output: "stdout",
				},
			}
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	log.Printf("Control Port: %d", cfg.Server.ControlPort)
	log.Printf("Web Port: %d", cfg.Server.WebPort)
	log.Printf("Clients configured: %d", len(cfg.Clients))
	log.Printf("===========================================")

	// 创建服务端
	srv := server.NewServer(cfg)

	// 设置日志捕获（在启动前设置，确保所有日志都被捕获）
	srv.SetupLogCapture()

	// 启动服务端
	if err := srv.Start(); err != nil {
		log.Printf("Warning: Failed to start server core: %v", err)
		log.Printf("Web UI will still be available for configuration.")
	}

	// 启动Web服务
	webAddr := fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.WebPort)
	webSrv := server.NewWebServer(srv, webAddr, configPath)
	go func() {
		if err := webSrv.Start(); err != nil {
			log.Fatalf("Web server error: %v", err)
		}
	}()

	log.Printf("Server started successfully!")
	scheme := "http"
	if cfg.Server.WebTLS != nil && cfg.Server.WebTLS.Enabled && cfg.Server.WebTLS.CertFile != "" && cfg.Server.WebTLS.KeyFile != "" {
		scheme = "https"
	}
	log.Printf("Web UI available at %s://%s:%d", scheme, cfg.Server.ListenAddr, cfg.Server.WebPort)

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Shutting down...")
	srv.Stop()
	log.Printf("Server stopped")
}

func printHelp() {
	fmt.Printf(`xPenetration Server v%s
内网穿透服务端

用法:
  xpen-server [选项]

选项:
  -c, --config <path>   指定配置文件路径 (默认: server.yaml)
  -h, --help            显示帮助信息
  -v, --version         显示版本信息

示例:
  # 默认启动（自动查找当前目录下的 server.yaml）
  xpen-server

  # 指定配置文件
  xpen-server -c /etc/xpen/server.yaml

配置文件说明:
  服务端配置文件包含以下主要部分:
  - server: 服务端监听设置
  - clients: 客户端配置列表（包含隧道分配）
  - log: 日志配置

更多信息请查看 README.md
`, version)
}
