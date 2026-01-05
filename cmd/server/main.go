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
	version    = "1.0.0"
	showHelp   bool
	showVer    bool
)

func init() {
	flag.StringVar(&configPath, "c", "configs/server.yaml", "配置文件路径")
	flag.StringVar(&configPath, "config", "configs/server.yaml", "配置文件路径")
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
		fmt.Printf("xPenetration Server v%s\n", version)
		return
	}

	// 加载配置
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("===========================================")
	log.Printf("  xPenetration Server v%s", version)
	log.Printf("===========================================")
	log.Printf("Control Port: %d", cfg.Server.ControlPort)
	log.Printf("Web Port: %d", cfg.Server.WebPort)
	log.Printf("Clients configured: %d", len(cfg.Clients))
	log.Printf("===========================================")

	// 创建服务端
	srv := server.NewServer(cfg)

	// 启动服务端
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// 启动Web服务
	webAddr := fmt.Sprintf("%s:%d", cfg.Server.ListenAddr, cfg.Server.WebPort)
	webSrv := server.NewWebServer(srv, webAddr)
	go func() {
		if err := webSrv.Start(); err != nil {
			log.Printf("Web server error: %v", err)
		}
	}()

	log.Printf("Server started successfully!")

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
  -c, --config <path>   指定配置文件路径 (默认: configs/server.yaml)
  -h, --help            显示帮助信息
  -v, --version         显示版本信息

示例:
  xpen-server -c /etc/xpen/server.yaml

配置文件说明:
  服务端配置文件包含以下主要部分:
  - server: 服务端监听设置
  - clients: 客户端配置列表（包含隧道分配）
  - log: 日志配置

更多信息请查看 README.md
`, version)
}
