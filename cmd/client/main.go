package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xpenetration/internal/client"
	"xpenetration/internal/config"
)

var (
	configPath string
	serverAddr string
	serverPort int
	secretKey  string
	clientName string
	version    = "1.0.0"
	showHelp   bool
	showVer    bool
)

func init() {
	flag.StringVar(&configPath, "c", "", "配置文件路径")
	flag.StringVar(&configPath, "config", "", "配置文件路径")
	flag.StringVar(&serverAddr, "s", "", "服务端地址")
	flag.StringVar(&serverAddr, "server", "", "服务端地址")
	flag.IntVar(&serverPort, "p", 7000, "服务端端口")
	flag.IntVar(&serverPort, "port", 7000, "服务端端口")
	flag.StringVar(&secretKey, "k", "", "密钥")
	flag.StringVar(&secretKey, "key", "", "密钥")
	flag.StringVar(&clientName, "n", "", "客户端名称")
	flag.StringVar(&clientName, "name", "", "客户端名称")
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
		fmt.Printf("xPenetration Client v%s\n", version)
		return
	}

	var cfg *config.ClientConnConfig
	var err error

	// 加载配置
	if configPath != "" {
		cfg, err = config.LoadClientConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		// 尝试自动查找当前目录下的 client.yaml
		defaultConfigPath := "client.yaml"
		if _, err := os.Stat(defaultConfigPath); err == nil {
			cfg, err = config.LoadClientConfig(defaultConfigPath)
			if err != nil {
				log.Fatalf("Failed to load config from %s: %v", defaultConfigPath, err)
			}
			log.Printf("Using default config file: %s", defaultConfigPath)
		} else {
			// 使用命令行参数
			if serverAddr == "" {
				log.Fatal("Server address is required. Use -s <address> or -c <config file>")
			}
			if secretKey == "" {
				log.Fatal("Secret key is required. Use -k <key> or -c <config file>")
			}
			if clientName == "" {
				log.Fatal("Client name is required. Use -n <name> or -c <config file>")
			}

			cfg = &config.ClientConnConfig{
				Client: config.ClientConnSettings{
					ServerAddr:        serverAddr,
					ServerPort:        serverPort,
					SecretKey:         secretKey,
					ClientName:        clientName,
					AutoReconnect:     true,
					ReconnectInterval: 5,
				},
				Log: config.LogSettings{
					Level:  "info",
					Output: "stdout",
				},
			}
		}
	}

	// 命令行参数覆盖配置文件
	if serverAddr != "" {
		cfg.Client.ServerAddr = serverAddr
	}
	if serverPort != 7000 {
		cfg.Client.ServerPort = serverPort
	}
	if secretKey != "" {
		cfg.Client.SecretKey = secretKey
	}
	if clientName != "" {
		cfg.Client.ClientName = clientName
	}

	log.Printf("===========================================")
	log.Printf("  xPenetration Client v%s", version)
	log.Printf("===========================================")
	log.Printf("Server: %s:%d", cfg.Client.ServerAddr, cfg.Client.ServerPort)
	log.Printf("Client Name: %s", cfg.Client.ClientName)
	log.Printf("Auto Reconnect: %v", cfg.Client.AutoReconnect)
	log.Printf("===========================================")

	// 创建客户端
	cli := client.NewClient(cfg)

	// 处理退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("Shutting down...")
		cli.Stop()
	}()

	// 启动客户端
	if err := cli.Start(); err != nil {
		log.Fatalf("Client error: %v", err)
	}

	log.Printf("Client stopped")
}

func printHelp() {
	fmt.Printf(`xPenetration Client v%s
内网穿透客户端

用法:
  xpen-client [选项]

选项:
  -c, --config <path>   指定配置文件路径
  -s, --server <addr>   服务端地址
  -p, --port <port>     服务端端口 (默认: 7000)
  -k, --key <key>       密钥
  -n, --name <name>     客户端名称
  -h, --help            显示帮助信息
  -v, --version         显示版本信息

示例:
  # 使用配置文件
  xpen-client -c configs/client.yaml

  # 使用命令行参数
  xpen-client -s server.example.com -p 7000 -k "my-secret" -n "my-client"

  # 混合使用（命令行参数覆盖配置文件）
  xpen-client -c configs/client.yaml -s new-server.example.com

配置文件说明:
  客户端配置文件包含以下主要部分:
  - client: 客户端连接设置
  - log: 日志配置

更多信息请查看 README.md
`, version)
}
