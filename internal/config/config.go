package config

import (
	"os"

	"gopkg.in/yaml.v3"
	"xpenetration/internal/protocol"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	Server  ServerSettings    `yaml:"server"`
	Clients []ClientSettings  `yaml:"clients"`
	Log     LogSettings       `yaml:"log"`
}

// ServerSettings 服务端设置
type ServerSettings struct {
	ListenAddr  string `yaml:"listen_addr"`  // 监听地址
	ControlPort int    `yaml:"control_port"` // 控制端口
	WebPort     int    `yaml:"web_port"`     // Web管理端口
	SecretKey   string `yaml:"secret_key"`   // 全局密钥
}

// ClientSettings 客户端配置（服务端侧）
type ClientSettings struct {
	Name      string            `yaml:"name"`       // 客户端名称
	SecretKey string            `yaml:"secret_key"` // 客户端专属密钥（可选，为空则使用全局密钥）
	Tunnels   []protocol.Tunnel `yaml:"tunnels"`    // 分配给该客户端的隧道
}

// LogSettings 日志设置
type LogSettings struct {
	Level  string `yaml:"level"`  // 日志级别: debug, info, warn, error
	Output string `yaml:"output"` // 输出位置: stdout, file path
}

// ClientConfig 客户端配置
type ClientConnConfig struct {
	Client ClientConnSettings `yaml:"client"`
	Log    LogSettings        `yaml:"log"`
}

// ClientConnSettings 客户端连接设置
type ClientConnSettings struct {
	ServerAddr string `yaml:"server_addr"` // 服务端地址
	ServerPort int    `yaml:"server_port"` // 服务端控制端口
	SecretKey  string `yaml:"secret_key"`  // 密钥
	ClientName string `yaml:"client_name"` // 客户端名称
	AutoReconnect bool   `yaml:"auto_reconnect"` // 自动重连
	ReconnectInterval int `yaml:"reconnect_interval"` // 重连间隔（秒）
}

// LoadServerConfig 加载服务端配置
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// 设置默认值
	if config.Server.ListenAddr == "" {
		config.Server.ListenAddr = "0.0.0.0"
	}
	if config.Server.ControlPort == 0 {
		config.Server.ControlPort = 7000
	}
	if config.Server.WebPort == 0 {
		config.Server.WebPort = 7500
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}
	if config.Log.Output == "" {
		config.Log.Output = "stdout"
	}

	return &config, nil
}

// LoadClientConfig 加载客户端配置
func LoadClientConfig(path string) (*ClientConnConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ClientConnConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// 设置默认值
	if config.Client.ServerPort == 0 {
		config.Client.ServerPort = 7000
	}
	if config.Client.ReconnectInterval == 0 {
		config.Client.ReconnectInterval = 5
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}
	if config.Log.Output == "" {
		config.Log.Output = "stdout"
	}

	return &config, nil
}

// SaveServerConfig 保存服务端配置
func SaveServerConfig(path string, config *ServerConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// SaveClientConfig 保存客户端配置
func SaveClientConfig(path string, config *ClientConnConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
