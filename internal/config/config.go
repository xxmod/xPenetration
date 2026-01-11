package config

import (
	"os"

	"xpenetration/internal/protocol"

	"gopkg.in/yaml.v3"
)

// ServerConfig 服务端配置
type ServerConfig struct {
	Server  ServerSettings   `yaml:"server" json:"server"`
	Clients []ClientSettings `yaml:"clients" json:"clients"`
	Log     LogSettings      `yaml:"log" json:"log"`
	ACME    *ACMESettings    `yaml:"acme" json:"acme"` // ACME自动证书配置
}

// ServerSettings 服务端设置
type ServerSettings struct {
	ListenAddr  string             `yaml:"listen_addr" json:"listen_addr"`   // 监听地址
	ControlPort int                `yaml:"control_port" json:"control_port"` // 控制端口
	UDPPort     int                `yaml:"udp_port" json:"udp_port"`         // UDP数据传输端口（用于原生UDP隧道）
	WebPort     int                `yaml:"web_port" json:"web_port"`         // Web管理端口
	SecretKey   string             `yaml:"secret_key" json:"secret_key"`     // 全局密钥
	WebAuth     *WebAuth           `yaml:"web_auth" json:"web_auth"`         // Web管理界面Basic Auth（可选）
	WebTLS      *WebTLS            `yaml:"web_tls" json:"web_tls"`           // Web管理界面TLS配置（可选）
	Encryption  EncryptionSettings `yaml:"encryption" json:"encryption"`     // 传输加密设置
}

// EncryptionSettings 传输加密配置
type EncryptionSettings struct {
	Enabled bool `yaml:"enabled" json:"enabled"` // 是否启用端到端加密
}

// WebAuth Web管理界面认证配置
type WebAuth struct {
	Username string `yaml:"username" json:"username"` // 用户名
	Password string `yaml:"password" json:"password"` // 密码
}

// WebTLS Web管理界面TLS配置
type WebTLS struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`     // 是否启用HTTPS
	CertFile string `yaml:"cert_file" json:"cert_file"` // 证书文件路径（PEM）
	KeyFile  string `yaml:"key_file" json:"key_file"`   // 私钥文件路径（PEM）
}

// ACMESettings ACME自动证书配置
type ACMESettings struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`               // 是否启用ACME
	Email         string   `yaml:"email" json:"email"`                   // 注册邮箱
	Domains       []string `yaml:"domains" json:"domains"`               // 申请证书的域名列表
	CAServer      string   `yaml:"ca_server" json:"ca_server"`           // CA服务器（可选，默认Let's Encrypt）
	AcceptTOS     bool     `yaml:"accept_tos" json:"accept_tos"`         // 是否同意服务条款
	RenewBefore   int      `yaml:"renew_before" json:"renew_before"`     // 证书到期前多少天续签（默认30天）
	HTTPPort      int      `yaml:"http_port" json:"http_port"`           // HTTP-01挑战端口（默认80）
	DataDir       string   `yaml:"data_dir" json:"data_dir"`             // ACME数据存储目录
	AutoRenew     bool     `yaml:"auto_renew" json:"auto_renew"`         // 是否自动续签
	RenewInterval int      `yaml:"renew_interval" json:"renew_interval"` // 续签检查间隔（小时，默认24）
	EABEnabled    bool     `yaml:"eab_enabled" json:"eab_enabled"`       // 是否启用EAB（External Account Binding）
	EABKid        string   `yaml:"eab_kid" json:"eab_kid"`               // EAB Key ID
	EABHmacKey    string   `yaml:"eab_hmac_key" json:"eab_hmac_key"`     // EAB HMAC Key
	// DNS-01 挑战配置
	ChallengeType string `yaml:"challenge_type" json:"challenge_type"` // 挑战类型: http-01 或 dns-01
	DNSProvider   string `yaml:"dns_provider" json:"dns_provider"`     // DNS提供商: cloudflare, alidns, tencentcloud 等
	DNSConfig     string `yaml:"dns_config" json:"dns_config"`         // DNS提供商配置（JSON格式）
}

// ClientSettings 客户端配置（服务端侧）
type ClientSettings struct {
	Name      string            `yaml:"name" json:"name"`             // 客户端名称
	SecretKey string            `yaml:"secret_key" json:"secret_key"` // 客户端专属密钥（可选，为空则使用全局密钥）
	Tunnels   []protocol.Tunnel `yaml:"tunnels" json:"tunnels"`       // 分配给该客户端的隧道
}

// LogSettings 日志设置
type LogSettings struct {
	Level  string `yaml:"level" json:"level"`   // 日志级别: debug, info, warn, error
	Output string `yaml:"output" json:"output"` // 输出位置: stdout, file path
}

// ClientConfig 客户端配置
type ClientConnConfig struct {
	Client ClientConnSettings `yaml:"client" json:"client"`
	Log    LogSettings        `yaml:"log" json:"log"`
}

// ClientConnSettings 客户端连接设置
type ClientConnSettings struct {
	ServerAddr        string `yaml:"server_addr" json:"server_addr"`               // 服务端地址
	ServerPort        int    `yaml:"server_port" json:"server_port"`               // 服务端控制端口
	ServerUDPPort     int    `yaml:"server_udp_port" json:"server_udp_port"`       // 服务端UDP传输端口（用于原生UDP隧道）
	SecretKey         string `yaml:"secret_key" json:"secret_key"`                 // 密钥
	ClientName        string `yaml:"client_name" json:"client_name"`               // 客户端名称
	AutoReconnect     bool   `yaml:"auto_reconnect" json:"auto_reconnect"`         // 自动重连
	ReconnectInterval int    `yaml:"reconnect_interval" json:"reconnect_interval"` // 重连间隔（秒）
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
	if config.Server.UDPPort == 0 {
		config.Server.UDPPort = 7001
	}
	if config.Server.WebPort == 0 {
		config.Server.WebPort = 7500
	}
	if config.Server.WebTLS == nil {
		config.Server.WebTLS = &WebTLS{}
	}
	if config.ACME == nil {
		config.ACME = &ACMESettings{}
	}
	if config.ACME.RenewBefore <= 0 {
		config.ACME.RenewBefore = 30
	}
	if config.ACME.HTTPPort <= 0 {
		config.ACME.HTTPPort = 80
	}
	if config.ACME.RenewInterval <= 0 {
		config.ACME.RenewInterval = 24
	}
	if config.ACME.DataDir == "" {
		config.ACME.DataDir = "acme"
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
	if config.Client.ServerUDPPort == 0 {
		config.Client.ServerUDPPort = 7001
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
