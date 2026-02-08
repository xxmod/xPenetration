package config

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

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

// ValidateServerConfig 验证服务端配置的合法性
// 检查客户端名称重复、隧道名称重复、端口冲突等
func ValidateServerConfig(cfg *ServerConfig) []string {
	var errors []string

	// 收集服务端自身占用的端口
	reservedPorts := map[int]string{}
	if cfg.Server.ControlPort > 0 {
		reservedPorts[cfg.Server.ControlPort] = "服务端控制端口"
	}
	if cfg.Server.UDPPort > 0 {
		reservedPorts[cfg.Server.UDPPort] = "服务端UDP端口"
	}
	if cfg.Server.WebPort > 0 {
		reservedPorts[cfg.Server.WebPort] = "Web管理端口"
	}

	// 检查服务端端口之间是否互相冲突
	portValues := []struct {
		port int
		name string
	}{
		{cfg.Server.ControlPort, "控制端口"},
		{cfg.Server.UDPPort, "UDP端口"},
		{cfg.Server.WebPort, "Web管理端口"},
	}
	for i := 0; i < len(portValues); i++ {
		for j := i + 1; j < len(portValues); j++ {
			if portValues[i].port > 0 && portValues[i].port == portValues[j].port {
				errors = append(errors, fmt.Sprintf("服务端端口冲突：%s 和 %s 使用了相同的端口 %d",
					portValues[i].name, portValues[j].name, portValues[i].port))
			}
		}
	}

	// 检查客户端名称重复
	clientNames := map[string]int{}
	for idx, client := range cfg.Clients {
		name := client.Name
		if name == "" {
			errors = append(errors, fmt.Sprintf("第 %d 个客户端名称为空", idx+1))
			continue
		}
		if prevIdx, exists := clientNames[name]; exists {
			errors = append(errors, fmt.Sprintf("客户端名称重复：\"%s\" (第 %d 和第 %d 个客户端)", name, prevIdx+1, idx+1))
		} else {
			clientNames[name] = idx
		}
	}

	// 检查隧道名称重复和端口冲突
	tunnelNames := map[string]string{} // tunnelName -> clientName
	// 使用 "协议:端口" 作为key，TCP和UDP可以共用同一端口号
	serverPorts := map[string]string{} // "protocol:serverPort" -> "clientName/tunnelName"
	for _, client := range cfg.Clients {
		for _, tunnel := range client.Tunnels {
			tunnelKey := client.Name + "/" + tunnel.Name

			// 检查隧道名称是否为空
			if tunnel.Name == "" {
				errors = append(errors, fmt.Sprintf("客户端 \"%s\" 存在未命名的隧道", client.Name))
				continue
			}

			// 检查隧道名称重复（全局唯一）
			if ownerClient, exists := tunnelNames[tunnel.Name]; exists {
				errors = append(errors, fmt.Sprintf("隧道名称重复：\"%s\" (客户端 \"%s\" 和 \"%s\")",
					tunnel.Name, ownerClient, client.Name))
			} else {
				tunnelNames[tunnel.Name] = client.Name
			}

			// 检查隧道服务端端口是否冲突
			if tunnel.ServerPort > 0 {
				// 确定协议类型，默认为tcp
				proto := "tcp"
				if strings.EqualFold(tunnel.Protocol, "udp") {
					proto = "udp"
				}
				portKey := fmt.Sprintf("%s:%d", proto, tunnel.ServerPort)

				// 与其他隧道的端口冲突（同协议同端口才算冲突）
				if existingTunnel, exists := serverPorts[portKey]; exists {
					errors = append(errors, fmt.Sprintf("隧道端口冲突：%s 端口 %d 被 \"%s\" 和 \"%s\" 同时使用",
						strings.ToUpper(proto), tunnel.ServerPort, existingTunnel, tunnelKey))
				} else {
					serverPorts[portKey] = tunnelKey
				}

				// 与服务端保留端口冲突（服务端控制端口和Web端口为TCP，UDP端口为UDP）
				if reservedName, exists := reservedPorts[tunnel.ServerPort]; exists {
					// 判断保留端口的协议类型是否与隧道冲突
					reservedProto := "tcp"
					if tunnel.ServerPort == cfg.Server.UDPPort {
						reservedProto = "udp"
					}
					if reservedProto == proto {
						errors = append(errors, fmt.Sprintf("隧道端口冲突：隧道 \"%s\" 的 %s 端口 %d 与%s冲突",
							tunnelKey, strings.ToUpper(proto), tunnel.ServerPort, reservedName))
					}
				}
			}
		}
	}

	return errors
}

// CheckPortsAvailability 检查新配置中的端口是否被系统其他程序占用
// currentCfg 为当前正在运行的配置，其中已占用的端口属于本服务，无需检查
// 返回被占用端口的描述列表（空表示全部可用）
func CheckPortsAvailability(newCfg *ServerConfig, currentCfg *ServerConfig) []string {
	var conflicts []string

	// 收集当前服务已占用的端口（这些端口在重启时会被释放，无需检查）
	ownedPorts := make(map[int]bool)
	if currentCfg != nil {
		ownedPorts[currentCfg.Server.ControlPort] = true
		ownedPorts[currentCfg.Server.UDPPort] = true
		ownedPorts[currentCfg.Server.WebPort] = true
		for _, client := range currentCfg.Clients {
			for _, tunnel := range client.Tunnels {
				if tunnel.ServerPort > 0 {
					ownedPorts[tunnel.ServerPort] = true
				}
			}
		}
	}

	// 收集新配置中需要检查的端口
	type portInfo struct {
		Port     int
		Name     string
		Protocol string // "tcp", "udp", "both"
	}
	var portsToCheck []portInfo

	// 服务端端口
	if newCfg.Server.ControlPort > 0 {
		portsToCheck = append(portsToCheck, portInfo{newCfg.Server.ControlPort, "控制端口", "tcp"})
	}
	if newCfg.Server.UDPPort > 0 {
		portsToCheck = append(portsToCheck, portInfo{newCfg.Server.UDPPort, "UDP传输端口", "udp"})
	}
	if newCfg.Server.WebPort > 0 {
		portsToCheck = append(portsToCheck, portInfo{newCfg.Server.WebPort, "Web管理端口", "tcp"})
	}

	// 隧道端口
	for _, client := range newCfg.Clients {
		for _, tunnel := range client.Tunnels {
			if tunnel.ServerPort > 0 {
				proto := "tcp"
				if strings.EqualFold(tunnel.Protocol, "udp") {
					proto = "udp"
				}
				name := fmt.Sprintf("隧道 \"%s/%s\"", client.Name, tunnel.Name)
				portsToCheck = append(portsToCheck, portInfo{tunnel.ServerPort, name, proto})
			}
		}
	}

	// 去重：同一端口只检查一次
	checked := make(map[int]bool)
	for _, p := range portsToCheck {
		if checked[p.Port] {
			continue
		}
		checked[p.Port] = true

		// 跳过当前服务自身占用的端口
		if ownedPorts[p.Port] {
			continue
		}

		// 尝试绑定端口，检测是否被其他程序占用
		addr := fmt.Sprintf(":%d", p.Port)
		if p.Protocol == "udp" {
			if conflict := checkUDPPort(addr); conflict != "" {
				conflicts = append(conflicts, fmt.Sprintf("%s (UDP端口 %d) %s", p.Name, p.Port, conflict))
			}
		} else {
			if conflict := checkTCPPort(addr); conflict != "" {
				conflicts = append(conflicts, fmt.Sprintf("%s (TCP端口 %d) %s", p.Name, p.Port, conflict))
			}
		}
	}

	return conflicts
}

// checkTCPPort 尝试监听 TCP 端口，返回空字符串表示可用，否则返回错误描述（含占用进程信息）
func checkTCPPort(addr string) string {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// 解析端口号
		port := parsePort(addr)
		procInfo := findProcessByPort(port, "tcp")
		if procInfo != "" {
			return fmt.Sprintf("已被占用 (%s)", procInfo)
		}
		return "已被其他程序占用"
	}
	ln.Close()
	return ""
}

// checkUDPPort 尝试监听 UDP 端口，返回空字符串表示可用，否则返回错误描述（含占用进程信息）
func checkUDPPort(addr string) string {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "地址解析失败"
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		port := parsePort(addr)
		procInfo := findProcessByPort(port, "udp")
		if procInfo != "" {
			return fmt.Sprintf("已被占用 (%s)", procInfo)
		}
		return "已被其他程序占用"
	}
	conn.Close()
	return ""
}

// parsePort 从 ":port" 格式地址中提取端口号
func parsePort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) > 0 {
		p, _ := strconv.Atoi(parts[len(parts)-1])
		return p
	}
	return 0
}

// findProcessByPort 查找占用指定端口的进程信息，返回 "进程名 (PID: xxx)" 或空字符串
func findProcessByPort(port int, proto string) string {
	if port <= 0 {
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		return findProcessWindows(port, proto)
	default:
		return findProcessLinux(port, proto)
	}
}

// findProcessWindows 在 Windows 上通过 netstat + tasklist 查找占用端口的进程
func findProcessWindows(port int, proto string) string {
	// netstat -ano 输出格式：
	//   TCP    0.0.0.0:7000    0.0.0.0:0    LISTENING    12345
	//   UDP    0.0.0.0:7001    *:*                       12345
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return ""
	}

	portStr := fmt.Sprintf(":%d ", port)
	protoUpper := strings.ToUpper(proto)
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(line), protoUpper) {
			continue
		}
		if !strings.Contains(line, portStr) {
			continue
		}
		// 对 TCP 只匹配 LISTENING 状态
		if protoUpper == "TCP" && !strings.Contains(strings.ToUpper(line), "LISTENING") {
			continue
		}
		// 提取末尾 PID
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pidStr := fields[len(fields)-1]
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		name := getProcessNameWindows(pid)
		if name != "" {
			return fmt.Sprintf("%s, PID: %d", name, pid)
		}
		return fmt.Sprintf("PID: %d", pid)
	}
	return ""
}

// getProcessNameWindows 通过 tasklist 获取进程名
func getProcessNameWindows(pid int) string {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return ""
	}
	// 输出格式: "进程名","PID","会话名","会话#","内存使用"
	line := strings.TrimSpace(string(out))
	if strings.HasPrefix(line, "\"") {
		parts := strings.SplitN(line, ",", 3)
		if len(parts) >= 1 {
			return strings.Trim(parts[0], "\"")
		}
	}
	return ""
}

// findProcessLinux 在 Linux/macOS 上通过 ss 或 lsof 查找占用端口的进程
func findProcessLinux(port int, proto string) string {
	// 优先尝试 ss（Linux）
	if info := findProcessBySS(port, proto); info != "" {
		return info
	}
	// 回退到 lsof（macOS / 其他 Unix）
	return findProcessByLsof(port, proto)
}

// findProcessBySS 使用 ss -lpn 查找占用端口的进程
func findProcessBySS(port int, proto string) string {
	filter := "tcp"
	if strings.EqualFold(proto, "udp") {
		filter = "udp"
	}
	out, err := exec.Command("ss", "-lpn", "state", "listening", "sport", "=", fmt.Sprintf(":%d", port)).Output()
	if err != nil {
		// ss 不一定在所有系统上可用
		return ""
	}
	_ = filter
	// ss 输出中进程信息格式: users:(("nginx",pid=1234,fd=5))
	re := regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) >= 3 {
		return fmt.Sprintf("%s, PID: %s", matches[1], matches[2])
	}
	return ""
}

// findProcessByLsof 使用 lsof 查找占用端口的进程
func findProcessByLsof(port int, proto string) string {
	protoArg := "TCP"
	if strings.EqualFold(proto, "udp") {
		protoArg = "UDP"
	}
	out, err := exec.Command("lsof", "-i", fmt.Sprintf("%s:%d", protoArg, port), "-sTCP:LISTEN", "-nP", "-t").Output()
	if err != nil {
		return ""
	}
	pidStr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return ""
	}
	// 获取进程名
	nameOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err == nil {
		name := strings.TrimSpace(string(nameOut))
		if name != "" {
			return fmt.Sprintf("%s, PID: %d", name, pid)
		}
	}
	return fmt.Sprintf("PID: %d", pid)
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
