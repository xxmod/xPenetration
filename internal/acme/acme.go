package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
)

// ACMEConfig ACME配置
type ACMEConfig struct {
	Enabled       bool     `json:"enabled" yaml:"enabled"`               // 是否启用ACME
	Email         string   `json:"email" yaml:"email"`                   // 注册邮箱
	Domains       []string `json:"domains" yaml:"domains"`               // 申请证书的域名列表
	CAServer      string   `json:"ca_server" yaml:"ca_server"`           // CA服务器URL（可选，默认Let's Encrypt）
	AcceptTOS     bool     `json:"accept_tos" yaml:"accept_tos"`         // 是否同意服务条款
	RenewBefore   int      `json:"renew_before" yaml:"renew_before"`     // 证书到期前多少天续签（默认30天）
	HTTPPort      int      `json:"http_port" yaml:"http_port"`           // HTTP-01挑战使用的端口（默认80）
	DataDir       string   `json:"data_dir" yaml:"data_dir"`             // ACME数据存储目录
	AutoRenew     bool     `json:"auto_renew" yaml:"auto_renew"`         // 是否自动续签
	RenewInterval int      `json:"renew_interval" yaml:"renew_interval"` // 续签检查间隔（小时，默认24）
	EABEnabled    bool     `json:"eab_enabled" yaml:"eab_enabled"`       // 是否启用EAB
	EABKid        string   `json:"eab_kid" yaml:"eab_kid"`               // EAB Key ID
	EABHmacKey    string   `json:"eab_hmac_key" yaml:"eab_hmac_key"`     // EAB HMAC Key
	// DNS-01 挑战配置
	ChallengeType string `json:"challenge_type" yaml:"challenge_type"` // 挑战类型: http-01 或 dns-01
	DNSProvider   string `json:"dns_provider" yaml:"dns_provider"`     // DNS提供商
	DNSConfig     string `json:"dns_config" yaml:"dns_config"`         // DNS提供商配置（JSON格式）
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Domains    []string  `json:"domains"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	DaysLeft   int       `json:"days_left"`
	CertFile   string    `json:"cert_file"`
	KeyFile    string    `json:"key_file"`
	ValidChain bool      `json:"valid_chain"`
}

// ACMEStatus ACME状态
type ACMEStatus struct {
	Enabled         bool             `json:"enabled"`
	Configured      bool             `json:"configured"`
	Registered      bool             `json:"registered"`
	CertificateInfo *CertificateInfo `json:"certificate_info,omitempty"`
	LastRenewTime   *time.Time       `json:"last_renew_time,omitempty"`
	LastError       string           `json:"last_error,omitempty"`
	NextRenewCheck  *time.Time       `json:"next_renew_check,omitempty"`
}

// Manager ACME管理器
type Manager struct {
	config            *ACMEConfig
	dataDir           string
	challengeProvider *HTTP01ChallengeProvider
	client            *lego.Client
	user              *ACMEUser
	mu                sync.RWMutex
	stopChan          chan struct{}
	running           bool
	lastRenewTime     *time.Time
	lastError         string
	nextRenewCheck    *time.Time
	onCertRenewed     func(certFile, keyFile string) // 证书续签回调
}

// ACMEUser 实现 lego 的 User 接口
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

// HTTP01ChallengeProvider HTTP-01挑战处理器
type HTTP01ChallengeProvider struct {
	tokens map[string]string
	mu     sync.RWMutex
}

// NewHTTP01ChallengeProvider 创建HTTP-01挑战处理器
func NewHTTP01ChallengeProvider() *HTTP01ChallengeProvider {
	return &HTTP01ChallengeProvider{
		tokens: make(map[string]string),
	}
}

// Present 存储挑战令牌
func (p *HTTP01ChallengeProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	log.Printf("[ACME] Challenge presented for domain %s, token: %s", domain, token)
	return nil
}

// CleanUp 清理挑战令牌
func (p *HTTP01ChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
	log.Printf("[ACME] Challenge cleaned up for domain %s", domain)
	return nil
}

// GetToken 获取挑战令牌（用于HTTP处理）
func (p *HTTP01ChallengeProvider) GetToken(token string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	keyAuth, ok := p.tokens[token]
	return keyAuth, ok
}

// NewManager 创建ACME管理器
func NewManager(config *ACMEConfig) *Manager {
	if config == nil {
		config = &ACMEConfig{}
	}

	// 设置默认值
	if config.RenewBefore <= 0 {
		config.RenewBefore = 30
	}
	if config.HTTPPort <= 0 {
		config.HTTPPort = 80
	}
	if config.RenewInterval <= 0 {
		config.RenewInterval = 24
	}
	if config.DataDir == "" {
		config.DataDir = "acme"
	}
	if config.CAServer == "" {
		config.CAServer = lego.LEDirectoryProduction
	}

	return &Manager{
		config:            config,
		dataDir:           config.DataDir,
		challengeProvider: NewHTTP01ChallengeProvider(),
		stopChan:          make(chan struct{}),
	}
}

// SetOnCertRenewed 设置证书续签回调
func (m *Manager) SetOnCertRenewed(callback func(certFile, keyFile string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCertRenewed = callback
}

// GetChallengeProvider 获取HTTP-01挑战处理器
func (m *Manager) GetChallengeProvider() *HTTP01ChallengeProvider {
	return m.challengeProvider
}

// Initialize 初始化ACME管理器
func (m *Manager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		return nil
	}

	// 确保数据目录存在
	if err := os.MkdirAll(m.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create ACME data directory: %v", err)
	}

	// 加载或创建用户
	user, err := m.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to load/create ACME user: %v", err)
	}
	m.user = user

	// 创建lego配置
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = m.config.CAServer
	legoCfg.Certificate.KeyType = certcrypto.EC256

	// 创建lego客户端
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}
	m.client = client

	// 根据挑战类型设置不同的挑战提供者
	challengeType := m.config.ChallengeType
	if challengeType == "" {
		challengeType = "http-01" // 默认使用 HTTP-01
	}

	if challengeType == "dns-01" {
		// 设置 DNS-01 挑战
		dnsProvider, err := m.createDNSProvider()
		if err != nil {
			return fmt.Errorf("failed to create DNS provider: %v", err)
		}
		err = client.Challenge.SetDNS01Provider(dnsProvider)
		if err != nil {
			return fmt.Errorf("failed to set DNS-01 provider: %v", err)
		}
		log.Printf("[ACME] Using DNS-01 challenge with provider: %s", m.config.DNSProvider)
	} else {
		// 设置 HTTP-01 挑战
		err = client.Challenge.SetHTTP01Provider(m.challengeProvider)
		if err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %v", err)
		}
		log.Printf("[ACME] Using HTTP-01 challenge on port %d", m.config.HTTPPort)
	}

	// 注册账号（如果尚未注册）
	if user.Registration == nil {
		if !m.config.AcceptTOS {
			return fmt.Errorf("must accept Terms of Service to use ACME")
		}

		var reg *registration.Resource
		var err error

		// 检查是否启用 EAB
		if m.config.EABEnabled && m.config.EABKid != "" && m.config.EABHmacKey != "" {
			log.Printf("[ACME] Registering with EAB (External Account Binding)...")
			reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  m.config.EABKid,
				HmacEncoded:          m.config.EABHmacKey,
			})
		} else {
			reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		}

		if err != nil {
			return fmt.Errorf("failed to register ACME account: %v", err)
		}
		user.Registration = reg

		// 保存注册信息
		if err := m.saveUser(user); err != nil {
			log.Printf("[ACME] Warning: failed to save user registration: %v", err)
		}

		log.Printf("[ACME] Account registered successfully with email: %s", user.Email)
	}

	return nil
}

// Start 启动自动续签
func (m *Manager) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.stopChan = make(chan struct{})
	m.mu.Unlock()

	if !m.config.Enabled || !m.config.AutoRenew {
		return
	}

	go m.renewLoop()
	log.Printf("[ACME] Auto-renewal started, check interval: %d hours", m.config.RenewInterval)
}

// Stop 停止自动续签
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopChan)
	m.mu.Unlock()
}

// renewLoop 续签循环
func (m *Manager) renewLoop() {
	// 首次检查
	m.checkAndRenew()

	interval := time.Duration(m.config.RenewInterval) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkAndRenew()
		case <-m.stopChan:
			return
		}
	}
}

// checkAndRenew 检查并续签证书
func (m *Manager) checkAndRenew() {
	m.mu.Lock()
	now := time.Now()
	next := now.Add(time.Duration(m.config.RenewInterval) * time.Hour)
	m.nextRenewCheck = &next
	m.mu.Unlock()

	certInfo := m.GetCertificateInfo()
	if certInfo == nil {
		// 没有证书，尝试申请
		log.Printf("[ACME] No certificate found, attempting to obtain...")
		if err := m.ObtainCertificate(); err != nil {
			m.setLastError(fmt.Sprintf("Failed to obtain certificate: %v", err))
			log.Printf("[ACME] Failed to obtain certificate: %v", err)
		}
		return
	}

	// 检查是否需要续签
	if certInfo.DaysLeft <= m.config.RenewBefore {
		log.Printf("[ACME] Certificate expires in %d days, renewing...", certInfo.DaysLeft)
		if err := m.RenewCertificate(); err != nil {
			m.setLastError(fmt.Sprintf("Failed to renew certificate: %v", err))
			log.Printf("[ACME] Failed to renew certificate: %v", err)
		} else {
			m.setLastError("")
			now := time.Now()
			m.mu.Lock()
			m.lastRenewTime = &now
			m.mu.Unlock()
			log.Printf("[ACME] Certificate renewed successfully")
		}
	} else {
		log.Printf("[ACME] Certificate is valid for %d more days, no renewal needed", certInfo.DaysLeft)
	}
}

// ObtainCertificate 申请新证书
func (m *Manager) ObtainCertificate() error {
	m.mu.RLock()
	client := m.client
	domains := m.config.Domains
	m.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("ACME client not initialized")
	}

	if len(domains) == 0 {
		return fmt.Errorf("no domains configured")
	}

	log.Printf("[ACME] Requesting certificate for domains: %v", domains)

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// 保存证书
	if err := m.saveCertificate(certificates); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	log.Printf("[ACME] Certificate obtained and saved successfully")

	// 触发回调
	m.triggerCertRenewed()

	return nil
}

// RenewCertificate 续签证书
func (m *Manager) RenewCertificate() error {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("ACME client not initialized")
	}

	// 加载当前证书
	certFile := m.GetCertFilePath()
	keyFile := m.GetKeyFilePath()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		// 如果没有现有证书，则申请新证书
		return m.ObtainCertificate()
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return m.ObtainCertificate()
	}

	// 续签
	certRes := certificate.Resource{
		Domain:      m.config.Domains[0],
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	newCert, err := client.Certificate.Renew(certRes, true, false, "")
	if err != nil {
		return fmt.Errorf("failed to renew certificate: %v", err)
	}

	// 保存新证书
	if err := m.saveCertificate(newCert); err != nil {
		return fmt.Errorf("failed to save renewed certificate: %v", err)
	}

	// 触发回调
	m.triggerCertRenewed()

	return nil
}

// saveCertificate 保存证书到文件
func (m *Manager) saveCertificate(cert *certificate.Resource) error {
	certPath := m.GetCertFilePath()
	keyPath := m.GetKeyFilePath()

	// 保存证书
	if err := os.WriteFile(certPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	// 保存私钥
	if err := os.WriteFile(keyPath, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	log.Printf("[ACME] Certificate saved: %s, Key saved: %s", certPath, keyPath)
	return nil
}

// GetCertFilePath 获取证书文件路径
func (m *Manager) GetCertFilePath() string {
	return filepath.Join(m.dataDir, "cert.pem")
}

// GetKeyFilePath 获取私钥文件路径
func (m *Manager) GetKeyFilePath() string {
	return filepath.Join(m.dataDir, "key.pem")
}

// GetCertificateInfo 获取当前证书信息
func (m *Manager) GetCertificateInfo() *CertificateInfo {
	certFile := m.GetCertFilePath()
	keyFile := m.GetKeyFilePath()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil
	}

	// 解析证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	// 检查私钥是否存在
	_, keyErr := os.ReadFile(keyFile)

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	return &CertificateInfo{
		Domains:    cert.DNSNames,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		Issuer:     cert.Issuer.CommonName,
		Serial:     cert.SerialNumber.String(),
		DaysLeft:   daysLeft,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ValidChain: keyErr == nil,
	}
}

// GetStatus 获取ACME状态
func (m *Manager) GetStatus() *ACMEStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := &ACMEStatus{
		Enabled:    m.config.Enabled,
		Configured: len(m.config.Domains) > 0 && m.config.Email != "",
		Registered: m.user != nil && m.user.Registration != nil,
		LastError:  m.lastError,
	}

	if m.lastRenewTime != nil {
		t := *m.lastRenewTime
		status.LastRenewTime = &t
	}

	if m.nextRenewCheck != nil {
		t := *m.nextRenewCheck
		status.NextRenewCheck = &t
	}

	status.CertificateInfo = m.GetCertificateInfo()

	return status
}

// GetConfig 获取当前配置
func (m *Manager) GetConfig() *ACMEConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg := *m.config
	return &cfg
}

// UpdateConfig 更新配置
func (m *Manager) UpdateConfig(newConfig *ACMEConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 应用默认值
	if newConfig.RenewBefore <= 0 {
		newConfig.RenewBefore = 30
	}
	if newConfig.HTTPPort <= 0 {
		newConfig.HTTPPort = 80
	}
	if newConfig.RenewInterval <= 0 {
		newConfig.RenewInterval = 24
	}
	if newConfig.DataDir == "" {
		newConfig.DataDir = m.config.DataDir
	}
	if newConfig.CAServer == "" {
		newConfig.CAServer = lego.LEDirectoryProduction
	}

	m.config = newConfig
	m.dataDir = newConfig.DataDir

	return nil
}

// getCAAccountDir 获取CA服务器对应的账户目录
// 不同CA使用不同的子目录，避免切换CA时账户混淆
func (m *Manager) getCAAccountDir() string {
	// 从CA服务器URL生成唯一标识
	caURL := m.config.CAServer
	if caURL == "" {
		caURL = lego.LEDirectoryProduction
	}

	// 解析URL获取主机名
	parsed, err := url.Parse(caURL)
	if err != nil || parsed.Host == "" {
		// 如果解析失败，使用URL的hash作为目录名
		hash := sha256.Sum256([]byte(caURL))
		return filepath.Join(m.dataDir, "accounts", hex.EncodeToString(hash[:8]))
	}

	// 使用主机名作为目录名（替换特殊字符）
	hostDir := strings.ReplaceAll(parsed.Host, ":", "_")
	return filepath.Join(m.dataDir, "accounts", hostDir)
}

// loadOrCreateUser 加载或创建ACME用户
func (m *Manager) loadOrCreateUser() (*ACMEUser, error) {
	// 使用CA特定的账户目录
	accountDir := m.getCAAccountDir()
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create account directory: %v", err)
	}

	userFile := filepath.Join(accountDir, "user.json")
	keyFile := filepath.Join(accountDir, "user-key.pem")

	// 尝试加载现有用户
	if _, err := os.Stat(userFile); err == nil {
		return m.loadUserFromDir(accountDir)
	}

	// 创建新用户
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	user := &ACMEUser{
		Email:      m.config.Email,
		PrivateKey: privateKey,
	}

	// 保存私钥
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %v", err)
	}

	log.Printf("[ACME] Created new user with email: %s (CA: %s)", m.config.Email, m.config.CAServer)
	return user, nil
}

// loadUser 从文件加载用户（兼容旧版本）
func (m *Manager) loadUser() (*ACMEUser, error) {
	return m.loadUserFromDir(m.getCAAccountDir())
}

// loadUserFromDir 从指定目录加载用户
func (m *Manager) loadUserFromDir(accountDir string) (*ACMEUser, error) {
	userFile := filepath.Join(accountDir, "user.json")
	keyFile := filepath.Join(accountDir, "user-key.pem")

	// 加载私钥
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	user := &ACMEUser{
		Email:      m.config.Email,
		PrivateKey: privateKey,
	}

	// 加载注册信息
	if data, err := os.ReadFile(userFile); err == nil {
		var reg registration.Resource
		if json.Unmarshal(data, &reg) == nil {
			user.Registration = &reg
		}
	}

	log.Printf("[ACME] Loaded existing user with email: %s (CA: %s)", user.Email, m.config.CAServer)
	return user, nil
}

// saveUser 保存用户信息
func (m *Manager) saveUser(user *ACMEUser) error {
	accountDir := m.getCAAccountDir()
	userFile := filepath.Join(accountDir, "user.json")

	if user.Registration != nil {
		data, err := json.MarshalIndent(user.Registration, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(userFile, data, 0600)
	}
	return nil
}

func (m *Manager) setLastError(err string) {
	m.mu.Lock()
	m.lastError = err
	m.mu.Unlock()
}

func (m *Manager) triggerCertRenewed() {
	m.mu.RLock()
	callback := m.onCertRenewed
	m.mu.RUnlock()

	if callback != nil {
		callback(m.GetCertFilePath(), m.GetKeyFilePath())
	}
}

// ForceRenew 强制续签证书
func (m *Manager) ForceRenew(ctx context.Context) error {
	return m.RenewCertificate()
}

// GetCAServers 获取可用的CA服务器列表
func GetCAServers() map[string]string {
	return map[string]string{
		"letsencrypt":         lego.LEDirectoryProduction,
		"letsencrypt_staging": lego.LEDirectoryStaging,
		"zerossl":             "https://acme.zerossl.com/v2/DV90",
		"buypass":             "https://api.buypass.com/acme/directory",
		"buypass_test":        "https://api.test4.buypass.no/acme/directory",
		"google":              "https://dv.acme-v02.api.pki.goog/directory",
		"google_test":         "https://dv.acme-v02.test-api.pki.goog/directory",
	}
}

// GetDNSProviders 获取支持的DNS提供商列表
func GetDNSProviders() map[string]DNSProviderInfo {
	return map[string]DNSProviderInfo{
		"cloudflare": {
			Name:        "Cloudflare",
			Description: "Cloudflare DNS",
			ConfigFields: []DNSConfigField{
				{Name: "api_token", Label: "API Token", Type: "password", Required: true, Help: "Cloudflare API Token（需要 Zone:DNS:Edit 权限）"},
			},
		},
		"alidns": {
			Name:        "阿里云 DNS",
			Description: "Alibaba Cloud DNS",
			ConfigFields: []DNSConfigField{
				{Name: "access_key_id", Label: "Access Key ID", Type: "text", Required: true, Help: "阿里云 AccessKey ID"},
				{Name: "access_key_secret", Label: "Access Key Secret", Type: "password", Required: true, Help: "阿里云 AccessKey Secret"},
			},
		},
		"tencentcloud": {
			Name:        "腾讯云 DNSPod",
			Description: "Tencent Cloud DNSPod",
			ConfigFields: []DNSConfigField{
				{Name: "secret_id", Label: "Secret ID", Type: "text", Required: true, Help: "腾讯云 SecretId"},
				{Name: "secret_key", Label: "Secret Key", Type: "password", Required: true, Help: "腾讯云 SecretKey"},
			},
		},
	}
}

// DNSProviderInfo DNS提供商信息
type DNSProviderInfo struct {
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	ConfigFields []DNSConfigField `json:"config_fields"`
}

// DNSConfigField DNS配置字段
type DNSConfigField struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Type     string `json:"type"` // text, password
	Required bool   `json:"required"`
	Help     string `json:"help"`
}

// createDNSProvider 根据配置创建DNS提供商
func (m *Manager) createDNSProvider() (challenge.Provider, error) {
	provider := m.config.DNSProvider
	configJSON := m.config.DNSConfig

	if provider == "" {
		return nil, fmt.Errorf("DNS provider not configured")
	}

	// 解析配置JSON
	var configMap map[string]string
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &configMap); err != nil {
			return nil, fmt.Errorf("failed to parse DNS config: %v", err)
		}
	} else {
		configMap = make(map[string]string)
	}

	switch provider {
	case "cloudflare":
		apiToken := configMap["api_token"]
		if apiToken == "" {
			return nil, fmt.Errorf("Cloudflare API token is required")
		}
		// 设置环境变量供 lego 使用
		os.Setenv("CF_DNS_API_TOKEN", apiToken)
		return cloudflare.NewDNSProvider()

	case "alidns":
		accessKeyID := configMap["access_key_id"]
		accessKeySecret := configMap["access_key_secret"]
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("Alibaba Cloud AccessKey ID and Secret are required")
		}
		os.Setenv("ALICLOUD_ACCESS_KEY", accessKeyID)
		os.Setenv("ALICLOUD_SECRET_KEY", accessKeySecret)
		return alidns.NewDNSProvider()

	case "tencentcloud":
		secretID := configMap["secret_id"]
		secretKey := configMap["secret_key"]
		if secretID == "" || secretKey == "" {
			return nil, fmt.Errorf("Tencent Cloud SecretId and SecretKey are required")
		}
		os.Setenv("TENCENTCLOUD_SECRET_ID", secretID)
		os.Setenv("TENCENTCLOUD_SECRET_KEY", secretKey)
		return tencentcloud.NewDNSProvider()

	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", provider)
	}
}
