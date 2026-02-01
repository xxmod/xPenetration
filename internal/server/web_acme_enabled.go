//go:build acme
// +build acme

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"xpenetration/internal/acme"
	"xpenetration/internal/config"
)

type acmeProviderImpl struct {
	ws              *WebServer
	manager         *acme.Manager
	challengeServer *http.Server
}

func newACMEProvider(ws *WebServer) acmeProvider {
	return &acmeProviderImpl{ws: ws}
}

func (p *acmeProviderImpl) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/acme/status", p.handleACMEStatus)
	mux.HandleFunc("/api/acme/config", p.handleACMEConfig)
	mux.HandleFunc("/api/acme/obtain", p.handleACMEObtain)
	mux.HandleFunc("/api/acme/renew", p.handleACMERenew)
	mux.HandleFunc("/api/acme/ca-servers", p.handleACMECAServers)
	mux.HandleFunc("/api/acme/dns-providers", p.handleACMEDNSProviders)
}

func (p *acmeProviderImpl) init(cfg *config.ServerConfig) {
	if cfg == nil || cfg.ACME == nil || !cfg.ACME.Enabled {
		return
	}

	acmeCfg := &acme.ACMEConfig{
		Enabled:       cfg.ACME.Enabled,
		Email:         cfg.ACME.Email,
		Domains:       cfg.ACME.Domains,
		CAServer:      cfg.ACME.CAServer,
		AcceptTOS:     cfg.ACME.AcceptTOS,
		RenewBefore:   cfg.ACME.RenewBefore,
		HTTPPort:      cfg.ACME.HTTPPort,
		DataDir:       cfg.ACME.DataDir,
		AutoRenew:     cfg.ACME.AutoRenew,
		RenewInterval: cfg.ACME.RenewInterval,
		EABEnabled:    cfg.ACME.EABEnabled,
		EABKid:        cfg.ACME.EABKid,
		EABHmacKey:    cfg.ACME.EABHmacKey,
		ChallengeType: cfg.ACME.ChallengeType,
		DNSProvider:   cfg.ACME.DNSProvider,
		DNSConfig:     cfg.ACME.DNSConfig,
	}

	p.manager = acme.NewManager(acmeCfg)
	p.manager.SetOnCertRenewed(func(certFile, keyFile string) {
		log.Printf("[ACME] Certificate renewed, updating WebTLS config...")
		p.updateWebTLSFromACME(certFile, keyFile)
	})

	if err := p.manager.Initialize(); err != nil {
		log.Printf("[ACME] Failed to initialize: %v", err)
		return
	}

	if cfg.ACME.HTTPPort > 0 {
		go p.startACMEChallengeServer(cfg.ACME.HTTPPort)
	}

	p.manager.Start()

	if certInfo := p.manager.GetCertificateInfo(); certInfo != nil {
		p.updateWebTLSFromACME(certInfo.CertFile, certInfo.KeyFile)
	}
}

func (p *acmeProviderImpl) stop() {
	if p.manager != nil {
		p.manager.Stop()
	}

	if p.challengeServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.challengeServer.Shutdown(ctx)
	}
}

func (p *acmeProviderImpl) startACMEChallengeServer(port int) {
	if p.manager == nil {
		return
	}

	challengeProvider := p.manager.GetChallengeProvider()
	if challengeProvider == nil {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		keyAuth, ok := challengeProvider.GetToken(token)
		if !ok {
			log.Printf("[ACME] Challenge token not found: %s", token)
			http.NotFound(w, r)
			return
		}
		log.Printf("[ACME] Serving challenge response for token: %s", token)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(keyAuth))
	})

	addr := fmt.Sprintf(":%d", port)
	p.challengeServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("[ACME] HTTP-01 challenge server listening on %s", addr)
	if err := p.challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[ACME] Challenge server error: %v", err)
	}
}

func (p *acmeProviderImpl) updateWebTLSFromACME(certFile, keyFile string) {
	p.ws.mu.Lock()
	defer p.ws.mu.Unlock()

	cfg := p.ws.server.GetConfig()
	if cfg == nil {
		return
	}

	if _, err := os.Stat(certFile); err != nil {
		log.Printf("[ACME] Certificate file not found: %s", certFile)
		return
	}
	if _, err := os.Stat(keyFile); err != nil {
		log.Printf("[ACME] Key file not found: %s", keyFile)
		return
	}

	if cfg.Server.WebTLS == nil {
		cfg.Server.WebTLS = &config.WebTLS{}
	}
	cfg.Server.WebTLS.Enabled = true
	cfg.Server.WebTLS.CertFile = certFile
	cfg.Server.WebTLS.KeyFile = keyFile

	if err := config.SaveServerConfig(p.ws.configPath, cfg); err != nil {
		log.Printf("[ACME] Failed to save WebTLS config: %v", err)
		return
	}

	log.Printf("[ACME] WebTLS config updated with ACME certificate")
}

func (p *acmeProviderImpl) handleACMEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if p.manager == nil {
		p.ws.writeJSON(w, map[string]interface{}{
			"available":  true,
			"enabled":    false,
			"configured": false,
			"message":    "ACME not initialized",
		})
		return
	}

	status := p.manager.GetStatus()
	status.Enabled = status.Enabled || (p.manager != nil)
	p.ws.writeJSON(w, status)
}

func (p *acmeProviderImpl) handleACMEConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.handleACMEConfigGet(w, r)
	case http.MethodPost:
		p.handleACMEConfigPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *acmeProviderImpl) handleACMEConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg := p.ws.server.GetConfig()
	if cfg == nil || cfg.ACME == nil {
		p.ws.writeJSON(w, &config.ACMESettings{})
		return
	}
	p.ws.writeJSON(w, cfg.ACME)
}

func (p *acmeProviderImpl) handleACMEConfigPost(w http.ResponseWriter, r *http.Request) {
	var newACMEConfig config.ACMESettings
	if err := json.NewDecoder(r.Body).Decode(&newACMEConfig); err != nil {
		http.Error(w, "Invalid config format", http.StatusBadRequest)
		return
	}

	p.ws.mu.Lock()
	defer p.ws.mu.Unlock()

	cfg := p.ws.server.GetConfig()
	if cfg == nil {
		http.Error(w, "Server config not found", http.StatusInternalServerError)
		return
	}

	cfg.ACME = &newACMEConfig

	if err := config.SaveServerConfig(p.ws.configPath, cfg); err != nil {
		log.Printf("[ACME] Failed to save config: %v", err)
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	if p.manager != nil {
		p.manager.Stop()
	}

	p.manager = nil
	if newACMEConfig.Enabled {
		acmeCfg := &acme.ACMEConfig{
			Enabled:       newACMEConfig.Enabled,
			Email:         newACMEConfig.Email,
			Domains:       newACMEConfig.Domains,
			CAServer:      newACMEConfig.CAServer,
			AcceptTOS:     newACMEConfig.AcceptTOS,
			RenewBefore:   newACMEConfig.RenewBefore,
			HTTPPort:      newACMEConfig.HTTPPort,
			DataDir:       newACMEConfig.DataDir,
			AutoRenew:     newACMEConfig.AutoRenew,
			RenewInterval: newACMEConfig.RenewInterval,
			EABEnabled:    newACMEConfig.EABEnabled,
			EABKid:        newACMEConfig.EABKid,
			EABHmacKey:    newACMEConfig.EABHmacKey,
			ChallengeType: newACMEConfig.ChallengeType,
			DNSProvider:   newACMEConfig.DNSProvider,
			DNSConfig:     newACMEConfig.DNSConfig,
		}

		p.manager = acme.NewManager(acmeCfg)
		p.manager.SetOnCertRenewed(func(certFile, keyFile string) {
			log.Printf("[ACME] Certificate renewed, updating WebTLS config...")
			p.updateWebTLSFromACME(certFile, keyFile)
		})

		if err := p.manager.Initialize(); err != nil {
			log.Printf("[ACME] Failed to initialize: %v", err)
			p.ws.writeJSON(w, map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Failed to initialize ACME: %v", err),
			})
			return
		}

		if newACMEConfig.HTTPPort > 0 && p.challengeServer == nil {
			go p.startACMEChallengeServer(newACMEConfig.HTTPPort)
		}

		p.manager.Start()
	}

	log.Printf("[ACME] Config saved and applied")
	p.ws.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "ACME config saved",
	})
}

func (p *acmeProviderImpl) handleACMEObtain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if p.manager == nil {
		http.Error(w, "ACME not initialized", http.StatusBadRequest)
		return
	}

	log.Printf("[ACME] Manual certificate obtain requested")

	go func() {
		if err := p.manager.ObtainCertificate(); err != nil {
			log.Printf("[ACME] Failed to obtain certificate: %v", err)
		}
	}()

	p.ws.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Certificate obtain started, please check status later",
	})
}

func (p *acmeProviderImpl) handleACMERenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if p.manager == nil {
		http.Error(w, "ACME not initialized", http.StatusBadRequest)
		return
	}

	log.Printf("[ACME] Manual certificate renewal requested")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := p.manager.ForceRenew(ctx); err != nil {
			log.Printf("[ACME] Failed to renew certificate: %v", err)
		}
	}()

	p.ws.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Certificate renewal started, please check status later",
	})
}

func (p *acmeProviderImpl) handleACMECAServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	servers := acme.GetCAServers()
	p.ws.writeJSON(w, servers)
}

func (p *acmeProviderImpl) handleACMEDNSProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := acme.GetDNSProviders()
	p.ws.writeJSON(w, providers)
}
