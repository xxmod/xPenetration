//go:build !acme
// +build !acme

package server

import (
	"net/http"

	"xpenetration/internal/config"
)

type acmeProviderStub struct {
	ws *WebServer
}

func newACMEProvider(ws *WebServer) acmeProvider {
	return &acmeProviderStub{ws: ws}
}

func (p *acmeProviderStub) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/acme/status", p.handleStatus)
	mux.HandleFunc("/api/acme/config", p.handleConfig)
	mux.HandleFunc("/api/acme/obtain", p.handleDisabled)
	mux.HandleFunc("/api/acme/renew", p.handleDisabled)
	mux.HandleFunc("/api/acme/ca-servers", p.handleEmptyList)
	mux.HandleFunc("/api/acme/dns-providers", p.handleEmptyList)
}

func (p *acmeProviderStub) init(cfg *config.ServerConfig) {}

func (p *acmeProviderStub) stop() {}

func (p *acmeProviderStub) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.ws.writeJSON(w, map[string]interface{}{
		"available":  false,
		"enabled":    false,
		"configured": false,
		"message":    "ACME module not included in this build",
	})
}

func (p *acmeProviderStub) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p.ws.writeJSON(w, map[string]interface{}{
			"available": false,
			"enabled":   false,
		})
		return
	}

	http.Error(w, "ACME module not included in this build", http.StatusNotImplemented)
}

func (p *acmeProviderStub) handleDisabled(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "ACME module not included in this build", http.StatusNotImplemented)
}

func (p *acmeProviderStub) handleEmptyList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.ws.writeJSON(w, map[string]interface{}{})
}
