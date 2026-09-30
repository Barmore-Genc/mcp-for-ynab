// Package server is the HTTP surface of the container: the OAuth 2.1
// authorization server, the sign-in page it renders, and the mount point for
// the MCP endpoint.
package server

import (
	"net/http"
	"net/url"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oidc"
)

// maxBodyBytes bounds the OAuth endpoints' request bodies. Their largest
// legitimate input is a registration with a few redirect URIs.
const maxBodyBytes = 64 << 10

type Server struct {
	cfg     config.Config
	signer  *oauth.Signer
	oidc    *oidc.Provider
	limiter *limiter
	mux     *http.ServeMux
	// secureCookies is false only for a loopback http origin, where a browser
	// would drop a Secure cookie.
	secureCookies bool
}

// New wires the routes. mcpHandler serves /mcp and is expected to do its own
// bearer check against the same signer.
func New(cfg config.Config, signer *oauth.Signer, mcpHandler http.Handler) *Server {
	s := &Server{cfg: cfg, signer: signer, limiter: newLimiter(), mux: http.NewServeMux()}
	if u, err := url.Parse(cfg.Origin); err == nil && u.Scheme == "https" {
		s.secureCookies = true
	}
	if cfg.OIDC != nil {
		s.oidc = oidc.New(*cfg.OIDC)
	}
	s.registerOAuthRoutes()
	s.mux.Handle("/mcp", mcpHandler)
	s.mux.Handle("/mcp/", mcpHandler)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, http.StatusOK, "YNAB MCP server",
			"Add "+s.cfg.Origin+"/mcp as a connector in your AI agent. You will be asked to sign in here to allow it.")
	})
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

// HTTPServer returns an http.Server for addr with timeouts suited to this
// handler. There is no WriteTimeout because /mcp holds server-sent event
// streams open for as long as a session lasts.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
