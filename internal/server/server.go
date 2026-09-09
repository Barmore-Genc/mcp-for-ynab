// Package server is the HTTP surface of the container: the OAuth 2.1
// authorization server, the sign-in page it renders, and the mount point for
// the MCP endpoint.
package server

import (
	"net/http"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
)

type Server struct {
	cfg     config.Config
	signer  *oauth.Signer
	limiter *limiter
	mux     *http.ServeMux
}

// New wires the routes. mcpHandler serves /mcp and is expected to do its own
// bearer check against the same signer.
func New(cfg config.Config, signer *oauth.Signer, mcpHandler http.Handler) *Server {
	s := &Server{cfg: cfg, signer: signer, limiter: newLimiter(), mux: http.NewServeMux()}
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
