// Command mcp-for-ynab serves one YNAB budget as an MCP endpoint over HTTP,
// with its own OAuth 2.1 authorization server in front of it because that is
// the only way AI agent harnesses know how to connect.
//
// Everything it needs comes from the environment and nothing is written to
// disk, so the container is the whole deployment.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/mcpserver"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/server"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
)

// version is set by the build: the git tag in a release, dev-<date> otherwise.
var version = "dev"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	api, err := ynab.NewAPI(cfg.YNABToken)
	if err != nil {
		log.Fatalf("YNAB client: %v", err)
	}
	// Without an explicit signing key the password is the secret. That ties the
	// credentials to it deliberately: changing the password is then also how an
	// operator revokes every token that was issued under the old one.
	secret := cfg.SigningKey
	if secret == "" {
		secret = cfg.Password
	}
	signer := oauth.NewSigner(secret)

	mcpSrv := mcpserver.New(api, signer, cfg.Origin, version, cfg.ReadOnly)
	srv := server.New(cfg, signer, mcpSrv.Handler())

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdown)
	}()

	mode := "read and write"
	if cfg.ReadOnly {
		mode = "read only"
	}
	log.Printf("mcp-for-ynab %s listening on %s, serving %s/mcp (%s)", version, cfg.Addr, cfg.Origin, mode)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http server: %v", err)
	}
}
