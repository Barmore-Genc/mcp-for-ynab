package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
)

func newHandler(t *testing.T, signer *oauth.Signer) http.Handler {
	t.Helper()
	api, err := ynab.NewAPIAt("test-token", "http://ynab.invalid")
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	return New(api, signer, "https://ynab.example", "test", false).Handler()
}

// An unauthenticated call has to be refused before it reaches a tool, and the
// refusal has to say where to authenticate — that header is what starts the
// OAuth discovery an MCP client does.
func TestUnauthenticatedRequestIsRefusedWithDiscovery(t *testing.T) {
	ts := httptest.NewServer(newHandler(t, oauth.NewSigner("secret")))
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if want := "oauth-protected-resource"; !strings.Contains(resp.Header.Get("WWW-Authenticate"), want) {
		t.Fatalf("WWW-Authenticate does not point at the metadata: %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestTokenFromAnotherKeyIsRefused(t *testing.T) {
	ts := httptest.NewServer(newHandler(t, oauth.NewSigner("secret")))
	defer ts.Close()

	forged := oauth.NewSigner("someone else's key").Mint(oauth.Payload{Kind: oauth.KindAccess, ClientID: "c1"}, time.Hour)
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+forged)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// A refresh token is not an access token, even though the same key signed it.
func TestRefreshTokenIsNotAccepted(t *testing.T) {
	signer := oauth.NewSigner("secret")
	ts := httptest.NewServer(newHandler(t, signer))
	defer ts.Close()

	refresh := signer.Mint(oauth.Payload{Kind: oauth.KindRefresh, ClientID: "c1"}, time.Hour)
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+refresh)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}
