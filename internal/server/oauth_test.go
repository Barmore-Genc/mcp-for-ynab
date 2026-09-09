package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
)

const (
	testUser     = "budgeteer"
	testPass     = "correct-horse-battery"
	testRedirect = "http://127.0.0.1:33418/callback"
	testVerifier = "verifier-0123456789-0123456789-0123456789"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := config.Config{
		YNABToken: "ynab-token",
		Username:  testUser,
		Password:  testPass,
		Origin:    "https://ynab.example",
	}
	srv := New(cfg, oauth.NewSigner("signing-secret"), http.NotFoundHandler())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// noRedirect keeps the test in control of the /authorize redirect so the code
// can be read off the Location header instead of being chased to a callback
// that does not exist.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func challenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func register(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{testRedirect},
		"client_name":   "Test Agent",
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d", resp.StatusCode)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.ClientID == "" {
		t.Fatal("register returned no client_id")
	}
	return out.ClientID
}

func authorizeForm(clientID string) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"state":                 {"state-123"},
		"code_challenge":        {challenge()},
		"code_challenge_method": {"S256"},
		"response_type":         {"code"},
		"scope":                 {scopeYNAB},
	}
}

func signIn(t *testing.T, ts *httptest.Server, clientID, user, pass string) *http.Response {
	t.Helper()
	form := authorizeForm(clientID)
	form.Set("username", user)
	form.Set("password", pass)
	form.Set("decision", "allow")
	resp, err := noRedirect().PostForm(ts.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func codeFrom(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected a redirect, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "state-123" {
		t.Fatalf("state not echoed back, got %q", got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", loc)
	}
	return code
}

func exchange(t *testing.T, ts *httptest.Server, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(ts.URL+"/token", form)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &out)
	return resp, out
}

func codeForm(clientID, code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {testVerifier},
	}
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	code := codeFrom(t, signIn(t, ts, clientID, testUser, testPass))

	resp, out := exchange(t, ts, codeForm(clientID, code))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status %d: %v", resp.StatusCode, out)
	}
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("token response missing credentials: %v", out)
	}
	signer := oauth.NewSigner("signing-secret")
	if _, err := signer.Verify(access, oauth.KindAccess); err != nil {
		t.Fatalf("issued access token does not verify: %v", err)
	}

	resp, out = exchange(t, ts, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status %d: %v", resp.StatusCode, out)
	}
	if out["access_token"] == "" {
		t.Fatalf("refresh returned no access token: %v", out)
	}
}

func TestAuthorizeRendersLoginForm(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	resp, err := http.Get(ts.URL + "/authorize?" + authorizeForm(clientID).Encode())
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `name="password"`) {
		t.Fatalf("login form not rendered: %s", body)
	}
	// The client's own name is what tells the operator who is asking.
	if !strings.Contains(string(body), "Test Agent") {
		t.Fatalf("client name not shown: %s", body)
	}
}

func TestWrongPasswordDoesNotIssueCode(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	resp := signIn(t, ts, clientID, testUser, "wrong-password-here")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("a failed sign-in redirected to %s", loc)
	}
}

func TestRepeatedWrongPasswordIsRateLimited(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	for range maxAttempts {
		signIn(t, ts, clientID, testUser, "wrong-password-here")
	}
	if got := signIn(t, ts, clientID, testUser, testPass).StatusCode; got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", maxAttempts, got)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	code := codeFrom(t, signIn(t, ts, clientID, testUser, testPass))

	if resp, out := exchange(t, ts, codeForm(clientID, code)); resp.StatusCode != http.StatusOK {
		t.Fatalf("first exchange failed: %d %v", resp.StatusCode, out)
	}
	resp, out := exchange(t, ts, codeForm(clientID, code))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a redeemed code was accepted a second time: %v", out)
	}
}

func TestTokenRejectsWrongPKCEVerifier(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	code := codeFrom(t, signIn(t, ts, clientID, testUser, testPass))
	form := codeForm(clientID, code)
	form.Set("code_verifier", "some-other-verifier-000000000000000000000")
	if resp, out := exchange(t, ts, form); resp.StatusCode == http.StatusOK {
		t.Fatalf("PKCE mismatch accepted: %v", out)
	}
}

func TestTokenRejectsMismatchedRedirectURI(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	code := codeFrom(t, signIn(t, ts, clientID, testUser, testPass))
	form := codeForm(clientID, code)
	form.Set("redirect_uri", "http://127.0.0.1:33418/other")
	if resp, out := exchange(t, ts, form); resp.StatusCode == http.StatusOK {
		t.Fatalf("redirect_uri mismatch accepted: %v", out)
	}
}

// An unregistered redirect_uri must render an error rather than redirect to it,
// which is the open redirect the exact-match check exists to prevent.
func TestAuthorizeRefusesUnregisteredRedirect(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	form := authorizeForm(clientID)
	form.Set("redirect_uri", "https://attacker.example/callback")
	resp, err := noRedirect().Get(ts.URL + "/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (Location: %q)", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRegisterRefusesNonLoopbackHTTPRedirect(t *testing.T) {
	ts := newTestServer(t)
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{"http://attacker.example/cb"}})
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorizeRequiresS256(t *testing.T) {
	ts := newTestServer(t)
	clientID := register(t, ts)
	form := authorizeForm(clientID)
	form.Set("code_challenge_method", "plain")
	resp, err := noRedirect().Get(ts.URL + "/authorize?" + form.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("plain PKCE was not refused, redirected to %q (status %d)", loc, resp.StatusCode)
	}
}

func TestMetadataEndpoints(t *testing.T) {
	ts := newTestServer(t)
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/mcp",
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(out) == 0 {
			t.Fatalf("%s returned %d %v", path, resp.StatusCode, out)
		}
	}
}
