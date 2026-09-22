package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/oidc"
	"github.com/go-jose/go-jose/v4"
)

const (
	idpSubject = "user-1"
	idpEmail   = "budgeteer@example.com"
)

// fakeIDP is a minimal OpenID provider: discovery, a JWKS, an authorization
// endpoint that hands out codes, and a token endpoint that returns a signed ID
// token. It is enough for go-oidc to treat it as real, which is the point.
type fakeIDP struct {
	ts      *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	subject string
	email   string

	mu    sync.Mutex
	codes map[string]authRequest
}

type authRequest struct {
	Nonce       string
	Challenge   string
	RedirectURI string
	ClientID    string
	Subject     string
	Email       string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	f := &fakeIDP{key: key, kid: "test-key", subject: idpSubject, email: idpEmail, codes: map[string]authRequest{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeIDP) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                f.ts.URL,
		"authorization_endpoint":                f.ts.URL + "/authorize",
		"token_endpoint":                        f.ts.URL + "/token",
		"jwks_uri":                              f.ts.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	})
}

func (f *fakeIDP) jwks(w http.ResponseWriter, r *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       f.key.Public(),
		KeyID:     f.kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	writeJSON(w, http.StatusOK, set)
}

func (f *fakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	code := oauth.RandomID()
	f.mu.Lock()
	f.codes[code] = authRequest{
		Nonce:       q.Get("nonce"),
		Challenge:   q.Get("code_challenge"),
		RedirectURI: redirect,
		ClientID:    q.Get("client_id"),
		Subject:     f.subject,
		Email:       f.email,
	}
	f.mu.Unlock()

	u, _ := url.Parse(redirect)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", q.Get("state"))
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	f.mu.Lock()
	req, ok := f.codes[r.PostFormValue("code")]
	delete(f.codes, r.PostFormValue("code"))
	f.mu.Unlock()
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown code")
		return
	}
	if req.Challenge != "" {
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != req.Challenge {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE failed")
			return
		}
	}
	if got := r.PostFormValue("redirect_uri"); got != req.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "idp-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     f.idToken(req),
	})
}

func (f *fakeIDP) idToken(req authRequest) string {
	claims, _ := json.Marshal(map[string]any{
		"iss":            f.ts.URL,
		"sub":            req.Subject,
		"aud":            req.ClientID,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"nonce":          req.Nonce,
		"email":          req.Email,
		"email_verified": true,
	})
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: f.key, KeyID: f.kid}},
		&jose.SignerOptions{},
	)
	if err != nil {
		panic(err)
	}
	obj, err := signer.Sign(claims)
	if err != nil {
		panic(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func newOIDCTestServer(t *testing.T, issuer string, allowedEmails ...string) *httptest.Server {
	t.Helper()
	cfg := config.Config{
		YNABToken:  "ynab-token",
		Origin:     "https://ynab.example",
		SigningKey: "signing-secret",
		OIDC: &oidc.Config{
			Issuer:        issuer,
			ClientID:      "mcp-for-ynab",
			RedirectURI:   "https://ynab.example/oidc/callback",
			Name:          "Pocket ID",
			AllowedEmails: allowedEmails,
		},
	}
	srv := New(cfg, oauth.NewSigner("signing-secret"), http.NotFoundHandler())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// signInThroughProvider walks the whole delegated flow the way a browser and
// an MCP client would: consent locally, get redirected to the provider, come
// back through the callback, and receive the local authorization code.
func signInThroughProvider(t *testing.T, ts *httptest.Server, idp *fakeIDP, clientID string) *http.Response {
	t.Helper()
	form := authorizeForm(clientID)
	form.Set("decision", "allow")
	resp, err := noRedirect().PostForm(ts.URL+"/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected a redirect to the provider, got %d", resp.StatusCode)
	}

	authURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("provider location: %v", err)
	}
	if want, _ := url.Parse(idp.ts.URL); authURL.Host != want.Host {
		t.Fatalf("redirected to %q rather than the provider", authURL)
	}
	q := authURL.Query()
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("provider request missing state, nonce or PKCE: %v", q)
	}

	// The provider authenticates the person and sends the browser back to the
	// configured callback. The test server's real address stands in for the
	// public MCP_ORIGIN, so re-point the redirect without touching the query.
	idpResp, err := noRedirect().Get(authURL.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	defer idpResp.Body.Close()
	if idpResp.StatusCode != http.StatusFound {
		t.Fatalf("provider did not redirect back, got %d", idpResp.StatusCode)
	}
	cbURL, err := url.Parse(idpResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("callback location: %v", err)
	}
	origin, _ := url.Parse(ts.URL)
	cbURL.Scheme, cbURL.Host = origin.Scheme, origin.Host
	if cbURL.Path != "/oidc/callback" {
		t.Fatalf("provider redirected to %s, not the callback", cbURL.Path)
	}

	cbResp, err := noRedirect().Get(cbURL.String())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return cbResp
}

func TestOIDCSignInIssuesWorkingTokens(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL)
	clientID := register(t, ts)

	code := codeFrom(t, signInThroughProvider(t, ts, idp, clientID))
	resp, out := exchange(t, ts, codeForm(clientID, code))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status %d: %v", resp.StatusCode, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("token response missing credentials: %v", out)
	}
	if _, err := oauth.NewSigner("signing-secret").Verify(access, oauth.KindAccess); err != nil {
		t.Fatalf("issued access token does not verify: %v", err)
	}
}

func TestOIDCLoginFormOffersProvider(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL)
	clientID := register(t, ts)

	resp, err := http.Get(ts.URL + "/authorize?" + authorizeForm(clientID).Encode())
	if err != nil {
		t.Fatalf("get authorize: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	if !strings.Contains(body, "Continue with Pocket ID") {
		t.Fatalf("provider not offered on the sign-in page: %s", body)
	}
	// The password fields have no place once a provider owns the sign-in.
	if strings.Contains(body, `name="password"`) {
		t.Fatalf("password field still rendered in OIDC mode: %s", body)
	}
}

func TestOIDCDeniesUnlistedIdentity(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL, "someone-else@example.com")
	clientID := register(t, ts)

	resp := signInThroughProvider(t, ts, idp, clientID)
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("unlisted identity was not refused, redirected to %q", loc)
	}
}

// A callback whose signed state does not verify must not be able to mint a
// code, which is what stops a forged callback from logging anyone in.
func TestOIDCCallbackRejectsForgedState(t *testing.T) {
	idp := newFakeIDP(t)
	ts := newOIDCTestServer(t, idp.ts.URL)
	register(t, ts)

	resp, err := noRedirect().Get(ts.URL + "/oidc/callback?state=forged&code=abc")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state accepted, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("forged state redirected to %q", loc)
	}
}
