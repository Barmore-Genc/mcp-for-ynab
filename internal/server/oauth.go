package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
)

// scopeYNAB is the only scope. There is one user and one YNAB token behind this
// server, so there is nothing for a second scope to express; MCP_READ_ONLY,
// which is the operator's call rather than the client's, is what narrows access.
const scopeYNAB = "ynab"

func (s *Server) registerOAuthRoutes() {
	// RFC 9728 protected-resource metadata, and RFC 8414 authorization-server
	// metadata. Both are served at the bare well-known path and at the /mcp
	// path-insertion variant, because clients probe for either.
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleResourceMetadata)
	s.mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.handleResourceMetadata)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthServerMetadata)
	s.mux.HandleFunc("/.well-known/oauth-authorization-server/mcp", s.handleAuthServerMetadata)

	s.mux.HandleFunc("POST /register", s.handleRegister)
	s.mux.HandleFunc("GET /authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /authorize", s.handleAuthorizeSubmit)
	s.mux.HandleFunc("POST /token", s.handleToken)
}

func (s *Server) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if corsPreflight(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.cfg.Origin + "/mcp",
		"authorization_servers":    []string{s.cfg.Origin},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{scopeYNAB},
	})
}

func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if corsPreflight(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Origin,
		"authorization_endpoint":                s.cfg.Origin + "/authorize",
		"token_endpoint":                        s.cfg.Origin + "/token",
		"registration_endpoint":                 s.cfg.Origin + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{scopeYNAB},
	})
}

// registrationRequest is the subset of RFC 7591 client metadata this server
// reads. Anything else a client sends is ignored rather than rejected.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// handleRegister is dynamic client registration (RFC 7591), unauthenticated as
// the MCP spec requires. The client id it returns is a signed credential
// carrying the registration itself, so registering stores nothing.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed registration body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"redirect_uri must be https or a loopback http address")
			return
		}
	}
	// This server only issues public clients bound by PKCE, so a client asking
	// for a secret-based method is refused rather than silently downgraded.
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata",
			"only token_endpoint_auth_method=none is supported")
		return
	}
	id := s.signer.Mint(oauth.Payload{
		Kind:         oauth.KindClient,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
	}, 0)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              req.RedirectURIs,
		"client_name":                req.ClientName,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      scopeYNAB,
	})
}

// authorizeParams is a validated /authorize request, shared by the form render
// and the form submission.
type authorizeParams struct {
	ClientID    string
	ClientName  string
	RedirectURI string
	State       string
	Challenge   string
	Scope       string
}

// validateAuthorize checks an authorize request. A bad client_id or
// redirect_uri returns redirectOK=false and must render an error page: sending
// the error to an unvalidated redirect_uri is the open redirect the exact-match
// check exists to prevent. Anything else may travel back to the client.
func (s *Server) validateAuthorize(v url.Values) (p authorizeParams, redirectOK bool, errMsg string) {
	client, err := s.signer.Verify(v.Get("client_id"), oauth.KindClient)
	if err != nil {
		return p, false, "unknown client"
	}
	redirectURI := v.Get("redirect_uri")
	// Exact string match against the registered set: no normalization, prefix
	// or wildcard.
	if !exactContains(client.RedirectURIs, redirectURI) {
		return p, false, "redirect_uri does not match a registered value"
	}
	p = authorizeParams{
		ClientID:    v.Get("client_id"),
		ClientName:  client.ClientName,
		RedirectURI: redirectURI,
		State:       v.Get("state"),
		Challenge:   v.Get("code_challenge"),
		Scope:       v.Get("scope"),
	}
	switch {
	case v.Get("response_type") != "code":
		return p, true, "unsupported_response_type"
	case p.State == "":
		return p, true, "state is required"
	case p.Challenge == "":
		return p, true, "code_challenge is required"
	case v.Get("code_challenge_method") != "S256":
		return p, true, "code_challenge_method must be S256"
	}
	return p, true, ""
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	p, redirectOK, errMsg := s.validateAuthorize(r.URL.Query())
	if errMsg != "" {
		s.authorizeError(w, r, p, redirectOK, errMsg)
		return
	}
	renderLogin(w, p, "")
}

// handleAuthorizeSubmit is the login form. There is no session cookie and no
// separate consent step: the operator proves who they are by typing the
// credentials from the container's environment, and doing so on a form that
// names the client asking is the consent.
func (s *Server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "malformed form")
		return
	}
	p, redirectOK, errMsg := s.validateAuthorize(r.PostForm)
	if errMsg != "" {
		s.authorizeError(w, r, p, redirectOK, errMsg)
		return
	}
	if r.PostFormValue("decision") == "deny" {
		redirectAuthError(w, r, p, "access_denied")
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		renderErrorPage(w, http.StatusTooManyRequests, "too many sign-in attempts, wait a minute and try again")
		return
	}
	if !s.checkCredentials(r.PostFormValue("username"), r.PostFormValue("password")) {
		// The form is re-rendered rather than redirected so the request keeps
		// its parameters without them landing in browser history.
		w.WriteHeader(http.StatusUnauthorized)
		renderLogin(w, p, "Wrong username or password.")
		return
	}
	s.limiter.reset(clientIP(r))
	code := s.signer.Mint(oauth.Payload{
		Kind:        oauth.KindCode,
		ClientID:    p.ClientID,
		RedirectURI: p.RedirectURI,
		Challenge:   p.Challenge,
		Scope:       scopeYNAB,
	}, oauth.CodeTTL)
	redirectWithCode(w, r, p, code)
}

// checkCredentials compares both fields in constant time. They are hashed
// first so the comparison is over fixed-length values and cannot be timed for
// the length of the real password.
func (s *Server) checkCredentials(user, pass string) bool {
	okUser := subtle.ConstantTimeCompare(hash(user), hash(s.cfg.Username))
	okPass := subtle.ConstantTimeCompare(hash(pass), hash(s.cfg.Password))
	return okUser&okPass == 1
}

func hash(v string) []byte {
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	p, err := s.signer.Verify(r.PostFormValue("code"), oauth.KindCode)
	if err != nil {
		// Unknown, expired and already-redeemed all read the same, because the
		// difference is only useful to someone replaying codes.
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	if r.PostFormValue("client_id") != p.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	// The redirect_uri must match the one the code was issued against (RFC 6749
	// 4.1.3), so a code stolen mid-flight cannot be redeemed toward another
	// endpoint.
	if r.PostFormValue("redirect_uri") != p.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !oauth.VerifyS256(r.PostFormValue("code_verifier"), p.Challenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if !s.signer.Redeem(p) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	s.issueTokens(w, p.ClientID)
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	p, err := s.signer.Verify(r.PostFormValue("refresh_token"), oauth.KindRefresh)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	if r.PostFormValue("client_id") != p.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	s.issueTokens(w, p.ClientID)
}

// issueTokens writes the RFC 6749 5.1 success body. Refresh tokens are not
// rotated: rotation needs a record of which token is current, and this server
// keeps no such record. Changing MCP_PASSWORD (or MCP_SIGNING_KEY) is what
// revokes an outstanding one.
func (s *Server) issueTokens(w http.ResponseWriter, clientID string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  s.signer.Mint(oauth.Payload{Kind: oauth.KindAccess, ClientID: clientID, Scope: scopeYNAB}, oauth.AccessTTL),
		"token_type":    "Bearer",
		"expires_in":    int(oauth.AccessTTL / time.Second),
		"refresh_token": s.signer.Mint(oauth.Payload{Kind: oauth.KindRefresh, ClientID: clientID, Scope: scopeYNAB}, oauth.RefreshTTL),
		"scope":         scopeYNAB,
	})
}

func (s *Server) authorizeError(w http.ResponseWriter, r *http.Request, p authorizeParams, redirectOK bool, msg string) {
	if !redirectOK {
		renderErrorPage(w, http.StatusBadRequest, msg)
		return
	}
	code := "invalid_request"
	if msg == "unsupported_response_type" {
		code = msg
	}
	redirectAuthError(w, r, p, code)
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, p authorizeParams, code string) {
	redirectBack(w, r, p, url.Values{"code": {code}, "state": {p.State}})
}

func redirectAuthError(w http.ResponseWriter, r *http.Request, p authorizeParams, code string) {
	v := url.Values{"error": {code}}
	if p.State != "" {
		v.Set("state", p.State)
	}
	redirectBack(w, r, p, v)
}

func redirectBack(w http.ResponseWriter, r *http.Request, p authorizeParams, add url.Values) {
	u, err := url.Parse(p.RedirectURI)
	if err != nil {
		renderErrorPage(w, http.StatusBadRequest, "invalid redirect_uri")
		return
	}
	q := u.Query()
	for k, vs := range add {
		q.Set(k, vs[0])
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeOAuthError writes an RFC 6749 error body. These reach the OAuth client
// rather than a person, so the text is developer-facing.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

// validRedirectURI accepts https URLs and loopback http URLs, which is what
// native clients and Claude Code use for their callback.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	default:
		return false
	}
}

func exactContains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func corsPreflight(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// clientIP identifies a caller for rate limiting. X-Forwarded-For is trusted
// because this is meant to sit behind a reverse proxy; a caller that can forge
// the header can already reach the login form directly, and the limiter is a
// brute-force speed bump rather than an access control.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
