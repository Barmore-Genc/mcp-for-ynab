package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
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

	// The consent form is the one endpoint a browser posts to with the
	// operator's authority, so it refuses submissions made by other sites.
	cop := http.NewCrossOriginProtection()
	if u, err := url.Parse(s.cfg.Origin); err == nil && u.Host != "" {
		if err := cop.AddTrustedOrigin(u.Scheme + "://" + u.Host); err != nil {
			log.Printf("cross-origin protection: %v", err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderErrorPage(w, http.StatusForbidden,
			"This sign-in form was submitted from another website. Start again from your agent.")
	}))

	s.mux.Handle("POST /register", http.MaxBytesHandler(http.HandlerFunc(s.handleRegister), maxBodyBytes))
	s.mux.HandleFunc("GET /authorize", s.handleAuthorize)
	s.mux.Handle("POST /authorize", http.MaxBytesHandler(cop.Handler(http.HandlerFunc(s.handleAuthorizeSubmit)), maxBodyBytes))
	s.mux.Handle("POST /token", http.MaxBytesHandler(http.HandlerFunc(s.handleToken), maxBodyBytes))
	// The callback is where an OIDC provider returns the browser. It exists
	// whether or not a provider is configured so a stale bookmark gets an
	// explanation rather than a 404.
	s.mux.HandleFunc("GET /oidc/callback", s.handleOIDCCallback)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	req.ClientName = cleanClientName(req.ClientName)
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

// validateAuthorize checks an authorize request. Every failure is shown as an
// error page rather than sent to the redirect_uri: anyone can register a client
// with any https redirect, so redirecting on a malformed request would make
// this server an open redirect. The client only hears back once a person has
// acted on the consent page.
func (s *Server) validateAuthorize(v url.Values) (p authorizeParams, errMsg string) {
	client, err := s.signer.Verify(v.Get("client_id"), oauth.KindClient)
	if err != nil {
		return p, "The app is not registered with this server."
	}
	redirectURI := v.Get("redirect_uri")
	// Exact string match against the registered set: no normalization, prefix
	// or wildcard.
	if !exactContains(client.RedirectURIs, redirectURI) {
		return p, "The app asked to be sent somewhere it did not register (redirect_uri does not match)."
	}
	p = authorizeParams{
		ClientID: v.Get("client_id"),
		// Clients registered before names were cleaned at registration still
		// carry the raw name.
		ClientName:  cleanClientName(client.ClientName),
		RedirectURI: redirectURI,
		State:       v.Get("state"),
		Challenge:   v.Get("code_challenge"),
		Scope:       v.Get("scope"),
	}
	switch {
	case v.Get("response_type") != "code":
		return p, "The app sent an invalid sign-in request (response_type must be code)."
	case p.State == "":
		return p, "The app sent an invalid sign-in request (state is required)."
	case p.Challenge == "":
		return p, "The app sent an invalid sign-in request (code_challenge is required)."
	case v.Get("code_challenge_method") != "S256":
		return p, "The app sent an invalid sign-in request (code_challenge_method must be S256)."
	}
	return p, ""
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	p, errMsg := s.validateAuthorize(r.URL.Query())
	if errMsg != "" {
		renderErrorPage(w, http.StatusBadRequest, errMsg)
		return
	}
	s.renderLogin(w, r, http.StatusOK, p, "")
}

// handleAuthorizeSubmit is the consent form. There is no session cookie and no
// separate consent step: with a local password the operator types it here, and
// with OIDC they click through to the provider; either way, submitting a form
// that names where access is sent is the consent.
func (s *Server) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderErrorPage(w, http.StatusBadRequest, "The sign-in form could not be read.")
		return
	}
	p, errMsg := s.validateAuthorize(r.PostForm)
	if errMsg != "" {
		renderErrorPage(w, http.StatusBadRequest, errMsg)
		return
	}
	if r.PostFormValue("decision") == "deny" {
		redirectAuthError(w, r, p, "access_denied")
		return
	}
	// With a provider configured the local password is not consulted at all:
	// the operator continues at the provider and comes back through
	// /oidc/callback with a verified identity.
	if s.oidc != nil {
		s.startOIDC(w, r, p)
		return
	}
	caller := s.clientAddr(r)
	if !s.limiter.allow(caller) {
		renderErrorPage(w, http.StatusTooManyRequests, "Too many sign-in attempts. Wait a minute and try again.")
		return
	}
	if !s.checkCredentials(r.PostFormValue("username"), r.PostFormValue("password")) {
		// The form is re-rendered rather than redirected so the request keeps
		// its parameters without them landing in browser history.
		s.renderLogin(w, r, http.StatusUnauthorized, p, "Wrong username or password.")
		return
	}
	s.limiter.reset(caller)
	redirectWithCode(w, r, p, s.mintCode(p, time.Now()))
}

func (s *Server) mintCode(p authorizeParams, authTime time.Time) string {
	return s.signer.Mint(oauth.Payload{
		Kind:        oauth.KindCode,
		ClientID:    p.ClientID,
		RedirectURI: p.RedirectURI,
		Challenge:   p.Challenge,
		Scope:       scopeYNAB,
		AuthTime:    authTime.Unix(),
	}, oauth.CodeTTL)
}

// startOIDC redirects the browser to the identity provider. Everything the
// callback needs to resume the original request travels in the signed state,
// so the server remembers nothing between the two halves of the flow.
//
// The state is readable by the provider and anyone who sees the URL, so it
// carries no secrets. The upstream nonce and PKCE verifier are derived from the
// state's id with the signing key, and the state is bound to this browser by a
// cookie holding a random value whose hash the state carries. Without that
// binding, someone could start a sign-in themselves and send the provider link
// to the owner, whose sign-in would then deliver a code to the attacker's app.
func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request, p authorizeParams) {
	id := oauth.RandomID()
	binding := oauth.RandomSecret()
	state := s.signer.Mint(oauth.Payload{
		Kind:        oauth.KindOIDC,
		ID:          id,
		ClientID:    p.ClientID,
		RedirectURI: p.RedirectURI,
		Challenge:   p.Challenge,
		Scope:       p.Scope,
		ClientState: p.State,
		Binding:     hashBinding(binding),
	}, oauth.OIDCFlowTTL)
	nonce, verifier := s.upstreamSecrets(id)

	// Discovery is cached but the first sign-in fetches it, and the provider
	// may be slow or down; bound it so the request cannot hang forever.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	authURL, err := s.oidc.AuthCodeURL(ctx, state, nonce, verifier)
	if err != nil {
		log.Printf("oidc: build authorization URL: %q", err.Error())
		renderErrorPage(w, http.StatusBadGateway,
			"Could not reach the identity provider. Check the MCP_OIDC_ settings and that the provider is reachable.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.flowCookieName(id),
		Value:    binding,
		Path:     "/",
		MaxAge:   int(oauth.OIDCFlowTTL / time.Second),
		Secure:   s.secureCookies,
		HttpOnly: true,
		// Lax is what lets the cookie come back on the provider's top-level
		// redirect to the callback, which is a cross-site navigation.
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) upstreamSecrets(stateID string) (nonce, verifier string) {
	return s.signer.Derive("oidc-nonce", stateID), s.signer.Derive("oidc-verifier", stateID)
}

// flowCookieName is per sign-in so two connectors authorizing at once in the
// same browser do not overwrite each other's binding. The __Host- prefix makes
// the browser refuse the cookie unless it is Secure, host-only and at "/", so
// no other site on a parent domain can plant one. It cannot be used on a
// loopback http origin, where the cookie is not Secure.
func (s *Server) flowCookieName(stateID string) string {
	if s.secureCookies {
		return "__Host-mcp-oidc-" + stateID
	}
	return "mcp-oidc-" + stateID
}

func hashBinding(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleOIDCCallback completes the upstream sign-in. It verifies the signed
// state, redeems the code at the provider, checks the ID token and the
// allowlist, and only then mints the local authorization code the MCP client
// has been waiting for.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		renderErrorPage(w, http.StatusNotFound, "This server is not configured for OIDC sign-in.")
		return
	}
	q := r.URL.Query()
	p, err := s.signer.Verify(q.Get("state"), oauth.KindOIDC)
	if err != nil {
		renderErrorPage(w, http.StatusBadRequest,
			"This sign-in link is invalid or has expired. Start again from your agent.")
		return
	}
	// Checked before anything can redirect to the client, so a sign-in started
	// elsewhere never reaches the redirect_uri it names.
	cookie, err := r.Cookie(s.flowCookieName(p.ID))
	if err != nil || p.Binding == "" ||
		subtle.ConstantTimeCompare([]byte(hashBinding(cookie.Value)), []byte(p.Binding)) != 1 {
		renderErrorPage(w, http.StatusForbidden,
			"This sign-in was started in a different browser, or the browser did not keep its cookie. "+
				"Start again from your agent in this browser.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookie.Name,
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.secureCookies,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	ap := authorizeParams{
		ClientID:    p.ClientID,
		RedirectURI: p.RedirectURI,
		State:       p.ClientState,
		Challenge:   p.Challenge,
		Scope:       p.Scope,
	}

	// The provider reports a refusal (or a failed sign-in) as an error query
	// parameter instead of a code.
	if e := q.Get("error"); e != "" {
		log.Printf("oidc: provider returned error %q: %q", e, q.Get("error_description"))
		redirectAuthError(w, r, ap, "access_denied")
		return
	}
	if q.Get("code") == "" {
		redirectAuthError(w, r, ap, "invalid_request")
		return
	}
	// A state is one-time. Without this a callback URL that leaked into a log or
	// history could be replayed for another local code.
	if !s.signer.Redeem(p) {
		renderErrorPage(w, http.StatusBadRequest, "This sign-in has already been completed.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	nonce, verifier := s.upstreamSecrets(p.ID)
	id, err := s.oidc.Exchange(ctx, q.Get("code"), verifier, nonce)
	if err != nil {
		// A failed exchange is the server's problem (provider down, clock skew,
		// bad client secret), not a denial by the person signing in.
		log.Printf("oidc: exchange: %q", err.Error())
		redirectAuthError(w, r, ap, "server_error")
		return
	}
	if !s.oidc.Allowed(id) {
		log.Printf("oidc: refused sign-in for subject %q (email %q, verified %t)", id.Subject, id.Email, id.EmailVerified)
		redirectAuthError(w, r, ap, "access_denied")
		return
	}
	log.Printf("oidc: subject %q (email %q) signed in", id.Subject, id.Email)
	redirectWithCode(w, r, ap, s.mintCode(ap, time.Now()))
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
	s.issueTokens(w, p.ClientID, p.AuthTime)
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
	// A refresh token from before sign-in times were recorded has no AuthTime
	// and is refused, which costs its holder one sign-in.
	if p.AuthTime == 0 || time.Since(time.Unix(p.AuthTime, 0)) >= oauth.MaxSessionAge {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "sign-in is too old, authorize again")
		return
	}
	s.issueTokens(w, p.ClientID, p.AuthTime)
}

// issueTokens writes the RFC 6749 5.1 success body. Refresh tokens are not
// rotated: rotation needs a record of which token is current, and this server
// keeps no such record. Changing MCP_SIGNING_KEY revokes every outstanding one
// at once; otherwise each stops working MaxSessionAge after the sign-in it
// descends from.
func (s *Server) issueTokens(w http.ResponseWriter, clientID string, authTime int64) {
	remaining := time.Until(time.Unix(authTime, 0).Add(oauth.MaxSessionAge))
	accessTTL := min(oauth.AccessTTL, remaining)
	refreshTTL := min(oauth.RefreshTTL, remaining)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": s.signer.Mint(oauth.Payload{
			Kind: oauth.KindAccess, ClientID: clientID, Scope: scopeYNAB,
		}, accessTTL),
		"token_type": "Bearer",
		"expires_in": int(accessTTL / time.Second),
		"refresh_token": s.signer.Mint(oauth.Payload{
			Kind: oauth.KindRefresh, ClientID: clientID, Scope: scopeYNAB, AuthTime: authTime,
		}, refreshTTL),
		"scope": scopeYNAB,
	})
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
// native clients and Claude Code use for their callback. A fragment is refused
// as RFC 6749 3.1.2 requires, and the host has to be a plain name or address.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || !cspHost.MatchString(u.Host) {
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
