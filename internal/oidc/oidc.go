// Package oidc makes the server an OIDC relying party. When the operator
// points it at an identity provider, the sign-in step of the MCP OAuth flow is
// delegated to that provider instead of being checked against a password in the
// container's environment, and this server only ever holds the provider's
// client credentials.
//
// Nothing here is specific to any one provider. Discovery, the authorization
// code exchange and ID token verification all come from the provider's
// .well-known/openid-configuration document, so Pocket ID, Keycloak, Auth0,
// Google and the rest are configured the same way: issuer plus client id.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config is everything the server needs to talk to an identity provider. It is
// read from the environment, and an empty ClientSecret is allowed: providers
// that support public clients are authenticated with PKCE alone.
type Config struct {
	// Issuer is the provider's base URL. Discovery is fetched from
	// <Issuer>/.well-known/openid-configuration.
	Issuer string
	// ClientID and ClientSecret identify this server at the provider.
	ClientID     string
	ClientSecret string
	// Scopes requested at the provider. "openid" is always requested.
	Scopes []string
	// RedirectURI is where the provider sends the browser back. It must match
	// a redirect URI registered at the provider exactly.
	RedirectURI string
	// Name is what the sign-in page calls the provider ("Pocket ID", "Google").
	Name string
	// AllowedEmails and AllowedSubjects restrict who may complete the flow. An
	// email only counts when the provider says it is verified.
	AllowedEmails   []string
	AllowedSubjects []string
	// AllowAny accepts every account the provider authenticates. It has to be
	// asked for explicitly, because on a public provider such as Google it
	// would let anyone with an account in.
	AllowAny bool
}

// Provider wraps one identity provider. Discovery is done lazily and cached:
// the container can start and serve its health endpoint while the provider is
// unreachable, and the first sign-in attempt pays the discovery cost.
type Provider struct {
	cfg Config

	mu       sync.Mutex
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func New(cfg Config) *Provider { return &Provider{cfg: cfg} }

// Name returns the display name, falling back to the issuer's host so the
// sign-in page never shows a raw URL when the operator did not name it.
func (p *Provider) Name() string {
	if p.cfg.Name != "" {
		return p.cfg.Name
	}
	if u, err := url.Parse(p.cfg.Issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return "your identity provider"
}

// ensure discovers the provider and caches everything derived from it. The
// lock is held across discovery so a burst of sign-ins does not all fetch the
// same document; a failed attempt leaves the cache empty and the next sign-in
// retries.
func (p *Provider) ensure(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier != nil {
		return nil
	}
	prov, err := oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("discover %s: %w", p.cfg.Issuer, err)
	}
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"email", "profile"}
	}
	// openid is what makes this OIDC rather than plain OAuth2; without it the
	// provider returns no ID token and there is nothing to verify.
	if !slices.Contains(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}
	p.oauth2 = &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  p.cfg.RedirectURI,
		Scopes:       scopes,
	}
	if p.cfg.ClientSecret == "" {
		// A public client authenticates by putting client_id in the token
		// request body. Skip x/oauth2's auto-detection, which would try HTTP
		// basic auth first and make providers that reject it log a failure.
		p.oauth2.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	p.verifier = prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID})
	return nil
}

// AuthCodeURL builds the provider URL the browser is sent to. verifier is the
// PKCE code verifier; it is always used, which is what lets a public client
// with no secret complete the exchange.
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	if err := p.ensure(ctx); err != nil {
		return "", err
	}
	return p.oauth2.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

// Identity is the part of the verified ID token the server cares about.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// AuthorizationOrigin returns the scheme and host of the provider's
// authorization endpoint. The sign-in page has to allow it as a form target,
// because submitting the form ends in a redirect there.
func (p *Provider) AuthorizationOrigin(ctx context.Context) (string, error) {
	if err := p.ensure(ctx); err != nil {
		return "", err
	}
	u, err := url.Parse(p.oauth2.Endpoint.AuthURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("authorization endpoint %q is not an absolute URL", p.oauth2.Endpoint.AuthURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// Exchange redeems an authorization code at the provider and verifies the ID
// token it returns: signature against the provider's published keys, issuer,
// audience, expiry, and the nonce minted for this flow.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	if err := p.ensure(ctx); err != nil {
		return Identity{}, err
	}
	// x/oauth2 does not send redirect_uri on the token request by default.
	// Providers are allowed to require it (RFC 6749 4.1.3), so send it.
	tok, err := p.oauth2.Exchange(ctx, code,
		oauth2.VerifierOption(verifier),
		oauth2.SetAuthURLParam("redirect_uri", p.cfg.RedirectURI),
	)
	if err != nil {
		return Identity{}, fmt.Errorf("exchange code: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, fmt.Errorf("provider returned no id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, fmt.Errorf("id_token nonce does not match")
	}
	var claims struct {
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read id_token claims: %w", err)
	}
	return Identity{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: isTrue(claims.EmailVerified),
	}, nil
}

// isTrue reads email_verified, which some providers (Cognito among them) send
// as the string "true" rather than a JSON boolean.
func isTrue(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && strings.EqualFold(s, "true")
}

// Allowed reports whether the identity is permitted to finish signing in. An
// unverified email is ignored: many providers let a user put any address in
// their profile, and matching on it would let them claim someone else's.
func (p *Provider) Allowed(id Identity) bool {
	if p.cfg.AllowAny {
		return true
	}
	for _, want := range p.cfg.AllowedSubjects {
		if want == id.Subject {
			return true
		}
	}
	if !id.EmailVerified || id.Email == "" {
		return false
	}
	for _, want := range p.cfg.AllowedEmails {
		if strings.EqualFold(strings.TrimSpace(want), id.Email) {
			return true
		}
	}
	return false
}
