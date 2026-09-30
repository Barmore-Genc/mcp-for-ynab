package config

import (
	"net/netip"
	"strings"
	"testing"
)

const testKey = "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// setPasswordMode clears any variables a previous test may have left and
// supplies the minimum a password deployment needs.
func setPasswordMode(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"MCP_OIDC_ISSUER", "MCP_OIDC_CLIENT_ID", "MCP_OIDC_CLIENT_SECRET",
		"MCP_OIDC_SCOPES", "MCP_OIDC_PROVIDER_NAME", "MCP_OIDC_REDIRECT_URI",
		"MCP_OIDC_ALLOWED_EMAILS", "MCP_OIDC_ALLOWED_SUBJECTS", "MCP_OIDC_ALLOW_ANY",
		"MCP_PASSWORD", "MCP_USERNAME", "MCP_SIGNING_KEY", "MCP_ORIGIN", "MCP_TRUSTED_PROXIES",
		"YNAB_ACCESS_TOKEN",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("YNAB_ACCESS_TOKEN", "token")
	t.Setenv("MCP_ORIGIN", "https://ynab.example")
	t.Setenv("MCP_USERNAME", "budgeteer")
	t.Setenv("MCP_PASSWORD", "correct-horse-battery")
	t.Setenv("MCP_SIGNING_KEY", testKey)
}

// setOIDCMode is the minimum an OIDC deployment needs, with no password.
func setOIDCMode(t *testing.T) {
	t.Helper()
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "")
	t.Setenv("MCP_USERNAME", "")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")
	t.Setenv("MCP_OIDC_ALLOWED_EMAILS", "me@example.com")
}

func TestPasswordModeNeedsNoOIDC(t *testing.T) {
	setPasswordMode(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.OIDC != nil {
		t.Fatalf("OIDC configured from an empty environment: %+v", c.OIDC)
	}
}

func TestOIDCReplacesPassword(t *testing.T) {
	setOIDCMode(t)
	t.Setenv("MCP_OIDC_PROVIDER_NAME", "Pocket ID")
	t.Setenv("MCP_OIDC_ALLOWED_EMAILS", "me@example.com, other@example.com")
	t.Setenv("MCP_OIDC_SCOPES", "openid email groups")

	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.OIDC == nil {
		t.Fatal("OIDC not configured")
	}
	if c.OIDC.RedirectURI != "https://ynab.example/oidc/callback" {
		t.Fatalf("redirect URI defaulted to %q", c.OIDC.RedirectURI)
	}
	if got := len(c.OIDC.AllowedEmails); got != 2 {
		t.Fatalf("expected two allowed emails, got %d", got)
	}
	if got := len(c.OIDC.Scopes); got != 3 {
		t.Fatalf("expected three scopes, got %d", got)
	}
}

func TestOIDCRedirectURIOverride(t *testing.T) {
	setOIDCMode(t)
	t.Setenv("MCP_OIDC_REDIRECT_URI", "https://ynab.example/auth/callback")

	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.OIDC.RedirectURI != "https://ynab.example/auth/callback" {
		t.Fatalf("redirect URI override ignored: %q", c.OIDC.RedirectURI)
	}
}

func TestOIDCNeedsBothIssuerAndClientID(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_OIDC_CLIENT_ID") {
		t.Fatalf("expected a missing client id error, got %v", err)
	}
}

// Accepting any account a provider authenticates is only safe with a private
// provider, so it has to be a deliberate setting rather than the default.
func TestOIDCRequiresAllowlistOrExplicitAllowAny(t *testing.T) {
	setOIDCMode(t)
	t.Setenv("MCP_OIDC_ALLOWED_EMAILS", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_OIDC_ALLOW_ANY") {
		t.Fatalf("expected an allowlist error, got %v", err)
	}

	t.Setenv("MCP_OIDC_ALLOWED_SUBJECTS", "user-1")
	if _, err := Load(); err != nil {
		t.Fatalf("subject allowlist rejected: %v", err)
	}

	t.Setenv("MCP_OIDC_ALLOWED_SUBJECTS", "")
	t.Setenv("MCP_OIDC_ALLOW_ANY", "true")
	c, err := Load()
	if err != nil {
		t.Fatalf("explicit allow-any rejected: %v", err)
	}
	if !c.OIDC.AllowAny {
		t.Fatal("MCP_OIDC_ALLOW_ANY not carried into the OIDC config")
	}
}

// The signing key signs client ids that anyone can obtain from /register, so
// it has to be supplied, random and long, in every mode.
func TestSigningKeyIsRequiredInEveryMode(t *testing.T) {
	for name, set := range map[string]func(*testing.T){"password": setPasswordMode, "oidc": setOIDCMode} {
		t.Run(name, func(t *testing.T) {
			set(t)
			t.Setenv("MCP_SIGNING_KEY", "")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_SIGNING_KEY") {
				t.Fatalf("expected a signing key error, got %v", err)
			}
		})
	}
}

func TestShortSigningKeyIsRejected(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_SIGNING_KEY", "a-stable-signing-key")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("expected a key length error, got %v", err)
	}
}

func TestSigningKeyMustDifferFromPassword(t *testing.T) {
	setPasswordMode(t)
	pw := "a-password-that-is-long-enough-for-a-key"
	t.Setenv("MCP_PASSWORD", pw)
	t.Setenv("MCP_SIGNING_KEY", pw)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_PASSWORD") {
		t.Fatalf("expected an error for a key equal to the password, got %v", err)
	}
}

// The password length floor guards the local login form and must not apply
// when the provider is the gate.
func TestOIDCSkipsPasswordLengthFloor(t *testing.T) {
	setOIDCMode(t)
	t.Setenv("MCP_PASSWORD", "short")
	if _, err := Load(); err != nil {
		t.Fatalf("short password rejected in OIDC mode: %v", err)
	}
}

// OIDC takes precedence over a leftover password, but not silently: the
// caller logs the warning so it shows up in `docker logs`.
func TestOIDCWithLeftoverPasswordWarns(t *testing.T) {
	setOIDCMode(t)
	t.Setenv("MCP_USERNAME", "operator")
	t.Setenv("MCP_PASSWORD", "correct-horse-battery")

	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", c.Warnings)
	}
	if !strings.Contains(c.Warnings[0], "MCP_PASSWORD") {
		t.Fatalf("warning does not name the ignored setting: %q", c.Warnings[0])
	}
}

func TestPasswordModeStillEnforcesLength(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("expected a password length error, got %v", err)
	}
}

// The password is posted to MCP_ORIGIN, so plain http is only acceptable when
// it never leaves the machine.
func TestOriginNeedsHTTPSUnlessLoopback(t *testing.T) {
	cases := map[string]bool{
		"https://mcp.example":       true,
		"http://localhost:8080":     true,
		"http://127.0.0.1:8080":     true,
		"http://[::1]:8080":         true,
		"http://mcp.example":        false,
		"http://192.168.1.10:8080":  false,
		"mcp.example":               false,
		"ftp://mcp.example":         false,
		"http://localhost.evil.com": false,
	}
	for origin, ok := range cases {
		setPasswordMode(t)
		t.Setenv("MCP_ORIGIN", origin)
		_, err := Load()
		if ok && err != nil {
			t.Errorf("%s rejected: %v", origin, err)
		}
		if !ok && err == nil {
			t.Errorf("%s accepted", origin)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_TRUSTED_PROXIES", "10.0.0.0/8, 172.18.0.1 fd00::/8")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.18.0.1/32"),
		netip.MustParsePrefix("fd00::/8"),
	}
	if len(c.TrustedProxies) != len(want) {
		t.Fatalf("got %v", c.TrustedProxies)
	}
	for i := range want {
		if c.TrustedProxies[i] != want[i] {
			t.Fatalf("got %v, want %v", c.TrustedProxies, want)
		}
	}

	t.Setenv("MCP_TRUSTED_PROXIES", "not-an-address")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_TRUSTED_PROXIES") {
		t.Fatalf("expected a trusted proxies error, got %v", err)
	}
}
