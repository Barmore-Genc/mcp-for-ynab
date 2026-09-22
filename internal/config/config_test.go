package config

import (
	"strings"
	"testing"
)

// setPasswordMode clears any OIDC variables a previous test may have left and
// supplies the minimum a password deployment needs.
func setPasswordMode(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"MCP_OIDC_ISSUER", "MCP_OIDC_CLIENT_ID", "MCP_OIDC_CLIENT_SECRET",
		"MCP_OIDC_SCOPES", "MCP_OIDC_PROVIDER_NAME", "MCP_OIDC_REDIRECT_URI",
		"MCP_OIDC_ALLOWED_EMAILS", "MCP_OIDC_ALLOWED_SUBJECTS",
		"MCP_PASSWORD", "MCP_USERNAME", "MCP_SIGNING_KEY", "MCP_ORIGIN", "YNAB_ACCESS_TOKEN",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("YNAB_ACCESS_TOKEN", "token")
	t.Setenv("MCP_ORIGIN", "https://ynab.example")
	t.Setenv("MCP_USERNAME", "budgeteer")
	t.Setenv("MCP_PASSWORD", "correct-horse-battery")
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
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "")
	t.Setenv("MCP_USERNAME", "")
	t.Setenv("MCP_SIGNING_KEY", "a-stable-signing-key")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")
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
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "")
	t.Setenv("MCP_SIGNING_KEY", "a-stable-signing-key")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")
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

// Without a password there is nothing to derive the token signing key from, so
// leaving MCP_SIGNING_KEY out would make every credential invalid after a
// restart. Refuse the configuration instead.
func TestOIDCRequiresSigningKey(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "")
	t.Setenv("MCP_USERNAME", "")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_SIGNING_KEY") {
		t.Fatalf("expected a signing key error, got %v", err)
	}
}

// The password length floor guards the local login form and must not apply
// when the provider is the gate.
func TestOIDCSkipsPasswordLengthFloor(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_PASSWORD", "short")
	t.Setenv("MCP_SIGNING_KEY", "a-stable-signing-key")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")
	if _, err := Load(); err != nil {
		t.Fatalf("short password rejected in OIDC mode: %v", err)
	}
}

// OIDC takes precedence over a leftover password, but not silently: the
// caller logs the warning so it shows up in `docker logs`.
func TestOIDCWithLeftoverPasswordWarns(t *testing.T) {
	setPasswordMode(t)
	t.Setenv("MCP_SIGNING_KEY", "a-stable-signing-key")
	t.Setenv("MCP_OIDC_ISSUER", "https://id.example")
	t.Setenv("MCP_OIDC_CLIENT_ID", "mcp-for-ynab")

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
