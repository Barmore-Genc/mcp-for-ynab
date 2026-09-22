// Package config reads the server's settings from the environment. Everything
// the container needs arrives this way: there is no config file and no state
// on disk, so an operator's whole interface is `docker run -e`.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oidc"
)

type Config struct {
	// YNABToken is a YNAB personal access token. Every YNAB call the server
	// makes uses it, so the MCP server sees exactly one YNAB account.
	YNABToken string
	// Username and Password are what the operator types in the browser during
	// the OAuth login, when the server is not delegating sign-in to an OIDC
	// provider. They are the only credentials this server has.
	Username string
	Password string
	// OIDC, when set, replaces the local password with an identity provider.
	// The sign-in step of the MCP OAuth flow is then an OIDC authorization
	// code flow against that provider.
	OIDC *oidc.Config
	// Origin is the public base URL the server is reached at, scheme included.
	// OAuth metadata, the redirect back and the resource identifier are all
	// built from it, so a wrong value breaks discovery rather than degrading.
	Origin string
	Addr   string
	// SigningKey signs the OAuth credentials. Left empty it is derived from the
	// password, which means credentials survive a container restart but are
	// invalidated by a password change. In OIDC mode there is no password, so
	// it has to be set explicitly.
	SigningKey string
	// ReadOnly drops every write tool from the tool list.
	ReadOnly bool
	// Warnings are non-fatal configuration problems worth putting in the log:
	// settings that are accepted but ignored. The caller logs them.
	Warnings []string
}

func Load() (Config, error) {
	c := Config{
		YNABToken:  os.Getenv("YNAB_ACCESS_TOKEN"),
		Username:   os.Getenv("MCP_USERNAME"),
		Password:   os.Getenv("MCP_PASSWORD"),
		Origin:     strings.TrimSuffix(os.Getenv("MCP_ORIGIN"), "/"),
		Addr:       os.Getenv("MCP_ADDR"),
		SigningKey: os.Getenv("MCP_SIGNING_KEY"),
		ReadOnly:   truthy(os.Getenv("MCP_READ_ONLY")),
	}
	if c.Addr == "" {
		c.Addr = ":8080"
	}

	// A configured provider is triggered by either half of its required pair;
	// setting one without the other is a mistake worth reporting rather than
	// silently falling back to the password.
	issuer := strings.TrimSpace(os.Getenv("MCP_OIDC_ISSUER"))
	clientID := strings.TrimSpace(os.Getenv("MCP_OIDC_CLIENT_ID"))
	if issuer != "" || clientID != "" {
		if issuer == "" || clientID == "" {
			return c, fmt.Errorf("MCP_OIDC_ISSUER and MCP_OIDC_CLIENT_ID must be set together")
		}
		// The issuer is compared byte-for-byte against the ID token's iss, so
		// normalise the trailing slash operators habitually paste in.
		issuer = strings.TrimSuffix(issuer, "/")
		u, err := url.Parse(issuer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return c, fmt.Errorf("MCP_OIDC_ISSUER must be an absolute URL, got %q", issuer)
		}
		c.OIDC = &oidc.Config{
			Issuer:          issuer,
			ClientID:        clientID,
			ClientSecret:    os.Getenv("MCP_OIDC_CLIENT_SECRET"),
			Scopes:          splitList(os.Getenv("MCP_OIDC_SCOPES")),
			Name:            strings.TrimSpace(os.Getenv("MCP_OIDC_PROVIDER_NAME")),
			AllowedEmails:   splitList(os.Getenv("MCP_OIDC_ALLOWED_EMAILS")),
			AllowedSubjects: splitList(os.Getenv("MCP_OIDC_ALLOWED_SUBJECTS")),
		}
		c.OIDC.RedirectURI = strings.TrimSpace(os.Getenv("MCP_OIDC_REDIRECT_URI"))
		if c.OIDC.RedirectURI == "" {
			c.OIDC.RedirectURI = c.Origin + "/oidc/callback"
		}
		// OIDC wins when both are configured, which is almost always a leftover
		// password rather than a deliberate choice. Say so loudly instead of
		// letting someone believe the password is still a way in.
		if c.Username != "" || c.Password != "" {
			c.Warnings = append(c.Warnings,
				"MCP_USERNAME/MCP_PASSWORD are set but MCP_OIDC_ISSUER is configured; "+
					"sign-in goes through OIDC and the local password is ignored")
		}
	}

	required := map[string]string{
		"YNAB_ACCESS_TOKEN": c.YNABToken,
		"MCP_ORIGIN":        c.Origin,
	}
	if c.OIDC == nil {
		required["MCP_USERNAME"] = c.Username
		required["MCP_PASSWORD"] = c.Password
	} else if c.SigningKey == "" {
		// The credentials this server issues still have to be signed. Without a
		// password to derive from, the key has to be supplied or a restart would
		// silently invalidate every outstanding token.
		return c, fmt.Errorf("MCP_SIGNING_KEY is required when MCP_OIDC_ISSUER is set")
	}
	var missing []string
	for name, v := range required {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required environment variables: %s", strings.Join(sorted(missing), ", "))
	}
	if !strings.HasPrefix(c.Origin, "http://") && !strings.HasPrefix(c.Origin, "https://") {
		return c, fmt.Errorf("MCP_ORIGIN must include the scheme, got %q", c.Origin)
	}
	// Short passwords are the whole attack surface here: the login form is the
	// only gate in front of someone's finances, and it is reachable by anyone
	// who can reach the container. This does not apply in OIDC mode, where the
	// gate is the identity provider.
	if c.OIDC == nil && len(c.Password) < 12 {
		return c, fmt.Errorf("MCP_PASSWORD must be at least 12 characters")
	}
	return c, nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitList reads a comma- or whitespace-separated environment value into a
// list, dropping empties so trailing separators are harmless.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func sorted(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}
