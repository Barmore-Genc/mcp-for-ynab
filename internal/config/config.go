// Package config reads the server's settings from the environment. Everything
// the container needs arrives this way: there is no config file and no state
// on disk, so an operator's whole interface is `docker run -e`.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oidc"
)

// MinSigningKeyLen is the shortest MCP_SIGNING_KEY accepted. Every client id
// the server hands out is signed with it, so a short or guessable key can be
// recovered offline from one registration.
const MinSigningKeyLen = 32

type Config struct {
	// YNABToken is a YNAB personal access token. Every YNAB call the server
	// makes uses it, so the MCP server sees exactly one YNAB account.
	YNABToken string
	// Username and Password are what the operator types in the browser during
	// the OAuth login, when the server is not delegating sign-in to an OIDC
	// provider. They are only ever compared against the login form.
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
	// SigningKey signs the OAuth credentials. It is required so that it is
	// random rather than derived from something a person chose, and so that
	// credentials survive a container restart.
	SigningKey string
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is believed
	// when working out who is trying to sign in. Empty means the connecting
	// address is used as is.
	TrustedProxies []netip.Prefix
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
		SigningKey: strings.TrimSpace(os.Getenv("MCP_SIGNING_KEY")),
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
			AllowAny:        truthy(os.Getenv("MCP_OIDC_ALLOW_ANY")),
		}
		c.OIDC.RedirectURI = strings.TrimSpace(os.Getenv("MCP_OIDC_REDIRECT_URI"))
		if c.OIDC.RedirectURI == "" {
			c.OIDC.RedirectURI = c.Origin + "/oidc/callback"
		}
		hasList := len(c.OIDC.AllowedEmails) > 0 || len(c.OIDC.AllowedSubjects) > 0
		switch {
		case !hasList && !c.OIDC.AllowAny:
			return c, fmt.Errorf("set MCP_OIDC_ALLOWED_EMAILS or MCP_OIDC_ALLOWED_SUBJECTS to say who may sign in, " +
				"or MCP_OIDC_ALLOW_ANY=true to accept every account the provider authenticates")
		case hasList && c.OIDC.AllowAny:
			c.Warnings = append(c.Warnings,
				"MCP_OIDC_ALLOW_ANY is set, so MCP_OIDC_ALLOWED_EMAILS/MCP_OIDC_ALLOWED_SUBJECTS are ignored")
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
		"MCP_SIGNING_KEY":   c.SigningKey,
	}
	if c.OIDC == nil {
		required["MCP_USERNAME"] = c.Username
		required["MCP_PASSWORD"] = c.Password
	}
	var missing []string
	for name, v := range required {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		msg := "missing required environment variables: " + strings.Join(missing, ", ")
		if slices.Contains(missing, "MCP_SIGNING_KEY") {
			msg += " (generate MCP_SIGNING_KEY with `openssl rand -base64 32`)"
		}
		return c, fmt.Errorf("%s", msg)
	}
	if err := checkOrigin(c.Origin); err != nil {
		return c, err
	}
	if len(c.SigningKey) < MinSigningKeyLen {
		return c, fmt.Errorf("MCP_SIGNING_KEY must be at least %d characters of random data; "+
			"generate one with `openssl rand -base64 32`", MinSigningKeyLen)
	}
	// Short passwords are the whole attack surface here: the login form is the
	// only gate in front of someone's finances, and it is reachable by anyone
	// who can reach the container. This does not apply in OIDC mode, where the
	// gate is the identity provider.
	if c.OIDC == nil && len(c.Password) < 12 {
		return c, fmt.Errorf("MCP_PASSWORD must be at least 12 characters")
	}
	if c.Password != "" && c.SigningKey == c.Password {
		return c, fmt.Errorf("MCP_SIGNING_KEY must not be the same as MCP_PASSWORD")
	}
	proxies, err := parsePrefixes(os.Getenv("MCP_TRUSTED_PROXIES"))
	if err != nil {
		return c, fmt.Errorf("MCP_TRUSTED_PROXIES: %w", err)
	}
	c.TrustedProxies = proxies
	return c, nil
}

// checkOrigin requires https, except for a loopback host: the sign-in form
// posts the password to this origin, and a plain http origin anywhere else
// would send it across the network in the clear.
func checkOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("MCP_ORIGIN must be an absolute http(s) URL, got %q", origin)
	}
	if u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		return fmt.Errorf("MCP_ORIGIN must use https unless the host is localhost or a loopback address, got %q", origin)
	}
	return nil
}

// IsLoopbackHost reports whether host names this machine.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parsePrefixes reads a list of CIDRs, accepting a bare address as a
// single-host prefix.
func parsePrefixes(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(v) {
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q", item)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
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
