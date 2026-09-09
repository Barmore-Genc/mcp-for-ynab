// Package config reads the server's settings from the environment. Everything
// the container needs arrives this way: there is no config file and no state
// on disk, so an operator's whole interface is `docker run -e`.
package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	// YNABToken is a YNAB personal access token. Every YNAB call the server
	// makes uses it, so the MCP server sees exactly one YNAB account.
	YNABToken string
	// Username and Password are what the operator types in the browser during
	// the OAuth login. They are the only credentials this server has.
	Username string
	Password string
	// Origin is the public base URL the server is reached at, scheme included.
	// OAuth metadata, the redirect back and the resource identifier are all
	// built from it, so a wrong value breaks discovery rather than degrading.
	Origin string
	Addr   string
	// SigningKey signs the OAuth credentials. Left empty it is derived from the
	// password, which means credentials survive a container restart but are
	// invalidated by a password change.
	SigningKey string
	// ReadOnly drops every write tool from the tool list.
	ReadOnly bool
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
	var missing []string
	for name, v := range map[string]string{
		"YNAB_ACCESS_TOKEN": c.YNABToken,
		"MCP_USERNAME":      c.Username,
		"MCP_PASSWORD":      c.Password,
		"MCP_ORIGIN":        c.Origin,
	} {
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
	// who can reach the container.
	if len(c.Password) < 12 {
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
