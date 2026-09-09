// Package mcpserver exposes a YNAB budget as MCP tools.
//
// The tool surface is deliberately much smaller than the API behind it: 44 YNAB
// endpoints become 13 tools, and the ones that only differ by which id they are
// scoped to (the five transaction list endpoints, the singular getters) are
// parameters here rather than tools of their own. What a tool costs is not the
// call, it is the schema every request carries and the choice the model has to
// make; two tools that take the same arguments and answer the same question are
// a tax on every turn.
//
// Two rules run through all of it. Nothing speaks milliunits or uuids to the
// model — amounts are currency numbers and anything that takes an id takes a
// name as well. And list output is rendered as compact lines rather than dumped
// as JSON, because the JSON for two hundred transactions is most of a context
// window and the same rows as lines are a tenth of that.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/oauth"
	"github.com/Barmore-Genc/mcp-for-ynab/internal/ynab"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	api     *ynab.API
	signer  *oauth.Signer
	origin  string
	version string
	// readOnly drops the write tools from tools/list entirely rather than
	// failing them when called, so a model never plans around a tool it cannot
	// use.
	readOnly bool
	// now is time.Now except in tests, where relative dates need a fixed today.
	now func() time.Time
}

func New(api *ynab.API, signer *oauth.Signer, origin, version string, readOnly bool) *Server {
	return &Server{api: api, signer: signer, origin: origin, version: version, readOnly: readOnly, now: time.Now}
}

// Handler is the http.Handler to mount at /mcp. A request without a valid
// access token gets a 401 carrying the WWW-Authenticate header that tells an
// OAuth client where to go and authenticate.
func (s *Server) Handler() http.Handler {
	srv := s.build()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	return sdkauth.RequireBearerToken(s.verify, &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.origin + "/.well-known/oauth-protected-resource",
	})(h)
}

// verify resolves the bearer token this server minted at /token. There is one
// user, so the token says which client is calling and nothing more.
func (s *Server) verify(_ context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
	p, err := s.signer.Verify(token, oauth.KindAccess)
	if err != nil {
		return nil, fmt.Errorf("access token not accepted: %w", sdkauth.ErrInvalidToken)
	}
	return &sdkauth.TokenInfo{UserID: p.ClientID, Expiration: p.ExpiresAt()}, nil
}

func (s *Server) build() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "ynab",
		Title:   "YNAB",
		Version: s.version,
	}, &mcp.ServerOptions{
		Instructions: "Tools for reading and changing a YNAB budget. Amounts are always in the " +
			"budget's currency, never milliunits, and spending is negative. Anywhere an account, " +
			"category or payee is asked for, its name works as well as its id. Start with " +
			"ynab_list_budgets if you do not know which budget you are working in; every other tool " +
			"defaults to the most recently used one.",
	})
	s.addReadTools(srv)
	if !s.readOnly {
		s.addWriteTools(srv)
	}
	return srv
}

// text returns a tool result as one text block. Every tool answers this way:
// what the model reads is prose and lines, and a second structured copy of the
// same data would only double the tokens.
func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// fail turns an error into a tool result rather than a protocol error, which is
// what lets the model read the explanation and try something else. A mapped
// YNAB error and a resolution failure both already say what to do next; an
// unexpected error is reported as itself.
func fail(err error) (*mcp.CallToolResult, any, error) {
	var (
		apiErr *ynab.Error
		amb    *ynab.AmbiguousError
		nf     *ynab.NotFoundError
	)
	switch {
	case errors.As(err, &apiErr), errors.As(err, &amb), errors.As(err, &nf):
	default:
		err = fmt.Errorf("could not complete the request: %w", err)
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}, nil, nil
}

// plan resolves the optional budget argument every tool carries.
func plan(id string) string {
	if id == "" {
		return ynab.PlanLastUsed
	}
	return id
}

func readOnlyTool() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)}
}

func writeTool(destructive bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: ptr(destructive), OpenWorldHint: ptr(true)}
}

func ptr[T any](v T) *T { return &v }
