package server

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Barmore-Genc/mcp-for-ynab/internal/config"
)

// The login and error pages are the only HTML this server serves. They are
// inline templates rather than files so the binary stays the whole deployment.
const pageCSS = `
  :root { color-scheme: light dark; --bg: #fbfaf8; --card: #fff; --line: #e3ded6;
    --text: #1c1a17; --muted: #6b6560; --accent: #2b7a5b; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #14130f; --card: #1d1c18; --line: #322f29; --text: #ece9e3;
      --muted: #9a938a; --accent: #4cb98c; }
  }
  body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text);
    display: flex; min-height: 100vh; align-items: center; justify-content: center;
    margin: 0; padding: 1rem; box-sizing: border-box; }
  .card { width: 100%; max-width: 24rem; padding: 2rem; background: var(--card);
    border: 1px solid var(--line); border-radius: 14px; box-sizing: border-box; }
  h1 { font-size: 1.2rem; margin: 0 0 .5rem; }
  p { color: var(--muted); line-height: 1.6; font-size: .9rem; }
  strong { color: var(--text); }
  .dest { margin: 1rem 0; padding: .75rem; border: 1px solid var(--line); border-radius: 8px; }
  .dest strong { display: block; font-size: 1.05rem; overflow-wrap: anywhere; }
  .name { overflow-wrap: anywhere; }
  label { display: block; font-size: .8rem; margin: 1rem 0 .3rem; color: var(--muted); }
  input { width: 100%; padding: .6rem; font-size: 1rem; border-radius: 8px;
    border: 1px solid var(--line); background: var(--bg); color: var(--text);
    box-sizing: border-box; }
  .row { display: flex; gap: .75rem; margin-top: 1.5rem; }
  p.sso { margin-top: 1rem; }
  button { flex: 1; padding: .7rem; border-radius: 8px; border: 0; font-size: .95rem;
    font-weight: 600; cursor: pointer; }
  .allow { background: var(--accent); color: #fff; }
  .deny { background: transparent; color: var(--muted); border: 1px solid var(--line); }
  .err { color: #c0392b; font-size: .85rem; margin-top: 1rem; }
`

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title><style>` + pageCSS + `</style></head><body>
<div class="card">
  <h1>Connect to your budget</h1>
  <p>An app is asking to read and change your YNAB budgets. Only continue if you
  started this from your AI agent just now.</p>
  <div class="dest"><p>After you sign in, access is sent to
  <strong>{{.RedirectHost}}</strong>{{if .Loopback}}an app running on this computer.{{end}}</p></div>
  {{if .P.ClientName}}<p class="name">Name given by the app: {{.P.ClientName}}</p>{{end}}
  <form method="post" action="/authorize">
    <input type="hidden" name="client_id" value="{{.P.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.P.RedirectURI}}">
    <input type="hidden" name="state" value="{{.P.State}}">
    <input type="hidden" name="code_challenge" value="{{.P.Challenge}}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="scope" value="{{.P.Scope}}">
    {{if .SSO}}
    <p class="sso">You will be taken to <strong>{{.ProviderName}}</strong> to sign in.</p>
    {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
    <div class="row">
      <button class="deny" type="submit" name="decision" value="deny">Cancel</button>
      <button class="allow" type="submit" name="decision" value="allow">Continue with {{.ProviderName}}</button>
    </div>
    {{else}}
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
    <div class="row">
      <button class="deny" type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
      <button class="allow" type="submit" name="decision" value="allow">Sign in</button>
    </div>
    {{end}}
  </form>
</div></body></html>`))

// renderLogin shows the consent page for a validated /authorize request. With
// an identity provider configured the form asks for no password of its own; it
// is just the consent step before the browser leaves for the provider.
//
// The client name is chosen by whoever registered the client, so the page
// leads with where the result is sent, which the name cannot disguise.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, p authorizeParams, errMsg string) {
	view := struct {
		P            authorizeParams
		RedirectHost string
		Loopback     bool
		Error        string
		SSO          bool
		ProviderName string
	}{P: p, Error: errMsg}
	// The form's submission ends in a redirect: to the client with a code, or
	// to the identity provider. Browsers apply form-action to that redirect,
	// so both destinations have to be listed.
	var targets []string
	if u, err := url.Parse(p.RedirectURI); err == nil {
		view.RedirectHost = u.Host
		view.Loopback = u.Scheme == "http" && config.IsLoopbackHost(u.Hostname())
		targets = append(targets, p.RedirectURI)
	}
	if s.oidc != nil {
		view.SSO = true
		view.ProviderName = s.oidc.Name()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		// A failed discovery is reported when the form is submitted.
		if origin, err := s.oidc.AuthorizationOrigin(ctx); err == nil {
			targets = append(targets, origin)
		}
	}
	setPageHeaders(w, targets...)
	w.WriteHeader(status)
	loginTmpl.Execute(w, view)
}

var errorTmpl = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title><style>` + pageCSS + `</style></head><body>
<div class="card"><h1>{{.Title}}</h1><p>{{.Message}}</p></div>
</body></html>`))

func renderErrorPage(w http.ResponseWriter, status int, msg string) {
	renderPage(w, status, "Could not connect", msg)
}

func renderPage(w http.ResponseWriter, status int, title, msg string) {
	setPageHeaders(w)
	w.WriteHeader(status)
	errorTmpl.Execute(w, struct{ Title, Message string }{title, msg})
}

// cspHost matches what may appear as the host of a CSP source expression. It
// keeps a registered redirect URI from smuggling extra directives into the
// header through characters such as ';' that a URL host may contain.
var cspHost = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]+)?$|^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$`)

// setPageHeaders marks a response as one of this server's HTML pages. Pages
// load nothing, may not be framed, and send no Referer, since the URL of the
// sign-in page carries the OAuth request.
func setPageHeaders(w http.ResponseWriter, formTargets ...string) {
	formAction := "'self'"
	for _, t := range formTargets {
		u, err := url.Parse(t)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !cspHost.MatchString(u.Host) {
			continue
		}
		formAction += " " + u.Scheme + "://" + u.Host
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+
		"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
}

const maxClientNameLen = 100

// cleanClientName makes a registrant-chosen name safe to show: control and
// formatting characters (which include the bidirectional overrides that can
// make text read backwards) are dropped, whitespace is collapsed, and the
// result is cut to maxClientNameLen characters.
func cleanClientName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == utf8.RuneError, unicode.Is(unicode.Cf, r):
			continue
		case unicode.IsSpace(r) || unicode.IsControl(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	name = strings.Join(strings.Fields(b.String()), " ")
	if utf8.RuneCountInString(name) > maxClientNameLen {
		name = string([]rune(name)[:maxClientNameLen])
	}
	return name
}
