package server

import (
	"html/template"
	"net/http"
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
  label { display: block; font-size: .8rem; margin: 1rem 0 .3rem; color: var(--muted); }
  input { width: 100%; padding: .6rem; font-size: 1rem; border-radius: 8px;
    border: 1px solid var(--line); background: var(--bg); color: var(--text);
    box-sizing: border-box; }
  .row { display: flex; gap: .75rem; margin-top: 1.5rem; }
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
  <p><strong>{{.P.ClientName}}</strong> is asking to read and change your YNAB budgets.
  Sign in to allow it.</p>
  <form method="post" action="/authorize">
    <input type="hidden" name="client_id" value="{{.P.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.P.RedirectURI}}">
    <input type="hidden" name="state" value="{{.P.State}}">
    <input type="hidden" name="code_challenge" value="{{.P.Challenge}}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="scope" value="{{.P.Scope}}">
    <label for="username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
    <div class="row">
      <button class="deny" type="submit" name="decision" value="deny">Cancel</button>
      <button class="allow" type="submit" name="decision" value="allow">Sign in</button>
    </div>
  </form>
</div></body></html>`))

func renderLogin(w http.ResponseWriter, p authorizeParams, errMsg string) {
	if p.ClientName == "" {
		p.ClientName = "An application"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, struct {
		P     authorizeParams
		Error string
	}{p, errMsg})
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	errorTmpl.Execute(w, struct{ Title, Message string }{title, msg})
}
