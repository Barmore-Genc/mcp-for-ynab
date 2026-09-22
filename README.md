# mcp-for-ynab

An MCP server that gives an AI agent access to your [YNAB](https://www.ynab.com/)
budget. It runs as one small container, holds no state, and needs nothing but a
YNAB token and a way to sign you in: either a username and password you choose,
or an identity provider it delegates to over OpenID Connect.

## What it can do

Thirteen tools cover the parts of the YNAB API an agent has any use for:

| Tool | What it is for |
| --- | --- |
| `ynab_list_budgets` | Which budgets exist, and their currency |
| `ynab_get_budget_month` | Ready to Assign, and every category's assigned/spent/available |
| `ynab_list_accounts` | Accounts and balances |
| `ynab_list_payees` | Find a payee by name |
| `ynab_search_transactions` | Find transactions, or total them by category, payee, account or month |
| `ynab_get_transaction` | One transaction in full, including splits |
| `ynab_list_scheduled_transactions` | What is coming up |
| `ynab_create_transactions` | Record transactions, with splits |
| `ynab_update_transactions` | Categorize, approve, clear, or correct in bulk |
| `ynab_delete_transaction` | Delete one transaction (needs `confirm`) |
| `ynab_assign_budget` | Assign money to categories, or move it between them |
| `ynab_manage_scheduled_transaction` | Create, change or delete a recurring transaction |
| `ynab_manage_category` | Create or rename categories and groups, set targets |

Amounts are always in your budget's currency and never in YNAB's milliunits, and
anywhere an account, category or payee is asked for, its name works as well as
its id. Set `MCP_READ_ONLY=true` to drop the six write tools entirely.

## Running it

```sh
docker run -p 8080:8080 \
  -e YNAB_ACCESS_TOKEN=... \
  -e MCP_USERNAME=you \
  -e MCP_PASSWORD='a long password' \
  -e MCP_ORIGIN=https://ynab.example.com \
  ghcr.io/barmore-genc/mcp-for-ynab:latest
```

Get the YNAB token from **Account Settings → Developer Settings → New Access
Token** in the YNAB web app. It is a personal access token, so this server sees
exactly the one YNAB account it belongs to.

`MCP_ORIGIN` is the public URL the server is reached at, scheme included. It has
to be right: the OAuth flow builds every URL it advertises from it. Put the
container behind a reverse proxy that terminates TLS, or run it on a private
network.

| Variable | Required | Meaning |
| --- | --- | --- |
| `YNAB_ACCESS_TOKEN` | yes | YNAB personal access token |
| `MCP_ORIGIN` | yes | Public base URL, e.g. `https://ynab.example.com` |
| `MCP_USERNAME` | password mode | What you type on the sign-in page |
| `MCP_PASSWORD` | password mode | The password for it, at least 12 characters |
| `MCP_SIGNING_KEY` | no¹ | Signs the OAuth credentials; derived from the password otherwise |
| `MCP_ADDR` | no | Listen address, `:8080` by default |
| `MCP_READ_ONLY` | no | `true` to offer only the read tools |
| `MCP_OIDC_ISSUER` | OIDC mode | Provider base URL, e.g. `https://id.example.com` |
| `MCP_OIDC_CLIENT_ID` | OIDC mode | Client id registered at the provider |
| `MCP_OIDC_CLIENT_SECRET` | no | Only for confidential clients; omit for a public PKCE client |
| `MCP_OIDC_PROVIDER_NAME` | no | Name shown on the sign-in button, e.g. `Pocket ID` |
| `MCP_OIDC_SCOPES` | no | Scopes to request, `openid email profile` by default |
| `MCP_OIDC_REDIRECT_URI` | no | Overrides the callback, `$MCP_ORIGIN/oidc/callback` by default |
| `MCP_OIDC_ALLOWED_EMAILS` | no | Comma-separated addresses allowed to sign in |
| `MCP_OIDC_ALLOWED_SUBJECTS` | no | Comma-separated provider subject ids allowed to sign in |

¹ Required in OIDC mode, where there is no password to derive it from.

## Connecting an agent to it

Add `https://your-origin/mcp` as an MCP connector. The agent will send you to a
sign-in page; enter the username and password from the container's environment —
or, if an identity provider is configured, continue with the provider — and it
is connected.

There is no account to create and no other user interface. The sign-in page and
the OAuth endpoints behind it exist because the OAuth flow is the only way the
connector UIs know how to authenticate against an MCP server.

## Delegating sign-in to an identity provider

Instead of a password in the container's environment, the sign-in step can be
handed to any OpenID Connect provider. The flow is unchanged from the agent's
point of view — it still gets an authorization code from this server — but when
the browser reaches the sign-in page, the server sends it to your provider, and
only mints the code once the provider has authenticated the person and returned
a verified ID token.

This works with Pocket ID, Keycloak, Authentik, Auth0, Google, Entra ID and
anything else that publishes a `.well-known/openid-configuration`. Nothing is
tailored to a specific vendor: the server reads the provider's endpoints from
discovery and is configured with an issuer and a client id.

Set `MCP_OIDC_ISSUER` and `MCP_OIDC_CLIENT_ID` to turn it on, drop
`MCP_USERNAME`/`MCP_PASSWORD`, and supply `MCP_SIGNING_KEY` (in OIDC mode there
is no password for the token signing key to be derived from). When an issuer is
set, sign-in goes through OIDC and a leftover `MCP_USERNAME`/`MCP_PASSWORD` is
ignored; the server logs a warning saying so rather than pretending the password
still works.

### Pocket ID

1. Create an OIDC client in Pocket ID under **Administration → OIDC Clients →
   Add OIDC client**.
   - **Name**: `mcp-for-ynab`
   - **Callback URL**: `https://ynab.example.com/oidc/callback` — this must be
     `MCP_ORIGIN` plus `/oidc/callback` unless you override
     `MCP_OIDC_REDIRECT_URI`.
   - Leave **Public client** on to authenticate with PKCE and no secret, or turn
     it off and copy the secret.
2. Start the container with the client details:

   ```sh
   docker run -p 8080:8080 \
     -e YNAB_ACCESS_TOKEN=... \
     -e MCP_ORIGIN=https://ynab.example.com \
     -e MCP_OIDC_ISSUER=https://id.example.com \
     -e MCP_OIDC_CLIENT_ID=<client id> \
     -e MCP_OIDC_PROVIDER_NAME='Pocket ID' \
     -e MCP_OIDC_ALLOWED_EMAILS=you@example.com \
     -e MCP_SIGNING_KEY=$(openssl rand -base64 32) \
     ghcr.io/barmore-genc/mcp-for-ynab:latest
   ```

   `MCP_OIDC_ISSUER` is Pocket ID's own URL, the one you open in a browser, not
   an internal container address. `MCP_OIDC_CLIENT_SECRET` is only needed if you
   turned **Public client** off, and `MCP_OIDC_ALLOWED_EMAILS` is optional too:
   leave it out to accept anyone who can sign in at Pocket ID. The required OIDC
   variables are just `MCP_OIDC_ISSUER`, `MCP_OIDC_CLIENT_ID` and
   `MCP_SIGNING_KEY`.

3. Connect the agent as usual. The sign-in page now shows a single **Continue
   with Pocket ID** button; after Pocket ID authenticates you, you land back on
   `/oidc/callback` and the agent receives its code.

### Other providers

The same variables apply. For Google, for example:

```sh
-e MCP_OIDC_ISSUER=https://accounts.google.com \
-e MCP_OIDC_CLIENT_ID=...apps.googleusercontent.com \
-e MCP_OIDC_CLIENT_SECRET=... \
-e MCP_OIDC_PROVIDER_NAME=Google \
-e MCP_OIDC_ALLOWED_EMAILS=you@gmail.com
```

Register `https://ynab.example.com/oidc/callback` as the authorized redirect URI
at the provider. Request whatever scopes you need with `MCP_OIDC_SCOPES`; the
`openid` scope is always present.

### Who is allowed in

By default any account the provider authenticates may sign in, which is only
safe when the provider is itself restricted to you. Set
`MCP_OIDC_ALLOWED_EMAILS` (and/or `MCP_OIDC_ALLOWED_SUBJECTS`) to pin the server
to specific identities. An email has to match exactly, case-insensitively; the
subject is the provider's stable user id. A sign-in that matches neither is sent
back to the agent as `access_denied` and logged by the server.

## How authentication works

The container is its own OAuth 2.1 authorization server. It registers clients
dynamically, requires PKCE with S256, and issues an access token good for an
hour and a refresh token good for thirty days.

None of that is stored. Every credential it issues is a signed string that
carries its own contents, so the container keeps no database and no volume, and
restarting or replacing it does not disconnect anything. The only thing held in
memory is the set of authorization codes already redeemed, which expire a minute
after they are minted.

Changing `MCP_PASSWORD` (or `MCP_SIGNING_KEY`) invalidates every outstanding
token at once, which is how you revoke access. In OIDC mode the password does
not exist, so `MCP_SIGNING_KEY` is the revocation switch; the signed state that
carries an in-progress sign-in through the provider expires after ten minutes
and can be used only once.

## Development

```sh
go test ./...
go build ./...
```

The YNAB client in `internal/ynab/client.gen.go` is generated from YNAB's own
OpenAPI document, vendored at `internal/ynab/openapi.yaml`. To pick up a new
version of the API:

```sh
curl -o internal/ynab/openapi.yaml https://api.ynab.com/papi/open_api_spec.yaml
go generate ./...
```

The spec is OpenAPI 3.1 and the generator only reads 3.0, so `go generate` first
runs `tools/openapi30`, which rewrites the nullable type arrays. Both the
rewritten spec and the generated client are committed; CI fails if they are out
of date.
