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
docker run -p 127.0.0.1:8080:8080 \
  -e YNAB_ACCESS_TOKEN=... \
  -e MCP_USERNAME=you \
  -e MCP_PASSWORD='a long password' \
  -e MCP_SIGNING_KEY="$(openssl rand -base64 32)" \
  -e MCP_ORIGIN=https://ynab.example.com \
  ghcr.io/barmore-genc/mcp-for-ynab:latest
```

Generate `MCP_SIGNING_KEY` once and keep it: every token the server issues is
signed with it, so a new key signs every connected agent out.

With Docker Compose, copy `docker-compose.example.yml`, fill in the values and
run `docker compose up -d`.

Get the YNAB token from **Account Settings → Developer Settings → New Access
Token** in the YNAB web app. It is a personal access token, so this server sees
exactly the one YNAB account it belongs to.

`MCP_ORIGIN` is the public URL the server is reached at, scheme included. It has
to be right: the OAuth flow builds every URL it advertises from it. It must be
`https://`, except for `localhost` or a loopback address while trying the server
out on your own machine.

The examples publish the port on `127.0.0.1` only. Put a reverse proxy that
terminates TLS in front of it, and set `MCP_TRUSTED_PROXIES` to the proxy's
address so the server counts sign-in attempts per visitor rather than all as the
proxy. The server reads `X-Forwarded-For` only from the addresses listed there.

| Variable | Required | Meaning |
| --- | --- | --- |
| `YNAB_ACCESS_TOKEN` | yes | YNAB personal access token |
| `MCP_ORIGIN` | yes | Public base URL, e.g. `https://ynab.example.com` |
| `MCP_SIGNING_KEY` | yes | Signs the OAuth credentials. At least 32 characters of random data, e.g. from `openssl rand -base64 32` |
| `MCP_USERNAME` | password mode | What you type on the sign-in page |
| `MCP_PASSWORD` | password mode | The password for it, at least 12 characters |
| `MCP_TRUSTED_PROXIES` | no | Comma-separated addresses or CIDRs of reverse proxies whose `X-Forwarded-For` is used, e.g. `172.16.0.0/12` |
| `MCP_ADDR` | no | Listen address, `:8080` by default |
| `MCP_READ_ONLY` | no | `true` to offer only the read tools |
| `MCP_OIDC_ISSUER` | OIDC mode | Provider base URL, e.g. `https://id.example.com` |
| `MCP_OIDC_CLIENT_ID` | OIDC mode | Client id registered at the provider |
| `MCP_OIDC_CLIENT_SECRET` | no | Only for confidential clients; omit for a public PKCE client |
| `MCP_OIDC_PROVIDER_NAME` | no | Name shown on the sign-in button, e.g. `Pocket ID` |
| `MCP_OIDC_SCOPES` | no | Scopes to request, `openid email profile` by default |
| `MCP_OIDC_REDIRECT_URI` | no | Overrides the callback, `$MCP_ORIGIN/oidc/callback` by default |
| `MCP_OIDC_ALLOWED_EMAILS` | OIDC mode¹ | Comma-separated verified addresses allowed to sign in |
| `MCP_OIDC_ALLOWED_SUBJECTS` | OIDC mode¹ | Comma-separated provider subject ids allowed to sign in |
| `MCP_OIDC_ALLOW_ANY` | OIDC mode¹ | `true` to accept every account the provider authenticates |

¹ OIDC mode needs at least one of these three.

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

Set `MCP_OIDC_ISSUER` and `MCP_OIDC_CLIENT_ID` to turn it on, say who may sign
in (see [Who is allowed in](#who-is-allowed-in)), and drop
`MCP_USERNAME`/`MCP_PASSWORD`. When an issuer is set, sign-in goes through OIDC
and a leftover `MCP_USERNAME`/`MCP_PASSWORD` is ignored; the server logs a
warning saying so rather than pretending the password still works.

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
   docker run -p 127.0.0.1:8080:8080 \
     -e YNAB_ACCESS_TOKEN=... \
     -e MCP_ORIGIN=https://ynab.example.com \
     -e MCP_OIDC_ISSUER=https://id.example.com \
     -e MCP_OIDC_CLIENT_ID=<client id> \
     -e MCP_OIDC_PROVIDER_NAME='Pocket ID' \
     -e MCP_OIDC_ALLOWED_EMAILS=you@example.com \
     -e MCP_SIGNING_KEY="$(openssl rand -base64 32)" \
     ghcr.io/barmore-genc/mcp-for-ynab:latest
   ```

   `MCP_OIDC_ISSUER` is Pocket ID's own URL, the one you open in a browser, not
   an internal container address. `MCP_OIDC_CLIENT_SECRET` is only needed if you
   turned **Public client** off. To accept anyone who can sign in at Pocket ID,
   replace `MCP_OIDC_ALLOWED_EMAILS` with `MCP_OIDC_ALLOW_ANY=true`.

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

Set `MCP_OIDC_ALLOWED_EMAILS` and/or `MCP_OIDC_ALLOWED_SUBJECTS` to pin the
server to specific identities. An email has to match exactly, case-insensitively,
and only counts when the provider marks it as verified (`email_verified`); the
subject is the provider's stable user id. A sign-in that matches neither is sent
back to the agent as `access_denied` and logged by the server.

`MCP_OIDC_ALLOW_ANY=true` accepts every account the provider authenticates
instead. Use it only when the provider itself contains nobody but you: with
Google, for example, it would let in anyone with a Google account. The server
refuses to start in OIDC mode unless one of these is set.

## How authentication works

The container is its own OAuth 2.1 authorization server. It registers clients
dynamically, requires PKCE with S256, and issues an access token good for an
hour and a refresh token good for thirty days. Each refresh extends that, up to
90 days after you signed in; after that the agent sends you through the sign-in
page again.

None of that is stored. Every credential it issues is a signed string that
carries its own contents, so the container keeps no database and no volume, and
restarting or replacing it does not disconnect anything. The only thing held in
memory is the set of authorization codes already redeemed, which expire a minute
after they are minted.

Changing `MCP_SIGNING_KEY` invalidates every outstanding token at once, which is
how you revoke access. Changing `MCP_PASSWORD` only affects future sign-ins.

The sign-in page shows the address the agent will receive access at. Check it
before you sign in: the app name shown below it is whatever the app registered
itself as. Sign-in attempts are limited to 5 per minute per address and 20 per
minute in total.

With an identity provider, a sign-in has to finish in the browser that started
it. The signed state that carries it through the provider expires after ten
minutes and can be used only once.

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
