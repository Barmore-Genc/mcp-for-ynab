# mcp-for-ynab

An MCP server that gives an AI agent access to your [YNAB](https://www.ynab.com/)
budget. It runs as one small container, holds no state, and needs nothing but a
YNAB token and a username and password of your choosing.

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
| `MCP_USERNAME` | yes | What you type on the sign-in page |
| `MCP_PASSWORD` | yes | The password for it, at least 12 characters |
| `MCP_ORIGIN` | yes | Public base URL, e.g. `https://ynab.example.com` |
| `MCP_ADDR` | no | Listen address, `:8080` by default |
| `MCP_READ_ONLY` | no | `true` to offer only the read tools |
| `MCP_SIGNING_KEY` | no | Signs the OAuth credentials; derived from the password otherwise |

## Connecting an agent to it

Add `https://your-origin/mcp` as an MCP connector. The agent will send you to a
sign-in page; enter the username and password from the container's environment,
and it is connected.

There is no account to create and no other user interface. The sign-in page and
the OAuth endpoints behind it exist because the OAuth flow is the only way the
connector UIs know how to authenticate against an MCP server.

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
token at once, which is how you revoke access.

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
