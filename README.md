# zabbix-auth-mcp

An OAuth 2.1 front door for [zabbix-mcp-server](https://github.com/rutgers-lcsr/zabbix-mcp-server)
(the LCSR fork of initMAX's server) so Claude (claude.ai, Claude Desktop,
Claude Code) can use Zabbix as an MCP connector, logging in with a Zabbix
(LDAP) account and acting in Zabbix as that user, with that user's role and
host group permissions. Zabbix, not this service, decides what each user may
see and do.

Sibling of [grafana-auth-mcp](https://git.lcsr.rutgers.edu/systems-cs/grafana-auth-mcp),
deployed the same way.

## The problem

Claude's custom connectors authenticate to remote MCP servers with OAuth 2.1
only: the server has to publish OAuth metadata, accept dynamic client
registration, and run an authorization-code flow with PKCE. zabbix-mcp-server
over HTTP wants a static bearer token per client and talks to Zabbix with one
shared API token, so every user would have the shared token's rights and
nothing in Zabbix would show who did what. Upstream declined to change that
(their issue #74), hence the fork.

## What this does

```
Claude ──OAuth──▶ zabbix-auth-mcp ──bearer + X-Zabbix-Token──▶ zabbix-mcp-server ──user's token──▶ Zabbix
                        │                                                                         ▲
                        └── login form: user.login, then token.create + token.generate ───────────┘
```

`zabbix-auth-mcp` is both the OAuth authorization server and a reverse proxy:

1. An MCP client calls `/mcp` without a token and gets a `401` whose
   `WWW-Authenticate` header points at `/.well-known/oauth-protected-resource/mcp`.
2. From there it discovers the authorization server (this same service) and
   registers itself at `/register`.
3. It sends the user's browser to `/authorize`, which shows a login form. The
   credentials go to Zabbix's `user.login`, so Zabbix and its LDAP decide who
   the user is. With the session that comes back, and nothing else, the
   service creates an API token for that same user (`token.create`,
   `token.generate`) and closes the session. The password is not stored, and
   no service account is involved: a user can only mint tokens for themselves.
4. The client swaps the authorization code (plus PKCE verifier) at `/token`
   for an access token (1 hour) and a rotating refresh token (30 days). The
   Zabbix token expires with the refresh token; each refresh pushes both out
   again (`token.update`). If Zabbix will not renew it (revoked, role
   changed) the refresh fails and the user logs in again.
5. Every `/mcp` request is checked against the token store and forwarded to
   zabbix-mcp-server with its own bearer token plus the user's Zabbix token in
   `X-Zabbix-Token`. The fork runs every Zabbix call with that token, so
   Zabbix applies the user's permissions and its audit log names the user.
   Responses, including SSE streams, are passed back unchanged. Only a short
   allowlist of headers is forwarded, so the caller's token, cookies, `Origin`
   and any forged `X-Zabbix-Token` never reach zabbix-mcp-server.

One log line per MCP call records who did what:

```
INFO proxy: user=mk1800 POST tools/call host_get
```

## What Zabbix needs

- Zabbix 5.4 or newer (API tokens). Tested against 6.0. Both the 6.0 body
  `auth` style and the 6.4+ `Authorization` header are handled, chosen from
  `apiinfo.version`.
- Each user's role must allow API access and the "Manage API tokens" action
  (both on by default in the built-in roles). A user whose role lacks the
  latter sees "Zabbix would not issue an API token" on the login form.
- Nothing else: no service user, no shared token. The tokens this service
  creates are named `zabbix-auth-mcp <timestamp>` under the user's own API
  tokens, where the user or an admin can revoke them.

## Deploying on popek

Same model as grafana-auth-mcp. This is its own compose project in
`/data/local/docker_sources/zabbix-mcp`, on `macvlan-vlan4`, so it gets a
public address (`IPV4_ADDRESS` in `.env`) and serves https on 443 there.
claude.ai and Claude Desktop connectors are driven from Anthropic's servers,
so the proxy must be reachable from the public internet; Claude Code connects
from your own machine. The proxy is also on the project's bridge network,
which is how it reaches zabbix-mcp-server; zabbix-mcp-server itself is only
on the bridge and reaches Zabbix (sarek) through popek's host and the VLAN
router. The fork's container is built straight from its GitHub branch by
`docker compose build`; there is nothing to clone for it.

Port 80 on the public address serves nothing: it redirects Let's Encrypt
challenges to services.cs.rutgers.edu and everything else to https. That is
what lets the cert keep coming from services (the `remotecert_compose`
model, where certbot runs on services and popek fetches the cert) even
though the public DNS name points at the proxy rather than at services.

1. **Name, address, cert.** `zabbix-mcp.lcsr.rutgers.edu` at `128.6.4.31`:
   both the internal and the external DNS A record point there, and the
   campus firewall must allow 80 and 443 to it. Follow the
   `remotecert_compose` role in systems-playbooks: the name goes into
   `remotecert_compose_certs` in popek's host_vars, and after the play check
   that `/etc/letsencrypt/live/<name>/cert.pem` exists on popek. (The role's
   README asks for an external CNAME to services; here the port-80 redirect
   plays that part, and it must be running before the first issuance.)

2. **Clone and configure.**

   ```bash
   cd /data/local/docker_sources
   git clone https://github.com/rutgers-lcsr/zabbix-auth-mcp.git zabbix-mcp
   cd zabbix-mcp
   cp .env.example .env   # then set MCP_BACKEND_TOKEN; check BASE_URL, CERT_NAME, IPV4_ADDRESS, ZABBIX_URL
   mkdir -p data && chmod 700 data   # holds the users' Zabbix tokens
   ```

   `zabbix-mcp/config.toml` is the fork's config; the Zabbix URL is repeated
   there because that file cannot read `.env`.

3. **Start it.** `docker compose up -d --build`. `docker compose logs`
   should show uvicorn listening on 443 and zabbix-mcp-server registering
   its tools. Before the cert exists, start with
   `docker compose -f docker-compose.yml -f compose.bootstrap.yml up -d`
   instead: that serves the port-80 redirect the issuance needs and skips
   TLS. Once the cert has arrived, `docker compose up -d --force-recreate`.

4. **Check.** `curl https://<name>/.well-known/oauth-authorization-server`
   should return JSON, and `curl -i https://<name>/mcp` should return a
   401 with a `WWW-Authenticate` header. Then add the connector in Claude,
   log in with your own Zabbix account, and ask for the host list: it should
   be exactly what you see in the Zabbix UI, and a new API token named
   `zabbix-auth-mcp <timestamp>` appears under your user in Zabbix.

When the cert renews, the `remotecert_compose` role's `compose-restart` hook
restarts this service because it mounts the cert directory. To prove the
renewal path works end to end, run on services:
`certbot renew --dry-run --cert-name <name>`.

## Connecting Claude

- **claude.ai / Claude Desktop:** Settings → Connectors → Add custom
  connector. URL: `https://<name>/mcp`. Leave OAuth Client ID and Secret
  empty; Claude registers itself. Click Connect and log in with your Zabbix
  account.
- **Claude Code:** `claude mcp add --transport http zabbix https://<name>/mcp`,
  then run `/mcp` inside Claude Code to authenticate.

Anyone with a Zabbix login can connect and gets exactly their own Zabbix
permissions. Set `ALLOWED_USERS` to restrict it further.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `BASE_URL` | yes | Public https URL of this service, no trailing slash. |
| `ZABBIX_URL` | yes | Zabbix frontend URL (with its path, e.g. `/zabbix`), used to check logins and issue tokens. |
| `MCP_BACKEND_URL` | yes | zabbix-mcp-server's streamable-http endpoint (compose sets `http://zabbix-mcp-server:8080/mcp`). |
| `MCP_BACKEND_TOKEN` | yes | Shared secret; zabbix-mcp-server reads it into `auth_token` from the same variable. |
| `ALLOWED_USERS` | no | Comma-separated Zabbix usernames. Empty means anyone with a Zabbix login. |
| `ALLOWED_REDIRECT_HOSTS` | no | Hosts OAuth clients may redirect to. Default `claude.ai,claude.com,localhost,127.0.0.1,blob.cs.rutgers.edu`. |
| `ZABBIX_TOKEN_HEADER` | no | Header carrying the user's token to zabbix-mcp-server. Default `X-Zabbix-Token`; must match `zabbix-mcp/config.toml`. |
| `ZABBIX_TOKEN_NAME` | no | Prefix of the API token names created in Zabbix. Default `zabbix-auth-mcp`. |
| `DB_PATH` | no | SQLite file for clients, tokens and the users' Zabbix tokens. Default `data/zabbix-auth-mcp.sqlite3`. |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | no | Seconds. Defaults 3600 and 2592000. The Zabbix token lives as long as the refresh token. |
| `ACME_REDIRECT_URL` | no | Where port 80 sends Let's Encrypt challenges. Default `http://services.cs.rutgers.edu`. |
| `PORT`, `HTTP_PORT`, `SSL_CERTFILE`, `SSL_KEYFILE` | container | https port (default 8443), the optional redirect-only http port, and the cert uvicorn serves. |
| `CERT_NAME`, `IPV4_ADDRESS` | compose | Letsencrypt directory name mounted into the container, and the container's public address. |

## Endpoints

| Path | Purpose |
|---|---|
| `/mcp` | The protected MCP endpoint (GET, POST, DELETE), proxied to zabbix-mcp-server. |
| `/.well-known/oauth-protected-resource[/mcp]` | RFC 9728 resource metadata. |
| `/.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata. |
| `/register` | RFC 7591 dynamic client registration. |
| `/authorize` | GET shows the login form, POST checks the credentials with Zabbix and mints the token. |
| `/token` | Token endpoint (`authorization_code`, `refresh_token`). |
| `/healthz` | Liveness. |

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest            # unit tests, Zabbix and zabbix-mcp-server stubbed
tests/integration.sh        # the real fork + this service against a fake Zabbix, full flow
```

The unit tests cover discovery, registration, the login form, PKCE,
single-use codes, refresh rotation and token renewal, the allowlist, header
filtering and the Zabbix token the proxy forwards. The integration script
starts a fake Zabbix JSON-RPC server that answers the handful of methods
involved, the real zabbix-mcp-server fork from a sibling checkout, and this
service, then drives the OAuth flow and an MCP tool call through all three
and checks that the fork called Zabbix with the token minted at login.
