"""
OAuth 2.1 authorization server, as required by the MCP authorization spec:

  * RFC 8414 / RFC 9728 metadata so clients can discover us,
  * RFC 7591 dynamic client registration (claude.ai registers itself),
  * authorization code flow with mandatory PKCE, where the "login" step is a
    form whose credentials are checked by Zabbix, which then issues the API
    token the user's MCP calls will run with,
  * token endpoint with rotating refresh tokens.

The only resource this server issues tokens for is our own /mcp endpoint.
"""
import base64
import hashlib
import html
import logging
import secrets
import time
from string import Template
from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

import config
import store
import zabbix

router = APIRouter()
log = logging.getLogger(__name__)

AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")

LOGIN_PAGE = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zabbix MCP login</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 22rem; margin: 4rem auto; padding: 0 1rem; color: #222; }
  label { display: block; margin-top: 1rem; }
  input { width: 100%; padding: .5rem; font-size: 1rem; box-sizing: border-box; margin-top: .25rem; }
  button { margin-top: 1.5rem; padding: .6rem 1.2rem; font-size: 1rem; }
  .error { color: #b00020; }
</style></head>
<body>
<h1>Zabbix MCP</h1>
<p>$client wants to use Zabbix as you. Log in with your Zabbix account.</p>
$error
<form method="post" action="/authorize">
  <input type="hidden" name="rid" value="$rid">
  <label>Username <input name="username" autocomplete="username" autofocus required></label>
  <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
  <button type="submit">Log in</button>
</form>
</body></html>
""")


def _error(status: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _with_params(url: str, params: dict) -> str:
    """Append query parameters (skipping None values) to a redirect URI."""
    parts = urlsplit(url)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _redirect_uri_allowed(uri: str) -> bool:
    parts = urlsplit(uri)
    if parts.fragment or parts.hostname not in config.ALLOWED_REDIRECT_HOSTS:
        return False
    # Loopback redirects (Claude Code, MCP Inspector) may be plain http.
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1"))


def _resource_ok(resource: str | None) -> bool:
    if resource is None:
        return True
    return resource.rstrip("/").lower() in (config.RESOURCE_URL.lower(), config.BASE_URL.lower())


def _login_page(rid: str, client_name: str | None, error: str | None = None) -> HTMLResponse:
    return HTMLResponse(LOGIN_PAGE.substitute(
        client=html.escape(client_name or "An MCP client"),
        error=f'<p class="error">{html.escape(error)}</p>' if error else "",
        rid=html.escape(rid),
    ))


# --- discovery --------------------------------------------------------------

@router.get("/.well-known/oauth-authorization-server")
def authorization_server_metadata():
    return {
        "issuer": config.BASE_URL,
        "authorization_endpoint": f"{config.BASE_URL}/authorize",
        "token_endpoint": f"{config.BASE_URL}/token",
        "registration_endpoint": f"{config.BASE_URL}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": list(AUTH_METHODS),
    }


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_metadata():
    return {
        "resource": config.RESOURCE_URL,
        "authorization_servers": [config.BASE_URL],
        "bearer_methods_supported": ["header"],
    }


# --- dynamic client registration -------------------------------------------

@router.post("/register")
async def register(request: Request):
    try:
        body = await request.json()
    except ValueError:
        return _error(400, "invalid_client_metadata", "body must be JSON")
    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _error(400, "invalid_client_metadata", "redirect_uris is required")
    for uri in redirect_uris:
        if not isinstance(uri, str) or not _redirect_uri_allowed(uri):
            return _error(400, "invalid_redirect_uri", f"redirect_uri not allowed: {uri}")
    method = body.get("token_endpoint_auth_method", "client_secret_basic")
    if method not in AUTH_METHODS:
        return _error(400, "invalid_client_metadata", f"unsupported token_endpoint_auth_method: {method}")

    client = {
        "client_id": store.new_secret(16),
        "client_secret": None if method == "none" else store.new_secret(32),
        "client_name": body.get("client_name"),
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": method,
        "created_at": int(time.time()),
    }
    store.save_client(client)
    log.info("registered client=%s name=%r redirect_uris=%s", client["client_id"], client["client_name"], redirect_uris)

    response = {k: v for k, v in client.items() if v is not None}
    response["client_id_issued_at"] = response.pop("created_at")
    if client["client_secret"]:
        response["client_secret_expires_at"] = 0
    response["grant_types"] = ["authorization_code", "refresh_token"]
    response["response_types"] = ["code"]
    return JSONResponse(response, status_code=201)


# --- authorization endpoint (login checked by Zabbix) -----------------------

@router.get("/authorize")
def authorize(request: Request):
    q = request.query_params
    client = store.get_client(q.get("client_id", ""))
    redirect_uri = q.get("redirect_uri")
    # Until the client and its redirect URI check out, errors must not redirect.
    if client is None:
        return HTMLResponse("Unknown client_id.", status_code=400)
    if redirect_uri not in client["redirect_uris"]:
        return HTMLResponse("redirect_uri is not registered for this client.", status_code=400)

    def fail(error: str, description: str):
        return RedirectResponse(
            _with_params(redirect_uri, {"error": error, "error_description": description, "state": q.get("state")}),
            status_code=302,
        )

    if q.get("response_type") != "code":
        return fail("unsupported_response_type", "only response_type=code is supported")
    if not q.get("code_challenge") or q.get("code_challenge_method", "plain") != "S256":
        return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
    if not _resource_ok(q.get("resource")):
        return fail("invalid_target", f"resource must be {config.RESOURCE_URL}")

    rid = store.save_auth_request(
        client_id=client["client_id"],
        redirect_uri=redirect_uri,
        code_challenge=q["code_challenge"],
        state=q.get("state"),
        scope=q.get("scope"),
    )
    return _login_page(rid, client["client_name"])


@router.post("/authorize")
async def authorize_login(request: Request):
    form = await request.form()
    rid = form.get("rid", "")
    req = store.get_auth_request(rid)
    if req is None:
        return HTMLResponse("This login request has expired. Start again from your MCP client.", status_code=400)
    client = store.get_client(req["client_id"])
    client_name = client["client_name"] if client else None

    try:
        session, userid, username = await zabbix.login(form.get("username", ""), form.get("password", ""))
    except zabbix.LoginError as e:
        log.warning("login failed user=%r client=%s: %s", form.get("username"), req["client_id"], e)
        return _login_page(rid, client_name, str(e))  # the request stays pending for another try

    if config.ALLOWED_USERS and username.lower() not in config.ALLOWED_USERS:
        await zabbix.logout(session)
        store.delete_auth_request(rid)
        log.warning("denied user=%s client=%s", username, req["client_id"])
        return RedirectResponse(
            _with_params(req["redirect_uri"], {
                "error": "access_denied",
                "error_description": f"{username} is not allowed to use this Zabbix MCP server",
                "state": req["state"],
            }),
            status_code=302,
        )

    # The Zabbix token lives as long as the refresh token; each refresh
    # extends both.
    try:
        zabbix_token, zabbix_tokenid = await zabbix.mint_token(session, userid, int(time.time()) + config.REFRESH_TOKEN_TTL)
    except zabbix.ZabbixError as e:
        log.warning("token.create failed user=%s client=%s: %s", username, req["client_id"], e)
        return _login_page(rid, client_name, f"Zabbix would not issue an API token: {e}")

    store.delete_auth_request(rid)
    code = store.new_secret(32)
    store.save_auth_code(
        code,
        client_id=req["client_id"],
        redirect_uri=req["redirect_uri"],
        code_challenge=req["code_challenge"],
        scope=req["scope"],
        username=username,
        zabbix_token=zabbix_token,
        zabbix_tokenid=zabbix_tokenid,
    )
    log.info("authorized user=%s client=%s", username, req["client_id"])
    return RedirectResponse(_with_params(req["redirect_uri"], {"code": code, "state": req["state"]}), status_code=302)


# --- token endpoint ---------------------------------------------------------

def _client_credentials(request: Request, form) -> tuple[str | None, str | None]:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "basic":
        try:
            client_id, _, secret = base64.b64decode(value).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return None, None
        return unquote(client_id), unquote(secret)
    return form.get("client_id"), form.get("client_secret")


def _client_auth_ok(client: dict, secret: str | None) -> bool:
    if client["client_secret"] is None:  # public client
        return True
    return secret is not None and secrets.compare_digest(secret, client["client_secret"])


def _pkce_ok(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(expected, challenge)


def _issue_tokens(client_id: str, username: str, scope: str | None, zabbix_token: str, zabbix_tokenid: str) -> JSONResponse:
    store.purge_expired()
    access, refresh = store.new_secret(32), store.new_secret(32)
    store.save_token(access, "access", client_id, username, scope, config.ACCESS_TOKEN_TTL, zabbix_token, zabbix_tokenid)
    store.save_token(refresh, "refresh", client_id, username, scope, config.REFRESH_TOKEN_TTL, zabbix_token, zabbix_tokenid)
    log.info("issued tokens user=%s client=%s", username, client_id)
    body = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": config.ACCESS_TOKEN_TTL,
        "refresh_token": refresh,
    }
    if scope:
        body["scope"] = scope
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@router.post("/token")
async def token(request: Request):
    form = await request.form()
    client_id, secret = _client_credentials(request, form)
    client = store.get_client(client_id or "")
    if client is None or not _client_auth_ok(client, secret):
        return _error(401, "invalid_client", "client authentication failed")

    grant_type = form.get("grant_type")
    if grant_type == "authorization_code":
        code = store.pop_auth_code(form.get("code", ""))
        if code is None or code["client_id"] != client["client_id"]:
            return _error(400, "invalid_grant", "authorization code is invalid or expired")
        if form.get("redirect_uri") and form["redirect_uri"] != code["redirect_uri"]:
            return _error(400, "invalid_grant", "redirect_uri mismatch")
        if not _pkce_ok(form.get("code_verifier", ""), code["code_challenge"]):
            return _error(400, "invalid_grant", "PKCE verification failed")
        if not _resource_ok(form.get("resource")):
            return _error(400, "invalid_target", f"resource must be {config.RESOURCE_URL}")
        return _issue_tokens(client["client_id"], code["username"], code["scope"], code["zabbix_token"], code["zabbix_tokenid"])

    if grant_type == "refresh_token":
        old = store.get_token(form.get("refresh_token", ""), "refresh")
        if old is None or old["client_id"] != client["client_id"]:
            return _error(400, "invalid_grant", "refresh token is invalid or expired")
        store.delete_token(form["refresh_token"])  # rotate
        try:
            await zabbix.extend_token(old["zabbix_token"], old["zabbix_tokenid"], int(time.time()) + config.REFRESH_TOKEN_TTL)
        except zabbix.ZabbixError as e:
            # The token was revoked, or expired: the user logs in again.
            log.warning("token.update failed user=%s client=%s: %s", old["username"], client["client_id"], e)
            return _error(400, "invalid_grant", "the Zabbix API token could not be renewed; log in again")
        return _issue_tokens(client["client_id"], old["username"], old["scope"], old["zabbix_token"], old["zabbix_tokenid"])

    return _error(400, "unsupported_grant_type", "use authorization_code or refresh_token")
