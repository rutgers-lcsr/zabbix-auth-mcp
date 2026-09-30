"""
End-to-end tests of the OAuth flow and the proxy, with Zabbix and
zabbix-mcp-server replaced by stubs. Config is set through the environment before importing the
app, so these must run in their own process (which pytest does).
"""
import base64
import hashlib
import os
import re
import tempfile
from urllib.parse import parse_qs, urlsplit

TMP = tempfile.mkdtemp()
os.environ.update({
    "BASE_URL": "https://mcp.test",
    "MCP_BACKEND_URL": "http://backend/mcp",
    "MCP_BACKEND_TOKEN": "backend-secret",
    "ZABBIX_URL": "http://zabbix.test/zabbix",
    "ALLOWED_USERS": "alice, carol",  # empty would mean "anyone Zabbix accepts"
    "DB_PATH": os.path.join(TMP, "test.sqlite3"),
})

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import proxy  # noqa: E402
import zabbix  # noqa: E402
from main import app  # noqa: E402

CALLBACK = "https://claude.ai/api/mcp/auth_callback"

backend = FastAPI()


@backend.api_route("/mcp", methods=["GET", "POST", "DELETE"])
async def backend_mcp(request: Request):
    """Stand-in for zabbix-mcp-server: echoes what it received."""
    return JSONResponse(
        {"seen_headers": dict(request.headers), "body": (await request.body()).decode()},
        headers={"Mcp-Session-Id": "sess-1", "X-Internal": "hidden"},
    )


zabbix_calls: list[tuple] = []
mint_fails = False
extend_fails = False


async def fake_login(username: str, password: str) -> tuple[str, str, str]:
    """Stand-in for user.login: the password is always 'pw'."""
    if password == "pw" and username:
        return f"sess-{username}", "42", username
    raise zabbix.LoginError("Incorrect user name or password or account is temporarily blocked.")


async def fake_logout(session: str) -> None:
    zabbix_calls.append(("logout", session))


async def fake_mint_token(session: str, userid: str, expires_at: int) -> tuple[str, str]:
    zabbix_calls.append(("mint", session, userid, expires_at))
    if mint_fails:
        raise zabbix.ZabbixError('No permissions to call "token.create".')
    return f"ztok-{session.removeprefix('sess-')}", "7"


async def fake_extend_token(token: str, tokenid: str, expires_at: int) -> None:
    zabbix_calls.append(("extend", token, tokenid, expires_at))
    if extend_fails:
        raise zabbix.ZabbixError("Not authorised.")


@pytest.fixture(autouse=True)
def stubs(monkeypatch):
    global mint_fails, extend_fails
    mint_fails = extend_fails = False
    zabbix_calls.clear()
    monkeypatch.setattr(zabbix, "login", fake_login)
    monkeypatch.setattr(zabbix, "logout", fake_logout)
    monkeypatch.setattr(zabbix, "mint_token", fake_mint_token)
    monkeypatch.setattr(zabbix, "extend_token", fake_extend_token)
    monkeypatch.setattr(proxy, "client", httpx.AsyncClient(transport=httpx.ASGITransport(app=backend)))


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def pkce():
    verifier = "correct-horse-battery-staple-correct-horse-battery-staple"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(client, **extra):
    r = client.post("/register", json={"redirect_uris": [CALLBACK], "client_name": "Claude", **extra})
    assert r.status_code == 201, r.text
    return r.json()


def start_login(client, client_id, challenge, state="xyz", resource="https://mcp.test/mcp"):
    """GET /authorize. Returns the login page's rid, or the error params sent to the redirect_uri."""
    r = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": CALLBACK,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": resource,
        },
        follow_redirects=False,
    )
    if r.status_code == 302:
        return None, {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    assert r.status_code == 200, r.text
    assert "Claude wants to use Zabbix as you" in r.text
    return re.search(r'name="rid" value="([^"]+)"', r.text).group(1), None


def submit_login(client, rid, username, password="pw"):
    """POST the login form. Returns (response, params sent to the redirect_uri or None)."""
    r = client.post("/authorize", data={"rid": rid, "username": username, "password": password}, follow_redirects=False)
    if r.status_code != 302:
        return r, None
    location = urlsplit(r.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == CALLBACK
    return r, {k: v[0] for k, v in parse_qs(location.query).items()}


def login(client, client_id, challenge, username="alice"):
    rid, _ = start_login(client, client_id, challenge)
    _, params = submit_login(client, rid, username)
    return params


def test_unauthenticated_request_points_at_metadata(client):
    r = client.post("/mcp", json={})
    assert r.status_code == 401
    assert 'resource_metadata="https://mcp.test/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]

    meta = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert meta == {
        "resource": "https://mcp.test/mcp",
        "authorization_servers": ["https://mcp.test"],
        "bearer_methods_supported": ["header"],
    }
    assert client.get("/.well-known/oauth-protected-resource").json() == meta

    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["issuer"] == "https://mcp.test"
    assert asm["registration_endpoint"] == "https://mcp.test/register"
    assert asm["code_challenge_methods_supported"] == ["S256"]


def test_register_rejects_untrusted_redirect(client):
    r = client.post("/register", json={"redirect_uris": ["https://evil.example/cb"]})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"
    r = client.post("/register", json={"redirect_uris": ["http://claude.ai/api/mcp/auth_callback"]})
    assert r.status_code == 400, "https is required for non-loopback hosts"
    r = client.post("/register", json={"redirect_uris": ["http://localhost:3334/callback"]})
    assert r.status_code == 201, "loopback may be plain http (Claude Code, MCP Inspector)"


def test_full_flow_and_proxy(client):
    reg = register(client, token_endpoint_auth_method="none")
    assert "client_secret" not in reg
    verifier, challenge = pkce()
    params = login(client, reg["client_id"], challenge)
    assert params["state"] == "xyz"

    exchange = {
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": CALLBACK,
        "client_id": reg["client_id"],
        "code_verifier": verifier,
        "resource": "https://mcp.test/mcp",
    }
    r = client.post("/token", data=exchange)
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == 3600 and tok["refresh_token"]

    r = client.post("/token", data=exchange)
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant", "codes are single use"

    r = client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_datasources"}}',
        headers={
            "Authorization": f"Bearer {tok['access_token']}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Session-Id": "sess-1",
            "Origin": "https://claude.ai",
            "Cookie": "session=abc",
            "X-Zabbix-Token": "forged",
        },
    )
    assert r.status_code == 200, r.text
    seen = r.json()["seen_headers"]
    assert seen["authorization"] == "Bearer backend-secret", "caller token is swapped for the backend token"
    assert seen["x-zabbix-token"] == "ztok-alice", "the token Zabbix issued to alice at login, not the forged one"
    assert seen["mcp-session-id"] == "sess-1" and seen["accept"] == "application/json, text/event-stream"
    assert "origin" not in seen and "cookie" not in seen
    assert r.headers["mcp-session-id"] == "sess-1" and "x-internal" not in r.headers

    # Login used the session once, to mint the token for alice's own userid.
    mint = next(c for c in zabbix_calls if c[0] == "mint")
    assert mint[1:3] == ("sess-alice", "42")

    r = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": reg["client_id"]})
    assert r.status_code == 200, r.text
    new = r.json()
    assert new["access_token"] != tok["access_token"]
    extend = next(c for c in zabbix_calls if c[0] == "extend")
    assert extend[1:3] == ("ztok-alice", "7"), "refresh pushes the Zabbix token's expiry out"
    r = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": reg["client_id"]})
    assert r.status_code == 400, "refresh tokens rotate"
    r = client.post("/mcp", content=b"{}", headers={"Authorization": f"Bearer {new['access_token']}"})
    assert r.status_code == 200
    assert r.json()["seen_headers"]["x-zabbix-token"] == "ztok-alice", "the refreshed grant keeps the same Zabbix token"


def test_refresh_fails_when_zabbix_will_not_renew_the_token(client):
    global extend_fails
    reg = register(client, token_endpoint_auth_method="none")
    verifier, challenge = pkce()
    params = login(client, reg["client_id"], challenge)
    tok = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"], "redirect_uri": CALLBACK,
        "client_id": reg["client_id"], "code_verifier": verifier,
    }).json()
    extend_fails = True
    r = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": reg["client_id"]})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
    assert "log in again" in r.json()["error_description"]


def test_login_without_token_permission_shows_the_error(client):
    global mint_fails
    mint_fails = True
    reg = register(client)
    _, challenge = pkce()
    rid, _ = start_login(client, reg["client_id"], challenge)
    r, params = submit_login(client, rid, "alice")
    assert r.status_code == 200 and params is None
    assert "Zabbix would not issue an API token" in r.text and "token.create" in r.text
    _, params = submit_login(client, rid, "alice")
    assert r.status_code == 200 and params is None, "a failed mint does not consume the login request either"


def test_wrong_password_then_right_password(client):
    reg = register(client)
    _, challenge = pkce()
    rid, _ = start_login(client, reg["client_id"], challenge)
    r, params = submit_login(client, rid, "alice", password="wrong")
    assert r.status_code == 200 and params is None
    assert "Incorrect user name or password" in r.text
    _, params = submit_login(client, rid, "alice")
    assert "code" in params, "a failed attempt does not consume the login request"
    r, _ = submit_login(client, rid, "alice")
    assert r.status_code == 400, "a successful login does"


def test_wrong_pkce_verifier(client):
    reg = register(client, token_endpoint_auth_method="none")
    _, challenge = pkce()
    params = login(client, reg["client_id"], challenge)
    r = client.post("/token", data={
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": CALLBACK,
        "client_id": reg["client_id"],
        "code_verifier": "not-the-verifier",
    })
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"


def test_user_not_allowed(client):
    reg = register(client)
    _, challenge = pkce()
    params = login(client, reg["client_id"], challenge, username="bob")
    assert params["error"] == "access_denied" and "bob" in params["error_description"]
    assert params["state"] == "xyz"
    assert ("logout", "sess-bob") in zabbix_calls, "the session is closed and no token is minted"
    assert not any(c[0] == "mint" for c in zabbix_calls)


def test_wrong_resource(client):
    reg = register(client)
    _, challenge = pkce()
    _, params = start_login(client, reg["client_id"], challenge, resource="https://other.example/mcp")
    assert params["error"] == "invalid_target"


def test_confidential_client_needs_secret(client):
    reg = register(client)  # default token_endpoint_auth_method issues a secret
    assert reg["client_secret"] and reg["token_endpoint_auth_method"] == "client_secret_basic"
    verifier, challenge = pkce()
    params = login(client, reg["client_id"], challenge)
    exchange = {
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": CALLBACK,
        "client_id": reg["client_id"],
        "code_verifier": verifier,
    }
    r = client.post("/token", data=exchange)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client"
    r = client.post("/token", data=exchange, auth=(reg["client_id"], reg["client_secret"]))
    assert r.status_code == 200, r.text


def test_unknown_client_does_not_redirect(client):
    r = client.get("/authorize", params={"client_id": "nope", "redirect_uri": CALLBACK}, follow_redirects=False)
    assert r.status_code == 400
    reg = register(client)
    r = client.get("/authorize", params={"client_id": reg["client_id"], "redirect_uri": "https://claude.ai/other"}, follow_redirects=False)
    assert r.status_code == 400
    r = client.post("/authorize", data={"rid": "nope", "username": "alice", "password": "pw"}, follow_redirects=False)
    assert r.status_code == 400
