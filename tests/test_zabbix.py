"""The Zabbix module against a mocked JSON-RPC endpoint: which calls it makes,
how it carries the session on 6.0 versus 6.4+, and that the login session is
closed whatever happens."""
import json
import os

os.environ.setdefault("BASE_URL", "https://mcp.test")
os.environ.setdefault("MCP_BACKEND_URL", "http://backend/mcp")
os.environ.setdefault("MCP_BACKEND_TOKEN", "backend-secret")
os.environ.setdefault("ZABBIX_URL", "http://zabbix.test/zabbix")

import httpx  # noqa: E402
import pytest  # noqa: E402

import zabbix  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeZabbix:
    def __init__(self, version="6.0.45", fail=()):
        self.version = version
        self.fail = set(fail)
        self.calls = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url == "http://zabbix.test/zabbix/api_jsonrpc.php"
        body = json.loads(request.content)
        auth = body.get("auth")
        header = request.headers.get("authorization")
        if header:
            auth = header.removeprefix("Bearer ")
        self.calls.append((body["method"], body["params"], auth, "auth" in body, bool(header)))
        m = body["method"]
        if m in self.fail:
            return httpx.Response(200, json={"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params.", "data": f'No permissions to call "{m}".'}, "id": 1})
        results = {
            "apiinfo.version": self.version,
            "user.login": {"sessionid": "sess-1", "userid": 42, "username": "alice"},
            "token.create": {"tokenids": ["7"]},
            "token.generate": [{"tokenid": "7", "token": "ztok"}],
            "token.update": {"tokenids": ["7"]},
            "user.logout": True,
        }
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": results[m], "id": 1})


@pytest.fixture
def fake(monkeypatch):
    fz = FakeZabbix()
    real = httpx.AsyncClient

    def patched(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fz.handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(zabbix.httpx, "AsyncClient", patched)
    monkeypatch.setattr(zabbix, "_header_auth", None)
    return fz


async def test_login_then_mint_uses_the_session_once_and_closes_it(fake):
    session, userid, username = await zabbix.login("Alice", "pw")
    assert (session, userid, username) == ("sess-1", "42", "alice")
    token, tokenid = await zabbix.mint_token(session, userid, 1234)
    assert (token, tokenid) == ("ztok", "7")
    methods = [c[0] for c in fake.calls]
    # The version probe runs lazily, before the first call that carries a credential.
    assert methods == ["user.login", "apiinfo.version", "token.create", "token.generate", "user.logout"]
    create = next(c for c in fake.calls if c[0] == "token.create")
    assert create[1] == {"name": create[1]["name"], "userid": "42", "expires_at": 1234}
    assert create[1]["name"].startswith("zabbix-auth-mcp ")
    # Zabbix 6.0: the session travels in the body, never in a header.
    for c in fake.calls[2:]:
        assert c[2] == "sess-1" and c[3] and not c[4]


async def test_zabbix_64_takes_the_session_in_the_header(fake):
    fake.version = "7.0.3"
    session, userid, _ = await zabbix.login("alice", "pw")
    await zabbix.mint_token(session, userid, 1)
    for c in fake.calls[2:]:
        assert c[2] == "sess-1" and not c[3] and c[4]


async def test_mint_failure_still_logs_out_and_reports_the_zabbix_message(fake):
    fake.fail.add("token.create")
    with pytest.raises(zabbix.ZabbixError, match='No permissions to call "token.create"'):
        await zabbix.mint_token("sess-1", "42", 1)
    assert fake.calls[-1][0] == "user.logout"


async def test_bad_password_is_a_login_error_with_zabbix_wording(fake):
    fake.fail.add("user.login")
    with pytest.raises(zabbix.LoginError, match="user.login"):
        await zabbix.login("alice", "nope")


async def test_extend_authenticates_with_the_token_itself(fake):
    await zabbix.extend_token("ztok", "7", 99)
    assert fake.calls[-1] == ("token.update", {"tokenid": "7", "expires_at": 99}, "ztok", True, False)


async def test_unreachable_zabbix(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("refused")
    real = httpx.AsyncClient
    monkeypatch.setattr(zabbix.httpx, "AsyncClient", lambda *a, **k: real(*a, transport=httpx.MockTransport(boom), **k))
    monkeypatch.setattr(zabbix, "_header_auth", None)
    with pytest.raises(zabbix.LoginError, match="unreachable"):
        await zabbix.login("alice", "pw")
