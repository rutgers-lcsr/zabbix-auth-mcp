"""
Talking to Zabbix.

Login: the submitted credentials go to user.login, so Zabbix (and the LDAP
behind it) decides who the user is. The session that comes back is used for
one thing, creating an API token for that same user (token.create followed by
token.generate), and is then closed. The password is not stored.

Per request: that API token goes along with every zabbix-mcp-server call in
the ZABBIX_TOKEN_HEADER header, and zabbix-mcp-server runs the call with it,
so Zabbix applies the user's own role and host group permissions. No service
account is involved anywhere: a user can only mint tokens for themselves, and
that needs the "Manage API tokens" action in their Zabbix role.
"""
import logging
import time

import httpx

import config

log = logging.getLogger(__name__)

API_URL = f"{config.ZABBIX_URL}/api_jsonrpc.php"

# Zabbix 6.4+ takes the session or token in an Authorization header; older
# versions want it in the body as "auth" (and 7.2+ rejects "auth"). Decided
# once, from apiinfo.version.
_header_auth: bool | None = None


class LoginError(Exception):
    """Shown to the user on the login form."""


class ZabbixError(Exception):
    """Zabbix answered with an error, or did not answer."""


async def _call(client: httpx.AsyncClient, method: str, params, auth: str | None = None):
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json-rpc"}
    if auth is not None:
        if await _uses_header_auth(client):
            headers["Authorization"] = f"Bearer {auth}"
        else:
            body["auth"] = auth
    try:
        resp = await client.post(API_URL, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        raise ZabbixError(f"Zabbix is unreachable ({e.__class__.__name__})") from e
    if "error" in data:
        err = data["error"]
        raise ZabbixError(f"{err.get('message', '')} {err.get('data', '')}".strip())
    return data["result"]


async def _uses_header_auth(client: httpx.AsyncClient) -> bool:
    global _header_auth
    if _header_auth is None:
        version = await _call(client, "apiinfo.version", {})
        major, minor = (int(x) for x in version.split(".")[:2])
        _header_auth = (major, minor) >= (6, 4)
        log.info("Zabbix %s at %s (%s auth)", version, config.ZABBIX_URL, "header" if _header_auth else "body")
    return _header_auth


async def login(username: str, password: str) -> tuple[str, str, str]:
    """Check the credentials with Zabbix. Returns (session id, userid, username as Zabbix spells it)."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            user = await _call(client, "user.login", {"username": username, "password": password, "userData": True})
        except ZabbixError as e:
            raise LoginError(str(e)) from e
    # 5.4+ calls the login name "username"; older releases said "alias".
    return user["sessionid"], str(user["userid"]), user.get("username") or user.get("alias") or username


async def logout(session: str) -> None:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            await _call(client, "user.logout", [], auth=session)
        except ZabbixError as e:
            log.warning("user.logout failed: %s", e)


async def mint_token(session: str, userid: str, expires_at: int) -> tuple[str, str]:
    """Create an API token for the logged-in user and close the session. Returns (token, tokenid)."""
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            # Token names are unique per user, hence the timestamp.
            name = f"{config.ZABBIX_TOKEN_NAME} {time.strftime('%Y-%m-%d %H:%M:%S')}"
            created = await _call(client, "token.create", {"name": name, "userid": userid, "expires_at": expires_at}, auth=session)
            tokenid = str(created["tokenids"][0])
            generated = await _call(client, "token.generate", [tokenid], auth=session)
            return generated[0]["token"], tokenid
        finally:
            try:
                await _call(client, "user.logout", [], auth=session)
            except ZabbixError as e:
                log.warning("user.logout failed: %s", e)


async def extend_token(token: str, tokenid: str, expires_at: int) -> None:
    """Push the token's expiry out (on refresh), authenticated with the token itself."""
    async with httpx.AsyncClient(timeout=15) as client:
        await _call(client, "token.update", {"tokenid": tokenid, "expires_at": expires_at}, auth=token)
