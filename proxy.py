"""
The protected MCP endpoint. Validates the caller's access token, then forwards
the request to zabbix-mcp-server with its own bearer token plus the logged-in
user's Zabbix API token, which makes every Zabbix call run as that user, and
streams the answer back.
"""
import json
import logging

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

import config
import store

router = APIRouter()
log = logging.getLogger(__name__)

# Only these request headers reach zabbix-mcp-server. Everything else (the
# caller's Authorization, Cookie, Origin, Host, a forged token header, ...) is
# dropped: it must only ever see its own token and the one we add.
# The Mcp-* ones carry the 2026-07-28 stateless generation's envelope
# (Mcp-Method, Mcp-Name, Mcp-Param-*), which zabbix-mcp-server needs to
# route a self-contained POST.
FORWARD_REQUEST_HEADERS = {"content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id",
                           "mcp-method", "mcp-name"}
FORWARD_RESPONSE_HEADERS = {"content-type", "mcp-session-id", "mcp-protocol-version", "cache-control"}

# read=None: SSE streams from zabbix-mcp-server stay open indefinitely.
client = httpx.AsyncClient(timeout=httpx.Timeout(10, read=None))

RESOURCE_METADATA_URL = f"{config.BASE_URL}/.well-known/oauth-protected-resource/mcp"


def _unauthorized(description: str, invalid_token: bool) -> JSONResponse:
    challenge = f'Bearer resource_metadata="{RESOURCE_METADATA_URL}"'
    if invalid_token:
        challenge = f'Bearer error="invalid_token", resource_metadata="{RESOURCE_METADATA_URL}"'
    return JSONResponse(
        {"error": "invalid_token", "error_description": description},
        status_code=401,
        headers={"WWW-Authenticate": challenge},
    )


def _describe(body: bytes) -> str:
    """'tools/call list_datasources' style summary of a JSON-RPC body, for the audit log."""
    try:
        msg = json.loads(body)
    except ValueError:
        return ""
    if not isinstance(msg, dict):
        return ""
    method = msg.get("method", "")
    params = msg.get("params") or {}
    name = params.get("name") if isinstance(params, dict) else None
    return f"{method} {name}" if name else method


@router.api_route("/mcp", methods=["GET", "POST", "DELETE"])
async def mcp(request: Request):
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return _unauthorized("missing bearer token", invalid_token=False)
    access = store.get_token(token, "access")
    if access is None:
        return _unauthorized("access token is invalid or expired", invalid_token=True)

    body = await request.body()
    log.info("user=%s %s %s", access["username"], request.method, _describe(body))

    headers = {k: v for k, v in request.headers.items() if k in FORWARD_REQUEST_HEADERS or k.startswith("mcp-param-")}
    headers["Authorization"] = f"Bearer {config.MCP_BACKEND_TOKEN}"
    headers[config.ZABBIX_TOKEN_HEADER] = access["zabbix_token"]
    upstream = client.build_request(
        request.method,
        config.MCP_BACKEND_URL,
        params=request.query_params.multi_items(),
        headers=headers,
        content=body,
    )
    try:
        resp = await client.send(upstream, stream=True)
    except httpx.HTTPError as e:
        log.error("zabbix-mcp-server unreachable: %s", e)
        return JSONResponse({"error": "bad_gateway", "error_description": "zabbix-mcp-server is unreachable"}, status_code=502)

    return StreamingResponse(
        resp.aiter_raw(),
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items() if k.lower() in FORWARD_RESPONSE_HEADERS},
        background=BackgroundTask(resp.aclose),
    )
