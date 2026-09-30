"""
zabbix-auth-mcp: an OAuth 2.1 front door for zabbix-mcp-server.

MCP clients such as claude.ai only speak OAuth, while zabbix-mcp-server only
accepts a static bearer token. This service sits in between: users log in with
their Zabbix credentials, receive OAuth tokens, and every MCP request they make
is forwarded to zabbix-mcp-server with an API token Zabbix issued to that
user, so Zabbix applies their own permissions. Run with `uvicorn main:app`.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

import config
import oauth
import proxy
import store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    yield
    await proxy.client.aclose()


app = FastAPI(title="zabbix-auth-mcp", docs_url=None, redoc_url=None, lifespan=lifespan)
app.include_router(oauth.router)
app.include_router(proxy.router)


@app.get("/")
def root():
    return PlainTextResponse(f"zabbix-auth-mcp. Point your MCP client at {config.RESOURCE_URL}\n")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
