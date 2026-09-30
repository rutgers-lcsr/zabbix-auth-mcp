"""The port-80 listener: ACME challenges go to services, everything else to https."""
import os

os.environ.setdefault("BASE_URL", "https://mcp.test")
os.environ.setdefault("MCP_BACKEND_URL", "http://backend/mcp")
os.environ.setdefault("MCP_BACKEND_TOKEN", "backend-secret")
os.environ.setdefault("ZABBIX_URL", "http://zabbix.test/zabbix")

from fastapi.testclient import TestClient  # noqa: E402

import http_redirect  # noqa: E402

client = TestClient(http_redirect.app)


def test_acme_challenge_goes_to_services():
    r = client.get("/.well-known/acme-challenge/abc123", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "http://services.cs.rutgers.edu/.well-known/acme-challenge/abc123"


def test_everything_else_goes_to_https():
    r = client.get("/mcp?x=1", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "https://mcp.test/mcp?x=1"
