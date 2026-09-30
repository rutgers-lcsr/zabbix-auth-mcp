"""
The plain-http listener (port 80). It never serves content.

Let's Encrypt HTTP-01 challenges are redirected to services, where certbot
issues and renews the cert (the remotecert_compose model), even though the
name now points at us. Everything else is redirected to the https URL.
Run with `uvicorn http_redirect:app --lifespan off`.
"""
import config

ACME_PREFIX = "/.well-known/acme-challenge/"


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    path = scope["path"]
    if path.startswith(ACME_PREFIX):
        location = config.ACME_REDIRECT_URL + path
    else:
        query = scope.get("query_string", b"").decode()
        location = config.BASE_URL + path + (f"?{query}" if query else "")
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [(b"location", location.encode()), (b"content-length", b"0")],
    })
    await send({"type": "http.response.body", "body": b""})
