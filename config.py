"""
Configuration, read from environment variables (or a .env file).

Everything that builds an absolute URL uses BASE_URL, so the service does not
depend on Host/X-Forwarded headers and works the same behind any TLS setup.
"""
import os

from dotenv import load_dotenv

load_dotenv()


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


def _csv(name: str, default: str = "") -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


# Public https URL of this service, exactly as MCP clients see it, no trailing
# slash. Used as the OAuth issuer and for every redirect.
BASE_URL = _required("BASE_URL").rstrip("/")
# Canonical identifier of the MCP endpoint (the OAuth "resource").
RESOURCE_URL = f"{BASE_URL}/mcp"

# The real zabbix-mcp-server (its streamable-http endpoint) and the bearer
# token it expects, i.e. its [server].auth_token.
MCP_BACKEND_URL = _required("MCP_BACKEND_URL")
MCP_BACKEND_TOKEN = _required("MCP_BACKEND_TOKEN")

# Zabbix itself (the frontend URL, e.g. https://zabbix.example.edu/zabbix).
# Used at login to check the user's credentials (Zabbix asks LDAP) and to
# mint the API token that every MCP call then runs with.
ZABBIX_URL = _required("ZABBIX_URL").rstrip("/")

# Header that carries the user's Zabbix API token to zabbix-mcp-server. Must
# match [server].zabbix_token_header in its config.toml.
ZABBIX_TOKEN_HEADER = os.getenv("ZABBIX_TOKEN_HEADER", "X-Zabbix-Token")

# Prefix of the API token names this service creates in Zabbix, so they can
# be told apart from tokens the user made by hand.
ZABBIX_TOKEN_NAME = os.getenv("ZABBIX_TOKEN_NAME", "zabbix-auth-mcp")

# Optional allowlist of Zabbix usernames. Empty means anyone who can log in to
# Zabbix, who then only ever gets their own Zabbix permissions.
ALLOWED_USERS = {u.lower() for u in _csv("ALLOWED_USERS")}

# Hosts that dynamically registered OAuth clients may redirect to. claude.ai
# and claude.com cover Claude web/desktop/mobile; localhost covers Claude Code
# and the MCP Inspector.
ALLOWED_REDIRECT_HOSTS = set(_csv("ALLOWED_REDIRECT_HOSTS", "claude.ai,claude.com,localhost,127.0.0.1,blob.cs.rutgers.edu"))

DB_PATH = os.getenv("DB_PATH", "data/zabbix-auth-mcp.sqlite3")

# Where the port-80 listener sends Let's Encrypt HTTP-01 challenges: certbot
# runs on services, so challenges must end up there although the public DNS
# name points at us.
ACME_REDIRECT_URL = os.getenv("ACME_REDIRECT_URL", "http://services.cs.rutgers.edu").rstrip("/")

AUTH_REQUEST_TTL = 600  # seconds a user has to finish logging in
AUTH_CODE_TTL = 300
ACCESS_TOKEN_TTL = int(os.getenv("ACCESS_TOKEN_TTL", 3600))
# Also the lifetime of the Zabbix API token minted at login; each refresh
# pushes both out again.
REFRESH_TOKEN_TTL = int(os.getenv("REFRESH_TOKEN_TTL", 30 * 24 * 3600))
