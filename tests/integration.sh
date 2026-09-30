#!/bin/bash
# End-to-end check of the whole chain on localhost, no docker: a fake Zabbix
# 6.0 (tests/fake_zabbix.py), the real zabbix-mcp-server fork from a sibling
# checkout (FORK_DIR, default ../zabbix-mcp-server, with its .venv), and this
# service. Drives registration, the login form, the token exchange, an MCP
# tool call and a refresh, and checks that the fork called Zabbix with the
# token minted at login and never with its own configured one. Leaves
# nothing running.
set -u
cd "$(dirname "$0")/.."
FORK_DIR=${FORK_DIR:-../zabbix-mcp-server}
PY=./.venv/bin/python
FORK=$(realpath "$FORK_DIR")/.venv/bin/zabbix-mcp-server
[ -x "$FORK" ] || { echo "no fork venv at $FORK (set FORK_DIR)"; exit 2; }
WORK=$(mktemp -d)
freeport() { python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"; }
ZPORT=$(freeport); MPORT=$(freeport); PPORT=$(freeport)
FAILED=0
check() { if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: expected '$2', got '$1'"; FAILED=1; fi; }
cleanup() { kill "${ZB:-}" "${MC:-}" "${UV:-}" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
waitfor() { for _ in $(seq 1 60); do curl -sf "$1" >/dev/null && return; sleep 0.5; done; echo "timeout waiting for $1"; exit 2; }

echo "--- starting fake Zabbix ($ZPORT), the fork ($MPORT) and the proxy ($PPORT)"
python3 tests/fake_zabbix.py "$ZPORT" "$WORK/zabbix.log" & ZB=$!
cat > "$WORK/config.toml" <<CFG
[server]
transport = "http"
host = "127.0.0.1"
port = $MPORT
auth_token = "it-secret"
trusted_proxies = ["127.0.0.1"]
zabbix_token_header = "X-Zabbix-Token"

[zabbix.it]
url = "http://127.0.0.1:$ZPORT/zabbix"
api_token = "no-shared-token"
read_only = false
CFG
(cd "$WORK" && "$FORK" --config "$WORK/config.toml" > "$WORK/fork.log" 2>&1) & MC=$!
export BASE_URL=http://127.0.0.1:$PPORT MCP_BACKEND_URL=http://127.0.0.1:$MPORT/mcp MCP_BACKEND_TOKEN=it-secret \
       ZABBIX_URL=http://127.0.0.1:$ZPORT/zabbix ALLOWED_USERS= DB_PATH=$WORK/db.sqlite3
./.venv/bin/uvicorn main:app --host 127.0.0.1 --port $PPORT > "$WORK/proxy.log" 2>&1 & UV=$!
waitfor "http://127.0.0.1:$MPORT/health"
waitfor "http://127.0.0.1:$PPORT/healthz"
P=http://127.0.0.1:$PPORT

echo "--- OAuth flow"
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST $P/mcp)" "401" "no bearer, no service"
CID=$(curl -s -X POST $P/register -H 'Content-Type: application/json' \
  -d '{"client_name":"Claude","redirect_uris":["http://localhost:1/cb"],"token_endpoint_auth_method":"none"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['client_id'])")
VERIFIER=correct-horse-battery-staple-correct-horse-battery-staple
CHALLENGE=$(python3 -c "import base64,hashlib; print(base64.urlsafe_b64encode(hashlib.sha256(b'$VERIFIER').digest()).rstrip(b'=').decode())")
RID=$(curl -s "$P/authorize?response_type=code&client_id=$CID&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb&code_challenge=$CHALLENGE&code_challenge_method=S256&state=st1&resource=$BASE_URL%2Fmcp" \
  | grep -o 'name="rid" value="[^"]*"' | cut -d'"' -f4)
check "$(curl -s -X POST $P/authorize -d "rid=$RID&username=alice&password=nope" | grep -c 'Incorrect user name or password')" "1" "wrong password shows Zabbix's error"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST $P/authorize -d "rid=$RID&username=alice&password=alicepw")
CODE=$(python3 -c "from urllib.parse import urlsplit, parse_qs; print(parse_qs(urlsplit('$LOC').query).get('code', [''])[0])")
check "$([ -n "$CODE" ] && echo yes)" "yes" "right password redirects with a code"
check "$(grep -c '"method": "token.generate", "auth": "sess-alice"' "$WORK/zabbix.log")" "1" "a token was minted with the login session"
check "$(grep -c '"method": "user.logout"' "$WORK/zabbix.log")" "1" "and the session was closed"
TOK=$(curl -s -X POST $P/token -d "grant_type=authorization_code&code=$CODE&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb&client_id=$CID&code_verifier=$VERIFIER")
ACCESS=$(echo "$TOK" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
REFRESH=$(echo "$TOK" | python3 -c "import json,sys; print(json.load(sys.stdin)['refresh_token'])")
check "$([ -n "$ACCESS" ] && echo yes)" "yes" "code exchanged for tokens"

echo "--- MCP call through the proxy runs as alice"
META='{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"it","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}'
mcpcall() {  # $1 = bearer, $2 = url, extra headers after
  curl -s -X POST "$2" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: host_get' "${@:3}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"_meta\":$META,\"name\":\"host_get\",\"arguments\":{\"limit\":1}}}"
}
OUT=$(mcpcall "$ACCESS" "$P/mcp")
check "$(echo "$OUT" | grep -c host-seen-by-alice)" "1" "host_get returned alice's host"
check "$(grep '"method": "host.get"' "$WORK/zabbix.log" | grep -c '"auth": "ztok-alice-')" "1" "the fork called Zabbix with alice's minted token"
check "$(grep -c '"auth": "no-shared-token"' "$WORK/zabbix.log")" "0" "the fork's own configured token was never used"

echo "--- the fork alone refuses to fall back"
OUT=$(mcpcall it-secret "http://127.0.0.1:$MPORT/mcp" -H 'X-Zabbix-Token;')
check "$(echo "$OUT" | grep -c 'empty Zabbix token')" "1" "empty token header is refused with a clear error"
OUT=$(mcpcall it-secret "http://127.0.0.1:$MPORT/mcp" -H 'X-Zabbix-Token: bogus')
check "$(echo "$OUT" | grep -c 'rejected the user')" "1" "a token Zabbix rejects is reported as such"
check "$(echo "$OUT" | grep -c host-seen-by-alice)" "0" "and returns no data"

echo "--- refresh renews the Zabbix token"
NEW=$(curl -s -X POST $P/token -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CID" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")
check "$([ -n "$NEW" ] && echo yes)" "yes" "refresh issued a new access token"
check "$(grep '"method": "token.update"' "$WORK/zabbix.log" | grep -c '"auth": "ztok-alice-')" "1" "token.update ran with the token itself"
OUT=$(mcpcall "$NEW" "$P/mcp")
check "$(echo "$OUT" | grep -c host-seen-by-alice)" "1" "the refreshed grant still works"

[ $FAILED = 0 ] && echo "--- all ok" || { echo "--- FAILURES; last MCP reply and logs:"; echo "$OUT" | head -c 600; echo; cat "$WORK/zabbix.log"; tail -n 15 "$WORK/proxy.log" "$WORK/fork.log"; }
exit $FAILED
