"""A stand-in Zabbix 6.0 JSON-RPC endpoint for tests/integration.sh.

Answers the handful of methods the login flow and a host_get tool call
involve, insists on body "auth" like 6.0 does, and appends one JSON line per
call to the log file given on the command line so the script can check who
called what with which credential.

    python3 tests/fake_zabbix.py PORT LOGFILE
"""
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSION = "sess-alice"
TOKEN = "ztok-alice-" + secrets.token_hex(4)
LOG = sys.argv[2]


def _error(data):
    return {"error": {"code": -32602, "message": "Invalid params.", "data": data}}


def handle(body):
    method, params, auth = body.get("method"), body.get("params"), body.get("auth")
    if method == "apiinfo.version":
        return {"result": "6.0.45"}
    if method == "user.login":
        if params.get("username") == "alice" and params.get("password") == "alicepw":
            return {"result": {"sessionid": SESSION, "userid": "42", "username": "alice"}}
        return _error("Incorrect user name or password or account is temporarily blocked.")
    if auth == SESSION:
        if method == "token.create":
            return {"result": {"tokenids": ["7"]}}
        if method == "token.generate":
            return {"result": [{"tokenid": "7", "token": TOKEN}]}
        if method == "user.logout":
            return {"result": True}
    if auth == TOKEN:
        if method == "token.update":
            return {"result": {"tokenids": ["7"]}}
        if method == "host.get":
            return {"result": [{"hostid": "10001", "host": "host-seen-by-alice", "name": "host-seen-by-alice"}]}
    return _error("Not authorised.")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        with open(LOG, "a") as f:
            f.write(json.dumps({"method": body.get("method"), "auth": body.get("auth"),
                                "header": self.headers.get("Authorization")}) + "\n")
        reply = {"jsonrpc": "2.0", "id": body.get("id"), **handle(body)}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
