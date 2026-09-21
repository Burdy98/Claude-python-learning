#!/usr/bin/env python3
"""
PyShop - a deliberately vulnerable HTTP/JSON inventory API, for practicing
Python HTTP client scripting (sockets, http.client, or requests).

Run:
    python3 server.py [port]      (defaults to port 8080, binds 127.0.0.1)

This is a plain HTTP server. Every endpoint speaks JSON: send a JSON body
(where noted) and you'll get a JSON body back, plus an ordinary HTTP
status code.

Endpoints:
    GET  /
        -> banner / server info

    GET  /help
        -> list of endpoints

    POST /login
        body: {"username": "...", "password": "..."}
        -> 200 {"status": "ok", "token": "..."}
        -> 401 {"status": "error", "reason": "..."}

    GET  /profile
        header: Authorization: Bearer <token>
        -> profile info for the identity carried in your token

    GET  /inventory
        header: Authorization: Bearer <token>
        -> list of items in stock

    POST /admin/import_config
        header: Authorization: Bearer <token>   (must carry admin identity)
        body: {"config": "<base64 blob>"}
        -> imports a saved diagnostics/config profile

There are three known accounts: guest, alice, admin. None of their
passwords are given to you here, and admin's is a random secret picked
at startup. Getting from "no credentials" to code execution takes a
chain of distinct bugs. Read this file, then write a client to talk to
the server and work the chain. No hints beyond that - that's the point.
"""

import base64
import http.server
import json
import pickle
import secrets
import socketserver
import sqlite3
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# --- "database" -----------------------------------------------------------

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute(
    "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT, role TEXT, bio TEXT)"
)

USERS_SEED = {
    "guest": {"role": "user", "bio": "Just browsing."},
    "alice": {"role": "user", "bio": "Warehouse manager."},
    "admin": {"role": "admin", "bio": "System administrator."},
}

for uname, info in USERS_SEED.items():
    pw = secrets.token_hex(16 if uname == "admin" else 8)
    DB.execute(
        "INSERT INTO users (username, password, role, bio) VALUES (?, ?, ?, ?)",
        (uname, pw, info["role"], info["bio"]),
    )
DB.commit()

INVENTORY = [
    {"sku": "SKU-1001", "name": "Widget", "qty": 42},
    {"sku": "SKU-1002", "name": "Gadget", "qty": 7},
    {"sku": "SKU-1003", "name": "Gizmo", "qty": 0},
]


# --- token helpers ----------------------------------------------------------

def make_token(username, role):
    payload = json.dumps({"username": username, "role": role}).encode()
    return base64.b64encode(payload).decode()


def read_token(token):
    try:
        payload = base64.b64decode(token.encode())
        data = json.loads(payload)
        if not isinstance(data, dict):
            return None
        if "username" not in data or "role" not in data:
            return None
        return data
    except Exception:
        return None


def get_bearer_token(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):]


# --- handler ----------------------------------------------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "PyShop/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[*] %s - %s\n" % (self.address_string(), fmt % args))

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # --- routes ---

    def do_GET(self):
        if self.path == "/":
            return self._send_json(200, {"status": "ok", "msg": "Welcome to PyShop v1.0"})

        if self.path == "/help":
            endpoints = [
                "GET /", "GET /help", "POST /login",
                "GET /profile", "GET /inventory", "POST /admin/import_config",
            ]
            return self._send_json(200, {"status": "ok", "endpoints": endpoints})

        if self.path == "/profile":
            return self._handle_profile()

        if self.path == "/inventory":
            return self._handle_inventory()

        return self._send_json(404, {"status": "error", "reason": "not found"})

    def do_POST(self):
        if self.path == "/login":
            return self._handle_login()

        if self.path == "/admin/import_config":
            return self._handle_import_config()

        return self._send_json(404, {"status": "error", "reason": "not found"})

    # --- implementations ---

    def _handle_login(self):
        body = self._read_json_body()
        username = body.get("username")
        password = body.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            return self._send_json(400, {"status": "error", "reason": "username and password are required strings"})

        query = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = DB.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            return self._send_json(400, {"status": "error", "reason": f"query failed: {e}"})

        if row is None:
            return self._send_json(401, {"status": "error", "reason": "invalid credentials"})

        token = make_token(row[0], row[1])
        return self._send_json(200, {"status": "ok", "token": token})

    def _handle_profile(self):
        token = get_bearer_token(self)
        data = read_token(token) if token else None
        if data is None:
            return self._send_json(401, {"status": "error", "reason": "not authenticated"})

        cur = DB.cursor()
        cur.execute("SELECT username, role, bio FROM users WHERE username = ?", (data["username"],))
        row = cur.fetchone()
        if row is None:
            return self._send_json(404, {"status": "error", "reason": "no such user"})

        return self._send_json(200, {"status": "ok", "username": row[0], "role": row[1], "bio": row[2]})

    def _handle_inventory(self):
        token = get_bearer_token(self)
        data = read_token(token) if token else None
        if data is None:
            return self._send_json(401, {"status": "error", "reason": "not authenticated"})

        return self._send_json(200, {"status": "ok", "items": INVENTORY})

    def _handle_import_config(self):
        token = get_bearer_token(self)
        data = read_token(token) if token else None
        if data is None:
            return self._send_json(401, {"status": "error", "reason": "not authenticated"})

        if data.get("role") != "admin":
            return self._send_json(403, {"status": "error", "reason": "admin role required"})

        body = self._read_json_body()
        config_b64 = body.get("config")
        if not isinstance(config_b64, str):
            return self._send_json(400, {"status": "error", "reason": "config (base64 string) is required"})

        try:
            blob = base64.b64decode(config_b64)
            config = pickle.loads(blob)
        except Exception as e:
            return self._send_json(400, {"status": "error", "reason": f"failed to import config: {e}"})

        return self._send_json(200, {"status": "ok", "imported": repr(config)})


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    print(f"[*] PyShop listening on {HOST}:{PORT}")
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
