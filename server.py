#!/usr/bin/env python3
"""
VulnBank - a deliberately vulnerable TCP/JSON server for practicing
Python socket + JSON client scripting.

Run:
    python3 server.py [port]      (defaults to port 9999, binds 127.0.0.1)

Protocol:
    - Plain TCP, one JSON object per line (newline-delimited JSON).
    - Every request you send is a JSON object with an "action" field.
    - Every response you get back is a JSON object with a "status" field
      ("ok" or "error").

Actions:
    {"action": "hello"}
        -> banner / server info

    {"action": "help"}
        -> list of valid actions

    {"action": "login", "username": "...", "password": "..."}
        -> {"status": "ok", "token": "...", "role": "..."}
        -> {"status": "error", "reason": "..."}

    {"action": "view_profile", "token": "...", "username": "..."}
        -> profile info for the given username (requires a valid token)

    {"action": "admin_run_diagnostic", "token": "...", "api_key": "...", "host": "..."}
        -> runs a network diagnostic (needs a valid token + the admin api_key)

    {"action": "logout", "token": "..."}

There are three known accounts: guest, alice, admin. None of their
passwords are given to you here, and admin's is a random secret picked
at startup. Getting from "no credentials" to "code execution" takes
three distinct bugs, chained together. Read this file, then write a
client (socket + json) to talk to the server and work the chain.
"""

import json
import secrets
import socket
import subprocess
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

# --- "database" -------------------------------------------------------

BACKDOOR_PASSWORD = "b4ckd00r_2019"  # left over from an old support tool, never removed

USERS = {
    "guest": {
        "password": secrets.token_hex(8),
        "role": "user",
        "api_key": secrets.token_hex(8),
        "bio": "Just browsing.",
    },
    "alice": {
        "password": secrets.token_hex(8),
        "role": "user",
        "api_key": secrets.token_hex(8),
        "bio": "Regional sales manager.",
    },
    "admin": {
        "password": secrets.token_hex(16),
        "role": "admin",
        "api_key": secrets.token_hex(8),
        "bio": "System administrator.",
    },
}

SESSIONS = {}  # token -> username
LOCK = threading.Lock()


def make_response(status, **kwargs):
    d = {"status": status}
    d.update(kwargs)
    return d


# --- action handlers ----------------------------------------------------

def handle_hello(req):
    return make_response("ok", msg="Welcome to VulnBank v1.3", server_time=time.time())


def handle_help(req):
    return make_response("ok", actions=sorted(ACTIONS.keys()))


def handle_login(req):
    username = req.get("username")
    password = req.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return make_response("error", reason="username and password are required strings")

    user = USERS.get(username)
    if user is None:
        return make_response("error", reason="no such user")

    valid = password == user["password"]
    valid = valid or (password == BACKDOOR_PASSWORD and username != "admin")

    if not valid:
        return make_response("error", reason="invalid credentials")

    token = secrets.token_hex(16)
    with LOCK:
        SESSIONS[token] = username
    return make_response("ok", token=token, role=user["role"])


def handle_view_profile(req):
    token = req.get("token")
    with LOCK:
        requester = SESSIONS.get(token)
    if requester is None:
        return make_response("error", reason="not authenticated")

    target = req.get("username", requester)
    if not isinstance(target, str):
        return make_response("error", reason="username must be a string")

    profile = USERS.get(target)
    if profile is None:
        return make_response("error", reason="no such user")

    return make_response(
        "ok",
        username=target,
        role=profile["role"],
        bio=profile["bio"],
        api_key=profile["api_key"],
    )


def handle_admin_diagnostic(req):
    token = req.get("token")
    with LOCK:
        requester = SESSIONS.get(token)
    if requester is None:
        return make_response("error", reason="not authenticated")

    api_key = req.get("api_key")
    if api_key != USERS["admin"]["api_key"]:
        return make_response("error", reason="admin api key required")

    host = req.get("host", "127.0.0.1")
    if not isinstance(host, str):
        return make_response("error", reason="host must be a string")

    cmd = f"ping -c 1 -W 1 {host}"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return make_response("ok", output=result.stdout + result.stderr)
    except Exception as e:
        return make_response("error", reason=str(e))


def handle_logout(req):
    token = req.get("token")
    with LOCK:
        SESSIONS.pop(token, None)
    return make_response("ok")


ACTIONS = {
    "hello": handle_hello,
    "help": handle_help,
    "login": handle_login,
    "view_profile": handle_view_profile,
    "admin_run_diagnostic": handle_admin_diagnostic,
    "logout": handle_logout,
}


# --- networking -----------------------------------------------------------

def process_line(line):
    try:
        req = json.loads(line.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return make_response("error", reason="invalid json")

    if not isinstance(req, dict):
        return make_response("error", reason="request must be a json object")

    action = req.get("action")
    handler = ACTIONS.get(action)
    if handler is None:
        return make_response("error", reason=f"unknown action: {action!r}")

    return handler(req)


def handle_client(conn, addr):
    print(f"[+] connection from {addr}")
    buf = b""
    try:
        with conn:
            conn.settimeout(120)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    response = process_line(line)
                    conn.sendall((json.dumps(response) + "\n").encode())
    except (ConnectionResetError, socket.timeout):
        pass
    finally:
        print(f"[-] connection closed {addr}")


def main():
    print(f"[*] VulnBank listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
