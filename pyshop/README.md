<details>

PyShop is a deliberately vulnerable HTTP/JSON inventory API. Three accounts exist (`guest`, `alice`, `admin`) and none of their passwords are given — admin's is a random secret picked at server startup. The goal is to go from zero credentials to remote code execution on the server by chaining together a handful of distinct bugs across the login, session token, and admin config-import endpoints.

<summary>Click to reveal the answer</summary>

Vulnerabilities:
- **SQL injection** in `POST /login` — the query is built with an unsanitized f-string (`WHERE username = '{username}' AND password = '{password}'`), letting a comment-based payload (`admin' -- `) bypass the password check entirely and authenticate as any known user.
- **Unsigned/tamperable session token** — the token is just `base64(json)` with no signature or MAC, so the server trusts whatever `username`/`role` the client claims. A user can forge or edit a token client-side to escalate straight to `{"role": "admin"}`, no injection required.
- **Insecure deserialization** in `POST /admin/import_config` — the endpoint runs `pickle.loads()` on attacker-supplied base64 data. A crafted object with a `__reduce__` method (e.g. returning `(os.system, ('cmd',))`) executes arbitrary code the moment it's unpickled, giving RCE.

Skills Learned:
- Writing an HTTP/JSON API client in Python with `requests` (vs. raw sockets)
- Basic SQL injection: comment-based auth bypass, and how `AND`/`OR` precedence plus unordered `SELECT` results affect which row gets returned
- Recognizing unsigned/tamper-able tokens 
- How Python's `pickle.loads()` can be turned into arbitrary code execution via `__reduce__`, and why de-serializing untrusted data is a code-execution risk regardless of what the server itself imports
- Base64 encoding/decoding binary payloads for transport inside JSON

</details>
