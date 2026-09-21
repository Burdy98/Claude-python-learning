## VulnBank

VulnBank is a deliberately vulnerable TCP/JSON server (newline-delimited JSON over a raw socket). Three accounts exist (`guest`, `alice`, `admin`) and none of their passwords are given — admin's is a random secret picked at server startup. The goal is to go from zero credentials to remote code execution on the server by chaining together a handful of distinct bugs across the login, profile, and admin diagnostic actions.
<details>
<summary>Click to reveal the answer</summary>

### Vulnerabilities:
- **Backdoor password / auth bypass** in the `login` action — a hardcoded legacy password (`b4ckd00r_2019`) authenticates as any username except `admin`, bypassing that user's real random password entirely.
- **IDOR** in `view_profile` — the handler trusts a `username` field in the request and returns *any* user's profile (including their `api_key`) as long as the caller has a valid session token, with no check that the caller owns that profile. Used to steal the admin's `api_key` while logged in as a low-privilege user.
- **Command injection** in `admin_run_diagnostic` — the `host` field is interpolated directly into a shell command (`f"ping -c 1 -W 1 {host}"`) and run with `subprocess.run(..., shell=True)`. Gated behind the stolen admin `api_key`, but once reached, shell metacharacters in `host` (e.g. `; touch /tmp/pwned`) give arbitrary code execution.

### Skills Learned:
- Writing a raw TCP client in Python with `socket` + newline-delimited JSON framing
- Recognizing broken authentication (hardcoded backdoor credentials) as a real-world vulnerability class
- Insecure Direct Object Reference (IDOR): why authorization must check *ownership*, not just *authentication*
- Command injection via `subprocess.run(shell=True)` with unsanitized input, and why `shell=True` + string interpolation is dangerous
- Chaining low-severity bugs (auth bypass → info leak) into a high-severity one (RCE)

</details>
