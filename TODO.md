# TODO

## Summary

| # | Name | Severity | Status |
|---|------|----------|--------|
| [1](#1-hash-endpoint-leaks-tokens-into-logs-high) | `/hash` endpoint leaks tokens into logs | High | Done |
| [2](#2-duplicate-hash-computation-functions-medium) | Duplicate hash computation functions | Medium | Not done |
| [3](#3-no-test-suite-medium) | No test suite | Medium | Not done |
| [4](#4-brute-force-state-not-cleared-on-all-auth-failures-medium) | Brute-force state not cleared on all auth failures | Medium | Not done |
| [5](#5-config-claims-base64token-but-never-decodes-base64-medium) | Config claims "base64token" but never decodes base64 | Medium | Not done |
| [6](#6-timing-side-channel-on-hash-comparison-fallback-medium) | Timing side-channel on hash comparison fallback | Medium | Not done |
| [7](#7-reload-config-has-no-brute-force-protection-medium) | `/reload-config` has no brute-force protection | Medium | Not done |
| [8](#8-no-input-validation-or-size-limits-on-config-entries-low-medium) | No input validation or size limits on config entries | Low-Medium | Not done |
| [9](#9-x-forwarded-for-is-trusted-blindly-low) | `X-Forwarded-For` is trusted blindly | Low | Not done |
| [10](#10-config-file-has-no-filesystem-level-access-control-low) | Config file has no filesystem-level access control | Low | Not done |
| [11](#11-config-loaded-at-module-level-before-fastapi-startup-low) | Config loaded at module level before FastAPI startup | Low | Not done |
| [12](#12-config-delimiter-doesnt-support-colons-in-tokens-medium) | Config delimiter doesn't support colons in tokens | Medium | Not done |
| [13](#13-no-graceful-shutdown-handling-low) | No graceful shutdown handling | Low | Not done |
| [14](#14-reload-config-doesnt-warn-on-emptyinvalid-config-after-reload-low) | `/reload-config` doesn't warn on empty/invalid config after reload | Low | Not done |
| [15](#15-brute-force-window-resets-full-on-success-trivially-gamed-low) | Brute-force window resets fully on success — trivially gamed | Low | Not done |
| [16](#16-hash-collisions-silently-overwrite-users-low) | Hash collisions silently overwrite users | Low | Not done |
| [17](#17-log-leakage-of-auth-hashes-high) | Log leakage of auth hashes | High | Not done |
| [18](#18-memory-exhaustion-via-failed-attempts-medium) | Memory exhaustion via `FAILED_ATTEMPTS` | Medium | Not done |
| [19](#19-dos-via-large-request-bodies-in-reload-config-medium) | DoS via large request bodies in `/reload-config` | Medium | Not done |
| [20](#20-unprotected-admin-secret-brute-force-via-hash-medium) | Unprotected admin secret brute-force via `/hash` | Medium | Not done |
| [21](#21-resource-exhaustion-via-unbounded-input-lengths-low) | Resource exhaustion via unbounded input lengths | Low | Not done |
| [22](#22-shared-brute-force-bucket-for-unknown-ips-low) | Shared brute-force bucket for unknown IPs | Low | Not done |

## 1. `/hash` endpoint leaks tokens into logs (High)

**Problem:** The `/hash` endpoint accepts `token` as a query parameter (`GET /hash?user=alice&token=ZGVtbzEyMw==&secret=...`). Query strings are written to web server logs, proxy logs, browser history, and any intermediary observability tool. Anyone with log access can read raw tokens.

**Fix:**
- Accept the `token` parameter in the request body (POST) instead of query params, so it never hits access logs.
- Add Pydantic model for validation:

```python
from pydantic import BaseModel, Field

class HashRequest(BaseModel):
    user: str = Field(..., description="The username")
    token: str = Field(..., description="The token")
```

- Change the endpoint to `POST /hash` with JSON body parsing.
- Keep the existing GET route temporarily for backward compatibility and mark it as deprecated with a `Deprecation` response header, then remove it in a later version.

---

## 2. Duplicate hash computation functions (Medium)

**Problem:** `compute_hash_hex()` (line 78) and `hash_token()` (line 86) do the exact same thing: `sha256("user:token")`. One uses the incremental API (`h.update()`), the other passes a single string. Having both is confusing and invites subtle bugs if one ever diverges.

**Fix:**
- Delete `compute_hash_hex()` entirely.
- Update every call site to use `hash_token()` instead:
  - `load_config()` line 115: change `h = compute_hash_hex(user, token)` to `h = hash_token(user, token)`
  - `/verify` success path (line 185): delete the re-computation entirely — it's a no-op. Replace lines 185-186 with just verifying the dict lookup was sufficient (the key in `HASH_TO_USER` already proves the hash is valid). If you want to keep timing-attack-safe comparison for defense-in-depth, compare directly without recomputing:
    ```python
    # Remove compute_hash_hex + hmac.compare_digest entirely.
    # The O(1) dict lookup on HASH_TO_USER is sufficient — if the key exists, the hash is valid.
    ```

---

## 3. No test suite (Medium)

**Problem:** There are zero tests. Any change to hash computation, config parsing, auth logic, or backoff behavior can silently break without detection.

**Fix:**
- Add `pytest` and `httpx` (for testing FastAPI apps) to `requirements.txt`:
  ```
  pytest>=8.0.0
  httpx>=0.27.0
  ```
- Create a `tests/` directory with:
  - `tests/__init__.py`
  - `tests/test_main.py` containing:
    - Tests for `load_config()` with valid, invalid, and missing files
    - Tests for `hash_token()` correctness against known inputs
    - Tests for `/verify` endpoint — valid token returns 200 + `X-Forwarded-User`, invalid returns 401, missing Authorization returns 401
    - Tests for `/reload-config` with and without `RELOAD_SECRET`
    - Tests for brute-force backoff behavior (multiple failed attempts trigger delays)
    - Tests for the `/hash` endpoint

---

## 4. Brute-force state not cleared on all auth failures (Medium)

**Problem:** Failed attempt tracking (`FAILED_ATTEMPTS`) is only cleared in `/verify` on success (line 188). If an admin hits `/reload-config` or `/hash` with a wrong secret from the same IP as a brute-forcer, those requests are unaffected by the backoff. Conversely, if a legitimate user gets rate-limited on `/verify`, they're blocked from using other endpoints too — which is reasonable but worth documenting. The bigger issue is that the backoff delay is applied *before* returning the 401 response, meaning every failed attempt incurs a growing `asyncio.sleep()` penalty — this blocks an event loop coroutine unnecessarily and wastes resources.

**Fix:**
- Replace the `await asyncio.sleep(delay)` pattern with a lightweight timing check instead. Use the backoff to decide whether to reject immediately or apply additional delay only when truly needed (e.g., if the count exceeds a threshold):
  ```python
  # In record_failed_attempt, only return True/False for blocking:
  def should_block(key: str) -> bool:
      now = time.time()
      FAILED_ATTEMPTS[key] = [t for t in FAILED_ATTEMPTS[key] if now - t < WINDOW]
      FAILED_ATTEMPTS[key].append(now)
      return len(FAILED_ATTEMPTS[key]) >= MAX_ATTEMPTS
  ```
- On `/verify`, when `should_block()` returns True, reject immediately (don't sleep on every failure). Sleeping during auth denial burns event-loop time and increases latency for all in-flight requests.
- Optionally add a separate bucket for admin endpoints (`/reload-config`, `/hash`) so brute-force protection doesn't interfere with legitimate admin operations — or just protect those endpoints well with `RELOAD_SECRET` and skip per-IP tracking there.

---

## 5. Config claims "base64token" but never decodes base64 (Medium)

**Problem:** The config file header says `# Format: user:base64token` and the example tokens look like they could be base64 (`ZGVtbzEyMw==`). However, `load_config()` at line 108 does `user, token = line.split(":", 1)` and uses `token` as a raw string — no `base64.b64decode()` call anywhere. The client-side hash computation in the README also treats the token as literal text (`sha256(f"{user}:{token}")`). This mismatch is confusing: admins might base64-encode their tokens thinking it's required, or skip encoding thinking it's plain text.

**Fix:**
- Pick one and commit to it:
  - **Option A (recommended):** Treat the token as a raw plaintext secret. Rename `base64token` to `secret` everywhere — in the config file header, code comments, README, and the `/hash` endpoint description. Remove any implication of base64 encoding.
  - **Option B:** Actually support base64 decoding. Import `base64`, decode the token before hashing: `token = base64.b64decode(token).decode("utf-8")`. Update the client examples to match. Keep backward compatibility by trying base64 decode first and falling back to raw if it fails (with a deprecation warning for raw tokens).
- Update the config file header, code comments, README docs, and the `/hash` endpoint description to be consistent with whichever option is chosen.

---

## 6. Timing side-channel on hash comparison fallback (Medium)

**Problem:** The `/verify` endpoint (line 183-197) takes two different paths:
- Hash found in `HASH_TO_USER` → runs `hmac.compare_digest()` then returns 200 or falls through to line 192
- Hash NOT found → skips hmac compare entirely and returns 401 at line 198

The difference in response time (hmac compare vs instant rejection) leaks whether a candidate hash partially hit an existing dict entry. While SHA-256 collision-based exploitation is impractical, the pattern defeats the purpose of using `hmac.compare_digest` in the first place.

**Fix:**
- Simplify the verify logic: since `HASH_TO_USER` is keyed by `sha256(user:token)`, an O(1) dict lookup *is* the full verification. If the key exists, the hash is valid by definition — no need for `hmac.compare_digest` or recomputation at all.
- On mismatch (hash not found in dict), always perform a dummy `hmac.compare_digest()` with random data to equalize response time across success and failure paths:
  ```python
  import os, hmac, hashlib

  # After failed lookup — constant-time dummy work to prevent timing leaks
  dummy_hash = hmac.new(os.urandom(32), b"dummy", hashlib.sha256).digest()
  hmac.compare_digest(dummy_hash, dummy_hash)
  ```

---

## 7. `/reload-config` has no brute-force protection (Medium)

**Problem:** The `/verify` endpoint rate-limits by IP, but `/reload-config` does not. An attacker can hammer this endpoint trying to guess `RELOAD_SECRET`. It returns 403 immediately with no delay or backoff. Each call also reloads and re-hashes all users from disk, so high volume becomes a resource-exhaustion DoS vector even without a successful guess.

**Fix:**
- Apply the same IP-based rate limiting to `/reload-config` on failed secret validation:
  ```python
  # In reload_config, before returning 403:
  if RELOAD_SECRET and (not provided or not hmac.compare_digest(provided, RELOAD_SECRET)):
      delay = record_failed_attempt(client_ip)
      await asyncio.sleep(delay)
      return JSONResponse({"error": "forbidden"}, status_code=403)
  ```
- Alternatively, add a per-endpoint rate limiter using `slowapi` or FastAPI's `RateLimiter` so admin endpoints have independent limits from auth endpoints.

---

## 8. No input validation or size limits on config entries (Low-Medium)

**Problem:** `load_config()` accepts any `user:token` pair with no length or character restrictions. If an attacker writes to the mounted config file or triggers a reload, they can inject extremely long tokens. Each entry triggers SHA256 hashing at load time — a thousand 1MB tokens would spike CPU on every reload.

**Fix:**
- Add max length checks in `load_config()`:
  ```python
  MAX_USER_LEN = 128
  MAX_TOKEN_LEN = 512

  # After splitting user:token
  if len(user) > MAX_USER_LEN:
      LOG.warning("User %r exceeds max length %d — skipped", user, MAX_USER_LEN)
      continue
  if len(token) > MAX_TOKEN_LEN:
      LOG.warning("Token for user %r exceeds max length %d — skipped", user, MAX_TOKEN_LEN)
      continue
  ```
- Optionally reject non-hex/base64 characters in tokens depending on expected format.

---

## 9. `X-Forwarded-For` is trusted blindly (Low)

**Problem:** `get_client_ip()` (line 68-71) trusts `X-Forwarded-For` without validation. If the service is ever exposed directly to the internet, an attacker can spoof their IP by setting `X-Forwarded-For: <any IP>`, defeating brute-force tracking and audit logging.

**Fix:**
- Only trust `X-Forwarded-For` when the direct connection comes from a known proxy IP (e.g., Docker network ranges like `172.16.0.0/12`, `10.0.0.0/8`, or `192.168.0.0/16`):
  ```python
  import ipaddress

  PROXY_RANGES = [
      ipaddress.ip_network("172.16.0.0/12"),
      ipaddress.ip_network("10.0.0.0/8"),
      ipaddress.ip_network("192.168.0.0/16"),
  ]

  def is_proxy(ip: str) -> bool:
      try:
          addr = ipaddress.ip_address(ip)
          return any(addr in net for net in PROXY_RANGES)
      except ValueError:
          return False

  def get_client_ip(request: Request) -> str:
      if request.client and is_proxy(request.client.host):
          xff = request.headers.get("X-Forwarded-For")
          if xff:
              return xff.split(",")[0].strip()
      return request.client.host if request.client else "unknown"
  ```

---

## 10. Config file has no filesystem-level access control (Low)

**Problem:** `config/users.cfg` is world-readable on the host (mode 644), and the Docker mount only applies read-only (`:ro`) but not permission-restricted access. Any user or process on the host can read raw tokens from the config file, even though the README says to treat it as a secret.

**Fix:**
- After mounting, restrict permissions inside the container:
  ```yaml
  # In compose.yml, add a command override:
  command: >
    sh -c "chmod 600 /app/config/users.cfg && exec uvicorn main:APP ..."
  ```
- Or use Docker secrets instead of volume mounts for production:
  ```yaml
  secrets:
    - source: auth_config
      target: /run/secrets/users.cfg
  ```
- At minimum, document in the README that the config file should be chmod'd to 600 before mounting.

---

## 11. Config loaded at module level before FastAPI startup (Low)

**Problem:** `load_config(CONFIG_FILE)` is called at line 131 during module import, *before* the `APP.on_event("startup")` handler runs. If the config file doesn't exist or hasn't been mounted yet (e.g., Docker container starting up with a volume that mounts asynchronously), the warning fires but there's no retry mechanism. Restarting the container after fixing the mount wouldn't re-trigger — `load_config` only runs once at import time unless `/reload-config` is called manually.

**Fix:**
- Move `load_config()` from module level (line 131) into `on_startup()`:
   ```python
   @APP.on_event("startup")
   async def on_startup():
       load_config(CONFIG_FILE)
       LOG.info("ForwardAuth server started; users=%d", len(USER_TO_TOKEN))
   ```
- Add a retry loop with backoff (3 attempts, 1s apart) in `on_startup()` for missing config files so late-mounting volumes are handled gracefully.

---

## 12. Config delimiter `:` doesn't support colons in tokens (Medium)

**Problem:** Line 108 uses `line.split(":", 1)` which splits on the first colon only. This means a token containing colons like `p:a:s:s` would parse as `user="alice"` and `token="ZGVtbzEyMw==:p:a:s"`. The client would hash `alice:ZGVtbzEyMw==` (without the extra `:a:s`) and never match. Tokens with colons silently fail auth with no warning or error.

**Fix:**
- Document this limitation in the README and config file header comments.
- If you want to support colons, use a different delimiter like `|` or `::`, or switch to YAML/TOML format:
   ```yaml
   # users.yml
   alice: ZGVtbzEyMw==:p:a:s  # token can safely contain colons
   bob: U29tZVBhc3N3b3Jk
   ```

---

## 13. No graceful shutdown handling (Low)

**Problem:** There's no `on_shutdown` handler. When the container receives SIGTERM, uvicorn stops accepting new connections but in-flight `/verify` requests could be mid-`asyncio.sleep(delay)` when killed. A request that was about to succeed after its backoff sleep might complete after the connection is torn down, returning a 200 with no response body visible to Traefik — causing it to treat the upstream as unhealthy.

**Fix:**
- Add an `on_shutdown` handler and a shutdown flag checked in middleware:
   ```python
   _SHUTDOWN = False

   @APP.on_event("shutdown")
   async def on_shutdown():
       global _SHUTDOWN
       _SHUTDOWN = True
       LOG.info("Shutting down — rejecting new auth requests")

   # In /verify, check early:
   if _SHUTDOWN:
       return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
   ```

---

## 14. `/reload-config` doesn't warn on empty/invalid config after reload (Low)

**Problem:** Line 222 calls `load_config(CONFIG_FILE)` which silently does nothing if the file is missing or empty — no error is returned to the caller. An admin could call `/reload-config` thinking it reloaded, but actually get `{loaded_users: 0}` with no visible warning. A broken config file goes unnoticed until auth starts failing for everyone.

**Fix:**
- Track previous user count and return a more informative response after reload:
   ```python
   @APP.api_route("/reload-config", methods=["GET", "POST"])
   async def reload_config(request: Request, secret: str | None = Query(None)):
       # ... auth check ...
       previous_count = len(USER_TO_TOKEN)
       load_config(CONFIG_FILE)
       if len(USER_TO_TOKEN) == 0 and previous_count > 0:
           return JSONResponse(
               {"loaded_users": 0, "warning": "no users loaded — config may be invalid"},
               status_code=500,
           )
       return {"loaded_users": len(USER_TO_TOKEN)}
   ```

---

## 15. Brute-force window resets fully on success — trivially gamed (Low)

**Problem:** Line 188 does `FAILED_ATTEMPTS.pop(client_ip, None)` which removes the entire bucket on any successful auth. An attacker can send one bad request to trigger backoff delay, then realize that *any* subsequent success from that IP clears everything and resets the counter. This means brute-force protection becomes a per-session reset that's trivially gamed:

1. Attacker sends 4 failed attempts → backoff builds up
2. Attacker waits out the sleep or abandons
3. Sometime later, sends 1 bad request → hits server
4. Immediately after, sends 1 good request from a valid token (e.g., leaked legitimate credentials)
5. All previous failures are wiped — attacker can start fresh

**Fix:**
- On success, don't fully remove the bucket — just clear expired entries:
   ```python
   # Instead of FAILED_ATTEMPTS.pop(client_ip, None):
   now = time.time()
   FAILED_ATTEMPTS[client_ip] = [t for t in FAILED_ATTEMPTS[client_ip] if now - t < WINDOW]
   ```
- This way historical attempts in the window still count toward the limit even after a successful auth.

---

## 16. Hash collisions silently overwrite users (Low)

**Problem:** Lines 116-117:
```python
if h not in hashes:
    hashes[h] = user
```
If two different `user:token` pairs happen to produce the same SHA-256 hash, only the *first* one in the file wins — the second is silently discarded with no error or warning. If a config file has duplicate entries (e.g., `alice:token1` and `bob:token2` where `sha256("alice:token1") == sha256("bob:token2")`), bob effectively disappears with no log output to explain why auth fails for him.

**Fix:**
- Log a warning when a collision is detected:
   ```python
   if h in hashes:
       LOG.warning("Hash collision for user %r — skipping duplicate entry", user)
   else:
       hashes[h] = user
   ```
- Optionally reject entries with the same hash at startup and return an error from `/reload-config`.

---

## 17. Log leakage of auth hashes (High)

**Problem:** The `/verify` endpoint (line 197) logs the `client_hash` on failure. Since the hash is the actual credential used for authentication, anyone with access to the logs can perform a "Pass-the-Hash" attack and impersonate any user.

**Fix:**
- Remove the `client_hash` from the log message in `/verify`.

---

## 18. Memory exhaustion via `FAILED_ATTEMPTS` (Medium)

**Problem:** `FAILED_ATTEMPTS` is a `defaultdict(list)` keyed by client IP. There is no global limit on the number of IPs tracked, nor is there a periodic cleanup of inactive IPs. An attacker with a botnet or IP spoofing capability could exhaust server memory.

**Fix:**
- Implement a maximum size for the `FAILED_ATTEMPTS` dictionary.
- Use a cache with TTL (e.g., `cachetools.TTLCache`) instead of a raw dictionary.

---

## 19. DoS via large request bodies in `/reload-config` (Medium)

**Problem:** In `/reload-config` (lines 211, 214), the server attempts to parse the JSON body or Form body before verifying the `RELOAD_SECRET`. A large malicious payload could cause OOM before the request is authorized.

**Fix:**
- Verify the secret from query parameters first.
- Set a strict limit on the request body size using a middleware.

---

## 20. Unprotected admin secret brute-force via `/hash` (Medium)

**Problem:** The `/hash` endpoint (line 225) requires `RELOAD_SECRET` but lacks the brute-force protection (rate limiting/backoff) found in `/verify`. An attacker can hammer this endpoint to guess the admin secret.

**Fix:**
- Apply the same IP-based backoff logic to the `/hash` endpoint as is used in `/verify`.

---

## 21. Resource exhaustion via unbounded input lengths (Low)

**Problem:** There are no maximum length constraints on the `user` or `token` parameters in the `/hash` endpoint (lines 227-229) or the configuration file entries (line 108). Extremely large inputs could lead to high CPU usage during hashing or memory pressure.

**Fix:**
- Add maximum length checks (e.g., 128 chars for user, 512 for token) in `load_config()` and the `/hash` endpoint.

---

## 22. Shared brute-force bucket for unknown IPs (Low)

**Problem:** If `get_client_ip` cannot determine the IP (line 72), it returns `"unknown"`. All such requests share the same brute-force tracking bucket. A single malicious user with an "unknown" IP can inadvertently block all other users whose IPs are also "unknown".

**Fix:**
- Avoid using a shared key for unknown IPs, or apply a more lenient rate limit to the "unknown" bucket.
