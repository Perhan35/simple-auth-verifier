#!/usr/bin/env python3
import os
import hashlib
import hmac
import logging
import asyncio
import time
from collections import defaultdict
from typing import Dict

from fastapi import FastAPI, Request, Response, status, Query
from fastapi.responses import PlainTextResponse, JSONResponse

# ----------------------------
# Logging setup
# ----------------------------
LOG = logging.getLogger("simpleauthverifier")
LOG.setLevel(logging.INFO)

if LOG.hasHandlers():
    LOG.handlers.clear()

handler = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s    %(asctime)s     %(message)s")
handler.setFormatter(formatter)
LOG.addHandler(handler)


# ----------------------------
# FastAPI app
# ----------------------------
APP = FastAPI(title="ForwardAuth Hashed Token Server")

CONFIG_FILE = os.getenv("CONFIG_FILE", "./config/users.cfg")
RELOAD_SECRET = os.getenv("RELOAD_SECRET")  # optional: protect reload endpoint

# In-memory maps
USER_TO_TOKEN: Dict[str, str] = {}
HASH_TO_USER: Dict[str, str] = {}


# ----------------------------
# Brute-force protection
# ----------------------------
FAILED_ATTEMPTS: Dict[str, list[float]] = defaultdict(list)
MAX_ATTEMPTS = 5       # max attempts
WINDOW = 60            # seconds
BACKOFF_BASE = 0.5     # initial delay in seconds
BACKOFF_MAX = 5        # max delay


def record_failed_attempt(key: str) -> float:
    """Record a failed attempt and return backoff delay in seconds."""
    now = time.time()
    # Remove old attempts outside the window
    FAILED_ATTEMPTS[key] = [t for t in FAILED_ATTEMPTS[key] if now - t < WINDOW]
    FAILED_ATTEMPTS[key].append(now)
    count = len(FAILED_ATTEMPTS[key])
    # Exponential backoff
    delay = min(BACKOFF_BASE * count, BACKOFF_MAX)
    return delay


def get_client_ip(request: Request) -> str:
    """
    Return real client IP, using X-Forwarded-For if present (Traefik-safe).
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # Sometimes contains a list: "client, proxy1, proxy2"
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ----------------------------
# Helper functions
# ----------------------------
def compute_hash_hex(user: str, token: str) -> str:
    """Return SHA256 hex digest of 'user:token'."""
    h = hashlib.sha256()
    h.update(user.encode("utf-8"))
    h.update(b":")
    h.update(token.encode("utf-8"))
    return h.hexdigest()


def load_config(path: str) -> None:
    """
    Load config file (user:base64token) and precompute hashes.
    This replaces global USER_TO_TOKEN and HASH_TO_USER.
    """
    global USER_TO_TOKEN, HASH_TO_USER
    users: Dict[str, str] = {}
    hashes: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for ln in fh:
                line = ln.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    LOG.warning("Skipping invalid line (no colon): %r", line)
                    continue
                user, token = line.split(":", 1)
                user = user.strip()
                token = token.strip()
                if not user or not token:
                    LOG.warning("Skipping invalid entry (empty user/token): %r", line)
                    continue
                users[user] = token
                h = compute_hash_hex(user, token)
                if h not in hashes:
                    hashes[h] = user
    except FileNotFoundError:
        LOG.warning("Config file not found at %s — no users loaded", path)
    except Exception as e:
        LOG.exception("Failed to load config: %s", e)

    USER_TO_TOKEN = users
    HASH_TO_USER = hashes
    LOG.info("Loaded %d users, %d precomputed hashes from %s", len(USER_TO_TOKEN), len(HASH_TO_USER), path)


# ----------------------------
# Initial load
# ----------------------------
load_config(CONFIG_FILE)


@APP.on_event("startup")
async def on_startup():
    LOG.info("ForwardAuth server started; users=%d", len(USER_TO_TOKEN))


# ----------------------------
# Endpoints
# ----------------------------
@APP.api_route("/verify", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def verify(request: Request):
    """
    Traefik ForwardAuth endpoint with brute-force protection.
    Expects: Authorization: Bearer <hex-sha256(user:base64token)>
    If valid -> 200 OK and header X-Forwarded-User
    If invalid -> 401
    """
    client_ip = get_client_ip(request)

    auth = request.headers.get("Authorization", "")
    if not auth:
        delay = record_failed_attempt(client_ip)
        await asyncio.sleep(delay)
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        delay = record_failed_attempt(client_ip)
        await asyncio.sleep(delay)
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    client_hash = parts[1].strip().lower()
    if not client_hash:
        delay = record_failed_attempt(client_ip)
        await asyncio.sleep(delay)
        return Response(status_code=status.HTTP_401_UNAUTHORIZED)

    # Fast path: dictionary lookup (O(1))
    user = HASH_TO_USER.get(client_hash)
    if user:
        expected = compute_hash_hex(user, USER_TO_TOKEN[user])
        if hmac.compare_digest(expected, client_hash):
            # success: clear failed attempts for this IP
            FAILED_ATTEMPTS.pop(client_ip, None)
            headers = {"X-Forwarded-User": user}
            return Response(status_code=status.HTTP_200_OK, headers=headers)
        LOG.warning("Hash lookup mismatch for user=%s", user)

    # Failed attempt: record and backoff
    delay = record_failed_attempt(client_ip)
    await asyncio.sleep(delay)
    return Response(status_code=status.HTTP_401_UNAUTHORIZED)


@APP.get("/health")
async def health():
    return PlainTextResponse("Simple Auth Server is running", status_code=200)


@APP.api_route("/reload-config", methods=["GET", "POST"])
async def reload_config(request: Request, secret: str | None = Query(None)):
    """
    Reload config from disk. Protected by RELOAD_SECRET if set.
    - GET: provide ?secret=<your-secret> in the URL
    - POST: provide secret in JSON body, form data, or query parameter
    """
    # extract secret from POST body if not in query
    if request.method == "POST" and secret is None:
        try:
            data = await request.json()
            secret = data.get("secret")
        except Exception:
            form = await request.form()
            secret = form.get("secret")

    if RELOAD_SECRET:
        provided = secret or ""
        if not provided or not hmac.compare_digest(provided, RELOAD_SECRET):
            return JSONResponse({"error": "forbidden"}, status_code=403)

    load_config(CONFIG_FILE)
    return {"loaded_users": len(USER_TO_TOKEN)}
