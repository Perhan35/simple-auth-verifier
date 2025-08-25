# simple-auth-verifier (SAV)

Sits behind a reverse proxy (ex: Traefik) and checks the provided token in the authorization header - Bearer token.

Tiny FastAPI ForwardAuth validator that accepts a SHA-256 hash of `user:token` as an API key.  
Admins keep a simple `user:token` config file; clients compute `sha256("user:token")` and present that hex digest in the `Authorization: Bearer <hash>` header. Designed to run behind Traefik (ForwardAuth) and protect services like Ollama.

---

## Features

- Precomputes `sha256(user:token)` at startup for O(1) verification lookups.
- Exposes:
  - `POST/GET /verify` — Traefik ForwardAuth endpoint (accepts common HTTP methods).
  - `GET /health` — simple health check.
  - `POST /reload-config` — optional config reload (protected by `RELOAD_SECRET` if set).
  - `GET /hash` — generate SHA-256 hash for `user:token` (protected by `RELOAD_SECRET`).
- Runs as a Docker container (Python 3.12, FastAPI + Uvicorn).
- Config format is human-friendly: `user:token` (one per line).

---

## Repo layout

```
.
├─ main.py
├─ requirements.txt
├─ Dockerfile-slim
├─ Dockerfile-alpine
├─ docker-compose.yml
├─ ...
└─ config/
   └─ users.cfg              # example config file
```

---

## Quickstart (local, development)

1. Clone the repo:

```bash
git clone https://github.com/Perhan35/simple-auth-verifier.git
cd simple-auth-verifier
```

2. Create a config directory and example `users.cfg`:

```text
# config/users.cfg
# Format: user:token
alice:ZGVtbzEyMw==
bob:U29tZVBhc3N3b3Jk
```

3. Build and run with Docker Compose:

```bash
docker compose up --build -d
```

OR

3. Activate Pyenv to work locally

```bash
pyenv install -s 3.12.0 && \
pyenv local 3.12.0 && \
python -m venv venv && \
source venv/Scripts/activate && \
pip install --upgrade pip && \
pip install -r requirements.txt
```

4. Run it!

```bash
RELOAD_SECRET="supersecret" uvicorn main:APP --reload
```

The auth service listens on container port `8000`. By default you can test it on the host at `http://localhost:8000` when running locally.

---

## How it works (summary)

- Admin writes `user:token` into `config/users.cfg`.
- On startup (and on reload), the server loads the file and precomputes a mapping:
  ```
  sha256(user:token) -> user
  ```
- Client computes the same SHA-256 hex digest and calls:
  ```
  Authorization: Bearer <hex-digest>
  ```
- Server checks digest in O(1) (dict lookup). If found, returns `200 OK` and header `X-Forwarded-User: <user>` for the upstream service.

---

## Examples — compute the hash (client-side)

### Python

```python
import hashlib

user = "alice"
token = "ZGVtbzEyMw=="  # token stored in config
digest = hashlib.sha256(f"{user}:{token}".encode("utf-8")).hexdigest()
print(digest)
```

### Bash / OpenSSL

```bash
USER="alice"
TOKEN="ZGVtbzEyMw=="
HASH=$(printf "%s:%s" "$USER" "$TOKEN" | openssl dgst -sha256 -hex | awk '{print $2}')
echo $HASH
```

---

## Curl tests (direct to auth service)

Assume `HASH` contains the computed hex digest.

```bash
curl -i -H "Authorization: Bearer $HASH" http://localhost:8000/verify
```

### Happy path (valid)

Expected response (headers show `X-Forwarded-User`):

```
HTTP/1.1 200 OK
X-Forwarded-User: alice
...
```

### Invalid token

Expected:

```
HTTP/1.1 401 Unauthorized
...
```

### Health check

```bash
curl http://localhost:8000/health
# returns "Simple Auth Server is running"
```

### Reload config (if `RELOAD_SECRET` is set)

```bash
# If RELOAD_SECRET=supersecret was set in the container:
curl -X POST "http://localhost:8000/reload-config" -d "secret=supersecret"
# returns {"loaded_users": N}
```

The secret should be set as environment variable your container or shell before running the server:

```bash
export RELOAD_SECRET="supersecret"   # Linux/macOS
set RELOAD_SECRET=supersecret        # Windows cmd
$env:RELOAD_SECRET="supersecret"     # PowerShell
- RELOAD_SECRET=supersecret          # Docker Compose
```

### Generate hash (if `RELOAD_SECRET` is set)

```bash
curl "http://localhost:8000/hash?user=alice&token=ZGVtbzEyMw==&secret=supersecret"
# returns {"username": "alice", "hash": "<sha256-hex>"}
```

**Security note:** The `/hash` endpoint is only meant as a helper for admins. Do **not** expose it publicly. Clients should compute hashes themselves.

## /hash endpoint

A convenience endpoint to compute the SHA-256 hex digest of `user:token`.

### Request

- **Method:** `GET`
- **Path:** `/hash`
- **Query parameters:**
  - `user` (required)
  - `token` (required)
  - `secret` (required iff `RELOAD_SECRET` is set)

### Response

```json
{"username": "<user>", "hash": "<sha256-hex>"}
```

**Notes:** This is for testing/bootstrapping; keep it on an internal network and protect it with `RELOAD_SECRET`. If your token contains special characters, URL-encode it in the query string.

---

## Example Traefik wiring (Docker labels)

Use this snippet on the service you want to protect (example: Ollama). Traefik will call the ForwardAuth endpoint and only forward the request if the auth service returns 200. See below.

**Notes:**

- Traefik must be on the same Docker network as the `forwardauth` service and able to resolve the service name (here `forwardauth`).
- Traefik forwards request headers to the `forwardauth` endpoint (including `Authorization`) so the service can validate them.

---

## Configuration & environment variables

- `CONFIG_FILE` — path to config file inside container (default: `/config/users.cfg`).
- `RELOAD_SECRET` — optional secret to protect `POST /reload-config` and `GET /hash`. If set, you must provide the secret when calling these endpoints.

Mount your config directory read-only into the container:

```yaml
volumes:
  - ./config:/config:ro
```

---

## Security & operational recommendations
- **Treat `config/users.cfg` as a secret.** Use read-only mounts, OS file permissions, Docker secrets, or a secrets manager for production.  
- **Do not expose the auth service publicly.** Keep it on the internal network and let Traefik call it. Set the service label `traefik.enable=false`.  
- **Use TLS for client → Traefik and Traefik → upstream.** Traefik should terminate TLS at the edge. Internal HTTP between Traefik and forwardauth is acceptable if the network is trusted.  
- **Rotate tokens** periodically by changing the `users.cfg` file and calling `/reload-config` (or restarting).  
- **Scale horizontally** by running multiple instances behind Traefik if you need higher throughput. Keep config synchronized (e.g., orchestrator volume, config management, or a shared secret store).  
- **Optional hardening:** store hashed tokens instead of raw tokens in config; use HSM/vault for token storage if required by policy.

---

## Performance notes

- Hashes are precomputed at load time and stored in an in-memory dict map (`hash -> user`) for O(1) lookups. This is efficient for hundreds to thousands of users.
- For massive user lists or strict timing-attack protection across all entries, consider alternate approaches (e.g., HSM, rate-limiting, or per-request HMACs).

---

## Troubleshooting

- `401` responses:
  - Verify client computed hash using exact `user:token` string and SHA-256 hex digest.
  - Check that Traefik forwards the `Authorization` header to the auth service (no header stripping middleware).
- `Config not found` warnings:
  - Ensure `CONFIG_FILE` path matches the mounted file inside the container and volume is mounted correctly.
- Networking issues:
  - Ensure Traefik and `forwardauth` are on the same Docker network. Check service name resolution.

---

## Docker / Compose examples

A minimal `docker-compose.yml` (example):

```yaml
services:
  forwardauth:
    build: .
    container_name: forwardauth
    restart: unless-stopped
    volumes:
      - ./config:/config:ro
    environment:
      - CONFIG_FILE=/config/users.cfg
      # - RELOAD_SECRET=some-secret
    labels:
      - "traefik.enable=false"

  # example protected service (Ollama)
  ollama:
    image: ghcr.io/ollama/ollama:latest
    container_name: ollama
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ollama.rule=Host(`ai.example.com`)

```
