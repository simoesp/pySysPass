# Installation Guide

This guide walks through installing pySysPass from a clean checkout, completing
the first-run setup, and verifying the result. Both Docker and Podman are
supported; the commands are interchangeable.

> **Not production-ready.** pySysPass is experimental and includes AI-assisted
> code. Review, harden, and audit it before any real-world use, and replace
> every default secret before exposing it beyond your machine.

## Contents

- [Prerequisites](#prerequisites)
- [Option A: Full stack with containers](#option-a-full-stack-with-containers)
- [First-run setup](#first-run-setup)
- [Verifying the installation](#verifying-the-installation)
- [Option B: Local development (no containers)](#option-b-local-development-no-containers)
- [Option C: Run against an existing sysPass PHP database](#option-c-run-against-an-existing-syspass-php-database)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

## Prerequisites

| Tool | Version | Needed for |
| --- | --- | --- |
| Docker + Docker Compose v2, **or** Podman + `podman-compose` | recent | Container stack (Option A) |
| Python | 3.11+ | Backend local development (Option B) |
| Node.js | 18+ | Frontend local development (Option B) |

The backend targets Python 3.11 (the container image is `python:3.11-slim`).
Older versions are not supported.

## Option A: Full stack with containers

This is the fastest path. It starts MySQL, the backend API, the frontend, and a
static Graphify report viewer.

From the repository root:

```bash
# Docker
docker compose -f podman-compose.yml up -d --build

# Podman (equivalent)
podman-compose up -d --build
```

> The compose file is named `podman-compose.yml` but is standard Compose v2 and
> works unchanged with `docker compose -f podman-compose.yml`.

Services and published ports:

| Service | URL | Purpose |
| --- | --- | --- |
| `frontend` | http://localhost:8080 | Web UI |
| `backend` | http://localhost:8000 | REST API |
| Swagger UI | http://localhost:8000/docs | Interactive API docs |
| Health check | http://localhost:8000/health | Liveness probe |
| `db` | localhost:3306 | MySQL 8 |
| `graphify` | http://localhost:8090 | Static knowledge-graph report |

The backend has `AUTO_INIT_DB_ON_STARTUP=true`, so on an empty database it
creates the full sysPass-compatible schema automatically on first boot. Wait for
the backend health check to pass before continuing:

```bash
curl -fsS http://localhost:8000/health && echo " backend up"
```

> **Change the defaults.** `podman-compose.yml` ships development secrets
> (`SECRET_KEY`, `ENCRYPTION_KEY`, `MYSQL_*`, and a sample `SYSPASS_PASSWORD_SALT`).
> Replace all of them before any shared or exposed deployment.

## First-run setup

A freshly bootstrapped database has an empty schema but **no administrator and
no master password**. You must complete setup before you can log in. The master
password is the root of sysPass encryption and is set once, at install time —
save it somewhere safe, because it cannot be recovered.

### Via the web UI

1. Open http://localhost:8080.
2. The app detects that no user exists and shows the first-run setup form.
3. Enter the administrator username and password. Either supply your own master
   password or let the installer generate one.
4. If the installer generates the master password, it stays on screen until you
   confirm you have saved it. Store it before continuing to login.

### Via the API

Check installation state:

```bash
curl -s http://localhost:8000/api/v1/auth/install/status
# {"installed": false, "user_count": 0, "has_master_password": false}
```

Install with a generated master password (returned once, in the response):

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/install \
  -H 'Content-Type: application/json' \
  -d '{
        "username": "admin",
        "password": "choose-a-strong-login-password",
        "email": "admin@example.com",
        "generate_master_password": true
      }'
```

The response includes `master_password` only when it was generated — copy it
immediately:

```json
{
  "user_id": 1,
  "username": "admin",
  "master_password_generated": true,
  "master_password": "…save-this…",
  "message": "Save the generated master password in a secure place before continuing."
}
```

To set your own master password instead, send `master_password` (minimum 12
characters) and omit `generate_master_password`:

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/install \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"strong-login-password","master_password":"your-master-password"}'
```

Installing twice is refused with HTTP 409 (`sysPass is already installed`).

## Verifying the installation

```bash
# Setup is complete
curl -s http://localhost:8000/api/v1/auth/install/status
# {"installed": true, "user_count": 1, "has_master_password": true}

# Log in with the administrator credentials created above
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"choose-a-strong-login-password"}'
```

Then open http://localhost:8080 and sign in through the UI.

## Option B: Local development (no containers)

### Backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE_URL="sqlite:///./syspass.db"   # or a MySQL URL
export SECRET_KEY="$(openssl rand -hex 32)"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend runs against SQLite for development or MySQL for
PHP-compatibility work. With `AUTO_INIT_DB_ON_STARTUP=true` (the default) it
bootstraps the schema on first start. Complete [first-run setup](#first-run-setup)
afterwards.

### Frontend

```bash
cd frontend
npm install
npm run dev   # Vite dev server on http://localhost:5173
```

## Option C: Run against an existing sysPass PHP database

Use `podman-compose.external.yml` to run the UI and backend against a database
created by sysPass PHP, without starting an internal MySQL. In this mode the
backend treats the schema as PHP-owned: automatic initialization is disabled and
the schema-mutation guard stays on.

```bash
cp .env.external.example .env.external
# Edit .env.external:
#   - the external DATABASE_URL (URL-encode special characters in credentials)
#   - SYSPASS_PASSWORD_SALT copied from the PHP install's app/config/config.xml
#   - independently generated SECRET_KEY and ENCRYPTION_KEY

# Docker
docker compose --env-file .env.external -f podman-compose.external.yml up -d --build
# Podman
podman-compose --env-file .env.external -f podman-compose.external.yml up -d --build
```

Defaults expose the UI at http://localhost:8081 and the backend at
http://localhost:8001. The `passwordSalt` is required to decrypt PHP-created
master-password material; without the matching salt, existing users cannot log
in. Because the database already has an administrator and master password, skip
first-run setup and log in with the existing PHP credentials.

Stop the stack with:

```bash
podman-compose --env-file .env.external -f podman-compose.external.yml down
```

## Configuration reference

Settings are read from environment variables (and optionally an `.env` file) via
[app/core/config.py](../app/core/config.py). Application-level settings live in
`config/runtime-config.json`, the JSON successor to PHP's `config.xml`.

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | unset (required) | SQLAlchemy connection string |
| `SECRET_KEY` | generated at runtime when unset | JWT signing secret |
| `ENCRYPTION_KEY` | generated at runtime when unset | Master key for AES encryption |
| `SYSPASS_PASSWORD_SALT` | empty | sysPass password-salt compatibility value (from PHP `config.xml`) |
| `SYSPASS_RUNTIME_CONFIG_JSON_PATH` | `config/runtime-config.json` | Structured JSON runtime config file |
| `SQLALCHEMY_SCHEMA_GUARD` | `true` | Prevents unintended schema mutation |
| `AUTO_INIT_DB_ON_STARTUP` | `true` | Bootstrap schema when the database is empty |
| `DEBUG` | `true` | Debug-friendly runtime behaviour |
| `CORS_ORIGINS` | empty | Allowed browser origins; falls back to `config/cors-origins.json` when unset |
| `CORS_ORIGINS_FILE` | `config/cors-origins.json` | Browser origin allowlist file |

> `SECRET_KEY` and `ENCRYPTION_KEY` are generated per process when unset, which
> is fine for a quick trial but rotates on every restart (invalidating issued
> JWTs). Set them explicitly for anything beyond a throwaway run.

## Troubleshooting

- **`install/status` shows `installed: false` after setup** — the schema
  bootstrap may have been interrupted. Restart the backend; it re-checks the
  full expected table set and retries missing tables on the next launch.
- **Backend never becomes healthy** — confirm the `db` service is healthy first
  (`docker compose -f podman-compose.yml ps`); the backend waits on it.
- **Existing PHP users cannot log in (Option C)** — the `SYSPASS_PASSWORD_SALT`
  does not match the PHP install. Copy the exact `passwordSalt` from the PHP
  `app/config/config.xml`.
- **Lost master password** — it cannot be recovered. On a fresh install, drop
  the database and re-run first-run setup.
