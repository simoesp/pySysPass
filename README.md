# pySysPass

`pySysPass` is a modern Python-based implementation of sysPass built with FastAPI, SQLAlchemy, Vue 3, and Quasar. It keeps compatibility with the original sysPass MySQL schema so existing data can be reused while moving the application stack away from the legacy PHP codebase.

Future repository home: [simoesp/pySysPass](https://github.com/simoesp/pySysPass)

## AI Notice

Parts of this project were generated or accelerated with AI assistance. All generated code should be reviewed, tested, and security-checked like any other contribution before production use.

## Production Warning

Please do not use this project in production. It is still evolving, includes AI-assisted code, and should be treated as experimental until it has been fully audited, hardened, and validated for real-world deployment.

## Documentation

The documentation is organized under [docs/README.md](docs/README.md).

Recommended entry points:

- [docs/README.md](docs/README.md): full documentation index
- [docs/installation.md](docs/installation.md): step-by-step installation and first-run setup
- [docs/api/reference.md](docs/api/reference.md): API reference and endpoint catalog
- [docs/security/policy.md](docs/security/policy.md): security model and reporting
- [docs/security/scanning.md](docs/security/scanning.md): local and CI scanning workflow
- [docs/project/feature-completion.md](docs/project/feature-completion.md): implementation status notes

## Overview

- FastAPI backend in `app/`
- Vue 3 + Quasar frontend in `frontend/`
- MySQL-compatible schema and Alembic migration support
- Podman Compose stack for local development
- Portainer-compatible stack file for container deployments
- `pytest` test suite
- Security and compatibility documentation for sysPass adopters

## Stack

### Backend

- Python 3.11
- FastAPI
- SQLAlchemy
- Alembic
- MySQL / PyMySQL

### Frontend

- Vue 3
- Quasar
- Vite
- Pinia
- Axios

### Security

- AES-256-CTR encryption for stored passwords
- RSA-2048 client-side password transport
- JWT authentication
- TOTP two-factor authentication
- bcrypt password hashing

## Features

### Security

- AES-256-CTR encryption with PBKDF2-derived keys, per-entry salt, and IV
- RSA-2048 public-key encryption in the browser before password submission
- JWT authentication with signed tokens
- TOTP-based two-factor authentication
- Audit and security event logging

### Account Management

- Account CRUD
- Password retrieval and decrypt counters
- Favourites
- Account copy / clone support
- Full account history
- File attachments
- Public share links
- Search by title, login, URL, and notes
- Password expiry tracking

### Organisation and Administration

- Categories, clients, and tags
- Users, user profiles, and user groups
- Notifications
- Config/settings endpoints
- Backup and restore workflows
- Import/export support
- LDAP endpoints
- Plugin and custom field endpoints
- Account sharing endpoints

### Frontend

- Vue 3 SPA with Quasar UI
- Multiple built-in themes
- Dark mode support
- Account detail/history views
- Tag-aware filtering and search flows

## Quick Start

For the full step-by-step guide, including first-run setup, verification, and
running against an existing sysPass PHP database, see
[docs/installation.md](docs/installation.md).

### Prerequisites

- Docker with Compose v2, or Podman with `podman-compose`
- Node.js 18+ for frontend-only local development
- Python 3.11+ for backend-only local development

### Start the full stack

The Compose file is standard Compose v2; use Docker or Podman interchangeably:

```bash
cd pySysPass

# Docker
docker compose -f podman-compose.yml up -d --build

# Podman
podman-compose up -d --build
```

This starts:

- `db` on `3306`
- `backend` on `8000`
- `frontend` on `8080`
- `graphify` on `8090`
- `test` as an on-demand pytest container

### Local URLs

- Frontend: `http://localhost:8080`
- API root: `http://localhost:8000/`
- Swagger UI: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`
- Graphify report: `http://localhost:8090`

### First-run setup

A freshly bootstrapped database has the full schema but no administrator and no
master password. Open `http://localhost:8080` and complete the first-run setup
form to create the admin and set (or generate) the master password — save it,
as it cannot be recovered. The equivalent API flow (`/api/v1/auth/install`) and
full details are in [docs/installation.md](docs/installation.md#first-run-setup).

### Deploy with Portainer

Use [portainer-stack.yml](portainer-stack.yml) for Portainer stack deployments.

The stack file is build-based by default. If you deploy from a Git repository in Portainer, it can build the backend and frontend directly from this repo. If you deploy from the Portainer web editor without repository context, publish images first and add explicit `image:` entries or environment-driven image overrides before deploying.

Provide at least these environment variables in Portainer before deploying:

- `MYSQL_ROOT_PASSWORD`
- `MYSQL_PASSWORD`
- `SECRET_KEY`
- `ENCRYPTION_KEY`

## Local Development

### Backend

```bash
cd pySysPass
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd pySysPass/frontend
npm install
npm run dev
```

The default Vite dev server runs on `http://localhost:5173`.

## Configuration

Settings are loaded from environment variables and optionally from `.env` via [app/core/config.py](app/core/config.py).
Application-level settings are stored in `config/runtime-config.json`, which is the JSON successor to the old PHP `config.xml` approach.

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | unset | SQLAlchemy connection string |
| `SECRET_KEY` | generated at runtime when unset | JWT signing secret |
| `ENCRYPTION_KEY` | generated at runtime when unset | Master key for AES encryption |
| `SYSPASS_PASSWORD_SALT` | empty | Runtime sysPass password salt compatibility value |
| `SYSPASS_RUNTIME_CONFIG_JSON_PATH` | `config/runtime-config.json` | Structured JSON runtime configuration file |
| `SQLALCHEMY_SCHEMA_GUARD` | `true` | Prevents unintended schema mutation paths |
| `AUTO_INIT_DB_ON_STARTUP` | `true` | Bootstrap schema automatically when the database is empty |
| `DEBUG` | `true` | Enables debug-friendly runtime behaviour |
| `CORS_ORIGINS` | empty by default | Allowed browser origins; when unset, values are loaded from `config/cors-origins.json` |
| `CORS_ORIGINS_FILE` | `config/cors-origins.json` | Path to the JSON file containing the browser origin allowlist |

The settings API continues to work, and file-backed JSON settings are preferred over legacy values stored in the database `Config` table. PHP-style XML and cache files remain supported as compatibility fallbacks for runtime metadata such as `passwordSalt`.

The compose stack includes development defaults. Change all secrets before any shared or production deployment.
`podman-compose.yml` keeps developer-friendly bind mounts and `--reload`; `portainer-stack.yml` is the cleaner runtime-oriented variant.

### Run against an existing sysPass database

Use `podman-compose.external.yml` to run the complete frontend and backend
without starting an internal database. The backend treats the external schema
as PHP-owned: automatic initialization is disabled and the schema mutation
guard remains enabled.

```bash
cp .env.external.example .env.external
# Edit .env.external with the external database URL, PHP passwordSalt, and
# independently generated application secrets.
podman-compose --env-file .env.external -f podman-compose.external.yml up -d --build
```

The defaults expose the UI at `http://localhost:8081` and the backend at
`http://localhost:8001`. The frontend proxies `/api/` and `/health` to the
backend over the private Compose network. Stop the stack with:

```bash
podman-compose --env-file .env.external -f podman-compose.external.yml down
```

On a brand-new database, run the installation flow first. The installer creates the initial administrator and sets the sysPass master password at install time. That master password can either be supplied explicitly or generated once by the API, and it must be saved outside the application.
When the installer generates the master password, the setup page keeps it visible until you confirm that it has been saved and continue to login. If you supply the master password yourself, successful setup reloads the application at the login page so installation state is checked again.
The administrator login and manually supplied master-password fields include the same secure password generator used for vault accounts, plus live strength and entropy feedback.
If startup is interrupted during schema creation, the bootstrap process now checks the full expected table set and retries missing tables on the next launch.

## API Overview

The backend exposes REST endpoints under `/api/v1` and publishes OpenAPI docs at `/docs`.

High-level endpoint groups:

- Authentication: `/api/v1/auth/*`
- Accounts: `/api/v1/accounts*`
- Users and groups: `/api/v1/users*`, `/api/v1/user-groups*`
- Organization: `/api/v1/categories*`, `/api/v1/clients*`, `/api/v1/tags*`
- Notifications and settings: `/api/v1/notifications*`, `/api/v1/settings*`
- Security and operations: `/api/v1/security/*`, `/api/v1/backup*`, `/api/v1/import*`, `/api/v1/plugins*`

Use the live OpenAPI UI at `/docs` for the detailed request and response schema.

## Further Reading

- [docs/api/reference.md](docs/api/reference.md)
- [docs/security/policy.md](docs/security/policy.md)
- [docs/security/scanning.md](docs/security/scanning.md)
- [docs/project/feature-completion.md](docs/project/feature-completion.md)

## Testing

Run tests locally:

```bash
cd pySysPass
pytest
```

Run tests in the compose environment:

```bash
cd pySysPass
podman-compose run --rm test
```

## Project Layout

```text
pySysPass/
├── app/              FastAPI backend
├── frontend/         Vue 3 + Quasar frontend
├── alembic/          Migration scaffolding
├── schemas/          SQL schema snapshots and compatibility scripts
├── tests/            pytest suite
└── podman-compose.yml
```

## Credits

Based on the original [sysPass](https://github.com/nuxsmin/sysPass) project by Rubén Domínguez.

The Python project is intended to live under [simoesp/pySysPass](https://github.com/simoesp/pySysPass).

## Author

Pedro Simoes <dr.wicked82@gmail.com>

## License

This software is distributed under the GNU GPLv3. See [COPYING](COPYING).
