# Base image pinned by digest (python:3.11-slim, multi-arch index) so a rebuild
# cannot silently change the OS layer. Update the tag and digest together.
FROM docker.io/library/python:3.11-slim@sha256:b7a9e5f6a93d6d4a31f129bbd4bdee69efccb6ded0fb230d78aafaf37af98377

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SYSPASS_RUNTIME_CONFIG_JSON_PATH=/app/data/runtime-config.json

WORKDIR /app

# mysqldump/mysql are required for fail-closed backups and offline restore;
# libmagic1 provides PHP fileinfo's MIME detection for attachments.
# Every Python dependency ships wheels, so no compiler or headers are needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-mysql-client libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Fixed unprivileged identity; mounted volumes must be owned by it
# (see docs/installation.md#container-user-and-volume-ownership).
RUN groupadd --system --gid 10001 syspass \
    && useradd --system --uid 10001 --gid syspass --home-dir /app --no-create-home --shell /usr/sbin/nologin syspass

# Exact, hash-verified runtime dependencies; test tools are not installed.
COPY requirements.lock .
RUN pip install --require-hashes --no-deps -r requirements.lock

# Explicit allowlist: never copy local secrets (.env*), runtime state (data/,
# backups/, config/runtime-config.json), tests, or tooling into the image.
COPY alembic.ini init_db.py ./
COPY alembic/ alembic/
COPY schemas/ schemas/
COPY app/ app/
COPY config/cors-origins.json config/cors-origins.json

# Code stays root-owned and read-only to the service account; only runtime
# state directories are writable.
RUN mkdir -p data backups plugins \
    && chown syspass:syspass data backups \
    && chmod 0700 data backups

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
