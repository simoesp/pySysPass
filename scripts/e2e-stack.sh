#!/usr/bin/env bash
# Start (up) or remove (down) a disposable production-like stack for browser
# tests: MySQL 8, the backend image (DEBUG=false), and the nginx frontend on
# 127.0.0.1:${E2E_PORT:-18300}. Never run it against real data.
set -euo pipefail
BACKEND_IMAGE=${BACKEND_IMAGE:-pysyspass-backend:e2e}
FRONTEND_IMAGE=${FRONTEND_IMAGE:-pysyspass-frontend:e2e}
PORT=${E2E_PORT:-18300}
NET=e2e-net

case "${1:-}" in
  up)
    docker network create --subnet 172.31.91.0/24 "$NET" >/dev/null
    docker run -d --rm --name e2e-db --network "$NET" -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=syspass \
      mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b >/dev/null
    # TCP, not the socket: MySQL's first-run init server accepts socket clients
    # only, then restarts; waiting on the socket races that restart.
    until docker exec e2e-db mysql --protocol=tcp -h127.0.0.1 -uroot -proot -e "select 1" syspass >/dev/null 2>&1; do sleep 2; done
    # nginx proxies to the host name "backend".
    # No --rm: keep the container (and its logs) if startup fails.
    docker run -d --name backend --network "$NET" --ip 172.31.91.20 \
      -e DATABASE_URL=mysql+pymysql://root:root@e2e-db:3306/syspass -e DEBUG=false \
      -e SECRET_KEY="$(openssl rand -hex 24)" -e ENCRYPTION_KEY="$(openssl rand -hex 24)" \
      -e SYSPASS_PASSWORD_SALT="$(openssl rand -hex 30)" -e TRUSTED_PROXY_HOSTS='["172.31.91.10"]' \
      -e AUTO_INIT_DB_ON_STARTUP=true "$BACKEND_IMAGE" >/dev/null
    docker run -d --rm --name e2e-frontend --network "$NET" --ip 172.31.91.10 -p "127.0.0.1:${PORT}:8080" \
      "$FRONTEND_IMAGE" >/dev/null
    for _ in $(seq 1 90); do
      curl -sf "http://127.0.0.1:${PORT}/health/ready" >/dev/null && { echo "stack ready on :${PORT}"; exit 0; }
      sleep 2
    done
    docker logs backend 2>&1 | tail -40
    exit 1
    ;;
  down)
    docker rm -f e2e-frontend backend e2e-db >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
