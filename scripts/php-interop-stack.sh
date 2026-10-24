#!/usr/bin/env bash
# Disposable sysPass PHP + pySysPass sharing one database (up|down).
# sysPass PHP 3.2.11 (official image) is installed with its own installer;
# pySysPass then joins the PHP-created database with the same password salt.
# PHP UI: 127.0.0.1:18400, pySysPass API: 127.0.0.1:18401. Synthetic data only.
set -euo pipefail
BACKEND_IMAGE=${BACKEND_IMAGE:-pysyspass-backend:e2e}
PHP_IMAGE=docker.io/syspass/syspass:3.2.11@sha256:d0fe3cf628402466f8df6877114166498b682aa9ec45faf06f55adaf1d3b121b
MYSQL_IMAGE=mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b
NET=php-interop-net

case "${1:-}" in
  up)
    docker network create "$NET" >/dev/null
    # PHP 7.3 in the sysPass image predates caching_sha2_password.
    docker run -d --rm --name interop-db --network "$NET" -e MYSQL_ROOT_PASSWORD=root \
      "$MYSQL_IMAGE" --default-authentication-plugin=mysql_native_password >/dev/null
    until docker exec interop-db mysql -uroot -proot -e "select 1" >/dev/null 2>&1; do sleep 2; done
    docker run -d --rm --name interop-php --network "$NET" -p 127.0.0.1:18400:80 "$PHP_IMAGE" >/dev/null
    until curl -sf -o /dev/null http://127.0.0.1:18400/index.php; do sleep 2; done
    result=$(curl -sf -X POST "http://127.0.0.1:18400/index.php?r=install/install" \
      --data-urlencode adminlogin=phpadmin --data-urlencode adminpass=PhpAdmin-Pass-2026 \
      --data-urlencode adminpassr=PhpAdmin-Pass-2026 --data-urlencode masterpassword=Php-Master-Pass-2026 \
      --data-urlencode masterpasswordr=Php-Master-Pass-2026 --data-urlencode dbuser=root \
      --data-urlencode dbpass=root --data-urlencode dbname=syspass --data-urlencode dbhost=interop-db \
      --data-urlencode dbtype=mysql --data-urlencode sitelang=en_US --data-urlencode hostingmode=0 \
      --data-urlencode install=true --data-urlencode isAjax=1)
    echo "$result" | grep -q '"status":0' || { echo "PHP install failed: $result" >&2; exit 1; }
    salt=$(docker exec interop-php sh -c \
      'sed -n "s:.*<passwordSalt>\(.*\)</passwordSalt>.*:\1:p" /var/www/html/sysPass/app/config/config.xml')
    docker run -d --rm --name interop-py --network "$NET" -p 127.0.0.1:18401:8000 \
      -e DATABASE_URL=mysql+pymysql://root:root@interop-db:3306/syspass -e DEBUG=false \
      -e SECRET_KEY="$(openssl rand -hex 24)" -e ENCRYPTION_KEY="$(openssl rand -hex 24)" \
      -e SYSPASS_PASSWORD_SALT="$salt" -e AUTO_INIT_DB_ON_STARTUP=false -e TRUSTED_PROXY_HOSTS='[]' \
      "$BACKEND_IMAGE" >/dev/null
    for _ in $(seq 1 60); do
      curl -sf http://127.0.0.1:18401/health/ready >/dev/null && { echo "PHP + pySysPass ready"; exit 0; }
      sleep 2
    done
    docker logs interop-py | tail -20
    exit 1
    ;;
  down)
    docker rm -f interop-py interop-php interop-db >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
