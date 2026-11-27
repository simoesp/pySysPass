# Deployment Guide

This guide documents deployment procedures for pySysPass across different platforms.

**IMPORTANT:** This documentation describes the TARGET architecture as designed in ADRs. Some procedures marked with `[NOT YET IMPLEMENTED]` depend on features that have been designed but not yet implemented.

---

## Table of Contents

1. [Docker Compose Deployment](#docker-compose-deployment)
2. [Standalone Container Deployment](#standalone-container-deployment)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [OpenShift Deployment](#openshift-deployment)
5. [Reverse Proxy Configuration](#reverse-proxy-configuration)
6. [TLS Termination](#tls-termination)
7. [Persistent Storage](#persistent-storage)
8. [Database Connectivity](#database-connectivity)
9. [Mounted Secrets](#mounted-secrets)
10. [Backup Storage](#backup-storage)
11. [LDAP Integration](#ldap-integration)
12. [Application Health Checks](#application-health-checks)
13. [Session Storage](#session-storage)
14. [Multiple Workers and Replicas](#multiple-workers-and-replicas)
15. [Logging and SIEM Integration](#logging-and-siem-integration)
16. [Upgrade and Rollback Procedures](#upgrade-and-rollback-procedures)

---

## Docker Compose Deployment

**Status:** ✅ Preferred straightforward self-hosted deployment

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 1.29+
- At least 4GB RAM
- 10GB disk space

### Configuration

#### 1. Create `docker-compose.yml`

```yaml
version: '3.8'

services:
  database:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: syspass
      MYSQL_USER: syspass
      MYSQL_PASSWORD: ${DB_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
    volumes:
      - mysql_data:/var/lib/mysql
      - ./init-db:/docker-entrypoint-initdb.d
    ports:
      - "3306:3306"
    command:
      - --default-authentication-plugin=mysql_native_password
      - --sql-mode=STRICT_TRANS_TABLES
    networks:
      - syspass
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  app:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=mysql://syspass:${DB_PASSWORD}@database:3306/syspass
      - SECRET_KEY=${SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - SERVICE_VAULT_KEY=${SERVICE_VAULT_KEY}
      - BACKUP_KEY=${BACKUP_KEY}
      - LDAP_ENABLED=${LDAP_ENABLED:-true}
      - LDAP_SERVER=${LDAP_SERVER}
      - LDAP_BASE_DN=${LDAP_BASE_DN}
      - LDAP_BIND_DN=${LDAP_BIND_DN}
      - LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD}
      - LDAP_UID_ATTRIBUTE=uid
      - LDAP_EMAIL_ATTRIBUTE=mail
    volumes:
      - rsa_keys:/srv/pySysPass/data:ro
      - ./backups:/srv/pySysPass/backups:ro
      - ./logs:/srv/pySysPass/logs
    depends_on:
      database:
        condition: service_healthy
    networks:
      - syspass
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./certbot/conf:/etc/letsencrypt:ro
    depends_on:
      - app
    networks:
      - syspass
    restart: unless-stopped

  certbot:
    image: certbot/certbot
    volumes:
      - ./certbot/conf:/etc/letsencrypt:ro
      - ./certbot/www:/var/www/certbot:ro
    entrypoint: /bin/sh -c "rm -f /shm/acme.sh; certbot --config /etc/letsencrypt/cli.ini cert --agree-tos --email ${CERT_EMAIL} --webroot -w /var/www/certbot/www --manual"
    networks:
      - syspass

volumes:
  mysql_data:
  rsa_keys:

networks:
  syspass:
    driver: bridge
```

### Environment Variables

|| Variable | Required | Description |
|----------|----------|-------------|
| `DB_PASSWORD` | ✅ | Database password |
| `MYSQL_ROOT_PASSWORD` | ✅ | MySQL root password |
| `SECRET_KEY` | ✅ | JWT signing key (32+ random bytes) |
| `ENCRYPTION_KEY` | ✅ | Encryption key (32+ random bytes) |
| `SERVICE_VAULT_KEY` | ✅ | Service vault root key |
| `BACKUP_KEY` | ✅ | Backup encryption key |
| `LDAP_ENABLED` | ❌ | Enable LDAP authentication (default: true) |
| `LDAP_SERVER` | If LDAP | LDAP server URL |
| `LDAP_BASE_DN` | If LDAP | LDAP base DN |
| `LDAP_BIND_DN` | If LDAP | LDAP bind DN |
| `LDAP_BIND_PASSWORD` | If LDAP | LDAP bind password |
| `CERT_EMAIL` | ✅ | Email for Let's Encrypt |

**PYSYSPASS_ prefix mapping** (per ADR-0017 V-01):
- The `.env.external.example` uses `PYSYSPASS_` prefix for environment variables
- pydantic `Settings` uses bare names (e.g., `SECRET_KEY`, not `PYSYSPASS_SECRET_KEY`)
- Docker Compose maps `${PYSYSPASS_...}` → bare names inside the container
- For local `.env` development, use bare names directly (no `PYSYSPASS_` prefix)

### Starting the Application

```bash
# Create secrets directory
mkdir -p /srv/pySysPass/secrets

# Generate secrets
openssl rand -base64 32 > /srv/pySysPass/secrets/SECRET_KEY
openssl rand -base64 32 > /srv/pySysPass/secrets/ENCRYPTION_KEY
openssl rand -base64 32 > /srv/pySysPass/secrets/SERVICE_VAULT_KEY
openssl rand -base64 32 > /srv/pySysPass/secrets/BACKUP_KEY

# Copy secrets to compose file
cat /srv/pySysPass/secrets/SECRET_KEY | xargs -I{} echo "SECRET_KEY={}" >> .env
cat /srv/pySysPass/secrets/ENCRYPTION_KEY | xargs -I{} echo "ENCRYPTION_KEY={}" >> .env
cat /srv/pySysPass/secrets/SERVICE_VAULT_KEY | xargs -I{} echo "SERVICE_VAULT_KEY={}" >> .env
cat /srv/pySysPass/secrets/BACKUP_KEY | xargs -I{} echo "BACKUP_KEY={}" >> .env

# Start services
docker-compose up -d
```

### Verification

```bash
# Check services are running
docker-compose ps

# Check application health
curl http://localhost:8000/health

# Check database connectivity
docker-compose exec database mysql -u syspass -p -e "SHOW DATABASES;"
```

---

## Standalone Container Deployment

**Status:** ✅ Supported for simple deployments

### Run Single Container

```bash
docker run -d \
  --name pySysPass \
  --network host \
  -e DATABASE_URL=mysql://syspass:${DB_PASSWORD}@localhost:3306/syspass \
  -e SECRET_KEY=${SECRET_KEY} \
  -e ENCRYPTION_KEY=${ENCRYPTION_KEY} \
  -e SERVICE_VAULT_KEY=${SERVICE_VAULT_KEY} \
  -e BACKUP_KEY=${BACKUP_KEY} \
  -v /srv/pySysPass/data:/srv/pySysPass/data \
  -v /srv/pySysPass/backups:/srv/pySysPass/backups \
  -v /srv/pySysPass/logs:/srv/pySysPass/logs \
  pySysPass:latest
```

### Verification

```bash
# Check container is running
docker ps

# Check application health
curl http://localhost:8000/health
```

---

## Kubernetes Deployment

**Status:** ⚠️ Requires investigation before deployment

### Prerequisites

- Kubernetes 1.20+
- Persistent storage (PV/PVC)
- Secret management (secrets or external)

### Configuration

#### 1. Create `kustomize` directory structure

```
kustomize/
  base/
    kustomization.yaml
    deployment.yaml
    service.yaml
    configmap.yaml
    secret.yaml
  overlays/
    production/
      kustomization.yaml
```

#### 2. Create deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pySysPass
  labels:
    app: pySysPass
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pySysPass
  template:
    metadata:
      labels:
        app: pySysPass
    spec:
      containers:
      - name: pySysPass
        image: pySysPass:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: database-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: SECRET_KEY
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: ENCRYPTION_KEY
        - name: SERVICE_VAULT_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: SERVICE_VAULT_KEY
        - name: BACKUP_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: BACKUP_KEY
        - name: LDAP_ENABLED
          value: "true"
        - name: LDAP_SERVER
          valueFrom:
            secretKeyRef:
              name: ldap-secrets
              key: server
        - name: LDAP_BASE_DN
          valueFrom:
            secretKeyRef:
              name: ldap-secrets
              key: base-dn
        - name: LDAP_BIND_DN
          valueFrom:
            secretKeyRef:
              name: ldap-secrets
              key: bind-dn
        - name: LDAP_BIND_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ldap-secrets
              key: bind-password
        volumeMounts:
        - name: data
          mountPath: /srv/pySysPass/data
          readOnly: true
        - name: backups
          mountPath: /srv/pySysPass/backups
          readOnly: true
        - name: logs
          mountPath: /srv/pySysPass/logs
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: pySysPass-data
      - name: backups
        persistentVolumeClaim:
          claimName: pySysPass-backups
      - name: logs
        emptyDir: {}
```

#### 3. Create secret.yaml

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pySysPass-secrets
type: Opaque
stringData:
  database-url: mysql://syspass:${DB_PASSWORD}@database:3306/syspass
  SECRET_KEY: $(openssl rand -base64 32)
  ENCRYPTION_KEY: $(openssl rand -base64 32)
  SERVICE_VAULT_KEY: $(openssl rand -base64 32)
  BACKUP_KEY: $(openssl rand -base64 32)
```

#### 4. Create service.yaml

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pySysPass
spec:
  selector:
    app: pySysPass
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

### Deployment

```bash
# Create secrets
kubectl create secret generic pySysPass-secrets \
  --from-literal=SECRET_KEY=$(openssl rand -base64 32) \
  --from-literal=ENCRYPTION_KEY=$(openssl rand -base64 32) \
  --from-literal=SERVICE_VAULT_KEY=$(openssl rand -base64 32) \
  --from-literal=BACKUP_KEY=$(openssl rand -base64 32)

# Create database secret
kubectl create secret generic ldap-secrets \
  --from-literal=server=${LDAP_SERVER} \
  --from-literal=base-dn=${LDAP_BASE_DN} \
  --from-literal=bind-dn=${LDAP_BIND_DN} \
  --from-literal=bind-password=${LDAP_BIND_PASSWORD}

# Deploy
kubectl apply -f kustomize/base/
```

### Verification

```bash
# Check deployment is running
kubectl get deployments pySysPass

# Check pods are ready
kubectl get pods -l app=pySysPass

# Check application health
kubectl exec -it <pod-name> -- curl http://localhost:8000/health
```

---

## OpenShift Deployment

**Status:** ⚠️ Requires investigation before deployment

### Prerequisites

- OpenShift 4.6+
- Persistent storage (PVC)
- Secret management (OpenShift secrets)

### Configuration

#### 1. Create buildconfig

```yaml
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: pySysPass
spec:
  outputTo:
    pvc:
      name: pySysPass-source
  source:
    type: Git
    git:
      uri: https://github.com/example/syspass.git
      revision: main
  strategy:
    type: Source
  triggers:
  - type: ImageChange
  - type: ConfigChange
```

#### 2. Create deploymentconfig

```yaml
apiVersion: apps.openshift.io/v1
kind: DeploymentConfig
metadata:
  name: pySysPass
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pySysPass
  template:
    metadata:
      labels:
        app: pySysPass
    spec:
      containers:
      - name: pySysPass
        image: pySysPass:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: database-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: SECRET_KEY
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: ENCRYPTION_KEY
        - name: SERVICE_VAULT_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: SERVICE_VAULT_KEY
        - name: BACKUP_KEY
          valueFrom:
            secretKeyRef:
              name: pySysPass-secrets
              key: BACKUP_KEY
        volumeMounts:
        - name: data
          mountPath: /srv/pySysPass/data
          readOnly: true
        - name: backups
          mountPath: /srv/pySysPass/backups
          readOnly: true
        - name: logs
          mountPath: /srv/pySysPass/logs
          readOnly: true
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: pySysPass-data
      - name: backups
        persistentVolumeClaim:
          claimName: pySysPass-backups
      - name: logs
        emptyDir: {}
```

### Deployment

```bash
# Create secrets
oc create secret generic pySysPass-secrets \
  --from-literal=SECRET_KEY=$(openssl rand -base64 32) \
  --from-literal=ENCRYPTION_KEY=$(openssl rand -base64 32) \
  --from-literal=SERVICE_VAULT_KEY=$(openssl rand -base64 32) \
  --from-literal=BACKUP_KEY=$(openssl rand -base64 32)

# Create PVCs
oc apply -f pvc-data.yaml
oc apply -f pvc-backups.yaml

# Deploy
oc apply -f deploymentconfig.yaml
```

---

## Reverse Proxy Configuration

**Status:** ✅ Recommended for production

### Nginx Configuration

#### 1. Create `nginx.conf`

```nginx
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml application/json;

    # Upstream
    upstream app {
        server app:8000;
        keepalive 32;
    }

    server {
        listen 80;
        server_name syspass.example.com;

        # SSL
        ssl_certificate /etc/letsencrypt/live/syspass.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/syspass.example.com/privkey.pem;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'; img-data: data:'svg'" always;

        # Root
        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
        }

        # Health check
        location /health {
            proxy_pass http://app/health;
            access_log off;
        }
    }
}
```

### HAProxy Configuration

```haproxy
frontend https_front
    bind *:443 ssl crt /etc/ssl/private/letsencrypt.pem
    mode http
    default_backend app

    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"

    # Rate limiting
    acl is_bot hdr(Host) -i .bot
    acl is_bot hdr(User-Agent) -i bot
    acl is_bot hdr(Referer) -i bot
    http-request deny if is_bot

backend app
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server app1 app:8000 check
    server app2 app:8000 check
```

---

## TLS Termination

**Status:** ✅ Recommended for production

### Let's Encrypt (Docker Compose)

```yaml
certbot:
  image: certbot/certbot
  volumes:
    - ./certbot/conf:/etc/letsencrypt:ro
    - ./certbot/www:/var/www/certbot:ro
  entrypoint: /bin/sh -c "rm -f /shm/acme.sh; certbot --config /etc/letsencrypt/cli.ini cert --agree-tos --email ${CERT_EMAIL} --webroot -w /var/www/certbot/www --manual"
```

### Let's Encrypt (Kubernetes)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ${CERT_EMAIL}
    privateKeySecretRef:
      name: letsencrypt-tls
    solvers:
    - http01:
        ingress:
          class: nginx
```

### Application-Side TLS (Not Recommended)

**WARNING:** Do not generate RSA keys in containers. Use mounted secrets instead:

```yaml
app:
  volumes:
    - ./data/rsa_private.pem:/srv/pySysPass/data/rsa_private.pem:ro
```

---

## Persistent Storage

**Status:** ✅ Required for production

### Docker Compose

```yaml
volumes:
  mysql_data:
    driver: local
  rsa_keys:
    driver: local
```

### Kubernetes

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pySysPass-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pySysPass-backups
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

### OpenShift

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pySysPass-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

---

## Database Connectivity

**Status:** ✅ Required for all deployments

### MySQL Configuration

```yaml
database:
  image: mysql:8.0
  environment:
    MYSQL_DATABASE: syspass
    MYSQL_USER: syspass
    MYSQL_PASSWORD: ${DB_PASSWORD}
    MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
  volumes:
    - mysql_data:/var/lib/mysql
    - ./init-db:/docker-entrypoint-initdb.d
  command:
    - --default-authentication-plugin=mysql_native_password
    - --sql-mode=STRICT_TRANS_TABLES
  healthcheck:
    test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
    interval: 10s
    timeout: 5s
    retries: 5
```

### Connection String

```
mysql://syspass:${DB_PASSWORD}@database:3306/syspass
```

### Connection Pooling (Recommended)

```python
DATABASE_URL = "mysql+pymysql://syspass:${DB_PASSWORD}@database:3306/syspass?pool_size=20&max_overflow=20&pool_recycle=3600"
```

---

## Mounted Secrets

**Status:** ✅ Required for production

### Docker Compose

```yaml
app:
  environment:
    - SECRET_KEY=$(cat /etc/secrets/SECRET_KEY)
    - ENCRYPTION_KEY=$(cat /etc/secrets/ENCRYPTION_KEY)
    - SERVICE_VAULT_KEY=$(cat /etc/secrets/SERVICE_VAULT_KEY)
    - BACKUP_KEY=$(cat /etc/secrets/BACKUP_KEY)
  volumes:
    - /etc/secrets:/etc/secrets:ro
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pySysPass-secrets
type: Opaque
stringData:
  SECRET_KEY: $(cat /etc/secrets/SECRET_KEY)
  ENCRYPTION_KEY: $(cat /etc/secrets/ENCRYPTION_KEY)
  SERVICE_VAULT_KEY: $(cat /etc/secrets/SERVICE_VAULT_KEY)
  BACKUP_KEY: $(cat /etc/secrets/BACKUP_KEY)
```

### File Permissions

```bash
chmod 600 /etc/secrets/SECRET_KEY
chmod 600 /etc/secrets/ENCRYPTION_KEY
chmod 600 /etc/secrets/SERVICE_VAULT_KEY
chmod 600 /etc/secrets/BACKUP_KEY
```

---

## Backup Storage

**Status:** ✅ Required for production

### Docker Compose

```yaml
app:
  volumes:
    - ./backups:/srv/pySysPass/backups:ro
```

### Kubernetes

```yaml
app:
  volumeMounts:
    - name: backups
      mountPath: /srv/pySysPass/backups
      readOnly: true
  volumes:
    - name: backups
      persistentVolumeClaim:
        claimName: pySysPass-backups
```

### Backup Directory Structure

```
backups/
  database.sql.enc          # Encrypted database backup
  manifest.json             # Backup metadata
  data.tar.gz.enc           # Encrypted runtime files
  backup-key                 # Backup encryption key
```

---

## LDAP Integration

**Status:** ✅ Supported with fail-closed policy

### Docker Compose

```yaml
app:
  environment:
    - LDAP_ENABLED=true
    - LDAP_SERVER=ldap://ad-server.example.com
    - LDAP_BASE_DN=dc=example,dc=com
    - LDAP_BIND_DN=cn=admin,dc=example,dc=com
    - LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD}
    - LDAP_UID_ATTRIBUTE=uid
    - LDAP_EMAIL_ATTRIBUTE=mail
```

### Kubernetes

```yaml
app:
  env:
    - name: LDAP_ENABLED
      value: "true"
    - name: LDAP_SERVER
      valueFrom:
        secretKeyRef:
          name: ldap-secrets
          key: server
    - name: LDAP_BASE_DN
      valueFrom:
        secretKeyRef:
          name: ldap-secrets
          key: base-dn
    - name: LDAP_BIND_DN
      valueFrom:
        secretKeyRef:
          name: ldap-secrets
          key: bind-dn
    - name: LDAP_BIND_PASSWORD
      valueFrom:
        secretKeyRef:
          name: ldap-secrets
          key: bind-password
```

### OpenShift

```yaml
env:
- name: LDAP_ENABLED
  value: "true"
- name: LDAP_SERVER
  valueFrom:
    secretKeyRef:
      name: ldap-secrets
      key: server
```

---

## Application Health Checks

**Status:** ✅ Implemented

### Docker Compose

```yaml
app:
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
    interval: 30s
    timeout: 10s
    retries: 3
```

### Kubernetes

```yaml
app:
  livenessProbe:
    httpGet:
      path: /health
      port: 8000
    initialDelaySeconds: 30
    periodSeconds: 10
  readinessProbe:
    httpGet:
      path: /health
      port: 8000
    initialDelaySeconds: 5
    periodSeconds: 5
```

### OpenShift

```yaml
env:
  - name: HEALTHCHECK_ENDPOINT
    value: /health
```

---

## Session Storage

**Status:** ✅ File-based (sessions.json)

### Current Implementation

Sessions are stored in file-based storage:

```yaml
app:
  volumes:
    - ./data:/srv/pySysPass/data
```

### Production Recommendation

For high-availability deployments, consider:

- Redis session store
- Database-backed sessions
- External session store

**[NOT YET IMPLEMENTED]**

---

## Multiple Workers and Replicas

**Status:** ✅ Supported

### Docker Compose (Single Worker)

```yaml
app:
  replicas: 1
```

### Kubernetes (Multiple Workers)

```yaml
spec:
  replicas: 2
```

### OpenShift (Multiple Workers)

```yaml
spec:
  replicas: 2
```

### Session Storage Considerations

For multiple workers, ensure session storage is:

- Shared (Redis, database)
- Or stateless with JWT-only

---

## Logging and SIEM Integration

**Status:** ⚠️ Requires implementation

### Docker Compose

```yaml
app:
  volumes:
    - ./logs:/srv/pySysPass/logs
```

### Kubernetes

```yaml
app:
  volumeMounts:
    - name: logs
      mountPath: /srv/pySysPass/logs
      readOnly: true
  volumes:
    - name: logs
      emptyDir: {}
```

### SIEM Integration (Proposed)

**[NOT YET IMPLEMENTED]**

Log aggregation:

- Fluentd/Fluent-bit
- Filebeat
- Logstash

---

## Upgrade and Rollback Procedures

### Docker Compose

```bash
# Upgrade
docker-compose pull
docker-compose up -d

# Rollback to previous version
docker-compose pull pySysPass:v1.0.0
docker-compose up -d --build
```

### Kubernetes

```bash
# Upgrade
kubectl set image deployment/pySysPass pySysPass=pySysPass:v1.0.1

# Rollback
kubectl rollout undo deployment/pySysPass

# View rollout history
kubectl rollout history deployment/pySysPass
```

### OpenShift

```bash
# Upgrade
oc start-build pySysPass --tag=v1.0.1

# Rollback
oc rollout undo deployment/pySysPass

# View rollout history
oc rollout history deployment/pySysPass
```

### Database Migration

```bash
# Run migrations
python -m app.db.migrate

# Verify migrations
python -m app.db.migration_status
```

---

## Security Considerations

### 1. Secret Management

- **DO:** Use mounted secrets with restrictive permissions (0400)
- **DO:** Store secrets in secure location (not in Docker image)
- **DO:** Use Kubernetes secrets or external secret managers
- **DON'T:** Store secrets in environment variables (process inspection risk)
- **DON'T:** Use plaintext secrets in Dockerfiles

### 2. Network Security

- **DO:** Use TLS for all communications
- **DO:** Use network policies to restrict access
- **DO:** Use internal networks for database
- **DON'T:** Expose database port to internet

### 3. Container Security

- **DO:** Use minimal base images (Alpine, distroless)
- **DO:** Run as non-root user
- **DO:** Use read-only filesystem where possible
- **DON'T:** Run with privileged mode

### 4. Authentication

- **DO:** Require MFA for all users
- **DO:** Use short-lived JWTs (15min)
- **DO:** Use server-side sessions (12hr)
- **DON'T:** Allow long-lived tokens

---

## Troubleshooting

### Common Issues

1. **Application won't start:**
   ```bash
   # Check logs
   docker-compose logs app
   
   # Check database connectivity
   docker-compose exec app mysql -u syspass -p -e "SHOW DATABASES;"
   ```

2. **Users cannot authenticate:**
   ```bash
   # Check database
   docker-compose exec database mysql -u syspass -p -e "SELECT * FROM User LIMIT 5;"
   ```

3. **Backup failures:**
   ```bash
   # Check backup key
   cat /srv/pySysPass/backups/backup-key
   ```

4. **LDAP authentication failures:**
   ```bash
   # Test LDAP connectivity
   ldapsearch -x -H ldap://ad-server -b dc=example,dc=com -s sub "(objectClass=*)"
   ```

---

## Related Documentation

- `docs/adr/0013-backup-disaster-recovery-and-cryptographic-recoverability.md`
- `docs/adr/0014-emergency-authentication-mode.md`
- `docs/security/policy.md`
- `docs/GLOSSARY.md`
