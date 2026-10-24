# Browser acceptance tests

Playwright tests that drive the real UI through nginx against a disposable
stack: sign-in, account creation, password reveal through the clipboard,
sign-out with server-side token revocation, failed sign-in, protected-route
redirects, and response security headers.

```bash
docker build -t pysyspass-backend:e2e . && docker build -t pysyspass-frontend:e2e frontend
scripts/e2e-stack.sh up          # MySQL 8 + backend + nginx on 127.0.0.1:18300
cd e2e && npm ci && npx playwright install chromium && npx playwright test
scripts/e2e-stack.sh down
```

The global setup installs the instance through the API with synthetic
credentials. Never point `E2E_BASE_URL` at a real installation.
