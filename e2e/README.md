# Browser acceptance tests

Playwright tests that drive the real UI through nginx against a disposable
stack: sign-in, account creation, password reveal through the clipboard,
sign-out with server-side token revocation, failed sign-in, protected-route
redirects, and response security headers. `settings-and-2fa.spec.js` turns on
"Show password as image" in Settings and checks that the account page shows an
image while copy still yields the text, then switches 2FA on in Settings,
enrolls through the profile page with a computed TOTP, and signs in with a
wrong and then a valid code. Each test restores the settings it changed. Tests
run in one worker because they share the admin user.

```bash
docker build -t pysyspass-backend:e2e . && docker build -t pysyspass-frontend:e2e frontend
scripts/e2e-stack.sh up          # MySQL 8 + backend + nginx on 127.0.0.1:18300
cd e2e && npm ci && npx playwright install chromium && npx playwright test
scripts/e2e-stack.sh down
```

The global setup installs the instance through the API with synthetic
credentials. Never point `E2E_BASE_URL` at a real installation.

## sysPass PHP web UI interoperability

`php-interop/` checks the other direction through the real PHP application:
the official sysPass 3.2.11 image is installed with its own installer, and
pySysPass joins the PHP-created database with the same password salt. The test
signs in to pySysPass as the PHP-created admin (unlocking a PHP-authored vault),
writes an account and a public link through the pySysPass API, then opens the
link and the account's "view password" dialog in the PHP web UI. A second test
imports a password-protected pySysPass XML export through PHP's Import screen.

```bash
docker build -t pysyspass-backend:e2e .
scripts/php-interop-stack.sh up   # PHP UI :18400, pySysPass API :18401
cd e2e && npx playwright test -c playwright.php-interop.config.js
scripts/php-interop-stack.sh down
```

The 2FA test also needs the sysPass Authenticator plugin (not in the official
image). Start the stack with `AUTHENTICATOR_DIR=/path/to/plugin-Authenticator`
(commit `b304661`) and run the suite with `INTEROP_2FA=1`. The script copies the
plugin in and, for that disposable container only, registers it with Composer's
autoloader as a real plugin install would. pySysPass enrolls the PHP admin;
PHP's plugin must reject a wrong code and accept a current TOTP and a pySysPass
recovery code.
