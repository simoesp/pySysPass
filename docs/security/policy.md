# Security Policy

## Supported Versions

This document applies to the **Python rewrite** of sysPass.

| Component | Version |
|-----------|---------|
| Python backend (FastAPI) | current development branch |
| Vue 3 frontend (Quasar) | current development branch |

For the original PHP sysPass, see the upstream repository.

---

## Security Model

### Transport Security

Passwords are encrypted **in the browser** before being sent to the server, even when the connection is plain HTTP:

1. On page load, the browser fetches the server's **RSA-2048 public key** from `GET /api/v1/security/public-key`.
2. When the user submits a password (login or account create/edit), the browser encrypts it using **RSA-OAEP-SHA-256** via the native Web Crypto API (`window.crypto.subtle`) — no third-party JavaScript library is involved.
3. The ciphertext is sent as `RSA:<base64>` in the normal password field.
4. The server detects the prefix, decrypts with the RSA-2048 private key, then proceeds with normal processing.

This means a passive attacker observing HTTP traffic cannot recover any plaintext password.

### Password Storage

Account passwords are encrypted with **AES-256-CTR**:

- A fresh 16-byte salt and 16-byte IV are generated per encryption operation.
- The encryption key is derived from the master `ENCRYPTION_KEY` using **PBKDF2-HMAC-SHA-256** (100,000 iterations).
- The stored value is `base64(salt ‖ IV ‖ ciphertext)` in a `varbinary` column.

User login passwords are hashed with **bcrypt**.

### Authentication

- API access requires a **JWT** (HS256, signed with `SECRET_KEY`), valid for 24 hours.
- Optionally protected by **TOTP two-factor authentication**.
- Account access is primarily user-scoped, with additional sharing and assignment mechanisms available through dedicated account-sharing and access-management routes.

### RSA Key Management

- The RSA-2048 key pair is generated on first run and stored in `data/rsa_private.pem`.
- The private key file is not protected by a passphrase. Restrict filesystem permissions (`chmod 600`) and ensure the `data/` directory is not web-accessible.
- In containerised deployments, mount `data/` as a persistent volume to survive container recreation.

### Recommendations for Production Deployments

1. **Always use HTTPS** — even though passwords are RSA-encrypted in transit, tokens and other request metadata are not.
2. **Set strong secrets** — change `SECRET_KEY` and `ENCRYPTION_KEY` in `.env` before deploying. Both should be at least 32 bytes of random data.
3. **Restrict `data/rsa_private.pem`** — the private key must not be world-readable (`chmod 600 data/rsa_private.pem`).
4. **Back up `ENCRYPTION_KEY` and `data/rsa_private.pem`** — losing either means losing access to stored passwords. Store both securely and separately from the database backup.
5. **Rotate secrets** — rotating `ENCRYPTION_KEY` requires re-encrypting all stored passwords. There is currently no automated rotation tool; plan accordingly.

---

## Reporting a Vulnerability

To report a vulnerability in this Python implementation, open a **private security advisory** on the GitHub repository, or email the maintainer directly.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions / components

Vulnerabilities will be acknowledged within 72 hours and patched as quickly as possible. Please allow time for a fix before public disclosure.
