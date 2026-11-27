# ADR-0009 — Session Architecture, API Token Lifecycle and Server-Side Vault Context

## Status

**Status:** Active

## Context

Current pySysPass implementation uses stateless JWTs with master password material embedded in claims. This creates security risks around token compromise and long-lived credential access. This ADR establishes a hybrid session model with short-lived JWTs, server-side session state, and independently managed vault contexts.

## Decision

### 1. Session Architecture Model

**Hybrid JWT + Server-Side Session:**
- JWTs contain only identity and session identifier (no cryptographic material)
- Server-side session state stores authorization and cryptographic context
- Every request validates JWT AND checks server-side session validity

**JWT Claims (Minimal):**
```json
{
  "sub": <user_id>,
  "sid": <session_id>,
  "jti": <token_id>,
  "iat": <timestamp>,
  "exp": <timestamp>,
  "azp": <authentication_assurance_level>
}
```

**Removed from JWT:**
- ❌ Master password material (encrypted or plaintext)
- ❌ Credential encryption keys
- ❌ Persistent vault secrets
- ❌ Authoritative permissions

**Authorization Flow:**
```
1. Client presents JWT
2. Server validates signature and expiration
3. Server checks server-side session validity
4. Server evaluates current authorization state
5. Server establishes vault context (if needed)
6. Authorization uses current permission data
```

### 2. Separate Security Lifecycles

**Six Independent Lifecycles:**
1. **Access Token**: JWT for authentication (15 min default)
2. **Refresh Token**: For obtaining new access tokens (optional, server-side stored)
3. **Authenticated Session**: User's login session (12 hours default)
4. **Vault Context**: Decrypted cryptographic material (4 hours default)
5. **MFA Assurance**: 2FA verification status (5 min sensitive operations)
6. **API Token**: Programmatic credentials (90 days default)

**Independence Rules:**
- Authenticated session ≠ unlocked vault
- Refreshed access token ≠ extended vault unlock
- Logout invalidates session but not necessarily all vault contexts
- Password change revokes session but preserves API tokens

### 3. Default Lifetimes (Configurable)

| Resource | Default Lifetime | Inactivity Timeout | Max Lifetime |
|----------|-----------------|-------------------|--------------|
| JWT access token | 15 minutes | 30 minutes | 12 hours |
| Authenticated session | N/A | 30 minutes | 12 hours |
| Vault unlock context | N/A | 15 minutes | 4 hours |
| Sensitive operation window | N/A | 5 minutes | N/A |
| New API token | N/A | N/A | 90 days |
| Legacy API token | N/A | N/A | N/A |

**Configuration:**
- Stored in `runtime.json`
- Admin configurable via settings API
- Cannot exceed absolute lifetimes
- Activity does not extend absolute lifetime

### 4. Refresh Token Management (Optional)

**If Implemented:**
- Cryptographically random (64 bytes)
- Stored server-side as bcrypt hash
- Rotated on every use
- Reuse detection and invalidation
- Bound to specific session and identity
- Respects absolute session lifetime

**Security Properties:**
- HttpOnly, Secure, SameSite=Strict cookie
- Never exposed to JavaScript
- CSRF-protected
- Independent revocation

**Browser Integration:**
- Refresh tokens stored in secure cookie
- Access tokens in memory only
- CSRF token separate from refresh token
- Logout invalidates all tokens

### 5. Server-Side Session Storage

**Storage Backends (Multiple Supported):**

| Backend | Use Case | Concurrency | Atomicity | Notes |
|---------|----------|-------------|-----------|-------|
| In-memory | Development | Single process | No | Reset on restart |
| Database | Production | Full | Yes | MySQL/PostgreSQL |
| Redis | HA deployments | Full | Yes | Optional dependency |
| File-based | Single instance | Limited | Yes | Current implementation |

**Current File-Based Storage Issues:**
- ❌ No file locking (concurrent access unsafe)
- ❌ No atomic updates (partial writes possible)
- ❌ No crash recovery (corruption possible)
- ❌ No multi-worker support
- ❌ Permission protection required
- ⚠️ Container restarts lose state

**Recommended Migration:**
- Use existing MySQL database for session storage
- Add `Session` table with:
  - `id` (primary key)
  - `session_id` (unique, indexed)
  - `user_id` (foreign key)
  - `authenticated_until` (timestamp)
  - `vault_until` (timestamp)
  - `revoked` (boolean)
  - `revoked_until` (timestamp)
  - `ip_address` (indexed)
  - `user_agent` (text)
  - `created_at` (timestamp)
- Migrate from `sessions.json`

### 6. Server-Side Vault Context

**Vault Context Model:**
- Bound to specific user AND specific session
- Independently lockable and revocable
- Time-limited (4 hours default)
- Protected from unauthorized access
- Invalidated on session termination
- Invalidated on cryptographic material rotation

**Multi-Device Behavior:**
- Unlocking vault on Device A does NOT unlock vault on Device B
- Each authenticated session has independent vault context
- Browser cookie or session ID identifies vault context

**Decrypted Material Storage:**
- Prefer application memory for short lifetimes
- If persisted: AES-GCM encrypted with independent key
- Never plaintext in database, files, logs, or distributed caches

### 7. Session Revocation

**Revocation Triggers:**

| Trigger | Action | Scope |
|---------|--------|-------|
| User logout | Revoke session | Individual |
| Admin session termination | Revoke session | Individual |
| Account disabled | Revoke session | All sessions |
| Account deleted | Revoke session | All sessions |
| Password change | Revoke session | All sessions |
| MFA reset | Revoke session | All sessions |
| Provider revocation | Revoke session | All sessions |
| Master password rotation | Revoke vault contexts | All sessions |
| Signing key compromise | Revoke all tokens | All users |
| Refresh token reuse | Revoke all sessions | All users |
| Security incident | Revoke as needed | Configurable |

**Revocation Propagation:**
- Maximum delay: Time to propagate to all instances
- File-based: Immediate on same instance
- Database: Immediate on master replication
- Redis: Sub-second (configurable)
- JWT: Already expired (no propagation needed)

**Permission Changes:**
- Affect subsequent authorization decisions
- No need for user to wait for JWT expiration
- Server-side session stores current permissions

### 8. API Token Architecture

**Python-Native API Tokens (Recommended):**
```
┌─────────────────────────────────────────────────────────┐
│ Token Metadata (Python-native, not in shared schema)    │
├─────────────────────────────────────────────────────────┤
│ - owner_id (user_id)                                    │
│ - name (human-readable)                                  │
│ - created_at (timestamp)                                │
│ - expires_at (timestamp, optional)                      │
│ - scopes (read, write, delete, export, etc.)           │
│ - resource_restrictions (optional)                      │
│ - last_used_at (timestamp)                              │
│ - revoked (boolean)                                     │
│ - revoked_at (timestamp)                                │
└─────────────────────────────────────────────────────────┘
```

**Token Types:**
1. **Read-only**: Can view accounts, cannot modify
2. **Write**: Can create/edit/delete accounts
3. **Export**: Can export credentials (requires master_pass)
4. **Admin**: Can manage tokens and users (restricted)

**Security Properties:**
- Cryptographically random bearer secrets
- One-time display at creation
- Non-secret identifier for lookup
- Server-side hashing (not plaintext)
- Constant-time verification

**Legacy PHP Compatibility:**
- Legacy tokens remain plaintext in `AuthToken` table
- Continue to work within original contract
- Admin warnings during token creation
- Migration procedures documented

### 9. API Token Storage Strategy

**Two-Token Model:**

| Token Type | Storage | Expiration | Compatibility |
|------------|---------|------------|---------------|
| Legacy PHP token | `AuthToken.token` (plaintext) | N/A | PHP-compatible |
| Python-native token | `AuthTokenMetadata` table | Configurable | Python-only |

**Migration Strategy:**
1. Create `AuthTokenMetadata` table
2. Admin creates Python-native token
3. Legacy token remains functional
4. Admin can delete legacy tokens after verification
5. PHP rollback ignores Python-native metadata

**Security Properties:**
- Legacy tokens: 64-char hex, no expiration
- Python-native tokens: Hashed, configurable expiration
- No plaintext recovery (hash only)

### 10. Programmatic Cryptographic Access

**Service Account Model:**

**Option A: JWT-based Access**
- Service account authenticates with credentials
- Obtains short-lived JWT
- JWT contains no cryptographic material
- Server-side vault context required

**Option B: API Token with Master Password**
- API token provides identity
- Master password required for vault unlock
- Admin must supply master password securely
- Not recommended for automation

**Option C: Dedicated Service Tokens**
- Separate token type for automation
- No master password in token
- Server-side vault context with service identity
- Revocable like regular sessions

**Recommended: Option A + Option C**
- Service accounts authenticate normally
- Obtain JWT (no mpass)
- Server establishes vault context
- No master password exposure

### 11. Security Verification Scenarios

**Required Test Coverage:**

| Scenario | Description | Expected Behavior |
|----------|-------------|-------------------|
| Expired access token | JWT with expired `exp` | Rejected immediately |
| Revoked session | Valid JWT but revoked session | Rejected, session invalid |
| Stolen token replay | Attacker uses stolen JWT | Valid until expiry (revocable) |
| Refresh rotation | Refresh token used | Old refresh invalidated, new issued |
| Vault expiration | Session active but vault expired | Vault locked, requires re-auth |
| Multi-device vault | Unlock on Device A | Device B vault unaffected |
| Logout invalidation | User logs out | Session revoked, tokens rejected |
| User disabled | Account disabled | All sessions revoked |
| Permission change | Permissions modified | Subsequent requests use new state |
| Master rotation | MPass rotated | All vault contexts invalidated |
| Concurrent sessions | Multiple workers | All sessions tracked correctly |
| Container restart | Service restarts | Sessions preserved (DB-backed) |
| API token expiration | Token expires | Rejected after expiration |
| API token scope | Token with read scope | Write operations denied |
| Legacy token compatibility | PHP token used | Works within original contract |

**Failure Scenarios:**
- Session backend unavailable: Reject all requests (no fallback to JWT)
- Database corruption: Fail securely, log error
- File-based storage unavailable: Fail securely

### 12. Architectural Guarantees

**Security Properties:**
- ✅ No master password in JWT claims
- ✅ Short-lived access tokens (15 min default)
- ✅ Server-side session state (authoritative)
- ✅ Independent vault contexts (per session)
- ✅ Immediate revocation (no caching)
- ✅ Permission changes effective immediately
- ✅ API tokens with configurable expiration
- ✅ Legacy token compatibility maintained

**Tradeoffs:**
- ❌ Increased complexity vs stateless JWT
- ❌ Additional storage requirements
- ❌ Session backend maintenance
- ⚠️ Performance overhead (session lookup)

**Benefits:**
- ✅ Reduced token compromise impact
- ✅ Better revocation capabilities
- ✅ Independent vault contexts
- ✅ Configurable lifetimes
- ✅ Security policy enforcement
- ✅ Better audit trail

## Consequences

### Operational

- Sessions must be stored (DB or Redis)
- Admin must configure lifetimes
- Master password must be rotated periodically
- Service account automation requires careful design
- Legacy token inventory and migration required

### Development

- Session storage abstraction required
- JWT validation + session check flow
- Vault context lifecycle management
- API token creation with metadata
- Refresh token implementation (optional)

### Security

- Reduced impact of token theft
- Better revocation capabilities
- Clear separation of concerns
- Audit trail for session activity
- Configurable security policies

## References

- `docs/adr/0008-encryption-architecture-master-password-and-cryptographic-key-lifecycle.md`
- `docs/adr/0005-authorization-access-control-and-administrator-privilege-boundaries.md`
- `docs/adr/0007-effective-permissions-acl-precedence-and-conflict-resolution.md`
- `app/services/session_service.py`: Current session handling
- `app/services/auth_service.py`: JWT issuance
- `app/services/master_password_rotation.py`: Rotation logic
- `app/models/account.py`: AuthToken model

## Related Documents

- `docs/security/policy.md`: Security requirements
- `docs/backup-recovery.md`: Recovery procedures
- `docs/installation.md`: Environment setup
- `scripts/php-interop-stack.sh`: PHP interoperability tests
