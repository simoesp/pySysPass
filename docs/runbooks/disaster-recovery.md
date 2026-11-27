# Disaster Recovery Runbook

This runbook documents procedures for recovering pySysPass from various disaster scenarios.

**IMPORTANT:** These procedures document the TARGET architecture as described in ADRs. Procedures marked with `[NOT YET IMPLEMENTED]` depend on features that have been designed but not yet implemented.

---

## Disaster Scenario Catalog

| Scenario | Severity | Recovery Time | ADR Reference |
|----------|----------|---------------|---------------|
| Active Directory outage | Critical | 5-15 min | ADR-0014 |
| Independent local break-glass authentication | Critical | 2-5 min | ADR-0014 |
| Emergency offline authentication activation | Critical | 3-10 min | ADR-0014 |
| Application host loss | Critical | 5-15 min | ADR-0013 |
| Database server loss | Critical | 5-15 min | ADR-0013 |
| Complete infrastructure loss | Critical | 30-60 min | ADR-0013 |
| External secret manager outage | Medium | 2-5 min | ADR-0013 |
| Encrypted backup restoration | High | 5-15 min | ADR-0013 |
| Historical backup restoration after key rotation | High | 10-20 min | ADR-0013 |
| Master password recovery | High | 5-10 min | ADR-0013 |
| Application secret recovery | High | 2-5 min | ADR-0013 |
| Security state reconciliation | Medium | 2-5 min | ADR-0013 |
| Emergency mode termination | Medium | 1-2 min | ADR-0014 |
| PHP rollback | Medium | 5-10 min | ADR-0001 |

---

## Scenario 1: Active Directory Outage

**Description:** Active Directory is unavailable (network failure, server outage, etc.) but pySysPass application is otherwise operational.

**Prerequisites:**
- Break-glass administrator credentials (stored independently)
- Server console/SSH access
- Emergency authentication mode not yet activated (normal scenario)

**Required Permissions:**
- Server administrator access
- Break-glass administrator credentials (independent storage)

**Required Recovery Material:**
- Break-glass administrator credentials
- Server access credentials

**Operational Steps:**

1. **Assess the situation:**
   ```bash
   # Check AD connectivity
   ldapsearch -x -H ldap://ad-server -b dc=example,dc=com -s sub "(objectClass=*)"
   ```

2. **Determine if emergency mode is needed:**
   - If break-glass administrators need to authenticate: activate emergency mode
   - If only LDAP-bound users need access: wait for AD recovery

3. **If break-glass access is required, activate emergency mode:**
   ```bash
   sudo /srv/pySysPass/scripts/activate-emergency-auth.sh
   ```
   - Enter operator authorization code
   - Enter break-glass administrator password
   - Script verifies password against local hash
   - Creates `/var/run/syspass/emergency-auth-active`
   - Logs to `/var/log/syspass/emergency-auth.log`
   - Sets timeout (default 2 hours)

4. **Break-glass administrator can authenticate:**
   ```
   https://syspass.example.com/login
   - Username: break-glass-1 (or other break-glass account)
   - Password: [break-glass password]
   - MFA code: [TOTP code from break-glass MFA device]
   ```

5. **Recover AD if needed:**
   - Use break-glass credentials to access AD recovery tools
   - Restore AD connectivity
   - Deactivate emergency mode when normal operation resumes

6. **Verify recovery:**
   ```bash
   # Check AD connectivity restored
   ldapsearch -x -H ldap://ad-server -b dc=example,dc=com -s sub "(objectClass=*)"
   ```

**Verification Requirements:**
- Break-glass administrator can authenticate
- Emergency mode active (check `/var/run/syspass/emergency-auth-active`)
- AD connectivity restored
- Emergency mode deactivated when no longer needed

**Expected Outcomes:**
- Break-glass administrators can authenticate during AD outage
- LDAP-bound users cannot authenticate until AD is restored
- Emergency mode automatically expires after 2 hours

**Failure Handling:**
- **Activation script fails:** Check server access, verify break-glass credentials
- **Password verification fails:** Verify break-glass credentials are correct
- **MFA verification fails:** Verify MFA device is functional
- **Emergency mode not activating:** Check logs at `/var/log/syspass/emergency-auth.log`

**Rollback Procedures:**
- Emergency mode deactivates automatically after timeout
- Manual deactivation:
  ```bash
  sudo /srv/pySysPass/scripts/deactivate-emergency-auth.sh
  ```

**Audit Requirements:**
- All emergency mode activations logged as CRITICAL
- All break-glass authentications logged as CRITICAL
- Audit log review required within 24 hours

---

## Scenario 2: Independent Local Break-Glass Authentication

**Description:** Break-glass administrator needs to authenticate without LDAP (AD unavailable) but emergency mode has NOT been activated.

**Prerequisites:**
- Break-glass administrator credentials (stored independently)
- Emergency mode MUST be activated first (see Scenario 1)

**Required Permissions:**
- Server administrator access
- Break-glass administrator credentials
- Emergency mode authorization

**Required Recovery Material:**
- Break-glass administrator credentials
- Emergency mode activation script
- MFA device for break-glass administrator

**Operational Steps:**

1. **Activate emergency mode (see Scenario 1, Step 3)**

2. **Break-glass administrator authenticates:**
   ```
   https://syspass.example.com/login
   - Username: break-glass-1
   - Password: [break-glass password]
   - MFA code: [TOTP code]
   ```

3. **Verify authentication succeeded:**
   - User can access vault
   - Can create/edit accounts
   - Can access recovery credentials

**Verification Requirements:**
- Break-glass administrator can authenticate
- Emergency mode is active
- Break-glass administrator has vault access

**Expected Outcomes:**
- Break-glass administrator authenticated successfully
- Emergency mode active (2-hour window)
- Normal LDAP authentication still fails

**Failure Handling:**
- **Authentication fails:** Verify break-glass credentials, verify emergency mode is active
- **MFA fails:** Verify MFA device is functional
- **No vault access:** Check user permissions, verify account exists in `emergency_credentials` table

**Audit Requirements:**
- All break-glass authentications logged as CRITICAL
- Review audit log for unauthorized access attempts

---

## Scenario 3: Emergency Offline Authentication Activation

**Description:** Designated LDAP recovery personnel need to authenticate offline when emergency mode is active.

**Prerequisites:**
- Emergency mode activated (see Scenario 1 or 2)
- Recovery personnel have MFA device configured
- Recovery personnel credentials pre-enrolled in `emergency_credentials` table

**Required Permissions:**
- Emergency mode activation authorization
- Recovery personnel credentials

**Required Recovery Material:**
- Emergency mode activation credentials
- Recovery personnel MFA device
- Recovery personnel credentials

**Operational Steps:**

1. **Verify emergency mode is active:**
   ```bash
   ls -la /var/run/syspass/emergency-auth-active
   ```

2. **Recovery personnel authenticate:**
   ```
   https://syspass.example.com/login
   - Username: recovery-personnel-1
   - Password: [recovery password]
   - MFA code: [TOTP code from MFA device]
   ```

3. **If recovery personnel has recovery token:**
   ```
   - Recovery token field: [optional, for designated recovery personnel]
   ```

4. **Verify authentication succeeded:**
   - User can access vault
   - Can perform recovery operations

**Verification Requirements:**
- Recovery personnel can authenticate
- MFA verification succeeded
- Recovery token verified (if provided)

**Expected Outcomes:**
- Recovery personnel authenticated successfully
- Emergency mode active (2-hour window)
- Recovery personnel has appropriate access

**Failure Handling:**
- **Authentication fails:** Verify credentials, verify emergency mode is active
- **MFA fails:** Verify MFA device is functional
- **Recovery token fails:** Verify token is valid, check expiration
- **No vault access:** Check user permissions

**Audit Requirements:**
- All recovery personnel authentications logged as CRITICAL
- All recovery token uses logged as CRITICAL

---

## Scenario 4: Application Host Loss

**Description:** The entire application host is unavailable (hardware failure, fire, etc.).

**Prerequisites:**
- Database backup (encrypted)
- Backup encryption key (stored independently)
- Runtime files backup (encrypted)
- Backup encryption key (stored independently)
- Recovery instructions (stored separately)

**Required Permissions:**
- Database server access
- Backup storage access
- Recovery key access

**Required Recovery Material:**
- Database backup file
- Backup encryption key
- Runtime files backup
- Recovery key (independent storage)
- Recovery instructions

**Operational Steps:**

1. **Provision new server:**
   ```bash
   # Install OS and dependencies
   apt update && apt install -y python3 python3-venv mysql-server
   ```

2. **Clone application code:**
   ```bash
   git clone https://github.com/example/syspass.git
   cd syspass
   ```

3. **Set up virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Set up database:**
   ```bash
   mysql -u root -p
   CREATE DATABASE syspass;
   CREATE USER 'syspass'@'localhost' IDENTIFIED BY 'password';
   GRANT ALL PRIVILEGES ON syspass.* TO 'syspass'@'localhost';
   EXIT;
   ```

5. **Restore database from encrypted backup:**
   ```bash
   openssl enc -d -aes-256-cbc -salt -in backups/database.sql.enc \
     -out backups/database.sql \
     -pass file:/etc/syspass/backup-key
   mysql -u syspass -p syspass < backups/database.sql
   ```

6. **Restore runtime files:**
   ```bash
   tar -xzf backups/data.tar -C /srv/pySysPass/data
   ```

7. **Set restrictive permissions:**
   ```bash
   chmod 600 /srv/pySysPass/data/rsa_private.pem
   chmod 600 /etc/syspass/backup-key
   ```

8. **Start application:**
   ```bash
   systemctl start pySysPass
   ```

9. **Verify application is running:**
   ```bash
   curl https://syspass.example.com/health
   ```

**Verification Requirements:**
- Application responds to health check
- Users can authenticate
- Existing accounts accessible

**Expected Outcomes:**
- Application running on new server
- All data restored
- Users can authenticate

**Failure Handling:**
- **Database restore fails:** Verify backup integrity, verify key is correct
- **Runtime restore fails:** Verify files are complete
- **Application won't start:** Check logs, verify configuration
- **Users cannot authenticate:** Check database restore, verify encryption keys

**Rollback Procedures:**
- None required (fresh install)

**Audit Requirements:**
- Backup restore logged as CRITICAL
- Review audit logs after restore

---

## Scenario 5: Database Server Loss

**Description:** Only the database server is unavailable (not entire infrastructure).

**Prerequisites:**
- Database backup (encrypted)
- Backup encryption key
- Access to database server (for restore)

**Required Permissions:**
- Database server access
- Backup storage access

**Required Recovery Material:**
- Database backup file
- Backup encryption key
- Database connection information

**Operational Steps:**

1. **Stop application:**
   ```bash
   systemctl stop pySysPass
   ```

2. **Remove old database:**
   ```bash
   DROP DATABASE syspass;
   ```

3. **Restore database from encrypted backup:**
   ```bash
   openssl enc -d -aes-256-cbc -salt -in backups/database.sql.enc \
     -out backups/database.sql \
     -pass file:/etc/syspass/backup-key
   mysql -u syspass -p syspass < backups/database.sql
   ```

4. **Start application:**
   ```bash
   systemctl start pySysPass
   ```

5. **Verify application is running:**
   ```bash
   curl https://syspass.example.com/health
   ```

**Verification Requirements:**
- Application responds to health check
- Users can authenticate
- Existing accounts accessible

**Expected Outcomes:**
- Database restored
- Application running
- Users can authenticate

**Failure Handling:**
- **Database restore fails:** Verify backup integrity, verify key is correct
- **Application won't start:** Check logs, verify configuration
- **Users cannot authenticate:** Check database restore, verify encryption keys

**Rollback Procedures:**
- None required (fresh database restore)

**Audit Requirements:**
- Database restore logged as CRITICAL

---

## Scenario 6: Complete Infrastructure Loss

**Description:** All infrastructure is unavailable (disaster scenario).

**Prerequisites:**
- Backup encryption key (stored independently)
- Master password recovery material (stored independently)
- Emergency administrator credentials (stored independently)
- Recovery instructions (stored separately)
- Database backup (encrypted)
- Runtime files backup

**Required Permissions:**
- Backup storage access
- Key storage access
- Recovery instructions access

**Required Recovery Material:**
- All recovery material from independent storage
- Recovery instructions
- Backup files
- Keys

**Operational Steps:**

1. **Provision new infrastructure:**
   ```bash
   # Provision new servers for application and database
   # Set up network connectivity
   ```

2. **Restore all components (see Scenario 4 and 5)**

3. **Verify all services are running:**
   ```bash
   # Check application
   curl https://syspass.example.com/health
   
   # Check database
   mysql -u syspass -p -e "SHOW DATABASES;"
   ```

4. **Verify users can authenticate:**
   ```bash
   # Test with break-glass account (emergency mode may be active)
   curl -X POST https://syspass.example.com/login \
     -d "username=break-glass-1" \
     -d "password=[password]" \
     -d "otp=[MFA code]"
   ```

**Verification Requirements:**
- All services running
- Users can authenticate
- Existing accounts accessible

**Expected Outcomes:**
- Full system restored
- All data accessible
- Users authenticated

**Failure Handling:**
- **Services won't start:** Check configuration, verify dependencies
- **Users cannot authenticate:** Check database restore, verify keys
- **Partial data loss:** Check backup integrity

**Rollback Procedures:**
- None required (fresh infrastructure)

**Audit Requirements:**
- All restore operations logged as CRITICAL

---

## Scenario 7: External Secret Manager Outage

**Description:** External secret manager (e.g., HashiCorp Vault) is unavailable but application needs to start.

**Prerequisites:**
- Application can start without external secret manager (default)
- Local fallback for application secrets

**Required Permissions:**
- Application configuration access
- Backup storage access (if secrets are backed up there)

**Required Recovery Material:**
- Application secrets backed up locally (if configured)
- Alternative secret source

**Operational Steps:**

1. **Check if application can start:**
   ```bash
   # Application should start without external secret manager
   systemctl start pySysPass
   ```

2. **If secrets are needed:**
   ```bash
   # Use locally backed up secrets
   cat /etc/syspass/backup-key
   ```

3. **Restore secrets from backup:**
   ```bash
   # Restore from backup storage
   cp /backup/secrets/backup-key /etc/syspass/backup-key
   ```

**Verification Requirements:**
- Application is running
- Users can authenticate
- Existing accounts accessible

**Expected Outcomes:**
- Application running without external secret manager
- Users can authenticate

**Failure Handling:**
- **Application won't start:** Check logs, verify configuration
- **Users cannot authenticate:** Verify secrets are restored

**Rollback Procedures:**
- Restore secrets from backup
- Restart application

**Audit Requirements:**
- Secret restoration logged

---

## Scenario 8: Encrypted Backup Restoration

**Description:** Restoring from encrypted backup (standard procedure).

**Prerequisites:**
- Encrypted backup file
- Backup encryption key (stored independently)
- Backup decryption key

**Required Permissions:**
- Backup storage access
- Key storage access

**Required Recovery Material:**
- Encrypted backup file
- Backup encryption key
- Backup decryption key

**Operational Steps:**

1. **Verify backup integrity:**
   ```bash
   # Verify HMAC
   openssl dgst -sha256 -mac HMAC -macopt hexkey=[key] \
     -in backups/database.sql.enc
   ```

2. **Decrypt backup:**
   ```bash
   openssl enc -d -aes-256-cbc -salt -in backups/database.sql.enc \
     -out backups/database.sql \
     -pass file:/etc/syspass/backup-key
   ```

3. **Restore database:**
   ```bash
   mysql -u syspass -p syspass < backups/database.sql
   ```

4. **Restore runtime files (if included):**
   ```bash
   tar -xzf backups/data.tar -C /srv/pySysPass/data
   ```

5. **Verify restoration:**
   ```bash
   # Check user count
   mysql -u syspass -p -e "SELECT COUNT(*) FROM User;"
   ```

**Verification Requirements:**
- Database restored
- Runtime files restored
- Application running
- Users can authenticate

**Expected Outcomes:**
- Backup restored successfully
- All data accessible

**Failure Handling:**
- **Decryption fails:** Verify key is correct
- **Integrity check fails:** Backup may be corrupted
- **Restore fails:** Check database permissions, verify backup format

**Rollback Procedures:**
- None required (restore from backup)

**Audit Requirements:**
- Backup restoration logged as CRITICAL

---

## Scenario 9: Historical Backup Restoration After Key Rotation

**Description:** Restoring from old backup encrypted with previous backup encryption key.

**Prerequisites:**
- Historical backup file
- Old backup encryption key (retained for historical backups)
- New backup encryption key (for future backups)

**Required Permissions:**
- Backup storage access
- Key storage access

**Required Recovery Material:**
- Historical backup file
- Old backup encryption key
- New backup encryption key (for future use)

**Operational Steps:**

1. **Identify old backup encryption key:**
   ```bash
   # Check backup manifest for key ID
   cat backups/manifest.json
   ```

2. **Locate old backup encryption key:**
   ```bash
   # Keys retained for historical backup recovery
   cat /etc/syspass/backup-key-old
   ```

3. **Decrypt backup with old key:**
   ```bash
   openssl enc -d -aes-256-cbc -salt -in backups/database.sql.enc \
     -out backups/database.sql \
     -pass file:/etc/syspass/backup-key-old
   ```

4. **Restore database:**
   ```bash
   mysql -u syspass -p syspass < backups/database.sql
   ```

5. **Update backup encryption key (after restore):**
   ```bash
   # Generate new key
   openssl rand -base64 32 > /etc/syspass/backup-key-old
   
   # Keep old key for historical recovery
   ```

**Verification Requirements:**
- Database restored
- Users can authenticate
- Existing data accessible

**Expected Outcomes:**
- Historical backup restored successfully
- All data accessible

**Failure Handling:**
- **Decryption fails:** Old key may be lost or incorrect
- **Backup corrupted:** Backup may be incomplete
- **Restore fails:** Check database permissions

**Rollback Procedures:**
- None required (restore from backup)

**Audit Requirements:**
- Historical backup restoration logged as CRITICAL
- Key rotation documented

---

## Scenario 10: Master Password Recovery

**Description:** Recovering the global master password when it is lost.

**Prerequisites:**
- Master password recovery material (stored independently)
- User password knowledge (for verification)

**Required Permissions:**
- Database access
- Recovery material access

**Required Recovery Material:**
- Master password recovery material (stored independently)

**Operational Steps:**

1. **Verify you have recovery material:**
   ```bash
   # Check if recovery material exists
   ls -la /secure/master-password-recovery/
   ```

2. **Recover master password:**
   ```bash
   # Use recovery material to recover master password
   # (Procedure documented in recovery instructions)
   ```

3. **Verify recovered master password:**
   ```bash
   # Verify by attempting to decrypt sample credential
   python -c "from app.core.defuse_compat import Defuse; ..."
   ```

**Verification Requirements:**
- Master password recovered
- Can decrypt sample credentials

**Expected Outcomes:**
- Master password recovered
- Can access encrypted credentials

**Failure Handling:**
- **Recovery fails:** Recovery material may be lost or corrupted
- **Verification fails:** Master password may be incorrect

**Rollback Procedures:**
- None required (recovery)

**Audit Requirements:**
- Master password recovery logged as CRITICAL
- Document who performed recovery

---

## Scenario 11: Application Secret Recovery

**Description:** Recovering lost application secrets (SECRET_KEY, ENCRYPTION_KEY).

**Prerequisites:**
- Secret recovery material (stored independently)

**Required Permissions:**
- Secret storage access

**Required Recovery Material:**
- SECRET_KEY recovery material
- ENCRYPTION_KEY recovery material

**Operational Steps:**

1. **Recover SECRET_KEY:**
   ```bash
   cat /secure/secrets/SECRET_KEY
   ```

2. **Recover ENCRYPTION_KEY:**
   ```bash
   cat /secure/secrets/ENCRYPTION_KEY
   ```

3. **Update application configuration:**
   ```bash
   # Update environment variables
   export SECRET_KEY=$(cat /secure/secrets/SECRET_KEY)
   export ENCRYPTION_KEY=$(cat /secure/secrets/ENCRYPTION_KEY)
   ```

4. **Restart application:**
   ```bash
   systemctl restart pySysPass
   ```

**Verification Requirements:**
- Application running
- Users can authenticate
- Existing data accessible

**Expected Outcomes:**
- Secrets recovered
- Application functional

**Failure Handling:**
- **Secrets lost:** May need to rotate all credentials
- **Verification fails:** Secrets may be incorrect

**Rollback Procedures:**
- None required (recovery)

**Audit Requirements:**
- Secret recovery logged as CRITICAL

---

## Scenario 12: Security State Reconciliation

**Description:** After restoration, security state must be reconciled (sessions invalidated, tokens revoked, etc.).

**Prerequisites:**
- Application running
- Backup restored

**Required Permissions:**
- Database access
- Admin access

**Required Recovery Material:**
- None (procedure only)

**Operational Steps:**

1. **Verify sessions are invalidated:**
   ```bash
   # Check sessions table (should be empty or old)
   mysql -u syspass -p -e "SELECT COUNT(*) FROM Session;"
   ```

2. **Verify API tokens are revoked:**
   ```bash
   # Check AuthToken table
   mysql -u syspass -p -e "SELECT COUNT(*) FROM AuthToken;"
   ```

3. **Verify emergency mode is inactive:**
   ```bash
   ls -la /var/run/syspass/emergency-auth-active
   # Should not exist
   ```

4. **Verify vault contexts are revoked:**
   ```bash
   # Check service_vaults table (if implemented)
   mysql -u syspass -p -e "SELECT COUNT(*) FROM ServiceVault;"
   ```

5. **Re-provision service vault contexts (if applicable):**
   ```bash
   # (Procedure for re-provisioning vault contexts)
   ```

6. **Verify security state is trustworthy:**
   ```bash
   # Run security validation script
   python -m app.security.validate
   ```

**Verification Requirements:**
- Sessions invalidated
- API tokens revoked
- Emergency mode inactive
- Vault contexts revoked
- Security state trustworthy

**Expected Outcomes:**
- Security state reconciled
- System is in known-good state

**Failure Handling:**
- **Sessions not invalidated:** Manual cleanup required
- **Emergency mode still active:** Manual deactivation required

**Rollback Procedures:**
- None required (reconciliation)

**Audit Requirements:**
- Security state reconciliation logged

---

## Scenario 13: Emergency Mode Termination

**Description:** Terminating emergency mode when normal operation is restored.

**Prerequisites:**
- Emergency mode active
- Normal LDAP authentication working
- All break-glass accounts no longer needed

**Required Permissions:**
- Server access
- Emergency mode deactivation authorization

**Required Recovery Material:**
- Deactivation script
- Authorization credentials

**Operational Steps:**

1. **Verify normal operation is restored:**
   ```bash
   # Test LDAP authentication
   ldapsearch -x -H ldap://ad-server -b dc=example,dc=com
   ```

2. **Deactivate emergency mode:**
   ```bash
   sudo /srv/pySysPass/scripts/deactivate-emergency-auth.sh
   ```
   - Script removes `/var/run/syspass/emergency-auth-active`
   - Logs deactivation to `/var/log/syspass/emergency-auth.log`
   - Terminates all emergency sessions

3. **Verify emergency mode is inactive:**
   ```bash
   ls -la /var/run/syspass/emergency-auth-active
   # Should not exist
   ```

4. **Verify emergency sessions are terminated:**
   ```bash
   # Check sessions table for emergency sessions
   mysql -u syspass -p -e "SELECT * FROM Session WHERE isEmergency=1;"
   # Should return no results
   ```

**Verification Requirements:**
- Emergency mode inactive
- No emergency sessions active
- Normal LDAP authentication working

**Expected Outcomes:**
- Emergency mode terminated
- All emergency sessions terminated
- Normal operation restored

**Failure Handling:**
- **Deactivation fails:** Check authorization, verify script permissions
- **Sessions not terminated:** Manual cleanup required

**Rollback Procedures:**
- Emergency mode reactivates automatically if activation conditions met

**Audit Requirements:**
- Emergency mode deactivation logged as CRITICAL

---

## Scenario 14: PHP Rollback

**Description:** Rolling back to sysPass PHP for compatibility with existing PHP deployments.

**Prerequisites:**
- PHP sysPass installation available
- Database backup compatible with PHP schema

**Required Permissions:**
- Database access
- PHP sysPass installation

**Required Recovery Material:**
- PHP sysPass installation
- Database backup

**Operational Steps:**

1. **Stop Python application:**
   ```bash
   systemctl stop pySysPass
   ```

2. **Prepare database for PHP:**
   ```bash
   # PHP ignores unknown fields, so Python JSON blobs are preserved
   # No database modification required
   ```

3. **Restore Python backup to PHP:**
   ```bash
   mysql -u syspass -p syspass < backups/database.sql
   ```

4. **Start PHP application:**
   ```bash
   # Start PHP sysPass
   ```

5. **Verify PHP application is working:**
   ```bash
   # Test PHP application
   ```

**Verification Requirements:**
- PHP application running
- Users can authenticate
- Existing data accessible

**Expected Outcomes:**
- PHP application running
- Python data preserved
- Users authenticated

**Failure Handling:**
- **PHP won't start:** Check PHP configuration
- **Users cannot authenticate:** Check credentials

**Rollback Procedures:**
- None required (rollback)

**Audit Requirements:**
- PHP rollback logged as CRITICAL

---

## General Recovery Procedures

### Backup Verification Before Restoration

**Always verify backup integrity before restoration:**

```bash
# Verify HMAC
openssl dgst -sha256 -mac HMAC -macopt hexkey=[backup-key] \
  -in backups/database.sql.enc

# Verify file integrity
sha256sum backups/database.sql.enc
# Compare with manifest
```

### Security State Validation

**After restoration, always run security validation:**

```bash
python -m app.security.validate
```

### Audit Log Review

**After any recovery operation, review audit logs:**

```bash
journalctl --user -u pySysPass -n 100 --no-pager
```

### Recovery Checklist

**After any recovery:**

- [ ] Application running
- [ ] Database accessible
- [ ] Users can authenticate
- [ ] Security state reconciled
- [ ] Audit logs reviewed
- [ ] Emergency mode inactive (if not needed)
- [ ] Backup integrity verified

---

## Recovery Material Storage Requirements

**All recovery material must be stored independently:**

| Recovery Material | Storage Location | Permissions |
|------------------|------------------|-------------|
| Backup encryption key | `/etc/syspass/backup-key` | 0400 |
| Master password recovery | `/secure/master-password-recovery/` | 0400 |
| Emergency credentials | `/secure/emergency-credentials/` | 0400 |
| Recovery instructions | `/secure/recovery-instructions/` | 0400 |
| Database backup | `/backup/databases/` | 0400 |
| Runtime files backup | `/backup/runtime/` | 0400 |

**IMPORTANT:** Never store recovery material inside pySysPass or on the production application host.

---

## Testing Requirements

**All recovery procedures must be tested regularly:**

- Quarterly: Full recovery test (Scenario 4 or 6)
- Monthly: Database restore test (Scenario 5)
- Weekly: Backup integrity verification
- Daily: Security state validation

**Test results must be documented and stored.**

---

## Related Documentation

- `docs/adr/0013-backup-disaster-recovery-and-cryptographic-recoverability.md`
- `docs/adr/0014-emergency-authentication-mode.md`
- `docs/security/policy.md`
- `docs/GLOSSARY.md`
