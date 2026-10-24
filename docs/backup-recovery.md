# Backup and offline recovery

Backups are published only after every requested payload succeeds. Database dumps
use a single transaction for InnoDB. The container includes dump/import clients.
All supplied stacks persist runtime data and backups in separate named volumes.
Copy archives to encrypted off-host storage; same-host volumes are not disaster
recovery. Archives contain secrets.

A live database dump and runtime files are not one atomic snapshot. Stop all Python
and PHP writers for a coordinated checkpoint. Preserve the deployment's existing
encryption keys and PHP password salt separately; never rotate them during recovery.

## Restore procedure

1. Test the trusted archive against an isolated database and runtime volume first.
   SQL imports execute database statements. Full recovery needs `database.sql` and
   `data/` in the archive.
2. Stop every application, worker, and PHP instance sharing the database or files.
   Keep MySQL running. Take an independent database and runtime-volume checkpoint.
3. From the project directory, using the stack's original environment:

   ```sh
   docker compose -f podman-compose.yml stop backend frontend
   docker compose -f podman-compose.yml run --rm --no-deps backend \
     python -m app.restore_backup BACKUP_FILENAME.zip --confirm-stopped
   ```

   Substitute your external or Portainer Compose filename as appropriate. Mount
   the original `/app/data` and `/app/backups` volumes and use the intended
   `DATABASE_URL`. The flag confirms an operator action; it cannot detect PHP writers.
4. On success restart the stack, then verify login, vault decryption, runtime config,
   and sample accounts. On failure keep writers stopped. Restore attempts database
   snapshot rollback and file rollback. If rollback fails, the error identifies
   retained `.restore-*` recovery material. Preserve it and recover using your
   independent checkpoint before restarting.

SQL DDL is not transactional. Rollback is best effort and cannot promise removal of
extra tables introduced by arbitrary SQL archives. Dump/import timeout is currently
120 seconds; large deployments should use their database recovery tooling. URL
options other than `charset` are refused so TLS settings cannot be silently ignored;
use TLS-aware external tooling for these deployments.

Web restore returns HTTP 409. Offline restore replaces directory contents while
preserving the mounted directory itself. Runtime and archive symlinks are rejected.

## Existing deployments

Before replacing a pre-fix Portainer backend, export `/app/data`, `/app/backups`,
and `/app/config/runtime-config.json` from the existing container. Populate the new
runtime and backup volumes, placing config at `/app/data/runtime-config.json`.
Retain the old container until volumes and key material have been verified.
Empty named volumes do not migrate existing files.

The backend now runs as UID `10001`. Files copied into volumes as root, and
volumes written by older root images, must be re-owned before the new backend
can use them; see [container user and volume ownership](installation.md#container-user-and-volume-ownership).
The offline restore command runs as the same account.

## Disposable rehearsal

`scripts/check-backup-recovery.py` tests an actual dump/import and runtime file
recovery, including preservation of the data directory inode. Run only against
an isolated bootstrapped MySQL database and disposable data/backup directories,
with `ALLOW_DISPOSABLE_RECOVERY_TEST=yes`. It modifies the canonical `Category`
table without changing the PHP schema.

## Changing the vault master password

The online rekey operation stays disabled. Change the master password offline,
the way sysPass PHP does: re-encrypt `Account.pass/key`, the `AccountHistory`
rows whose `mPassHash` matches the current `Config.masterPwd`, and every
`CustomFieldData` row with a key; then store the new `masterPwd` hash and
`lastupdatempass`. Users, in pySysPass and in PHP, re-enter the new master
password once at their next sign-in.

1. Enable maintenance mode (PHP requires it too), then stop every Python and PHP
   application writer.
2. Run a dry run, then the change. Supply the passwords through the environment
   or the prompts, never as arguments:

   ```bash
   docker compose -f podman-compose.yml run --rm --no-deps backend \
     python -m app.rotate_master_password --confirm-stopped --dry-run
   docker compose -f podman-compose.yml run --rm --no-deps backend \
     python -m app.rotate_master_password --confirm-stopped
   ```

3. Start the stack, disable maintenance mode, and sign in with the new master
   password.

The command checks that the current password matches `masterPwd`. It decrypts
every candidate value with it and aborts if any value fails; PHP would skip that
row instead. It writes a full backup before changing anything and fails if the
backup fails. It makes every change in one database transaction, decrypts each
rewritten value with the new password before committing, retires any temporary
master password, and ends all pySysPass sessions. Values still in the legacy
pySysPass AES format make it stop unless `--include-legacy` is given, which
rewrites them in the native format. History rows encrypted under an older master
password are left unchanged, as in PHP.

To undo the change, restore the backup the command reported, using the restore
procedure above. Keep that archive and both passwords until users have signed in
successfully.

## Rotating ENCRYPTION_KEY or SECRET_KEY

sysPass PHP data never depends on these keys: account passwords, 2FA state and
public links are encrypted under the vault master password or the PHP password
salt. Only values written by earlier pySysPass releases (legacy formats),
session tokens, and pending 2FA setups use `ENCRYPTION_KEY`.

1. Report legacy values: `python -m app.encryption_key check` (exit status 1
   while any remain).
2. If any remain, enable maintenance mode, stop every writer, and convert them:

   ```bash
   python -m app.encryption_key migrate --confirm-stopped
   ```

   The command backs up first, then rewrites legacy account and history
   passwords and 2FA rows in the native sysPass formats in one transaction.
   Legacy public links are not converted: a native link reveals the password
   while a legacy one did not. The command stops until you rerun it with
   `--drop-legacy-links`, which deletes them so owners can recreate them.
3. Run `check` again and confirm it reports 0.
4. Set the new `ENCRYPTION_KEY` (and/or `SECRET_KEY`), then run
   `python -m app.encryption_key end-sessions` with the new configuration and
   start the stack. Everyone signs in again; pending 2FA setups restart.

Keep the old key until step 3 reports 0 and a test sign-in succeeds: legacy
values cannot be read without it.
