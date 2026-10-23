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

## Disposable rehearsal

`scripts/check-backup-recovery.py` tests an actual dump/import and runtime file
recovery, including preservation of the data directory inode. Run only against
an isolated bootstrapped MySQL database and disposable data/backup directories,
with `ALLOW_DISPOSABLE_RECOVERY_TEST=yes`. It modifies the canonical `Category`
table without changing the PHP schema.
