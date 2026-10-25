"""Destructive recovery rehearsal: run ONLY against a disposable, bootstrapped database."""
import os
from pathlib import Path

from sqlalchemy import create_engine, text

from app.services.backup_service import BackupService


def main():
    if os.environ.get("ALLOW_DISPOSABLE_RECOVERY_TEST") != "yes":
        raise SystemExit("Requires ALLOW_DISPOSABLE_RECOVERY_TEST=yes and a disposable database/data volume")
    url = os.environ["DATABASE_URL"]
    engine = create_engine(url)
    data = Path("data")
    data.mkdir(exist_ok=True)
    inode = data.stat().st_ino
    marker = data / "recovery-check.txt"
    marker.write_text("before")
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO Category (name, hash) VALUES ('recovery-before', SHA1('recovery-before'))"
        ))
    service = BackupService()
    backup = service.create_full_backup(url)
    assert backup["db_included"] and backup["data_included"]
    with engine.begin() as connection:
        connection.execute(text("UPDATE Category SET name='recovery-after' WHERE name='recovery-before'"))
    engine.dispose()
    marker.write_text("after")
    service.restore_backup(backup["filename"], url, offline=True)
    assert data.stat().st_ino == inode
    assert marker.read_text() == "before"
    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM Category WHERE name='recovery-before'")).scalar() == 1
        assert connection.execute(text("SELECT COUNT(*) FROM Category WHERE name='recovery-after'")).scalar() == 0
    engine.dispose()
    print("Database and mounted runtime data recovery passed")


if __name__ == "__main__":
    main()
