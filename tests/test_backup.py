import zipfile
from pathlib import Path

import pytest

from app.services.backup_service import BackupService


def _write_backup_archive(archive_path: Path, include_db: bool = True, include_data: bool = True):
    with zipfile.ZipFile(archive_path, "w") as archive:
        if include_db:
            archive.writestr("database.sql", "CREATE TABLE demo (id INT);\n")
        if include_data:
            archive.writestr("data/example.txt", "restored-data")


def test_list_backups_reports_archive_contents(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "sample.zip"
    _write_backup_archive(archive_path)

    service = BackupService(backup_dir=str(backup_dir))
    backups = service.list_backups()

    assert len(backups) == 1
    assert backups[0]["filename"] == "sample.zip"
    assert backups[0]["db_included"] is True
    assert backups[0]["data_included"] is True


def test_restore_backup_restores_data_and_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "restore.zip"
    _write_backup_archive(archive_path)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "old.txt").write_text("old-data", encoding="utf-8")

    service = BackupService(backup_dir=str(backup_dir))
    restore_calls = []

    def fake_mysql_restore(db_url, source):
        restore_calls.append((db_url, source.read_text(encoding="utf-8")))
        return True

    monkeypatch.setattr(service, "_try_mysql_restore", fake_mysql_restore)

    result = service.restore_backup(str(archive_path), db_url="mysql+pymysql://u:p@localhost:3306/db")

    assert result["filename"] == "restore.zip"
    assert result["db_restored"] is True
    assert result["data_restored"] is True
    assert restore_calls == [("mysql+pymysql://u:p@localhost:3306/db", "CREATE TABLE demo (id INT);\n")]
    assert (tmp_path / "data" / "example.txt").read_text(encoding="utf-8") == "restored-data"
    assert not (tmp_path / "data" / "old.txt").exists()


def test_restore_backup_requires_db_client_for_database_dump(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "restore.zip"
    _write_backup_archive(archive_path, include_db=True, include_data=False)

    service = BackupService(backup_dir=str(backup_dir))
    monkeypatch.setattr(service, "_try_mysql_restore", lambda db_url, source: False)

    with pytest.raises(RuntimeError, match="Failed to restore database dump"):
        service.restore_backup(str(archive_path), db_url="mysql+pymysql://u:p@localhost:3306/db")


def test_backup_routes_are_registered():
    from app.api.v1.backup import router

    route_paths = [route.path for route in router.routes]

    assert "/backup/" in route_paths
    assert "/backup/create" in route_paths
    assert "/backup/{filename}/download" in route_paths
    assert "/backup/{filename}/restore" in route_paths
    assert "/backup/{filename}" in route_paths
