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

    monkeypatch.setattr(service, "_try_mysqldump", lambda url, dest: True)
    monkeypatch.setattr(service, "_try_mysql_restore", fake_mysql_restore)

    result = service.restore_backup(archive_path.name, db_url="mysql+pymysql://u:p@localhost:3306/db", offline=True)

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
    monkeypatch.setattr(service, "_try_mysqldump", lambda url, dest: True)
    results = iter([False, True])
    monkeypatch.setattr(service, "_try_mysql_restore", lambda db_url, source: next(results))

    with pytest.raises(RuntimeError, match="Failed to restore database dump"):
        service.restore_backup(archive_path.name, db_url="mysql+pymysql://u:p@localhost:3306/db", offline=True)


@pytest.mark.parametrize(
    "filename",
    ["../outside.zip", "/tmp/outside.zip", "nested/backup.zip", "backup.sql"],
)
def test_backup_paths_reject_untrusted_filenames(tmp_path, filename):
    service = BackupService(backup_dir=str(tmp_path / "backups"))

    with pytest.raises(ValueError, match="Invalid backup filename"):
        service.resolve_backup_path(filename)


def test_restore_rejects_zip_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "malicious.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escaped.txt", "not allowed")

    service = BackupService(backup_dir=str(backup_dir))
    with pytest.raises(RuntimeError, match="invalid paths"):
        service.restore_backup(archive_path.name, offline=True)

    assert not (tmp_path / "escaped.txt").exists()


def test_backup_routes_are_registered():
    from app.api.v1.backup import router

    route_paths = [route.path for route in router.routes]

    assert "/backup/" in route_paths
    assert "/backup/create" in route_paths
    assert "/backup/{filename}/download" in route_paths
    assert "/backup/{filename}/restore" in route_paths
    assert "/backup/{filename}" in route_paths


def test_failed_dump_never_publishes_archive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    service = BackupService()
    monkeypatch.setattr(service, "_try_mysqldump", lambda url, dest: False)
    with pytest.raises(RuntimeError, match="no backup was published"):
        service.create_full_backup("mysql://user@localhost/db")
    assert list(service.backup_dir.iterdir()) == []


def test_restore_requires_offline_mode(tmp_path):
    with pytest.raises(RuntimeError, match="offline"):
        BackupService(str(tmp_path)).restore_backup("sample.zip")


def test_failed_import_rolls_back_files_without_replacing_mount_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    service = BackupService()
    _write_backup_archive(service.backup_dir / "restore.zip")
    data = tmp_path / "data"
    data.mkdir()
    inode = data.stat().st_ino
    (data / "original.txt").write_text("original")

    def snapshot(url, dest):
        dest.write_text("rollback snapshot")
        return True

    calls = []

    def restore(url, source):
        calls.append(source.read_text())
        return len(calls) == 2

    monkeypatch.setattr(service, "_try_mysqldump", snapshot)
    monkeypatch.setattr(service, "_try_mysql_restore", restore)
    with pytest.raises(RuntimeError, match="original state recovered"):
        service.restore_backup("restore.zip", "mysql://user@localhost/db", offline=True)
    assert calls == ["CREATE TABLE demo (id INT);\n", "rollback snapshot"]
    assert data.stat().st_ino == inode
    assert [path.name for path in data.iterdir()] == ["original.txt"]
    assert (data / "original.txt").read_text() == "original"
    assert not list(service.backup_dir.glob(".restore-*"))


def test_failed_rollback_retains_snapshot(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    service = BackupService()
    _write_backup_archive(service.backup_dir / "restore.zip", include_data=False)

    def snapshot(url, dest):
        dest.write_text("recovery")
        return True

    monkeypatch.setattr(service, "_try_mysqldump", snapshot)
    monkeypatch.setattr(service, "_try_mysql_restore", lambda url, source: False)
    with pytest.raises(RuntimeError, match="Keep applications stopped"):
        service.restore_backup("restore.zip", "mysql://user@localhost/db", offline=True)
    assert next(service.backup_dir.glob(".restore-*/rollback.sql")).read_text() == "recovery"


def test_partial_archives_are_not_listed(tmp_path):
    service = BackupService(str(tmp_path))
    _write_backup_archive(tmp_path / ".backup-partial.zip")
    assert service.list_backups() == []


def test_backup_rejects_symlinked_runtime_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "outside").write_text("private")
    (tmp_path / "data" / "linked").symlink_to(tmp_path / "outside")
    with pytest.raises(RuntimeError, match="symbolic links"):
        BackupService().create_full_backup()


def test_database_url_parsing_preserves_escaped_credentials():
    from app.services.backup_service import _parse_db_url

    parsed = _parse_db_url("mysql+pymysql://user:p%40ss%2Fword@localhost:3307/vault?charset=utf8mb4")
    assert parsed["password"] == "p@ss/word"
    assert parsed["port"] == 3307
    assert _parse_db_url("mysql://user@localhost/vault?ssl_ca=/ca.pem") is None


def test_web_restore_is_disabled_without_touching_database():
    import asyncio
    from unittest.mock import Mock

    from fastapi import HTTPException

    from app.api.v1.backup import restore_backup

    database = Mock()
    with pytest.raises(HTTPException) as error:
        asyncio.run(restore_backup("sample.zip", db=database, current_user={"id": 1}))
    assert error.value.status_code == 409
    assert database.mock_calls == []
