import json
import multiprocessing
from unittest.mock import patch

import pytest

from app.core import runtime_json_config
from app.services.config_service import ConfigService


def test_runtime_json_config_stores_grouped_values(tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime-config.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(runtime_path))

    assert runtime_json_config.set_runtime_config_value("app_url", "https://vault.example.test")
    assert runtime_json_config.get_runtime_config_value("app_url") == "https://vault.example.test"

    payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert payload["general"]["app_url"] == "https://vault.example.test"


def test_config_service_prefers_runtime_json_over_db(db_session, tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime-config.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(runtime_path))

    svc = ConfigService(db_session)
    svc.set("mail_from", "noreply@example.test")

    assert svc.get("mail_from") == "noreply@example.test"
    assert runtime_json_config.get_runtime_config_value("mail_from") == "noreply@example.test"


def _concurrent_writer(path, key, start):
    runtime_json_config.settings.SYSPASS_RUNTIME_CONFIG_JSON_PATH = path
    start.wait()
    runtime_json_config.set_runtime_config_value(key, key)


def test_concurrent_workers_preserve_each_update(tmp_path, monkeypatch):
    path = tmp_path / "runtime.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(path))
    # spawn: the test process has live threadpool threads, and fork() with
    # threads can deadlock the child.
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    keys = list(runtime_json_config.SECTION_KEYS)[:12]
    workers = [context.Process(target=_concurrent_writer, args=(str(path), key, start)) for key in keys]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(timeout=10)
        if worker.is_alive():
            worker.terminate()
            worker.join()
        assert worker.exitcode == 0
    for key in keys:
        assert runtime_json_config.get_runtime_config_value(key) == key
    assert path.stat().st_mode & 0o777 == 0o600


def test_failed_replace_preserves_original_config(tmp_path, monkeypatch):
    path = tmp_path / "runtime.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(path))
    runtime_json_config.set_runtime_config_value("mail_user", "original")
    original = path.read_bytes()

    def fail_replace(*args):
        raise OSError("simulated interrupted replacement")

    monkeypatch.setattr(runtime_json_config.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        runtime_json_config.set_runtime_config_value("mail_user", "changed")
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".runtime.json.*"))


def test_bulk_update_is_one_write_preserving_compatibility(tmp_path, monkeypatch, db_session):
    path = tmp_path / "runtime.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(path))
    path.write_text(json.dumps({"compatibility": {"passwordSalt": "existing-php-salt"}, "extension": {"x": 1}}))
    with patch.object(runtime_json_config, "_write_document", wraps=runtime_json_config._write_document) as writer:
        ConfigService(db_session).set_many({"mail_user": "user", "mail_pass": "value", "app_url": None})
        assert writer.call_count == 1
    document = json.loads(path.read_text())
    assert document["compatibility"]["passwordSalt"] == "existing-php-salt"
    assert document["extension"] == {"x": 1}
    assert document["mail"] == {"mail_user": "user", "mail_pass": "value"}


def test_invalid_existing_json_is_preserved(tmp_path, monkeypatch):
    path = tmp_path / "runtime.json"
    monkeypatch.setattr(runtime_json_config.settings, "SYSPASS_RUNTIME_CONFIG_JSON_PATH", str(path))
    path.write_text('{"compatibility":')
    with pytest.raises(ValueError):
        runtime_json_config.set_runtime_config_value("mail_user", "value")
    assert path.read_text() == '{"compatibility":'
