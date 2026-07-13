import json

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
