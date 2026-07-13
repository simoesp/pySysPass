from app.core.config import settings
from app.core.syspass_runtime_config import clear_runtime_config_cache
from app.services.auth_service import make_user_key


def test_make_user_key_uses_runtime_config_salt(monkeypatch, tmp_path):
    config_xml = tmp_path / "config.xml"
    config_xml.write_text(
        "<config><passwordSalt>runtime-salt</passwordSalt><configDate>123</configDate></config>",
        encoding="utf-8",
    )

    monkeypatch.setattr(settings, "SYSPASS_CONFIG_XML_PATH", str(config_xml))
    monkeypatch.setattr(settings, "SYSPASS_PASSWORD_SALT", "")
    clear_runtime_config_cache()

    try:
        assert make_user_key("password", "alice") == "passwordaliceruntime-salt"
    finally:
        clear_runtime_config_cache()
