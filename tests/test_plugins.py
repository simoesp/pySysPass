import json
from pathlib import Path

import pytest

from app.core.security import EncryptionService
from app.schemas.account import AccountCreate
from app.services.account_service import AccountService
from app.services.plugin_service import PLATFORM_HOOKS, PluginService


def _make_plugin(root: Path, name: str = "sample_plugin", enabled: bool = True, config: dict | None = None):
    plugin_dir = root / "plugins" / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "version": "1.2.3",
        "author": "Test Suite",
        "description": "Sample plugin for tests",
        "enabled": enabled,
        "config": config or {"output_file": str(root / "hook-output.jsonl")},
        "hooks": ["on_account_created"],
    }
    (plugin_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (plugin_dir / f"{name}.py").write_text(
        """
from pathlib import Path
import json
from app.services.plugin_service import Plugin

class Plugin(Plugin):
    def get_config_schema(self):
        return {"type": "object", "properties": {"output_file": {"type": "string"}}}

    def on_account_created(self, payload=None, actor_user_id=None):
        out = Path(self.config["output_file"])
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as f:
            record = {"hook": "on_account_created", "actor_user_id": actor_user_id, "payload": payload}
            f.write(json.dumps(record) + "\\n")
        return {"ok": True}
""".strip(),
        encoding="utf-8",
    )
    return plugin_dir


def test_plugin_service_sync_enable_and_config(db_session, tmp_path):
    _make_plugin(tmp_path)
    service = PluginService(db_session, plugins_dir=str(tmp_path / "plugins"))

    plugins = service.sync_plugins()
    assert len(plugins) == 1
    assert plugins[0]["name"] == "sample_plugin"
    assert plugins[0]["available"] is True
    assert plugins[0]["enabled"] is True

    plugin = service.get_plugin("sample_plugin")
    assert plugin is not None
    assert plugin["config_schema"]["type"] == "object"
    assert plugin["declared_hooks"] == ["on_account_created"]

    assert service.update_plugin_config("sample_plugin", {"output_file": str(tmp_path / "other.jsonl")}) is True
    updated = service.get_plugin("sample_plugin")
    assert updated["config"]["output_file"].endswith("other.jsonl")

    assert service.disable_plugin("sample_plugin") is True
    assert service.get_plugin("sample_plugin")["enabled"] is False
    assert service.enable_plugin("sample_plugin") is True
    assert service.get_plugin("sample_plugin")["enabled"] is True


def test_plugin_service_calls_enabled_hook(db_session, tmp_path):
    output_file = tmp_path / "events.jsonl"
    _make_plugin(tmp_path, config={"output_file": str(output_file)})
    service = PluginService(db_session, plugins_dir=str(tmp_path / "plugins"))
    service.sync_plugins()

    results = service.call_plugin_hook(
        "on_account_created",
        payload={"id": 42, "title": "Example"},
        actor_user_id=7,
    )

    assert results
    assert results[0]["plugin"] == "sample_plugin"
    assert output_file.exists()
    line = json.loads(output_file.read_text(encoding="utf-8").strip())
    assert line["hook"] == "on_account_created"
    assert line["actor_user_id"] == 7
    assert line["payload"]["id"] == 42


def test_account_service_emits_plugin_hook(db_session, tmp_path, monkeypatch):
    from app.models.account import Category, Client, User
    from app.services.auth_service import get_password_hash

    output_file = tmp_path / "account-hooks.jsonl"
    _make_plugin(tmp_path, config={"output_file": str(output_file)})
    monkeypatch.chdir(tmp_path)
    PluginService(db_session).sync_plugins()

    category = Category(id=1, name="Plugin Category", hash=b"c" * 40)
    client = Client(id=1, name="Plugin Client", hash=b"d" * 40, isGlobal=False)
    db_session.add(category)
    db_session.add(client)

    user = User(
        id=1,
        name="Plugin Tester",
        username="plugin-tester",
        email="plugin@test.local",
        password=get_password_hash("testpassword").encode("utf-8"),
        isUserAdmin=False,
        userGroupId=1,
        userProfileId=1,
        hashSalt=b"plugin-test-salt",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    service = AccountService(db_session, EncryptionService("test-encryption-key-32bytes!!"))
    account = service.create_account(
        AccountCreate(
            title="Plugin Test",
            login="plugin-user",
            password="secret123",
            category_id=category.id,
            client_id=client.id,
        ),
        user.id,
    )

    assert account["title"] == "Plugin Test"
    assert output_file.exists()
    lines = output_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["hook"] == "on_account_created"
    assert event["payload"]["title"] == "Plugin Test"
    assert event["actor_user_id"] == user.id


def test_plugin_routes_and_hook_catalog_are_registered():
    from app.api.v1.plugins import router

    route_paths = [route.path for route in router.routes]
    assert "/plugins" in route_paths
    assert "/plugins/sync" in route_paths
    assert "/plugins/hooks" in route_paths
    assert "/plugins/{plugin_name}" in route_paths
    assert "/plugins/{plugin_name}/enable" in route_paths
    assert "/plugins/{plugin_name}/disable" in route_paths
    assert "/plugins/{plugin_name}/config" in route_paths
    assert "on_account_created" in PLATFORM_HOOKS


def test_plugin_module_cannot_escape_plugin_directory(db_session, tmp_path):
    plugin_dir = _make_plugin(tmp_path, name="contained")
    manifest_path = plugin_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["module"] = "../../outside.py"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "outside.py").write_text("class Plugin: pass", encoding="utf-8")

    service = PluginService(db_session, plugins_dir=str(tmp_path / "plugins"))
    service.sync_plugins()

    with pytest.raises(ValueError, match="Invalid plugin module"):
        service.load_plugin("contained")


@pytest.mark.parametrize("plugin_name", ["../outside", "nested/plugin", ".hidden"])
def test_plugin_names_reject_path_syntax(db_session, tmp_path, plugin_name):
    service = PluginService(db_session, plugins_dir=str(tmp_path / "plugins"))

    with pytest.raises(ValueError, match="Invalid plugin name"):
        service._manifest_path(plugin_name)
