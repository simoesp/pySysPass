"""Plugin platform services and runtime hooks."""
from __future__ import annotations

from datetime import datetime
import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.account import Plugin as PluginRow


PLUGIN_STATE_VERSION = 1

PLATFORM_HOOKS: Dict[str, str] = {
    "on_account_created": "Runs after an account is created.",
    "on_account_updated": "Runs after an account is updated.",
    "on_account_deleted": "Runs after an account is deleted.",
    "on_account_copied": "Runs after an account is copied.",
    "on_password_decrypted": "Runs after an account password is revealed.",
    "on_backup_created": "Runs after a backup archive is created.",
    "on_backup_restored": "Runs after a backup archive is restored.",
}


class PluginInfo:
    """Plugin metadata exposed to the application."""

    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        enabled: bool = True,
        available: bool = True,
        config: Optional[Dict[str, Any]] = None,
        install_date: Optional[datetime] = None,
        last_update: Optional[datetime] = None,
        hooks: Optional[List[str]] = None,
        manifest: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
    ):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.enabled = enabled
        self.available = available
        self.config = config or {}
        self.install_date = install_date or datetime.now()
        self.last_update = last_update
        self.hooks = hooks or []
        self.manifest = manifest or {}
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "enabled": self.enabled,
            "available": self.available,
            "config": self.config,
            "install_date": self.install_date.isoformat() if self.install_date else None,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "hooks": self.hooks,
            "manifest": self.manifest,
            "errors": self.errors,
        }


class Plugin:
    """Base plugin class that runtime plugins should inherit from."""

    def __init__(self):
        self.name = ""
        self.version = ""
        self.author = ""
        self.description = ""
        self.config: Dict[str, Any] = {}

    def on_install(self):
        """Called when a plugin is first registered."""

    def on_uninstall(self):
        """Called when a plugin is uninstalled."""

    def on_enable(self):
        """Called when a plugin becomes enabled."""

    def on_disable(self):
        """Called when a plugin becomes disabled."""

    def get_config_schema(self) -> Dict[str, Any]:
        """Return a JSON-schema-like config description for the plugin."""
        return {}


class PluginService:
    """Service for syncing, loading, and dispatching plugins."""

    def __init__(self, db: Optional[Session] = None, plugins_dir: str = "./plugins"):
        self.db = db
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.loaded_plugins: Dict[str, Plugin] = {}
        self.plugin_info: Dict[str, PluginInfo] = {}

    # ── Discovery and persistence ────────────────────────────────────────

    def _manifest_path(self, plugin_name: str) -> Path:
        return self.plugins_dir / plugin_name / "manifest.json"

    def _module_path(self, plugin_name: str, manifest: Dict[str, Any]) -> Path:
        module_name = manifest.get("module") or f"{plugin_name}.py"
        return self.plugins_dir / plugin_name / module_name

    def _load_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        with manifest_path.open("r", encoding="utf-8") as f:
            manifest = json.load(f)
        if not manifest.get("name"):
            manifest["name"] = manifest_path.parent.name
        return manifest

    def _serialize_row_data(self, config: Dict[str, Any], manifest: Dict[str, Any]) -> bytes:
        payload = {
            "version": PLUGIN_STATE_VERSION,
            "config": config,
            "manifest": manifest,
        }
        return json.dumps(payload, ensure_ascii=True).encode("utf-8")

    def _deserialize_row_data(self, row: PluginRow) -> Dict[str, Any]:
        if not row.data:
            return {"config": {}, "manifest": {}}
        try:
            raw = row.data.decode("utf-8") if isinstance(row.data, (bytes, bytearray)) else str(row.data)
            payload = json.loads(raw)
            return {
                "config": payload.get("config", {}) or {},
                "manifest": payload.get("manifest", {}) or {},
            }
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return {"config": {}, "manifest": {}}

    def _row_to_info(self, row: PluginRow, manifest: Optional[Dict[str, Any]] = None) -> PluginInfo:
        stored = self._deserialize_row_data(row)
        manifest_data = manifest or stored.get("manifest", {}) or {}
        hooks = manifest_data.get("hooks") or []
        return PluginInfo(
            name=row.name,
            version=row.versionLevel or manifest_data.get("version", "0.0.0"),
            author=manifest_data.get("author", ""),
            description=manifest_data.get("description", ""),
            enabled=bool(row.enabled),
            available=bool(row.available),
            config=stored.get("config", {}),
            hooks=hooks,
            manifest=manifest_data,
        )

    def discover_plugins(self) -> List[str]:
        """Discover plugin directory names with valid manifests."""
        return [item["name"] for item in self.discover_plugin_manifests()]

    def discover_plugin_manifests(self) -> List[Dict[str, Any]]:
        """Read all available manifests from the plugins directory."""
        manifests: List[Dict[str, Any]] = []
        for plugin_dir in sorted(self.plugins_dir.iterdir()):
            if not plugin_dir.is_dir():
                continue
            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                manifest = self._load_manifest(manifest_path)
                manifest["path"] = str(plugin_dir)
                manifest["hooks"] = manifest.get("hooks") or []
                manifests.append(manifest)
            except (OSError, json.JSONDecodeError):
                continue
        return manifests

    def sync_plugins(self) -> List[Dict[str, Any]]:
        """Sync discovered plugins into the database-backed registry."""
        manifests = self.discover_plugin_manifests()
        manifest_by_name = {m["name"]: m for m in manifests}

        if self.db is None:
            infos = []
            for manifest in manifests:
                info = PluginInfo(
                    name=manifest["name"],
                    version=manifest.get("version", "0.0.0"),
                    author=manifest.get("author", ""),
                    description=manifest.get("description", ""),
                    enabled=bool(manifest.get("enabled", True)),
                    available=True,
                    config=manifest.get("config", {}) or {},
                    hooks=manifest.get("hooks") or [],
                    manifest=manifest,
                )
                self.plugin_info[info.name] = info
                infos.append(info.to_dict())
            return infos

        existing_rows = {row.name: row for row in self.db.query(PluginRow).all()}

        for name, manifest in manifest_by_name.items():
            row = existing_rows.get(name)
            if row is None:
                row = PluginRow(
                    name=name,
                    enabled=bool(manifest.get("enabled", True)),
                    available=True,
                    versionLevel=manifest.get("version", "0.0.0"),
                    data=self._serialize_row_data(manifest.get("config", {}) or {}, manifest),
                )
                self.db.add(row)
                existing_rows[name] = row
            else:
                stored = self._deserialize_row_data(row)
                row.available = True
                row.versionLevel = manifest.get("version", row.versionLevel)
                row.data = self._serialize_row_data(stored.get("config", {}), manifest)

        for name, row in existing_rows.items():
            if name not in manifest_by_name:
                row.available = False

        self.db.commit()
        rows = self.db.query(PluginRow).order_by(PluginRow.name.asc()).all()
        result = []
        self.plugin_info = {}
        for row in rows:
            info = self._row_to_info(row, manifest_by_name.get(row.name))
            self.plugin_info[row.name] = info
            result.append(info.to_dict())
        return result

    # ── Runtime loading ──────────────────────────────────────────────────

    def _instantiate_plugin(self, plugin_name: str, fire_enable: bool = False) -> Optional[Plugin]:
        if plugin_name in self.loaded_plugins:
            return self.loaded_plugins[plugin_name]

        self.sync_plugins()
        info = self.plugin_info.get(plugin_name)
        manifest_path = self._manifest_path(plugin_name)
        if not manifest_path.exists():
            return None
        manifest = self._load_manifest(manifest_path)
        module_path = self._module_path(plugin_name, manifest)
        if not module_path.exists():
            raise RuntimeError(f"Plugin module not found for {plugin_name}")

        spec = importlib.util.spec_from_file_location(f"plugin_{plugin_name}", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Failed to build import spec for {plugin_name}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin_class = getattr(module, "Plugin", None)
        if plugin_class is None:
            raise RuntimeError(f"Plugin class not found in {module_path.name}")

        plugin: Plugin = plugin_class()
        plugin.name = manifest.get("name", plugin_name)
        plugin.version = manifest.get("version", "0.0.0")
        plugin.author = manifest.get("author", "")
        plugin.description = manifest.get("description", "")
        plugin.config = dict(info.config) if info else {}
        if fire_enable and hasattr(plugin, "on_enable"):
            plugin.on_enable()
        self.loaded_plugins[plugin_name] = plugin
        return plugin

    def load_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """Load a plugin if it is available and enabled."""
        info = self.get_plugin(plugin_name)
        if not info or not info.get("available") or not info.get("enabled"):
            return None
        return self._instantiate_plugin(plugin_name, fire_enable=True)

    def load_enabled_plugins(self) -> Dict[str, Plugin]:
        """Load all enabled and available plugins."""
        self.sync_plugins()
        for info in self.get_all_plugins():
            if info["enabled"] and info["available"]:
                try:
                    self._instantiate_plugin(info["name"], fire_enable=True)
                except Exception:
                    continue
        return self.loaded_plugins

    # ── Registry queries ─────────────────────────────────────────────────

    def get_all_plugins(self) -> List[Dict[str, Any]]:
        """List the current plugin registry."""
        return self.sync_plugins()

    def get_plugin(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get one plugin record."""
        self.sync_plugins()
        info = self.plugin_info.get(plugin_name)
        if not info:
            return None
        result = info.to_dict()
        result["config_schema"] = self.get_plugin_config_schema(plugin_name)
        result["declared_hooks"] = self.get_declared_hooks(plugin_name)
        return result

    def get_declared_hooks(self, plugin_name: str) -> List[str]:
        """Return hook names declared by manifest or plugin implementation."""
        info = self.plugin_info.get(plugin_name)
        hooks = list(info.hooks) if info else []
        try:
            plugin = self._instantiate_plugin(plugin_name, fire_enable=False)
            if plugin:
                for name in dir(plugin):
                    if name in PLATFORM_HOOKS and name not in hooks:
                        hooks.append(name)
        except Exception:
            pass
        return sorted(hooks)

    def get_plugin_config_schema(self, plugin_name: str) -> Dict[str, Any]:
        """Get a plugin's config schema if it exposes one."""
        try:
            plugin = self._instantiate_plugin(plugin_name, fire_enable=False)
            if plugin:
                schema = plugin.get_config_schema()
                return schema or {}
        except Exception:
            return {}
        return {}

    # ── Mutations ────────────────────────────────────────────────────────

    def install_plugin(self, plugin_dir: str) -> bool:
        """Install a plugin by copying it into the local plugins dir."""
        source_path = Path(plugin_dir)
        plugin_name = source_path.name
        target_path = self.plugins_dir / plugin_name
        try:
            import shutil

            shutil.copytree(source_path, target_path)
            self.sync_plugins()
            plugin = self.load_plugin(plugin_name)
            if plugin:
                plugin.on_install()
            return True
        except Exception as exc:
            raise RuntimeError(f"Failed to install plugin: {exc}") from exc

    def uninstall_plugin(self, plugin_name: str, remove_data: bool = False) -> bool:
        """Uninstall a plugin by marking it unavailable or deleting it."""
        plugin = self.loaded_plugins.pop(plugin_name, None)
        if plugin:
            plugin.on_disable()
            plugin.on_uninstall()

        if self.db is not None:
            row = self.db.query(PluginRow).filter(PluginRow.name == plugin_name).first()
            if row:
                row.enabled = False
                row.available = False
                if remove_data:
                    self.db.delete(row)
                self.db.commit()

        plugin_dir = self.plugins_dir / plugin_name
        if plugin_dir.exists():
            import shutil

            if remove_data:
                shutil.rmtree(plugin_dir)
            else:
                shutil.move(plugin_dir, plugin_dir.with_suffix(".disabled"))

        self.plugin_info.pop(plugin_name, None)
        return True

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin and persist its state."""
        self.sync_plugins()
        if self.db is None:
            plugin = self._instantiate_plugin(plugin_name, fire_enable=True)
            return plugin is not None

        row = self.db.query(PluginRow).filter(PluginRow.name == plugin_name).first()
        if not row or not row.available:
            return False
        row.enabled = True
        self.db.commit()
        self.loaded_plugins.pop(plugin_name, None)
        self._instantiate_plugin(plugin_name, fire_enable=True)
        return True

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin and persist its state."""
        self.sync_plugins()
        if self.db is None:
            plugin = self.loaded_plugins.pop(plugin_name, None)
            if plugin:
                plugin.on_disable()
                return True
            return False

        row = self.db.query(PluginRow).filter(PluginRow.name == plugin_name).first()
        if not row:
            return False
        row.enabled = False
        self.db.commit()
        plugin = self.loaded_plugins.pop(plugin_name, None)
        if plugin:
            plugin.on_disable()
        return True

    def update_plugin_config(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Persist plugin configuration and refresh the in-memory instance."""
        self.sync_plugins()
        if self.db is None:
            info = self.plugin_info.get(plugin_name)
            if not info:
                return False
            info.config = config
            if plugin_name in self.loaded_plugins:
                self.loaded_plugins[plugin_name].config = config
            return True

        row = self.db.query(PluginRow).filter(PluginRow.name == plugin_name).first()
        if not row:
            return False
        stored = self._deserialize_row_data(row)
        manifest = stored.get("manifest", {})
        row.data = self._serialize_row_data(config, manifest)
        row.versionLevel = manifest.get("version", row.versionLevel)
        self.db.commit()
        if plugin_name in self.loaded_plugins:
            self.loaded_plugins[plugin_name].config = config
        self.sync_plugins()
        return True

    # ── Hooks ────────────────────────────────────────────────────────────

    def get_platform_hooks(self) -> List[Dict[str, str]]:
        return [{"name": name, "description": description} for name, description in sorted(PLATFORM_HOOKS.items())]

    def call_plugin_hook(self, hook_name: str, *args, **kwargs) -> List[Dict[str, Any]]:
        """Call one hook on all enabled plugins."""
        if hook_name not in PLATFORM_HOOKS:
            return []

        self.sync_plugins()
        results: List[Dict[str, Any]] = []
        for info in self.plugin_info.values():
            if not info.enabled or not info.available:
                continue
            try:
                plugin = self._instantiate_plugin(info.name, fire_enable=info.name not in self.loaded_plugins)
                if plugin and hasattr(plugin, hook_name):
                    result = getattr(plugin, hook_name)(*args, **kwargs)
                    results.append({"plugin": info.name, "result": result})
            except Exception as exc:
                results.append({"plugin": info.name, "error": str(exc)})
        return results


# Convenience instance for non-request flows that do not need DB persistence.
plugin_service = PluginService()
