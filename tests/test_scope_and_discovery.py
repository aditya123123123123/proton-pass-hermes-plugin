"""Synthetic scope revocation and real Hermes directory-plugin discovery."""
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("proton_scope_under_test", ROOT / "__init__.py")
pp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pp)
ITEM = {"share_id": "share", "item_id": "item"}


@pytest.fixture
def synthetic(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(pp, "_handle_key", lambda: b"[REDACTED]")
    calls = []
    item = {"id": "item", "share_id": "share", "item_type": "login", "state": "active"}

    def run(conn, args, **kwargs):
        calls.append(args)
        if args[:2] == ["item", "list"]:
            return json.dumps({"items": [item, {**item, "id": "other"}]})
        field = args[args.index("--field") + 1]
        return {"urls": "https://example.com", "username": "synthetic", "password": "[REDACTED]"}[field]

    monkeypatch.setattr(pp.ProtonPassLoginBackend, "_connection", lambda self: {})
    monkeypatch.setattr(pp.ProtonPassLoginBackend, "_run_pass", lambda self, *a, **kw: run(*a, **kw))
    return calls


@pytest.mark.parametrize("cfg", [
    {}, {"allowed_vault_names": []}, {"allowlisted_items": []},
    {"allowed_vault_names": [], "allowlisted_items": []},
    {"allowed_vault_names": None, "allowlisted_items": None},
    {"allowed_vault_names": ["Hermes Access"], "allowlisted_items": []},
])
def test_no_scope_does_not_contact_provider(cfg, synthetic):
    backend = pp.ProtonPassLoginBackend(cfg)
    handle = backend._encode_handle({**ITEM, "origin": "https://example.com", "vault_name": "Hermes Access"})
    assert backend.list_items() == []
    assert backend.get_meta(handle) is None
    assert backend.resolve_password(handle) == ""
    assert synthetic == []


@pytest.mark.parametrize("scope, expected", [
    ({"allowlisted_items": [ITEM]}, 1),
    ({"allowed_vault_names": ["Hermes Access"]}, 2),
    ({"allowed_vault_names": ["Hermes Access"], "allowlisted_items": [ITEM]}, 1),
])
def test_explicit_scopes_work_and_metadata_never_reads_password(scope, expected, synthetic):
    backend = pp.ProtonPassLoginBackend(scope)
    metas = backend.list_items()
    assert len(metas) == expected
    assert all(backend.get_meta(meta.id) == meta for meta in metas)
    assert not any("password" in call for call in synthetic)
    assert backend.resolve_password(metas[0].id) == "[REDACTED]"


@pytest.mark.parametrize("scope", [
    {"allowlisted_items": [ITEM]},
    {"allowed_vault_names": ["Hermes Access"]},
    {"allowed_vault_names": ["Hermes Access"], "allowlisted_items": [ITEM]},
])
@pytest.mark.parametrize("revocation", ["clear", "empty", "different"])
def test_old_handles_revalidate_scope_before_provider(scope, revocation, synthetic):
    scope = dict(scope)  # parametrized mappings must not leak revocation between cases
    backend = pp.ProtonPassLoginBackend(scope)
    handle = backend.list_items()[0].id
    if revocation == "clear":
        scope.clear()
    elif revocation == "empty":
        scope.update(allowed_vault_names=[], allowlisted_items=[])
    else:
        scope.update(allowed_vault_names=["Different"], allowlisted_items=[{**ITEM, "item_id": "different"}])
    synthetic.clear()
    # Test both retained instances and the fresh instances used by core routing.
    for current in (backend, pp.ProtonPassLoginBackend(scope)):
        assert current.get_meta(handle) is None
        assert current.resolve_password(handle) == ""
    assert synthetic == []


@pytest.mark.parametrize("vaults", [[], ["Hermes Access"]])
def test_item_revocation_with_unchanged_vault_scope(vaults, synthetic):
    scope = {"allowed_vault_names": vaults, "allowlisted_items": [ITEM]}
    backend = pp.ProtonPassLoginBackend(scope)
    handle = backend.list_items()[0].id
    scope["allowlisted_items"] = [{**ITEM, "item_id": "different"}]
    synthetic.clear()
    assert backend.get_meta(handle) is None
    assert backend.resolve_password(handle) == ""
    assert synthetic == []


@pytest.mark.parametrize("vaults", ["Hermes Access", [None], [42], [""], [" Hermes Access"], ["Hermes Access\n"]])
def test_malformed_vault_scope_never_reaches_provider(vaults, synthetic):
    backend = pp.ProtonPassLoginBackend({"allowed_vault_names": vaults})
    with pytest.raises(ValueError, match="allowed_vault_names"):
        backend.list_items()
    assert synthetic == []


def test_real_directory_discovery_availability_activation_and_unload(tmp_path, monkeypatch):
    from agent import secret_scope
    from agent.vault_backends.base import backend_for_handle, enabled_backends, is_installed
    from hermes_cli.plugins import PluginManager
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override
    from hermes_yaml import safe_dump

    home = tmp_path / "profile"
    plugin = home / "plugins" / "proton-pass"
    plugin.mkdir(parents=True)
    for filename in ("__init__.py", "plugin.yaml"):
        shutil.copyfile(ROOT / filename, plugin / filename)
    binary = home / "fake-pass-cli"
    binary.write_text("#!/bin/sh\nexit 99\n")
    binary.chmod(0o700)
    connection = home / "proton-pass" / "connection.json"
    connection.parent.mkdir()
    connection.write_text(json.dumps({"binary": str(binary)}))
    config = {"plugins": {"enabled": ["proton-pass"]}, "vault": {
        "onepassword": {"enabled": False}, "bitwarden": {"enabled": False},
        "protonpass": {"allowlisted_items": [ITEM]},
    }}
    config_path = home / "config.yaml"
    config_path.write_text(safe_dump(config))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(home))
    home_token = set_hermes_home_override(home)
    secret_token = secret_scope.set_secret_scope({})
    manager = PluginManager()
    try:
        manager.discover_and_load()
        assert is_installed("protonpass") is True
        assert backend_for_handle("pp:synthetic") is None  # backend is default-off
        config["vault"]["protonpass"]["enabled"] = True
        config_path.write_text(safe_dump(config))
        backend = backend_for_handle("pp:synthetic")
        assert backend is not None
        assert backend.name == "protonpass"
        assert backend.cfg["allowlisted_items"] == [ITEM]
        assert "protonpass" in [b.name for b in enabled_backends()]
        # Core re-reads profile policy when routing a previously issued handle.
        module = __import__(type(backend).__module__, fromlist=["_handle_key"])
        monkeypatch.setattr(module, "_handle_key", lambda: b"[REDACTED]")
        stale = backend._encode_handle({**ITEM, "origin": "https://example.com", "vault_name": ""})
        config["vault"]["protonpass"] = {"enabled": True}
        config_path.write_text(safe_dump(config))
        revoked = backend_for_handle(stale)
        assert revoked is not None
        monkeypatch.setattr(revoked, "_connection", lambda: pytest.fail("revoked scope reached provider"))
        assert revoked.list_items() == []
        assert revoked.get_meta(stale) is None
        assert revoked.resolve_password(stale) == ""
        config["vault"]["protonpass"]["enabled"] = False
        config_path.write_text(safe_dump(config))
        assert backend_for_handle(stale) is None
        # Availability performs local metadata checks only: never runs the CLI.
        binary.unlink()
        assert is_installed("protonpass") is False
        assert backend_for_handle("pp:synthetic") is None
    finally:
        manager.unload()
        secret_scope.reset_secret_scope(secret_token)
        reset_hermes_home_override(home_token)
    from agent.vault_backends.registry import list_backend_classes
    assert not any(b.name == "protonpass" for b in list_backend_classes(scope=str(home.resolve())))
