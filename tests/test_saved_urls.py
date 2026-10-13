"""Synthetic-only origin parsing and protected-fill regressions."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("proton_urls_under_test", Path(__file__).resolve().parents[1] / "__init__.py")
pp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pp)
A = "https://accounts.example.com"
B = "https://login.example.net"


def origins(raw):
    return pp._valid_origins(pp.ProtonPassLoginBackend._field_values(raw))


@pytest.mark.parametrize("raw, expected", [
    (A, [A]), (A + "/login", [A]),
    (A + ", " + B, [A, B]), (A + "\n" + B, [A, B]),
    ([A, B], [A, B]), (json.dumps([A, B]), [A, B]),
    (json.dumps(A), [A]), (json.dumps([A], indent=2), [A]),
    (A + ", " + A + "/path", [A]),
    ("HTTPS://ACCOUNTS.EXAMPLE.COM:443/a", [A]),
    ("http://localhost:8080/a", ["http://localhost:8080"]),
    (A + "/a,b?x=c,d", [A]),
    (A + "/a,https://other.example", [A]),
    (A + "/?next=https://other.example,a", [A]),
    (json.dumps([A + "/a,b", B + "/?q=c,d"]), [A, B]),
    (A + "/a,b, " + B + "/?x=c,d", [A, B]),
    (A + "/%20?q=%2C", [A]),
])
def test_supported_formats(raw, expected):
    assert origins(raw) == expected


BAD = [
    "https://accounts.example.com, https", A + "," + B,
    A + ",  " + B, A + ",\t" + B, A + "; " + B,
    A + " " + B, A + "\r\n" + B, A + "\n\n" + B,
    " " + A, A + " ", A + "\t", A + "\x00", A + "\x1b[0m",
    A + "/\npath", A + "/\u200b", "https://user:synthetic@example.com",
    "https://@example.com", "https://example.com\\@evil.example",
    "https://example.com:bad", "https://example.com:", "https://example.com:65536",
    "https://example.com:0", "https://example.com:0443", "https://example.com:443junk",
    "https://example.com%2Fevil", "https://example.com,evil", "https://-bad.example",
    "https://example..com", "https://example.com.", "https://exa_mple.com",
    "https:///missing", "//example.com", "javascript:alert(1)",
    A + "/%ZZ", A + "/%0a", A + "/%7f", A + "/%5c",
    "https://127.1", "https://0x7f000001", "https://[::1]",  # unsupported canonicalization: refuse
    '["' + A + '",]', {"urls": [A]}, [A, 3], [A, ""],
    [A, "https://user:synthetic@example.com"], [A, B + "\n" + A],
    [A, B + ", " + A], None, 42,
]


@pytest.mark.parametrize("raw", BAD)
def test_invalid_or_ambiguous_input_fails_closed(raw):
    assert origins(raw) == []


@pytest.fixture
def backend(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(pp, "_handle_key", lambda: b"synthetic-key-not-a-real-credential")
    b = pp.ProtonPassLoginBackend({"allowed_vault_names": [], "allowlisted_items": [{"share_id": "share", "item_id": "item"}]})
    item = {"id": "item", "share_id": "share", "item_type": "login", "state": "active", "title": "Synthetic"}
    monkeypatch.setattr(b, "_connection", lambda: {})
    monkeypatch.setattr(b, "_run_pass", lambda *a, **kw: json.dumps({"items": [item]}))
    b.test_urls = A + ", " + B
    b.test_fields = []

    def field(conn, share_id, item_id, field, **kw):
        b.test_fields.append(field)
        assert (share_id, item_id) == ("share", "item")
        return {"urls": b.test_urls, "username": "synthetic@example.com", "password": "SYNTHETIC_ONLY_SENTINEL"}[field]

    monkeypatch.setattr(b, "_item_field", field)
    return b


def test_multi_origin_handles_revalidate_and_do_not_resolve_for_metadata(backend):
    metas = backend.list_items()
    assert [m.origin for m in metas] == [A, B]
    assert len({m.id for m in metas}) == 2
    assert all(not m.allowed_origins for m in metas)
    assert all(backend.get_meta(m.id) == m for m in metas)
    assert "password" not in backend.test_fields
    assert backend.resolve_password(metas[0].id) == "SYNTHETIC_ONLY_SENTINEL"


def test_removed_origin_and_malformed_saved_urls_revoke_old_handles(backend):
    handle = backend.list_items()[0].id
    backend.test_urls = B
    assert backend.get_meta(handle) is None
    assert backend.resolve_password(handle) == ""
    backend.test_urls = A + ", https"
    assert backend.get_meta(handle) is None
    assert backend.resolve_password(handle) == ""
    assert "password" not in backend.test_fields


@pytest.mark.parametrize("page", [B, "http://accounts.example.com", A + ":8443", "https://child.accounts.example.com", "https://accounts.example.com.evil.test"])
def test_protected_fill_refuses_nonmatching_origin_before_secret(backend, monkeypatch, page):
    import agent.vault_backends as backends
    import tools.browser_vault_tool as vault
    meta = backend.list_items()[0]
    monkeypatch.setattr(backends, "backend_for_handle", lambda handle: backend)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *args: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda *args: page)
    monkeypatch.setattr(vault, "_eval_js", lambda *args: pytest.fail("must not inspect or fill"))
    result = json.loads(vault.browser_vault_fill(meta.id, task_id="synthetic"))
    assert result["error_type"] == "origin_mismatch"
    assert "password" not in backend.test_fields
    assert "SYNTHETIC_ONLY_SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize("navigated", [False, True])
def test_protected_synthetic_fill_keeps_secret_channel_and_atomic_guard(backend, monkeypatch, which, navigated, capsys, caplog):
    import agent.vault_backends as backends
    import tools.browser_vault_tool as vault
    meta = backend.list_items()[which]
    monkeypatch.setattr(backends, "backend_for_handle", lambda handle: backend)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *args: meta.origin)
    controls = [{"autocomplete": "current-password", "formIndex": 0, "index": 0,
                 "label": "", "name": "pw", "type": "password"}]
    monkeypatch.setattr(vault, "_eval_js", lambda *args: {"success": True, "result": json.dumps(controls)})
    secret_calls = []

    def secret_eval(task, expression):
        assert "SYNTHETIC_ONLY_SENTINEL" in expression
        assert "window.location.origin" in expression
        assert json.dumps(meta.origin) in expression
        secret_calls.append(True)
        return {"success": True, "result": json.dumps(
            {"refused": "origin_changed", "found": "https://evil.example"} if navigated else {"filled": 1})}

    monkeypatch.setattr(vault, "_eval_js_secret", secret_eval)
    result = json.loads(vault.browser_vault_fill(meta.id, task_id="synthetic"))
    assert result["success"] is (not navigated)
    if navigated:
        assert result["error_type"] == "origin_changed"
        assert result.get("filled_fields", 0) == 0
    else:
        assert result["filled_fields"] == 1
        assert result["origin"] == meta.origin
    assert secret_calls == [True]
    captured = capsys.readouterr()
    assert "SYNTHETIC_ONLY_SENTINEL" not in json.dumps(result) + captured.out + captured.err + caplog.text


def test_signed_malformed_origin_fails_before_provider_lookup(backend, monkeypatch):
    meta = backend.list_items()[0]
    payload = backend._decode_handle(meta.id)
    payload["origin"] = "https://accounts.example.com, https"
    handle = backend._encode_handle(payload)
    monkeypatch.setattr(backend, "_connection", lambda: pytest.fail("invalid origin reached provider"))
    assert backend.get_meta(handle) is None
