"""Synthetic CLI -> Proton adapter -> protected fill recovery acceptance."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

SPEC = importlib.util.spec_from_file_location("proton_recovery_under_test", Path(__file__).resolve().parents[1] / "__init__.py")
pp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pp)


@pytest.fixture
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(pp, "_handle_key", lambda: b"[REDACTED]")
    cli = tmp_path / "fake-pass-cli"
    code = '''import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["PROTON_PASS_SESSION_DIR"])
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps(args) + "\\n")
if args == ["info"]:
    if not (root / "authenticated").exists():
        print("This operation requires an authenticated client; Command is not logout there is no session", file=sys.stderr)
        sys.exit(1)
    print("synthetic session")
elif args == ["login"]:
    assert os.environ["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] == "[REDACTED]"
    (root / "authenticated").touch()
    print("synthetic login")
elif args[:2] == ["item", "list"]:
    assert "--share-id=-synthetic-share" in args
    assert "--filter-type" in args and "--filter-state" in args
    print(json.dumps({"items": [{"id": "-synthetic-item", "share_id": "-synthetic-share", "item_type": "login", "state": "active", "title": "Synthetic"}]}))
elif args[:2] == ["item", "view"]:
    assert "--share-id=-synthetic-share" in args and "--item-id=-synthetic-item" in args
    field = args[args.index("--field") + 1]
    print({"urls": "http://127.0.0.1:18764", "username": "synthetic-user", "password": "  [REDACTED]  "}[field])
else:
    sys.exit(2)
'''
    compile(code, str(cli), "exec")
    cli.write_text("#!" + sys.executable + "\n" + code)
    cli.chmod(0o700)
    conn = {"binary": str(cli)}
    b = pp.ProtonPassLoginBackend({"allowed_vault_names": [], "allowlisted_items": [{"share_id": "-synthetic-share", "item_id": "-synthetic-item"}]})
    monkeypatch.setattr(b, "_connection", lambda: conn)
    monkeypatch.setattr(pp, "get_secret_str", lambda name: "[REDACTED]")
    b.test_calls = []
    original_run_once = b._run_once
    def record_run_once(*args, **kwargs):
        b.test_calls.append(args[1])
        return original_run_once(*args, **kwargs)
    monkeypatch.setattr(b, "_run_once", record_run_once)
    return b, conn, tmp_path


def test_expired_session_recovers_through_cli_and_protected_fill(backend, monkeypatch, capsys, caplog):
    b, conn, root = backend
    import agent.vault_backends as backends
    import tools.browser_vault_tool as vault
    metas = b.list_items()
    assert len(metas) == 1
    meta = metas[0]
    assert meta.origin == "http://127.0.0.1:18764"
    # Each provider operation gets a fresh temporary CLI session and therefore
    # authenticates independently; no vendor session is reused across calls.
    assert b.test_calls.count(["login"]) == 3
    assert not any("password" in call for call in b.test_calls)
    monkeypatch.setattr(backends, "backend_for_handle", lambda h: b)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, origin_match: meta.origin)
    monkeypatch.setattr(vault, "_eval_js", lambda *a: {"success": True, "result": json.dumps([{"type": "password", "autocomplete": "current-password", "name": "password", "index": 0, "formIndex": 0}])})
    sent = []
    def secret_eval(task, expression):
        assert "  [REDACTED]  " in expression
        assert "window.location.origin" in expression
        assert json.dumps(meta.origin) in expression
        sent.append(True)
        return {"success": True, "result": json.dumps({"filled": 1})}
    monkeypatch.setattr(vault, "_eval_js_secret", secret_eval)
    result = json.loads(vault.browser_vault_fill(meta.id, task_id="synthetic"))
    assert result["success"] is True and result["filled_fields"] == 1
    assert sent == [True]
    captured = capsys.readouterr()
    output = json.dumps(result) + captured.out + captured.err + caplog.text
    assert "[REDACTED]" not in output


def test_wrong_origin_refuses_before_cli_secret_read(backend, monkeypatch):
    b, conn, root = backend
    import agent.vault_backends as backends
    import tools.browser_vault_tool as vault
    meta = b.list_items()[0]
    monkeypatch.setattr(backends, "backend_for_handle", lambda h: b)
    monkeypatch.setattr(vault, "_focus_bound_origin", lambda *a, origin_match: None)
    monkeypatch.setattr(vault, "_current_page_origin", lambda *a: "http://127.0.0.1:18765")
    monkeypatch.setattr(vault, "_eval_js_secret", lambda *a: pytest.fail("wrong origin reached fill"))
    result = json.loads(vault.browser_vault_fill(meta.id, task_id="synthetic"))
    assert result["error_type"] == "origin_mismatch"
    assert not any("password" in call for call in b.test_calls)


@pytest.mark.parametrize("error", ["permission denied [REDACTED]", "network unavailable [REDACTED]"])
def test_non_auth_failure_does_not_reauthenticate(backend, monkeypatch, error):
    b, conn, root = backend
    calls = []
    def run(c, args, **kw):
        calls.append(args)
        if args == ["login"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 1, "", error)
    monkeypatch.setattr(b, "_run_once", run)
    with pytest.raises(RuntimeError) as raised:
        b.list_items()
    assert "[REDACTED]" not in str(raised.value)
    assert calls.count(["login"]) == 1


def test_failed_recovery_is_bounded_and_redacted(backend, monkeypatch):
    b, conn, root = backend
    calls = []
    def run(c, args, **kw):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "requires an authenticated client [REDACTED]")
    monkeypatch.setattr(b, "_run_once", run)
    with pytest.raises(RuntimeError) as raised:
        b.list_items()
    assert calls == [["login"]]
    assert "[REDACTED]" not in str(raised.value)
