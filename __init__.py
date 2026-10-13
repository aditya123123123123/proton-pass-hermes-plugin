"""Local Proton Pass login backend for Hermes browser vault autofill."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from agent.secret_sources.base import scrub_ansi
from agent.secret_scope import get_secret_str
from agent.vault_backends.base import LoginBackend
from agent.vault_store import VaultError, VaultItemMeta, normalize_origin
from hermes_constants import get_hermes_home

_TIMEOUT = 30.0
_ENV_KEEP = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "SystemRoot",
    "SYSTEMROOT",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)
_AUTH_MARKERS = (
    "requires an authenticated client",
    "not authenticated",
    "unauthenticated",
    "session expired",
    "invalid session",
    "no session",
)



def register(ctx) -> None:
    ctx.register_login_backend(ProtonPassLoginBackend)


class ProtonPassLoginBackend(LoginBackend):
    name = "protonpass"
    display_name = "Proton Pass"
    prefix = "pp:"
    needs_unlock = False
    enabled_by_default = False

    def __init__(self, cfg: Optional[Dict[str, Any]] = None):
        self.cfg = cfg or {}
        self._allowlisted_items = _parse_allowlisted_items(self.cfg.get("allowlisted_items", None))

    @classmethod
    def is_installed(cls, cfg: Optional[Dict[str, Any]] = None) -> bool:
        try:
            cfg = cfg or {}
            conn = _connection_file_from_cfg(cfg)
            if not conn.is_file():
                return False
            data = _load_json_file(conn)
            binary = str(cfg.get("binary_path") or data.get("binary") or "").strip()
            if binary:
                return Path(binary).is_file()
            return shutil.which("pass-cli") is not None
        except Exception:
            return False

    def owns(self, handle: str) -> bool:
        return handle.startswith(self.prefix)

    def list_items(self) -> List[VaultItemMeta]:
        if self._allowlisted_items == set():
            return []
        conn = self._connection()
        out: List[VaultItemMeta] = []
        vault_names = self._allowed_vault_names()
        if not vault_names and self._allowlisted_items:
            for share_id, item_ids in self._allowlisted_item_ids_by_share():
                try:
                    items = self._list_active_login_items_for_share(conn, share_id)
                except RuntimeError:
                    raise RuntimeError("Proton Pass metadata listing failed; check connection and exact-item access") from None
                for item in items:
                    if str(item.get("id") or "") in item_ids:
                        out.extend(self._metadata_for_item(conn, "", item))
            return out
        for vault_name in vault_names:
            for item in self._list_active_login_items_for_vault(conn, vault_name):
                out.extend(self._metadata_for_item(conn, vault_name, item))
        return out

    def get_meta(self, handle: str) -> Optional[VaultItemMeta]:
        if self._allowlisted_items == set():
            return None
        payload = self._decode_handle(handle)
        if payload is None:
            return None
        conn = self._connection()
        item = self._listed_active_item(conn, str(payload.get("vault_name") or ""), str(payload.get("share_id") or ""), str(payload.get("item_id") or ""))
        if item is None:
            return None
        metas = self._metadata_for_item(conn, str(payload.get("vault_name") or ""), item)
        return next((m for m in metas if m.origin == payload.get("origin") and m.id == handle), None)

    def resolve_password(self, handle: str) -> str:
        payload = self._decode_handle(handle)
        if payload is None:
            return ""
        meta = self.get_meta(handle)
        if meta is None:
            return ""
        conn = self._connection()
        return self._item_field(
            conn,
            str(payload.get("share_id") or ""),
            str(payload.get("item_id") or ""),
            "password",
            reason=f"filling saved password on {meta.origin}",
        )

    def resolve_otp(self, handle: str) -> Optional[str]:
        return None

    def _connection(self) -> dict[str, Any]:
        conn_file = _connection_file_from_cfg(self.cfg)
        if not conn_file.is_file():
            raise RuntimeError("Proton Pass connection is not configured")
        conn = _load_json_file(conn_file)
        binary = str(self.cfg.get("binary_path") or conn.get("binary") or "").strip()
        if not binary:
            binary = shutil.which("pass-cli") or ""
        if not binary or not Path(binary).is_file():
            raise RuntimeError("Proton Pass CLI is not available")
        conn["binary"] = binary
        return conn

    def _allowed_vault_names(self) -> List[str]:
        raw = self.cfg.get("allowed_vault_names")
        if isinstance(raw, list):
            names = [str(v).strip() for v in raw if str(v).strip()]
            return names
        else:
            names = []
        return names or ["Hermes Access"]

    def _metadata_for_item(self, conn: dict[str, Any], vault_name: str, item: dict[str, Any]) -> List[VaultItemMeta]:
        item_id = item.get("id")
        share_id = item.get("share_id")
        if not _valid_opaque_id(item_id) or not _valid_opaque_id(share_id):
            return []
        url_values = self._field_values(
            self._item_field(
                conn,
                share_id,
                item_id,
                "urls",
                reason=f"listing website identity for Proton Pass item {item_id}",
            )
        )
        origins = _valid_origins(url_values)
        if not origins:
            return []
        username = self._optional_identity_field(conn, share_id, item_id)
        label = str(item.get("title") or origins[0])
        created = str(item.get("create_time") or item.get("created_at") or "")
        metas: List[VaultItemMeta] = []
        for origin in origins:
            handle = self._encode_handle(
                {
                    "item_id": item_id,
                    "share_id": share_id,
                    "vault_id": item.get("vault_id"),
                    "vault_name": vault_name,
                    "origin": origin,
                    "label": label,
                    "created_at": created,
                }
            )
            metas.append(
                VaultItemMeta(
                    id=handle,
                    kind="login",
                    label=label,
                    origin=origin,
                    created_at=created,
                    identifier_type="username" if username else None,
                    identifier=username,
                )
            )
        return metas

    def _listed_active_item(self, conn: dict[str, Any], vault_name: str, share_id: str, item_id: str) -> Optional[dict[str, Any]]:
        if not vault_name and self._allowlisted_items is not None:
            if not self._item_allowed({"id": item_id, "share_id": share_id}):
                return None
            try:
                items = self._list_active_login_items_for_share(conn, share_id)
            except RuntimeError:
                return None
            for item in items:
                if str(item.get("id") or "") == item_id:
                    return item
            return None
        if not vault_name or vault_name not in self._allowed_vault_names():
            return None
        for item in self._list_active_login_items_for_vault(conn, vault_name):
            if str(item.get("id") or "") == item_id and str(item.get("share_id") or "") == share_id:
                return item
        return None

    def _list_active_login_items_for_share(self, conn: dict[str, Any], share_id: str) -> List[dict[str, Any]]:
        return self._list_active_login_items(
            conn,
            [
                "item",
                "list",
                f"--share-id={share_id}",
                "--filter-type",
                "login",
                "--filter-state",
                "active",
                "--output",
                "json",
            ],
            reason=f"listing website identity metadata from Proton Pass share {share_id}",
            expected_share_id=share_id,
        )

    def _list_active_login_items_for_vault(self, conn: dict[str, Any], vault_name: str) -> List[dict[str, Any]]:
        return self._list_active_login_items(
            conn,
            [
                "item",
                "list",
                vault_name,
                "--filter-type",
                "login",
                "--filter-state",
                "active",
                "--output",
                "json",
            ],
            reason=f"listing website identity metadata from Proton Pass vault {vault_name}",
        )

    def _list_active_login_items(
        self,
        conn: dict[str, Any],
        args: List[str],
        *,
        reason: str,
        expected_share_id: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        raw = self._run_pass(conn, args, reason=reason)
        parsed = _loads_json(raw)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
            raise RuntimeError("Proton Pass returned an invalid item list")
        out: List[dict[str, Any]] = []
        for item in parsed["items"]:
            if not isinstance(item, dict):
                continue
            if expected_share_id is not None and str(item.get("share_id") or "") != expected_share_id:
                continue
            if not _valid_opaque_id(item.get("id")) or not _valid_opaque_id(item.get("share_id")):
                continue
            if str(item.get("item_type") or "").lower() != "login":
                continue
            if str(item.get("state") or "").lower() not in {"1", "active"}:
                continue
            if not self._item_allowed(item):
                continue
            out.append(item)
        return out

    def _allowlisted_item_ids_by_share(self) -> List[tuple[str, set[str]]]:
        grouped: dict[str, set[str]] = {}
        for share_id, item_id in sorted(self._allowlisted_items or set()):
            grouped.setdefault(share_id, set()).add(item_id)
        return sorted(grouped.items())

    def _item_allowed(self, item: dict[str, Any]) -> bool:
        if self._allowlisted_items is None:
            return True
        return (str(item.get("share_id") or ""), str(item.get("id") or "")) in self._allowlisted_items

    def _item_field(self, conn: dict[str, Any], share_id: str, item_id: str, field: str, *, reason: str) -> str:
        argv = ["item", "view", f"--share-id={share_id}", f"--item-id={item_id}", "--field", field]
        return self._run_pass(conn, argv, reason=reason)

    def _optional_identity_field(self, conn: dict[str, Any], share_id: str, item_id: str) -> Optional[str]:
        for field in ("username", "email"):
            try:
                value = self._item_field(
                    conn,
                    share_id,
                    item_id,
                    field,
                    reason=f"listing website identity for Proton Pass item {item_id}",
                )
            except _MissingField:
                continue
            return value.strip() or None
        return None

    @staticmethod
    def _field_values(raw: Any) -> List[str]:
        """Decode URL-field framing only; never coerce or repair saved URLs.

        pass-cli renders URL arrays with ', '. LF-delimited legacy output and
        JSON/native string lists are also accepted. Bare commas are URL data,
        not separators. Ambiguous framing fails closed; unsupported schemes
        from raw CLI output are ignored and never surfaced as origins.
        """
        raw_legacy_framed = False
        if isinstance(raw, str):
            if raw.lstrip().startswith(('[', '"', '{')):
                try:
                    raw = json.loads(raw)
                except (ValueError, TypeError):
                    return []
                values = [raw] if isinstance(raw, str) else raw
            else:
                if "\r" in raw or "\n\n" in raw:
                    return []
                raw_legacy_framed = True
                values = [value for line in raw.split('\n') for value in line.split(', ')]
        else:
            values = raw
        if not isinstance(values, list) or not values:
            return []
        if raw_legacy_framed:
            kept = []
            for value in values:
                if _discardable_unsupported_scheme(value):
                    continue
                kept.append(value)
            values = kept
            if not values:
                return []
        if any(_strict_saved_origin(value) is None for value in values):
            return []
        return values

    @staticmethod
    def _field_scalar(raw: str) -> str:
        parsed = _loads_json(raw)
        if isinstance(parsed, str):
            return parsed
        if parsed is None:
            return ""
        return str(parsed)

    def _run_pass(self, conn: dict[str, Any], args: List[str], *, reason: str) -> str:
        token = get_secret_str("PROTON_PASS_PERSONAL_ACCESS_TOKEN")
        if not token:
            raise RuntimeError("Proton Pass personal access token is not configured in Hermes")
        with tempfile.TemporaryDirectory(prefix="hermes-proton-pass-") as session_dir:
            session_conn = dict(conn)
            session_conn["session_dir"] = session_dir
            try:
                login = self._run_once(
                    session_conn,
                    ["login"],
                    reason=_reason("authenticating Proton Pass for this autofill operation"),
                    pat_token=token,
                    login=True,
                )
                if login.returncode != 0:
                    raise RuntimeError("Proton Pass authentication failed")
                proc = self._run_once(session_conn, args, reason=_reason(reason))
            finally:
                token = ""
            if proc.returncode == 0:
                return proc.stdout or ""
            if _is_missing_field(proc.stderr):
                raise _MissingField()
            if _looks_auth_error(proc.stderr):
                raise RuntimeError("Proton Pass authentication failed")
            raise RuntimeError("Proton Pass command failed")

    def _run_once(
        self,
        conn: dict[str, Any],
        args: List[str],
        *,
        reason: str,
        pat_token: Optional[str] = None,
        login: bool = False,
    ) -> subprocess.CompletedProcess:
        env = _minimal_env()
        env["NO_COLOR"] = "1"
        env["PROTON_PASS_SESSION_DIR"] = str(conn.get("session_dir") or "")
        env["PROTON_PASS_AGENT_REASON"] = _reason(reason)
        if login and pat_token is not None:
            env["PROTON_PASS_PERSONAL_ACCESS_TOKEN"] = pat_token
        try:
            proc = subprocess.run(  # noqa: S603
                [str(conn["binary"]), *args],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Proton Pass command timed out") from None
        except OSError:
            raise RuntimeError("Proton Pass command failed to start") from None
        proc.stderr = scrub_ansi((proc.stderr or b"").decode("utf-8", errors="replace"))
        proc.stdout = _remove_one_lf((proc.stdout or b"").decode("utf-8", errors="replace"))
        return proc

    def _encode_handle(self, payload: dict[str, Any]) -> str:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = _b64(body)
        sig = hmac.new(_handle_key(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{self.prefix}{encoded}.{sig}"

    def _decode_handle(self, handle: str) -> Optional[dict[str, Any]]:
        if not handle.startswith(self.prefix):
            return None
        rest = handle[len(self.prefix):]
        if "." not in rest:
            return None
        encoded, sig = rest.rsplit(".", 1)
        expected = hmac.new(_handle_key(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            payload = json.loads(_unb64(encoded).decode("utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        origin = _strict_saved_origin(payload.get("origin"))
        if origin is None or origin != payload.get("origin"):
            return None
        if not _valid_opaque_id(payload.get("item_id")):
            return None
        if not _valid_opaque_id(payload.get("share_id")):
            return None
        return payload


class _MissingField(Exception):
    pass


def _connection_file_from_cfg(cfg: Dict[str, Any]) -> Path:
    configured = str((cfg or {}).get("connection_file") or "").strip()
    return _resolve_profile_path(configured or "proton-pass/connection.json")


def _resolve_profile_path(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return get_hermes_home() / path


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("Proton Pass connection file is invalid") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Proton Pass connection file is invalid")
    return parsed


def _minimal_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _ENV_KEEP if k in os.environ}


def _looks_auth_error(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _AUTH_MARKERS)


def _is_missing_field(text: str) -> bool:
    lowered = (text or "").lower()
    return "field does not exist:" in lowered


def _loads_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception as exc:
        raise RuntimeError("Proton Pass returned invalid JSON") from exc


def _strict_saved_origin(value: Any) -> Optional[str]:
    """Validate before urlsplit/normalize_origin can discard unsafe syntax.

    Deliberately restrict to ASCII DNS names and canonical IPv4: the host's
    normalizer does not preserve IPv6 brackets, and browser IDNA/numeric-host
    normalization must not silently create a different origin here.
    """
    if not isinstance(value, str) or not value or not value.isascii():
        return None
    if any(not c.isprintable() or c.isspace() for c in value):
        return None
    if any(c in value for c in '\\<>"{}|^`'):
        return None
    if re.search(r'%(?![0-9a-fA-F]{2})', value):
        return None
    if any(int(m, 16) < 32 or int(m, 16) in (127, 92)
           for m in re.findall(r'%([0-9a-fA-F]{2})', value)):
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme not in {'http', 'https'} or not parts.netloc or '@' in parts.netloc:
            return None
        # No escaped hosts, userinfo, ambiguous commas, IPv6 or empty ports.
        authority = re.fullmatch(r'([A-Za-z0-9.-]+)(?::([1-9][0-9]{0,4}))?', parts.netloc)
        if authority is None:
            return None
        host, port = authority.groups()
        if port is not None and int(port) > 65535:
            return None
        if len(host) > 253 or any(
            re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) is None
            for label in host.split('.')
        ):
            return None
        # WHATWG treats numeric final labels as IPv4, including hex/short forms.
        last = host.rsplit('.', 1)[-1]
        if last.isdigit() or re.fullmatch(r'0[xX][0-9a-fA-F]+', last):
            if str(ipaddress.IPv4Address(host)) != host:
                return None
        return normalize_origin(value)
    except (ValueError, VaultError):
        return None


def _discardable_unsupported_scheme(value: Any) -> bool:
    if not isinstance(value, str) or not value or not value.isascii():
        return False
    if any(not c.isprintable() or c.isspace() for c in value):
        return False
    if any(c in value for c in '\\<>"{}|^`,'):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return bool(parts.scheme) and parts.scheme not in {'http', 'https'}


def _valid_origins(urls: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for url in urls:
        origin = _strict_saved_origin(url)
        if origin is None:
            return []
        if origin not in seen:
            seen.add(origin)
            out.append(origin)
    return out


def _valid_opaque_id(value: Any) -> bool:
    # Preserve opaque provider bytes, including leading '-'; never coerce or trim.
    return isinstance(value, str) and bool(value) and all(
        char.isprintable() and not char.isspace() for char in value
    )


def _parse_allowlisted_items(raw: Any) -> Optional[set[tuple[str, str]]]:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ValueError("vault.protonpass.allowlisted_items must be a list")
    out: set[tuple[str, str]] = set()
    for row in raw:
        if not isinstance(row, dict) or set(row) != {"share_id", "item_id"}:
            raise ValueError("vault.protonpass.allowlisted_items entries must contain only share_id and item_id")
        share_id = row.get("share_id")
        item_id = row.get("item_id")
        if not _valid_opaque_id(share_id) or not _valid_opaque_id(item_id):
            raise ValueError("vault.protonpass.allowlisted_items IDs must be non-empty strings without whitespace or control characters")
        out.add((share_id, item_id))
    return out


def _remove_one_lf(value: str) -> str:
    return value[:-1] if value.endswith("\n") else value


def _handle_key() -> bytes:
    root = get_hermes_home() / "proton-pass"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "handle.key"
    if path.exists():
        return path.read_bytes()
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _reason(text: str) -> str:
    clean = " ".join(str(text or "").split())
    return clean[:300] or "Proton Pass browser autofill"
