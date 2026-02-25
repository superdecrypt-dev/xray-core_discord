import base64
import grp
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import string
import tarfile
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..utils.locks import file_lock

ACCOUNT_ROOT = Path("/opt/account")
QUOTA_ROOT = Path("/opt/quota")
SPEED_POLICY_ROOT = Path("/opt/speed")
SPEED_CONFIG_FILE = Path("/etc/xray-speed/config.json")
XRAY_CONFDIR = Path("/usr/local/etc/xray/conf.d")
XRAY_INBOUNDS_CONF = XRAY_CONFDIR / "10-inbounds.json"
XRAY_OUTBOUNDS_CONF = XRAY_CONFDIR / "20-outbounds.json"
XRAY_ROUTING_CONF = XRAY_CONFDIR / "30-routing.json"
XRAY_DNS_CONF = XRAY_CONFDIR / "02-dns.json"
NGINX_CONF = Path("/etc/nginx/conf.d/xray.conf")
XRAY_DOMAIN_FILE = Path("/etc/xray/domain")
CERT_DIR = Path("/opt/cert")
CERT_FULLCHAIN = CERT_DIR / "fullchain.pem"
CERT_PRIVKEY = CERT_DIR / "privkey.pem"
WORK_DIR = Path(os.getenv("BOT_STATE_DIR", "/var/lib/xray-telegram-bot")) / "tmp"
ROUTING_LOCK_FILE = "/var/lock/xray-routing.lock"
SPEED_POLICY_LOCK_FILE = "/var/lock/xray-speed-policy.lock"
PROTOCOLS = ("vless", "vmess", "trojan")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DOMAIN_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
SPEED_OUTBOUND_TAG_PREFIX = "speed-mark-"
SPEED_RULE_MARKER_PREFIX = "dummy-speed-user-"
SPEED_MARK_MIN = 1000
SPEED_MARK_MAX = 59999
QUOTA_UNIT_DECIMAL = {"decimal", "gb", "1000", "gigabyte"}
BALANCER_EGRESS_TAG = "egress-balance"
BALANCER_ALLOWED_STRATEGIES = {"random", "roundRobin", "leastPing", "leastLoad"}
DEFAULT_EGRESS_PORTS = {"1-65535", "0-65535"}
DNS_LOCK_FILE = "/var/lock/xray-dns.lock"
DNS_QUERY_STRATEGY_ALLOWED = {"UseIP", "UseIPv4", "UseIPv6", "PreferIPv4", "PreferIPv6"}
CLOUDFLARE_API_TOKEN = os.getenv(
    "CLOUDFLARE_API_TOKEN",
    "ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ",
).strip()
PROVIDED_ROOT_DOMAINS = (
    "vyxara1.web.id",
    "vyxara2.web.id",
    "vyxara1.qzz.io",
    "vyxara2.qzz.io",
)
ACME_SH_INSTALL_REF = os.getenv("ACME_SH_INSTALL_REF", "f39d066ced0271d87790dc426556c1e02a88c91b").strip()
ACME_SH_TARBALL_URL = f"https://codeload.github.com/acmesh-official/acme.sh/tar.gz/{ACME_SH_INSTALL_REF}"
ACME_SH_SCRIPT_URL = f"https://raw.githubusercontent.com/acmesh-official/acme.sh/{ACME_SH_INSTALL_REF}/acme.sh"
ACME_SH_DNS_CF_HOOK_URL = (
    f"https://raw.githubusercontent.com/acmesh-official/acme.sh/{ACME_SH_INSTALL_REF}/dnsapi/dns_cf.sh"
)


def _run_cmd(
    argv: list[str],
    timeout: int = 25,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[bool, str]:
    try:
        proc = shutil.which(argv[0])
        if proc is None:
            return False, f"Command tidak ditemukan: {argv[0]}"
        import subprocess

        cp = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            cwd=cwd,
        )
    except Exception as exc:
        return False, f"Gagal menjalankan {' '.join(argv)}: {exc}"

    out = ((cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")).strip()
    if not out:
        out = "(no output)"
    if cp.returncode != 0:
        return False, f"[exit {cp.returncode}]\n{out}"
    return True, out


def _service_exists(name: str) -> bool:
    ok, _ = _run_cmd(["systemctl", "status", name], timeout=10)
    if ok:
        return True
    ok2, out2 = _run_cmd(["systemctl", "list-unit-files", f"{name}.service"], timeout=10)
    if not ok2:
        return False
    return f"{name}.service" in out2


def _service_is_active(name: str) -> bool:
    ok, out = _run_cmd(["systemctl", "is-active", name], timeout=10)
    if not ok:
        return False
    state = out.splitlines()[-1].strip() if out else ""
    return state == "active"


def _restart_and_wait(name: str, timeout_sec: int = 20) -> bool:
    _run_cmd(["systemctl", "restart", name], timeout=30)
    end = time.time() + max(1, timeout_sec)
    while time.time() < end:
        if _service_is_active(name):
            return True
        time.sleep(0.5)
    if _service_is_active(name):
        return True

    # Recovery path for rapid restart bursts (systemd start-limit-hit).
    _run_cmd(["systemctl", "reset-failed", name], timeout=10)
    _run_cmd(["systemctl", "start", name], timeout=30)
    end2 = time.time() + max(1, timeout_sec)
    while time.time() < end2:
        if _service_is_active(name):
            return True
        time.sleep(0.5)
    return _service_is_active(name)


def _read_json(path: Path) -> tuple[bool, Any]:
    if not path.exists():
        return False, f"File tidak ditemukan: {path}"
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Gagal parse JSON {path}: {exc}"


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = path.stat()
    except Exception:
        previous = None
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=path.suffix or ".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
            json.dump(payload, wf, ensure_ascii=False, indent=2)
            wf.write("\n")
            wf.flush()
            os.fsync(wf.fileno())
        os.replace(tmp, path)
        if previous is not None:
            try:
                os.chmod(path, previous.st_mode & 0o777)
            except Exception:
                pass
            try:
                os.chown(path, previous.st_uid, previous.st_gid)
            except Exception:
                pass
        if path.parent == XRAY_CONFDIR:
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
            try:
                xray_gid = grp.getgrnam("xray").gr_gid
                os.chown(path, 0, xray_gid)
            except Exception:
                pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        previous = path.stat()
    except Exception:
        previous = None
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=path.suffix or ".txt", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
            wf.write(content)
            wf.flush()
            os.fsync(wf.fileno())
        os.replace(tmp, path)
        if previous is not None:
            try:
                os.chmod(path, previous.st_mode & 0o777)
            except Exception:
                pass
            try:
                os.chown(path, previous.st_uid, previous.st_gid)
            except Exception:
                pass
        if path.parent == XRAY_CONFDIR:
            try:
                os.chmod(path, 0o640)
            except Exception:
                pass
            try:
                xray_gid = grp.getgrnam("xray").gr_gid
                os.chown(path, 0, xray_gid)
            except Exception:
                pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def _chmod_600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except Exception:
        pass


def _ensure_runtime_dirs() -> None:
    for p in [
        ACCOUNT_ROOT / "vless",
        ACCOUNT_ROOT / "vmess",
        ACCOUNT_ROOT / "trojan",
        QUOTA_ROOT / "vless",
        QUOTA_ROOT / "vmess",
        QUOTA_ROOT / "trojan",
        SPEED_POLICY_ROOT / "vless",
        SPEED_POLICY_ROOT / "vmess",
        SPEED_POLICY_ROOT / "trojan",
        WORK_DIR,
    ]:
        p.mkdir(parents=True, exist_ok=True)


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip()
        if not s:
            return default
        return int(float(s))
    except Exception:
        return default


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return float(int(v))
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).strip().lower().replace("mbit", "").replace("mbps", "")
        if not s:
            return default
        return float(s)
    except Exception:
        return default


def _fmt_number(v: float) -> str:
    if v <= 0:
        return "0"
    if abs(v - round(v)) < 1e-9:
        return str(int(round(v)))
    return f"{v:.3f}".rstrip("0").rstrip(".")


def _fmt_quota_gb_from_bytes(quota_bytes: int) -> str:
    if quota_bytes <= 0:
        return "0"
    return _fmt_number(quota_bytes / (1024**3))


def _is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def _email(proto: str, username: str) -> str:
    return f"{username}@{proto}"


def _detect_public_ipv4() -> str:
    ok, out = _run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"], timeout=8)
    if ok:
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if m:
            return m.group(1)
    return "0.0.0.0"


def _detect_domain() -> str:
    if NGINX_CONF.exists():
        for line in NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+);", line)
            if m:
                token = m.group(1).strip().split()[0]
                if token and token != "_":
                    return token
    ok, fqdn = _run_cmd(["hostname", "-f"], timeout=8)
    if ok and fqdn.strip():
        return fqdn.splitlines()[0].strip()
    ok2, host = _run_cmd(["hostname"], timeout=8)
    if ok2 and host.strip():
        return host.splitlines()[0].strip()
    return "-"


def _parse_date_only(raw: Any) -> date | None:
    s = str(raw or "").strip()[:10]
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def _status_lock_reason(status: dict[str, Any]) -> str:
    if bool(status.get("manual_block")):
        return "manual"
    if bool(status.get("quota_exhausted")):
        return "quota"
    if bool(status.get("ip_limit_locked")):
        return "ip_limit"
    return ""


def _status_apply_lock_fields(status: dict[str, Any]) -> None:
    reason = _status_lock_reason(status)
    status["lock_reason"] = reason
    if reason:
        status["locked_at"] = str(status.get("locked_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    else:
        status["locked_at"] = ""


def _account_candidates(proto: str, username: str) -> list[Path]:
    return [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
    ]


def _quota_candidates(proto: str, username: str) -> list[Path]:
    return [
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]


def _resolve_existing(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.exists():
            return p
    return None


def _load_quota(proto: str, username: str) -> tuple[bool, Path | str, dict[str, Any] | str]:
    target = _resolve_existing(_quota_candidates(proto, username))
    if target is None:
        return False, f"File quota tidak ditemukan untuk {username} [{proto}]", ""
    ok, payload = _read_json(target)
    if not ok:
        return False, str(payload), ""
    if not isinstance(payload, dict):
        return False, f"Format quota tidak valid: {target}", ""
    return True, target, payload


def _save_quota(path: Path, payload: dict[str, Any]) -> None:
    _write_json_atomic(path, payload)
    _chmod_600(path)


def _extract_username_from_file_name(path: Path, proto: str) -> str:
    stem = path.stem
    suffix = f"@{proto}"
    if stem.endswith(suffix):
        return stem[: -len(suffix)]
    return stem


def _username_exists_anywhere(username: str) -> tuple[bool, str]:
    needle = username.strip().lower()

    for proto in PROTOCOLS:
        acc_dir = ACCOUNT_ROOT / proto
        if acc_dir.exists():
            for p in acc_dir.glob("*.txt"):
                if _extract_username_from_file_name(p, proto).lower() == needle:
                    return True, f"account:{proto}:{p.name}"
        q_dir = QUOTA_ROOT / proto
        if q_dir.exists():
            for p in q_dir.glob("*.json"):
                if _extract_username_from_file_name(p, proto).lower() == needle:
                    return True, f"quota:{proto}:{p.name}"

    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if ok and isinstance(payload, dict):
        inbounds = payload.get("inbounds", [])
        if isinstance(inbounds, list):
            for ib in inbounds:
                if not isinstance(ib, dict):
                    continue
                proto = str(ib.get("protocol") or "")
                settings = ib.get("settings") or {}
                clients = settings.get("clients") if isinstance(settings, dict) else []
                if not isinstance(clients, list):
                    continue
                for c in clients:
                    if not isinstance(c, dict):
                        continue
                    email = str(c.get("email") or "").lower().strip()
                    if email == f"{needle}@{proto}":
                        return True, f"xray:{proto}:{email}"
    return False, ""


def _generate_credential(proto: str) -> str:
    if proto == "trojan":
        return secrets.token_hex(16)
    return str(uuid.uuid4())


def _xray_add_client(proto: str, username: str, cred: str) -> tuple[bool, str]:
    if not XRAY_INBOUNDS_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_INBOUNDS_CONF}"

    email = _email(proto, username)
    with file_lock(ROUTING_LOCK_FILE):
        ok, payload = _read_json(XRAY_INBOUNDS_CONF)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, "Format inbounds tidak valid"

        original = json.loads(json.dumps(payload))
        inbounds = payload.get("inbounds")
        if not isinstance(inbounds, list):
            return False, "Format inbounds tidak valid: inbounds bukan list"

        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if ib.get("protocol") != proto:
                continue
            settings = ib.get("settings") or {}
            clients = settings.get("clients")
            if isinstance(clients, list):
                for c in clients:
                    if isinstance(c, dict) and str(c.get("email") or "") == email:
                        return False, f"User sudah ada di config: {email}"

        if proto == "vless":
            client = {"id": cred, "email": email}
        elif proto == "vmess":
            client = {"id": cred, "alterId": 0, "email": email}
        elif proto == "trojan":
            client = {"password": cred, "email": email}
        else:
            return False, f"Protocol tidak didukung: {proto}"

        updated = False
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if ib.get("protocol") != proto:
                continue
            settings = ib.setdefault("settings", {})
            clients = settings.get("clients")
            if clients is None:
                settings["clients"] = []
                clients = settings["clients"]
            if not isinstance(clients, list):
                continue
            clients.append(client)
            updated = True

        if not updated:
            return False, f"Inbound protocol {proto} tidak ditemukan"

        try:
            _write_json_atomic(XRAY_INBOUNDS_CONF, payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah add user (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_INBOUNDS_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update inbounds: {exc}"

    return True, "ok"


def _xray_delete_client(proto: str, username: str) -> tuple[bool, str]:
    if not XRAY_INBOUNDS_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_INBOUNDS_CONF}"
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config tidak ditemukan: {XRAY_ROUTING_CONF}"

    email = _email(proto, username)
    with file_lock(ROUTING_LOCK_FILE):
        ok_inb, inb_payload = _read_json(XRAY_INBOUNDS_CONF)
        if not ok_inb:
            return False, str(inb_payload)
        ok_rt, rt_payload = _read_json(XRAY_ROUTING_CONF)
        if not ok_rt:
            return False, str(rt_payload)
        if not isinstance(inb_payload, dict) or not isinstance(rt_payload, dict):
            return False, "Format config Xray tidak valid"

        inb_original = json.loads(json.dumps(inb_payload))
        rt_original = json.loads(json.dumps(rt_payload))

        inbounds = inb_payload.get("inbounds")
        if not isinstance(inbounds, list):
            return False, "Format inbounds tidak valid"

        removed = 0
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            if ib.get("protocol") != proto:
                continue
            settings = ib.get("settings") or {}
            clients = settings.get("clients")
            if not isinstance(clients, list):
                continue
            before = len(clients)
            settings["clients"] = [c for c in clients if not (isinstance(c, dict) and str(c.get("email") or "") == email)]
            removed += before - len(settings["clients"])
            ib["settings"] = settings

        if removed == 0:
            return False, f"User tidak ditemukan di inbounds: {email}"

        routing = rt_payload.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if isinstance(rules, list):
            markers = {"dummy-block-user", "dummy-quota-user", "dummy-limit-user", "dummy-warp-user", "dummy-direct-user"}
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                users = rule.get("user")
                if not isinstance(users, list):
                    continue
                has_marker = any(u in markers for u in users)
                if not has_marker:
                    has_marker = any(isinstance(u, str) and u.startswith(SPEED_RULE_MARKER_PREFIX) for u in users)
                if not has_marker:
                    continue
                rule["user"] = [u for u in users if u != email]
            routing["rules"] = rules
            rt_payload["routing"] = routing

        try:
            _write_json_atomic(XRAY_INBOUNDS_CONF, inb_payload)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_INBOUNDS_CONF, inb_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah delete user (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_INBOUNDS_CONF, inb_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update config saat delete user: {exc}"

    return True, "ok"


def _routing_set_user_in_marker(marker: str, email: str, state: str, outbound_tag: str = "blocked") -> tuple[bool, str]:
    if state not in {"on", "off"}:
        return False, "state harus on/off"
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config routing tidak ditemukan: {XRAY_ROUTING_CONF}"

    with file_lock(ROUTING_LOCK_FILE):
        ok, payload = _read_json(XRAY_ROUTING_CONF)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, "Format routing tidak valid"

        original = json.loads(json.dumps(payload))
        routing = payload.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        if not isinstance(rules, list):
            return False, "Format routing.rules tidak valid"

        target = None
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field":
                continue
            if rule.get("outboundTag") != outbound_tag:
                continue
            users = rule.get("user")
            if not isinstance(users, list):
                continue
            if marker in users:
                target = rule
                break

        if target is None:
            return False, f"Marker {marker} pada outboundTag={outbound_tag} tidak ditemukan"

        users = target.get("user") or []
        if not isinstance(users, list):
            users = []

        if marker not in users:
            users.insert(0, marker)
        else:
            users = [marker] + [u for u in users if u != marker]

        changed = False
        if state == "on":
            if email not in users:
                users.append(email)
                changed = True
        else:
            new_users = [u for u in users if u != email]
            if new_users != users:
                users = new_users
                changed = True

        if not changed:
            return True, "noop"

        target["user"] = users
        routing["rules"] = rules
        payload["routing"] = routing

        try:
            _write_json_atomic(XRAY_ROUTING_CONF, payload)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_ROUTING_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah update routing marker (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_ROUTING_CONF, original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update routing marker: {exc}"

    return True, "ok"


def _is_speed_outbound_tag(tag: str) -> bool:
    return bool(tag) and tag.startswith(SPEED_OUTBOUND_TAG_PREFIX)


def _routing_default_rule_index(rules: list[Any]) -> int:
    idx = -1
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        port = str(rule.get("port") or "").strip()
        if port not in DEFAULT_EGRESS_PORTS:
            continue
        if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
            continue
        idx = i
    return idx


def _outbound_tags_from_cfg(out_cfg: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    outbounds = out_cfg.get("outbounds")
    if not isinstance(outbounds, list):
        return tags
    for item in outbounds:
        if not isinstance(item, dict):
            continue
        tag = str(item.get("tag") or "").strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


def _pick_default_balancer_selector(outbound_tags: list[str]) -> list[str]:
    selector: list[str] = []
    for preferred in ("direct", "warp"):
        if preferred in outbound_tags and preferred not in selector:
            selector.append(preferred)
    if selector:
        return selector

    deny = {"api", "blocked"}
    for tag in outbound_tags:
        if tag in deny or _is_speed_outbound_tag(tag):
            continue
        selector.append(tag)
        if len(selector) >= 2:
            break
    return selector


def _sanitize_balancer_selector(raw_selector: Any, outbound_tags: list[str]) -> list[str]:
    if not isinstance(raw_selector, list):
        return []
    known = set(outbound_tags)
    deny = {"api", "blocked"}
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in raw_selector:
        tag = str(item or "").strip()
        if not tag or tag in seen:
            continue
        if tag in deny or _is_speed_outbound_tag(tag):
            continue
        if tag not in known:
            continue
        seen.add(tag)
        cleaned.append(tag)
    return cleaned


def _normalize_selector_input(selector_raw: str, outbound_tags: list[str]) -> tuple[bool, list[str] | str]:
    raw = str(selector_raw or "").strip()
    if not raw or raw.lower() == "auto":
        auto_sel = _pick_default_balancer_selector(outbound_tags)
        if not auto_sel:
            return False, "Selector otomatis kosong. Pastikan outbound non-system tersedia."
        return True, auto_sel

    known = set(outbound_tags)
    deny = {"api", "blocked"}
    selector: list[str] = []
    seen: set[str] = set()
    for part in raw.split(","):
        tag = str(part or "").strip()
        if not tag or tag in seen:
            continue
        if tag in deny or _is_speed_outbound_tag(tag):
            continue
        if tag not in known:
            continue
        seen.add(tag)
        selector.append(tag)

    if not selector:
        return False, "Selector kosong. Gunakan auto atau isi tag outbound valid non-speed dipisah koma."
    return True, selector


def _upsert_egress_balancer(
    routing: dict[str, Any],
    outbound_tags: list[str],
    selector_override: list[str] | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    balancers = routing.get("balancers")
    if not isinstance(balancers, list):
        balancers = []

    balancer: dict[str, Any] | None = None
    for item in balancers:
        if isinstance(item, dict) and item.get("tag") == BALANCER_EGRESS_TAG:
            balancer = item
            break

    if balancer is None:
        balancer = {"tag": BALANCER_EGRESS_TAG, "selector": [], "strategy": {"type": "random"}}
        balancers.insert(0, balancer)

    selector = selector_override if selector_override is not None else _sanitize_balancer_selector(balancer.get("selector"), outbound_tags)
    if not selector:
        selector = _pick_default_balancer_selector(outbound_tags)
    if not selector:
        return False, "Tidak ada outbound valid untuk balancer egress-balance.", None

    balancer["selector"] = selector
    strategy = balancer.get("strategy")
    if not isinstance(strategy, dict):
        strategy = {}
    stype = str(strategy.get("type") or "").strip()
    if stype not in BALANCER_ALLOWED_STRATEGIES:
        strategy["type"] = "random"
    balancer["strategy"] = strategy

    routing["balancers"] = balancers
    return True, "ok", balancer


def _routing_set_default_egress_mode(rt_cfg: dict[str, Any], out_cfg: dict[str, Any], mode: str) -> tuple[bool, str]:
    mode_n = str(mode or "").strip().lower()
    if mode_n not in {"direct", "warp", "balancer"}:
        return False, "Mode egress harus direct/warp/balancer."

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return False, "Invalid routing config: routing.rules bukan list"

    idx = _routing_default_rule_index(rules)
    if idx < 0:
        return False, "Default rule (port 1-65535 / 0-65535) tidak ditemukan."

    outbound_tags = _outbound_tags_from_cfg(out_cfg)
    if mode_n in {"direct", "warp"} and mode_n not in set(outbound_tags):
        return False, f"Outbound '{mode_n}' tidak ditemukan pada 20-outbounds.json."

    target = rules[idx]
    if not isinstance(target, dict):
        return False, "Default rule tidak valid."

    if mode_n in {"direct", "warp"}:
        target.pop("balancerTag", None)
        target["outboundTag"] = mode_n
    else:
        ok_bal, msg_bal, _ = _upsert_egress_balancer(routing, outbound_tags, selector_override=None)
        if not ok_bal:
            return False, msg_bal
        target.pop("outboundTag", None)
        target["balancerTag"] = BALANCER_EGRESS_TAG

    rules[idx] = target
    routing["rules"] = rules
    rt_cfg["routing"] = routing
    return True, f"Default egress di-set ke {mode_n}."


def _routing_set_balancer_strategy(rt_cfg: dict[str, Any], out_cfg: dict[str, Any], strategy_raw: str) -> tuple[bool, str]:
    strategy = str(strategy_raw or "").strip()
    if strategy not in BALANCER_ALLOWED_STRATEGIES:
        choices = ", ".join(sorted(BALANCER_ALLOWED_STRATEGIES))
        return False, f"Strategy invalid. Pilihan: {choices}."

    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    outbound_tags = _outbound_tags_from_cfg(out_cfg)
    ok_bal, msg_bal, balancer = _upsert_egress_balancer(routing, outbound_tags, selector_override=None)
    if not ok_bal or balancer is None:
        return False, msg_bal

    strategy_obj = balancer.get("strategy")
    if not isinstance(strategy_obj, dict):
        strategy_obj = {}
    strategy_obj["type"] = strategy
    balancer["strategy"] = strategy_obj
    routing["balancers"] = routing.get("balancers", [])
    rt_cfg["routing"] = routing
    return True, f"Balancer strategy di-set ke {strategy}."


def _routing_set_balancer_selector(rt_cfg: dict[str, Any], out_cfg: dict[str, Any], selector_raw: str) -> tuple[bool, str]:
    routing = rt_cfg.get("routing")
    if not isinstance(routing, dict):
        routing = {}
    outbound_tags = _outbound_tags_from_cfg(out_cfg)
    ok_sel, sel_or_msg = _normalize_selector_input(selector_raw, outbound_tags)
    if not ok_sel:
        return False, str(sel_or_msg)
    selector = sel_or_msg
    assert isinstance(selector, list)

    ok_bal, msg_bal, _ = _upsert_egress_balancer(routing, outbound_tags, selector_override=selector)
    if not ok_bal:
        return False, msg_bal
    rt_cfg["routing"] = routing
    return True, f"Balancer selector di-set: {', '.join(selector)}"


def _apply_routing_transaction(
    mutator: Any,
) -> tuple[bool, str]:
    if not XRAY_ROUTING_CONF.exists():
        return False, f"Config routing tidak ditemukan: {XRAY_ROUTING_CONF}"
    if not XRAY_OUTBOUNDS_CONF.exists():
        return False, f"Config outbounds tidak ditemukan: {XRAY_OUTBOUNDS_CONF}"

    with file_lock(ROUTING_LOCK_FILE):
        ok_rt, rt_cfg = _read_json(XRAY_ROUTING_CONF)
        if not ok_rt:
            return False, str(rt_cfg)
        ok_out, out_cfg = _read_json(XRAY_OUTBOUNDS_CONF)
        if not ok_out:
            return False, str(out_cfg)
        if not isinstance(rt_cfg, dict) or not isinstance(out_cfg, dict):
            return False, "Format config Xray tidak valid."

        rt_original = json.loads(json.dumps(rt_cfg))
        try:
            ok_mut, msg_mut = mutator(rt_cfg, out_cfg)
            if not ok_mut:
                return False, str(msg_mut)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_cfg)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah update network controls (rollback)."
            return True, str(msg_mut)
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update routing network controls: {exc}"


def _normalize_dns_root(cfg: Any) -> dict[str, Any]:
    if not isinstance(cfg, dict):
        cfg = {}
    dns_obj = cfg.get("dns")
    if not isinstance(dns_obj, dict):
        dns_obj = {}
    cfg["dns"] = dns_obj
    return cfg


def _dns_servers_list(cfg: dict[str, Any]) -> list[Any]:
    dns_obj = cfg.get("dns")
    if not isinstance(dns_obj, dict):
        dns_obj = {}
        cfg["dns"] = dns_obj
    servers = dns_obj.get("servers")
    if not isinstance(servers, list):
        servers = []
    dns_obj["servers"] = servers
    return servers


def _dns_set_server_idx(cfg: dict[str, Any], idx: int, value: str) -> None:
    val = str(value or "").strip()
    if not val:
        return
    servers = _dns_servers_list(cfg)
    while len(servers) <= idx:
        servers.append("")
    if isinstance(servers[idx], dict):
        servers[idx]["address"] = val
    else:
        servers[idx] = val


def _is_valid_port_text(port_text: str) -> bool:
    if not port_text.isdigit():
        return False
    try:
        port = int(port_text)
    except Exception:
        return False
    return 1 <= port <= 65535


def _is_valid_dns_host(value: str) -> bool:
    host = str(value or "").strip().lower().strip(".")
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        pass
    return bool(DOMAIN_RE.match(host))


def _is_valid_dns_server_value(value: str) -> bool:
    val = str(value or "").strip()
    if not val:
        return False

    # Plain IP/FQDN.
    if _is_valid_dns_host(val):
        return True

    # IPv4 with explicit port.
    if ":" in val and val.count(":") == 1:
        host, port_text = val.rsplit(":", 1)
        if _is_valid_port_text(port_text) and _is_valid_dns_host(host):
            return True

    # Bracketed IPv6 with explicit port.
    m = re.match(r"^\[(.+)\]:(\d{1,5})$", val)
    if m:
        host = m.group(1)
        port_text = m.group(2)
        if _is_valid_port_text(port_text):
            try:
                ipaddress.ip_address(host)
                return True
            except Exception:
                return False

    # URI form (for DoH/DoT style values), e.g. https://dns.google/dns-query.
    parsed = urllib.parse.urlparse(val)
    if parsed.scheme and parsed.hostname and _is_valid_dns_host(str(parsed.hostname)):
        return True

    return False


def _apply_dns_transaction(mutator: Any) -> tuple[bool, str]:
    with file_lock(DNS_LOCK_FILE):
        cfg_original: dict[str, Any]
        if XRAY_DNS_CONF.exists():
            ok_read, raw_cfg = _read_json(XRAY_DNS_CONF)
            if not ok_read:
                raw_cfg = {}
            cfg_original = raw_cfg if isinstance(raw_cfg, dict) else {}
        else:
            cfg_original = {"dns": {}}

        cfg_work = json.loads(json.dumps(cfg_original))
        cfg_work = _normalize_dns_root(cfg_work)
        cfg_snapshot = json.loads(json.dumps(cfg_work))

        try:
            ok_mut, msg_mut = mutator(cfg_work)
            if not ok_mut:
                return False, str(msg_mut)

            _write_json_atomic(XRAY_DNS_CONF, cfg_work)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_DNS_CONF, cfg_snapshot)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah update DNS (rollback)."
            return True, str(msg_mut)
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_DNS_CONF, cfg_snapshot)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal update DNS: {exc}"


def _dns_set_primary(cfg: dict[str, Any], value: str) -> tuple[bool, str]:
    val = str(value or "").strip()
    if not val:
        return False, "Primary DNS tidak boleh kosong."
    if not _is_valid_dns_server_value(val):
        return False, "Primary DNS tidak valid. Gunakan IP/FQDN/URI DNS yang valid."
    _dns_set_server_idx(cfg, 0, val)
    return True, f"Primary DNS di-set ke {val}."


def _dns_set_secondary(cfg: dict[str, Any], value: str) -> tuple[bool, str]:
    val = str(value or "").strip()
    if not val:
        return False, "Secondary DNS tidak boleh kosong."
    if not _is_valid_dns_server_value(val):
        return False, "Secondary DNS tidak valid. Gunakan IP/FQDN/URI DNS yang valid."
    servers = _dns_servers_list(cfg)
    if len(servers) == 0:
        _dns_set_server_idx(cfg, 0, "1.1.1.1")
    _dns_set_server_idx(cfg, 1, val)
    return True, f"Secondary DNS di-set ke {val}."


def _dns_set_query_strategy(cfg: dict[str, Any], strategy: str) -> tuple[bool, str]:
    val = str(strategy or "").strip()
    if val not in DNS_QUERY_STRATEGY_ALLOWED:
        choices = ", ".join(sorted(DNS_QUERY_STRATEGY_ALLOWED))
        return False, f"Query strategy invalid. Pilihan: {choices}."
    dns_obj = cfg.get("dns")
    assert isinstance(dns_obj, dict)
    dns_obj["queryStrategy"] = val
    return True, f"Query strategy di-set ke {val}."


def _dns_toggle_cache(cfg: dict[str, Any]) -> tuple[bool, str]:
    dns_obj = cfg.get("dns")
    assert isinstance(dns_obj, dict)
    current = bool(dns_obj.get("disableCache"))
    dns_obj["disableCache"] = not current
    state = "OFF" if not current else "ON"
    # disableCache=true means cache OFF.
    return True, f"DNS cache sekarang: {state}."


def _build_links(proto: str, username: str, cred: str, domain: str) -> dict[str, str]:
    public_paths = {
        "vless": {"ws": "/vless-ws", "httpupgrade": "/vless-hup", "grpc": "vless-grpc"},
        "vmess": {"ws": "/vmess-ws", "httpupgrade": "/vmess-hup", "grpc": "vmess-grpc"},
        "trojan": {"ws": "/trojan-ws", "httpupgrade": "/trojan-hup", "grpc": "trojan-grpc"},
    }

    def vless_link(net: str, val: str) -> str:
        q = {"encryption": "none", "security": "tls", "type": net, "sni": domain}
        if net in {"ws", "httpupgrade"}:
            q["path"] = val or "/"
        elif net == "grpc" and val:
            q["serviceName"] = val
        return f"vless://{cred}@{domain}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + '@' + proto)}"

    def trojan_link(net: str, val: str) -> str:
        q = {"security": "tls", "type": net, "sni": domain}
        if net in {"ws", "httpupgrade"}:
            q["path"] = val or "/"
        elif net == "grpc" and val:
            q["serviceName"] = val
        return f"trojan://{cred}@{domain}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + '@' + proto)}"

    def vmess_link(net: str, val: str) -> str:
        obj = {
            "v": "2",
            "ps": username + "@" + proto,
            "add": domain,
            "port": "443",
            "id": cred,
            "aid": "0",
            "net": net,
            "type": "none",
            "host": domain,
            "tls": "tls",
            "sni": domain,
        }
        if net in {"ws", "httpupgrade"}:
            obj["path"] = val or "/"
        elif net == "grpc":
            obj["path"] = val or ""
            obj["type"] = "gun"
        raw = json.dumps(obj, separators=(",", ":"))
        return "vmess://" + base64.b64encode(raw.encode()).decode()

    links: dict[str, str] = {}
    p = public_paths.get(proto, {})
    for net in ("ws", "httpupgrade", "grpc"):
        v = p.get(net, "")
        if proto == "vless":
            links[net] = vless_link(net, v)
        elif proto == "vmess":
            links[net] = vmess_link(net, v)
        elif proto == "trojan":
            links[net] = trojan_link(net, v)
    return links


def _build_account_text(
    proto: str,
    username: str,
    credential: str,
    domain: str,
    ip: str,
    quota_bytes: int,
    created_at: str,
    expired_at: str,
    days: int,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down: float,
    speed_up: float,
) -> str:
    links = _build_links(proto, username, credential, domain)
    lines = [
        "=== XRAY ACCOUNT INFO ===",
        f"Domain      : {domain}",
        f"IP          : {ip}",
        f"Username    : {username}",
        f"Protocol    : {proto}",
    ]
    if proto in {"vless", "vmess"}:
        lines.append(f"UUID        : {credential}")
    else:
        lines.append(f"Password    : {credential}")

    lines.extend(
        [
            f"Quota Limit : {_fmt_quota_gb_from_bytes(max(0, quota_bytes))} GB",
            f"Expired     : {max(0, days)} days",
            f"Valid Until : {expired_at}",
            f"Created     : {created_at}",
            f"IP Limit    : {'ON' if ip_enabled else 'OFF'}" + (f" ({ip_limit})" if ip_enabled else ""),
        ]
    )

    if speed_enabled and speed_down > 0 and speed_up > 0:
        lines.append(f"Speed Limit : ON (DOWN {_fmt_number(speed_down)} Mbps | UP {_fmt_number(speed_up)} Mbps)")
    else:
        lines.append("Speed Limit : OFF")

    lines.extend(
        [
            "",
            "Links Import:",
            f"  WebSocket   : {links.get('ws', '-')}",
            f"  HTTPUpgrade : {links.get('httpupgrade', '-')}",
            f"  gRPC        : {links.get('grpc', '-')}",
            "",
        ]
    )
    return "\n".join(lines)


def _read_account_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not path.exists():
        return fields
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in raw:
                continue
            k, v = raw.split(":", 1)
            fields[k.strip()] = v.strip()
    except Exception:
        return {}
    return fields


def _find_credential_in_inbounds(proto: str, username: str) -> str:
    email = _email(proto, username)
    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if not ok or not isinstance(payload, dict):
        return ""
    inbounds = payload.get("inbounds", [])
    if not isinstance(inbounds, list):
        return ""
    for ib in inbounds:
        if not isinstance(ib, dict) or ib.get("protocol") != proto:
            continue
        clients = (ib.get("settings") or {}).get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if not isinstance(c, dict):
                continue
            if str(c.get("email") or "") != email:
                continue
            if proto == "trojan":
                return str(c.get("password") or "").strip()
            return str(c.get("id") or "").strip()
    return ""


def _write_account_artifacts(
    proto: str,
    username: str,
    credential: str,
    quota_bytes: int,
    days: int,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down: float,
    speed_up: float,
) -> tuple[Path, Path]:
    _ensure_runtime_dirs()

    created_date = datetime.now(timezone.utc).date()
    expired_date = created_date + timedelta(days=max(1, int(days)))
    created_at = created_date.strftime("%Y-%m-%d")
    expired_at = expired_date.strftime("%Y-%m-%d")

    domain = _detect_domain()
    ip = _detect_public_ipv4()

    account_file = ACCOUNT_ROOT / proto / f"{username}@{proto}.txt"
    quota_file = QUOTA_ROOT / proto / f"{username}@{proto}.json"

    account_text = _build_account_text(
        proto=proto,
        username=username,
        credential=credential,
        domain=domain,
        ip=ip,
        quota_bytes=int(max(0, quota_bytes)),
        created_at=created_at,
        expired_at=expired_at,
        days=max(0, int(days)),
        ip_enabled=bool(ip_enabled),
        ip_limit=max(0, int(ip_limit)) if ip_enabled else 0,
        speed_enabled=bool(speed_enabled),
        speed_down=float(speed_down) if speed_enabled else 0.0,
        speed_up=float(speed_up) if speed_enabled else 0.0,
    )

    quota_payload: dict[str, Any] = {
        "username": _email(proto, username),
        "protocol": proto,
        "quota_limit": int(max(0, quota_bytes)),
        "quota_unit": "binary",
        "quota_used": 0,
        "created_at": created_at,
        "expired_at": expired_at,
        "status": {
            "manual_block": False,
            "quota_exhausted": False,
            "ip_limit_enabled": bool(ip_enabled),
            "ip_limit": int(max(0, ip_limit)) if ip_enabled else 0,
            "speed_limit_enabled": bool(speed_enabled),
            "speed_down_mbit": float(speed_down) if speed_enabled else 0.0,
            "speed_up_mbit": float(speed_up) if speed_enabled else 0.0,
            "ip_limit_locked": False,
            "lock_reason": "",
            "locked_at": "",
        },
    }

    _write_text_atomic(account_file, account_text)
    _write_json_atomic(quota_file, quota_payload)
    _chmod_600(account_file)
    _chmod_600(quota_file)
    return account_file, quota_file


def _refresh_account_info_for_user(proto: str, username: str, domain: str | None = None, ip: str | None = None) -> tuple[bool, str]:
    if proto not in PROTOCOLS:
        return False, f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "Username tidak valid"

    _ensure_runtime_dirs()

    account_target = _resolve_existing(_account_candidates(proto, username))
    quota_target = _resolve_existing(_quota_candidates(proto, username))

    if account_target is None:
        account_target = ACCOUNT_ROOT / proto / f"{username}@{proto}.txt"

    account_fields = _read_account_fields(account_target)

    quota_data: dict[str, Any] = {}
    if quota_target is not None:
        ok, payload = _read_json(quota_target)
        if ok and isinstance(payload, dict):
            quota_data = payload

    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}

    quota_limit = _to_int(quota_data.get("quota_limit"), 0)
    created_at = str(quota_data.get("created_at") or account_fields.get("Created") or "").strip()[:10]
    if not created_at:
        created_at = datetime.utcnow().strftime("%Y-%m-%d")

    expired_at = str(quota_data.get("expired_at") or account_fields.get("Valid Until") or "").strip()[:10]
    if not expired_at:
        expired_at = "-"

    d_created = _parse_date_only(created_at)
    d_expired = _parse_date_only(expired_at)
    if d_created and d_expired:
        days = max(0, (d_expired - d_created).days)
    elif d_expired:
        days = max(0, (d_expired - date.today()).days)
    else:
        days = 0

    ip_enabled = bool(status.get("ip_limit_enabled"))
    ip_limit = _to_int(status.get("ip_limit"), 0) if ip_enabled else 0

    speed_enabled = bool(status.get("speed_limit_enabled"))
    speed_down = _to_float(status.get("speed_down_mbit"), 0.0)
    speed_up = _to_float(status.get("speed_up_mbit"), 0.0)
    if speed_down <= 0 or speed_up <= 0:
        speed_enabled = False
        speed_down = 0.0
        speed_up = 0.0

    credential = _find_credential_in_inbounds(proto, username)
    if not credential:
        if proto == "trojan":
            credential = account_fields.get("Password", "").strip()
        else:
            credential = account_fields.get("UUID", "").strip()
    if not credential:
        return False, f"Credential tidak ditemukan untuk {username}@{proto}"

    domain_eff = str(domain or "").strip() or _detect_domain()
    ip_eff = str(ip or "").strip() or account_fields.get("IP", "").strip() or _detect_public_ipv4()

    content = _build_account_text(
        proto=proto,
        username=username,
        credential=credential,
        domain=domain_eff,
        ip=ip_eff,
        quota_bytes=quota_limit,
        created_at=created_at,
        expired_at=expired_at,
        days=days,
        ip_enabled=ip_enabled,
        ip_limit=ip_limit,
        speed_enabled=speed_enabled,
        speed_down=speed_down,
        speed_up=speed_up,
    )

    _write_text_atomic(account_target, content)
    _chmod_600(account_target)
    return True, "ok"


def _refresh_all_account_info(domain: str | None = None, ip: str | None = None) -> tuple[int, int]:
    _ensure_runtime_dirs()
    domain_eff = str(domain or "").strip() or _detect_domain()
    ip_eff = str(ip or "").strip() or _detect_public_ipv4()

    updated = 0
    failed = 0

    for proto in PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        selected: dict[str, Path] = {}
        selected_has_at: dict[str, bool] = {}
        for p in sorted(d.glob("*.txt")):
            username = _extract_username_from_file_name(p, proto)
            if not username:
                continue
            has_at = "@" in p.stem
            prev = selected.get(username)
            if prev is not None:
                if has_at and not selected_has_at.get(username, False):
                    selected[username] = p
                    selected_has_at[username] = True
                continue
            selected[username] = p
            selected_has_at[username] = has_at

        for username in sorted(selected.keys()):
            ok, _ = _refresh_account_info_for_user(proto, username, domain=domain_eff, ip=ip_eff)
            if ok:
                updated += 1
            else:
                failed += 1

    return updated, failed


def _account_info_needs_compat_refresh() -> bool:
    _ensure_runtime_dirs()
    for proto in PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        for p in sorted(d.glob("*.txt")):
            stem = p.stem
            expected_suffix = f"@{proto}"
            is_legacy_name = not stem.endswith(expected_suffix)

            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return True

            has_links_block = bool(re.search(r"(?m)^Links Import:\s*$", text))
            has_grpc_line = bool(re.search(r"(?m)^\s*gRPC\s*:", text))
            if is_legacy_name or not has_links_block or not has_grpc_line:
                return True
    return False


def op_account_info_compat_refresh_if_needed() -> tuple[bool, str, str]:
    title = "User Management - Account Info Compat Refresh"
    if not _account_info_needs_compat_refresh():
        return True, title, "Skip: format account info sudah kompatibel."

    domain = _detect_domain()
    ip_override: str | None = None
    ok_ip, ip_or_err = _get_public_ipv4()
    if ok_ip:
        ip_override = str(ip_or_err)

    updated, failed = _refresh_all_account_info(domain=domain, ip=ip_override)
    msg = f"Compat refresh selesai: updated={updated}, failed={failed}"
    if failed > 0:
        return False, title, msg
    return True, title, msg


def _speed_policy_file_path(proto: str, username: str) -> Path:
    return SPEED_POLICY_ROOT / proto / f"{username}@{proto}.json"


def _speed_policy_exists(proto: str, username: str) -> bool:
    return _speed_policy_file_path(proto, username).exists()


def _speed_policy_remove(proto: str, username: str) -> None:
    p = _speed_policy_file_path(proto, username)
    with file_lock(SPEED_POLICY_LOCK_FILE):
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


def _valid_mark(v: Any) -> bool:
    m = _to_int(v, -1)
    return SPEED_MARK_MIN <= m <= SPEED_MARK_MAX


def _collect_used_marks(exclude_path: Path | None = None) -> set[int]:
    used: set[int] = set()
    for proto in PROTOCOLS:
        d = SPEED_POLICY_ROOT / proto
        if not d.exists():
            continue
        for p in d.glob("*.json"):
            if exclude_path is not None and p.resolve() == exclude_path.resolve():
                continue
            ok, payload = _read_json(p)
            if not ok or not isinstance(payload, dict):
                continue
            m = _to_int(payload.get("mark"), -1)
            if _valid_mark(m):
                used.add(m)
    return used


def _speed_policy_upsert(proto: str, username: str, down_mbit: float, up_mbit: float) -> tuple[bool, int | str]:
    down = _to_float(down_mbit, 0.0)
    up = _to_float(up_mbit, 0.0)
    if down <= 0 or up <= 0:
        return False, "Speed harus > 0"

    _ensure_runtime_dirs()

    email = _email(proto, username)
    target = _speed_policy_file_path(proto, username)

    with file_lock(SPEED_POLICY_LOCK_FILE):
        existing_mark = None
        if target.exists():
            ok, payload = _read_json(target)
            if ok and isinstance(payload, dict) and _valid_mark(payload.get("mark")):
                existing_mark = _to_int(payload.get("mark"), -1)

        used = _collect_used_marks(exclude_path=target)

        mark: int
        if existing_mark is not None and existing_mark not in used:
            mark = existing_mark
        else:
            size = SPEED_MARK_MAX - SPEED_MARK_MIN + 1
            seed = int(hashlib.sha256(email.encode("utf-8")).hexdigest()[:8], 16)
            start = SPEED_MARK_MIN + (seed % size)
            mark = -1
            for i in range(size):
                cand = SPEED_MARK_MIN + ((start - SPEED_MARK_MIN + i) % size)
                if cand not in used:
                    mark = cand
                    break
            if mark < 0:
                return False, "Range mark speed policy habis"

        payload = {
            "enabled": True,
            "username": email,
            "protocol": proto,
            "mark": mark,
            "down_mbit": round(down, 3),
            "up_mbit": round(up, 3),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_json_atomic(target, payload)
        _chmod_600(target)

    return True, mark


def _list_speed_mark_users() -> dict[int, list[str]]:
    mark_users: dict[int, set[str]] = {}
    for proto in PROTOCOLS:
        d = SPEED_POLICY_ROOT / proto
        if not d.exists():
            continue
        for p in sorted(d.glob("*.json")):
            ok, payload = _read_json(p)
            if not ok or not isinstance(payload, dict):
                continue
            enabled = payload.get("enabled", True)
            enabled_bool = bool(enabled) if isinstance(enabled, bool) else str(enabled).strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if not enabled_bool:
                continue
            mark = _to_int(payload.get("mark"), -1)
            if not _valid_mark(mark):
                continue
            down = _to_float(payload.get("down_mbit"), 0.0)
            up = _to_float(payload.get("up_mbit"), 0.0)
            if down <= 0 or up <= 0:
                continue
            email = str(payload.get("username") or payload.get("email") or p.stem).strip()
            if not email:
                continue
            mark_users.setdefault(mark, set()).add(email)
    return {k: sorted(v) for k, v in sorted(mark_users.items())}


def _speed_policy_sync_xray() -> tuple[bool, str]:
    if not XRAY_OUTBOUNDS_CONF.exists() or not XRAY_ROUTING_CONF.exists():
        return False, "File outbounds/routing tidak ditemukan"

    with file_lock(ROUTING_LOCK_FILE):
        ok_out, out_cfg = _read_json(XRAY_OUTBOUNDS_CONF)
        ok_rt, rt_cfg = _read_json(XRAY_ROUTING_CONF)
        if not ok_out:
            return False, str(out_cfg)
        if not ok_rt:
            return False, str(rt_cfg)
        if not isinstance(out_cfg, dict) or not isinstance(rt_cfg, dict):
            return False, "Format config Xray tidak valid"

        out_original = json.loads(json.dumps(out_cfg))
        rt_original = json.loads(json.dumps(rt_cfg))

        outbounds = out_cfg.get("outbounds")
        if not isinstance(outbounds, list):
            return False, "outbounds bukan list"

        routing = rt_cfg.get("routing") or {}
        rules = routing.get("rules") if isinstance(routing, dict) else None
        balancers = routing.get("balancers") if isinstance(routing, dict) else None
        if not isinstance(rules, list):
            return False, "routing.rules bukan list"
        if not isinstance(balancers, list):
            balancers = []

        mark_users = _list_speed_mark_users()
        speed_bal_prefix = f"{SPEED_OUTBOUND_TAG_PREFIX}bal-"

        out_by_tag: dict[str, dict[str, Any]] = {}
        for out in outbounds:
            if isinstance(out, dict):
                tag = str(out.get("tag") or "").strip()
                if tag:
                    out_by_tag[tag] = out

        def is_default_rule(rule: Any) -> bool:
            if not isinstance(rule, dict):
                return False
            if rule.get("type") != "field":
                return False
            port = str(rule.get("port", "")).strip()
            if port not in {"1-65535", "0-65535"}:
                return False
            if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
                return False
            return True

        default_rule = None
        for rule in rules:
            if is_default_rule(rule):
                default_rule = rule
                break

        base_mode = "outbound"
        base_selector: list[str] = []
        base_strategy: dict[str, Any] = {}
        base_balancer_tag = ""

        if isinstance(default_rule, dict):
            bt = str(default_rule.get("balancerTag") or "").strip()
            ot = str(default_rule.get("outboundTag") or "").strip()
            if bt:
                base_mode = "balancer"
                base_balancer_tag = bt
            elif ot:
                base_selector = [ot]

        balancers_by_tag: dict[str, dict[str, Any]] = {}
        for b in balancers:
            if isinstance(b, dict):
                t = str(b.get("tag") or "").strip()
                if t:
                    balancers_by_tag[t] = b

        if base_mode == "balancer":
            b0 = balancers_by_tag.get(base_balancer_tag)
            if isinstance(b0, dict):
                sel = b0.get("selector")
                if isinstance(sel, list):
                    base_selector.extend([str(x).strip() for x in sel if str(x).strip()])
                st = b0.get("strategy")
                if isinstance(st, dict):
                    base_strategy = json.loads(json.dumps(st))

            if not base_selector and isinstance(default_rule, dict):
                ot = str(default_rule.get("outboundTag") or "").strip()
                if ot:
                    base_mode = "outbound"
                    base_selector = [ot]

        if not base_selector:
            if "direct" in out_by_tag:
                base_selector = ["direct"]
            else:
                for tag in out_by_tag.keys():
                    if not tag.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                        base_selector = [tag]
                        break

        if not base_selector:
            return False, "Outbound dasar untuk speed policy tidak ditemukan"

        effective_selector: list[str] = []
        seen: set[str] = set()
        for tag in base_selector:
            t = str(tag).strip()
            if not t or t in {"api", "blocked"} or t.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                continue
            if t not in out_by_tag:
                continue
            if t in seen:
                continue
            seen.add(t)
            effective_selector.append(t)

        if not effective_selector:
            if "direct" in out_by_tag:
                effective_selector = ["direct"]
            else:
                for t in out_by_tag.keys():
                    if t in {"api", "blocked"} or t.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                        continue
                    effective_selector = [t]
                    break

        if not effective_selector:
            return False, "Selector outbound dasar untuk speed policy kosong"

        clean_outbounds: list[Any] = []
        for out in outbounds:
            if isinstance(out, dict):
                tag = str(out.get("tag") or "").strip()
                if tag.startswith(SPEED_OUTBOUND_TAG_PREFIX):
                    continue
            clean_outbounds.append(out)

        mark_out_tags: dict[int, dict[str, str]] = {}
        for mark in sorted(mark_users.keys()):
            per_mark: dict[str, str] = {}
            for base_tag in effective_selector:
                src = out_by_tag.get(base_tag)
                if not isinstance(src, dict):
                    continue
                clone = json.loads(json.dumps(src))
                safe_base_tag = re.sub(r"[^A-Za-z0-9_.-]", "-", base_tag)
                clone_tag = f"{SPEED_OUTBOUND_TAG_PREFIX}{mark}-{safe_base_tag}"
                clone["tag"] = clone_tag
                ss = clone.get("streamSettings")
                if not isinstance(ss, dict):
                    ss = {}
                sock = ss.get("sockopt")
                if not isinstance(sock, dict):
                    sock = {}
                sock["mark"] = int(mark)
                ss["sockopt"] = sock
                clone["streamSettings"] = ss
                clean_outbounds.append(clone)
                per_mark[base_tag] = clone_tag
            mark_out_tags[mark] = per_mark

        out_cfg["outbounds"] = clean_outbounds

        clean_balancers: list[Any] = []
        for bal in balancers:
            if isinstance(bal, dict):
                t = str(bal.get("tag") or "").strip()
                if t.startswith(speed_bal_prefix):
                    continue
            clean_balancers.append(bal)

        speed_balancers: dict[int, str] = {}
        if base_mode == "balancer":
            for mark in sorted(mark_users.keys()):
                selector = [mark_out_tags.get(mark, {}).get(bt, "") for bt in effective_selector]
                selector = [t for t in selector if t]
                if not selector:
                    continue
                btag = f"{speed_bal_prefix}{mark}"
                obj: dict[str, Any] = {"tag": btag, "selector": selector}
                if base_strategy:
                    obj["strategy"] = json.loads(json.dumps(base_strategy))
                clean_balancers.append(obj)
                speed_balancers[mark] = btag

        def is_protected_rule(rule: Any) -> bool:
            if not isinstance(rule, dict):
                return False
            if rule.get("type") != "field":
                return False
            ot = str(rule.get("outboundTag") or "").strip()
            return ot in {"api", "blocked"}

        kept_rules: list[Any] = []
        for rule in rules:
            if not isinstance(rule, dict):
                kept_rules.append(rule)
                continue
            if rule.get("type") != "field":
                kept_rules.append(rule)
                continue
            users = rule.get("user")
            ot = str(rule.get("outboundTag") or "").strip()
            bt = str(rule.get("balancerTag") or "").strip()
            has_speed_marker = isinstance(users, list) and any(
                isinstance(u, str) and u.startswith(SPEED_RULE_MARKER_PREFIX) for u in users
            )
            if has_speed_marker and (ot.startswith(SPEED_OUTBOUND_TAG_PREFIX) or bt.startswith(speed_bal_prefix)):
                continue
            kept_rules.append(rule)

        insert_idx = len(kept_rules)
        for idx, rule in enumerate(kept_rules):
            if is_protected_rule(rule):
                continue
            insert_idx = idx
            break

        speed_rules: list[dict[str, Any]] = []
        for mark, users in sorted(mark_users.items()):
            marker = f"{SPEED_RULE_MARKER_PREFIX}{mark}"
            rule: dict[str, Any] = {"type": "field", "user": [marker] + users}
            if base_mode == "balancer":
                btag = speed_balancers.get(mark, "")
                if not btag:
                    continue
                rule["balancerTag"] = btag
            else:
                first_base = effective_selector[0]
                ot = mark_out_tags.get(mark, {}).get(first_base, "")
                if not ot:
                    continue
                rule["outboundTag"] = ot
            speed_rules.append(rule)

        merged_rules = kept_rules[:insert_idx] + speed_rules + kept_rules[insert_idx:]
        routing["rules"] = merged_rules
        routing["balancers"] = clean_balancers
        rt_cfg["routing"] = routing

        try:
            _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_cfg)
            _write_json_atomic(XRAY_ROUTING_CONF, rt_cfg)
            if not _restart_and_wait("xray", timeout_sec=20):
                _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
                return False, "xray tidak aktif setelah sinkronisasi speed policy (rollback)."
        except Exception as exc:
            try:
                _write_json_atomic(XRAY_OUTBOUNDS_CONF, out_original)
                _write_json_atomic(XRAY_ROUTING_CONF, rt_original)
                _restart_and_wait("xray", timeout_sec=20)
            except Exception:
                pass
            return False, f"Gagal sinkronisasi speed policy: {exc}"

    return True, "ok"


def _speed_policy_apply_now() -> bool:
    if Path("/usr/local/bin/xray-speed").exists() and SPEED_CONFIG_FILE.exists():
        ok, _ = _run_cmd(["/usr/local/bin/xray-speed", "once", "--config", str(SPEED_CONFIG_FILE)], timeout=30)
        if ok:
            return True
    if _service_exists("xray-speed"):
        return _restart_and_wait("xray-speed", timeout_sec=20)
    return False


def _quota_sync_speed_policy_for_user(proto: str, username: str, quota_data: dict[str, Any]) -> tuple[bool, str]:
    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}
    speed_on = bool(status.get("speed_limit_enabled"))
    speed_down = _to_float(status.get("speed_down_mbit"), 0.0)
    speed_up = _to_float(status.get("speed_up_mbit"), 0.0)

    if speed_on:
        if speed_down <= 0 or speed_up <= 0:
            return False, "Speed limit aktif tapi nilai speed_down/speed_up belum valid (>0)."
        ok_upsert, mark_or_err = _speed_policy_upsert(proto, username, speed_down, speed_up)
        if not ok_upsert:
            return False, f"Gagal menyimpan speed policy: {mark_or_err}"
        ok_sync, sync_msg = _speed_policy_sync_xray()
        if not ok_sync:
            return False, sync_msg
        if not _speed_policy_apply_now():
            return False, "Speed policy tersimpan, tetapi apply runtime gagal (xray-speed)."
        return True, f"Speed policy aktif (mark={mark_or_err})."

    removed = _speed_policy_exists(proto, username)
    if removed:
        _speed_policy_remove(proto, username)
        ok_sync, sync_msg = _speed_policy_sync_xray()
        if not ok_sync:
            return False, sync_msg
    _speed_policy_apply_now()
    return True, "ok"


def _delete_account_artifacts(proto: str, username: str) -> None:
    for p in [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


def _run_limit_ip_restart_if_present() -> None:
    for name in ("xray-limit-ip", "xray-limit"):
        if _service_exists(name):
            _restart_and_wait(name, timeout_sec=15)
            break


def op_user_add(
    proto: str,
    username: str,
    days: int,
    quota_gb: float,
    ip_enabled: bool,
    ip_limit: int,
    speed_enabled: bool,
    speed_down_mbit: float,
    speed_up_mbit: float,
) -> tuple[bool, str, str]:
    if proto not in PROTOCOLS:
        return False, "User Management - Add User", f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "User Management - Add User", "Username tidak valid."
    if days <= 0:
        return False, "User Management - Add User", "Masa aktif harus > 0 hari."
    if quota_gb <= 0:
        return False, "User Management - Add User", "Quota harus > 0 GB."
    if ip_enabled and ip_limit <= 0:
        return False, "User Management - Add User", "IP limit harus > 0 jika IP limit aktif."

    speed_on = bool(speed_enabled)
    down = _to_float(speed_down_mbit, 0.0)
    up = _to_float(speed_up_mbit, 0.0)
    if speed_on and (down <= 0 or up <= 0):
        return False, "User Management - Add User", "Speed limit aktif, tapi speed download/upload belum valid (>0)."

    exists, where = _username_exists_anywhere(username)
    if exists:
        return False, "User Management - Add User", f"Username sudah ada: {username} ({where})"

    cred = _generate_credential(proto)
    quota_bytes = int(round(quota_gb * (1024**3)))

    ok_add, add_msg = _xray_add_client(proto, username, cred)
    if not ok_add:
        return False, "User Management - Add User", add_msg

    try:
        account_file, quota_file = _write_account_artifacts(
            proto=proto,
            username=username,
            credential=cred,
            quota_bytes=quota_bytes,
            days=days,
            ip_enabled=ip_enabled,
            ip_limit=ip_limit,
            speed_enabled=speed_on,
            speed_down=down,
            speed_up=up,
        )

        if speed_on:
            ok_sync, sync_msg = _quota_sync_speed_policy_for_user(
                proto,
                username,
                {
                    "status": {
                        "speed_limit_enabled": True,
                        "speed_down_mbit": down,
                        "speed_up_mbit": up,
                    }
                },
            )
            if not ok_sync:
                _speed_policy_remove(proto, username)
                _speed_policy_sync_xray()
                _speed_policy_apply_now()
                _xray_delete_client(proto, username)
                _delete_account_artifacts(proto, username)
                return False, "User Management - Add User", f"Rollback add user karena speed policy gagal: {sync_msg}"

        msg = (
            f"Add user sukses.\n"
            f"- User: {username}@{proto}\n"
            f"- Account: {account_file}\n"
            f"- Quota: {quota_file}"
        )
        return True, "User Management - Add User", msg
    except Exception as exc:
        _xray_delete_client(proto, username)
        _delete_account_artifacts(proto, username)
        return False, "User Management - Add User", f"Gagal menyimpan artefak user: {exc}"


def op_user_account_file_download(proto: str, username: str) -> tuple[bool, dict[str, str] | str]:
    if proto not in PROTOCOLS:
        return False, f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "Username tidak valid."

    account_file = _resolve_existing(_account_candidates(proto, username))
    if account_file is None:
        return False, f"File account tidak ditemukan untuk {username}@{proto}."

    try:
        raw = account_file.read_bytes()
    except Exception as exc:
        return False, f"Gagal membaca file account: {exc}"

    return True, {
        "filename": f"{username}@{proto}.txt",
        "content_base64": base64.b64encode(raw).decode("ascii"),
        "content_type": "text/plain",
    }


def op_user_delete(proto: str, username: str) -> tuple[bool, str, str]:
    if proto not in PROTOCOLS:
        return False, "User Management - Delete User", f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "User Management - Delete User", "Username tidak valid."

    ok_del, del_msg = _xray_delete_client(proto, username)
    if not ok_del:
        return False, "User Management - Delete User", del_msg

    _delete_account_artifacts(proto, username)
    _speed_policy_remove(proto, username)
    _speed_policy_sync_xray()
    _speed_policy_apply_now()

    return True, "User Management - Delete User", f"Delete user selesai: {username}@{proto}"


def _find_credential_from_account(proto: str, username: str) -> str:
    acc = _resolve_existing(_account_candidates(proto, username))
    if acc is None:
        return ""
    fields = _read_account_fields(acc)
    if proto == "trojan":
        return fields.get("Password", "").strip()
    return fields.get("UUID", "").strip()


def _user_exists_in_inbounds(proto: str, username: str) -> bool:
    email = _email(proto, username)
    ok, payload = _read_json(XRAY_INBOUNDS_CONF)
    if not ok or not isinstance(payload, dict):
        return False
    inbounds = payload.get("inbounds", [])
    if not isinstance(inbounds, list):
        return False
    for ib in inbounds:
        if not isinstance(ib, dict) or ib.get("protocol") != proto:
            continue
        clients = (ib.get("settings") or {}).get("clients")
        if not isinstance(clients, list):
            continue
        for c in clients:
            if isinstance(c, dict) and str(c.get("email") or "") == email:
                return True
    return False


def op_user_extend_expiry(proto: str, username: str, mode: str, value: str) -> tuple[bool, str, str]:
    if proto not in PROTOCOLS:
        return False, "User Management - Extend Expiry", f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "User Management - Extend Expiry", "Username tidak valid."

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "User Management - Extend Expiry", str(q_path_or_msg)
    quota_path = q_path_or_msg
    quota_data = q_data_or_msg
    assert isinstance(quota_path, Path)
    assert isinstance(quota_data, dict)

    current_expiry = str(quota_data.get("expired_at") or "").strip()[:10]
    today = date.today()

    mode_n = str(mode or "").strip().lower()
    if mode_n in {"extend", "tambah", "days", "1"}:
        add_days = _to_int(value, 0)
        if add_days <= 0:
            return False, "User Management - Extend Expiry", "Nilai extend harus angka hari > 0."
        base = _parse_date_only(current_expiry) or today
        if base < today:
            base = today
        new_expiry = (base + timedelta(days=add_days)).strftime("%Y-%m-%d")
    elif mode_n in {"set", "date", "2"}:
        d = _parse_date_only(value)
        if d is None:
            return False, "User Management - Extend Expiry", "Format tanggal harus YYYY-MM-DD."
        new_expiry = d.strftime("%Y-%m-%d")
    else:
        return False, "User Management - Extend Expiry", "Mode harus extend atau set."

    quota_data["expired_at"] = new_expiry
    status = quota_data.get("status") if isinstance(quota_data.get("status"), dict) else {}

    st_quota = bool(status.get("quota_exhausted"))
    st_manual = bool(status.get("manual_block"))
    st_iplocked = bool(status.get("ip_limit_locked"))

    if st_quota:
        status["quota_exhausted"] = False

    _status_apply_lock_fields(status)
    quota_data["status"] = status
    _save_quota(quota_path, quota_data)

    if st_quota:
        _routing_set_user_in_marker("dummy-quota-user", _email(proto, username), "off", outbound_tag="blocked")
    if st_manual:
        _routing_set_user_in_marker("dummy-block-user", _email(proto, username), "on", outbound_tag="blocked")
    if st_iplocked:
        _routing_set_user_in_marker("dummy-limit-user", _email(proto, username), "on", outbound_tag="blocked")

    if not _user_exists_in_inbounds(proto, username):
        cred = _find_credential_from_account(proto, username)
        if cred:
            _xray_add_client(proto, username, cred)

    _refresh_account_info_for_user(proto, username)

    return (
        True,
        "User Management - Extend Expiry",
        f"Expiry diperbarui: {username}@{proto}\n- Lama: {current_expiry or '-'}\n- Baru: {new_expiry}",
    )


def op_quota_set_limit(proto: str, username: str, quota_gb: float) -> tuple[bool, str, str]:
    if proto not in PROTOCOLS:
        return False, "Quota - Set Limit", f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return False, "Quota - Set Limit", "Username tidak valid"
    if quota_gb <= 0:
        return False, "Quota - Set Limit", "Quota harus > 0 GB"

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Set Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    q_data["quota_limit"] = int(round(quota_gb * (1024**3)))
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    _status_apply_lock_fields(st)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Set Limit", f"Quota limit diubah ke {_fmt_number(quota_gb)} GB untuk {username}@{proto}"


def op_quota_reset_used(proto: str, username: str) -> tuple[bool, str, str]:
    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Reset Used", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    q_data["quota_used"] = 0
    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["quota_exhausted"] = False
    _status_apply_lock_fields(st)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    _routing_set_user_in_marker("dummy-quota-user", _email(proto, username), "off", outbound_tag="blocked")
    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Reset Used", f"Quota used di-reset untuk {username}@{proto}"


def op_quota_manual_block(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Manual Block", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["manual_block"] = bool(enabled)
    _status_apply_lock_fields(st)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    if enabled:
        ok_rt, msg_rt = _routing_set_user_in_marker("dummy-block-user", _email(proto, username), "on", outbound_tag="blocked")
        if not ok_rt:
            return False, "Quota - Manual Block", msg_rt
        return True, "Quota - Manual Block", f"Manual block ON untuk {username}@{proto}"

    ok_rt, msg_rt = _routing_set_user_in_marker("dummy-block-user", _email(proto, username), "off", outbound_tag="blocked")
    if not ok_rt:
        return False, "Quota - Manual Block", msg_rt
    return True, "Quota - Manual Block", f"Manual block OFF untuk {username}@{proto}"


def op_quota_ip_limit_enable(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - IP Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit_enabled"] = bool(enabled)
    if not enabled:
        st["ip_limit_locked"] = False
    _status_apply_lock_fields(st)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    if not enabled:
        _routing_set_user_in_marker("dummy-limit-user", _email(proto, username), "off", outbound_tag="blocked")

    _run_limit_ip_restart_if_present()
    _refresh_account_info_for_user(proto, username)
    return True, "Quota - IP Limit", f"IP limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}"


def op_quota_set_ip_limit(proto: str, username: str, limit: int) -> tuple[bool, str, str]:
    if limit <= 0:
        return False, "Quota - Set IP Limit", "IP limit harus > 0"

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Set IP Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit"] = int(limit)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    _run_limit_ip_restart_if_present()
    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Set IP Limit", f"IP limit diubah ke {limit} untuk {username}@{proto}"


def op_quota_unlock_ip_lock(proto: str, username: str) -> tuple[bool, str, str]:
    email = _email(proto, username)
    if Path("/usr/local/bin/limit-ip").exists():
        _run_cmd(["/usr/local/bin/limit-ip", "unlock", email], timeout=15)

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Unlock IP Lock", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["ip_limit_locked"] = False
    _status_apply_lock_fields(st)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    _routing_set_user_in_marker("dummy-limit-user", email, "off", outbound_tag="blocked")
    _run_limit_ip_restart_if_present()
    return True, "Quota - Unlock IP Lock", f"IP lock di-unlock untuk {username}@{proto}"


def op_quota_set_speed_down(proto: str, username: str, speed_down: float) -> tuple[bool, str, str]:
    if speed_down <= 0:
        return False, "Quota - Speed Download", "Speed download harus > 0"

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Download", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_down_mbit"] = float(speed_down)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    if bool(st.get("speed_limit_enabled")):
        ok_sync, msg_sync = _quota_sync_speed_policy_for_user(proto, username, q_data)
        if not ok_sync:
            return False, "Quota - Speed Download", msg_sync

    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Speed Download", f"Speed download diubah ke {_fmt_number(speed_down)} Mbps untuk {username}@{proto}"


def op_quota_set_speed_up(proto: str, username: str, speed_up: float) -> tuple[bool, str, str]:
    if speed_up <= 0:
        return False, "Quota - Speed Upload", "Speed upload harus > 0"

    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Upload", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_up_mbit"] = float(speed_up)
    q_data["status"] = st
    _save_quota(q_path, q_data)

    if bool(st.get("speed_limit_enabled")):
        ok_sync, msg_sync = _quota_sync_speed_policy_for_user(proto, username, q_data)
        if not ok_sync:
            return False, "Quota - Speed Upload", msg_sync

    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Speed Upload", f"Speed upload diubah ke {_fmt_number(speed_up)} Mbps untuk {username}@{proto}"


def op_quota_speed_limit(proto: str, username: str, enabled: bool) -> tuple[bool, str, str]:
    ok_q, q_path_or_msg, q_data_or_msg = _load_quota(proto, username)
    if not ok_q:
        return False, "Quota - Speed Limit", str(q_path_or_msg)
    q_path = q_path_or_msg
    q_data = q_data_or_msg
    assert isinstance(q_path, Path)
    assert isinstance(q_data, dict)

    st = q_data.get("status") if isinstance(q_data.get("status"), dict) else {}
    st["speed_limit_enabled"] = bool(enabled)

    if enabled:
        down = _to_float(st.get("speed_down_mbit"), 0.0)
        up = _to_float(st.get("speed_up_mbit"), 0.0)
        if down <= 0 or up <= 0:
            return False, "Quota - Speed Limit", "Set speed download/upload > 0 dulu sebelum ON."

    q_data["status"] = st
    _save_quota(q_path, q_data)

    ok_sync, msg_sync = _quota_sync_speed_policy_for_user(proto, username, q_data)
    if not ok_sync:
        return False, "Quota - Speed Limit", msg_sync

    _refresh_account_info_for_user(proto, username)
    return True, "Quota - Speed Limit", f"Speed limit {'ON' if enabled else 'OFF'} untuk {username}@{proto}"


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().lower()


def _apply_nginx_domain(domain: str) -> tuple[bool, str]:
    if not NGINX_CONF.exists():
        return False, f"Nginx conf tidak ditemukan: {NGINX_CONF}"

    original = NGINX_CONF.read_text(encoding="utf-8", errors="ignore")
    changed = False
    out_lines: list[str] = []

    for line in original.splitlines():
        if re.match(r"^\s*server_name\s+", line):
            indent = re.match(r"^(\s*)", line).group(1) if re.match(r"^(\s*)", line) else ""
            out_lines.append(f"{indent}server_name {domain};")
            changed = True
        else:
            out_lines.append(line)

    if not changed:
        return False, "Baris server_name tidak ditemukan di nginx config"

    candidate = "\n".join(out_lines) + "\n"

    try:
        _write_text_atomic(NGINX_CONF, candidate)
        ok_test, out_test = _run_cmd(["nginx", "-t"], timeout=20)
        if not ok_test:
            _write_text_atomic(NGINX_CONF, original)
            return False, f"nginx -t gagal setelah ubah domain:\n{out_test}"

        if not _restart_and_wait("nginx", timeout_sec=20):
            _write_text_atomic(NGINX_CONF, original)
            _restart_and_wait("nginx", timeout_sec=20)
            return False, "nginx gagal restart setelah ubah domain (rollback)."
    except Exception as exc:
        try:
            _write_text_atomic(NGINX_CONF, original)
            _restart_and_wait("nginx", timeout_sec=20)
        except Exception:
            pass
        return False, f"Gagal apply domain ke nginx: {exc}"

    # Keep compatibility with legacy scripts that still read active domain from /etc/xray/domain.
    try:
        XRAY_DOMAIN_FILE.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(XRAY_DOMAIN_FILE, f"{domain}\n")
    except Exception:
        pass

    return True, "ok"


def _parse_bool_text(raw: Any, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return raw
    text = str(raw or "").strip().lower()
    if text in {"1", "true", "yes", "y", "on", "aktif", "enable", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "nonaktif", "disable", "disabled"}:
        return False
    return default


def _download_file(url: str, dest: Path, timeout: int = 60) -> tuple[bool, str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
        _write_text_atomic(dest, data.decode("utf-8", errors="ignore")) if url.endswith(".sh") else dest.write_bytes(data)
        if not url.endswith(".sh"):
            try:
                os.chmod(dest, 0o700)
            except Exception:
                pass
        return True, "ok"
    except Exception as exc:
        return False, f"Gagal download {url}: {exc}"


def _rand_email() -> str:
    return f"admin{random.randint(1000, 9999)}@gmail.com"


def _acme_path() -> Path:
    return Path("/root/.acme.sh/acme.sh")


def _ensure_acme_installed() -> tuple[bool, str]:
    acme = _acme_path()
    if acme.exists():
        _run_cmd([str(acme), "--set-default-ca", "--server", "letsencrypt"], timeout=30)
        return True, "ok"

    account_email = _rand_email()
    tmpdir = Path(tempfile.mkdtemp(prefix="acme-install-"))
    src_dir: Path | None = None
    try:
        tgz = tmpdir / "acme.tar.gz"
        ok_dl, _ = _download_file(ACME_SH_TARBALL_URL, tgz, timeout=120)
        if ok_dl:
            try:
                with tarfile.open(tgz, "r:gz") as tf:
                    tf.extractall(tmpdir)
                for d in tmpdir.iterdir():
                    if d.is_dir() and d.name.startswith("acme.sh-"):
                        src_dir = d
                        break
            except Exception:
                src_dir = None

        if src_dir is None:
            src_dir = tmpdir / "acme-single"
            src_dir.mkdir(parents=True, exist_ok=True)
            ok_script, msg_script = _download_file(ACME_SH_SCRIPT_URL, src_dir / "acme.sh", timeout=120)
            if not ok_script:
                return False, msg_script

        script = src_dir / "acme.sh"
        if not script.exists():
            return False, "acme.sh script tidak ditemukan setelah download."
        try:
            os.chmod(script, 0o700)
        except Exception:
            pass

        ok_install, out_install = _run_cmd(
            ["bash", str(script), "--install", "--home", "/root/.acme.sh", "--accountemail", account_email],
            timeout=240,
            cwd=str(src_dir),
        )
        if not ok_install:
            return False, f"Install acme.sh gagal:\n{out_install}"

        if not acme.exists():
            return False, "acme.sh tidak ditemukan setelah install."

        _run_cmd([str(acme), "--set-default-ca", "--server", "letsencrypt"], timeout=30)
        return True, "ok"
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


def _ensure_dns_cf_hook() -> tuple[bool, str]:
    hook = Path("/root/.acme.sh/dnsapi/dns_cf.sh")
    if hook.exists() and hook.stat().st_size > 0:
        return True, "ok"
    hook.parent.mkdir(parents=True, exist_ok=True)
    ok_dl, msg_dl = _download_file(ACME_SH_DNS_CF_HOOK_URL, hook, timeout=120)
    if not ok_dl:
        return False, msg_dl
    try:
        os.chmod(hook, 0o700)
    except Exception:
        pass
    if not hook.exists() or hook.stat().st_size <= 0:
        return False, "Hook dns_cf tetap tidak ditemukan setelah bootstrap."
    return True, "ok"


def _stop_conflicting_services() -> list[str]:
    stopped: list[str] = []
    for svc in ("nginx", "apache2", "caddy", "lighttpd"):
        if _service_exists(svc) and _service_is_active(svc):
            stopped.append(svc)
        if _service_exists(svc):
            _run_cmd(["systemctl", "stop", svc], timeout=25)
    return stopped


def _restore_services(services: list[str]) -> None:
    for svc in services:
        if _service_exists(svc):
            _run_cmd(["systemctl", "start", svc], timeout=25)


def _cf_api(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> tuple[bool, dict[str, Any] | str]:
    token = CLOUDFLARE_API_TOKEN.strip()
    if not token:
        return False, "CLOUDFLARE_API_TOKEN belum di-set."

    url = f"https://api.cloudflare.com/client/v4{endpoint}"
    data_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data_bytes,
        method=method.upper(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    body_text = ""
    status = 0
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = int(resp.getcode() or 0)
            body_text = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        status = int(exc.code or 0)
        try:
            body_text = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            body_text = str(exc)
    except Exception as exc:
        return False, f"Gagal call Cloudflare API: {exc}"

    if not body_text.strip():
        return False, f"Cloudflare API empty response (HTTP {status or '?'}) for {endpoint}"

    try:
        parsed = json.loads(body_text)
    except Exception:
        return False, f"Cloudflare API non-JSON response (HTTP {status or '?'}) for {endpoint}:\n{body_text}"

    if not (200 <= status < 300):
        return False, f"Cloudflare API HTTP {status} for {endpoint}: {body_text}"

    if not bool(parsed.get("success", False)):
        errs = parsed.get("errors")
        if isinstance(errs, list) and errs:
            msg = "; ".join(str(e.get("message") or e) for e in errs if isinstance(e, dict) or isinstance(e, str))
            if msg:
                return False, f"Cloudflare API error: {msg}"
        return False, f"Cloudflare API success=false untuk endpoint {endpoint}"

    return True, parsed


def _cf_get_zone_id_by_name(zone_name: str) -> tuple[bool, str]:
    endpoint = f"/zones?name={urllib.parse.quote(zone_name)}&per_page=1"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list) or not result:
        return False, f"Zone Cloudflare tidak ditemukan: {zone_name}"
    zid = str((result[0] or {}).get("id") or "").strip()
    if not zid:
        return False, f"Zone id tidak ditemukan untuk: {zone_name}"
    return True, zid


def _cf_get_account_id_by_zone(zone_id: str) -> tuple[bool, str]:
    ok, res = _cf_api("GET", f"/zones/{zone_id}")
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    account_id = str((((payload.get("result") or {}).get("account") or {}).get("id") or "")).strip()
    if not account_id:
        return False, f"CF account id tidak ditemukan untuk zone: {zone_id}"
    return True, account_id


def _cf_list_a_records_by_name(zone_id: str, fqdn: str) -> tuple[bool, list[dict[str, Any]] | str]:
    endpoint = f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(fqdn)}&per_page=100"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list):
        return True, []
    out: list[dict[str, Any]] = []
    for item in result:
        if isinstance(item, dict):
            out.append(item)
    return True, out


def _cf_list_a_records_by_ip(zone_id: str, ip: str) -> tuple[bool, list[dict[str, Any]] | str]:
    endpoint = f"/zones/{zone_id}/dns_records?type=A&content={urllib.parse.quote(ip)}&per_page=100"
    ok, res = _cf_api("GET", endpoint)
    if not ok:
        return False, str(res)
    payload = res if isinstance(res, dict) else {}
    result = payload.get("result")
    if not isinstance(result, list):
        return True, []
    out: list[dict[str, Any]] = []
    for item in result:
        if isinstance(item, dict):
            out.append(item)
    return True, out


def _cf_delete_record(zone_id: str, record_id: str) -> tuple[bool, str]:
    ok, res = _cf_api("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
    if not ok:
        return False, str(res)
    return True, "ok"


def _cf_create_a_record(zone_id: str, name: str, ip: str, proxied: bool = False) -> tuple[bool, str]:
    payload = {
        "type": "A",
        "name": name,
        "content": ip,
        "ttl": 1,
        "proxied": bool(proxied),
    }
    ok, res = _cf_api("POST", f"/zones/{zone_id}/dns_records", payload=payload)
    if not ok:
        return False, str(res)
    return True, "ok"


def _gen_subdomain_random() -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(5))


def _validate_subdomain(subdomain: str) -> bool:
    s = str(subdomain or "").strip()
    if not s:
        return False
    if s != s.lower():
        return False
    if " " in s:
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$", s))


def _resolve_root_domain_input(raw: str) -> tuple[bool, str]:
    text = str(raw or "").strip().lower()
    if not text:
        return False, "Root domain wajib diisi."
    if text.isdigit():
        idx = int(text)
        if 1 <= idx <= len(PROVIDED_ROOT_DOMAINS):
            return True, PROVIDED_ROOT_DOMAINS[idx - 1]
        return False, f"Index root domain di luar range 1-{len(PROVIDED_ROOT_DOMAINS)}."
    for root in PROVIDED_ROOT_DOMAINS:
        if text == root.lower():
            return True, root
    return False, f"Root domain tidak dikenali: {raw}. Pilihan: {', '.join(PROVIDED_ROOT_DOMAINS)}"


def _cf_prepare_subdomain_a_record(
    zone_id: str,
    fqdn: str,
    ip: str,
    proxied: bool,
    allow_existing_same_ip: bool,
) -> tuple[bool, str]:
    ok_name, name_records_or_err = _cf_list_a_records_by_name(zone_id, fqdn)
    if not ok_name:
        return False, str(name_records_or_err)
    name_records = name_records_or_err if isinstance(name_records_or_err, list) else []

    rec_ips = [str(r.get("content") or "").strip() for r in name_records if isinstance(r, dict)]
    if rec_ips:
        any_same = any(v == ip for v in rec_ips)
        any_diff = any(v and v != ip for v in rec_ips)
        if any_same:
            if allow_existing_same_ip:
                return True, f"A record sudah ada dan sama: {fqdn} -> {ip}"
            return False, f"A record {fqdn} -> {ip} sudah ada. Set allow_existing_same_ip=on untuk lanjut."
        if any_diff:
            return False, f"Subdomain {fqdn} sudah ada di Cloudflare tapi IP berbeda: {', '.join(rec_ips)}"

    ok_ip, same_ip_or_err = _cf_list_a_records_by_ip(zone_id, ip)
    if not ok_ip:
        return False, str(same_ip_or_err)
    same_ip_records = same_ip_or_err if isinstance(same_ip_or_err, list) else []
    for rec in same_ip_records:
        rec_id = str(rec.get("id") or "").strip()
        rec_name = str(rec.get("name") or "").strip()
        if not rec_id or not rec_name:
            continue
        if rec_name == fqdn:
            continue
        ok_del, del_msg = _cf_delete_record(zone_id, rec_id)
        if not ok_del:
            return False, f"Gagal hapus A record lama {rec_name}: {del_msg}"

    ok_create, create_msg = _cf_create_a_record(zone_id, fqdn, ip, proxied=proxied)
    if not ok_create:
        return False, create_msg
    return True, f"DNS A record siap: {fqdn} -> {ip} (proxied={'true' if proxied else 'false'})"


def _issue_cert_dns_cf_wildcard(domain: str, root_domain: str, zone_id: str, account_id: str = "") -> tuple[bool, str]:
    ok_verify, verify_res = _cf_api("GET", "/user/tokens/verify")
    if not ok_verify:
        return False, (
            "Token Cloudflare tidak valid/kurang scope. "
            "Butuh minimal Zone:DNS Edit + Zone:Read.\n"
            f"{verify_res}"
        )

    ok_acme, acme_msg = _ensure_acme_installed()
    if not ok_acme:
        return False, acme_msg
    ok_hook, hook_msg = _ensure_dns_cf_hook()
    if not ok_hook:
        return False, hook_msg

    acme = _acme_path()
    env = os.environ.copy()
    env["CF_Token"] = CLOUDFLARE_API_TOKEN
    if account_id:
        env["CF_Account_ID"] = account_id
    if zone_id:
        env["CF_Zone_ID"] = zone_id

    ok_issue, out_issue = _run_cmd(
        [str(acme), "--issue", "--force", "--dns", "dns_cf", "-d", domain, "-d", f"*.{domain}"],
        timeout=360,
        env=env,
    )
    if not ok_issue:
        return False, f"Gagal issue sertifikat wildcard via dns_cf untuk {domain}:\n{out_issue}"

    ok_install, out_install = _run_cmd(
        [
            str(acme),
            "--install-cert",
            "-d",
            domain,
            "--key-file",
            str(CERT_PRIVKEY),
            "--fullchain-file",
            str(CERT_FULLCHAIN),
            "--reloadcmd",
            "systemctl restart nginx || true",
        ],
        timeout=180,
        env=env,
    )
    if not ok_install:
        return False, f"Gagal install sertifikat wildcard untuk {domain}:\n{out_install}"

    _chmod_600(CERT_PRIVKEY)
    _chmod_600(CERT_FULLCHAIN)
    return True, f"Sertifikat wildcard terpasang untuk {domain} (root: {root_domain})"


def _issue_cert_standalone(domain: str) -> tuple[bool, str]:
    ok_acme, acme_msg = _ensure_acme_installed()
    if not ok_acme:
        return False, acme_msg
    acme = _acme_path()

    CERT_DIR.mkdir(parents=True, exist_ok=True)

    ok_issue, out_issue = _run_cmd(
        [
            str(acme),
            "--issue",
            "--force",
            "--standalone",
            "-d",
            domain,
            "--httpport",
            "80",
        ],
        timeout=240,
    )
    if not ok_issue:
        return False, f"Issue cert gagal:\n{out_issue}"

    ok_install, out_install = _run_cmd(
        [
            str(acme),
            "--install-cert",
            "-d",
            domain,
            "--key-file",
            str(CERT_PRIVKEY),
            "--fullchain-file",
            str(CERT_FULLCHAIN),
            "--reloadcmd",
            "systemctl restart nginx || true",
        ],
        timeout=120,
    )
    if not ok_install:
        return False, f"Install cert gagal:\n{out_install}"

    _chmod_600(CERT_PRIVKEY)
    _chmod_600(CERT_FULLCHAIN)
    return True, "ok"


def _get_public_ipv4() -> tuple[bool, str]:
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=6) as resp:
                text = resp.read().decode("utf-8", errors="ignore").strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", text):
                return True, text
        except Exception:
            continue
    fallback = _detect_public_ipv4()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", fallback) and fallback != "0.0.0.0":
        return True, fallback
    return False, "Gagal mendapatkan public IPv4 VPS."


def _parse_subdomain_mode(raw: Any) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        return "auto"
    if text in {"1", "auto", "acak", "random", "generate", "generated"}:
        return "auto"
    if text in {"2", "manual", "input", "custom"}:
        return "manual"
    return ""


def op_domain_cloudflare_root_list() -> tuple[bool, str, str]:
    lines = [f"{i + 1}. {root}" for i, root in enumerate(PROVIDED_ROOT_DOMAINS)]
    msg = "Root domain Cloudflare yang tersedia:\n" + "\n".join(lines)
    msg += "\n\nInput bisa nomor (contoh: 1) atau nama domain penuh."
    return True, "Domain Control - Root Domain List", msg


def op_domain_setup_custom(domain: str) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain (Custom)"
    domain_n = _normalize_domain(domain)
    if not DOMAIN_RE.match(domain_n):
        return False, title, "Domain tidak valid."

    stopped_services = _stop_conflicting_services()
    completed = False
    try:
        ok_cert, cert_msg = _issue_cert_standalone(domain_n)
        if not ok_cert:
            return False, title, cert_msg

        ok_ng, ng_msg = _apply_nginx_domain(domain_n)
        if not ok_ng:
            return False, title, ng_msg
        completed = True
    except Exception as exc:
        return False, title, f"Setup domain custom gagal: {exc}"
    finally:
        # Success path: nginx sudah di-restart oleh _apply_nginx_domain, restore service lain
        # yang tadinya aktif agar state sistem kembali seperti sebelum wizard.
        if completed:
            _restore_services([svc for svc in stopped_services if svc != "nginx"])
        else:
            # Failure path: pastikan semua service yang sebelumnya aktif dipulihkan.
            _restore_services(stopped_services)

    ip_override: str | None = None
    ok_ip, ip_or_err = _get_public_ipv4()
    if ok_ip:
        ip_override = str(ip_or_err)
    updated, failed = _refresh_all_account_info(domain=domain_n, ip=ip_override)
    msg = (
        f"Domain aktif sekarang: {domain_n}\n"
        f"- Certificate mode : standalone\n"
        f"- Refresh account info: updated={updated}, failed={failed}"
    )
    return True, title, msg


def op_domain_setup_cloudflare(
    root_domain_input: str,
    subdomain_mode: str = "auto",
    subdomain: str = "",
    proxied: Any = False,
    allow_existing_same_ip: Any = False,
) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain (Cloudflare Wizard)"

    ok_root, root_or_err = _resolve_root_domain_input(root_domain_input)
    if not ok_root:
        return False, title, str(root_or_err)
    root_domain = str(root_or_err)

    ok_ip, ip_or_err = _get_public_ipv4()
    if not ok_ip:
        return False, title, str(ip_or_err)
    vps_ipv4 = str(ip_or_err)

    ok_zone, zone_or_err = _cf_get_zone_id_by_name(root_domain)
    if not ok_zone:
        return False, title, str(zone_or_err)
    zone_id = str(zone_or_err)

    account_id = ""
    ok_acc, acc_or_err = _cf_get_account_id_by_zone(zone_id)
    if ok_acc:
        account_id = str(acc_or_err)

    mode = _parse_subdomain_mode(subdomain_mode)
    if not mode:
        return (
            False,
            title,
            "subdomain_mode tidak valid. Gunakan: auto/manual (atau 1/2).",
        )

    if mode == "auto":
        sub = _gen_subdomain_random()
    else:
        sub = str(subdomain or "").strip().lower()
        if not _validate_subdomain(sub):
            return (
                False,
                title,
                "Subdomain tidak valid. Hanya huruf kecil, angka, titik, dan strip (-).",
            )

    domain_final = f"{sub}.{root_domain}".lower()
    proxied_b = _parse_bool_text(proxied, default=False)
    allow_same_b = _parse_bool_text(allow_existing_same_ip, default=False)

    ok_dns, dns_msg = _cf_prepare_subdomain_a_record(
        zone_id=zone_id,
        fqdn=domain_final,
        ip=vps_ipv4,
        proxied=proxied_b,
        allow_existing_same_ip=allow_same_b,
    )
    if not ok_dns:
        return False, title, dns_msg

    stopped_services = _stop_conflicting_services()
    completed = False
    try:
        ok_cert, cert_msg = _issue_cert_dns_cf_wildcard(
            domain=domain_final,
            root_domain=root_domain,
            zone_id=zone_id,
            account_id=account_id,
        )
        if not ok_cert:
            return False, title, cert_msg

        ok_ng, ng_msg = _apply_nginx_domain(domain_final)
        if not ok_ng:
            return False, title, ng_msg
        completed = True
    except Exception as exc:
        return False, title, f"Setup Cloudflare wizard gagal: {exc}"
    finally:
        if completed:
            _restore_services([svc for svc in stopped_services if svc != "nginx"])
        else:
            _restore_services(stopped_services)

    updated, failed = _refresh_all_account_info(domain=domain_final, ip=vps_ipv4)
    msg = (
        f"Domain aktif sekarang: {domain_final}\n"
        f"- Root domain      : {root_domain}\n"
        f"- Cloudflare proxy : {'ON' if proxied_b else 'OFF'}\n"
        f"- DNS              : {dns_msg}\n"
        f"- Certificate mode : dns_cf wildcard\n"
        f"- Refresh account info: updated={updated}, failed={failed}"
    )
    if not ok_acc:
        msg += f"\n- Catatan: CF_ACCOUNT_ID tidak ditemukan ({acc_or_err})"
    return True, title, msg


def op_domain_set(domain: str, issue_cert: bool = False) -> tuple[bool, str, str]:
    title = "Domain Control - Set Domain"
    domain_n = _normalize_domain(domain)
    if not DOMAIN_RE.match(domain_n):
        return False, title, "Domain tidak valid."

    if issue_cert:
        ok_setup, _, msg_setup = op_domain_setup_custom(domain_n)
        if not ok_setup:
            return False, title, msg_setup
        return True, title, msg_setup

    ok_ng, ng_msg = _apply_nginx_domain(domain_n)
    if not ok_ng:
        return False, title, ng_msg

    updated, failed = _refresh_all_account_info(domain=domain_n)
    msg = (
        f"Domain berhasil diubah ke: {domain_n}\n"
        f"- Refresh account info: updated={updated}, failed={failed}"
    )
    return True, title, msg


def op_domain_refresh_accounts() -> tuple[bool, str, str]:
    updated, failed = _refresh_all_account_info()
    return True, "Domain Control - Refresh Account Info", f"Selesai: updated={updated}, failed={failed}"


def op_network_set_egress_mode(mode: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set Egress Mode"
    mode_n = str(mode or "").strip().lower()

    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, out_cfg: _routing_set_default_egress_mode(rt_cfg, out_cfg, mode_n)
    )
    if not ok_apply:
        return False, title, msg_apply

    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        return True, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
    return True, title, msg_apply


def op_network_set_balancer_strategy(strategy: str) -> tuple[bool, str, str]:
    title = "Network Controls - Balancer Strategy"
    strategy_n = str(strategy or "").strip()

    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, out_cfg: _routing_set_balancer_strategy(rt_cfg, out_cfg, strategy_n)
    )
    if not ok_apply:
        return False, title, msg_apply

    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        return True, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
    return True, title, msg_apply


def op_network_set_balancer_selector(selector: str) -> tuple[bool, str, str]:
    title = "Network Controls - Balancer Selector"
    selector_n = str(selector or "").strip()

    ok_apply, msg_apply = _apply_routing_transaction(
        lambda rt_cfg, out_cfg: _routing_set_balancer_selector(rt_cfg, out_cfg, selector_n)
    )
    if not ok_apply:
        return False, title, msg_apply

    ok_sync, msg_sync = _speed_policy_sync_xray()
    if not ok_sync:
        return True, title, f"{msg_apply}\nCatatan sinkronisasi speed policy: {msg_sync}"
    return True, title, msg_apply


def op_network_set_balancer_selector_auto() -> tuple[bool, str, str]:
    return op_network_set_balancer_selector("auto")


def op_network_set_dns_primary(value: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set Primary DNS"
    val = str(value or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_primary(cfg, val))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_set_dns_secondary(value: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set Secondary DNS"
    val = str(value or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_secondary(cfg, val))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_set_dns_query_strategy(strategy: str) -> tuple[bool, str, str]:
    title = "Network Controls - Set DNS Query Strategy"
    strategy_n = str(strategy or "").strip()
    ok_apply, msg_apply = _apply_dns_transaction(lambda cfg: _dns_set_query_strategy(cfg, strategy_n))
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply


def op_network_toggle_dns_cache() -> tuple[bool, str, str]:
    title = "Network Controls - Toggle DNS Cache"
    ok_apply, msg_apply = _apply_dns_transaction(_dns_toggle_cache)
    if not ok_apply:
        return False, title, msg_apply
    return True, title, msg_apply
