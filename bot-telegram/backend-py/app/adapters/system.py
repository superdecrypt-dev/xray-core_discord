import base64
import json
import re
import shutil
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, List, Tuple

ACCOUNT_ROOT = Path("/opt/account")
QUOTA_ROOT = Path("/opt/quota")
XRAY_CONFDIR = Path("/usr/local/etc/xray/conf.d")
NGINX_CONF = Path("/etc/nginx/conf.d/xray.conf")
CERT_FULLCHAIN = Path("/opt/cert/fullchain.pem")
NETWORK_STATE_FILE = Path("/var/lib/xray-manage/network_state.json")
WIREPROXY_CONF = Path("/etc/wireproxy/config.conf")
XRAY_OBSERVE_BIN = Path("/usr/local/bin/xray-observe")
XRAY_OBSERVE_CONFIG_FILE = Path("/etc/xray-observe/config.env")
XRAY_OBSERVE_ALERT_LOG = Path("/var/log/xray-observe/alerts.log")
XRAY_OBSERVE_REPORT_FILE = Path("/var/lib/xray-observe/last-report.txt")
XRAY_DOMAIN_GUARD_BIN = Path("/usr/local/bin/xray-domain-guard")
XRAY_DOMAIN_GUARD_CONFIG_FILE = Path("/etc/xray-domain-guard/config.env")
XRAY_DOMAIN_GUARD_LOG_FILE = Path("/var/log/xray-observe/domain-guard.log")
WARP_TIER_STATE_KEY = "warp_tier_target"
WARP_PLUS_LICENSE_STATE_KEY = "warp_plus_license_key"
READONLY_GEOSITE_DOMAINS = (
    "geosite:apple",
    "geosite:meta",
    "geosite:google",
    "geosite:openai",
    "geosite:spotify",
    "geosite:netflix",
    "geosite:reddit",
)
PROTOCOLS = ("vless", "vmess", "trojan")
QUOTA_UNIT_DECIMAL = {"decimal", "gb", "1000", "gigabyte"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
EXIT_CODE_RE = re.compile(r"^\[exit (\d+)\]$")
ALLOWED_SERVICES = (
    "xray",
    "nginx",
    "wireproxy",
    "xray-expired",
    "xray-quota",
    "xray-limit-ip",
    "xray-speed",
)


def run_cmd(argv: List[str], timeout: int = 20) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return False, f"Command tidak ditemukan: {argv[0]}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout: {' '.join(argv)}"
    except Exception as exc:
        return False, f"Gagal menjalankan command: {exc}"

    out = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
    if not out:
        out = "(no output)"
    if proc.returncode != 0:
        return False, f"[exit {proc.returncode}]\n{out}"
    return True, out


def read_json(path: Path) -> Tuple[bool, object]:
    if not path.exists():
        return False, f"File tidak ditemukan: {path}"
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Gagal parse JSON {path}: {exc}"


def bytes_to_gib(value: int) -> str:
    gib = value / (1024 * 1024 * 1024)
    return f"{gib:.2f} GiB"


def memory_summary() -> str:
    meminfo = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            meminfo[key.strip()] = int(raw.strip().split()[0]) * 1024
    except Exception:
        return "-"

    total = meminfo.get("MemTotal", 0)
    avail = meminfo.get("MemAvailable", 0)
    used = max(total - avail, 0)
    if total <= 0:
        return "-"
    return f"{bytes_to_gib(used)} / {bytes_to_gib(total)}"


def detect_domain() -> str:
    # Samakan prioritas dengan manage.sh: nginx server_name -> hostname -f -> hostname.
    if NGINX_CONF.exists():
        for line in NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+);", line)
            if m:
                token = m.group(1).strip().split()[0]
                if token and token != "_":
                    return token
    ok_fqdn, fqdn = run_cmd(["hostname", "-f"], timeout=8)
    if ok_fqdn and fqdn.strip():
        return fqdn.splitlines()[0].strip()
    ok_host, host = run_cmd(["hostname"], timeout=8)
    if ok_host and host.strip():
        return host.splitlines()[0].strip()
    return "-"


def detect_tls_expiry() -> str:
    if not CERT_FULLCHAIN.exists():
        return "cert tidak ditemukan"
    ok, out = run_cmd(["openssl", "x509", "-in", str(CERT_FULLCHAIN), "-noout", "-enddate"], timeout=10)
    if not ok:
        return out
    line = out.splitlines()[-1].strip()
    return line.replace("notAfter=", "")


def service_state(name: str) -> str:
    ok, out = run_cmd(["systemctl", "is-active", name], timeout=8)
    if ok:
        return out.splitlines()[-1].strip()
    return out.splitlines()[-1].strip() if out.strip() else "unknown"


def systemctl_enabled_state(name: str) -> str:
    ok, out = run_cmd(["systemctl", "is-enabled", name], timeout=8)
    if ok:
        return out.splitlines()[-1].strip()
    return out.splitlines()[-1].strip() if out.strip() else "unknown"


def _extract_exit_code(raw: str) -> int | None:
    line = str(raw or "").splitlines()[0].strip() if str(raw or "").splitlines() else ""
    m = EXIT_CODE_RE.match(line)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _tail_lines(path: Path, limit: int = 80) -> list[str]:
    if limit < 1:
        limit = 1
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    return lines[-limit:]


def _human_bytes(value: int) -> str:
    n = max(0, int(value))
    if n >= 1024**4:
        return f"{n / (1024**4):.2f} TiB"
    if n >= 1024**3:
        return f"{n / (1024**3):.2f} GiB"
    if n >= 1024**2:
        return f"{n / (1024**2):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


def op_status_overview() -> tuple[str, str]:
    ok_uptime, uptime = run_cmd(["uptime", "-p"], timeout=8)
    ok_kernel, kernel = run_cmd(["uname", "-sr"], timeout=8)
    ok_host, host = run_cmd(["hostname"], timeout=8)
    ok_ip, ip_raw = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"], timeout=8)

    ip = "-"
    if ok_ip:
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", ip_raw)
        if m:
            ip = m.group(1)

    service_lines = [f"- {svc}: {service_state(svc)}" for svc in ALLOWED_SERVICES]
    msg = (
        "Ringkasan Sistem\n"
        f"- Hostname : {host if ok_host else '-'}\n"
        f"- Kernel   : {kernel if ok_kernel else '-'}\n"
        f"- Uptime   : {uptime if ok_uptime else '-'}\n"
        f"- RAM      : {memory_summary()}\n"
        f"- IPv4     : {ip}\n"
        f"- Domain   : {detect_domain()}\n"
        f"- TLS Exp  : {detect_tls_expiry()}\n\n"
        "Status Service\n"
        + "\n".join(service_lines)
    )
    return "Status & Diagnostics", msg


def op_xray_test() -> tuple[bool, str, str]:
    cmd = ["xray", "run", "-test", "-confdir", str(XRAY_CONFDIR)]
    ok, out = run_cmd(cmd, timeout=20)
    title = "Xray Config Test"

    lines = [line.strip() for line in str(out or "").splitlines() if line.strip()]
    deprec_re = re.compile(r"common/errors:\s*The feature .* is deprecated", re.IGNORECASE)
    deprec_lines = [line for line in lines if deprec_re.search(line)]
    normal_lines = [line for line in lines if not deprec_re.search(line) and not line.startswith("[exit ")]

    if ok:
        msg = (
            "SUCCESS\n"
            "- Konfigurasi Xray valid.\n"
            "- Detail log tidak ditampilkan di Telegram."
        )
        if deprec_lines:
            msg += (
                f"\n- Ditemukan {len(deprec_lines)} warning deprecation transport legacy "
                "(WS/HUP/gRPC/VMess/Trojan)."
            )
        return True, title, msg

    lower_out = str(out or "").lower()
    if "command tidak ditemukan: xray" in lower_out:
        return (
            False,
            title,
            "FAILED\n"
            "- Binary `xray` tidak ditemukan di host.\n"
            "- Periksa instalasi Xray dan PATH service backend.",
        )

    if "timeout:" in lower_out:
        return (
            False,
            title,
            "FAILED\n"
            "- Test config Xray timeout.\n"
            "- Coba ulang saat beban server lebih rendah atau cek health service xray.",
        )

    error_hint = normal_lines[0] if normal_lines else ""
    if len(error_hint) > 180:
        error_hint = error_hint[:177] + "..."

    msg = (
        "FAILED\n"
        "- Test config Xray gagal dijalankan atau konfigurasi tidak valid.\n"
        "- Detail log tidak ditampilkan di Telegram.\n"
        "- Cek manual via SSH: xray run -test -confdir /usr/local/etc/xray/conf.d"
    )
    if deprec_lines:
        msg += (
            f"\n- Catatan: terdeteksi {len(deprec_lines)} warning deprecation transport legacy."
        )
    if error_hint:
        msg += f"\n- Ringkasan error: {error_hint}"
    return False, title, msg


def op_tls_info() -> tuple[bool, str, str]:
    if not CERT_FULLCHAIN.exists():
        return False, "TLS Certificate Info", f"File tidak ada: {CERT_FULLCHAIN}"
    ok, out = run_cmd(
        [
            "openssl",
            "x509",
            "-in",
            str(CERT_FULLCHAIN),
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-startdate",
            "-enddate",
            "-fingerprint",
            "-sha256",
        ],
        timeout=10,
    )
    if ok:
        return True, "TLS Certificate Info", out
    return False, "TLS Certificate Info", f"Gagal membaca cert:\n{out}"


def op_observe_snapshot() -> tuple[bool, str, str]:
    title = "Observability Snapshot"
    if not XRAY_OBSERVE_BIN.exists():
        return False, title, "xray-observe belum terpasang. Jalankan setup.sh terbaru."

    ok, out = run_cmd([str(XRAY_OBSERVE_BIN), "once"], timeout=180)
    rc = 0 if ok else _extract_exit_code(out)

    summary = "Snapshot selesai."
    if rc == 0:
        summary = "Snapshot sehat (critical=0)."
    elif rc == 1:
        summary = "Snapshot selesai dengan critical issue."
    elif rc is not None:
        summary = f"Snapshot selesai dengan status {rc}."

    lines = [
        summary,
        f"Config path : {XRAY_OBSERVE_CONFIG_FILE}",
        f"Alert path  : {XRAY_OBSERVE_ALERT_LOG}",
        f"Report path : {XRAY_OBSERVE_REPORT_FILE}",
    ]

    if XRAY_OBSERVE_REPORT_FILE.exists():
        report_tail = _tail_lines(XRAY_OBSERVE_REPORT_FILE, limit=24)
        if report_tail:
            lines.extend(["", "Last report (tail):", *report_tail])

    if out and out != "(no output)":
        out_lines = [line for line in out.splitlines() if line.strip() and not line.strip().startswith("[exit ")]
        if out_lines:
            lines.extend(["", "Command output:", *out_lines[:30]])

    msg = "\n".join(lines)
    if rc in (None, 0):
        return True, title, msg
    return False, title, msg


def op_observe_status() -> tuple[bool, str, str]:
    title = "Observability Status"
    if not XRAY_OBSERVE_BIN.exists():
        return False, title, "xray-observe belum terpasang. Jalankan setup.sh terbaru."

    lines = [
        f"Binary       : {XRAY_OBSERVE_BIN}",
        f"Config path  : {XRAY_OBSERVE_CONFIG_FILE}",
        f"Alert path   : {XRAY_OBSERVE_ALERT_LOG}",
        f"Report path  : {XRAY_OBSERVE_REPORT_FILE}",
        "",
        f"Timer active : {service_state('xray-observe.timer')}",
        f"Timer enable : {systemctl_enabled_state('xray-observe.timer')}",
        f"Svc active   : {service_state('xray-observe.service')}",
    ]

    if XRAY_OBSERVE_REPORT_FILE.exists():
        report_tail = _tail_lines(XRAY_OBSERVE_REPORT_FILE, limit=24)
        if report_tail:
            lines.extend(["", "Last report (tail):", *report_tail])
    else:
        lines.append("")
        lines.append("Belum ada report observability.")

    return True, title, "\n".join(lines)


def op_observe_alert_log(lines: int = 80) -> tuple[bool, str, str]:
    title = "Observability Alert Log"
    if not XRAY_OBSERVE_ALERT_LOG.exists():
        return False, title, f"Log alert belum tersedia: {XRAY_OBSERVE_ALERT_LOG}"

    log_lines = _tail_lines(XRAY_OBSERVE_ALERT_LOG, limit=lines)
    if not log_lines:
        return False, title, f"Log alert kosong: {XRAY_OBSERVE_ALERT_LOG}"
    return True, title, "\n".join(log_lines)


def op_domain_guard_check() -> tuple[bool, str, str]:
    title = "Domain & Cert Guard Check"
    if not XRAY_DOMAIN_GUARD_BIN.exists():
        return False, title, "xray-domain-guard belum terpasang. Jalankan setup.sh terbaru."

    ok, out = run_cmd([str(XRAY_DOMAIN_GUARD_BIN), "check"], timeout=180)
    rc = 0 if ok else _extract_exit_code(out)

    summary = "Check selesai."
    if rc == 0:
        summary = "Domain & cert sehat."
    elif rc == 1:
        summary = "Check selesai: warning terdeteksi."
    elif rc == 2:
        summary = "Check selesai: kondisi critical terdeteksi."
    elif rc is not None:
        summary = f"Check selesai dengan status {rc}."

    lines = [
        summary,
        f"Config path : {XRAY_DOMAIN_GUARD_CONFIG_FILE}",
        f"Log path    : {XRAY_DOMAIN_GUARD_LOG_FILE}",
    ]
    if out and out != "(no output)":
        out_lines = [line for line in out.splitlines() if line.strip() and not line.strip().startswith("[exit ")]
        if out_lines:
            lines.extend(["", "Command output:", *out_lines[:40]])
    msg = "\n".join(lines)
    if rc in (None, 0):
        return True, title, msg
    return False, title, msg


def op_domain_guard_status() -> tuple[bool, str, str]:
    title = "Domain & Cert Guard Status"
    if not XRAY_DOMAIN_GUARD_BIN.exists():
        return False, title, "xray-domain-guard belum terpasang. Jalankan setup.sh terbaru."

    lines = [
        f"Binary       : {XRAY_DOMAIN_GUARD_BIN}",
        f"Config path  : {XRAY_DOMAIN_GUARD_CONFIG_FILE}",
        f"Log path     : {XRAY_DOMAIN_GUARD_LOG_FILE}",
        "",
        f"Timer active : {service_state('xray-domain-guard.timer')}",
        f"Timer enable : {systemctl_enabled_state('xray-domain-guard.timer')}",
        f"Svc active   : {service_state('xray-domain-guard.service')}",
    ]

    if XRAY_DOMAIN_GUARD_LOG_FILE.exists():
        log_tail = _tail_lines(XRAY_DOMAIN_GUARD_LOG_FILE, limit=24)
        if log_tail:
            lines.extend(["", "Domain guard log (tail):", *log_tail])

    return True, title, "\n".join(lines)


def op_domain_guard_renew_if_needed(force: bool = False) -> tuple[bool, str, str]:
    title = "Domain & Cert Guard Renew-if-Needed"
    if not XRAY_DOMAIN_GUARD_BIN.exists():
        return False, title, "xray-domain-guard belum terpasang. Jalankan setup.sh terbaru."

    cmd = [str(XRAY_DOMAIN_GUARD_BIN), "renew-if-needed"]
    if force:
        cmd.append("--force")
    ok, out = run_cmd(cmd, timeout=300)
    rc = 0 if ok else _extract_exit_code(out)

    summary = "Renew-if-needed selesai."
    if rc == 0:
        summary = "Renew-if-needed selesai, status sehat."
    elif rc == 1:
        summary = "Renew-if-needed selesai dengan warning."
    elif rc == 2:
        summary = "Renew-if-needed selesai namun masih ada kondisi critical."
    elif rc is not None:
        summary = f"Renew-if-needed selesai dengan status {rc}."

    lines = [summary, f"Log path: {XRAY_DOMAIN_GUARD_LOG_FILE}"]
    if out and out != "(no output)":
        out_lines = [line for line in out.splitlines() if line.strip() and not line.strip().startswith("[exit ")]
        if out_lines:
            lines.extend(["", "Command output:", *out_lines[:40]])
    msg = "\n".join(lines)
    if rc in (None, 0):
        return True, title, msg
    return False, title, msg


def list_accounts() -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    for proto in PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        selected: dict[str, Path] = {}
        selected_has_at: dict[str, bool] = {}
        for path in sorted(d.glob("*.txt")):
            stem = path.stem
            suffix = f"@{proto}"
            username = stem[: -len(suffix)] if stem.endswith(suffix) else stem
            if not username:
                continue
            has_at = "@" in stem
            prev = selected.get(username)
            if prev is not None:
                if has_at and not selected_has_at.get(username, False):
                    selected[username] = path
                    selected_has_at[username] = True
                continue
            selected[username] = path
            selected_has_at[username] = has_at
        for username in sorted(selected.keys()):
            records.append((proto, username))
    return records


def op_user_list() -> tuple[str, str]:
    records = list_accounts()
    if not records:
        return "User Management - List", f"Tidak ada data di {ACCOUNT_ROOT}/{{vless,vmess,trojan}}"

    counts = {p: 0 for p in PROTOCOLS}
    for proto, _ in records:
        counts[proto] += 1

    lines = [f"{i+1:03d}. {user} [{proto}]" for i, (proto, user) in enumerate(records[:250])]
    body = (
        f"Total user: {len(records)}\n"
        f"- vless : {counts['vless']}\n"
        f"- vmess : {counts['vmess']}\n"
        f"- trojan: {counts['trojan']}\n\n"
        "Daftar (maks 250):\n"
        + "\n".join(lines)
    )
    return "User Management - List", body


def op_user_search(query: str) -> tuple[str, str]:
    q = query.lower().strip()
    records = list_accounts()
    hits = [(proto, user) for proto, user in records if q in user.lower()]
    if not hits:
        return "User Management - Search", f"Tidak ada user cocok dengan query: {query}"
    lines = [f"{i+1:03d}. {user} [{proto}]" for i, (proto, user) in enumerate(hits[:250])]
    return "User Management - Search", f"Hasil: {len(hits)}\n\n" + "\n".join(lines)


def _quota_candidates(proto: str, username: str) -> list[Path]:
    return [
        QUOTA_ROOT / proto / f"{username}@{proto}.json",
        QUOTA_ROOT / proto / f"{username}.json",
    ]


def _account_candidates(proto: str, username: str) -> list[Path]:
    return [
        ACCOUNT_ROOT / proto / f"{username}@{proto}.txt",
        ACCOUNT_ROOT / proto / f"{username}.txt",
    ]


def _is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username))


def _to_int(v: object, default: int = 0) -> int:
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


def _to_float(v: object, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return float(int(v))
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).strip()
        if not s:
            return default
        return float(s)
    except Exception:
        return default


def _fmt_number(value: float) -> str:
    if value <= 0:
        return "0"
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.3f}".rstrip("0").rstrip(".")


def _fmt_quota_limit_gb(data: dict) -> str:
    quota_limit = _to_int(data.get("quota_limit"), 0)
    if quota_limit <= 0:
        return "0 GB"
    unit = str(data.get("quota_unit") or "binary").strip().lower()
    bpg = 1000**3 if unit in QUOTA_UNIT_DECIMAL else 1024**3
    return f"{_fmt_number(quota_limit / bpg)} GB"


def _fmt_quota_used(data: dict) -> str:
    used = _to_int(data.get("quota_used"), 0)
    if used < 0:
        used = 0
    if used >= 1024**3:
        return f"{used / (1024**3):.2f} GB"
    if used >= 1024**2:
        return f"{used / (1024**2):.2f} MB"
    if used >= 1024:
        return f"{used / 1024:.2f} KB"
    return f"{used} B"


def _status_block_reason(status: dict) -> str:
    lock_reason = str(status.get("lock_reason") or "").strip().lower()
    if bool(status.get("manual_block")) or lock_reason == "manual":
        return "MANUAL"
    if bool(status.get("quota_exhausted")) or lock_reason == "quota":
        return "QUOTA"
    if bool(status.get("ip_limit_locked")) or lock_reason == "ip_limit":
        return "IP_LIMIT"
    return "-"


def _status_ip_limit(status: dict) -> str:
    enabled = bool(status.get("ip_limit_enabled"))
    limit = _to_int(status.get("ip_limit"), 0)
    if not enabled:
        return "OFF"
    return f"ON({limit})" if limit > 0 else "ON"


def _status_speed_limit(status: dict) -> str:
    enabled = bool(status.get("speed_limit_enabled"))
    if not enabled:
        return "OFF"
    down = _to_float(status.get("speed_down_mbit"), 0.0)
    up = _to_float(status.get("speed_up_mbit"), 0.0)
    if down <= 0 or up <= 0:
        return "OFF"
    return f"ON({_fmt_number(down)}/{_fmt_number(up)} Mbps)"


def _fmt_active_period(data: dict) -> str:
    expired_at = str(data.get("expired_at") or "").strip()[:10]
    if not expired_at:
        return "-"
    try:
        exp_date = datetime.strptime(expired_at, "%Y-%m-%d").date()
        remain = max(0, (exp_date - date.today()).days)
        return f"{remain} hari (sampai {expired_at})"
    except Exception:
        return expired_at


def _read_account_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    if not path.exists():
        return fields
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in raw:
                continue
            key, value = raw.split(":", 1)
            fields[key.strip()] = value.strip()
    except Exception:
        return {}
    return fields


def _fmt_active_period_from_account_fields(fields: dict[str, str]) -> str:
    valid_until = str(fields.get("Valid Until") or "").strip()[:10]
    if valid_until:
        try:
            exp_date = datetime.strptime(valid_until, "%Y-%m-%d").date()
            remain = max(0, (exp_date - date.today()).days)
            return f"{remain} hari (sampai {valid_until})"
        except Exception:
            return valid_until

    expired_raw = str(fields.get("Expired") or "").strip()
    if not expired_raw:
        return "-"
    match = re.search(r"(\d+)", expired_raw)
    if not match:
        return expired_raw
    try:
        days = max(0, int(match.group(1)))
    except Exception:
        return expired_raw
    return f"{days} hari"


def _fmt_quota_limit_from_account_fields(fields: dict[str, str]) -> str:
    quota_raw = str(fields.get("Quota Limit") or "").strip()
    if not quota_raw:
        return "0 GB"
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)", quota_raw)
    if not match:
        return quota_raw
    try:
        return f"{_fmt_number(float(match.group(1)))} GB"
    except Exception:
        return quota_raw


def _fmt_ip_limit_from_account_fields(fields: dict[str, str]) -> str:
    ip_raw = str(fields.get("IP Limit") or "").strip()
    if not ip_raw:
        return "OFF"
    if ip_raw.upper().startswith("OFF"):
        return "OFF"
    match = re.search(r"ON\s*\((\d+)\)", ip_raw, re.IGNORECASE)
    if match:
        return f"ON({match.group(1)})"
    if ip_raw.upper().startswith("ON"):
        return "ON"
    return ip_raw


def _fmt_speed_limit_from_account_fields(fields: dict[str, str]) -> str:
    speed_raw = str(fields.get("Speed Limit") or "").strip()
    if not speed_raw:
        return "OFF"
    if speed_raw.upper().startswith("OFF"):
        return "OFF"
    down_match = re.search(r"DOWN\s*([0-9]+(?:\.[0-9]+)?)", speed_raw, re.IGNORECASE)
    up_match = re.search(r"UP\s*([0-9]+(?:\.[0-9]+)?)", speed_raw, re.IGNORECASE)
    if down_match and up_match:
        try:
            down = _fmt_number(float(down_match.group(1)))
            up = _fmt_number(float(up_match.group(1)))
            return f"ON({down}/{up} Mbps)"
        except Exception:
            return speed_raw
    return speed_raw


def _iter_proto_quota_files(proto: str) -> list[tuple[str, Path]]:
    d = QUOTA_ROOT / proto
    if not d.exists():
        return []

    selected: dict[str, Path] = {}
    selected_has_at: dict[str, bool] = {}
    for path in sorted(d.glob("*.json")):
        stem = path.stem
        suffix = f"@{proto}"
        username = stem[: -len(suffix)] if stem.endswith(suffix) else stem
        if not username:
            continue
        has_at = "@" in stem
        prev = selected.get(username)
        if prev is not None:
            if has_at and not selected_has_at.get(username, False):
                selected[username] = path
                selected_has_at[username] = True
            continue
        selected[username] = path
        selected_has_at[username] = has_at
    return [(u, selected[u]) for u in sorted(selected.keys())]


def _pick_field(data: dict, keys: list[str], default: str = "-") -> str:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return str(data[key])
    return default


def op_quota_summary() -> tuple[str, str]:
    lines: list[str] = []
    count = 0
    for proto in PROTOCOLS:
        for username, path in _iter_proto_quota_files(proto):
            ok, payload = read_json(path)
            if not ok:
                lines.append(f"- {proto}/{path.name}: invalid json")
                count += 1
                continue

            data = payload if isinstance(payload, dict) else {}
            status = data.get("status") if isinstance(data.get("status"), dict) else {}
            exp = str(_pick_field(data, ["expired_at", "expired", "expiry", "expires"]))[:10]
            quota = _fmt_quota_limit_gb(data)
            used = _fmt_quota_used(data)
            ip_limit = _status_ip_limit(status)
            speed_limit = _status_speed_limit(status)
            block = _status_block_reason(status)
            lines.append(
                f"- {username} [{proto}] limit={quota} used={used} exp={exp} ip={ip_limit} speed={speed_limit} block={block}"
            )
            count += 1
            if count >= 200:
                break
        if count >= 200:
            break

    if not lines:
        return "Quota & Access Control - Summary", f"Tidak ada file quota di {QUOTA_ROOT}/{{vless,vmess,trojan}}"
    return "Quota & Access Control - Summary", "Maks 200 entri:\n" + "\n".join(lines)


def op_quota_detail(proto: str, username: str) -> tuple[str, str]:
    if proto not in PROTOCOLS:
        return "Quota & Access Control - Detail", f"Proto tidak valid: {proto}"
    if not _is_valid_username(username):
        return "Quota & Access Control - Detail", "Username tidak valid. Gunakan huruf/angka/._- tanpa spasi."
    for candidate in _quota_candidates(proto, username):
        if not candidate.exists():
            continue
        ok, payload = read_json(candidate)
        if not ok:
            return "Quota & Access Control - Detail", str(payload)
        parts = [f"Quota File: {candidate}", "", json.dumps(payload, indent=2, ensure_ascii=False)]

        account_file = next((p for p in _account_candidates(proto, username) if p.exists()), None)
        if account_file is not None:
            try:
                account_text = account_file.read_text(encoding="utf-8", errors="ignore").strip()
            except Exception as exc:
                account_text = f"Gagal membaca {account_file}: {exc}"
            parts.extend(
                [
                    "",
                    f"XRAY ACCOUNT INFO File: {account_file}",
                    "",
                    account_text or "(kosong)",
                ]
            )
        else:
            parts.extend(["", "XRAY ACCOUNT INFO: file tidak ditemukan di /opt/account"])

        return "Quota & Access Control - Detail", "\n".join(parts)
    return "Quota & Access Control - Detail", f"File quota tidak ditemukan untuk {username} [{proto}]"


def op_account_info(proto: str, username: str) -> tuple[str, str]:
    proto_n = proto.lower().strip()
    user_n = username.strip()
    if proto_n not in PROTOCOLS:
        return "User Management - Account Info", f"Proto tidak valid: {proto}"
    if not _is_valid_username(user_n):
        return "User Management - Account Info", "Username tidak valid. Gunakan huruf/angka/._- tanpa spasi."

    for candidate in _account_candidates(proto_n, user_n):
        if not candidate.exists():
            continue
        try:
            content = candidate.read_text(encoding="utf-8", errors="ignore").strip()
        except Exception as exc:
            return "User Management - Account Info", f"Gagal membaca file {candidate}: {exc}"
        if not content:
            content = "(kosong)"
        return "User Management - Account Info", f"File: {candidate}\n\n{content}"
    return "User Management - Account Info", f"File account tidak ditemukan untuk {user_n} [{proto_n}]"


def op_account_info_summary(proto: str, username: str) -> tuple[bool, dict[str, str] | str]:
    proto_n = proto.lower().strip()
    user_n = username.strip()
    if proto_n not in PROTOCOLS:
        return False, f"Proto tidak valid: {proto}"
    if not _is_valid_username(user_n):
        return False, "Username tidak valid. Gunakan huruf/angka/._- tanpa spasi."

    for candidate in _quota_candidates(proto_n, user_n):
        if not candidate.exists():
            continue
        ok, payload = read_json(candidate)
        if not ok:
            return False, str(payload)
        if not isinstance(payload, dict):
            return False, f"Format quota tidak valid: {candidate}"
        status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
        return True, {
            "username": user_n,
            "protocol": proto_n,
            "active_period": _fmt_active_period(payload),
            "quota_gb": _fmt_quota_limit_gb(payload),
            "ip_limit": _status_ip_limit(status),
            "speed_limit": _status_speed_limit(status),
        }
    for candidate in _account_candidates(proto_n, user_n):
        if not candidate.exists():
            continue
        fields = _read_account_fields(candidate)
        if not fields:
            continue
        protocol = str(fields.get("Protocol") or proto_n).strip().lower()
        if protocol not in PROTOCOLS:
            protocol = proto_n
        return True, {
            "username": str(fields.get("Username") or user_n).strip() or user_n,
            "protocol": protocol,
            "active_period": _fmt_active_period_from_account_fields(fields),
            "quota_gb": _fmt_quota_limit_from_account_fields(fields),
            "ip_limit": _fmt_ip_limit_from_account_fields(fields),
            "speed_limit": _fmt_speed_limit_from_account_fields(fields),
        }
    return False, f"File quota/account tidak ditemukan untuk {user_n} [{proto_n}]"


def op_network_outbound_summary() -> tuple[str, str]:
    out_file = XRAY_CONFDIR / "20-outbounds.json"
    route_file = XRAY_CONFDIR / "30-routing.json"
    lines = []

    ok_out, payload_out = read_json(out_file)
    if ok_out and isinstance(payload_out, dict):
        outbounds = payload_out.get("outbounds", [])
        tags = []
        if isinstance(outbounds, list):
            for item in outbounds:
                if isinstance(item, dict) and isinstance(item.get("tag"), str):
                    tags.append(item["tag"])
        lines.append(f"Outbounds: {len(tags)}")
        if tags:
            lines.append("Tags: " + ", ".join(tags[:40]))
    else:
        lines.append(f"Gagal baca outbounds: {payload_out}")

    ok_rt, payload_rt = read_json(route_file)
    if ok_rt and isinstance(payload_rt, dict):
        routing = payload_rt.get("routing", {})
        rules = routing.get("rules", []) if isinstance(routing, dict) else []
        balancers = routing.get("balancers", []) if isinstance(routing, dict) else []
        lines.append(f"Routing rules: {len(rules) if isinstance(rules, list) else 0}")
        lines.append(f"Balancers: {len(balancers) if isinstance(balancers, list) else 0}")
    else:
        lines.append(f"Gagal baca routing: {payload_rt}")

    return "Network Controls - Egress Summary", "\n".join(lines)


def op_dns_summary() -> tuple[str, str]:
    dns_file = XRAY_CONFDIR / "02-dns.json"
    ok, payload = read_json(dns_file)
    if not ok:
        return "Network Controls - DNS", str(payload)
    if not isinstance(payload, dict):
        return "Network Controls - DNS", f"Format DNS tidak valid di {dns_file}"

    dns_obj = payload.get("dns", {})
    if not isinstance(dns_obj, dict):
        return "Network Controls - DNS", f"Objek dns tidak ditemukan di {dns_file}"

    query_strategy = dns_obj.get("queryStrategy", "-")
    servers = dns_obj.get("servers", [])
    hosts = dns_obj.get("hosts", {})

    lines = [f"queryStrategy: {query_strategy}", "servers:"]
    if isinstance(servers, list):
        for item in servers[:30]:
            lines.append(f"- {item}")
    if isinstance(hosts, dict):
        lines.append(f"hosts entries: {len(hosts)}")

    return "Network Controls - DNS", "\n".join(lines)


def op_network_state_raw() -> tuple[str, str]:
    if not NETWORK_STATE_FILE.exists():
        return "Network Controls - State File", f"File tidak ditemukan: {NETWORK_STATE_FILE}"
    ok, payload = read_json(NETWORK_STATE_FILE)
    if not ok:
        return "Network Controls - State File", str(payload)
    return "Network Controls - State File", json.dumps(payload, indent=2, ensure_ascii=False)


def list_inbound_tags() -> list[str]:
    src = XRAY_CONFDIR / "10-inbounds.json"
    ok, payload = read_json(src)
    if not ok or not isinstance(payload, dict):
        return []

    out: list[str] = []
    seen: set[str] = set()
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        return []

    for item in inbounds:
        if not isinstance(item, dict):
            continue
        tag = str(item.get("tag") or "").strip()
        if not tag or tag == "api" or tag in seen:
            continue
        seen.add(tag)
        out.append(tag)
    out.sort()
    return out


def list_warp_domain_options(mode: str | None = None) -> list[str]:
    src = XRAY_CONFDIR / "30-routing.json"
    ok, payload = read_json(src)
    if not ok or not isinstance(payload, dict):
        return []

    routing = payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return []

    def collect_custom(outbound: str, marker: str) -> list[str]:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field":
                continue
            if str(rule.get("outboundTag") or "") != outbound:
                continue
            domains = rule.get("domain")
            if not isinstance(domains, list) or marker not in domains:
                continue
            found: list[str] = []
            for entry in domains:
                if not isinstance(entry, str):
                    continue
                ent = entry.strip()
                if not ent or ent == marker or ent in READONLY_GEOSITE_DOMAINS:
                    continue
                found.append(ent)
            return found
        return []

    requested = str(mode or "").strip().lower()
    selected: list[str] = []
    if requested == "direct":
        selected = collect_custom("direct", "regexp:^$")
    elif requested == "warp":
        selected = collect_custom("warp", "regexp:^$WARP")
    else:
        selected = collect_custom("direct", "regexp:^$") + collect_custom("warp", "regexp:^$WARP")

    ordered: list[str] = []
    seen: set[str] = set()
    for entry in selected:
        if entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    return ordered


def _warp_state_get(key: str) -> str:
    ok, payload = read_json(NETWORK_STATE_FILE)
    if not ok or not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    if value is None:
        return ""
    return str(value).strip()


def _warp_mask_license(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "(kosong)"
    if len(raw) <= 8:
        return raw
    return f"{raw[:4]}****{raw[-4:]}"


def _wireproxy_socks_bind_address() -> str:
    if not WIREPROXY_CONF.exists():
        return "127.0.0.1:40000"
    current_section = ""
    for raw in WIREPROXY_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            continue
        if current_section not in {"socks", "socks5"}:
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        if key.lower() == "bindaddress" and value:
            return value
    return "127.0.0.1:40000"


def _warp_live_tier() -> str:
    if shutil.which("curl") is None:
        return "unknown"
    bind_addr = _wireproxy_socks_bind_address()
    ok, out = run_cmd(
        [
            "curl",
            "-fsS",
            "--max-time",
            "8",
            "--socks5",
            bind_addr,
            "https://www.cloudflare.com/cdn-cgi/trace",
        ],
        timeout=12,
    )
    if not ok:
        return "unknown"
    warp_val = ""
    for raw in out.splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == "warp":
            warp_val = v.strip().lower()
            break
    if warp_val == "plus":
        return "plus"
    if warp_val == "on":
        return "free"
    if warp_val == "off":
        return "off"
    return "unknown"


def _current_egress_mode_summary() -> str:
    rt_src = XRAY_CONFDIR / "30-routing.json"
    ok, payload = read_json(rt_src)
    if not ok or not isinstance(payload, dict):
        return "unknown"

    routing = payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return "unknown"

    target: dict | None = None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "field":
            continue
        port = str(rule.get("port") or "").strip()
        if port not in {"1-65535", "0-65535"}:
            continue
        if rule.get("user") or rule.get("domain") or rule.get("ip") or rule.get("protocol"):
            continue
        target = rule
    if not isinstance(target, dict):
        return "unknown"

    balancer = str(target.get("balancerTag") or "").strip()
    if balancer:
        return f"balancer ({balancer})"
    outbound = str(target.get("outboundTag") or "").strip().lower()
    if outbound in {"direct", "warp"}:
        return outbound
    return "unknown"


def op_network_warp_status_report() -> tuple[str, str]:
    title = "Network Controls - WARP Status"
    rt_src = XRAY_CONFDIR / "30-routing.json"
    ok, payload = read_json(rt_src)
    if not ok or not isinstance(payload, dict):
        return title, f"Gagal baca routing: {payload}"

    routing = payload.get("routing")
    rules = routing.get("rules") if isinstance(routing, dict) else None
    if not isinstance(rules, list):
        return title, "Format routing.rules tidak valid."

    def _rule_list_user(marker: str, outbound: str) -> list[str]:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field" or str(rule.get("outboundTag") or "") != outbound:
                continue
            users = rule.get("user")
            if not isinstance(users, list) or marker not in users:
                continue
            out: list[str] = []
            seen: set[str] = set()
            for item in users:
                if not isinstance(item, str):
                    continue
                value = item.strip()
                if not value or value == marker or value in seen:
                    continue
                seen.add(value)
                out.append(value)
            return out
        return []

    def _rule_list_inbound(marker: str, outbound: str) -> list[str]:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field" or str(rule.get("outboundTag") or "") != outbound:
                continue
            tags = rule.get("inboundTag")
            if not isinstance(tags, list) or marker not in tags:
                continue
            out: list[str] = []
            seen: set[str] = set()
            for item in tags:
                if not isinstance(item, str):
                    continue
                value = item.strip()
                if not value or value == marker or value in seen:
                    continue
                seen.add(value)
                out.append(value)
            return out
        return []

    def _rule_list_domain(marker: str, outbound: str) -> list[str]:
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") != "field" or str(rule.get("outboundTag") or "") != outbound:
                continue
            domains = rule.get("domain")
            if not isinstance(domains, list) or marker not in domains:
                continue
            out: list[str] = []
            seen: set[str] = set()
            for item in domains:
                if not isinstance(item, str):
                    continue
                value = item.strip()
                if not value or value == marker or value in seen:
                    continue
                seen.add(value)
                out.append(value)
            return out
        return []

    user_warp = _rule_list_user("dummy-warp-user", "warp")
    user_direct = _rule_list_user("dummy-direct-user", "direct")
    inb_warp = _rule_list_inbound("dummy-warp-inbounds", "warp")
    inb_direct = _rule_list_inbound("dummy-direct-inbounds", "direct")
    dom_direct = _rule_list_domain("regexp:^$", "direct")
    dom_warp = _rule_list_domain("regexp:^$WARP", "warp")

    lines = [
        f"Egress Global : {_current_egress_mode_summary()}",
        f"wireproxy     : {service_state('wireproxy')}",
        f"User Override : warp={len(user_warp)}, direct={len(user_direct)}",
        f"Inbound Ovr   : warp={len(inb_warp)}, direct={len(inb_direct)}",
        f"Domain List   : direct={len(dom_direct)}, warp={len(dom_warp)}",
        "",
        "User warp (sample): " + (", ".join(user_warp[:8]) if user_warp else "-"),
        "User direct (sample): " + (", ".join(user_direct[:8]) if user_direct else "-"),
        "Inbound warp (sample): " + (", ".join(inb_warp[:8]) if inb_warp else "-"),
        "Inbound direct (sample): " + (", ".join(inb_direct[:8]) if inb_direct else "-"),
        "Domain direct (sample): " + (", ".join(dom_direct[:8]) if dom_direct else "-"),
        "Domain warp (sample): " + (", ".join(dom_warp[:8]) if dom_warp else "-"),
        "",
        f"Tier target   : {_warp_state_get(WARP_TIER_STATE_KEY) or 'unknown'}",
        f"Tier live     : {_warp_live_tier()}",
        f"WARP+ License : {_warp_mask_license(_warp_state_get(WARP_PLUS_LICENSE_STATE_KEY))}",
    ]
    return title, "\n".join(lines)


def op_network_warp_tier_status() -> tuple[str, str]:
    title = "Network Controls - WARP Tier Status"
    lines = [
        f"Target Tier   : {_warp_state_get(WARP_TIER_STATE_KEY) or 'unknown'}",
        f"Live Tier     : {_warp_live_tier()}",
        f"wireproxy     : {service_state('wireproxy')}",
        f"WARP+ License : {_warp_mask_license(_warp_state_get(WARP_PLUS_LICENSE_STATE_KEY))}",
        f"WGCF Account  : {'OK' if Path('/etc/wgcf/wgcf-account.toml').exists() else 'missing'}",
        f"WGCF Profile  : {'OK' if Path('/etc/wgcf/wgcf-profile.conf').exists() else 'missing'}",
    ]
    return title, "\n".join(lines)


def op_domain_info() -> tuple[str, str]:
    body = (
        f"Domain aktif : {detect_domain()}\n"
        f"Cert file    : {CERT_FULLCHAIN}\n"
        f"TLS expiry   : {detect_tls_expiry()}"
    )
    return "Domain Control", body


def op_domain_nginx_server_name() -> tuple[str, str]:
    if not NGINX_CONF.exists():
        return "Domain Control - Nginx Server Name", f"File tidak ditemukan: {NGINX_CONF}"
    lines = []
    for line in NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
        if re.match(r"^\s*server_name\s+", line):
            lines.append(line.rstrip())
    if not lines:
        lines.append("(tidak ada baris server_name)")
    return "Domain Control - Nginx Server Name", "\n".join(lines)


def _traffic_analytics_dataset() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    proto_summary: dict[str, dict[str, int]] = {
        proto: {"users": 0, "used_bytes": 0, "quota_bytes": 0}
        for proto in PROTOCOLS
    }

    for proto in PROTOCOLS:
        for username, path in _iter_proto_quota_files(proto):
            ok, payload = read_json(path)
            data = payload if ok and isinstance(payload, dict) else {}

            resolved_username = str(data.get("username") or username).strip() or username
            used_bytes = max(0, _to_int(data.get("quota_used"), 0))
            quota_bytes = max(0, _to_int(data.get("quota_limit"), 0))
            expired_at = str(data.get("expired_at") or "-").strip()[:10] or "-"

            entries.append(
                {
                    "username": resolved_username,
                    "proto": proto,
                    "used_bytes": used_bytes,
                    "quota_bytes": quota_bytes,
                    "expired_at": expired_at,
                    "source_file": str(path),
                }
            )
            proto_summary[proto]["users"] += 1
            proto_summary[proto]["used_bytes"] += used_bytes
            proto_summary[proto]["quota_bytes"] += quota_bytes

    entries.sort(
        key=lambda item: (
            -int(item.get("used_bytes", 0)),
            str(item.get("username", "")).lower(),
            str(item.get("proto", "")).lower(),
        )
    )

    total_used = sum(int(item.get("used_bytes", 0)) for item in entries)
    total_quota = sum(int(item.get("quota_bytes", 0)) for item in entries)

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "quota_root": str(QUOTA_ROOT),
        "total_users": len(entries),
        "total_used_bytes": total_used,
        "total_quota_bytes": total_quota,
        "protocols": proto_summary,
        "top_users": entries,
    }


def _traffic_pct_text(used_bytes: int, quota_bytes: int) -> str:
    if quota_bytes <= 0:
        return "-"
    return f"{(used_bytes * 100.0 / quota_bytes):.1f}"


def op_traffic_analytics_overview() -> tuple[str, str]:
    data = _traffic_analytics_dataset()
    total_users = int(data.get("total_users") or 0)
    total_used = int(data.get("total_used_bytes") or 0)
    total_quota = int(data.get("total_quota_bytes") or 0)
    avg_used = int(total_used / total_users) if total_users > 0 else 0

    lines = [
        f"Generated UTC : {data.get('generated_at_utc') or '-'}",
        f"Total Users   : {total_users}",
        f"Total Used    : {_human_bytes(total_used)}",
        f"Total Quota   : {_human_bytes(total_quota)}",
        f"Avg/User Used : {_human_bytes(avg_used)}",
        "",
        "By Protocol:",
    ]

    protocols = data.get("protocols") if isinstance(data.get("protocols"), dict) else {}
    for proto in PROTOCOLS:
        info = protocols.get(proto) if isinstance(protocols, dict) else {}
        users = _to_int((info or {}).get("users"), 0)
        used = _to_int((info or {}).get("used_bytes"), 0)
        quota = _to_int((info or {}).get("quota_bytes"), 0)
        lines.append(
            f"  {proto.upper():<6} users={users:<4} used={_human_bytes(used):<12} quota={_human_bytes(quota)}"
        )

    top_users = data.get("top_users") if isinstance(data.get("top_users"), list) else []
    lines.extend(["", "Top 5 Users:"])
    if not top_users:
        lines.append("  (kosong)")
    else:
        for idx, row in enumerate(top_users[:5], start=1):
            username = str((row or {}).get("username") or "-")
            proto = str((row or {}).get("proto") or "-").upper()
            used = _human_bytes(_to_int((row or {}).get("used_bytes"), 0))
            lines.append(f"  {idx:>2}. {username:<20} {proto:<6} {used}")

    return "Traffic Analytics - Overview", "\n".join(lines)


def op_traffic_analytics_top_users(limit: int = 15) -> tuple[str, str]:
    cap = max(1, min(200, int(limit)))
    data = _traffic_analytics_dataset()
    rows = data.get("top_users") if isinstance(data.get("top_users"), list) else []
    if not rows:
        return "Traffic Analytics - Top Users", "Belum ada data traffic user."

    lines = [
        f"Top {cap} user berdasarkan penggunaan traffic:",
        "",
        f"{'NO':<4} {'PROTO':<8} {'USERNAME':<20} {'USED':<12} {'QUOTA':<12} {'USE%':>6} {'EXPIRED':<10}",
        f"{'-'*4:<4} {'-'*8:<8} {'-'*20:<20} {'-'*12:<12} {'-'*12:<12} {'-'*6:>6} {'-'*10:<10}",
    ]
    for idx, row in enumerate(rows[:cap], start=1):
        proto = str((row or {}).get("proto") or "-").upper()
        username = str((row or {}).get("username") or "-")[:20]
        used = _to_int((row or {}).get("used_bytes"), 0)
        quota = _to_int((row or {}).get("quota_bytes"), 0)
        exp = str((row or {}).get("expired_at") or "-")[:10]
        lines.append(
            f"{idx:<4} {proto:<8} {username:<20} {_human_bytes(used):<12} {_human_bytes(quota):<12} "
            f"{_traffic_pct_text(used, quota):>6} {exp:<10}"
        )
    return "Traffic Analytics - Top Users", "\n".join(lines)


def op_traffic_analytics_search(query: str) -> tuple[str, str]:
    needle = str(query or "").strip().lower()
    if not needle:
        return "Traffic Analytics - Search", "Keyword pencarian wajib diisi."

    data = _traffic_analytics_dataset()
    rows = data.get("top_users") if isinstance(data.get("top_users"), list) else []
    hits = [
        row
        for row in rows
        if needle in f"{str((row or {}).get('username') or '').strip()}@{str((row or {}).get('proto') or '').strip()}".lower()
    ]
    if not hits:
        return "Traffic Analytics - Search", f"Tidak ada user cocok untuk keyword: {query}"

    lines = [
        f"Ditemukan {len(hits)} user.",
        "",
        f"{'NO':<4} {'PROTO':<8} {'USERNAME':<20} {'USED':<12} {'QUOTA':<12} {'USE%':>6} {'EXPIRED':<10}",
        f"{'-'*4:<4} {'-'*8:<8} {'-'*20:<20} {'-'*12:<12} {'-'*12:<12} {'-'*6:>6} {'-'*10:<10}",
    ]
    for idx, row in enumerate(hits[:200], start=1):
        proto = str((row or {}).get("proto") or "-").upper()
        username = str((row or {}).get("username") or "-")[:20]
        used = _to_int((row or {}).get("used_bytes"), 0)
        quota = _to_int((row or {}).get("quota_bytes"), 0)
        exp = str((row or {}).get("expired_at") or "-")[:10]
        lines.append(
            f"{idx:<4} {proto:<8} {username:<20} {_human_bytes(used):<12} {_human_bytes(quota):<12} "
            f"{_traffic_pct_text(used, quota):>6} {exp:<10}"
        )
    return "Traffic Analytics - Search", "\n".join(lines)


def op_traffic_analytics_export_json() -> tuple[bool, str, str, dict[str, str] | None]:
    title = "Traffic Analytics - Export JSON"
    payload = _traffic_analytics_dataset()
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    if len(raw) > 1_900_000:
        return (
            False,
            title,
            "Dataset terlalu besar untuk lampiran Telegram (>1.9MB). Gunakan menu CLI untuk export penuh.",
            None,
        )

    filename = f"traffic-analytics-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    download = {
        "filename": filename,
        "content_base64": base64.b64encode(raw).decode("ascii"),
        "content_type": "application/json",
    }
    msg = (
        "Dataset traffic analytics siap diunduh.\n"
        f"- File: {filename}\n"
        f"- Total users: {payload.get('total_users', 0)}"
    )
    return True, title, msg, download


def _speedtest_bin() -> str | None:
    if shutil.which("speedtest"):
        return "speedtest"
    snap_bin = Path("/snap/bin/speedtest")
    if snap_bin.exists():
        return str(snap_bin)
    return None


def _speedtest_parse_json(raw: str) -> tuple[bool, dict[str, Any] | str]:
    text = str(raw or "").strip()
    if not text:
        return False, "Output speedtest kosong."

    def has_speed_metrics(payload: dict[str, Any]) -> bool:
        ping = payload.get("ping")
        download = payload.get("download")
        upload = payload.get("upload")
        return (
            isinstance(ping, dict)
            and isinstance(download, dict)
            and isinstance(upload, dict)
            and "latency" in ping
            and "bandwidth" in download
            and "bandwidth" in upload
        )

    candidates = [line.strip() for line in text.splitlines() if line.strip()]
    fallback_dict: dict[str, Any] | None = None
    for chunk in reversed(candidates):
        if not (chunk.startswith("{") and chunk.endswith("}")):
            continue
        try:
            payload = json.loads(chunk)
        except Exception:
            continue
        if isinstance(payload, dict):
            if has_speed_metrics(payload):
                return True, payload
            if fallback_dict is None:
                fallback_dict = payload

    try:
        payload = json.loads(text)
    except Exception:
        payload = None
    if isinstance(payload, dict):
        if has_speed_metrics(payload):
            return True, payload
        if fallback_dict is None:
            fallback_dict = payload

    if fallback_dict is not None:
        # Fallback terakhir agar error message tetap informatif saat CLI speedtest
        # hanya mengembalikan log/noise tanpa metrik result.
        return True, fallback_dict

    return False, "Output speedtest tidak valid (JSON tidak ditemukan)."


def _speedtest_to_float(value: Any) -> float | None:
    try:
        num = float(value)
    except Exception:
        return None
    if not (num >= 0):
        return None
    return num


def _speedtest_latency_text(payload: dict[str, Any]) -> str:
    ping = payload.get("ping")
    if not isinstance(ping, dict):
        return "-"
    val = _speedtest_to_float(ping.get("latency"))
    if val is None:
        return "-"
    return f"{val:.2f} ms"


def _speedtest_packet_loss_text(payload: dict[str, Any]) -> str:
    val = _speedtest_to_float(payload.get("packetLoss"))
    if val is None:
        return "-"
    return f"{val:.2f} %"


def _speedtest_bandwidth_text(payload: dict[str, Any], key: str) -> str:
    block = payload.get(key)
    if not isinstance(block, dict):
        return "-"
    bandwidth = _speedtest_to_float(block.get("bandwidth"))
    if bandwidth is None:
        return "-"
    mbps = (bandwidth * 8.0) / 1_000_000.0
    return f"{mbps:.2f} Mbps"


def _speedtest_compact_summary(payload: dict[str, Any]) -> str:
    isp = str(payload.get("isp") or "-").strip() or "-"
    latency = _speedtest_latency_text(payload)
    packet_loss = _speedtest_packet_loss_text(payload)
    download = _speedtest_bandwidth_text(payload, "download")
    upload = _speedtest_bandwidth_text(payload, "upload")
    return (
        f"ISP         : {isp}\n"
        f"Latency     : {latency}\n"
        f"Packet Loss : {packet_loss}\n"
        f"Download    : {download}\n"
        f"Upload      : {upload}"
    )


def _speedtest_has_minimum_metrics(payload: dict[str, Any]) -> bool:
    latency = _speedtest_latency_text(payload)
    download = _speedtest_bandwidth_text(payload, "download")
    upload = _speedtest_bandwidth_text(payload, "upload")
    return not (latency == "-" and download == "-" and upload == "-")


def op_speedtest_run() -> tuple[bool, str, str]:
    binary = _speedtest_bin()
    if not binary:
        return False, "Speedtest", "Binary speedtest tidak ditemukan."

    ok, out = run_cmd(
        [binary, "--accept-license", "--accept-gdpr", "--progress=no", "--format=json"],
        timeout=180,
    )
    if ok:
        ok_parse, payload_or_err = _speedtest_parse_json(out)
        if not ok_parse:
            return False, "Speedtest - Run", str(payload_or_err)
        assert isinstance(payload_or_err, dict)
        summary = _speedtest_compact_summary(payload_or_err)
        if not _speedtest_has_minimum_metrics(payload_or_err):
            return False, "Speedtest - Run", f"Hasil speedtest tidak lengkap.\n{summary}"
        return True, "Speedtest - Run", summary
    return False, "Speedtest - Run", f"Gagal speedtest:\n{out}"


def op_speedtest_version() -> tuple[bool, str, str]:
    binary = _speedtest_bin()
    if not binary:
        return False, "Speedtest", "Binary speedtest tidak ditemukan."
    ok, out = run_cmd([binary, "--version"], timeout=20)
    if ok:
        return True, "Speedtest - Version", out
    return False, "Speedtest - Version", f"Gagal membaca versi speedtest:\n{out}"


def op_fail2ban_status() -> tuple[str, str]:
    if not shutil.which("fail2ban-client"):
        return "Security - fail2ban", "fail2ban-client tidak tersedia."
    ok, out = run_cmd(["fail2ban-client", "status"], timeout=20)
    if ok:
        return "Security - fail2ban", out
    return "Security - fail2ban", f"Gagal membaca status fail2ban:\n{out}"


def _read_sysctl(key: str) -> str:
    path = Path("/proc/sys") / key.replace(".", "/")
    if path.exists():
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    ok, out = run_cmd(["sysctl", "-n", key], timeout=8)
    return out.strip() if ok else "-"


def op_sysctl_summary() -> tuple[str, str]:
    keys = [
        "net.core.default_qdisc",
        "net.ipv4.tcp_congestion_control",
        "net.ipv4.ip_forward",
        "net.ipv4.tcp_syncookies",
    ]
    lines = [f"- {key}: {_read_sysctl(key)}" for key in keys]
    return "Security - Kernel/Network Summary", "\n".join(lines)


def op_maintenance_status() -> tuple[str, str]:
    lines = [f"- {svc}: {service_state(svc)}" for svc in ALLOWED_SERVICES]
    return "Maintenance - Service Status", "\n".join(lines)


def op_restart_service(service: str) -> tuple[bool, str, str]:
    if service not in ALLOWED_SERVICES:
        return False, "Maintenance - Restart", f"Service tidak diizinkan: {service}"
    ok, out = run_cmd(["systemctl", "restart", service], timeout=25)
    state = service_state(service)
    if ok:
        return True, "Maintenance - Restart", f"Restart {service} berhasil.\nState: {state}"
    return False, "Maintenance - Restart", f"Restart {service} gagal.\n{out}\nState: {state}"
