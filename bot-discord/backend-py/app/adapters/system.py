import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, List, Tuple

ACCOUNT_ROOT = Path("/opt/account")
QUOTA_ROOT = Path("/opt/quota")
XRAY_CONFDIR = Path("/usr/local/etc/xray/conf.d")
NGINX_CONF = Path("/etc/nginx/conf.d/xray.conf")
CERT_FULLCHAIN = Path("/opt/cert/fullchain.pem")
NETWORK_STATE_FILE = Path("/var/lib/xray-manage/network_state.json")
PROTOCOLS = ("vless", "vmess", "trojan")
QUOTA_UNIT_DECIMAL = {"decimal", "gb", "1000", "gigabyte"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
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
    if ok:
        return (
            True,
            "Xray Config Test",
            "SUCCESS\n"
            "- Konfigurasi Xray valid.\n"
            "- Detail log tidak ditampilkan di Discord.",
        )

    error_hint = ""
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("[exit "):
            continue
        error_hint = line
        break
    if len(error_hint) > 180:
        error_hint = error_hint[:177] + "..."

    msg = (
        "FAILED\n"
        "- Konfigurasi Xray tidak valid.\n"
        "- Detail log tidak ditampilkan di Discord.\n"
        "- Cek manual via SSH: xray run -test -confdir /usr/local/etc/xray/conf.d"
    )
    if error_hint:
        msg += f"\n- Ringkasan error: {error_hint}"
    return False, "Xray Config Test", msg


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

    candidates = [line.strip() for line in text.splitlines() if line.strip()]
    for chunk in reversed(candidates):
        if not (chunk.startswith("{") and chunk.endswith("}")):
            continue
        try:
            payload = json.loads(chunk)
        except Exception:
            continue
        if isinstance(payload, dict):
            return True, payload

    try:
        payload = json.loads(text)
    except Exception:
        payload = None
    if isinstance(payload, dict):
        return True, payload
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
