import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple

ACCOUNT_ROOT = Path("/opt/account")
QUOTA_ROOT = Path("/opt/quota")
XRAY_CONFDIR = Path("/usr/local/etc/xray/conf.d")
NGINX_CONF = Path("/etc/nginx/conf.d/xray.conf")
CERT_FULLCHAIN = Path("/opt/cert/fullchain.pem")
NETWORK_STATE_FILE = Path("/var/lib/xray-manage/network_state.json")
PROTOCOLS = ("vless", "vmess", "trojan")
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
    for path in (Path("/etc/xray/domain"), Path("/usr/local/etc/xray/domain")):
        if path.exists():
            lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
            if lines:
                return lines[0]

    if NGINX_CONF.exists():
        for line in NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*server_name\s+([^;]+);", line)
            if m:
                token = m.group(1).strip().split()[0]
                if token and token != "_":
                    return token
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


def op_xray_test() -> tuple[str, str]:
    cmd = ["xray", "run", "-test", "-confdir", str(XRAY_CONFDIR)]
    ok, out = run_cmd(cmd, timeout=20)
    if ok:
        return "Xray Config Test", f"SUCCESS\nCommand: {' '.join(cmd)}\n\n{out}"
    return "Xray Config Test", f"FAILED\nCommand: {' '.join(cmd)}\n\n{out}"


def op_tls_info() -> tuple[str, str]:
    if not CERT_FULLCHAIN.exists():
        return "TLS Certificate Info", f"File tidak ada: {CERT_FULLCHAIN}"
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
        return "TLS Certificate Info", out
    return "TLS Certificate Info", f"Gagal membaca cert:\n{out}"


def list_accounts() -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    for proto in PROTOCOLS:
        d = ACCOUNT_ROOT / proto
        if not d.exists():
            continue
        for path in sorted(d.glob("*.txt")):
            stem = path.stem
            suffix = f"@{proto}"
            username = stem[: -len(suffix)] if stem.endswith(suffix) else stem
            if username:
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


def _pick_field(data: dict, keys: list[str], default: str = "-") -> str:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return str(data[key])
    return default


def op_quota_summary() -> tuple[str, str]:
    lines: list[str] = []
    count = 0
    for proto in PROTOCOLS:
        d = QUOTA_ROOT / proto
        if not d.exists():
            continue
        for path in sorted(d.glob("*.json")):
            ok, payload = read_json(path)
            username = path.stem.replace(f"@{proto}", "")
            if not ok:
                lines.append(f"- {proto}/{path.name}: invalid json")
                count += 1
                continue

            data = payload if isinstance(payload, dict) else {}
            quota = _pick_field(data, ["quota_gb", "quota_limit_gb", "quotaLimitGb", "quota_limit", "limit_gb"])
            used = _pick_field(data, ["quota_used_gb", "used_gb", "quota_used", "used"])
            exp = _pick_field(data, ["expired_at", "expired", "expiry", "expires"])
            blk = _pick_field(data, ["manual_block", "blocked", "lock_reason"], default="-")
            lines.append(f"- {username} [{proto}] quota={quota} used={used} exp={exp} block={blk}")
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
    for candidate in _quota_candidates(proto, username):
        if not candidate.exists():
            continue
        ok, payload = read_json(candidate)
        if not ok:
            return "Quota & Access Control - Detail", str(payload)
        return "Quota & Access Control - Detail", f"File: {candidate}\n\n" + json.dumps(payload, indent=2, ensure_ascii=False)
    return "Quota & Access Control - Detail", f"File quota tidak ditemukan untuk {username} [{proto}]"


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


def op_speedtest_run() -> tuple[str, str]:
    binary = _speedtest_bin()
    if not binary:
        return "Speedtest", "Binary speedtest tidak ditemukan."
    ok, out = run_cmd([binary, "--accept-license", "--accept-gdpr"], timeout=120)
    if ok:
        return "Speedtest - Run", out
    return "Speedtest - Run", f"Gagal speedtest:\n{out}"


def op_speedtest_version() -> tuple[str, str]:
    binary = _speedtest_bin()
    if not binary:
        return "Speedtest", "Binary speedtest tidak ditemukan."
    ok, out = run_cmd([binary, "--version"], timeout=20)
    if ok:
        return "Speedtest - Version", out
    return "Speedtest - Version", f"Gagal membaca versi speedtest:\n{out}"


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


def op_restart_service(service: str) -> tuple[str, str]:
    if service not in ALLOWED_SERVICES:
        return "Maintenance - Restart", f"Service tidak diizinkan: {service}"
    ok, out = run_cmd(["systemctl", "restart", service], timeout=25)
    state = service_state(service)
    if ok:
        return "Maintenance - Restart", f"Restart {service} berhasil.\nState: {state}"
    return "Maintenance - Restart", f"Restart {service} gagal.\n{out}\nState: {state}"


def op_tail_log(service: str, lines: int = 80) -> tuple[str, str]:
    if service not in ALLOWED_SERVICES:
        return "Maintenance - Tail Log", f"Service tidak diizinkan: {service}"
    ok, out = run_cmd(["journalctl", "-u", service, "-n", str(lines), "--no-pager"], timeout=25)
    if ok:
        return f"Maintenance - Log {service}", out
    return f"Maintenance - Log {service}", f"Gagal ambil log {service}:\n{out}"
