#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# manage.sh - CLI Menu Manajemen (post-setup)
# - Tidak mengubah setup.sh
# - Fokus: operasi harian (status, user, quota, maintenance)
# ============================================================

# -------------------------
# Konstanta (samakan dengan setup.sh)
# -------------------------
XRAY_CONFDIR="/usr/local/etc/xray/conf.d"
XRAY_LOG_CONF="${XRAY_CONFDIR}/00-log.json"
XRAY_API_CONF="${XRAY_CONFDIR}/01-api.json"
XRAY_DNS_CONF="${XRAY_CONFDIR}/02-dns.json"
XRAY_INBOUNDS_CONF="${XRAY_CONFDIR}/10-inbounds.json"
XRAY_OUTBOUNDS_CONF="${XRAY_CONFDIR}/20-outbounds.json"
XRAY_ROUTING_CONF="${XRAY_CONFDIR}/30-routing.json"
XRAY_POLICY_CONF="${XRAY_CONFDIR}/40-policy.json"
XRAY_STATS_CONF="${XRAY_CONFDIR}/50-stats.json"
XRAY_OBSERVATORY_CONF="${XRAY_CONFDIR}/60-observatory.json"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
CERT_DIR="/opt/cert"
CERT_FULLCHAIN="${CERT_DIR}/fullchain.pem"
CERT_PRIVKEY="${CERT_DIR}/privkey.pem"
WIREPROXY_CONF="/etc/wireproxy/config.conf"
WGCF_DIR="/etc/wgcf"

# Domain / ACME / Cloudflare (disamakan dengan setup.sh)
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ}"
PROVIDED_ROOT_DOMAINS=(
"vyxara1.web.id"
"vyxara2.web.id"
"vyxara1.qzz.io"
"vyxara2.qzz.io"
)
ACME_SH_INSTALL_REF="${ACME_SH_INSTALL_REF:-f39d066ced0271d87790dc426556c1e02a88c91b}"
ACME_SH_SCRIPT_URL="https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_SH_INSTALL_REF}/acme.sh"
ACME_SH_TARBALL_URL="https://codeload.github.com/acmesh-official/acme.sh/tar.gz/${ACME_SH_INSTALL_REF}"
ACME_SH_DNS_CF_HOOK_URL="https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_SH_INSTALL_REF}/dnsapi/dns_cf.sh"

# Runtime state untuk Domain Control
DOMAIN=""
ACME_CERT_MODE="standalone"
ACME_ROOT_DOMAIN=""
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
VPS_IPV4=""
CF_PROXIED="false"
declare -ag DOMAIN_CTRL_STOPPED_SERVICES=()

# Account store (read-only source for Menu 2)
ACCOUNT_ROOT="/opt/account"
ACCOUNT_PROTO_DIRS=("vless" "vmess" "trojan")

# Quota metadata store (Menu 2 add/delete)
QUOTA_ROOT="/opt/quota"
QUOTA_PROTO_DIRS=("vless" "vmess" "trojan")

# Speed policy store (fondasi dari setup.sh)
SPEED_POLICY_ROOT="/opt/speed"
SPEED_POLICY_PROTO_DIRS=("vless" "vmess" "trojan")
SPEED_CONFIG_FILE="/etc/xray-speed/config.json"
SPEED_MARK_MIN=1000
SPEED_MARK_MAX=59999
SPEED_OUTBOUND_TAG_PREFIX="speed-mark-"
SPEED_RULE_MARKER_PREFIX="dummy-speed-user-"
SPEED_POLICY_LOCK_FILE="/var/lock/xray-speed-policy.lock"

# Direktori kerja untuk operasi aman (atomic write)
WORK_DIR="/var/lib/xray-manage"

# File lock bersama untuk sinkronisasi write ke routing config dengan daemon Python
# (xray-quota, limit-ip, user-block). Semua pihak harus acquire lock ini sebelum
# memodifikasi 30-routing.json untuk menghindari race condition last-write-wins.
ROUTING_LOCK_FILE="/var/lock/xray-routing.lock"

# Direktori laporan/export
REPORT_DIR="/var/log/xray-manage"
WARP_TIER_STATE_KEY="warp_tier_target"
WARP_PLUS_LICENSE_STATE_KEY="warp_plus_license_key"

# Main Menu header cache (best-effort, supaya render menu tetap cepat)
MAIN_INFO_CACHE_TTL=300
MAIN_INFO_CACHE_TS=0
MAIN_INFO_CACHE_OS="-"
MAIN_INFO_CACHE_RAM="-"
MAIN_INFO_CACHE_IP="-"
MAIN_INFO_CACHE_ISP="-"
MAIN_INFO_CACHE_COUNTRY="-"
MAIN_INFO_CACHE_DOMAIN="-"

# Cache metadata quota (proto:username -> "quota_gb|expired|created|ip_enabled|ip_limit")
declare -Ag QUOTA_FIELDS_CACHE=()

init_runtime_dirs() {
  mkdir -p "${WORK_DIR}"
  chmod 700 "${WORK_DIR}"

  mkdir -p "$(dirname "${ROUTING_LOCK_FILE}")" 2>/dev/null || true

  mkdir -p "${REPORT_DIR}"
  chmod 700 "${REPORT_DIR}"
}

# Pastikan directory account/quota ada
ensure_account_quota_dirs() {
  local proto
  mkdir -p "${ACCOUNT_ROOT}"
  mkdir -p "${QUOTA_ROOT}"
  chmod 700 "${ACCOUNT_ROOT}" "${QUOTA_ROOT}" || true

  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    mkdir -p "${ACCOUNT_ROOT}/${proto}"
    chmod 700 "${ACCOUNT_ROOT}/${proto}" || true
  done

  for proto in "${QUOTA_PROTO_DIRS[@]}"; do
    mkdir -p "${QUOTA_ROOT}/${proto}"
    chmod 700 "${QUOTA_ROOT}/${proto}" || true
  done
}

ensure_speed_policy_dirs() {
  local proto
  mkdir -p "${SPEED_POLICY_ROOT}"
  chmod 700 "${SPEED_POLICY_ROOT}" || true
  for proto in "${SPEED_POLICY_PROTO_DIRS[@]}"; do
    mkdir -p "${SPEED_POLICY_ROOT}/${proto}"
    chmod 700 "${SPEED_POLICY_ROOT}/${proto}" || true
  done
}

speed_policy_lock_prepare() {
  mkdir -p "$(dirname "${SPEED_POLICY_LOCK_FILE}")" 2>/dev/null || true
}

speed_policy_has_entries() {
  local proto
  for proto in "${SPEED_POLICY_PROTO_DIRS[@]}"; do
    if compgen -G "${SPEED_POLICY_ROOT}/${proto}/*.json" >/dev/null; then
      return 0
    fi
  done
  return 1
}

speed_policy_artifacts_present_in_xray() {
  # Cek apakah masih ada artefak speed policy di config Xray walau policy file kosong.
  # Ini penting untuk skenario "hapus policy terakhir tapi sync gagal".
  need_python3
  [[ -f "${XRAY_OUTBOUNDS_CONF}" && -f "${XRAY_ROUTING_CONF}" ]] || return 1

  python3 - <<'PY' \
    "${XRAY_OUTBOUNDS_CONF}" \
    "${XRAY_ROUTING_CONF}" \
    "${SPEED_OUTBOUND_TAG_PREFIX}" \
    "${SPEED_RULE_MARKER_PREFIX}"
import json
import sys

out_src, rt_src, out_prefix, marker_prefix = sys.argv[1:5]
bal_prefix = f"{out_prefix}bal-"

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

try:
  out_cfg = load_json(out_src)
  rt_cfg = load_json(rt_src)
except Exception:
  # Konservatif: jika tidak bisa diparse, paksa jalur resync agar kondisi stale tidak terlewat.
  raise SystemExit(0)

for o in (out_cfg.get("outbounds") or []):
  if not isinstance(o, dict):
    continue
  tag = o.get("tag")
  if isinstance(tag, str) and tag.startswith(out_prefix):
    raise SystemExit(0)

routing = rt_cfg.get("routing") or {}

for b in (routing.get("balancers") or []):
  if not isinstance(b, dict):
    continue
  tag = b.get("tag")
  if isinstance(tag, str) and tag.startswith(bal_prefix):
    raise SystemExit(0)

for r in (routing.get("rules") or []):
  if not isinstance(r, dict):
    continue
  if r.get("type") != "field":
    continue
  ot = r.get("outboundTag")
  bt = r.get("balancerTag")
  if isinstance(ot, str) and ot.startswith(out_prefix):
    raise SystemExit(0)
  if isinstance(bt, str) and bt.startswith(bal_prefix):
    raise SystemExit(0)
  users = r.get("user")
  if isinstance(users, list):
    for u in users:
      if isinstance(u, str) and u.startswith(marker_prefix):
        raise SystemExit(0)

raise SystemExit(1)
PY
}

speed_policy_resync_after_egress_change() {
  # Default egress/balancer mempengaruhi jalur dasar speed-mark outbounds.
  # Wajib sinkron ulang supaya speed user tidak memakai topology lama.
  # Walau policy kosong, tetap perlu sync bila artefak speed lama masih tertinggal.
  local need_sync="false"
  if speed_policy_has_entries; then
    need_sync="true"
  elif speed_policy_artifacts_present_in_xray; then
    need_sync="true"
  fi

  if [[ "${need_sync}" != "true" ]]; then
    return 0
  fi

  if ! speed_policy_sync_xray; then
    warn "Perubahan egress tersimpan, tetapi sinkronisasi speed policy gagal."
    return 1
  fi

  speed_policy_apply_now >/dev/null 2>&1 || true
  return 0
}

quota_migrate_dates_to_dateonly() {
  # Normalisasi created_at/expired_at menjadi YYYY-MM-DD untuk semua metadata quota.
  # Idempotent: nilai yang sudah date-only tidak diubah.
  need_python3
  python3 - <<'PY' "${QUOTA_ROOT}" "${QUOTA_PROTO_DIRS[@]}"
import json
import os
import re
import sys
import tempfile
from datetime import datetime

quota_root = sys.argv[1]
protos = tuple(sys.argv[2:])

DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

def normalize_date(value):
  if value is None:
    return None
  s = str(value).strip()
  if not s:
    return None
  if DATE_ONLY_RE.match(s):
    return s

  candidates = [s]
  if s.endswith("Z"):
    candidates.append(s[:-1] + "+00:00")
  if len(s) >= 10 and DATE_ONLY_RE.match(s[:10]):
    candidates.append(s[:10])

  for c in candidates:
    try:
      d = datetime.fromisoformat(c).date()
      return d.strftime("%Y-%m-%d")
    except Exception:
      pass

  for fmt in ("%Y-%m-%d %H:%M:%S",):
    try:
      d = datetime.strptime(s, fmt).date()
      return d.strftime("%Y-%m-%d")
    except Exception:
      pass

  return None

for proto in protos:
  d = os.path.join(quota_root, proto)
  if not os.path.isdir(d):
    continue
  for name in os.listdir(d):
    if not name.endswith(".json"):
      continue
    p = os.path.join(d, name)
    try:
      with open(p, "r", encoding="utf-8") as f:
        meta = json.load(f)
      if not isinstance(meta, dict):
        continue
    except Exception:
      print(f"[manage][WARN] Skip migrasi (JSON invalid): {p}", file=sys.stderr)
      continue

    changed = False
    for key in ("created_at", "expired_at"):
      if key not in meta:
        continue
      nd = normalize_date(meta.get(key))
      if nd is None:
        print(f"[manage][WARN] Skip field {key} (format tidak dikenali) di: {p}", file=sys.stderr)
        continue
      if meta.get(key) != nd:
        meta[key] = nd
        changed = True

    if changed:
      dirn = os.path.dirname(p) or "."
      fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
      try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
          json.dump(meta, wf, ensure_ascii=False, indent=2)
          wf.write("\n")
          wf.flush()
          os.fsync(wf.fileno())
        os.replace(tmp, p)
        try:
          os.chmod(p, 0o600)
        except Exception:
          pass
      finally:
        try:
          if os.path.exists(tmp):
            os.remove(tmp)
        except Exception:
          pass
PY
}

# -------------------------
# Util
# -------------------------
log() {
  echo "[manage] $*"
}

warn() {
  echo "[manage][WARN] $*" >&2
}

die() {
  echo "[manage][ERROR] $*" >&2
  exit 1
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Jalankan sebagai root: sudo ./manage.sh"
  fi
}

ensure_path_writable() {
  # args: file_path (existing)
  local path="$1"
  local dir tmp

  [[ -e "${path}" ]] || die "Path tidak ditemukan: ${path}"
  dir="$(dirname "${path}")"

  # Best-effort check: directory writable (detect read-only fs, weird perms)
  if ! touch "${dir}/.writetest.$$" 2>/dev/null; then
    warn "Directory tidak bisa ditulis: ${dir}"
    die "Tidak dapat menulis ke ${dir} (kemungkinan filesystem read-only / permission khusus)."
  fi
  rm -f "${dir}/.writetest.$$" 2>/dev/null || true

  # Immutable attribute check (best-effort)
  if have_cmd lsattr; then
    if lsattr -d "${path}" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      die "File immutable (chattr +i): ${path}. Jalankan: chattr -i '${path}'"
    fi
  fi

  # Temp file test (same dir) for atomic replace
  tmp="${dir}/.tmp.$$.$(basename "${path}")"
  if ! cp -a "${path}" "${tmp}" 2>/dev/null; then
    die "Gagal membuat temp file di ${dir} untuk atomic replace. Cek permission/immutable."
  fi
  rm -f "${tmp}" 2>/dev/null || true
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

now_ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

bytes_from_gb() {
  # GB (GiB) -> bytes
  local gb="${1:-0}"
  python3 - <<'PY' "${gb}"
import sys
try:
  gb=float(sys.argv[1])
except Exception:
  gb=0.0
b=int(gb*(1024**3))
if b < 0:
  b=0
print(b)
PY
}

quota_disp() {
  # Jika sudah ada unit (mis. "2.50 MB"), jangan tambahkan lagi.
  # Jika hanya angka (mis. "2.50"), tambahkan unit default.
  local v="${1:-}"
  local unit="${2:-GB}"
  if [[ -z "${v}" ]]; then
    echo "0 ${unit}"
    return 0
  fi
  if [[ "${v}" =~ [A-Za-z] ]]; then
    echo "${v}"
  else
    echo "${v} ${unit}"
  fi
}


normalize_gb_input() {
  # Accept "5" or "5GB" (case-insensitive). Returns numeric string or empty on invalid.
  local v="${1:-}"
  v="$(echo "${v}" | tr -d '[:space:]')"
  v="$(echo "${v}" | tr '[:lower:]' '[:upper:]')"
  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)GB$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo ""
}

normalize_speed_mbit_input() {
  # Accept "10", "10mbit", "10mbps", "10m" (case-insensitive), return numeric string.
  local v="${1:-}"
  v="$(echo "${v}" | tr -d '[:space:]')"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"

  if [[ "${v}" =~ ^([0-9]+([.][0-9]+)?)(mbit|mbps|m)?$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo ""
}

speed_mbit_is_positive() {
  local n="${1:-}"
  [[ "${n}" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  awk "BEGIN { exit !(${n} > 0) }"
}

validate_username() {
  # Aman untuk dipakai sebagai nama file: mencegah path traversal
  # Aturan:
  # - tidak boleh kosong
  # - tidak boleh mengandung '/', '\\', spasi, '@', atau '..'
  # - hanya karakter: A-Z a-z 0-9 . _ -
  local u="$1"

  if [[ -z "${u}" ]]; then
    return 1
  fi
  if [[ "${u}" == *"/"* || "${u}" == *"\\"* || "${u}" == *" "* || "${u}" == *"@"* || "${u}" == *".."* ]]; then
    return 1
  fi
  if [[ ! "${u}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]]; then
    return 1
  fi
  return 0
}

account_username_find_protos() {
  # args: username
  local username="$1"
  local protos=()
  local p
  for p in vless vmess trojan; do
    if [[ -f "${ACCOUNT_ROOT}/${p}/${username}@${p}.txt" ]]; then
      protos+=("${p}")
    fi
  done
  echo "${protos[*]:-}"
}

quota_username_find_protos() {
  # args: username
  local username="$1"
  local protos=()
  local p
  for p in vless vmess trojan; do
    if [[ -f "${QUOTA_ROOT}/${p}/${username}@${p}.json" ]]; then
      protos+=("${p}")
    fi
  done
  echo "${protos[*]:-}"
}

xray_username_find_protos() {
  # args: username
  local username="$1"
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${username}" 2>/dev/null || true
import json, sys
src, username = sys.argv[1:3]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

protos=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  proto=ib.get('protocol')
  st=(ib.get('settings') or {})
  clients=st.get('clients') or []
  if not isinstance(clients, list):
    continue
  for c in clients:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if not isinstance(em, str) or '@' not in em:
      continue
    u,p = em.split('@', 1)
    if u == username and isinstance(p, str) and p:
      protos.add(p.strip())
print(" ".join(sorted([x for x in protos if x])))
PY
}

is_yes() {
  # accept: y/yes/1/on/true
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "y" || "${v}" == "yes" || "${v}" == "1" || "${v}" == "on" || "${v}" == "true" ]]
}

is_back_choice() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "0" || "${v}" == "kembali" || "${v}" == "k" || "${v}" == "back" || "${v}" == "b" ]]
}

detect_domain() {
  # Try nginx conf server_name first, then hostname -f
  local dom=""
  if [[ -f "${NGINX_CONF}" ]]; then
    dom="$(grep -E '^[[:space:]]*server_name[[:space:]]+' "${NGINX_CONF}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/;.*$//')"
    dom="$(echo "${dom}" | awk '{print $1}' | tr -d ';')"
  fi
  if [[ -z "${dom}" ]]; then
    dom="$(hostname -f 2>/dev/null || hostname)"
  fi
  echo "${dom}"
}

detect_public_ip() {
  # Prefer route src (no internet needed), fallback hostname -I
  local ip=""
  if have_cmd ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  echo "${ip:-0.0.0.0}"
}

detect_public_ip_ipapi() {
  # Ambil public IP dari api.ipify.org (best-effort), fallback ke detect_public_ip
  local ip=""
  if have_cmd curl; then
    ip="$(curl -fsSL --max-time 5 "https://api.ipify.org" 2>/dev/null || true)"
  elif have_cmd wget; then
    ip="$(wget -qO- --timeout=5 "https://api.ipify.org" 2>/dev/null || true)"
  fi

  if [[ -z "${ip}" || ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    warn "Gagal fetch IP dari api.ipify.org, fallback ke deteksi lokal"
    ip="$(detect_public_ip)"
  fi
  echo "${ip}"
}

main_info_os_get() {
  local pretty=""
  if [[ -r /etc/os-release ]]; then
    pretty="$(awk -F= '/^PRETTY_NAME=/{print $2; exit}' /etc/os-release 2>/dev/null | sed -E 's/^"//; s/"$//')"
  fi
  [[ -n "${pretty}" ]] || pretty="$(uname -sr 2>/dev/null || true)"
  [[ -n "${pretty}" ]] || pretty="-"
  echo "${pretty}"
}

main_info_ram_get() {
  local kb
  kb="$(awk '/^MemTotal:[[:space:]]+[0-9]+/{print $2; exit}' /proc/meminfo 2>/dev/null || true)"
  if [[ -z "${kb}" || ! "${kb}" =~ ^[0-9]+$ ]]; then
    echo "-"
    return 0
  fi
  awk -v kb="${kb}" 'BEGIN{
    gib = kb / 1024 / 1024;
    if (gib >= 1) {
      printf "%.2f GiB", gib;
    } else {
      printf "%.0f MiB", kb / 1024;
    }
  }'
}

main_info_uptime_get() {
  local u
  if have_cmd uptime; then
    u="$(uptime -p 2>/dev/null | sed -E 's/^up[[:space:]]+//')"
    [[ -n "${u}" ]] && { echo "${u}"; return 0; }
  fi
  u="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || true)"
  if [[ -n "${u}" && "${u}" =~ ^[0-9]+$ ]]; then
    local d h m r
    d=$((u / 86400))
    r=$((u % 86400))
    h=$((r / 3600))
    r=$((r % 3600))
    m=$((r / 60))
    if (( d > 0 )); then
      echo "${d}d ${h}h ${m}m"
    elif (( h > 0 )); then
      echo "${h}h ${m}m"
    else
      echo "${m}m"
    fi
    return 0
  fi
  echo "-"
}

main_info_ip_quiet_get() {
  local ip=""
  if have_cmd curl; then
    ip="$(curl -4fsSL --max-time 4 "https://api.ipify.org" 2>/dev/null || true)"
  elif have_cmd wget; then
    ip="$(wget -qO- --timeout=4 "https://api.ipify.org" 2>/dev/null || true)"
  fi
  if [[ -z "${ip}" || ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="$(detect_public_ip)"
  fi
  if [[ "${ip}" == "0.0.0.0" ]]; then
    ip="-"
  fi
  [[ -n "${ip}" ]] || ip="-"
  echo "${ip}"
}

main_info_geo_lookup() {
  # args: ip -> prints: isp|country
  local ip="$1"
  local isp="-" country="-"
  local json

  case "${ip}" in
    ""|"-"|"0.0.0.0"|"127."*|"10."*|"192.168."*|"172.16."*|"172.17."*|"172.18."*|"172.19."*|"172.2"?.*|"172.30."*|"172.31."*)
      echo "-|-"
      return 0
      ;;
  esac

  if [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && have_cmd curl && have_cmd jq; then
    json="$(curl -fsSL --max-time 6 "https://ipwho.is/${ip}" 2>/dev/null || true)"
    if [[ -n "${json}" ]]; then
      country="$(echo "${json}" | jq -r 'if .success == true then (.country // "-") else "-" end' 2>/dev/null || true)"
      isp="$(echo "${json}" | jq -r 'if .success == true then (.connection.isp // .isp // "-") else "-" end' 2>/dev/null || true)"
    fi
  fi

  [[ -n "${isp}" && "${isp}" != "null" ]] || isp="-"
  [[ -n "${country}" && "${country}" != "null" ]] || country="-"
  echo "${isp}|${country}"
}

main_info_tls_expired_get() {
  local days
  days="$(cert_expiry_days_left)"
  if [[ -z "${days}" ]]; then
    echo "-"
    return 0
  fi
  if (( days < 0 )); then
    echo "Expired"
  else
    echo "${days} days"
  fi
}

main_info_warp_status_get() {
  local target
  if ! svc_exists wireproxy; then
    echo "Not Installed"
    return 0
  fi
  if ! svc_is_active wireproxy; then
    echo "Inactive"
    return 0
  fi
  target="$(warp_tier_state_target_get)"
  case "${target}" in
    plus) echo "Active (PLUS)" ;;
    free) echo "Active (FREE)" ;;
    *) echo "Active" ;;
  esac
}

account_count_by_proto() {
  # args: proto -> prints number of unique usernames from /opt/account/<proto>/*.txt
  local proto="$1"
  local dir="${ACCOUNT_ROOT}/${proto}"
  local f base username
  declare -A seen=()

  [[ -d "${dir}" ]] || { echo "0"; return 0; }
  while IFS= read -r -d '' f; do
    base="$(basename "${f}")"
    base="${base%.txt}"
    username="${base%%@*}"
    [[ -n "${username}" ]] || continue
    seen["${username}"]=1
  done < <(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null)

  echo "${#seen[@]}"
}

main_info_cache_refresh() {
  local now elapsed ip geo isp country
  now="$(date +%s 2>/dev/null || echo 0)"
  elapsed=$(( now - MAIN_INFO_CACHE_TS ))
  if (( MAIN_INFO_CACHE_TS > 0 && elapsed >= 0 && elapsed < MAIN_INFO_CACHE_TTL )); then
    return 0
  fi

  MAIN_INFO_CACHE_OS="$(main_info_os_get)"
  MAIN_INFO_CACHE_RAM="$(main_info_ram_get)"
  MAIN_INFO_CACHE_DOMAIN="$(detect_domain)"
  MAIN_INFO_CACHE_IP="$(main_info_ip_quiet_get)"

  ip="${MAIN_INFO_CACHE_IP}"
  geo="$(main_info_geo_lookup "${ip}")"
  isp="${geo%%|*}"
  country="${geo##*|}"
  [[ -n "${isp}" ]] || isp="-"
  [[ -n "${country}" ]] || country="-"
  MAIN_INFO_CACHE_ISP="${isp}"
  MAIN_INFO_CACHE_COUNTRY="${country}"
  MAIN_INFO_CACHE_TS="${now}"
}

main_menu_info_header_print() {
  local os ram up ip isp country domain tls warp
  local vless_count vmess_count trojan_count

  main_info_cache_refresh

  os="${MAIN_INFO_CACHE_OS}"
  ram="${MAIN_INFO_CACHE_RAM}"
  up="$(main_info_uptime_get)"
  ip="${MAIN_INFO_CACHE_IP}"
  isp="${MAIN_INFO_CACHE_ISP}"
  country="${MAIN_INFO_CACHE_COUNTRY}"
  domain="${MAIN_INFO_CACHE_DOMAIN}"
  tls="$(main_info_tls_expired_get)"
  warp="$(main_info_warp_status_get)"
  vless_count="$(account_count_by_proto "vless")"
  vmess_count="$(account_count_by_proto "vmess")"
  trojan_count="$(account_count_by_proto "trojan")"

  printf "%-11s : %s\n" "SYSTEM OS" "${os}"
  printf "%-11s : %s\n" "RAM" "${ram}"
  printf "%-11s : %s\n" "UPTIME" "${up}"
  printf "%-11s : %s\n" "IP VPS" "${ip}"
  printf "%-11s : %s\n" "ISP" "${isp}"
  printf "%-11s : %s\n" "COUNTRY" "${country}"
  printf "%-11s : %s\n" "DOMAIN" "${domain}"
  printf "%-11s : %s\n" "TLS EXPIRED" "${tls}"
  printf "%-11s : %s\n" "WARP STATUS" "${warp}"
  hr
  echo "ACCOUNTS: VLESS=${vless_count} | VMESS=${vmess_count} | TROJAN=${trojan_count}"
  hr
}

download_file_or_die() {
  local url="$1"
  local out="$2"
  curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$out" \
    || die "Gagal download: $url"
}

rand_str() {
  local n="${1:-16}"
  ( set +o pipefail; tr -dc 'a-z0-9' </dev/urandom | head -c "$n" )
}

rand_email() {
  local user part
  user="$(rand_str 10)"
  part="$(rand_str 6)"
  local domains=("gmail.com" "outlook.com" "proton.me" "icloud.com" "yahoo.com")
  local idx=$(( RANDOM % ${#domains[@]} ))
  echo "${user}.${part}@${domains[$idx]}"
}

confirm_yn() {
  local prompt="$1"
  local ans
  while true; do
    read -r -p "${prompt} (y/n): " ans
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Input tidak valid. Jawab y/n." ;;
    esac
  done
}

get_public_ipv4() {
  local ip=""
  ip="$(curl -4fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -4fsSL https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]' || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ -n "$ip" ]] || die "Gagal mendapatkan public IPv4 VPS."
  echo "$ip"
}

cf_api() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"

  [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || die "CLOUDFLARE_API_TOKEN belum di-set."

  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local resp code body trimmed

  if [[ -n "$data" ]]; then
    resp="$(curl -sS -L -X "$method" "$url" \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" \
      --connect-timeout 10 \
      --max-time 30 \
      --data "$data" \
      -w $'\n%{http_code}' || true)"
  else
    resp="$(curl -sS -L -X "$method" "$url" \
      -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      -H "Content-Type: application/json" \
      --connect-timeout 10 \
      --max-time 30 \
      -w $'\n%{http_code}' || true)"
  fi

  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"

  if [[ -z "${body:-}" ]]; then
    echo "[Cloudflare] Empty response (HTTP ${code:-?}) for ${endpoint}" >&2
    return 1
  fi

  trimmed="${body#"${body%%[![:space:]]*}"}"
  if [[ ! "$trimmed" =~ ^[\{\[] ]]; then
    echo "[Cloudflare] Non-JSON response (HTTP ${code:-?}) for ${endpoint}:" >&2
    echo "$body" >&2
    return 1
  fi

  if [[ ! "${code:-}" =~ ^2 ]]; then
    echo "[Cloudflare] HTTP ${code:-?} for ${endpoint}:" >&2
    echo "$body" >&2
    return 1
  fi

  printf '%s' "$body"
}

cf_get_zone_id_by_name() {
  local zone_name="$1"
  local json zid err

  json="$(cf_api GET "/zones?name=${zone_name}&per_page=1" || true)"
  if [[ -z "${json:-}" ]]; then
    return 1
  fi

  if ! echo "$json" | jq -e '.success == true' >/dev/null 2>&1; then
    err="$(echo "$json" | jq -r '.errors[0].message // empty' 2>/dev/null || true)"
    [[ -n "$err" ]] && echo "[Cloudflare] $err" >&2
    return 1
  fi

  zid="$(echo "$json" | jq -r '.result[0].id // empty' 2>/dev/null || true)"
  [[ -n "$zid" ]] || return 1
  echo "$zid"
}

cf_get_account_id_by_zone() {
  local zone_id="$1"
  local json aid

  json="$(cf_api GET "/zones/${zone_id}" || true)"
  if [[ -z "${json:-}" ]]; then
    return 1
  fi

  aid="$(echo "$json" | jq -r '.result.account.id // empty' 2>/dev/null || true)"
  [[ -n "$aid" ]] || return 1
  echo "$aid"
}

cf_list_a_records_by_ip() {
  local zone_id="$1"
  local ip="$2"
  local json

  json="$(cf_api GET "/zones/${zone_id}/dns_records?type=A&content=${ip}&per_page=100" || true)"
  if [[ -z "${json:-}" ]]; then
    return 0
  fi

  if ! echo "$json" | jq -e '.success == true' >/dev/null 2>&1; then
    return 1
  fi

  echo "$json" | jq -r '.result[] | "\(.id)\t\(.name)"'
}

cf_delete_record() {
  local zone_id="$1"
  local record_id="$2"
  cf_api DELETE "/zones/${zone_id}/dns_records/${record_id}" >/dev/null \
    || die "Gagal delete DNS record Cloudflare: $record_id"
}

cf_create_a_record() {
  local zone_id="$1"
  local name="$2"
  local ip="$3"
  local proxied="${4:-false}"

  if [[ "$proxied" != "true" && "$proxied" != "false" ]]; then
    proxied="false"
  fi

  local payload
  payload="$(cat <<EOF
{"type":"A","name":"$name","content":"$ip","ttl":1,"proxied":$proxied}
EOF
  )"
  cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null \
    || die "Gagal membuat A record Cloudflare untuk $name"
}

gen_subdomain_random() {
  rand_str 5
}

validate_subdomain() {
  local s="$1"
  [[ -n "$s" ]] || return 1
  [[ "$s" == "${s,,}" ]] || return 1
  [[ "$s" =~ ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$ ]] || return 1
  [[ "$s" != *" "* ]] || return 1
  return 0
}

cf_prepare_subdomain_a_record() {
  local zone_id="$1"
  local fqdn="$2"
  local ip="$3"
  local proxied="${4:-false}"

  log "Validasi DNS A record Cloudflare untuk: $fqdn"

  local json rec_ips any_same any_diff
  json="$(cf_api GET "/zones/${zone_id}/dns_records?type=A&name=${fqdn}&per_page=100" || true)"
  if [[ -n "${json:-}" ]] && echo "$json" | jq -e '.success == true' >/dev/null 2>&1; then
    mapfile -t rec_ips < <(echo "$json" | jq -r '.result[].content' 2>/dev/null || true)
    if [[ ${#rec_ips[@]} -gt 0 ]]; then
      any_same="0"
      any_diff="0"
      local cip
      for cip in "${rec_ips[@]}"; do
        if [[ "$cip" == "$ip" ]]; then
          any_same="1"
        else
          any_diff="1"
        fi
      done

      if [[ "$any_same" == "1" ]]; then
        warn "A record sudah ada: $fqdn -> $ip (sama dengan IP VPS)"
        if confirm_yn "Lanjut menggunakan domain ini?"; then
          log "Lanjut."
          return 0
        fi
        die "Dibatalkan oleh user."
      fi

      if [[ "$any_diff" == "1" ]]; then
        die "Subdomain $fqdn sudah ada di Cloudflare tetapi IP berbeda (${rec_ips[*]}). Gunakan nama subdomain lain."
      fi
    fi
  fi

  local same_ip=()
  mapfile -t same_ip < <(cf_list_a_records_by_ip "$zone_id" "$ip" || true)
  if [[ ${#same_ip[@]} -gt 0 ]]; then
    local line
    for line in "${same_ip[@]}"; do
      local rid="${line%%$'\t'*}"
      local rname="${line#*$'\t'}"
      if [[ "$rname" != "$fqdn" ]]; then
        warn "Ditemukan A record lain dengan IP sama ($ip): $rname -> $ip"
        warn "Menghapus A record: $rname"
        cf_delete_record "$zone_id" "$rid"
      fi
    done
  fi

  log "Membuat DNS A record: $fqdn -> $ip"
  cf_create_a_record "$zone_id" "$fqdn" "$ip" "$proxied"
}

domain_menu_v2() {
  echo "============================================"
  echo "   INPUT DOMAIN (TLS)"
  echo "============================================"
  echo "1. input domain sendiri"
  echo "2. gunakan domain yang disediakan"
  echo

  local choice=""
  while true; do
    read -r -p "Pilih opsi (1-2): " choice
    case "$choice" in
      1|2) break ;;
      *) echo "Pilihan tidak valid." ;;
    esac
  done

  if [[ "$choice" == "1" ]]; then
    local re='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    while true; do
      read -r -p "Masukkan domain: " DOMAIN
      DOMAIN="${DOMAIN,,}"

      [[ -n "${DOMAIN:-}" ]] || {
        echo "Domain tidak boleh kosong."
        continue
      }

      if [[ "$DOMAIN" =~ $re ]]; then
        log "Domain valid: $DOMAIN"
        ACME_CERT_MODE="standalone"
        ACME_ROOT_DOMAIN=""
        CF_ZONE_ID=""
        break
      else
        echo "Domain tidak valid. Coba lagi."
      fi
    done
    return 0
  fi

  VPS_IPV4="$(get_public_ipv4)"
  log "Public IPv4 VPS: $VPS_IPV4"

  [[ ${#PROVIDED_ROOT_DOMAINS[@]} -gt 0 ]] || die "Daftar domain induk (PROVIDED_ROOT_DOMAINS) kosong."

  echo
  echo "Pilih domain induk"
  local i=1
  local root=""
  for root in "${PROVIDED_ROOT_DOMAINS[@]}"; do
    echo "  $i. $root"
    i=$((i + 1))
  done

  local pick=""
  while true; do
    read -r -p "Pilih nomor domain induk (1-${#PROVIDED_ROOT_DOMAINS[@]}): " pick
    [[ "$pick" =~ ^[0-9]+$ ]] || { echo "Input harus angka."; continue; }
    [[ "$pick" -ge 1 && "$pick" -le ${#PROVIDED_ROOT_DOMAINS[@]} ]] || { echo "Di luar range."; continue; }
    break
  done

  ACME_ROOT_DOMAIN="${PROVIDED_ROOT_DOMAINS[$((pick - 1))]}"
  log "Domain induk terpilih: $ACME_ROOT_DOMAIN"

  CF_ZONE_ID="$(cf_get_zone_id_by_name "$ACME_ROOT_DOMAIN" || true)"
  [[ -n "${CF_ZONE_ID:-}" ]] || die "Zone Cloudflare untuk $ACME_ROOT_DOMAIN tidak ditemukan / token tidak punya akses (butuh Zone:Read + DNS:Edit)."
  CF_ACCOUNT_ID="$(cf_get_account_id_by_zone "$CF_ZONE_ID" || true)"
  [[ -n "${CF_ACCOUNT_ID:-}" ]] || warn "Tidak bisa ambil CF_ACCOUNT_ID dari zone (acme.sh dns_cf mungkin tetap bisa jalan tanpa ini)."

  echo
  echo "Pilih metode pembuatan subdomain"
  echo "1. generate secara acak"
  echo "2. input sendiri"

  local mth=""
  while true; do
    read -r -p "Pilih opsi (1-2): " mth
    case "$mth" in
      1|2) break ;;
      *) echo "Pilihan tidak valid." ;;
    esac
  done

  local sub=""
  if [[ "$mth" == "1" ]]; then
    sub="$(gen_subdomain_random)"
    log "Subdomain generated: $sub"
  else
    while true; do
      read -r -p "Masukkan nama subdomain: " sub
      sub="${sub,,}"
      if validate_subdomain "$sub"; then
        log "Subdomain valid: $sub"
        break
      fi
      echo "Subdomain tidak valid. Hanya huruf kecil, angka, titik, dan strip (-). Tanpa spasi/kapital/karakter aneh."
    done
  fi

  echo
  if confirm_yn "Aktifkan Cloudflare proxy (orange cloud) untuk DNS A record?"; then
    CF_PROXIED="true"
    log "Cloudflare proxy: ON (proxied=true)"
  else
    CF_PROXIED="false"
    log "Cloudflare proxy: OFF (proxied=false)"
  fi

  DOMAIN="${sub}.${ACME_ROOT_DOMAIN}"
  log "Domain final: $DOMAIN"

  cf_prepare_subdomain_a_record "$CF_ZONE_ID" "$DOMAIN" "$VPS_IPV4" "$CF_PROXIED"

  ACME_CERT_MODE="dns_cf_wildcard"
  log "Mode sertifikat: wildcard dns_cf untuk ${DOMAIN} (meliputi *.$DOMAIN)"
}

stop_conflicting_services() {
  DOMAIN_CTRL_STOPPED_SERVICES=()

  local svc
  for svc in nginx apache2 caddy lighttpd; do
    if svc_exists "${svc}" && svc_is_active "${svc}"; then
      DOMAIN_CTRL_STOPPED_SERVICES+=("${svc}")
    fi
    if svc_exists "${svc}"; then
      systemctl stop "${svc}" >/dev/null 2>&1 || true
    fi
  done
}

domain_control_restore_stopped_services() {
  if (( ${#DOMAIN_CTRL_STOPPED_SERVICES[@]} == 0 )); then
    return 0
  fi

  local svc
  for svc in "${DOMAIN_CTRL_STOPPED_SERVICES[@]}"; do
    if svc_exists "${svc}"; then
      systemctl start "${svc}" >/dev/null 2>&1 || warn "Gagal restore service: ${svc}"
    fi
  done
}

domain_control_clear_stopped_services() {
  DOMAIN_CTRL_STOPPED_SERVICES=()
}

domain_control_restore_on_exit() {
  # Safety net: jika proses domain control gagal di tengah (die/exit),
  # service yang sebelumnya aktif dipulihkan otomatis.
  if (( ${#DOMAIN_CTRL_STOPPED_SERVICES[@]} > 0 )); then
    warn "Domain Control berhenti sebelum selesai. Mencoba restore service yang tadi dihentikan..."
    domain_control_restore_stopped_services
    domain_control_clear_stopped_services
  fi
}

install_acme_and_issue_cert() {
  local email
  email="$(rand_email)"
  log "Email acme.sh (acak): $email"

  stop_conflicting_services

  local acme_tmpdir acme_src_dir acme_tgz acme_install_log
  acme_tmpdir="$(mktemp -d)"
  acme_tgz="${acme_tmpdir}/acme.tar.gz"
  acme_install_log="${acme_tmpdir}/acme-install.log"
  acme_src_dir=""

  if curl -fsSL --connect-timeout 15 --max-time 120 "${ACME_SH_TARBALL_URL}" -o "${acme_tgz}" 2>/dev/null; then
    if tar -xzf "${acme_tgz}" -C "${acme_tmpdir}" >/dev/null 2>&1; then
      acme_src_dir="$(find "${acme_tmpdir}" -maxdepth 1 -type d -name 'acme.sh-*' -print -quit)"
    fi
  fi

  if [[ -z "${acme_src_dir:-}" || ! -f "${acme_src_dir}/acme.sh" ]]; then
    warn "Source bundle acme.sh tidak tersedia, fallback ke single-file installer."
    acme_src_dir="${acme_tmpdir}/acme-single"
    mkdir -p "${acme_src_dir}"
    download_file_or_die "${ACME_SH_SCRIPT_URL}" "${acme_src_dir}/acme.sh"
  fi

  chmod 700 "${acme_src_dir}/acme.sh"
  if ! (cd "${acme_src_dir}" && bash ./acme.sh --install --home /root/.acme.sh --accountemail "$email") >"${acme_install_log}" 2>&1; then
    warn "Install acme.sh gagal. Ringkasan log:"
    sed -n '1,120p' "${acme_install_log}" >&2 || true
    rm -rf "${acme_tmpdir}" >/dev/null 2>&1 || true
    die "Gagal install acme.sh dari ref ${ACME_SH_INSTALL_REF}."
  fi
  rm -rf "${acme_tmpdir}" >/dev/null 2>&1 || true

  export PATH="/root/.acme.sh:${PATH}"
  [[ -x /root/.acme.sh/acme.sh ]] || die "acme.sh tidak ditemukan setelah proses install."
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null || true

  mkdir -p "${CERT_DIR}"
  chmod 700 "${CERT_DIR}"

  if [[ "${ACME_CERT_MODE:-standalone}" == "dns_cf_wildcard" ]]; then
    [[ -n "${ACME_ROOT_DOMAIN:-}" ]] || die "ACME_ROOT_DOMAIN kosong (mode dns_cf_wildcard)."
    [[ -n "${DOMAIN:-}" ]] || die "DOMAIN kosong (mode dns_cf_wildcard)."
    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || die "CLOUDFLARE_API_TOKEN kosong untuk mode wildcard dns_cf."
    log "Issue sertifikat wildcard untuk ${DOMAIN} via acme.sh (dns_cf)..."

    if [[ ! -s /root/.acme.sh/dnsapi/dns_cf.sh ]]; then
      warn "dns_cf hook tidak ditemukan, mencoba bootstrap dari ref ${ACME_SH_INSTALL_REF} ..."
      mkdir -p /root/.acme.sh/dnsapi
      download_file_or_die "${ACME_SH_DNS_CF_HOOK_URL}" /root/.acme.sh/dnsapi/dns_cf.sh
      chmod 700 /root/.acme.sh/dnsapi/dns_cf.sh >/dev/null 2>&1 || true
    fi
    [[ -s /root/.acme.sh/dnsapi/dns_cf.sh ]] || die "Hook dns_cf tetap tidak ditemukan setelah bootstrap."

    if ! cf_api GET "/user/tokens/verify" >/dev/null 2>&1; then
      die "Token Cloudflare tidak valid/kurang scope. Butuh minimal: Zone:DNS Edit + Zone:Read untuk zone domain."
    fi

    export CF_Token="$CLOUDFLARE_API_TOKEN"
    [[ -n "${CF_ACCOUNT_ID:-}" ]] && export CF_Account_ID="$CF_ACCOUNT_ID"
    [[ -n "${CF_ZONE_ID:-}" ]] && export CF_Zone_ID="$CF_ZONE_ID"

    /root/.acme.sh/acme.sh --issue --force --dns dns_cf \
      -d "$DOMAIN" -d "*.$DOMAIN" \
      || die "Gagal issue sertifikat wildcard via dns_cf (pastikan token Cloudflare valid)."

    /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --key-file "$CERT_PRIVKEY" \
      --fullchain-file "$CERT_FULLCHAIN" \
      --reloadcmd "systemctl restart nginx || true" >/dev/null
  else
    log "Issue sertifikat untuk $DOMAIN via acme.sh (standalone port 80)..."
    /root/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" --httpport 80 \
      || die "Gagal issue sertifikat (pastikan port 80 terbuka & DNS domain mengarah ke VPS)."

    /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --key-file "$CERT_PRIVKEY" \
      --fullchain-file "$CERT_FULLCHAIN" \
      --reloadcmd "systemctl restart nginx || true" >/dev/null
  fi

  chmod 600 "$CERT_PRIVKEY" "$CERT_FULLCHAIN"

  log "Sertifikat tersimpan:"
  log "  - $CERT_FULLCHAIN"
  log "  - $CERT_PRIVKEY"
  domain_control_clear_stopped_services
}

domain_control_apply_nginx_domain() {
  local domain="$1"
  [[ -n "${domain}" ]] || die "Domain kosong."
  [[ -f "${NGINX_CONF}" ]] || die "Nginx conf tidak ditemukan: ${NGINX_CONF}"
  ensure_path_writable "${NGINX_CONF}"

  local backup
  backup="${WORK_DIR}/xray.conf.domain-backup.$(date +%s)"
  cp -a "${NGINX_CONF}" "${backup}" || die "Gagal membuat backup nginx conf."

  if ! sed -E -i "s|^([[:space:]]*server_name[[:space:]]+)[^;]+;|\\1${domain};|g" "${NGINX_CONF}"; then
    cp -a "${backup}" "${NGINX_CONF}" >/dev/null 2>&1 || true
    die "Gagal update server_name di nginx conf."
  fi

  local domain_re
  domain_re="$(printf '%s\n' "${domain}" | sed -e 's/[.[\*^$()+?{|]/\\&/g')"
  if ! grep -Eq "^[[:space:]]*server_name[[:space:]]+${domain_re};" "${NGINX_CONF}"; then
    cp -a "${backup}" "${NGINX_CONF}" >/dev/null 2>&1 || true
    die "server_name ${domain}; tidak ditemukan setelah update."
  fi

  if ! nginx -t >/dev/null 2>&1; then
    warn "nginx -t gagal setelah update domain, rollback ke backup."
    cp -a "${backup}" "${NGINX_CONF}" >/dev/null 2>&1 || true
    nginx -t >&2 || true
    die "Konfigurasi nginx invalid setelah ubah domain."
  fi

  if ! systemctl restart nginx >/dev/null 2>&1; then
    warn "Restart nginx gagal setelah update domain, rollback ke backup."
    cp -a "${backup}" "${NGINX_CONF}" >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
    die "Gagal restart nginx setelah ubah domain."
  fi

  log "server_name nginx diperbarui ke: ${domain}"
}

domain_control_set_domain_now() {
  title
  echo "5) Domain Control > Set Domain (setup flow)"
  hr
  have_cmd curl || die "curl tidak ditemukan."
  have_cmd jq || die "jq tidak ditemukan."

  domain_menu_v2
  install_acme_and_issue_cert
  domain_control_apply_nginx_domain "${DOMAIN}"

  hr
  log "Domain aktif sekarang: ${DOMAIN}"
  pause
}

domain_control_show_info() {
  title
  echo "5) Domain Control > Show Current Domain"
  hr
  echo "Domain aktif : $(detect_domain)"
  echo "Cert file    : ${CERT_FULLCHAIN}"
  echo "Key file     : ${CERT_PRIVKEY}"
  if [[ -s "${CERT_FULLCHAIN}" && -s "${CERT_PRIVKEY}" ]]; then
    echo "Status cert  : tersedia"
  else
    echo "Status cert  : belum tersedia / kosong"
  fi
  hr
  pause
}

domain_control_menu() {
  while true; do
    title
    echo "5) Domain Control"
    hr
    echo "  1) Set Domain + Issue Certificate (sama seperti setup.sh)"
    echo "  2) Show Current Domain"
    echo "  0) Back (kembali)"
    echo "  kembali) Back"
    hr
    read -r -p "Pilih (1-2/0/kembali): " c
    case "${c}" in
      1) domain_control_set_domain_now ;;
      2) domain_control_show_info ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

need_python3() {
  have_cmd python3 || die "python3 tidak ditemukan. Install dulu: apt-get install -y python3"
}

gen_uuid() {
  if have_cmd uuidgen; then
    uuidgen
  else
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
  fi
}

pause() {
  read -r -p "Tekan ENTER untuk kembali..." _
}

run_action() {
  # Jalankan aksi dalam subshell supaya error tidak menutup script,
  # lalu kembali ke Main Menu.
  # args: label cmd...
  local label="$1"
  shift || true

  local rc=0
  set +e
  ( set -euo pipefail; "$@" )
  rc=$?
  set -euo pipefail

  if (( rc != 0 )); then
    warn "${label} gagal (rc=${rc}). Kembali ke Main Menu."
    pause
  fi
  return 0
}

hr() {
  printf '%*s\n' "${COLUMNS:-80}" '' | tr ' ' '-'
}

title() {
  clear || true
  echo "HM Xray - CLI Menu Manajemen"
  echo "File: ${0}"
  hr
}

# -------------------------
# Service helpers
# -------------------------
svc_state() {
  local svc="$1"
  systemctl is-active "${svc}" 2>/dev/null || true
}

svc_is_active() {
  local svc="$1"
  systemctl is-active --quiet "${svc}" >/dev/null 2>&1
}

svc_wait_active() {
  # args: service [timeout_seconds]
  local svc="$1"
  local timeout="${2:-20}"
  local checks i state

  if [[ ! "${timeout}" =~ ^[0-9]+$ ]] || (( timeout <= 0 )); then
    timeout=20
  fi
  checks=$(( timeout * 4 ))
  if (( checks < 1 )); then
    checks=1
  fi

  for (( i=0; i<checks; i++ )); do
    state="$(svc_state "${svc}")"
    if [[ "${state}" == "active" ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

svc_exists() {
  local svc="$1"
  local load
  load="$(systemctl show -p LoadState --value "${svc}" 2>/dev/null || true)"
  [[ -n "${load}" && "${load}" != "not-found" ]]
}

svc_status_line() {
  local svc="$1"
  if svc_is_active "${svc}"; then
    echo "OK   - ${svc} (active)"
  else
    echo "FAIL - ${svc} (inactive)"
  fi
}

svc_restart() {
  local svc="$1"
  local st
  systemctl restart "${svc}" >/dev/null 2>&1 || true
  if svc_wait_active "${svc}" 20; then
    log "Restart sukses: ${svc}"
    return 0
  fi

  st="$(svc_state "${svc}")"
  if [[ "${st}" == "failed" || "${st}" == "inactive" ]]; then
    # Recovery best-effort: antisipasi start-limit-hit saat restart beruntun.
    systemctl reset-failed "${svc}" >/dev/null 2>&1 || true
    sleep 1
    systemctl start "${svc}" >/dev/null 2>&1 || true
    if svc_wait_active "${svc}" 20; then
      log "Restart recovery sukses: ${svc}"
      return 0
    fi
    st="$(svc_state "${svc}")"
  fi

  warn "Restart dilakukan, tapi status masih tidak aktif: ${svc} (state=${st:-unknown})"
  return 1
}

svc_restart_if_exists() {
  local svc="$1"
  if systemctl cat "${svc}" >/dev/null 2>&1; then
    systemctl restart "${svc}" >/dev/null 2>&1 || true
    svc_wait_active "${svc}" 20 >/dev/null 2>&1 || true
    return 0
  fi
  return 1
}

svc_restart_any() {
  # args: list of service names (with or without .service)
  local s
  for s in "$@"; do
    if svc_restart_if_exists "${s}"; then
      return 0
    fi
    if [[ "${s}" != *.service ]]; then
      if svc_restart_if_exists "${s}.service"; then
        return 0
      fi
    fi
  done
  return 1
}

# -------------------------
# Account helpers (read-only)
# -------------------------
ACCOUNT_FILES=()
ACCOUNT_FILE_PROTOS=()

quota_cache_rebuild() {
  QUOTA_FIELDS_CACHE=()
  need_python3

  local line key val
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    key="${line%%|*}"
    val="${line#*|}"
    [[ -n "${key}" ]] || continue
    QUOTA_FIELDS_CACHE["${key}"]="${val}"
  done < <(python3 - <<'PY' "${QUOTA_ROOT}" "${QUOTA_PROTO_DIRS[@]}" 2>/dev/null || true
import json
import os
import sys

quota_root = sys.argv[1]
protos = tuple(sys.argv[2:])

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s = str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def fmt_gb(v):
  try:
    v = float(v)
  except Exception:
    return "0"
  if v <= 0:
    return "0"
  if abs(v - round(v)) < 1e-9:
    return str(int(round(v)))
  s = f"{v:.2f}"
  s = s.rstrip("0").rstrip(".")
  return s

for proto in protos:
  d = os.path.join(quota_root, proto)
  if not os.path.isdir(d):
    continue

  chosen = {}
  chosen_has_at = {}
  for name in sorted(os.listdir(d)):
    if not name.endswith(".json"):
      continue
    base = name[:-5]
    username = base.split("@", 1)[0] if "@" in base else base
    if not username:
      continue
    has_at = "@" in base
    prev = chosen.get(username)
    if prev is not None:
      # Prefer username@proto.json over legacy username.json
      if has_at and not chosen_has_at.get(username, False):
        chosen[username] = os.path.join(d, name)
        chosen_has_at[username] = True
      continue
    chosen[username] = os.path.join(d, name)
    chosen_has_at[username] = has_at

  for username in sorted(chosen.keys()):
    qf = chosen[username]
    quota_gb = "0"
    expired = "-"
    created = "-"
    ip_enabled = "false"
    ip_limit = 0

    try:
      with open(qf, "r", encoding="utf-8") as f:
        data = json.load(f)
      if isinstance(data, dict):
        ql = to_int(data.get("quota_limit"), 0)
        unit = str(data.get("quota_unit") or "binary").strip().lower()
        bpg = 1000**3 if unit in ("decimal", "gb", "1000", "gigabyte") else 1024**3
        quota_gb = fmt_gb(ql / bpg) if ql else "0"
        expired = str(data.get("expired_at") or "-")
        created = str(data.get("created_at") or "-")
        st_raw = data.get("status")
        st = st_raw if isinstance(st_raw, dict) else {}
        ip_enabled = str(bool(st.get("ip_limit_enabled"))).lower()
        ip_limit = to_int(st.get("ip_limit"), 0)
    except Exception:
      pass

    print(f"{proto}:{username}|{quota_gb}|{expired}|{created}|{ip_enabled}|{ip_limit}")
PY
)
}

account_collect_files() {
  ACCOUNT_FILES=()
  ACCOUNT_FILE_PROTOS=()

  local proto dir f base u key
  declare -A pos=()
  declare -A has_at=()

  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r -d '' f; do
      base="$(basename "${f}")"
      base="${base%.txt}"
      if [[ "${base}" == *"@"* ]]; then
        u="${base%%@*}"
      else
        u="${base}"
      fi
      key="${proto}:${u}"

      # Prefer file "username@proto.txt" over legacy "username.txt" if both exist.
      if [[ -n "${pos[${key}]:-}" ]]; then
        if [[ "${base}" == *"@"* && "${has_at[${key}]:-0}" != "1" ]]; then
          ACCOUNT_FILES[${pos[${key}]}]="${f}"
          ACCOUNT_FILE_PROTOS[${pos[${key}]}]="${proto}"
          has_at["${key}"]=1
        fi
        continue
      fi

      pos["${key}"]="${#ACCOUNT_FILES[@]}"
      if [[ "${base}" == *"@"* ]]; then
        has_at["${key}"]=1
      else
        has_at["${key}"]=0
      fi

      ACCOUNT_FILES+=("${f}")
      ACCOUNT_FILE_PROTOS+=("${proto}")
    done < <(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null | sort -z)
  done

  # Build metadata cache in one Python process to avoid N subprocesses per row.
  quota_cache_rebuild
}

ACCOUNT_PAGE_SIZE=10
ACCOUNT_PAGE=0

account_total_pages() {
  local total="${#ACCOUNT_FILES[@]}"
  if (( total == 0 )); then
    echo 0
    return 0
  fi
  echo $(( (total + ACCOUNT_PAGE_SIZE - 1) / ACCOUNT_PAGE_SIZE ))
}

account_parse_username_from_file() {
  # args: file_path proto -> prints username (tanpa suffix @proto jika ada)
  local f="$1"
  local proto="$2"
  local base user
  base="$(basename "${f}")"
  base="${base%.txt}"
  if [[ "${base}" == *"@"* ]]; then
    user="${base%%@*}"
  else
    user="${base}"
  fi
  echo "${user}"
}

quota_read_fields() {
  # args: proto username -> prints: quota_gb|expired_at|created_at|ip_enabled|ip_limit
  local proto="$1"
  local username="$2"
  local key="${proto}:${username}"
  local parsed

  if [[ -n "${QUOTA_FIELDS_CACHE["${key}"]+_}" ]]; then
    echo "${QUOTA_FIELDS_CACHE["${key}"]}"
    return 0
  fi

  local qf="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  if [[ ! -f "${qf}" ]]; then
    qf="${QUOTA_ROOT}/${proto}/${username}.json"
  fi
  if [[ ! -f "${qf}" ]]; then
    echo "-|-|-|-|-"
    return 0
  fi

  parsed="$(python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|-|-|-|-")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("-|-|-|-|-")
  raise SystemExit(0)

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s=str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def fmt_gb(v):
  try:
    v=float(v)
  except Exception:
    return "0"
  if v <= 0:
    return "0"
  if abs(v - round(v)) < 1e-9:
    return str(int(round(v)))
  s=f"{v:.2f}"
  s=s.rstrip("0").rstrip(".")
  return s

ql=to_int(d.get("quota_limit"), 0)
# Hormati quota_unit yang ditulis saat create user
unit=str(d.get("quota_unit") or "binary").strip().lower()
bpg=1000**3 if unit in ("decimal","gb","1000","gigabyte") else 1024**3
quota_gb=fmt_gb(ql/bpg) if ql else "0"
expired=d.get("expired_at") or "-"
created=d.get("created_at") or "-"
st_raw=d.get("status")
st=st_raw if isinstance(st_raw, dict) else {}
ip_en=bool(st.get("ip_limit_enabled"))
ip_lim=to_int(st.get("ip_limit"), 0)
print(f"{quota_gb}|{expired}|{created}|{str(ip_en).lower()}|{ip_lim}")
PY
)"
  QUOTA_FIELDS_CACHE["${key}"]="${parsed}"
  echo "${parsed}"
}

account_print_table_page() {
  # args: page
  local page="${1:-0}"
  local total="${#ACCOUNT_FILES[@]}"
  local pages
  pages="$(account_total_pages)"

  if (( total == 0 )); then
    warn "Tidak ada file account di ${ACCOUNT_ROOT}/{vless,vmess,trojan}"
    return 0
  fi

  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi

  local start end i f proto username fields quota_gb expired created ip_en ip_lim
  start=$((page * ACCOUNT_PAGE_SIZE))
  end=$((start + ACCOUNT_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi

  printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "NO" "PROTO" "USERNAME" "QUOTA" "VALID UNTIL" "IP"
  printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "----" "--------" "------------------" "----------" "-------------------" "-------"

  for (( i=start; i<end; i++ )); do
    f="${ACCOUNT_FILES[$i]}"
    proto="${ACCOUNT_FILE_PROTOS[$i]}"
    username="$(account_parse_username_from_file "${f}" "${proto}")"
    fields="$(quota_read_fields "${proto}" "${username}")"
    quota_gb="${fields%%|*}"
    fields="${fields#*|}"
    expired="${fields%%|*}"
    fields="${fields#*|}"
    created="${fields%%|*}"
    fields="${fields#*|}"
    ip_en="${fields%%|*}"
    ip_lim="${fields##*|}"

    local ip_show="OFF"
    if [[ "${ip_en}" == "true" ]]; then
      ip_show="ON(${ip_lim})"
    fi

    # BUG-17 fix: display page-relative row number (i - start + 1) so that
    # page 2 starts at NO=1, not NO=11. This matches user expectation when
    # entering a row number to select.
    printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "$((i - start + 1))" "${proto}" "${username}" "${quota_gb} GB" "${expired}" "${ip_show}"
  done

  echo
  echo "Halaman: $((page + 1))/${pages}  | Total akun: ${total}"
  if (( pages > 1 )); then
    echo "Ketik: next / previous / kembali"
  fi
}

human_size() {
  # bytes -> human-ish (KiB/MiB/GiB)
  local bytes="${1:-0}"
  local kib mib gib
  kib=$((1024))
  mib=$((1024 * 1024))
  gib=$((1024 * 1024 * 1024))

  if (( bytes >= gib )); then
    printf "%.1fGiB" "$(awk "BEGIN {print ${bytes}/${gib}}")"
  elif (( bytes >= mib )); then
    printf "%.1fMiB" "$(awk "BEGIN {print ${bytes}/${mib}}")"
  elif (( bytes >= kib )); then
    printf "%.1fKiB" "$(awk "BEGIN {print ${bytes}/${kib}}")"
  else
    printf "%dB" "${bytes}"
  fi
}

account_print_table() {
  local i f proto base mtime size
  if (( ${#ACCOUNT_FILES[@]} == 0 )); then
    warn "Tidak ada file account di ${ACCOUNT_ROOT}/{vless,vmess,trojan}"
    echo "Pastikan directory berikut ada:"
    echo "  ${ACCOUNT_ROOT}/vless"
    echo "  ${ACCOUNT_ROOT}/vmess"
    echo "  ${ACCOUNT_ROOT}/trojan"
    return 0
  fi

  printf "%-4s %-8s %-34s %-19s %-8s\n" "NO" "PROTO" "FILE" "UPDATED" "SIZE"
  printf "%-4s %-8s %-34s %-19s %-8s\n" "----" "--------" "----------------------------------" "-------------------" "--------"

  for i in "${!ACCOUNT_FILES[@]}"; do
    f="${ACCOUNT_FILES[$i]}"
    proto="${ACCOUNT_FILE_PROTOS[$i]}"
    base="$(basename "${f}")"
    mtime="$(stat -c '%y' "${f}" 2>/dev/null | cut -d'.' -f1 || echo '-')"
    size="$(stat -c '%s' "${f}" 2>/dev/null || echo '0')"
    printf "%-4s %-8s %-34s %-19s %-8s\n" "$((i + 1))" "${proto}" "${base}" "${mtime}" "$(human_size "${size}")"
  done
}

account_view_flow() {
  if (( ${#ACCOUNT_FILES[@]} == 0 )); then
    warn "Tidak ada file untuk dilihat"
    pause
    return 0
  fi

  local n f total page pages start end rows idx
  read -r -p "Masukkan NO untuk view (atau kembali): " n
  if is_back_choice "${n}"; then
    return 0
  fi
  [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }

  total="${#ACCOUNT_FILES[@]}"
  page="${ACCOUNT_PAGE:-0}"
  pages=$(( (total + ACCOUNT_PAGE_SIZE - 1) / ACCOUNT_PAGE_SIZE ))
  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi
  start=$((page * ACCOUNT_PAGE_SIZE))
  end=$((start + ACCOUNT_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi
  rows=$((end - start))

  if (( n < 1 || n > rows )); then
    warn "NO di luar range"
    pause
    return 0
  fi

  idx=$((start + n - 1))
  f="${ACCOUNT_FILES[$idx]}"
  title
  echo "View: ${f}"
  hr
  if have_cmd less; then
    less -R "${f}"
  else
    cat "${f}"
  fi
  hr
  pause
}

account_search_flow() {
  title
  echo "User Management > Search (read-only)"
  hr
  if ! have_cmd grep; then
    warn "grep tidak tersedia"
    pause
    return 0
  fi

  echo "Cari keyword (case-sensitive, gunakan regex bila perlu)."
  read -r -p "Query: " q
  if [[ -z "${q}" ]]; then
    warn "Query kosong"
    pause
    return 0
  fi

  local matches=() proto dir f
  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r f; do
      [[ -n "${f}" ]] && matches+=("${f}")
    done < <(grep -RIl -- "${q}" "${dir}" 2>/dev/null || true)
  done

  title
  echo "Hasil search: ${q}"
  hr
  if (( ${#matches[@]} == 0 )); then
    warn "Tidak ada hasil."
    hr
    pause
    return 0
  fi

  local i f proto base
  printf "%-4s %-8s %-34s %s\n" "NO" "PROTO" "FILE" "PATH"
  printf "%-4s %-8s %-34s %s\n" "----" "--------" "----------------------------------" "----"
  for i in "${!matches[@]}"; do
    f="${matches[$i]}"
    proto="$(basename "$(dirname "${f}")")"
    base="$(basename "${f}")"
    printf "%-4s %-8s %-34s %s\n" "$((i + 1))" "${proto}" "${base}" "${f}"
  done
  hr
  echo "  1) View salah satu hasil"
  echo "  0) Back (kembali)"
  hr
  read -r -p "Pilih: " c
  case "${c}" in
    1)
      read -r -p "Masukkan NO untuk view (atau kembali): " n
  if is_back_choice "${n}"; then
    return 0
  fi
      [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
      if (( n < 1 || n > ${#matches[@]} )); then
        warn "NO di luar range"
        pause
        return 0
      fi
      f="${matches[$((n - 1))]}"
      title
      echo "View: ${f}"
      hr
      if have_cmd less; then
        less -R "${f}"
      else
        cat "${f}"
      fi
      hr
      pause
      ;;
    0|kembali|k|back|b) : ;;
    *) : ;;
  esac
}

# -------------------------
# Diagnostics
# -------------------------
check_files() {
  local ok=0
  [[ -d "${XRAY_CONFDIR}" ]] || { warn "Tidak ada: ${XRAY_CONFDIR}"; ok=1; }
  [[ -f "${NGINX_CONF}" ]] || { warn "Tidak ada: ${NGINX_CONF}"; ok=1; }
  [[ -f "${CERT_FULLCHAIN}" ]] || { warn "Tidak ada: ${CERT_FULLCHAIN}"; ok=1; }
  [[ -f "${CERT_PRIVKEY}" ]] || { warn "Tidak ada: ${CERT_PRIVKEY}"; ok=1; }
  return "${ok}"
}

check_nginx_config() {
  if ! have_cmd nginx; then
    warn "nginx tidak tersedia, lewati nginx -t"
    return 0
  fi

  local out rc
  out="$(nginx -t 2>&1 || true)"
  if echo "${out}" | grep -q "test is successful"; then
    log "nginx -t: OK"
    return 0
  fi

  # Beberapa environment (container/sandbox terbatas) memblokir akses pid/log
  # sehingga nginx -t false-negative. Dalam kasus ini jadikan warning agar menu
  # diagnostic tetap bisa lanjut.
  if echo "${out}" | grep -Eqi "Permission denied|/var/run/nginx.pid|could not open error log file"; then
    warn "nginx -t tidak bisa diverifikasi penuh di environment ini (permission restriction)."
    echo "${out}" >&2
    return 0
  fi

  warn "nginx -t: GAGAL"
  if [[ -n "${out}" ]]; then
    echo "${out}" >&2
  else
    warn "Tidak ada output dari nginx -t"
  fi
  return 1
}

check_xray_config_json() {
  if ! have_cmd jq; then
    warn "jq tidak tersedia, lewati validasi JSON"
    return 0
  fi

  local ok=1 f
  for f in \
    "${XRAY_LOG_CONF}" \
    "${XRAY_API_CONF}" \
    "${XRAY_DNS_CONF}" \
    "${XRAY_INBOUNDS_CONF}" \
    "${XRAY_OUTBOUNDS_CONF}" \
    "${XRAY_ROUTING_CONF}" \
    "${XRAY_POLICY_CONF}" \
    "${XRAY_STATS_CONF}" \
    "${XRAY_OBSERVATORY_CONF}"; do
    if [[ ! -f "${f}" ]]; then
      warn "Konfigurasi tidak ditemukan: ${f}"
      ok=0
      continue
    fi
    if ! jq -e . "${f}" >/dev/null; then
      warn "JSON tidak valid: ${f}"
      ok=0
    fi
  done

  (( ok == 1 )) || die "Konfigurasi Xray (conf.d) tidak lengkap / invalid."
  log "Xray conf.d JSON: OK"
}

xray_confdir_syntax_test() {
  # Return 0 jika syntax confdir valid atau binary xray tidak tersedia.
  # Return non-zero jika xray tersedia namun test config gagal.
  if ! have_cmd xray; then
    return 0
  fi
  xray run -test -confdir "${XRAY_CONFDIR}" >/dev/null 2>&1
}


check_tls_expiry() {
  if have_cmd openssl && [[ -f "${CERT_FULLCHAIN}" ]]; then
    local end
    end="$(openssl x509 -in "${CERT_FULLCHAIN}" -noout -enddate 2>/dev/null | sed -e 's/^notAfter=//')"
    if [[ -n "${end}" ]]; then
      log "TLS notAfter: ${end}"
    else
      warn "Gagal baca expiry TLS"
    fi
  else
    warn "openssl/cert tidak tersedia, lewati cek TLS"
  fi
}

show_ports() {
  if have_cmd ss; then
    ss -lntp | sed -n '1,120p'
  else
    warn "ss tidak tersedia"
  fi
}

tail_logs() {
  local target="$1"
  local lines="${2:-120}"
  if [[ "${target}" == "xray" ]]; then
    journalctl -u xray --no-pager -n "${lines}"
  elif [[ "${target}" == "nginx" ]]; then
    journalctl -u nginx --no-pager -n "${lines}"
  else
    die "Target log tidak dikenal: ${target}"
  fi
}


show_listeners_compact() {
  # Ringkas output listeners (80/443) tanpa users:(...)
  if ! have_cmd ss; then
    warn "ss tidak tersedia"
    return 0
  fi

  printf "%-6s %-22s %-8s %s\n" "PROTO" "LOCAL" "PORT" "PROC"
  printf "%-6s %-22s %-8s %s\n" "------" "----------------------" "--------" "----"

  ss -lntpH 2>/dev/null | awk '
    $1 == "LISTEN" {
      local=$4
      port=local
      sub(/.*:/,"",port)

      if (port ~ /^(80|443)$/) {
        proc="-"
        line=$0

        if (line ~ /users:\(\("/) {
          sub(/.*users:\(\("/, "", line)
          sub(/".*/, "", line)
          if (line != "") proc=line
        }

        printf "%-6s %-22s %-8s %s\n", "tcp", local, port, proc
      }
    }
  ' || true
}

sanity_check_now() {
  title
  echo "Sanity Check (core only)"
  hr
  echo "$(svc_status_line xray)"
  echo "$(svc_status_line nginx)"
  hr

  echo "Daemon Status:"
  echo "$(svc_status_line xray-expired)"
  echo "$(svc_status_line xray-quota)"
  echo "$(svc_status_line xray-limit-ip)"
  hr

  check_files || true
  hr
  check_nginx_config || warn "Validasi nginx gagal (lanjut cek lain)."
  check_xray_config_json
  check_tls_expiry
  hr

  echo "Listeners (ringkas):"
  show_listeners_compact
  hr
  echo "[OK] Sanity check selesai (lihat WARN bila ada)."
  pause
}

trap 'domain_control_restore_on_exit' EXIT

# -------------------------
# Xray user management (placeholder)
# -------------------------


xray_backup_config() {
  # Rolling backup to avoid long-term pile-up.
  # args: file_path (optional)
  local src b
  src="${1:-${XRAY_INBOUNDS_CONF}}"

  b="${WORK_DIR}/$(basename "${src}").prev"
  cp -a "${src}" "${b}"
  echo "${b}"
}




xray_write_file_atomic() {
  # args: dest_path tmp_json_path
  local dest="$1"
  local src_tmp="$2"
  local dir base tmp_target mode uid gid

  dir="$(dirname "${dest}")"
  base="$(basename "${dest}")"
  tmp_target="${dir}/.${base}.new.$$"

  ensure_path_writable "${dest}"

  mode="$(stat -c '%a' "${dest}" 2>/dev/null || echo '600')"
  uid="$(stat -c '%u' "${dest}" 2>/dev/null || echo '0')"
  gid="$(stat -c '%g' "${dest}" 2>/dev/null || echo '0')"

  cp -f "${src_tmp}" "${tmp_target}"
  chmod "${mode}" "${tmp_target}" 2>/dev/null || chmod 600 "${tmp_target}" || true
  chown "${uid}:${gid}" "${tmp_target}" 2>/dev/null || chown 0:0 "${tmp_target}" || true

  mv -f "${tmp_target}" "${dest}" || {
    rm -f "${tmp_target}" 2>/dev/null || true
    die "Gagal replace ${dest} (permission denied / filesystem read-only / immutable)."
  }
}

xray_write_config_atomic() {
  # Backward-compat wrapper (writes inbounds conf).
  # args: tmp_json_path
  xray_write_file_atomic "${XRAY_INBOUNDS_CONF}" "$1"
}

xray_restart_or_rollback_file() {
  # args: target_file backup_file context_label
  local target="$1"
  local backup="$2"
  local ctx="${3:-config}"
  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    cp -a "${backup}" "${target}" 2>/dev/null || true
    systemctl restart xray || true
    die "xray tidak aktif setelah update ${ctx}. Config di-rollback ke backup: ${backup}"
  fi
}

xray_write_routing_locked() {
  # Wrapper xray_write_file_atomic untuk ROUTING_CONF dengan flock.
  # Gunakan ini untuk semua write ke 30-routing.json agar sinkron dengan
  # daemon Python (xray-quota, limit-ip, user-block) yang pakai lock yang sama.
  # args: tmp_json_path
  local tmp="$1"
  (
    flock -x 200
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}"
}



xray_add_client() {
  # args: protocol username uuid_or_pass
  local proto="$1"
  local username="$2"
  local cred="$3"

  local email="${username}@${proto}"
  need_python3

  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || die "Xray inbounds conf tidak ditemukan: ${XRAY_INBOUNDS_CONF}"
  ensure_path_writable "${XRAY_INBOUNDS_CONF}"

  local backup out changed
  backup="$(xray_backup_config "${XRAY_INBOUNDS_CONF}")"
  out="$(python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${ROUTING_LOCK_FILE}" "${proto}" "${email}" "${cred}"
import json
import os
import sys
import tempfile
import fcntl

src, lock_file, proto, email, cred = sys.argv[1:6]

def save_json_atomic(path, data):
  dirn = os.path.dirname(path) or "."
  st = None
  try:
    st = os.stat(path)
  except Exception:
    st = None
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st is not None:
      try:
        os.chmod(tmp, st.st_mode & 0o7777)
      except Exception:
        pass
      try:
        os.chown(tmp, st.st_uid, st.st_gid)
      except Exception:
        pass
    os.replace(tmp, path)
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

os.makedirs(os.path.dirname(lock_file) or "/var/lock", exist_ok=True)
with open(lock_file, "w", encoding="utf-8") as lf:
  fcntl.flock(lf, fcntl.LOCK_EX)
  try:
    with open(src, "r", encoding="utf-8") as f:
      cfg = json.load(f)

    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
      raise SystemExit("Invalid config: inbounds is not a list")

    def iter_clients_for_protocol(p):
      for ib in inbounds:
        if ib.get("protocol") != p:
          continue
        st = ib.get("settings") or {}
        clients = st.get("clients")
        if isinstance(clients, list):
          for c in clients:
            yield c

    for c in iter_clients_for_protocol(proto):
      if c.get("email") == email:
        raise SystemExit(f"user sudah ada di config untuk {proto}: {email}")

    if proto == "vless":
      client = {"id": cred, "email": email}
    elif proto == "vmess":
      client = {"id": cred, "alterId": 0, "email": email}
    elif proto == "trojan":
      client = {"password": cred, "email": email}
    else:
      raise SystemExit("Unsupported protocol: " + proto)

    updated = False
    for ib in inbounds:
      if ib.get("protocol") != proto:
        continue
      st = ib.setdefault("settings", {})
      clients = st.get("clients")
      if clients is None:
        st["clients"] = []
        clients = st["clients"]
      if not isinstance(clients, list):
        continue
      clients.append(client)
      updated = True

    if not updated:
      raise SystemExit(f"Tidak menemukan inbound protocol {proto} dengan settings.clients")

    save_json_atomic(src, cfg)
    print("changed=1")
  finally:
    fcntl.flock(lf, fcntl.LOCK_UN)
PY
)" || die "Gagal memproses inbounds untuk add user: ${email}"

  changed="$(printf '%s\n' "${out}" | tail -n 1 | awk -F'=' '/^changed=/{print $2; exit}')"
  if [[ "${changed}" != "1" ]]; then
    return 0
  fi

  # restart xray to apply
  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_INBOUNDS_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah add user. Config di-rollback ke backup: ${backup}"
  fi
}

xray_delete_client() {
  # args: protocol username
  local proto="$1"
  local username="$2"

  local email="${username}@${proto}"
  need_python3

  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || die "Xray inbounds conf tidak ditemukan: ${XRAY_INBOUNDS_CONF}"
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_INBOUNDS_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  local backup_inb backup_rt out changed
  backup_inb="$(xray_backup_config "${XRAY_INBOUNDS_CONF}")"
  backup_rt="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  out="$(python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${XRAY_ROUTING_CONF}" "${ROUTING_LOCK_FILE}" "${proto}" "${email}"
import json
import os
import sys
import tempfile
import fcntl

inb_src, rt_src, lock_file, proto, email = sys.argv[1:6]

def save_json_atomic(path, data):
  dirn = os.path.dirname(path) or "."
  st = None
  try:
    st = os.stat(path)
  except Exception:
    st = None
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, ensure_ascii=False, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st is not None:
      try:
        os.chmod(tmp, st.st_mode & 0o7777)
      except Exception:
        pass
      try:
        os.chown(tmp, st.st_uid, st.st_gid)
      except Exception:
        pass
    os.replace(tmp, path)
  finally:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass

os.makedirs(os.path.dirname(lock_file) or "/var/lock", exist_ok=True)
with open(lock_file, "w", encoding="utf-8") as lf:
  fcntl.flock(lf, fcntl.LOCK_EX)
  try:
    with open(inb_src, "r", encoding="utf-8") as f:
      inb_cfg = json.load(f)
    with open(rt_src, "r", encoding="utf-8") as f:
      rt_cfg = json.load(f)

    inbounds = inb_cfg.get("inbounds", [])
    if not isinstance(inbounds, list):
      raise SystemExit("Invalid inbounds config: inbounds is not a list")

    removed = 0
    for ib in inbounds:
      if ib.get("protocol") != proto:
        continue
      st = ib.get("settings") or {}
      clients = st.get("clients")
      if not isinstance(clients, list):
        continue
      before = len(clients)
      clients[:] = [c for c in clients if c.get("email") != email]
      removed += (before - len(clients))
      st["clients"] = clients
      ib["settings"] = st

    if removed == 0:
      raise SystemExit(f"Tidak menemukan user untuk dihapus: {email} ({proto})")

    routing = (rt_cfg.get("routing") or {})
    rules = routing.get("rules")
    if isinstance(rules, list):
      markers = {"dummy-block-user","dummy-quota-user","dummy-limit-user","dummy-warp-user","dummy-direct-user"}
      speed_marker_prefix = "dummy-speed-user-"
      for r in rules:
        if not isinstance(r, dict):
          continue
        u = r.get("user")
        if not isinstance(u, list):
          continue
        managed = any(m in u for m in markers)
        if not managed:
          managed = any(isinstance(x, str) and x.startswith(speed_marker_prefix) for x in u)
        if not managed:
          continue
        r["user"] = [x for x in u if x != email]
      routing["rules"] = rules
      rt_cfg["routing"] = routing

    save_json_atomic(inb_src, inb_cfg)
    save_json_atomic(rt_src, rt_cfg)
    print("changed=1")
  finally:
    fcntl.flock(lf, fcntl.LOCK_UN)
PY
)" || {
    (
      flock -x 200
      cp -a "${backup_inb}" "${XRAY_INBOUNDS_CONF}"
      cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal memproses delete user (rollback ke backup): ${email}"
  }

  changed="$(printf '%s\n' "${out}" | tail -n 1 | awk -F'=' '/^changed=/{print $2; exit}')"
  if [[ "${changed}" != "1" ]]; then
    return 0
  fi

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup_inb}" "${XRAY_INBOUNDS_CONF}"
      cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah delete user. Config di-rollback ke backup."
  fi
}

xray_routing_set_user_in_marker() {
  # args: marker email on|off [outbound_tag]
  # outbound_tag defaults to 'blocked' for backward compatibility
  local marker="$1"
  local email="$2"
  local state="$3"
  # BUG-08 fix: outboundTag is now a parameter instead of hardcoded 'blocked'.
  # Previously this function silently failed for any marker whose rule used a
  # different outboundTag (e.g. dummy-warp-user → 'warp', dummy-direct-user → 'direct').
  local outbound_tag="${4:-blocked}"

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  local backup
  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"

  local out changed
  # Load + modify + save dijalankan di lock yang sama agar tidak menimpa perubahan daemon.
  out="$(python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${ROUTING_LOCK_FILE}" "${marker}" "${email}" "${state}" "${outbound_tag}"
import json, sys, os, tempfile, fcntl
src, lock_file, marker, email, state, outbound_tag = sys.argv[1:7]

os.makedirs(os.path.dirname(lock_file) or "/var/lock", exist_ok=True)
with open(lock_file, "w", encoding="utf-8") as lf:
  fcntl.flock(lf, fcntl.LOCK_EX)
  try:
    with open(src, "r", encoding="utf-8") as f:
      cfg = json.load(f)

    routing = cfg.get("routing") or {}
    rules = routing.get("rules")
    if not isinstance(rules, list):
      raise SystemExit("Invalid routing config: routing.rules is not a list")

    target = None
    for r in rules:
      if not isinstance(r, dict):
        continue
      if r.get("type") != "field":
        continue
      if r.get("outboundTag") != outbound_tag:
        continue
      u = r.get("user")
      if not isinstance(u, list):
        continue
      if marker in u:
        target = r
        break

    if target is None:
      raise SystemExit(f"Tidak menemukan routing rule outboundTag={outbound_tag} dengan marker: {marker}")

    users = target.get("user") or []
    if not isinstance(users, list):
      users = []

    if marker not in users:
      users.insert(0, marker)
    else:
      users = [marker] + [x for x in users if x != marker]

    changed = False
    if state == "on":
      if email not in users:
        users.append(email)
        changed = True
    elif state == "off":
      new_users = [x for x in users if x != email]
      if new_users != users:
        users = new_users
        changed = True
    else:
      raise SystemExit("state harus 'on' atau 'off'")

    target["user"] = users
    routing["rules"] = rules
    cfg["routing"] = routing

    if changed:
      dirn = os.path.dirname(src) or "."
      st = None
      try:
        st = os.stat(src)
      except Exception:
        st = None
      fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
      try:
        with os.fdopen(fd, "w", encoding="utf-8") as wf:
          json.dump(cfg, wf, ensure_ascii=False, indent=2)
          wf.write("\n")
          wf.flush()
          os.fsync(wf.fileno())
        if st is not None:
          try:
            os.chmod(tmp, st.st_mode & 0o7777)
          except Exception:
            pass
          try:
            os.chown(tmp, st.st_uid, st.st_gid)
          except Exception:
            pass
        os.replace(tmp, src)
      finally:
        try:
          if os.path.exists(tmp):
            os.remove(tmp)
        except Exception:
          pass

    print("changed=1" if changed else "changed=0")
  finally:
    fcntl.flock(lf, fcntl.LOCK_UN)
PY
)" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal memproses routing: ${XRAY_ROUTING_CONF}"
  }

  changed="$(printf '%s\n' "${out}" | tail -n 1 | awk -F'=' '/^changed=/{print $2; exit}')"
  if [[ "${changed}" != "1" ]]; then
    return 0
  fi

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update routing. Routing di-rollback ke backup: ${backup}"
  fi
}


xray_extract_endpoints() {
  # args: protocol -> prints lines: network|path_or_service
  local proto="$1"
  need_python3
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${proto}"
import json, sys
src, proto = sys.argv[1:3]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)

seen=set()
for ib in cfg.get('inbounds', []) or []:
  if ib.get('protocol') != proto:
    continue
  ss = ib.get('streamSettings') or {}
  net = ss.get('network') or ''
  if not net:
    continue
  val=''
  if net == 'ws':
    ws = ss.get('wsSettings') or {}
    val = ws.get('path') or ''
  elif net in ('httpupgrade','httpUpgrade'):
    hu = ss.get('httpUpgradeSettings') or ss.get('httpupgradeSettings') or {}
    val = hu.get('path') or ''
  elif net == 'grpc':
    gs = ss.get('grpcSettings') or {}
    val = gs.get('serviceName') or ''
  key=(net,val)
  if key in seen:
    continue
  seen.add(key)
  print(net + "|" + val)
PY
}

speed_policy_file_path() {
  # args: proto username
  local proto="$1"
  local username="$2"
  echo "${SPEED_POLICY_ROOT}/${proto}/${username}@${proto}.json"
}

speed_policy_exists() {
  # args: proto username
  local proto="$1"
  local username="$2"
  local f
  f="$(speed_policy_file_path "${proto}" "${username}")"
  [[ -f "${f}" ]]
}

speed_policy_remove() {
  # args: proto username
  local proto="$1"
  local username="$2"
  local f
  f="$(speed_policy_file_path "${proto}" "${username}")"
  speed_policy_lock_prepare
  (
    flock -x 200
    if [[ -f "${f}" ]]; then
      rm -f "${f}" 2>/dev/null || true
    fi
  ) 200>"${SPEED_POLICY_LOCK_FILE}"
}

speed_policy_upsert() {
  # args: proto username down_mbit up_mbit
  local proto="$1"
  local username="$2"
  local down_mbit="$3"
  local up_mbit="$4"

  ensure_speed_policy_dirs
  speed_policy_lock_prepare
  need_python3

  local email out_file mark
  email="${username}@${proto}"
  out_file="$(speed_policy_file_path "${proto}" "${username}")"

  mark="$(
    (
      flock -x 200
      python3 - <<'PY' "${SPEED_POLICY_ROOT}" "${proto}" "${email}" "${down_mbit}" "${up_mbit}" "${out_file}"
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

root, proto, email, down_raw, up_raw, out_file = sys.argv[1:7]

def to_float(v):
  try:
    n = float(v)
  except Exception:
    return 0.0
  if n <= 0:
    return 0.0
  return round(n, 3)

down = to_float(down_raw)
up = to_float(up_raw)
if down <= 0 or up <= 0:
  raise SystemExit("speed mbit harus > 0")

MARK_MIN = 1000
MARK_MAX = 59999
RANGE = MARK_MAX - MARK_MIN + 1

def valid_mark(v):
  try:
    m = int(v)
  except Exception:
    return False
  return MARK_MIN <= m <= MARK_MAX

def load_json(path):
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:
    return {}

used = set()
for p1 in ("vless", "vmess", "trojan"):
  d = os.path.join(root, p1)
  if not os.path.isdir(d):
    continue
  for name in os.listdir(d):
    if not name.endswith(".json"):
      continue
    fp = os.path.join(d, name)
    if os.path.abspath(fp) == os.path.abspath(out_file):
      continue
    data = load_json(fp)
    m = data.get("mark")
    if valid_mark(m):
      used.add(int(m))

existing = load_json(out_file)
existing_mark = existing.get("mark")

if valid_mark(existing_mark) and int(existing_mark) not in used:
  mark = int(existing_mark)
else:
  seed = int(hashlib.sha256(email.encode("utf-8")).hexdigest()[:8], 16)
  start = MARK_MIN + (seed % RANGE)
  mark = None
  for i in range(RANGE):
    cand = MARK_MIN + ((start - MARK_MIN + i) % RANGE)
    if cand not in used:
      mark = cand
      break
  if mark is None:
    raise SystemExit("mark speed policy habis")

payload = {
  "enabled": True,
  "username": email,
  "protocol": proto,
  "mark": mark,
  "down_mbit": down,
  "up_mbit": up,
  "updated_at": datetime.now(timezone.utc).isoformat(),
}

os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=os.path.dirname(out_file) or ".")
try:
  with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False, indent=2)
    f.write("\n")
    f.flush()
    os.fsync(f.fileno())
  os.replace(tmp, out_file)
finally:
  try:
    if os.path.exists(tmp):
      os.remove(tmp)
  except Exception:
    pass

print(mark)
PY
    ) 200>"${SPEED_POLICY_LOCK_FILE}"
  )" || return 1

  [[ -n "${mark:-}" ]] || return 1
  chmod 600 "${out_file}" 2>/dev/null || true
  echo "${mark}"
}

speed_policy_apply_now() {
  if [[ -x /usr/local/bin/xray-speed && -f "${SPEED_CONFIG_FILE}" ]]; then
    /usr/local/bin/xray-speed once --config "${SPEED_CONFIG_FILE}" >/dev/null 2>&1 && return 0
  fi
  if svc_exists xray-speed; then
    svc_restart xray-speed >/dev/null 2>&1 || true
    svc_is_active xray-speed && return 0
  fi
  return 1
}

speed_policy_sync_xray() {
  need_python3
  [[ -f "${XRAY_OUTBOUNDS_CONF}" ]] || return 1
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 1
  ensure_path_writable "${XRAY_OUTBOUNDS_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  local backup_out backup_rt tmp_out tmp_rt
  backup_out="$(xray_backup_config "${XRAY_OUTBOUNDS_CONF}")"
  backup_rt="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp_out="${WORK_DIR}/20-outbounds.json.tmp"
  tmp_rt="${WORK_DIR}/30-routing-speed.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' \
      "${SPEED_POLICY_ROOT}" \
      "${XRAY_OUTBOUNDS_CONF}" \
      "${XRAY_ROUTING_CONF}" \
      "${tmp_out}" \
      "${tmp_rt}" \
      "${SPEED_OUTBOUND_TAG_PREFIX}" \
      "${SPEED_RULE_MARKER_PREFIX}" \
      "${SPEED_MARK_MIN}" \
      "${SPEED_MARK_MAX}"
import copy
import json
import os
import re
import sys

policy_root, out_src, rt_src, out_dst, rt_dst, out_prefix, marker_prefix, mark_min_raw, mark_max_raw = sys.argv[1:10]
mark_min = int(mark_min_raw)
mark_max = int(mark_max_raw)
speed_bal_prefix = f"{out_prefix}bal-"

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def dump_json(path, obj):
  with open(path, "w", encoding="utf-8") as f:
    json.dump(obj, f, ensure_ascii=False, indent=2)
    f.write("\n")

def boolify(v):
  if isinstance(v, bool):
    return v
  if isinstance(v, (int, float)):
    return bool(v)
  s = str(v or "").strip().lower()
  return s in ("1", "true", "yes", "on", "y")

def to_float(v):
  try:
    n = float(v)
  except Exception:
    return 0.0
  if n <= 0:
    return 0.0
  return n

def to_mark(v):
  try:
    m = int(v)
  except Exception:
    return None
  if m < mark_min or m > mark_max:
    return None
  return m

def list_mark_users(root):
  mark_users = {}
  for proto in ("vless", "vmess", "trojan"):
    d = os.path.join(root, proto)
    if not os.path.isdir(d):
      continue
    for name in sorted(os.listdir(d)):
      if not name.endswith(".json"):
        continue
      fp = os.path.join(d, name)
      try:
        data = load_json(fp)
      except Exception:
        continue
      if not isinstance(data, dict):
        continue
      if not boolify(data.get("enabled", True)):
        continue
      mark = to_mark(data.get("mark"))
      if mark is None:
        continue
      down = to_float(data.get("down_mbit"))
      up = to_float(data.get("up_mbit"))
      if down <= 0 or up <= 0:
        continue
      email = str(data.get("username") or data.get("email") or os.path.splitext(name)[0]).strip()
      if not email:
        continue
      mark_users.setdefault(mark, set()).add(email)
  return {k: sorted(v) for k, v in sorted(mark_users.items())}

def is_default_rule(r):
  if not isinstance(r, dict):
    return False
  if r.get("type") != "field":
    return False
  port = str(r.get("port", "")).strip()
  if port not in ("1-65535", "0-65535"):
    return False
  if r.get("user") or r.get("domain") or r.get("ip") or r.get("protocol"):
    return False
  return True

def is_protected_rule(r):
  if not isinstance(r, dict):
    return False
  if r.get("type") != "field":
    return False
  ot = r.get("outboundTag")
  return isinstance(ot, str) and ot in ("api", "blocked")

def norm_tag(v):
  if not isinstance(v, str):
    return ""
  return v.strip()

def sanitize_tag(v):
  s = norm_tag(v)
  if not s:
    return "x"
  return re.sub(r"[^A-Za-z0-9_.-]", "-", s)

mark_users = list_mark_users(policy_root)

out_cfg = load_json(out_src)
outbounds = out_cfg.get("outbounds")
if not isinstance(outbounds, list):
  raise SystemExit("Invalid outbounds config: outbounds bukan list")
outbounds_by_tag = {}
for o in outbounds:
  if not isinstance(o, dict):
    continue
  t = norm_tag(o.get("tag"))
  if not t:
    continue
  outbounds_by_tag[t] = o

rt_cfg = load_json(rt_src)
routing = rt_cfg.get("routing") or {}
rules = routing.get("rules")
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")
balancers = routing.get("balancers")
if not isinstance(balancers, list):
  balancers = []
balancers_by_tag = {}
for b in balancers:
  if not isinstance(b, dict):
    continue
  t = norm_tag(b.get("tag"))
  if not t:
    continue
  balancers_by_tag[t] = b

default_rule = None
for r in rules:
  if is_default_rule(r):
    default_rule = r

base_mode = "outbound"
base_selector = []
base_strategy = {}
base_balancer_tag = ""
if isinstance(default_rule, dict):
  bt = norm_tag(default_rule.get("balancerTag"))
  ot = norm_tag(default_rule.get("outboundTag"))
  if bt:
    base_mode = "balancer"
    base_balancer_tag = bt
  elif ot:
    base_selector = [ot]

if base_mode == "balancer":
  b0 = balancers_by_tag.get(base_balancer_tag)
  if isinstance(b0, dict):
    sel = b0.get("selector")
    if isinstance(sel, list):
      for t in sel:
        t2 = norm_tag(t)
        if t2:
          base_selector.append(t2)
    st = b0.get("strategy")
    if isinstance(st, dict):
      base_strategy = copy.deepcopy(st)
  if not base_selector and isinstance(default_rule, dict):
    ot = norm_tag(default_rule.get("outboundTag"))
    if ot:
      base_mode = "outbound"
      base_selector = [ot]

if not base_selector:
  if "direct" in outbounds_by_tag:
    base_selector = ["direct"]
  else:
    for t in outbounds_by_tag.keys():
      if not t.startswith(out_prefix):
        base_selector = [t]
        break
if not base_selector:
  raise SystemExit("Outbound dasar untuk speed policy tidak ditemukan")

effective_selector = []
seen = set()
for t in base_selector:
  t2 = norm_tag(t)
  if not t2:
    continue
  if t2 in ("api", "blocked"):
    continue
  if t2.startswith(out_prefix):
    continue
  if t2 not in outbounds_by_tag:
    continue
  if t2 in seen:
    continue
  seen.add(t2)
  effective_selector.append(t2)
if not effective_selector:
  # Recovery path untuk konfigurasi legacy/invalid:
  # jika selector dasar berisi tag speed/internal saja, fallback ke outbound non-speed.
  if "direct" in outbounds_by_tag:
    effective_selector = ["direct"]
  else:
    for t in outbounds_by_tag.keys():
      t2 = norm_tag(t)
      if not t2:
        continue
      if t2 in ("api", "blocked"):
        continue
      if t2.startswith(out_prefix):
        continue
      effective_selector = [t2]
      break
if not effective_selector:
  raise SystemExit("Selector outbound dasar untuk speed policy kosong")

clean_outbounds = []
for o in outbounds:
  if isinstance(o, dict):
    tag = norm_tag(o.get("tag"))
    if tag and tag.startswith(out_prefix):
      continue
  clean_outbounds.append(o)

mark_out_tags = {}
for mark in sorted(mark_users.keys()):
  per_mark = {}
  for base_tag in effective_selector:
    src = outbounds_by_tag.get(base_tag)
    if not isinstance(src, dict):
      continue
    clone_tag = f"{out_prefix}{mark}-{sanitize_tag(base_tag)}"
    so = copy.deepcopy(src)
    so["tag"] = clone_tag
    ss = so.get("streamSettings")
    if not isinstance(ss, dict):
      ss = {}
    sock = ss.get("sockopt")
    if not isinstance(sock, dict):
      sock = {}
    sock["mark"] = int(mark)
    ss["sockopt"] = sock
    so["streamSettings"] = ss
    clean_outbounds.append(so)
    per_mark[base_tag] = clone_tag
  mark_out_tags[mark] = per_mark

out_cfg["outbounds"] = clean_outbounds
dump_json(out_dst, out_cfg)

clean_balancers = []
for b in balancers:
  if isinstance(b, dict):
    t = norm_tag(b.get("tag"))
    if t.startswith(speed_bal_prefix):
      continue
  clean_balancers.append(b)

speed_balancers = {}
if base_mode == "balancer":
  for mark in sorted(mark_users.keys()):
    sel = []
    for base_tag in effective_selector:
      mt = mark_out_tags.get(mark, {}).get(base_tag)
      if mt:
        sel.append(mt)
    if not sel:
      continue
    btag = f"{speed_bal_prefix}{mark}"
    nb = {"tag": btag, "selector": sel}
    if isinstance(base_strategy, dict) and base_strategy:
      nb["strategy"] = copy.deepcopy(base_strategy)
    clean_balancers.append(nb)
    speed_balancers[mark] = btag

kept_rules = []
for r in rules:
  if not isinstance(r, dict):
    kept_rules.append(r)
    continue
  if r.get("type") != "field":
    kept_rules.append(r)
    continue
  users = r.get("user")
  ot = norm_tag(r.get("outboundTag"))
  bt = norm_tag(r.get("balancerTag"))
  has_speed_marker = isinstance(users, list) and any(
    isinstance(x, str) and x.startswith(marker_prefix) for x in users
  )
  if has_speed_marker and (ot.startswith(out_prefix) or bt.startswith(speed_bal_prefix)):
    continue
  kept_rules.append(r)

insert_idx = len(kept_rules)
for i, r in enumerate(kept_rules):
  if is_protected_rule(r):
    continue
  insert_idx = i
  break

speed_rules = []
for mark, users in sorted(mark_users.items()):
  marker = f"{marker_prefix}{mark}"
  rule = {
    "type": "field",
    "user": [marker] + users,
  }
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
dump_json(rt_dst, rt_cfg)
PY
    xray_write_file_atomic "${XRAY_OUTBOUNDS_CONF}" "${tmp_out}"
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp_rt}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup_out}" "${XRAY_OUTBOUNDS_CONF}"
      cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    return 1
  }

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup_out}" "${XRAY_OUTBOUNDS_CONF}"
      cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    return 1
  fi
  return 0
}

rollback_new_user_after_speed_failure() {
  # args: proto username
  local proto="$1"
  local username="$2"
  local email="${username}@${proto}"

  warn "Rollback akun ${email} karena setup speed-limit gagal."
  speed_policy_remove "${proto}" "${username}"
  speed_policy_sync_xray >/dev/null 2>&1 || true
  speed_policy_apply_now >/dev/null 2>&1 || true
  xray_delete_client "${proto}" "${username}" >/dev/null 2>&1 || true
  delete_account_artifacts "${proto}" "${username}" >/dev/null 2>&1 || true
}

write_account_artifacts() {
  # args: protocol username cred quota_bytes days ip_limit_enabled ip_limit_value speed_enabled speed_down_mbit speed_up_mbit
  local proto="$1"
  local username="$2"
  local cred="$3"
  local quota_bytes="$4"
  local days="$5"
  local ip_enabled="$6"
  local ip_limit="$7"
  local speed_enabled="$8"
  local speed_down="$9"
  local speed_up="${10}"

  ensure_account_quota_dirs
  need_python3

  local domain ip created expired
  domain="$(detect_domain)"
  ip="$(detect_public_ip_ipapi)"
  created="$(date -u '+%Y-%m-%d')"
  expired="$(date -u -d "+${days} days" '+%Y-%m-%d' 2>/dev/null || date -u '+%Y-%m-%d')"

  local acc_file quota_file
  acc_file="${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"
  quota_file="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"

  python3 - <<'PY' "${acc_file}" "${quota_file}" "${domain}" "${ip}" "${username}" "${proto}" "${cred}" "${quota_bytes}" "${created}" "${expired}" "${days}" "${ip_enabled}" "${ip_limit}" "${speed_enabled}" "${speed_down}" "${speed_up}"
import sys, json, base64, urllib.parse, datetime
acc_file, quota_file, domain, ip, username, proto, cred, quota_bytes, created_at, expired_at, days, ip_enabled, ip_limit, speed_enabled, speed_down, speed_up = sys.argv[1:17]
quota_bytes=int(quota_bytes)
days=int(float(days)) if str(days).strip() else 0
ip_enabled = str(ip_enabled).lower() in ("1","true","yes","y","on")
speed_enabled = str(speed_enabled).lower() in ("1","true","yes","y","on")
try:
  ip_limit_int=int(ip_limit)
except Exception:
  ip_limit_int=0
try:
  speed_down_mbit=float(speed_down)
except Exception:
  speed_down_mbit=0.0
try:
  speed_up_mbit=float(speed_up)
except Exception:
  speed_up_mbit=0.0
if not speed_enabled or speed_down_mbit <= 0 or speed_up_mbit <= 0:
  speed_enabled=False
  speed_down_mbit=0.0
  speed_up_mbit=0.0

def fmt_gb(v):
  try:
    v=float(v)
  except Exception:
    return "0"
  if v <= 0:
    return "0"
  if abs(v - round(v)) < 1e-9:
    return str(int(round(v)))
  s=f"{v:.2f}"
  s=s.rstrip("0").rstrip(".")
  return s

def fmt_mbit(v):
  try:
    n=float(v)
  except Exception:
    return "0"
  if n <= 0:
    return "0"
  if abs(n-round(n)) < 1e-9:
    return str(int(round(n)))
  s=f"{n:.2f}"
  return s.rstrip("0").rstrip(".")

# Public endpoint harus selaras dengan nginx public path (setup.sh).
PUBLIC_PATHS = {
  "vless": {"ws": "/vless-ws", "httpupgrade": "/vless-hup", "grpc": "vless-grpc"},
  "vmess": {"ws": "/vmess-ws", "httpupgrade": "/vmess-hup", "grpc": "vmess-grpc"},
  "trojan": {"ws": "/trojan-ws", "httpupgrade": "/trojan-hup", "grpc": "trojan-grpc"},
}


def vless_link(net, val):
  q={"encryption":"none","security":"tls","type":net,"sni":domain}
  if net in ("ws","httpupgrade"):
    q["path"]=val or "/"
  elif net=="grpc":
    if val:
      q["serviceName"]=val
  return f"vless://{cred}@{domain}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + "@" + proto)}"

def trojan_link(net, val):
  q={"security":"tls","type":net,"sni":domain}
  if net in ("ws","httpupgrade"):
    q["path"]=val or "/"
  elif net=="grpc":
    if val:
      q["serviceName"]=val
  return f"trojan://{cred}@{domain}:443?{urllib.parse.urlencode(q)}#{urllib.parse.quote(username + "@" + proto)}"

def vmess_link(net, val):
  obj={
    "v":"2",
    "ps":username + "@" + proto,
    "add":domain,
    "port":"443",
    "id":cred,
    "aid":"0",
    "net":net,
    "type":"none",
    "host":domain,
    "tls":"tls",
    "sni":domain
  }
  if net in ("ws","httpupgrade"):
    obj["path"]=val or "/"
  elif net=="grpc":
    obj["path"]=val or ""  # many clients use path as serviceName
    obj["type"]="gun"
  raw=json.dumps(obj, separators=(",",":"))
  return "vmess://" + base64.b64encode(raw.encode()).decode()

links={}
public_proto = PUBLIC_PATHS.get(proto, {})
for net in ("ws","httpupgrade","grpc"):
  val = public_proto.get(net, "")
  if proto=="vless":
    links[net]=vless_link(net,val)
  elif proto=="vmess":
    links[net]=vmess_link(net,val)
  elif proto=="trojan":
    links[net]=trojan_link(net,val)

quota_gb = quota_bytes/(1024**3) if quota_bytes else 0
quota_gb_disp = fmt_gb(quota_gb)

# Write account txt
lines=[]
lines.append("=== XRAY ACCOUNT INFO ===")
lines.append(f"Domain      : {domain}")
lines.append(f"IP          : {ip}")
lines.append(f"Username    : {username}")
lines.append(f"Protocol    : {proto}")
if proto in ("vless","vmess"):
  lines.append(f"UUID        : {cred}")
else:
  lines.append(f"Password    : {cred}")
lines.append(f"Quota Limit : {quota_gb_disp} GB")
lines.append(f"Expired     : {days} days")
lines.append(f"Valid Until : {expired_at}")
lines.append(f"Created     : {created_at}")
lines.append(f"IP Limit    : {'ON' if ip_enabled else 'OFF'}" + (f" ({ip_limit_int})" if ip_enabled else ""))
if speed_enabled:
  lines.append(f"Speed Limit : ON (DOWN {fmt_mbit(speed_down_mbit)} Mbps | UP {fmt_mbit(speed_up_mbit)} Mbps)")
else:
  lines.append("Speed Limit : OFF")
lines.append("")
lines.append("Links Import:")
lines.append(f"  WebSocket   : {links.get('ws','-')}")
lines.append(f"  HTTPUpgrade : {links.get('httpupgrade','-')}")
lines.append(f"  gRPC        : {links.get('grpc','-')}")
lines.append("")

with open(acc_file, "w", encoding="utf-8") as f:
  f.write("\n".join(lines))

# Write quota json metadata
meta={
  "username": username + "@" + proto,
  "protocol": proto,
  "quota_limit": quota_bytes,
  "quota_unit": "binary",
  "quota_used": 0,
  "created_at": created_at,
  "expired_at": expired_at,
  "status": {
    "manual_block": False,
    "quota_exhausted": False,
    "ip_limit_enabled": ip_enabled,
    "ip_limit": ip_limit_int if ip_enabled else 0,
    "speed_limit_enabled": speed_enabled,
    "speed_down_mbit": speed_down_mbit if speed_enabled else 0,
    "speed_up_mbit": speed_up_mbit if speed_enabled else 0,
    "ip_limit_locked": False,
    "lock_reason": "",
    "locked_at": ""
  }
}
with open(quota_file, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY

  chmod 600 "${acc_file}" "${quota_file}" || true
}


delete_one_file() {
  local f="$1"
  [[ -n "${f}" ]] || return 0
  if [[ -f "${f}" ]]; then
    if have_cmd lsattr && lsattr -d "${f}" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      warn "File immutable, lepas dulu: chattr -i '${f}'"
    fi
    chmod u+w "${f}" 2>/dev/null || true
    if rm -f "${f}" 2>/dev/null; then
      log "Hapus: ${f}"
    else
      warn "Gagal hapus: ${f} (permission denied/immutable)"
    fi
  fi
}

delete_account_artifacts() {
  # args: protocol username
  local proto="$1"
  local username="$2"

  local acc_file acc_file_legacy quota_file quota_file_legacy
  acc_file="${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"
  acc_file_legacy="${ACCOUNT_ROOT}/${proto}/${username}.txt"
  quota_file="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  quota_file_legacy="${QUOTA_ROOT}/${proto}/${username}.json"

  delete_one_file "${acc_file}"
  delete_one_file "${acc_file_legacy}"
  delete_one_file "${quota_file}"
  delete_one_file "${quota_file_legacy}"
  speed_policy_remove "${proto}" "${username}"
}



user_add_menu() {
  local page=0
  while true; do
    title
    echo "User Management > Add user"
    hr
    echo "Daftar akun (10 per halaman):"
    hr
    account_collect_files
    ACCOUNT_PAGE="${page}"
    account_print_table_page "${ACCOUNT_PAGE}"
    hr
    echo "Ketik: lanjut / next / previous / kembali"
    read -r -p "Pilihan: " nav
    if is_back_choice "${nav}"; then
      return 0
    fi
    case "${nav}" in
      lanjut|lanjutkan|l) break ;;
      next|n)
        local pages
        pages="$(account_total_pages)"
        if (( pages > 0 && page < pages - 1 )); then page=$((page + 1)); fi
        ;;
      previous|p|prev)
        if (( page > 0 )); then page=$((page - 1)); fi
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done

  title
  echo "User Management > Add user"
  hr

  ensure_account_quota_dirs
  need_python3

  echo "Pilih protocol:"
  echo "  1) vless"
  echo "  2) vmess"
  echo "  3) trojan"
  echo "  kembali) Back"
  hr
  read -r -p "Protocol (1-3/kembali): " p
  if is_back_choice "${p}"; then
    return 0
  fi
  local proto=""
  case "${p}" in
    1) proto="vless" ;;
    2) proto="vmess" ;;
    3) proto="trojan" ;;
    *) warn "Protocol tidak valid" ; pause ; return 0 ;;
  esac

  read -r -p "Username (atau kembali): " username
  if is_back_choice "${username}"; then
    return 0
  fi
  if [[ -z "${username}" ]]; then
    warn "Username kosong"
    pause
    return 0
  fi

  if ! validate_username "${username}"; then
    warn "Username tidak valid. Gunakan: A-Z a-z 0-9 . _ - (tanpa spasi, tanpa '/', tanpa '..', tanpa '@')."
    pause
    return 0
  fi


  local found_xray found_account found_quota
  found_xray="$(xray_username_find_protos "${username}" || true)"
  found_account="$(account_username_find_protos "${username}" || true)"
  found_quota="$(quota_username_find_protos "${username}" || true)"
  if [[ -n "${found_xray}" || -n "${found_account}" || -n "${found_quota}" ]]; then
    warn "Username sudah ada, batal membuat akun: ${username}"
    [[ -n "${found_xray}" ]] && echo "  - Xray inbounds: ${found_xray}"
    [[ -n "${found_account}" ]] && echo "  - Account file : ${found_account}"
    [[ -n "${found_quota}" ]] && echo "  - Quota meta   : ${found_quota}"
    pause
    return 0
  fi

  read -r -p "Masa aktif (hari) (atau kembali): " days
  if is_back_choice "${days}"; then
    return 0
  fi
  if [[ -z "${days}" || ! "${days}" =~ ^[0-9]+$ || "${days}" -le 0 ]]; then
    warn "Masa aktif harus angka hari > 0"
    pause
    return 0
  fi

  read -r -p "Quota (GB) (atau kembali): " quota_gb
  if is_back_choice "${quota_gb}"; then
    return 0
  fi
  if [[ -z "${quota_gb}" ]]; then
    warn "Quota kosong"
    pause
    return 0
  fi
  local quota_gb_num quota_bytes
  quota_gb_num="$(normalize_gb_input "${quota_gb}")"
  if [[ -z "${quota_gb_num}" ]]; then
    warn "Format quota tidak valid. Contoh: 10 atau 10GB"
    pause
    return 0
  fi
  quota_gb="${quota_gb_num}"
  quota_bytes="$(bytes_from_gb "${quota_gb_num}")"

  echo "Limit IP? (on/off)"
  read -r -p "IP Limit (on/off) (atau kembali): " ip_toggle
  if is_back_choice "${ip_toggle}"; then
    return 0
  fi
  local ip_enabled="false"
  local ip_limit="0"
  if is_yes "${ip_toggle}"; then
    ip_enabled="true"
    read -r -p "Limit IP (angka) (atau kembali): " ip_limit
    if is_back_choice "${ip_limit}"; then
      return 0
    fi
    if [[ -z "${ip_limit}" || ! "${ip_limit}" =~ ^[0-9]+$ || "${ip_limit}" -le 0 ]]; then
      warn "Limit IP harus angka > 0"
      pause
      return 0
    fi
  fi

  echo "Limit speed per user? (on/off)"
  read -r -p "Speed Limit (on/off) (atau kembali): " speed_toggle
  if is_back_choice "${speed_toggle}"; then
    return 0
  fi
  local speed_enabled="false"
  local speed_down_mbit="0"
  local speed_up_mbit="0"
  if is_yes "${speed_toggle}"; then
    speed_enabled="true"

    read -r -p "Speed Download Mbps (contoh: 20 atau 20mbit) (atau kembali): " speed_down
    if is_back_choice "${speed_down}"; then
      return 0
    fi
    speed_down_mbit="$(normalize_speed_mbit_input "${speed_down}")"
    if [[ -z "${speed_down_mbit}" ]] || ! speed_mbit_is_positive "${speed_down_mbit}"; then
      warn "Speed download tidak valid. Gunakan angka > 0, contoh: 20 atau 20mbit"
      pause
      return 0
    fi

    read -r -p "Speed Upload Mbps (contoh: 10 atau 10mbit) (atau kembali): " speed_up
    if is_back_choice "${speed_up}"; then
      return 0
    fi
    speed_up_mbit="$(normalize_speed_mbit_input "${speed_up}")"
    if [[ -z "${speed_up_mbit}" ]] || ! speed_mbit_is_positive "${speed_up_mbit}"; then
      warn "Speed upload tidak valid. Gunakan angka > 0, contoh: 10 atau 10mbit"
      pause
      return 0
    fi
  fi

  hr
  echo "Ringkasan:"
  echo "  Username : ${username}"
  echo "  Protocol : ${proto}"
  echo "  Email    : ${username}@${proto}"
  echo "  Expired  : ${days} hari"
  echo "  Quota    : ${quota_gb} GB"
  echo "  IP Limit : ${ip_enabled} $( [[ "${ip_enabled}" == "true" ]] && echo "(${ip_limit})" )"
  if [[ "${speed_enabled}" == "true" ]]; then
    echo "  Speed    : true (DOWN ${speed_down_mbit} Mbps | UP ${speed_up_mbit} Mbps)"
  else
    echo "  Speed    : false"
  fi
  hr

  local cred
  if [[ "${proto}" == "trojan" ]]; then
    cred="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
  else
    cred="$(gen_uuid)"
  fi

  xray_add_client "${proto}" "${username}" "${cred}"
  write_account_artifacts "${proto}" "${username}" "${cred}" "${quota_bytes}" "${days}" "${ip_enabled}" "${ip_limit}" "${speed_enabled}" "${speed_down_mbit}" "${speed_up_mbit}"

  if [[ "${speed_enabled}" == "true" ]]; then
    local speed_mark="" speed_err=""
    if ! speed_mark="$(speed_policy_upsert "${proto}" "${username}" "${speed_down_mbit}" "${speed_up_mbit}")"; then
      speed_err="gagal menyimpan speed policy"
    elif ! speed_policy_sync_xray; then
      speed_err="gagal sinkronisasi speed policy ke routing/outbound xray"
    elif ! speed_policy_apply_now; then
      speed_err="policy speed tersimpan, tetapi apply runtime gagal (cek service xray-speed)"
    fi

    if [[ -n "${speed_err}" ]]; then
      warn "Akun ${username}@${proto} dibatalkan: ${speed_err}."
      rollback_new_user_after_speed_failure "${proto}" "${username}"
      pause
      return 0
    fi

    log "Speed policy aktif untuk ${username}@${proto} (mark=${speed_mark}, down=${speed_down_mbit}Mbps, up=${speed_up_mbit}Mbps)"
  else
    if speed_policy_exists "${proto}" "${username}"; then
      speed_policy_remove "${proto}" "${username}"
      speed_policy_sync_xray >/dev/null 2>&1 || true
    fi
    speed_policy_apply_now >/dev/null 2>&1 || true
  fi

  title
  echo "Add user sukses ✅"
  hr
  echo "Account file:"
  echo "  ${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"
  echo "Quota metadata:"
  echo "  ${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  hr
  pause
}





user_del_menu() {
  local page=0
  while true; do
    title
    echo "User Management > Delete user"
    hr
    echo "Daftar akun (10 per halaman):"
    hr
    account_collect_files
    ACCOUNT_PAGE="${page}"
    account_print_table_page "${ACCOUNT_PAGE}"
    hr
    echo "Ketik: lanjut / next / previous / kembali"
    read -r -p "Pilihan: " nav
    if is_back_choice "${nav}"; then
      return 0
    fi
    case "${nav}" in
      lanjut|lanjutkan|l) break ;;
      next|n)
        local pages
        pages="$(account_total_pages)"
        if (( pages > 0 && page < pages - 1 )); then page=$((page + 1)); fi
        ;;
      previous|p|prev)
        if (( page > 0 )); then page=$((page - 1)); fi
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done

  title
  echo "User Management > Delete user"
  hr

  ensure_account_quota_dirs
  need_python3

  echo "Pilih protocol:"
  echo "  1) vless"
  echo "  2) vmess"
  echo "  3) trojan"
  echo "  kembali) Back"
  hr
  read -r -p "Protocol (1-3/kembali): " p
  if is_back_choice "${p}"; then
    return 0
  fi
  local proto=""
  case "${p}" in
    1) proto="vless" ;;
    2) proto="vmess" ;;
    3) proto="trojan" ;;
    *) warn "Protocol tidak valid" ; pause ; return 0 ;;
  esac

  read -r -p "Username (atau kembali): " username
  if is_back_choice "${username}"; then
    return 0
  fi
  if [[ -z "${username}" ]]; then
    warn "Username kosong"
    pause
    return 0
  fi

  if ! validate_username "${username}"; then
    warn "Username tidak valid. Gunakan: A-Z a-z 0-9 . _ - (tanpa spasi, tanpa '/', tanpa '..', tanpa '@')."
    pause
    return 0
  fi

  hr
  local speed_sync_ok="true"

  xray_delete_client "${proto}" "${username}"
  delete_account_artifacts "${proto}" "${username}"
  if ! speed_policy_sync_xray; then
    speed_sync_ok="false"
    warn "Delete user selesai, tetapi sinkronisasi speed policy gagal (cek log xray / konfigurasi routing)."
  fi
  speed_policy_apply_now >/dev/null 2>&1 || true

  title
  if [[ "${speed_sync_ok}" == "true" ]]; then
    echo "Delete user selesai ✅"
  else
    echo "Delete user selesai dengan peringatan ⚠"
    echo "Perubahan akun sudah diterapkan, namun sinkronisasi speed policy gagal."
  fi
  hr
  pause
}





user_extend_expiry_menu() {
  local page=0
  while true; do
    title
    echo "User Management > Extend/Set Expiry"
    hr
    echo "Daftar akun (10 per halaman):"
    hr
    account_collect_files
    ACCOUNT_PAGE="${page}"
    account_print_table_page "${ACCOUNT_PAGE}"
    hr
    echo "Ketik: lanjut / next / previous / kembali"
    read -r -p "Pilihan: " nav
    if is_back_choice "${nav}"; then
      return 0
    fi
    case "${nav}" in
      lanjut|lanjutkan|l) break ;;
      next|n)
        local pages
        pages="$(account_total_pages)"
        if (( pages > 0 && page < pages - 1 )); then page=$((page + 1)); fi
        ;;
      previous|p|prev)
        if (( page > 0 )); then page=$((page - 1)); fi
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done

  title
  echo "User Management > Extend/Set Expiry"
  hr

  ensure_account_quota_dirs
  need_python3

  echo "Pilih protocol:"
  echo "  1) vless"
  echo "  2) vmess"
  echo "  3) trojan"
  echo "  kembali) Back"
  hr
  read -r -p "Protocol (1-3/kembali): " p
  if is_back_choice "${p}"; then
    return 0
  fi
  local proto=""
  case "${p}" in
    1) proto="vless" ;;
    2) proto="vmess" ;;
    3) proto="trojan" ;;
    *) warn "Protocol tidak valid" ; pause ; return 0 ;;
  esac

  read -r -p "Username (atau kembali): " username
  if is_back_choice "${username}"; then
    return 0
  fi
  if [[ -z "${username}" ]]; then
    warn "Username kosong"
    pause
    return 0
  fi

  if ! validate_username "${username}"; then
    warn "Username tidak valid. Gunakan: A-Z a-z 0-9 . _ - (tanpa spasi, tanpa '/', tanpa '..', tanpa '@')."
    pause
    return 0
  fi

  local quota_file acc_file
  quota_file="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  acc_file="${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"

  if [[ ! -f "${quota_file}" ]]; then
    warn "Quota file tidak ditemukan: ${quota_file}"
    pause
    return 0
  fi

  # Tampilkan expiry saat ini
  local current_expiry
  current_expiry="$(python3 - <<'PY' "${quota_file}"
import json, sys
p = sys.argv[1]
try:
  d = json.load(open(p, 'r', encoding='utf-8'))
  print(str(d.get("expired_at") or "-"))
except Exception:
  print("-")
PY
)"

  hr
  echo "Username    : ${username}"
  echo "Protocol    : ${proto}"
  echo "Expiry saat ini : ${current_expiry}"
  hr
  echo "  1) Tambah hari (extend)"
  echo "  2) Set tanggal langsung (YYYY-MM-DD)"
  echo "  0) Back (kembali)"
  hr
  read -r -p "Pilih mode: " mode
  if is_back_choice "${mode}"; then
    return 0
  fi

  local new_expiry=""

  case "${mode}" in
    1)
      read -r -p "Tambah berapa hari? (atau kembali): " add_days
      if is_back_choice "${add_days}"; then
        return 0
      fi
      if [[ -z "${add_days}" || ! "${add_days}" =~ ^[0-9]+$ || "${add_days}" -le 0 ]]; then
        warn "Jumlah hari harus angka > 0"
        pause
        return 0
      fi
      # Hitung dari expiry saat ini, jika sudah lewat hitung dari hari ini
      new_expiry="$(python3 - <<'PY' "${current_expiry}" "${add_days}"
import sys
from datetime import datetime, timedelta, timezone
exp_str = sys.argv[1].strip()
add = int(sys.argv[2])
today = datetime.now(timezone.utc).date()
try:
  base = datetime.fromisoformat(exp_str[:10]).date()
  # Jika sudah expired, mulai dari hari ini
  if base < today:
    base = today
except Exception:
  base = today
result = base + timedelta(days=add)
print(result.strftime('%Y-%m-%d'))
PY
)"
      ;;
    2)
      read -r -p "Tanggal expiry baru (YYYY-MM-DD) (atau kembali): " input_date
      if is_back_choice "${input_date}"; then
        return 0
      fi
      # Validasi format tanggal
      if ! python3 - <<'PY' "${input_date}" 2>/dev/null; then
import sys
from datetime import datetime
s = sys.argv[1].strip()
try:
  datetime.strptime(s, '%Y-%m-%d')
  print(s)
except Exception:
  raise SystemExit(1)
PY
        warn "Format tanggal tidak valid. Gunakan: YYYY-MM-DD"
        pause
        return 0
      fi
      new_expiry="$(python3 - <<'PY' "${input_date}"
import sys
from datetime import datetime
s = sys.argv[1].strip()
datetime.strptime(s, '%Y-%m-%d')
print(s)
PY
)"
      ;;
    0|kembali|k|back|b)
      return 0
      ;;
    *)
      warn "Pilihan tidak valid"
      pause
      return 0
      ;;
  esac

  if [[ -z "${new_expiry}" ]]; then
    warn "Gagal menghitung tanggal baru"
    pause
    return 0
  fi

  hr
  echo "Ringkasan perubahan:"
  echo "  Username  : ${username}@${proto}"
  echo "  Expiry lama : ${current_expiry}"
  echo "  Expiry baru : ${new_expiry}"
  hr
  read -r -p "Konfirmasi simpan? (y/n): " confirm
  if ! is_yes "${confirm}"; then
    warn "Dibatalkan."
    pause
    return 0
  fi

  # Update quota JSON
  quota_atomic_update_file "${quota_file}" "d['expired_at'] = '${new_expiry}'"

  # Update account txt (baris Valid Until)
  # BUG-18 fix: use atomic write via tmp file instead of sed -i (which is not atomic)
  if [[ -f "${acc_file}" ]]; then
    local acc_tmp
    acc_tmp="${WORK_DIR}/account_update.$$.tmp"
    if sed "s|^Valid Until :.*|Valid Until : ${new_expiry}|" "${acc_file}" > "${acc_tmp}" 2>/dev/null; then
      mv -f "${acc_tmp}" "${acc_file}" || sed -i "s|^Valid Until :.*|Valid Until : ${new_expiry}|" "${acc_file}" 2>/dev/null || true
    else
      rm -f "${acc_tmp}" 2>/dev/null || true
    fi
    chmod 600 "${acc_file}" 2>/dev/null || true
  fi

  # Re-add user ke xray inbounds jika sudah dihapus oleh xray-expired daemon
  # BUG-09 fix: fetch existing_protos immediately before attempting re-add to reduce
  # the race window with xray-expired daemon (which runs every 2 seconds).
  # We cannot fully eliminate the race without a distributed lock across bash+python,
  # but minimising the gap between check and add is the best we can do here.
  local existing_protos
  existing_protos="$(xray_username_find_protos "${username}" 2>/dev/null || true)"
  if ! echo " ${existing_protos} " | grep -q " ${proto} "; then
    # User tidak ada di inbounds - baca credential dari account txt lalu re-add
    if [[ -f "${acc_file}" ]]; then
      local cred=""
      if [[ "${proto}" == "trojan" ]]; then
        cred="$(grep -E '^Password\s*:' "${acc_file}" | head -n1 | sed 's/^Password\s*:\s*//' | tr -d '[:space:]')"
      else
        cred="$(grep -E '^UUID\s*:' "${acc_file}" | head -n1 | sed 's/^UUID\s*:\s*//' | tr -d '[:space:]')"
      fi
      if [[ -n "${cred}" ]]; then
        xray_add_client "${proto}" "${username}" "${cred}" 2>/dev/null && \
          log "User ${username}@${proto} di-restore ke inbounds (expired lalu di-extend)." || \
          warn "Gagal me-restore ${username}@${proto} ke inbounds. Cek credential di: ${acc_file}"
      else
        warn "Credential tidak ditemukan di ${acc_file}. Re-add user manual jika diperlukan."
      fi
    else
      warn "Account file tidak ada: ${acc_file}. User mungkin perlu di-add ulang secara manual."
    fi
  fi

  # BUG-03 fix: after extending expiry (and possibly restoring user to inbounds),
  # BUG-FIX #3: xray-expired menghapus user dari SEMUA routing rules (termasuk
  # dummy-block-user dan dummy-limit-user) saat user expired. Setelah extend expiry,
  # kita HARUS me-restore routing marker yang masih aktif secara eksplisit.
  # Komentar lama "those markers remain intact" TIDAK benar — xray-expired sudah
  # membersihkannya. Fix: restore dummy-block-user jika manual_block=True,
  # dan dummy-limit-user jika ip_limit_locked=True.
  local st_quota st_manual st_iplocked
  st_quota="$(quota_get_status_bool "${quota_file}" "quota_exhausted" 2>/dev/null || echo "false")"
  st_manual="$(quota_get_status_bool "${quota_file}" "manual_block" 2>/dev/null || echo "false")"
  st_iplocked="$(quota_get_status_bool "${quota_file}" "ip_limit_locked" 2>/dev/null || echo "false")"

  if [[ "${st_quota}" == "true" ]]; then
    # Reset quota_exhausted flag and remove from dummy-quota-user routing rule
    quota_atomic_update_file "${quota_file}" "from datetime import datetime; st=d.setdefault('status',{}); mb=bool(st.get('manual_block')); il=bool(st.get('ip_limit_locked')); st['quota_exhausted']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('manual' if mb else ('ip_limit' if il else '')); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
    xray_routing_set_user_in_marker "dummy-quota-user" "${username}@${proto}" off
    log "Quota exhausted flag di-reset setelah extend expiry."
  fi

  # BUG-FIX #3: Restore manual block routing jika masih aktif.
  # xray-expired sudah menghapus user dari dummy-block-user saat expired,
  # sehingga perlu di-restore eksplisit agar block tetap berlaku.
  if [[ "${st_manual}" == "true" ]]; then
    xray_routing_set_user_in_marker "dummy-block-user" "${username}@${proto}" on
    log "Manual block routing di-restore setelah extend expiry (manual_block=true)."
  fi

  # BUG-FIX #3: Restore ip_limit routing jika masih terkunci.
  if [[ "${st_iplocked}" == "true" ]]; then
    xray_routing_set_user_in_marker "dummy-limit-user" "${username}@${proto}" on
    log "IP limit routing di-restore setelah extend expiry (ip_limit_locked=true)."
  fi

  title
  echo "Extend/Set Expiry selesai ✅"
  hr
  echo "  ${username}@${proto}"
  echo "  Expiry baru : ${new_expiry}"
  hr
  pause
}

user_list_menu() {
  ACCOUNT_PAGE=0
  while true; do
    title
    echo "User Management > List users (from ${ACCOUNT_ROOT})"
    hr

    account_collect_files
    account_print_table_page "${ACCOUNT_PAGE}"
    hr

    echo "  view) View file detail"
    echo "  search) Search"
    echo "  next) Next page"
    echo "  previous) Previous page"
    echo "  refresh) Refresh"
    echo "  kembali) Back"
    hr
    read -r -p "Pilih (view/search/next/previous/refresh/kembali): " c

    if is_back_choice "${c}"; then
      break
    fi

    case "${c}" in
      view|1) account_view_flow ;;
      search|2) account_search_flow ;;
      next|n)
        local pages
        pages="$(account_total_pages)"
        if (( pages > 0 && ACCOUNT_PAGE < pages - 1 )); then
          ACCOUNT_PAGE=$((ACCOUNT_PAGE + 1))
        fi
        ;;
      previous|p|prev)
        if (( ACCOUNT_PAGE > 0 )); then
          ACCOUNT_PAGE=$((ACCOUNT_PAGE - 1))
        fi
        ;;
      refresh|3) : ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

user_menu() {
  while true; do
    title
    echo "2) User Management (Xray Accounts)"
    hr
    echo "  1. Add user"
    echo "  2. Delete user"
    echo "  3. Extend/Set Expiry"
    echo "  4. List users (read-only)"
    echo "  0. Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) user_add_menu ;;
      2) user_del_menu ;;
      3) user_extend_expiry_menu ;;
      4) user_list_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

# -------------------------
# Quota & Access Control
# - Sumber metadata: /opt/quota/(vless|vmess|trojan)/*.json
# - Perubahan JSON menggunakan atomic write (tmp + replace) untuk menghindari file korup
# -------------------------
QUOTA_FILES=()
QUOTA_FILE_PROTOS=()
QUOTA_PAGE_SIZE=10
QUOTA_PAGE=0
QUOTA_QUERY=""
QUOTA_VIEW_INDEXES=()

quota_collect_files() {
  QUOTA_FILES=()
  QUOTA_FILE_PROTOS=()

  local proto dir f base u key
  declare -A pos=()
  declare -A has_at=()

  for proto in "${QUOTA_PROTO_DIRS[@]}"; do
    dir="${QUOTA_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r -d '' f; do
      base="$(basename "${f}")"
      base="${base%.json}"
      if [[ "${base}" == *"@"* ]]; then
        u="${base%%@*}"
      else
        u="${base}"
      fi

      key="${proto}:${u}"

      # Prefer file "username@proto.json" over legacy "username.json" if both exist.
      if [[ -n "${pos[${key}]:-}" ]]; then
        if [[ "${base}" == *"@"* && "${has_at[${key}]:-0}" != "1" ]]; then
          QUOTA_FILES[${pos[${key}]}]="${f}"
          QUOTA_FILE_PROTOS[${pos[${key}]}]="${proto}"
          has_at["${key}"]=1
        fi
        continue
      fi

      pos["${key}"]="${#QUOTA_FILES[@]}"
      if [[ "${base}" == *"@"* ]]; then
        has_at["${key}"]=1
      else
        has_at["${key}"]=0
      fi

      QUOTA_FILES+=("${f}")
      QUOTA_FILE_PROTOS+=("${proto}")
    done < <(find "${dir}" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null | sort -z)
  done
}


quota_total_pages_for_indexes() {
  local total="${#QUOTA_VIEW_INDEXES[@]}"
  if (( total == 0 )); then
    echo 0
    return 0
  fi
  echo $(( (total + QUOTA_PAGE_SIZE - 1) / QUOTA_PAGE_SIZE ))
}

quota_build_view_indexes() {
  # Bangun index view berdasarkan QUOTA_QUERY (case-insensitive, match username/file)
  QUOTA_VIEW_INDEXES=()

  local q
  q="$(echo "${QUOTA_QUERY:-}" | tr '[:upper:]' '[:lower:]')"

  if [[ -z "${q}" ]]; then
    local i
    for i in "${!QUOTA_FILES[@]}"; do
      QUOTA_VIEW_INDEXES+=("${i}")
    done
    return 0
  fi

  local i f proto base u
  for i in "${!QUOTA_FILES[@]}"; do
    f="${QUOTA_FILES[$i]}"
    proto="${QUOTA_FILE_PROTOS[$i]}"
    base="$(basename "${f}")"
    base="${base%.json}"
    if [[ "${base}" == *"@"* ]]; then
      u="${base%%@*}"
    else
      u="${base}"
    fi
    if echo "${u}" | tr '[:upper:]' '[:lower:]' | grep -qF -- "${q}"; then
      QUOTA_VIEW_INDEXES+=("${i}")
      continue
    fi
  done
}

quota_read_summary_fields() {
  # args: json_file
  # prints: username|quota_limit_disp|quota_used_disp|expired_at_date|flags_disp
  local qf="$1"
  need_python3
  python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|0 GB|0 B|-|BROKEN")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("-|0 GB|0 B|-|BROKEN")
  raise SystemExit(0)

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s=str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def fmt_gb(v):
  try:
    n=float(v)
  except Exception:
    n=0.0
  if n < 0:
    n=0.0
  s=f"{n:.3f}".rstrip('0').rstrip('.')
  return s if s else "0"

u=str(d.get("username") or "-")
ql=to_int(d.get("quota_limit"), 0)
qu=to_int(d.get("quota_used"), 0)

# Hormati quota_unit yang tersimpan di file (binary=GiB, decimal=GB)
unit=str(d.get("quota_unit") or "binary").strip().lower()
bpg=1000**3 if unit in ("decimal","gb","1000","gigabyte") else 1024**3
ql_disp=f"{fmt_gb(ql/bpg)} GB"

def used_disp(b):
  try:
    b=int(b)
  except Exception:
    b=0
  if b >= 1024**3:
    return f"{b/(1024**3):.2f} GB"
  if b >= 1024**2:
    return f"{b/(1024**2):.2f} MB"
  if b >= 1024:
    return f"{b/1024:.2f} KB"
  return f"{b} B"

qu_disp=used_disp(qu)

exp=str(d.get("expired_at") or "-")
exp_date=exp[:10] if exp and exp != "-" else "-"

st_raw=d.get("status")
st=st_raw if isinstance(st_raw, dict) else {}
ip_en=bool(st.get("ip_limit_enabled"))
try:
  ip_lim=to_int(st.get("ip_limit"), 0)
except Exception:
  ip_lim=0

ip_str="ON" if ip_en else "OFF"
if ip_en:
  ip_str += f"({ip_lim})" if ip_lim else "(ON)"

lr=str(st.get("lock_reason") or "").strip().lower()
reason="-"
if st.get("manual_block") or lr == "manual":
  reason="MANUAL"
elif st.get("quota_exhausted") or lr == "quota":
  reason="QUOTA"
elif st.get("ip_limit_locked") or lr == "ip_limit":
  reason="IP_LIMIT"

flags=f"IP_LIMIT={ip_str} | BLOCK={reason}"
print(f"{u}|{ql_disp}|{qu_disp}|{exp_date}|{flags}")
PY
}

quota_read_detail_fields() {
  # args: json_file
  # prints:
  # username|quota_limit_disp|quota_used_disp|expired_at_date|ip_limit_onoff|ip_limit_value|block_reason|speed_onoff|speed_down_mbit|speed_up_mbit
  local qf="$1"
  need_python3
  python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|0 GB|0 B|-|OFF|0|-|OFF|0|0")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("-|0 GB|0 B|-|OFF|0|-|OFF|0|0")
  raise SystemExit(0)

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s=str(v).strip()
    if s == "":
      return default
    return int(float(s))
  except Exception:
    return default

def to_float(v, default=0.0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return float(int(v))
    if isinstance(v, (int, float)):
      return float(v)
    s=str(v).strip()
    if s == "":
      return default
    return float(s)
  except Exception:
    return default

def fmt_gb(v):
  try:
    n=float(v)
  except Exception:
    n=0.0
  if n < 0:
    n=0.0
  s=f"{n:.3f}".rstrip('0').rstrip('.')
  return s if s else "0"

def fmt_mbit(v):
  try:
    n=float(v)
  except Exception:
    n=0.0
  if n < 0:
    n=0.0
  s=f"{n:.3f}".rstrip('0').rstrip('.')
  return s if s else "0"

u=str(d.get("username") or "-")
ql=to_int(d.get("quota_limit"), 0)
qu=to_int(d.get("quota_used"), 0)

# Hormati quota_unit yang tersimpan di file
unit=str(d.get("quota_unit") or "binary").strip().lower()
bpg=1000**3 if unit in ("decimal","gb","1000","gigabyte") else 1024**3
ql_disp=f"{fmt_gb(ql/bpg)} GB"

def used_disp(b):
  try:
    b=int(b)
  except Exception:
    b=0
  if b >= 1024**3:
    return f"{b/(1024**3):.2f} GB"
  if b >= 1024**2:
    return f"{b/(1024**2):.2f} MB"
  if b >= 1024:
    return f"{b/1024:.2f} KB"
  return f"{b} B"

qu_disp=used_disp(qu)

exp=str(d.get("expired_at") or "-")
exp_date=exp[:10] if exp and exp != "-" else "-"

st_raw=d.get("status")
st=st_raw if isinstance(st_raw, dict) else {}
ip_en=bool(st.get("ip_limit_enabled"))
try:
  ip_lim=to_int(st.get("ip_limit"), 0)
except Exception:
  ip_lim=0
ip_lim = ip_lim if ip_en else 0

lr=str(st.get("lock_reason") or "").strip().lower()
reason="-"
if st.get("manual_block") or lr == "manual":
  reason="MANUAL"
elif st.get("quota_exhausted") or lr == "quota":
  reason="QUOTA"
elif st.get("ip_limit_locked") or lr == "ip_limit":
  reason="IP_LIMIT"

speed_en=bool(st.get("speed_limit_enabled"))
speed_down=to_float(st.get("speed_down_mbit"), 0.0)
speed_up=to_float(st.get("speed_up_mbit"), 0.0)
if speed_down < 0:
  speed_down = 0.0
if speed_up < 0:
  speed_up = 0.0

print(f"{u}|{ql_disp}|{qu_disp}|{exp_date}|{'ON' if ip_en else 'OFF'}|{ip_lim}|{reason}|{'ON' if speed_en else 'OFF'}|{fmt_mbit(speed_down)}|{fmt_mbit(speed_up)}")
PY
}

quota_get_status_bool() {
  # args: json_file key
  local qf="$1"
  local key="$2"
  need_python3
  python3 - <<'PY' "${qf}" "${key}"
import json, sys
p, k = sys.argv[1:3]
try:
  d = json.load(open(p, 'r', encoding='utf-8'))
except Exception:
  print("false")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("false")
  raise SystemExit(0)
st = d.get("status") or {}
if not isinstance(st, dict):
  st = {}
v = st.get(k, False)
print("true" if bool(v) else "false")
PY
}

quota_get_status_int() {
  # args: json_file key
  local qf="$1"
  local key="$2"
  need_python3
  python3 - <<'PY' "${qf}" "${key}"
import json, sys
p, k = sys.argv[1:3]
try:
  d = json.load(open(p, 'r', encoding='utf-8'))
except Exception:
  print("0")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("0")
  raise SystemExit(0)
st = d.get("status") or {}
if not isinstance(st, dict):
  st = {}
v = st.get(k, 0)
try:
  print(int(v))
except Exception:
  print("0")
PY
}

quota_get_status_number() {
  # args: json_file key
  local qf="$1"
  local key="$2"
  need_python3
  python3 - <<'PY' "${qf}" "${key}"
import json, sys
p, k = sys.argv[1:3]
try:
  d = json.load(open(p, 'r', encoding='utf-8'))
except Exception:
  print("0")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("0")
  raise SystemExit(0)
st = d.get("status") or {}
if not isinstance(st, dict):
  st = {}
v = st.get(k, 0)
try:
  n = float(v)
except Exception:
  n = 0.0
if n < 0:
  n = 0.0
s = f"{n:.3f}".rstrip("0").rstrip(".")
print(s if s else "0")
PY
}

quota_get_lock_reason() {
  # args: json_file
  local qf="$1"
  need_python3
  python3 - <<'PY' "${qf}"
import json, sys
p = sys.argv[1]
try:
  d = json.load(open(p, 'r', encoding='utf-8'))
except Exception:
  print("")
  raise SystemExit(0)
if not isinstance(d, dict):
  print("")
  raise SystemExit(0)
st = d.get("status") or {}
if not isinstance(st, dict):
  st = {}
v = st.get("lock_reason") or ""
print(str(v))
PY
}

quota_sync_speed_policy_for_user() {
  # args: proto username quota_file
  local proto="$1"
  local username="$2"
  local qf="$3"

  local speed_on speed_down speed_up mark
  speed_on="$(quota_get_status_bool "${qf}" "speed_limit_enabled")"
  speed_down="$(quota_get_status_number "${qf}" "speed_down_mbit")"
  speed_up="$(quota_get_status_number "${qf}" "speed_up_mbit")"

  if [[ "${speed_on}" == "true" ]]; then
    if ! speed_mbit_is_positive "${speed_down}" || ! speed_mbit_is_positive "${speed_up}"; then
      warn "Speed limit aktif, tapi nilai download/upload belum valid (> 0)."
      return 1
    fi
    if ! mark="$(speed_policy_upsert "${proto}" "${username}" "${speed_down}" "${speed_up}")"; then
      warn "Gagal menyimpan speed policy ${username}@${proto}"
      return 1
    fi
    if ! speed_policy_sync_xray; then
      warn "Gagal sinkronisasi speed policy ke xray"
      return 1
    fi
    if ! speed_policy_apply_now; then
      warn "Speed policy tersimpan, tetapi apply runtime gagal (cek service xray-speed)"
      return 1
    fi
    log "Speed policy aktif untuk ${username}@${proto} (mark=${mark}, down=${speed_down}Mbps, up=${speed_up}Mbps)"
    return 0
  fi

  if speed_policy_exists "${proto}" "${username}"; then
    speed_policy_remove "${proto}" "${username}"
    if ! speed_policy_sync_xray; then
      warn "Speed limit dinonaktifkan, tetapi sinkronisasi speed policy ke xray gagal"
      return 1
    fi
  fi
  speed_policy_apply_now >/dev/null 2>&1 || true
  return 0
}



quota_print_table_page() {
  # args: page
  local page="${1:-0}"
  local total="${#QUOTA_VIEW_INDEXES[@]}"
  local pages
  pages="$(quota_total_pages_for_indexes)"

  if (( total == 0 )); then
    warn "Tidak ada quota metadata di ${QUOTA_ROOT}/{vless,vmess,trojan}"
    return 0
  fi

  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi

  local start end i real_idx f proto fields username ql_disp qu_disp exp_date
  start=$((page * QUOTA_PAGE_SIZE))
  end=$((start + QUOTA_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi

  if [[ -n "${QUOTA_QUERY}" ]]; then
    echo "Filter: ${QUOTA_QUERY}"
    hr
  fi

  printf "%-4s %-8s %-18s %-10s %-12s %-10s\n" "NO" "PROTO" "USERNAME" "LIMIT" "USED" "EXPIRED AT"

  printf "%-4s %-8s %-18s %-10s %-12s %-10s\n" "----" "--------" "------------------" "----------" "------------" "----------"


  for (( i=start; i<end; i++ )); do
    real_idx="${QUOTA_VIEW_INDEXES[$i]}"
    f="${QUOTA_FILES[$real_idx]}"
    proto="${QUOTA_FILE_PROTOS[$real_idx]}"

    fields="$(quota_read_summary_fields "${f}")"
    username="${fields%%|*}"
    fields="${fields#*|}"
    ql_disp="${fields%%|*}"
    fields="${fields#*|}"
    qu_disp="${fields%%|*}"
    fields="${fields#*|}"
    exp_date="${fields%%|*}"
    # BUG-17 fix: display page-relative row number (i - start + 1)
    printf "%-4s %-8s %-18s %-10s %-12s %-10s\n" "$((i - start + 1))" "${proto}" "${username}" "${ql_disp}" "${qu_disp}" "${exp_date}"

  done

  echo
  echo "Halaman: $((page + 1))/${pages}  | Total metadata: ${total}"
  if (( pages > 1 )); then
    echo "Ketik: next / previous / search / clear / kembali"
  fi
}

quota_atomic_update_file() {
  # args: json_file python_code
  # python_code dijalankan untuk memodifikasi dict 'd'
  # BUG-02 fix: code is passed as sys.argv[2] (NOT via heredoc string interpolation).
  # Previously the heredoc used <<PY (unquoted) which caused bash to expand ${code}
  # before passing it to Python — creating a code injection risk if the code string
  # contained shell metacharacters or triple-quotes.
  local qf="$1"
  local code="$2"
  need_python3

  python3 - "${qf}" "${code}" <<'PY'
import json, sys, os, tempfile
p = sys.argv[1]
code = sys.argv[2]

with open(p, 'r', encoding='utf-8') as f:
  d = json.load(f)

ns = {"d": d}
exec(code, ns, ns)

out = json.dumps(ns["d"], ensure_ascii=False, indent=2) + "\n"

dirn = os.path.dirname(p) or "."
fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
try:
  with os.fdopen(fd, "w", encoding="utf-8") as wf:
    wf.write(out)
    wf.flush()
    os.fsync(wf.fileno())
  os.replace(tmp, p)
finally:
  try:
    if os.path.exists(tmp):
      os.remove(tmp)
  except Exception:
    pass
PY

  chmod 600 "${qf}" 2>/dev/null || true
  QUOTA_FIELDS_CACHE=()
}

quota_view_json() {
  local qf="$1"
  title
  echo "Quota metadata: ${qf}"
  hr
  need_python3
  if have_cmd less; then
    python3 - <<'PY' "${qf}" | less -R
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print(open(p,'r',encoding='utf-8',errors='replace').read())
  raise SystemExit(0)
exp=d.get("expired_at")
if isinstance(exp, str) and exp:
  d["expired_at"]=exp[:10]
crt=d.get("created_at")
if isinstance(crt, str) and crt:
  d["created_at"]=crt[:10]
print(json.dumps(d, ensure_ascii=False, indent=2))
PY
  else
    python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print(open(p,'r',encoding='utf-8',errors='replace').read())
  raise SystemExit(0)
exp=d.get("expired_at")
if isinstance(exp, str) and exp:
  d["expired_at"]=exp[:10]
crt=d.get("created_at")
if isinstance(crt, str) and crt:
  d["created_at"]=crt[:10]
print(json.dumps(d, ensure_ascii=False, indent=2))
PY
  fi
  hr
  pause
}

quota_edit_flow() {
  # args: view_no (1-based pada halaman aktif)
  local view_no="$1"

  [[ "${view_no}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
  local total page pages start end rows
  total="${#QUOTA_VIEW_INDEXES[@]}"
  if (( total <= 0 )); then
    warn "Tidak ada data"
    pause
    return 0
  fi
  page="${QUOTA_PAGE:-0}"
  pages=$(( (total + QUOTA_PAGE_SIZE - 1) / QUOTA_PAGE_SIZE ))
  if (( page < 0 )); then page=0; fi
  if (( pages > 0 && page >= pages )); then page=$((pages - 1)); fi
  start=$((page * QUOTA_PAGE_SIZE))
  end=$((start + QUOTA_PAGE_SIZE))
  if (( end > total )); then end="${total}"; fi
  rows=$((end - start))

  if (( view_no < 1 || view_no > rows )); then
    warn "NO di luar range"
    pause
    return 0
  fi

  local list_pos real_idx qf proto
  list_pos=$((start + view_no - 1))
  real_idx="${QUOTA_VIEW_INDEXES[$list_pos]}"
  qf="${QUOTA_FILES[$real_idx]}"
  proto="${QUOTA_FILE_PROTOS[$real_idx]}"

  while true; do
    title
    echo "Quota & Access Control > Detail"
    hr
    echo "Proto : ${proto}"
    echo "File  : ${qf}"
    hr

    local fields username ql_disp qu_disp exp_date ip_state ip_lim block_reason speed_state speed_down speed_up
    fields="$(quota_read_detail_fields "${qf}")"
    IFS='|' read -r username ql_disp qu_disp exp_date ip_state ip_lim block_reason speed_state speed_down speed_up <<<"${fields}"

    # Normalisasi username ke format email (username@proto) untuk routing calls.
    # Metadata lama mungkin hanya menyimpan "alice", bukan "alice@vless".
    local email_for_routing="${username}"
    if [[ "${email_for_routing}" != *"@"* ]]; then
      email_for_routing="${email_for_routing}@${proto}"
    fi
    local speed_username="${username}"
    if [[ "${speed_username}" == *"@"* ]]; then
      speed_username="${speed_username%%@*}"
    fi

    local label_w=14
    printf "%-${label_w}s : %s\n" "Username" "${username}"
    printf "%-${label_w}s : %s\n" "Quota Limit" "${ql_disp}"
    printf "%-${label_w}s : %s\n" "Quota Used" "${qu_disp}"
    printf "%-${label_w}s : %s\n" "Expired At" "${exp_date}"
    printf "%-${label_w}s : %s\n" "IP Limit" "${ip_state}"
    printf "%-${label_w}s : %s\n" "Block Reason" "${block_reason}"
    printf "%-${label_w}s : %s\n" "IP Limit Max" "${ip_lim}"
    printf "%-${label_w}s : %s Mbps\n" "Speed Download" "${speed_down}"
    printf "%-${label_w}s : %s Mbps\n" "Speed Upload" "${speed_up}"
    printf "%-${label_w}s : %s\n" "Speed Limit" "${speed_state}"
    hr

    echo "  1) View JSON"
    echo "  2) Set Quota Limit (GB)"
    echo "  3) Reset Quota Used (set 0)"
    echo "  4) Manual Block/Unblock (toggle)"
    echo "  5) IP Limit Enable/Disable (toggle)"
    echo "  6) Set IP Limit (angka)"
    echo "  7) Unlock IP Lock"
    echo "  8) Set Speed Download (Mbps)"
    echo "  9) Set Speed Upload (Mbps)"
    echo " 10) Speed Limit Enable/Disable (toggle)"
    echo "  0) Back (kembali)"
    hr
    read -r -p "Pilih: " c
    if is_back_choice "${c}"; then
      return 0
    fi

    case "${c}" in
      1)
        quota_view_json "${qf}"
        ;;
      2)
        read -r -p "Quota Limit (GB) (atau kembali): " gb
        if is_back_choice "${gb}"; then
          continue
        fi
        if [[ -z "${gb}" ]]; then
          warn "Quota kosong"
          pause
          continue
        fi
        local gb_num qb
        gb_num="$(normalize_gb_input "${gb}")"
        if [[ -z "${gb_num}" ]]; then
          warn "Format quota tidak valid. Contoh: 5 atau 5GB"
          pause
          continue
        fi
        qb="$(bytes_from_gb "${gb_num}")"
        quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); d['quota_limit']=int(${qb}); now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('manual' if mb else ('quota' if qe else ('ip_limit' if il else ''))); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
        log "Quota limit diubah: ${gb_num} GB"
        pause
        ;;
      3)
        # BUG-06 fix: read mb/il BEFORE resetting qe so lock_reason is computed correctly.
        # BUG-05 fix: correct priority quota > ip_limit.
        quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); mb=bool(st.get('manual_block')); il=bool(st.get('ip_limit_locked')); d['quota_used']=0; st['quota_exhausted']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('manual' if mb else ('ip_limit' if il else '')); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
        xray_routing_set_user_in_marker "dummy-quota-user" "${email_for_routing}" off
        log "Quota used di-reset: 0 (status quota dibersihkan)"
        pause
        ;;
      4)
        local st_mb
        st_mb="$(quota_get_status_bool "${qf}" "manual_block")"
        if [[ "${st_mb}" == "true" ]]; then
          # BUG-06 fix: evaluate qe/il BEFORE setting manual_block=False.
          # Previously mb was read AFTER being set to False, so it was always False
          # and lock_reason could never be 'manual' in this branch.
          # BUG-05 fix applied here too: correct priority is quota > ip_limit (not reversed).
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); st['manual_block']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('quota' if qe else ('ip_limit' if il else '')); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
          xray_routing_set_user_in_marker "dummy-block-user" "${email_for_routing}" off
          log "Manual block: OFF"
        else
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); st['manual_block']=True; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); st['lock_reason']='manual'; st['locked_at']=st.get('locked_at') or now"
          xray_routing_set_user_in_marker "dummy-block-user" "${email_for_routing}" on
          log "Manual block: ON"
        fi
        pause
        ;;
      5)
        local ip_on
        ip_on="$(quota_get_status_bool "${qf}" "ip_limit_enabled")"
        if [[ "${ip_on}" == "true" ]]; then
          # BUG-06 fix: read il BEFORE resetting ip_limit_locked, then determine lock_reason.
          # BUG-05 fix: correct priority is quota > ip_limit.
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); st['ip_limit_enabled']=False; st['ip_limit_locked']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('manual' if mb else ('quota' if qe else '')); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
          xray_routing_set_user_in_marker "dummy-limit-user" "${email_for_routing}" off
          svc_restart_any xray-limit-ip xray-limit >/dev/null 2>&1 || true
          log "IP limit: OFF"
        else
          quota_atomic_update_file "${qf}" "st=d.setdefault('status',{}); st['ip_limit_enabled']=True"
          svc_restart_any xray-limit-ip xray-limit >/dev/null 2>&1 || true
          log "IP limit: ON"
        fi
        pause
        ;;
      6)
        read -r -p "IP Limit (angka) (atau kembali): " lim
        if is_back_choice "${lim}"; then
          continue
        fi
        if [[ -z "${lim}" || ! "${lim}" =~ ^[0-9]+$ || "${lim}" -le 0 ]]; then
          warn "IP limit harus angka > 0"
          pause
          continue
        fi
        quota_atomic_update_file "${qf}" "d.setdefault('status',{}); d['status']['ip_limit']=int(${lim})"
        svc_restart_any xray-limit-ip xray-limit >/dev/null 2>&1 || true
        log "IP limit diubah: ${lim}"
        pause
        ;;
      7)
        /usr/local/bin/limit-ip unlock "${email_for_routing}" >/dev/null 2>&1 || true
        # BUG-06 fix: read il BEFORE resetting, evaluate lock_reason correctly after.
        # BUG-05 fix: correct priority quota > ip_limit.
        quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); st['ip_limit_locked']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); lr=('manual' if mb else ('quota' if qe else '')); st['lock_reason']=lr; st['locked_at']=(st.get('locked_at') or now) if lr else ''"
        svc_restart_any xray-limit-ip xray-limit >/dev/null 2>&1 || true
        log "IP lock di-unlock"
        pause
        ;;
      8)
        read -r -p "Speed Download (Mbps) (contoh: 20 atau 20mbit) (atau kembali): " speed_down_input
        if is_back_choice "${speed_down_input}"; then
          continue
        fi
        speed_down_input="$(normalize_speed_mbit_input "${speed_down_input}")"
        if [[ -z "${speed_down_input}" ]] || ! speed_mbit_is_positive "${speed_down_input}"; then
          warn "Speed download tidak valid. Gunakan angka > 0, contoh: 20 atau 20mbit"
          pause
          continue
        fi
        quota_atomic_update_file "${qf}" "st=d.setdefault('status',{}); st['speed_down_mbit']=float(${speed_down_input})"
        if [[ "$(quota_get_status_bool "${qf}" "speed_limit_enabled")" == "true" ]]; then
          quota_sync_speed_policy_for_user "${proto}" "${speed_username}" "${qf}" || true
        fi
        log "Speed download diubah: ${speed_down_input} Mbps"
        pause
        ;;
      9)
        read -r -p "Speed Upload (Mbps) (contoh: 10 atau 10mbit) (atau kembali): " speed_up_input
        if is_back_choice "${speed_up_input}"; then
          continue
        fi
        speed_up_input="$(normalize_speed_mbit_input "${speed_up_input}")"
        if [[ -z "${speed_up_input}" ]] || ! speed_mbit_is_positive "${speed_up_input}"; then
          warn "Speed upload tidak valid. Gunakan angka > 0, contoh: 10 atau 10mbit"
          pause
          continue
        fi
        quota_atomic_update_file "${qf}" "st=d.setdefault('status',{}); st['speed_up_mbit']=float(${speed_up_input})"
        if [[ "$(quota_get_status_bool "${qf}" "speed_limit_enabled")" == "true" ]]; then
          quota_sync_speed_policy_for_user "${proto}" "${speed_username}" "${qf}" || true
        fi
        log "Speed upload diubah: ${speed_up_input} Mbps"
        pause
        ;;
      10)
        local speed_on speed_down_now speed_up_now
        speed_on="$(quota_get_status_bool "${qf}" "speed_limit_enabled")"
        if [[ "${speed_on}" == "true" ]]; then
          quota_atomic_update_file "${qf}" "st=d.setdefault('status',{}); st['speed_limit_enabled']=False"
          quota_sync_speed_policy_for_user "${proto}" "${speed_username}" "${qf}" || true
          log "Speed limit: OFF"
          pause
          continue
        fi

        speed_down_now="$(quota_get_status_number "${qf}" "speed_down_mbit")"
        speed_up_now="$(quota_get_status_number "${qf}" "speed_up_mbit")"

        if ! speed_mbit_is_positive "${speed_down_now}"; then
          read -r -p "Speed Download (Mbps) (contoh: 20 atau 20mbit): " speed_down_now
          speed_down_now="$(normalize_speed_mbit_input "${speed_down_now}")"
          if [[ -z "${speed_down_now}" ]] || ! speed_mbit_is_positive "${speed_down_now}"; then
            warn "Speed download tidak valid. Speed limit tetap OFF."
            pause
            continue
          fi
        fi
        if ! speed_mbit_is_positive "${speed_up_now}"; then
          read -r -p "Speed Upload (Mbps) (contoh: 10 atau 10mbit): " speed_up_now
          speed_up_now="$(normalize_speed_mbit_input "${speed_up_now}")"
          if [[ -z "${speed_up_now}" ]] || ! speed_mbit_is_positive "${speed_up_now}"; then
            warn "Speed upload tidak valid. Speed limit tetap OFF."
            pause
            continue
          fi
        fi

        quota_atomic_update_file "${qf}" "st=d.setdefault('status',{}); st['speed_down_mbit']=float(${speed_down_now}); st['speed_up_mbit']=float(${speed_up_now}); st['speed_limit_enabled']=True"
        quota_sync_speed_policy_for_user "${proto}" "${speed_username}" "${qf}" || true
        log "Speed limit: ON"
        pause
        ;;
      *)
        warn "Pilihan tidak valid"
        sleep 1
        ;;
    esac
  done
}

quota_menu() {
  # Minimal: list + search + pagination + view/edit metadata JSON
  ensure_account_quota_dirs
  need_python3

  QUOTA_PAGE=0
  QUOTA_QUERY=""

  while true; do
    title
    echo "3) Quota & Access Control"
    hr

    quota_collect_files
    quota_build_view_indexes
    quota_print_table_page "${QUOTA_PAGE}"
    hr

    echo "Masukkan NO untuk view/edit, atau ketik:"
    echo "  search) filter username"
    echo "  clear) hapus filter"
    echo "  next / previous"
    echo "  kembali) Back"
    hr
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      break
    fi

    case "${c}" in
      next|n)
        local pages
        pages="$(quota_total_pages_for_indexes)"
        if (( pages > 0 && QUOTA_PAGE < pages - 1 )); then
          QUOTA_PAGE=$((QUOTA_PAGE + 1))
        fi
        ;;
      previous|p|prev)
        if (( QUOTA_PAGE > 0 )); then
          QUOTA_PAGE=$((QUOTA_PAGE - 1))
        fi
        ;;
      search)
        read -r -p "Search username (atau kembali): " q
        if is_back_choice "${q}"; then
          continue
        fi
        QUOTA_QUERY="${q}"
        QUOTA_PAGE=0
        ;;
      clear)
        QUOTA_QUERY=""
        QUOTA_PAGE=0
        ;;
      *)
        if [[ "${c}" =~ ^[0-9]+$ ]]; then
          quota_edit_flow "${c}"
        else
          warn "Pilihan tidak valid"
          sleep 1
        fi
        ;;
    esac
  done
}

# -------------------------
# Network Controls
# - Egress mode: direct / warp / balancer
# - Balancer: tag "egress-balance"
# - Observatory: conf.d/60-observatory.json (untuk leastPing/leastLoad)
# - WARP: global / per-user / per-protocol (inbound)
# - Domain/Geosite: direct exceptions (editable list, template tetap readonly)
# -------------------------
warp_status() {
  title
  echo "WARP (wireproxy) status"
  hr
  if svc_exists wireproxy; then
    systemctl status wireproxy --no-pager || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  pause
}

network_state_file() {
  echo "${WORK_DIR}/network_state.json"
}

network_state_get() {
  # args: key
  local key="$1"
  local f
  f="$(network_state_file)"
  if [[ ! -f "${f}" ]]; then
    return 0
  fi
  python3 - <<'PY' "${f}" "${key}" 2>/dev/null || true
import json, sys
path, key = sys.argv[1:3]
try:
  with open(path,'r',encoding='utf-8') as f:
    d=json.load(f)
except Exception:
  d={}
v=d.get(key)
if v is None:
  raise SystemExit(0)
print(v)
PY
}

network_state_set() {
  # args: key value
  local key="$1"
  local val="$2"
  local f tmp
  f="$(network_state_file)"
  tmp="${WORK_DIR}/network_state.json.tmp"
  need_python3
  python3 - <<'PY' "${f}" "${tmp}" "${key}" "${val}"
import json, os, sys
path, tmp, key, val = sys.argv[1:5]
d={}
try:
  if os.path.exists(path):
    with open(path,'r',encoding='utf-8') as f:
      d=json.load(f) or {}
except Exception:
  d={}
d[key]=val
with open(tmp,'w',encoding='utf-8') as f:
  json.dump(d,f,ensure_ascii=False,indent=2)
  f.write("\n")
os.replace(tmp, path)
PY
  chmod 600 "${f}" 2>/dev/null || true
}

validate_email_user() {
  # args: email (username@protocol)
  local email="${1:-}"
  [[ "${email}" =~ ^[A-Za-z0-9._-]+@(vless|vmess|trojan)$ ]]
}

is_default_xray_email_or_tag() {
  # Default/bawaan Xray (disembunyikan dari menu WARP per-user):
  # default@(vless|vmess|trojan)-(ws|hup|grpc)
  local s="${1:-}"
  [[ "${s}" =~ ^default@(vless|vmess|trojan)-(ws|hup|grpc)$ ]]
}

is_readonly_geosite_domain() {
  # Geosite ini readonly (jangan disentuh), tampilkan di menu tapi jangan diubah:
  # apple, meta, google, openai, spotify, netflix, reddit
  local ent="${1:-}"
  case "${ent}" in
    geosite:apple|geosite:meta|geosite:google|geosite:openai|geosite:spotify|geosite:netflix|geosite:reddit)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

xray_routing_readonly_geosite_rule_print() {
  # Menampilkan rule geosite template (readonly) dari 30-routing.json
  # Rule ini dibuat oleh setup_modular.sh dan TIDAK boleh diedit dari menu.
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys

src=sys.argv[1]
targets=[
  "geosite:apple",
  "geosite:meta",
  "geosite:google",
  "geosite:openai",
  "geosite:spotify",
  "geosite:netflix",
  "geosite:reddit",
]
tset=set(targets)

try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

rules=((cfg.get("routing") or {}).get("rules") or [])
found=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get("type") != "field":
    continue
  dom=r.get("domain") or []
  if not isinstance(dom, list):
    continue
  if any(isinstance(x,str) and x in tset for x in dom):
    found=r
    break

if not found:
  print("  (rule readonly geosite tidak ditemukan)")
  raise SystemExit(0)

out="-"
if isinstance(found.get("outboundTag"), str) and found.get("outboundTag"):
  out=found.get("outboundTag")
elif isinstance(found.get("balancerTag"), str) and found.get("balancerTag"):
  out="balancer:" + found.get("balancerTag")

print(f"OutboundTag : {out} (readonly)")
dom=found.get("domain") or []
for i, x in enumerate(targets, start=1):
  if x in dom:
    print(f"  {i:>2}. {x}")
PY
}


xray_routing_default_rule_get() {
  # prints: mode=<direct|warp|balancer|unknown> tag=<tag-or-empty> balancer=<balancerTag-or-empty>
  need_python3
  python3 - <<'PY' "${XRAY_ROUTING_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules') or []
mode='unknown'
tag=''
bal=''
def is_default_rule(r):
  if not isinstance(r, dict):
    return False
  if r.get('type') != 'field':
    return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'):
    return False
  # Heuristic: default catch-all has only port + outboundTag/balancerTag
  return True

target=None
for r in rules:
  if is_default_rule(r):
    target=r
# pick last matching
if isinstance(target, dict):
  if 'balancerTag' in target and isinstance(target.get('balancerTag'), str) and target.get('balancerTag'):
    mode='balancer'
    bal=target.get('balancerTag','')
  else:
    ot=target.get('outboundTag')
    if isinstance(ot, str) and ot:
      tag=ot
      if ot == 'warp':
        mode='warp'
      elif ot == 'direct':
        mode='direct'
      else:
        mode='unknown'
print(f"mode={mode}")
print(f"tag={tag}")
print(f"balancer={bal}")
PY
}

xray_routing_default_rule_set() {
  # args: mode direct|warp|balancer
  local mode="$1"
  local tmp backup
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OUTBOUNDS_CONF}" "${tmp}" "${mode}" "${SPEED_OUTBOUND_TAG_PREFIX}"
import json, sys
src, ob_src, dst, mode, speed_out_prefix = sys.argv[1:6]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)

routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    idx=i

if idx is None:
  raise SystemExit("Default rule (port 1-65535) tidak ditemukan")

try:
  with open(ob_src,'r',encoding='utf-8') as f:
    ob_cfg=json.load(f)
except Exception:
  ob_cfg={}

def list_outbound_tags():
  out=[]
  seen=set()
  for o in (ob_cfg.get('outbounds') or []):
    if not isinstance(o, dict):
      continue
    t=o.get('tag')
    if not isinstance(t, str):
      continue
    t=t.strip()
    if not t or t in seen:
      continue
    seen.add(t)
    out.append(t)
  return out

def pick_default_selector(tags):
  deny={"api","blocked"}
  sel=[]
  for t in ("direct","warp"):
    if t in tags and t not in sel:
      sel.append(t)
  if not sel:
    for t in tags:
      if t in deny:
        continue
      if speed_out_prefix and isinstance(t, str) and t.startswith(speed_out_prefix):
        continue
      if t in sel:
        continue
      sel.append(t)
      if len(sel) >= 2:
        break
  return sel

r=rules[idx]
if mode == 'direct':
  r.pop('balancerTag', None)
  r['outboundTag']='direct'
elif mode == 'warp':
  r.pop('balancerTag', None)
  r['outboundTag']='warp'
elif mode == 'balancer':
  tags=list_outbound_tags()
  balancers=routing.get('balancers')
  if not isinstance(balancers, list):
    balancers=[]

  b=None
  for it in balancers:
    if isinstance(it, dict) and it.get('tag') == 'egress-balance':
      b=it
      break

  if b is None:
    b={"tag":"egress-balance","selector":[],"strategy":{"type":"random"}}
    balancers.insert(0,b)

  raw_sel=b.get('selector')
  if not isinstance(raw_sel, list):
    raw_sel=[]

  deny={"api","blocked"}
  valid_sel=[]
  seen=set()
  for t in raw_sel:
    if not isinstance(t, str):
      continue
    t=t.strip()
    if not t:
      continue
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t not in tags:
      continue
    if t in seen:
      continue
    seen.add(t)
    valid_sel.append(t)

  if not valid_sel:
    valid_sel=pick_default_selector(tags)
  if not valid_sel:
    raise SystemExit("Tidak ada outbound valid untuk balancer egress-balance.")

  b['selector']=valid_sel
  st=b.get('strategy')
  if not isinstance(st, dict):
    st={}
  if not isinstance(st.get('type'), str) or not st.get('type'):
    st['type']='random'
  b['strategy']=st
  routing['balancers']=balancers

  r.pop('outboundTag', None)
  r['balancerTag']='egress-balance'
else:
  raise SystemExit("Mode tidak dikenal: " + mode)

rules[idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update routing (rollback ke backup: ${backup})"
  }

  if ! xray_confdir_syntax_test; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Konfigurasi xray invalid setelah update routing default. Config di-rollback ke backup: ${backup}"
  fi

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update routing default. Config di-rollback ke backup: ${backup}"
  fi

  speed_policy_resync_after_egress_change || return 1
}

xray_routing_balancer_get() {
  # prints: strategy=<type> selector=<comma-separated>
  need_python3
  python3 - <<'PY' "${XRAY_ROUTING_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
balancers=routing.get('balancers') or []
b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if not isinstance(b, dict):
  print("strategy=")
  print("selector=")
  raise SystemExit(0)
st=(b.get('strategy') or {})
stype=st.get('type') if isinstance(st, dict) else ''
sel=b.get('selector') or []
if not isinstance(sel, list):
  sel=[]
sel=[str(x) for x in sel if str(x).strip()]
print("strategy=" + (str(stype) if stype is not None else ""))
print("selector=" + ",".join(sel))
PY
}

xray_routing_balancer_set_strategy() {
  # args: strategy type
  local stype="$1"
  local tmp backup
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${stype}"
import json, sys
src, dst, stype = sys.argv[1:4]
allowed={"random","roundRobin","leastPing","leastLoad"}
if stype not in allowed:
  raise SystemExit("Strategy invalid. Pilihan: " + ", ".join(sorted(allowed)))

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
balancers=routing.get('balancers')
if not isinstance(balancers, list):
  balancers=[]

b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if b is None:
  b={"tag":"egress-balance","selector":["direct","warp"],"strategy":{"type":"random"}}
  balancers.insert(0,b)

b.setdefault('strategy', {})
if not isinstance(b['strategy'], dict):
  b['strategy']={}
b['strategy']['type']=stype

routing['balancers']=balancers
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update balancer (rollback ke backup: ${backup})"
  }

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update balancer strategy. Config di-rollback ke backup: ${backup}"
  fi

  speed_policy_resync_after_egress_change || return 1
}

xray_routing_balancer_set_selector_from_outbounds() {
  # args: comma-separated or "auto"
  local mode="${1:-auto}"
  local tmp backup
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  [[ -f "${XRAY_OUTBOUNDS_CONF}" ]] || die "Xray outbounds conf tidak ditemukan: ${XRAY_OUTBOUNDS_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OUTBOUNDS_CONF}" "${tmp}" "${mode}" "${SPEED_OUTBOUND_TAG_PREFIX}"
import json, sys
rt_src, ob_src, dst, mode, speed_out_prefix = sys.argv[1:6]
with open(rt_src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
with open(ob_src,'r',encoding='utf-8') as f:
  ob=json.load(f)

def list_outbound_tags():
  out=[]
  for o in (ob.get('outbounds') or []):
    if not isinstance(o, dict):
      continue
    tag=o.get('tag')
    if isinstance(tag, str) and tag.strip():
      out.append(tag.strip())
  return out

routing=(cfg.get('routing') or {})
balancers=routing.get('balancers')
if not isinstance(balancers, list):
  balancers=[]
b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if b is None:
  b={"tag":"egress-balance","selector":["direct","warp"],"strategy":{"type":"random"}}
  balancers.insert(0,b)

sel=[]
if mode == 'auto':
  tags=list_outbound_tags()
  # Exclude internal/system tags
  deny={"api","blocked"}
  seen=set()
  for t in tags:
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t in seen:
      continue
    seen.add(t)
    sel.append(t)
else:
  deny={"api","blocked"}
  known=set(list_outbound_tags())
  seen=set()
  for x in mode.split(","):
    t=x.strip()
    if not t:
      continue
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t not in known:
      continue
    if t in seen:
      continue
    seen.add(t)
    sel.append(t)

if not sel:
  raise SystemExit("Selector kosong. Gunakan auto atau isi tag outbound valid non-speed dipisah koma.")

b['selector']=sel
routing['balancers']=balancers
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update selector balancer (rollback ke backup: ${backup})"
  }

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update balancer selector. Config di-rollback ke backup: ${backup}"
  fi

  speed_policy_resync_after_egress_change || return 1
}

xray_observatory_get() {
  # prints: probeURL=... interval=... concurrency=true|false subjectSelector=comma-separated
  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    echo "probeURL="
    echo "interval="
    echo "concurrency="
    echo "subjectSelector="
    return 0
  fi
  need_python3
  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
obs=cfg.get('observatory') or {}
if not isinstance(obs, dict):
  obs={}
probe=obs.get('probeURL') or obs.get('probeUrl') or ''
interval=obs.get('probeInterval') or ''
con=obs.get('enableConcurrency')
sub=obs.get('subjectSelector') or []
if not isinstance(sub, list):
  sub=[]
sub=[str(x) for x in sub if str(x).strip()]
print("probeURL=" + str(probe))
print("interval=" + str(interval))
print("concurrency=" + ("true" if bool(con) else "false"))
print("subjectSelector=" + ",".join(sub))
PY
}

xray_observatory_set_basic() {
  # args: probeURL interval enableConcurrency(true/false)
  local probe="$1"
  local interval="$2"
  local conc="$3"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    # Create empty file with safe perms
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_config "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${probe}" "${interval}" "${conc}"
import json, sys
src, dst, probe, interval, conc = sys.argv[1:6]
conc = str(conc).lower() in ("1","true","yes","y","on")
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f) if f.readable() else {}
if not isinstance(cfg, dict):
  cfg={}
obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}
if probe.strip():
  obs['probeURL']=probe.strip()
if interval.strip():
  obs['probeInterval']=interval.strip()
obs['enableConcurrency']=bool(conc)
if 'subjectSelector' not in obs:
  obs['subjectSelector']=[]
cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_OBSERVATORY_CONF}"
    die "Gagal update observatory (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_OBSERVATORY_CONF}" "${backup}" "observatory"
}


xray_observatory_set_probe_url() {
  # args: probeURL
  local probe="$1"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_config "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${probe}"
import json, sys
src, dst, probe = sys.argv[1:4]
probe = str(probe).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

if probe:
  obs['probeURL']=probe

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_OBSERVATORY_CONF}"
    die "Gagal update probeURL (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_OBSERVATORY_CONF}" "${backup}" "observatory probeURL"
}

xray_observatory_set_interval() {
  # args: interval (contoh: 30s / 10m)
  local interval="$1"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_config "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${interval}"
import json, sys
src, dst, interval = sys.argv[1:4]
interval = str(interval).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

if interval:
  obs['probeInterval']=interval

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_OBSERVATORY_CONF}"
    die "Gagal update interval (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_OBSERVATORY_CONF}" "${backup}" "observatory interval"
}

xray_observatory_toggle_concurrency() {
  local tmp backup
  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_config "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}"
import json, sys
src, dst = sys.argv[1:3]

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

cur=bool(obs.get('enableConcurrency'))
obs['enableConcurrency']=not cur

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_OBSERVATORY_CONF}"
    die "Gagal toggle concurrency (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_OBSERVATORY_CONF}" "${backup}" "observatory concurrency"
}

xray_observatory_sync_subject_selector_from_balancer() {
  local tmp backup
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_config "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OBSERVATORY_CONF}" "${tmp}"
import json, sys
rt, obs_src, dst = sys.argv[1:4]
with open(rt,'r',encoding='utf-8') as f:
  rt_cfg=json.load(f)
routing=(rt_cfg.get('routing') or {})
balancers=routing.get('balancers') or []
sel=[]
for b in balancers:
  if isinstance(b, dict) and b.get('tag') == 'egress-balance':
    s=b.get('selector') or []
    if isinstance(s, list):
      sel=[str(x) for x in s if str(x).strip()]
    break

with open(obs_src,'r',encoding='utf-8') as f:
  cfg=json.load(f) if f.readable() else {}
if not isinstance(cfg, dict):
  cfg={}
obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}
obs['subjectSelector']=sel
cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_OBSERVATORY_CONF}"
    die "Gagal sync subjectSelector (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_OBSERVATORY_CONF}" "${backup}" "observatory subjectSelector"
}

xray_routing_rule_toggle_user_outbound() {
  # args: marker outboundTag email on|off
  local marker="$1"
  local outbound="$2"
  local email="$3"
  local onoff="$4"
  local tmp backup

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${marker}" "${outbound}" "${email}" "${onoff}"
import json, sys
src, dst, marker, outbound, email, onoff = sys.argv[1:7]
enable = (onoff.lower() == 'on')

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

default_idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    default_idx=i

if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan, tidak bisa insert rule baru")

rule_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type') != 'field': continue
  if r.get('outboundTag') != outbound: continue
  u=r.get('user') or []
  # BUG-13 fix: explicitly require rule has a 'user' field (not 'inboundTag').
  # Without this check, a per-inbound rule with the same outboundTag could be
  # mistakenly matched and modified when looking for a per-user rule.
  if not isinstance(u, list) or 'inboundTag' in r:
    continue
  if marker in u:
    rule_idx=i
    break

if rule_idx is None:
  # Insert before default rule
  newr={"type":"field","user":[marker],"outboundTag":outbound}
  rules.insert(default_idx, newr)
  rule_idx=default_idx

r=rules[rule_idx]
u=r.get('user') or []
if not isinstance(u, list):
  u=[]
# Ensure marker is first
u=[x for x in u if x != marker]
u.insert(0, marker)

if enable:
  if email not in u:
    u.append(email)
else:
  u=[x for x in u if x != email]
  # Keep marker only

r['user']=u
rules[rule_idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update routing (rollback ke backup: ${backup})"
  }

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update routing per-user warp/direct. Config di-rollback ke backup: ${backup}"
  fi
}

xray_routing_rule_toggle_inbounds_outbound() {
  # args: marker outboundTag comma_inboundTags on|off
  local marker="$1"
  local outbound="$2"
  local tags_csv="$3"
  local onoff="$4"
  local tmp backup

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${marker}" "${outbound}" "${tags_csv}" "${onoff}"
import json, sys
src, dst, marker, outbound, tags_csv, onoff = sys.argv[1:7]
enable = (onoff.lower() == 'on')
tags=[t.strip() for t in tags_csv.split(",") if t.strip()]

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

default_idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    default_idx=i
if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan, tidak bisa insert rule baru")

rule_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type') != 'field': continue
  if r.get('outboundTag') != outbound: continue
  ib=r.get('inboundTag') or []
  if isinstance(ib, list) and marker in ib:
    rule_idx=i
    break

if rule_idx is None:
  newr={"type":"field","inboundTag":[marker],"outboundTag":outbound}
  rules.insert(default_idx, newr)
  rule_idx=default_idx

r=rules[rule_idx]
ib=r.get('inboundTag') or []
if not isinstance(ib, list):
  ib=[]
# Ensure marker first
ib=[x for x in ib if x != marker]
ib.insert(0, marker)

if enable:
  for t in tags:
    if t not in ib:
      ib.append(t)
else:
  ib=[x for x in ib if x not in tags]
  # Keep marker only

r['inboundTag']=ib
rules[rule_idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update routing (rollback ke backup: ${backup})"
  }

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update routing per-inbound warp/direct. Config di-rollback ke backup: ${backup}"
  fi
}

xray_list_inbounds_tags_by_protocol() {
  # args: proto
  local proto="$1"
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${proto}"
import json, sys
src, proto = sys.argv[1:3]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
tags=[]
for ib in cfg.get('inbounds', []) or []:
  if not isinstance(ib, dict):
    continue
  if ib.get('protocol') != proto:
    continue
  tag=ib.get('tag')
  if isinstance(tag, str) and tag.strip():
    tags.append(tag.strip())
print(",".join(tags))
PY
}

xray_inbounds_all_tags_get() {
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
tags=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  tag=ib.get('tag')
  if isinstance(tag, str) and tag.strip():
    tags.add(tag.strip())
for t in sorted(tags):
  print(t)
PY
}


network_show_summary() {
  title
  echo "Network / Proxy Summary"
  hr

  if [[ -f "${XRAY_ROUTING_CONF}" ]]; then
    xray_routing_default_rule_get
    hr
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get
    hr
  else
    warn "Routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  fi

  echo "Observatory:"
  xray_observatory_get
  hr

  if svc_exists wireproxy; then
    echo "$(svc_status_line wireproxy)"
  else
    echo "wireproxy: (tidak terpasang)"
  fi
  hr
  pause
}

egress_menu() {
  while true; do
    title
    echo "4) Network Controls > Egress Mode & Balancer"
    hr
    xray_routing_default_rule_get || true
    echo ""
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get || true
    echo ""
    echo "Observatory:"
    xray_observatory_get || true
    hr

    echo "  1) Set default egress: DIRECT"
    echo "  2) Set default egress: WARP"
    echo "  3) Set default egress: BALANCER (egress-balance)"
    echo "  4) Set balancer strategy (random/roundRobin/leastPing/leastLoad)"
    echo "  5) Set balancer selector (auto dari outbounds)"
    echo "  6) Set balancer selector (manual: tag1,tag2,...)"
    echo "  7) Observatory: set probeURL/interval/concurrency"
    echo "  8) Observatory: sync subjectSelector dari balancer selector"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) xray_routing_default_rule_set direct ; log "Default egress: DIRECT" ; pause ;;
      2) xray_routing_default_rule_set warp ; log "Default egress: WARP" ; pause ;;
      3) xray_routing_default_rule_set balancer ; log "Default egress: BALANCER" ; pause ;;
      4)
        read -r -p "Strategy (random/roundRobin/leastPing/leastLoad) (atau kembali): " st
        if is_back_choice "${st}"; then
          continue
        fi
        xray_routing_balancer_set_strategy "${st}"
        log "Balancer strategy updated: ${st}"
        pause
        ;;
      5)
        xray_routing_balancer_set_selector_from_outbounds auto
        log "Balancer selector di-set: auto"
        pause
        ;;
      6)
        read -r -p "Selector tags (tag1,tag2,...) (atau kembali): " sel
        if is_back_choice "${sel}"; then
          continue
        fi
        xray_routing_balancer_set_selector_from_outbounds "${sel}"
        log "Balancer selector updated"
        pause
        ;;
      7)
        read -r -p "probeURL (contoh https://www.google.com/generate_204) (atau kembali): " purl
        if is_back_choice "${purl}"; then
          continue
        fi
        read -r -p "probeInterval (contoh 30s) (atau kembali): " pint
        if is_back_choice "${pint}"; then
          continue
        fi
        read -r -p "enableConcurrency (true/false) (atau kembali): " pcon
        if is_back_choice "${pcon}"; then
          continue
        fi
        xray_observatory_set_basic "${purl}" "${pint}" "${pcon}"
        log "Observatory updated"
        pause
        ;;
      8)
        xray_observatory_sync_subject_selector_from_balancer
        log "Observatory subjectSelector disinkronkan"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}


# -------------------------
# Egress Mode & Balancer (revisi menu sederhana)
# -------------------------
egress_show_detailed_status() {
  title
  echo "Egress Detailed Status"
  hr
  if [[ -f "${XRAY_ROUTING_CONF}" ]]; then
    xray_routing_default_rule_get || true
    hr
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get || true
    hr
  else
    warn "Routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
    hr
  fi

  echo "Observatory:"
  xray_observatory_get || true
  hr
  pause
}

egress_set_mode_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Set Egress Mode"
    hr
    printf "Current Egress Mode: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) DIRECT"
    echo "  2) WARP"
    echo "  3) BALANCER"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        xray_routing_default_rule_set direct
        log "Egress Mode di-set: DIRECT"
        pause
        ;;
      2)
        xray_routing_default_rule_set warp
        log "Egress Mode di-set: WARP"
        pause
        ;;
      3)
        xray_routing_default_rule_set balancer
        log "Egress Mode di-set: BALANCER (egress-balance)"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_balancer_settings_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Balancer Settings (egress-balance)"
    hr
    xray_routing_balancer_get || true
    hr
    echo "  1) Set Strategy"
    echo "  2) Set Selector (auto)"
    echo "  3) Set Selector (manual)"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Strategy (random/roundRobin/leastPing/leastLoad) (atau kembali): " st
        if is_back_choice "${st}"; then
          continue
        fi
        case "${st}" in
          random|roundRobin|leastPing|leastLoad)
            xray_routing_balancer_set_strategy "${st}"
            log "Balancer strategy updated: ${st}"
            pause
            ;;
          *)
            warn "Strategy tidak valid"
            pause
            ;;
        esac
        ;;
      2)
        xray_routing_balancer_set_selector_from_outbounds auto
        log "Balancer selector di-set: auto"
        pause
        ;;
      3)
        read -r -p "Selector tags (tag1,tag2,...) (atau kembali): " sel
        if is_back_choice "${sel}"; then
          continue
        fi
        xray_routing_balancer_set_selector_from_outbounds "${sel}"
        log "Balancer selector updated"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_observatory_settings_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Observatory Settings"
    hr

    local probe interval conc subj
    probe="$(xray_observatory_get | awk -F'=' '/^probeURL=/{print $2; exit}' 2>/dev/null || true)"
    interval="$(xray_observatory_get | awk -F'=' '/^interval=/{print $2; exit}' 2>/dev/null || true)"
    conc="$(xray_observatory_get | awk -F'=' '/^concurrency=/{print $2; exit}' 2>/dev/null || true)"
    subj="$(xray_observatory_get | awk -F'=' '/^subjectSelector=/{print $2; exit}' 2>/dev/null || true)"

    echo "probeURL        : ${probe}"
    echo "interval        : ${interval}"
    echo "concurrency     : ${conc}"
    echo "subjectSelector : ${subj}"
    hr

    echo "  1) Set probeURL"
    echo "  2) Set interval"
    echo "  3) Toggle concurrency"
    echo "  4) Sync subjectSelector from balancer"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "probeURL (contoh https://www.google.com/generate_204) (atau kembali): " purl
        if is_back_choice "${purl}"; then
          continue
        fi
        xray_observatory_set_probe_url "${purl}"
        log "probeURL updated"
        pause
        ;;
      2)
        read -r -p "interval (contoh 30s / 10m) (atau kembali): " pint
        if is_back_choice "${pint}"; then
          continue
        fi
        xray_observatory_set_interval "${pint}"
        log "interval updated"
        pause
        ;;
      3)
        xray_observatory_toggle_concurrency
        log "concurrency toggled"
        pause
        ;;
      4)
        xray_observatory_sync_subject_selector_from_balancer
        log "Observatory subjectSelector disinkronkan"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_menu_simple() {
  while true; do
    title
    echo "4) Network Controls > Egress Mode & Balancer"
    hr
    printf "Current Egress Mode: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) Set Egress Mode"
    echo "  2) Balancer Settings"
    echo "  3) Observatory Settings"
    echo "  4) Show Detailed Status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) egress_set_mode_menu ;;
      2) egress_balancer_settings_menu ;;
      3) egress_observatory_settings_menu ;;
      4) egress_show_detailed_status ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_global_mode_get() {
  xray_routing_default_rule_get | awk -F'=' '/^mode=/{print $2; exit}' 2>/dev/null || true
}

warp_global_mode_pretty_get() {
  local mode bal
  mode="$(warp_global_mode_get)"
  bal="$(xray_routing_default_rule_get | awk -F'=' '/^balancer=/{print $2; exit}' 2>/dev/null || true)"
  case "${mode}" in
    warp) echo "warp" ;;
    direct) echo "direct" ;;
    balancer)
      if [[ -n "${bal}" ]]; then
        echo "balancer (${bal})"
      else
        echo "balancer"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

xray_routing_rule_user_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
out=[]
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  u=r.get('user') or []
  if not isinstance(u, list):
    continue
  if marker in u:
    for x in u:
      if isinstance(x, str) and x and x != marker:
        out.append(x)
    break
for x in out:
  print(x)
PY
}

xray_routing_rule_inbound_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
out=[]
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  ib=r.get('inboundTag') or []
  if not isinstance(ib, list):
    continue
  if marker in ib:
    for x in ib:
      if isinstance(x, str) and x and x != marker:
        out.append(x)
    break
for x in out:
  print(x)
PY
}

xray_routing_custom_domain_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
custom=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and marker in dom:
    custom=[x for x in dom if isinstance(x, str) and x and x != marker]
    break
if not isinstance(custom, list):
  custom=[]
for x in custom:
  print(x)
PY
}

xray_inbounds_all_client_emails_get() {
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
emails=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  st=(ib.get('settings') or {})
  clients=st.get('clients') or []
  if not isinstance(clients, list):
    continue
  for c in clients:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if isinstance(em, str) and em.strip():
      emails.add(em.strip())
for em in sorted(emails):
  print(em)
PY
}

warp_controls_summary() {
  local global wire_state
  global="$(warp_global_mode_pretty_get)"
  if svc_exists wireproxy; then
    if svc_is_active wireproxy; then
      wire_state="active"
    else
      wire_state="inactive"
    fi
  else
    wire_state="not-installed"
  fi

  local wu du wi di dd wd
  wu="$(xray_routing_rule_user_list_get "dummy-warp-user" "warp" | wc -l | tr -d ' ')"
  du="$(xray_routing_rule_user_list_get "dummy-direct-user" "direct" | wc -l | tr -d ' ')"
  wi="$(xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" | wc -l | tr -d ' ')"
  di="$(xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" | wc -l | tr -d ' ')"
  dd="$(xray_routing_custom_domain_list_get "regexp:^$" "direct" | wc -l | tr -d ' ')"
  wd="$(xray_routing_custom_domain_list_get 'regexp:^$WARP' "warp" | wc -l | tr -d ' ')"

  echo "WARP Global : ${global}"
  echo "wireproxy   : ${wire_state}"
  echo "Override    : user warp=${wu}, user direct=${du} | inbound warp=${wi}, inbound direct=${di}"
  echo "Domain list : direct=${dd}, warp=${wd}"
}

warp_controls_report() {
  title
  echo "WARP status report (detail)"
  hr
  warp_controls_summary || true
  hr

  need_python3
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
inb_path, routing_path = sys.argv[1:3]

def load_json(path):
  try:
    with open(path,'r',encoding='utf-8') as f:
      return json.load(f)
  except Exception:
    return {}

inb=load_json(inb_path)
rt=load_json(routing_path)

rules=((rt.get('routing') or {}).get('rules') or [])

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

def get_default_mode():
  target=None
  for r in rules:
    if is_default_rule(r):
      target=r
  mode='unknown'
  bal=''
  if isinstance(target, dict):
    bt=target.get('balancerTag')
    if isinstance(bt, str) and bt:
      mode='balancer'
      bal=bt
    else:
      ot=target.get('outboundTag')
      if ot == 'warp':
        mode='warp'
      elif ot == 'direct':
        mode='direct'
      elif isinstance(ot, str) and ot:
        mode='unknown'
      else:
        mode='unknown'
  return mode, bal

def rule_list_user(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    u=r.get('user') or []
    if isinstance(u, list) and marker in u:
      return [x for x in u if isinstance(x,str) and x and x != marker]
  return []

def rule_list_inbound(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    ib=r.get('inboundTag') or []
    if isinstance(ib, list) and marker in ib:
      return [x for x in ib if isinstance(x,str) and x and x != marker]
  return []

def rule_list_domain(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and marker in dom:
      return [x for x in dom if isinstance(x,str) and x and x != marker]
  return []

mode, bal = get_default_mode()
default_label = mode
if mode == 'balancer' and bal:
  default_label = f'balancer({bal})'

warp_users=set(rule_list_user('dummy-warp-user','warp'))
direct_users=set(rule_list_user('dummy-direct-user','direct'))
warp_inb=set(rule_list_inbound('dummy-warp-inbounds','warp'))
direct_inb=set(rule_list_inbound('dummy-direct-inbounds','direct'))
direct_dom=rule_list_domain('regexp:^$','direct')
warp_dom=rule_list_domain('regexp:^$WARP','warp')

# Collect client emails (and protocol)
clients=[]
for ib in (inb.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  proto=ib.get('protocol')
  st=(ib.get('settings') or {})
  cls=st.get('clients') or []
  if not isinstance(cls, list):
    continue
  for c in cls:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if isinstance(em, str) and em.strip():
      clients.append((em.strip(), proto if isinstance(proto,str) else ''))

# unique keep stable sorted
clients_sorted=sorted(set(clients), key=lambda x: (x[0], x[1]))

def eff_mode_for_email(email):
  if email in direct_users:
    return 'direct'
  if email in warp_users:
    return 'warp'
  if mode in ('warp','direct'):
    return mode
  return default_label

print("Per-user effective mode:")
print(f"{'Email':<28} {'Proto':<8} {'Effective':<12} {'Override':<10}")
print("-"*62)
for em, proto in clients_sorted:
  override=''
  if em in direct_users:
    override='direct'
  elif em in warp_users:
    override='warp'
  eff=eff_mode_for_email(em)
  print(f"{em:<28} {proto:<8} {eff:<12} {override:<10}")
if not clients_sorted:
  print("(tidak ada client ditemukan dari 10-inbounds.json)")

print()
print("Per-inboundTag effective mode:")
print(f"{'InboundTag':<28} {'Proto':<8} {'Effective':<12} {'Override':<10}")
print("-"*62)

def inbounds_tags_by_proto():
  out=[]
  for ib in (inb.get('inbounds') or []):
    if not isinstance(ib, dict):
      continue
    tag=ib.get('tag')
    proto=ib.get('protocol')
    if isinstance(tag,str) and tag.strip():
      out.append((tag.strip(), proto if isinstance(proto,str) else ''))
  return sorted(set(out), key=lambda x: (x[1], x[0]))

def eff_mode_for_inbound(tag):
  if tag in direct_inb:
    return 'direct'
  if tag in warp_inb:
    return 'warp'
  if mode in ('warp','direct'):
    return mode
  return default_label

tags=inbounds_tags_by_proto()
for tag, proto in tags:
  override=''
  if tag in direct_inb:
    override='direct'
  elif tag in warp_inb:
    override='warp'
  eff=eff_mode_for_inbound(tag)
  print(f"{tag:<28} {proto:<8} {eff:<12} {override:<10}")
if not tags:
  print("(tidak ada inbound tag ditemukan dari 10-inbounds.json)")

print()
print("Custom Domain/Geosite Lists:")
print("  Direct (custom):")
if direct_dom:
  for x in direct_dom:
    print(f"    - {x}")
else:
  print("    (kosong)")
print("  WARP (custom):")
if warp_dom:
  for x in warp_dom:
    print(f"    - {x}")
else:
  print("    (kosong)")
PY
  hr
  pause
}

xray_routing_custom_domain_entry_set_mode() {
  # args: mode direct|warp|off entry
  local mode="$1"
  local ent="$2"
  local tmp backup
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  (
    flock -x 200
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${mode}" "${ent}"
import json, sys
src, dst, mode, ent = sys.argv[1:5]
mode=mode.lower().strip()
ent=ent.strip()

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)

routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

def find_default_idx():
  idx=None
  for i,r in enumerate(rules):
    if is_default_rule(r):
      idx=i
  return idx

def find_template_direct_idx():
  for i,r in enumerate(rules):
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != 'direct':
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
      return i
  return None

def find_domain_rule_idx(outbound, marker):
  for i,r in enumerate(rules):
    if not isinstance(r, dict):
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and marker in dom:
      return i
  return None

def ensure_domain_rule(outbound, marker, insert_at):
  idx=find_domain_rule_idx(outbound, marker)
  if idx is not None:
    return idx
  newr={"type":"field","domain":[marker],"outboundTag":outbound}
  rules.insert(insert_at, newr)
  return insert_at

def normalize_rule(idx, marker, desired_present):
  r=rules[idx]
  dom=r.get('domain') or []
  if not isinstance(dom, list):
    dom=[]
  # keep marker first
  dom=[x for x in dom if x != marker]
  dom.insert(0, marker)
  # remove ent
  dom=[x for x in dom if x != ent]
  if desired_present:
    dom.append(ent)
  r['domain']=dom
  rules[idx]=r

default_idx=find_default_idx()
if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan")

tpl_idx=find_template_direct_idx()
# Base insertion point: after template direct if exists, else before default
base=(tpl_idx + 1) if tpl_idx is not None else default_idx

direct_marker='regexp:^$'
warp_marker='regexp:^$WARP'

direct_idx=find_domain_rule_idx('direct', direct_marker)
warp_idx=find_domain_rule_idx('warp', warp_marker)

# Insert order: template direct -> custom direct -> custom warp -> default
# Ensure direct rule position
if mode == 'direct':
  if direct_idx is None:
    direct_idx=ensure_domain_rule('direct', direct_marker, base)
    if direct_idx <= default_idx:
      default_idx += 1
    if warp_idx is not None and warp_idx >= direct_idx:
      pass
  # Ensure warp rule exists only if already exists; don't create unless needed
  if warp_idx is not None:
    normalize_rule(warp_idx, warp_marker, False)
  normalize_rule(direct_idx, direct_marker, True)

elif mode == 'warp':
  # ensure warp rule after direct rule if direct exists, else after template
  if direct_idx is not None:
    # ensure warp inserted after direct rule
    base_warp = direct_idx + 1
  else:
    base_warp = base
  if warp_idx is None:
    warp_idx=ensure_domain_rule('warp', warp_marker, base_warp)
    if warp_idx <= default_idx:
      default_idx += 1
  if direct_idx is not None:
    normalize_rule(direct_idx, direct_marker, False)
  normalize_rule(warp_idx, warp_marker, True)

elif mode == 'off':
  if direct_idx is not None:
    normalize_rule(direct_idx, direct_marker, False)
  if warp_idx is not None:
    normalize_rule(warp_idx, warp_marker, False)
else:
  raise SystemExit("Mode harus direct|warp|off")

routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
  ) 200>"${ROUTING_LOCK_FILE}" || {
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    die "Gagal update routing (rollback ke backup: ${backup})"
  }
  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    (
      flock -x 200
      cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    ) 200>"${ROUTING_LOCK_FILE}"
    systemctl restart xray || true
    die "xray tidak aktif setelah update custom domain mode. Config di-rollback ke backup: ${backup}"
  fi
}

warp_global_menu() {
  while true; do
    title
    echo "WARP Controls > WARP Global"
    hr
    printf "Status WARP Global: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) direct"
    echo "  2) warp"
    echo "  0) kembali"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        xray_routing_default_rule_set direct
        log "WARP Global di-set ke DIRECT"
        pause
        return 0
        ;;
      2)
        xray_routing_default_rule_set warp
        log "WARP Global di-set ke WARP"
        pause
        return 0
        ;;
      0|kembali|k|back|b) return 0 ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_user_set_effective_mode() {
  local email="$1"
  local desired="$2" # direct|warp

  if is_default_xray_email_or_tag "${email}"; then
    warn "User default Xray bersifat readonly: ${email}"
    return 0
  fi

  local in_warp="no"
  local in_direct="no"
  if xray_routing_rule_user_list_get "dummy-warp-user" "warp" 2>/dev/null | grep -Fxq "${email}"; then
    in_warp="yes"
  fi
  if xray_routing_rule_user_list_get "dummy-direct-user" "direct" 2>/dev/null | grep -Fxq "${email}"; then
    in_direct="yes"
  fi

  case "${desired}" in
    direct)
      if [[ "${in_warp}" == "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-warp-user" "warp" "${email}" off
      fi
      if [[ "${in_direct}" != "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-direct-user" "direct" "${email}" on
      fi
      ;;
    warp)
      if [[ "${in_direct}" == "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-direct-user" "direct" "${email}" off
      fi
      if [[ "${in_warp}" != "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-warp-user" "warp" "${email}" on
      fi
      ;;
    *) warn "Mode user harus direct|warp" ;;
  esac
}


warp_per_user_menu() {
  need_python3

  local page=0
  local page_size=10

  while true; do
    mapfile -t all_users_raw < <(xray_inbounds_all_client_emails_get 2>/dev/null || true)

    local all_users=()
    local u
    for u in "${all_users_raw[@]}"; do
      if is_default_xray_email_or_tag "${u}"; then
        continue
      fi
      all_users+=("${u}")
    done

    if (( ${#all_users[@]} == 0 )); then
      title
      echo "WARP Controls > WARP per-user"
      hr
      warn "Tidak menemukan user non-default dari config inbounds."
      hr
      pause
      return 0
    fi

    mapfile -t warp_override < <(xray_routing_rule_user_list_get "dummy-warp-user" "warp" 2>/dev/null || true)
    mapfile -t direct_override < <(xray_routing_rule_user_list_get "dummy-direct-user" "direct" 2>/dev/null || true)

    declare -A warp_set=()
    declare -A direct_set=()

    for u in "${warp_override[@]}"; do
      [[ -n "${u}" ]] && warp_set["${u}"]=1
    done
    for u in "${direct_override[@]}"; do
      [[ -n "${u}" ]] && direct_set["${u}"]=1
    done

    local global_mode default_mode
    global_mode="$(warp_global_mode_get || true)"
    case "${global_mode}" in
      warp) default_mode="warp" ;;
      direct) default_mode="direct" ;;
      balancer) default_mode="balancer" ;;
      *) default_mode="unknown" ;;
    esac

    local total pages start end i row email status
    total="${#all_users[@]}"
    pages=$(( (total + page_size - 1) / page_size ))
    if (( page < 0 )); then page=0; fi
    if (( page >= pages )); then page=$((pages - 1)); fi
    start=$((page * page_size))
    end=$((start + page_size))
    if (( end > total )); then end=total; fi

    title
    echo "WARP Controls > WARP per-user"
    hr
    printf "WARP Global: %s
" "$(warp_global_mode_pretty_get)"
    hr
    printf "%-4s %-32s %-7s
" "No" "User" "Status"
    printf "%-4s %-32s %-7s
" "----" "--------------------------------" "-------"

    for (( i=start; i<end; i++ )); do
      row=$((i - start + 1))
      email="${all_users[$i]}"

      if [[ -n "${direct_set[${email}]:-}" ]]; then
        status="direct"
      elif [[ -n "${warp_set[${email}]:-}" ]]; then
        status="warp"
      else
        status="${default_mode}"
      fi

      printf "%-4s %-32s %-7s
" "${row}" "${email}" "${status}"
    done

    echo
    echo "Halaman: $((page + 1))/${pages} | Total user: ${total}"
    if (( pages > 1 )); then
      echo "Toggle: next / previous / 0 kembali"
    else
      echo "Toggle: 0 kembali"
    fi
    hr
    read -r -p "Pilih No untuk ubah (atau next/previous/kembali): " c

    if is_back_choice "${c}"; then
      return 0
    fi

    case "${c}" in
      next|n)
        if (( page < pages - 1 )); then
          page=$((page + 1))
        fi
        continue
        ;;
      previous|prev|p)
        if (( page > 0 )); then
          page=$((page - 1))
        fi
        continue
        ;;
    esac

    if [[ ! "${c}" =~ ^[0-9]+$ ]]; then
      warn "Input tidak valid"
      sleep 1
      continue
    fi

    if (( c < 1 || c > (end - start) )); then
      warn "No di luar range"
      sleep 1
      continue
    fi

    email="${all_users[$((start + c - 1))]}"

    local cur_status
    if [[ -n "${direct_set[${email}]:-}" ]]; then
      cur_status="direct"
    elif [[ -n "${warp_set[${email}]:-}" ]]; then
      cur_status="warp"
    else
      cur_status="${default_mode}"
    fi

    while true; do
      title
      echo "WARP Controls > WARP per-user"
      hr
      echo "User   : ${email}"
      echo "Status : ${cur_status}"
      hr
      echo "  1) direct"
      echo "  2) warp"
      echo "  0) kembali"
      hr
      read -r -p "Pilih: " s

      if is_back_choice "${s}"; then
        break
      fi

      case "${s}" in
        1)
          warp_user_set_effective_mode "${email}" direct
          log "Per-user di-set DIRECT: ${email}"
          pause
          break
          ;;
        2)
          warp_user_set_effective_mode "${email}" warp
          log "Per-user di-set WARP: ${email}"
          pause
          break
          ;;
        *) warn "Pilihan tidak valid" ; sleep 1 ;;
      esac
    done
  done
}


warp_inbound_set_effective_mode() {
  local tag="$1"
  local desired="$2" # direct|warp

  if [[ "${tag}" == "api" ]]; then
    warn "Inbound internal (api) bersifat readonly: ${tag}"
    return 0
  fi

  local in_warp="no"
  local in_direct="no"
  if xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" 2>/dev/null | grep -Fxq "${tag}"; then
    in_warp="yes"
  fi
  if xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" 2>/dev/null | grep -Fxq "${tag}"; then
    in_direct="yes"
  fi

  case "${desired}" in
    direct)
      if [[ "${in_warp}" == "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-warp-inbounds" "warp" "${tag}" off
      fi
      if [[ "${in_direct}" != "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-direct-inbounds" "direct" "${tag}" on
      fi
      ;;
    warp)
      if [[ "${in_direct}" == "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-direct-inbounds" "direct" "${tag}" off
      fi
      if [[ "${in_warp}" != "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-warp-inbounds" "warp" "${tag}" on
      fi
      ;;
    *) warn "Mode inbound harus direct|warp" ;;
  esac
}


warp_per_inbounds_menu() {
  need_python3

  while true; do
    mapfile -t all_tags_raw < <(xray_inbounds_all_tags_get 2>/dev/null || true)

    local tags=()
    local t
    for t in "${all_tags_raw[@]}"; do
      if [[ "${t}" == "api" ]]; then
        continue
      fi
      tags+=("${t}")
    done

    if (( ${#tags[@]} == 0 )); then
      title
      echo "WARP Controls > WARP per-protocol inbounds"
      hr
      warn "Tidak ada inbound yang bisa diatur."
      hr
      pause
      return 0
    fi

    mapfile -t warp_override < <(xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" 2>/dev/null || true)
    mapfile -t direct_override < <(xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" 2>/dev/null || true)

    declare -A warp_set=()
    declare -A direct_set=()

    for t in "${warp_override[@]}"; do
      [[ -n "${t}" ]] && warp_set["${t}"]=1
    done
    for t in "${direct_override[@]}"; do
      [[ -n "${t}" ]] && direct_set["${t}"]=1
    done

    local global_mode default_mode
    global_mode="$(warp_global_mode_get || true)"
    case "${global_mode}" in
      warp) default_mode="warp" ;;
      direct) default_mode="direct" ;;
      balancer) default_mode="balancer" ;;
      *) default_mode="unknown" ;;
    esac

    title
    echo "WARP Controls > WARP per-protocol inbounds"
    hr
    printf "WARP Global: %s
" "$(warp_global_mode_pretty_get)"
    hr
    printf "%-4s %-28s %-7s
" "No" "Protocol (Inbound Tag)" "Status"
    printf "%-4s %-28s %-7s
" "----" "----------------------------" "-------"

    local i status
    for (( i=0; i<${#tags[@]}; i++ )); do
      t="${tags[$i]}"

      if [[ -n "${direct_set[${t}]:-}" ]]; then
        status="direct"
      elif [[ -n "${warp_set[${t}]:-}" ]]; then
        status="warp"
      else
        status="${default_mode}"
      fi

      printf "%-4s %-28s %-7s
" "$((i + 1))" "${t}" "${status}"
    done

    hr
    echo "Pilih No untuk ubah (direct/warp), atau 0 kembali"
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      return 0
    fi

    if [[ ! "${c}" =~ ^[0-9]+$ ]]; then
      warn "Input tidak valid"
      sleep 1
      continue
    fi
    if (( c < 1 || c > ${#tags[@]} )); then
      warn "No di luar range"
      sleep 1
      continue
    fi

    t="${tags[$((c - 1))]}"

    local cur_status
    if [[ -n "${direct_set[${t}]:-}" ]]; then
      cur_status="direct"
    elif [[ -n "${warp_set[${t}]:-}" ]]; then
      cur_status="warp"
    else
      cur_status="${default_mode}"
    fi

    while true; do
      title
      echo "WARP Controls > WARP per-protocol inbounds"
      hr
      echo "Inbound : ${t}"
      echo "Status  : ${cur_status}"
      hr
      echo "  1) direct"
      echo "  2) warp"
      echo "  0) kembali"
      hr
      read -r -p "Pilih: " s

      if is_back_choice "${s}"; then
        break
      fi

      case "${s}" in
        1)
          warp_inbound_set_effective_mode "${t}" direct
          log "Per-inbounds di-set DIRECT: ${t}"
          pause
          break
          ;;
        2)
          warp_inbound_set_effective_mode "${t}" warp
          log "Per-inbounds di-set WARP: ${t}"
          pause
          break
          ;;
        *) warn "Pilihan tidak valid" ; sleep 1 ;;
      esac
    done
  done
}


warp_domain_geosite_menu() {
  need_python3

  local mode="direct"

  while true; do
    title
    echo "WARP Controls > WARP per-Geosite/Domain"
    hr
    echo "Status: ${mode}"
    hr

    echo "Readonly (template) geosite:"
    xray_routing_readonly_geosite_rule_print || true
    hr

    local header ent
    local -a lst_raw=()
    local -a lst=()

    if [[ "${mode}" == "warp" ]]; then
      header="Custom WARP list:"
      mapfile -t lst_raw < <(xray_routing_custom_domain_list_get 'regexp:^$WARP' "warp" 2>/dev/null || true)
    else
      header="Custom DIRECT list:"
      mapfile -t lst_raw < <(xray_routing_custom_domain_list_get "regexp:^$" "direct" 2>/dev/null || true)
    fi

    for ent in "${lst_raw[@]}"; do
      lst+=("${ent}")
    done

    echo "${header}"
    if (( ${#lst[@]} == 0 )); then
      echo "  (kosong)"
    else
      local i
      for (( i=0; i<${#lst[@]}; i++ )); do
        ent="${lst[$i]}"
        if is_readonly_geosite_domain "${ent}"; then
          printf "  %2d. %s (readonly)\n" "$((i + 1))" "${ent}"
        else
          printf "  %2d. %s\n" "$((i + 1))" "${ent}"
        fi
      done
    fi
    hr

    echo "  1) direct"
    echo "  2) warp"
    echo "  3) tambah domain"
    echo "  4) hapus domain"
    echo "  0) kembali"
    hr
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      break
    fi

    case "${c}" in
      1) mode="direct" ;;
      2) mode="warp" ;;
      3)
        read -r -p "Entry (contoh: geosite:twitter / example.com) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"
        if [[ -z "${ent}" || "${ent}" == "regexp:^$" || "${ent}" == 'regexp:^$WARP' ]]; then
          warn "Entry tidak valid / reserved"
          pause
          continue
        fi
        if is_readonly_geosite_domain "${ent}"; then
          warn "Readonly geosite tidak boleh diubah dari menu ini: ${ent}"
          pause
          continue
        fi
        xray_routing_custom_domain_entry_set_mode "${mode}" "${ent}"
        log "Entry di-set ${mode^^}: ${ent}"
        pause
        ;;
      4)
        if (( ${#lst[@]} == 0 )); then
          warn "List kosong"
          pause
          continue
        fi
        read -r -p "Entry yang dihapus (No atau teks) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"

        if [[ "${ent}" =~ ^[0-9]+$ ]]; then
          if (( ent < 1 || ent > ${#lst[@]} )); then
            warn "No tidak ditemukan"
            pause
            continue
          fi
          ent="${lst[$((ent - 1))]}"
        fi

        if [[ -z "${ent}" || "${ent}" == "regexp:^$" || "${ent}" == 'regexp:^$WARP' ]]; then
          warn "Entry tidak valid / reserved"
          pause
          continue
        fi
        if is_readonly_geosite_domain "${ent}"; then
          warn "Readonly geosite tidak bisa dihapus dari menu ini: ${ent}"
          pause
          continue
        fi

        xray_routing_custom_domain_entry_set_mode off "${ent}"
        log "Entry dihapus (OFF): ${ent}"
        pause
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}



warp_tier_state_target_get() {
  local raw
  raw="$(network_state_get "${WARP_TIER_STATE_KEY}" 2>/dev/null || true)"
  raw="$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "${raw}" in
    free|plus) echo "${raw}" ;;
    *) echo "unknown" ;;
  esac
}

warp_plus_license_state_get() {
  network_state_get "${WARP_PLUS_LICENSE_STATE_KEY}" 2>/dev/null | tr -d '\r' || true
}

warp_plus_license_mask() {
  local key="${1:-}"
  local len
  key="$(echo "${key}" | tr -d '[:space:]')"
  len="${#key}"
  if (( len <= 8 )); then
    echo "${key}"
    return 0
  fi
  echo "${key:0:4}****${key:len-4:4}"
}

warp_trace_field_get() {
  # args: field_name
  local field="${1:-}"
  local bind_addr trace
  [[ -n "${field}" ]] || return 0
  [[ -f "${WIREPROXY_CONF}" ]] || return 0
  if ! have_cmd curl; then
    return 0
  fi
  bind_addr="$(awk -F'=' '
    /^[[:space:]]*BindAddress[[:space:]]*=/ {
      v=$2
      gsub(/[[:space:]]/, "", v)
      print v
      exit
    }
  ' "${WIREPROXY_CONF}" 2>/dev/null || true)"
  [[ -n "${bind_addr}" ]] || bind_addr="127.0.0.1:40000"

  trace="$(curl -fsS --max-time 8 --socks5 "${bind_addr}" "https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null || true)"
  [[ -n "${trace}" ]] || return 0
  echo "${trace}" | awk -F= -v k="${field}" '$1==k {print $2; exit}'
}

warp_live_tier_get() {
  local warpv
  warpv="$(warp_trace_field_get warp | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "${warpv}" in
    plus) echo "plus" ;;
    on) echo "free" ;;
    off) echo "off" ;;
    *) echo "unknown" ;;
  esac
}

warp_wireproxy_socks_block_get() {
  if [[ ! -f "${WIREPROXY_CONF}" ]]; then
    cat <<'EOF'
[Socks5]
BindAddress = 127.0.0.1:40000
EOF
    return 0
  fi

  awk '
    BEGIN { inblk=0; found=0 }
    /^[[:space:]]*\[(Socks|Socks5)\][[:space:]]*$/ {
      inblk=1
      if (found==0) {
        print "[Socks5]"
        found=1
      }
      next
    }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      inblk=0
      next
    }
    inblk { print; next }
    END {
      if (found==0) {
        print "[Socks5]"
        print "BindAddress = 127.0.0.1:40000"
      }
    }
  ' "${WIREPROXY_CONF}" 2>/dev/null
}

warp_wireproxy_apply_profile() {
  # args: wgcf_profile_path
  local profile="${1:-}"
  local tmp backup socks_block ts
  [[ -n "${profile}" && -f "${profile}" ]] || {
    warn "Profile wgcf tidak ditemukan: ${profile}"
    return 1
  }

  mkdir -p "$(dirname "${WIREPROXY_CONF}")"
  tmp="$(mktemp)"
  socks_block="$(warp_wireproxy_socks_block_get)"

  awk '
    BEGIN { drop=0 }
    /^[[:space:]]*\[(Socks|Socks5)\][[:space:]]*$/ { drop=1; next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { drop=0 }
    drop { next }
    { print }
  ' "${profile}" > "${tmp}"
  printf "\n%s\n" "${socks_block}" >> "${tmp}"

  if [[ -f "${WIREPROXY_CONF}" ]]; then
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="${WIREPROXY_CONF}.bak.${ts}"
    cp -f "${WIREPROXY_CONF}" "${backup}" 2>/dev/null || true
  fi

  if ! install -m 600 "${tmp}" "${WIREPROXY_CONF}"; then
    rm -f "${tmp}" 2>/dev/null || true
    warn "Gagal menulis wireproxy config: ${WIREPROXY_CONF}"
    return 1
  fi
  rm -f "${tmp}" 2>/dev/null || true
  return 0
}

warp_wgcf_register_noninteractive() {
  local reg_log="/tmp/wgcf-register-manage.$$.log"

  mkdir -p "${WGCF_DIR}"
  pushd "${WGCF_DIR}" >/dev/null || {
    warn "Gagal masuk ke ${WGCF_DIR}"
    return 1
  }

  if [[ -f "wgcf-account.toml" ]]; then
    popd >/dev/null || true
    return 0
  fi

  if have_cmd expect; then
    expect <<'EOF' >"${reg_log}" 2>&1 || true
set timeout 180
log_user 1
spawn wgcf register
expect {
  -re {Use the arrow keys.*} { send "\r"; exp_continue }
  -re {Do you agree.*} { send "\r"; exp_continue }
  -re {\(y/n\)} { send "y\r"; exp_continue }
  -re {Yes/No} { send "\r"; exp_continue }
  -re {accept} { send "\r"; exp_continue }
  eof
}
EOF
  else
    set +o pipefail
    yes | wgcf register >"${reg_log}" 2>&1 || true
    set -o pipefail
  fi

  popd >/dev/null || true
  if [[ ! -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    warn "wgcf register gagal. Log: ${reg_log}"
    tail -n 60 "${reg_log}" >&2 || true
    return 1
  fi
  return 0
}

warp_wgcf_build_profile() {
  # args: tier [license_key]
  local tier="${1:-free}"
  local license_key="${2:-}"
  local gen_log="/tmp/wgcf-generate-manage.$$.log"
  local upd_log="/tmp/wgcf-update-manage.$$.log"

  mkdir -p "${WGCF_DIR}"
  if [[ ! -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    if ! warp_wgcf_register_noninteractive; then
      return 1
    fi
  fi

  pushd "${WGCF_DIR}" >/dev/null || {
    warn "Gagal masuk ke ${WGCF_DIR}"
    return 1
  }

  if [[ "${tier}" == "plus" ]]; then
    license_key="$(echo "${license_key}" | tr -d '[:space:]')"
    if [[ -z "${license_key}" ]]; then
      popd >/dev/null || true
      warn "License key WARP+ kosong"
      return 1
    fi
    if ! wgcf update --license-key "${license_key}" >"${upd_log}" 2>&1; then
      popd >/dev/null || true
      warn "wgcf update --license-key gagal. Log: ${upd_log}"
      tail -n 60 "${upd_log}" >&2 || true
      return 1
    fi
  fi

  if ! wgcf generate -p "${WGCF_DIR}/wgcf-profile.conf" >"${gen_log}" 2>&1; then
    popd >/dev/null || true
    warn "wgcf generate gagal. Log: ${gen_log}"
    tail -n 60 "${gen_log}" >&2 || true
    return 1
  fi
  popd >/dev/null || true

  if [[ ! -s "${WGCF_DIR}/wgcf-profile.conf" ]]; then
    warn "wgcf-profile.conf tidak ditemukan setelah generate"
    return 1
  fi
  return 0
}

warp_tier_show_status() {
  local target live svc_state license_raw license_masked
  target="$(warp_tier_state_target_get)"
  live="$(warp_live_tier_get)"
  license_raw="$(warp_plus_license_state_get)"
  license_masked="$(warp_plus_license_mask "${license_raw}")"
  if svc_exists wireproxy; then
    svc_state="$(svc_state wireproxy)"
  else
    svc_state="not-installed"
  fi

  printf "Target Tier   : %s\n" "${target}"
  printf "Live Tier     : %s\n" "${live}"
  printf "wireproxy     : %s\n" "${svc_state}"
  if [[ -n "${license_raw}" ]]; then
    printf "WARP+ License : %s\n" "${license_masked}"
  else
    printf "WARP+ License : (kosong)\n"
  fi
}

warp_tier_switch_free() {
  title
  echo "4) Network Controls > WARP Controls > Switch ke WARP Free"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  mkdir -p "${WGCF_DIR}"
  if [[ -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    cp -f "${WGCF_DIR}/wgcf-account.toml" "${WGCF_DIR}/wgcf-account.toml.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  fi
  rm -f "${WGCF_DIR}/wgcf-account.toml" "${WGCF_DIR}/wgcf-profile.conf" 2>/dev/null || true

  if ! warp_wgcf_register_noninteractive; then
    hr
    pause
    return 0
  fi
  if ! warp_wgcf_build_profile free; then
    hr
    pause
    return 0
  fi
  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  network_state_set "${WARP_TIER_STATE_KEY}" "free"
  log "WARP tier target di-set: free"
  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_switch_plus() {
  local saved_key key masked
  title
  echo "4) Network Controls > WARP Controls > Switch ke WARP Plus"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  saved_key="$(warp_plus_license_state_get)"
  masked="$(warp_plus_license_mask "${saved_key}")"
  if [[ -n "${saved_key}" ]]; then
    echo "License tersimpan: ${masked}"
    read -r -p "Input WARP+ License Key (Enter=pakai tersimpan, atau kembali): " key
    if is_back_choice "${key}"; then
      return 0
    fi
    key="$(echo "${key}" | tr -d '[:space:]')"
    [[ -n "${key}" ]] || key="${saved_key}"
  else
    read -r -p "Input WARP+ License Key (atau kembali): " key
    if is_back_choice "${key}"; then
      return 0
    fi
    key="$(echo "${key}" | tr -d '[:space:]')"
  fi

  if [[ -z "${key}" ]]; then
    warn "License key WARP+ kosong"
    hr
    pause
    return 0
  fi

  if ! warp_wgcf_build_profile plus "${key}"; then
    hr
    pause
    return 0
  fi
  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  network_state_set "${WARP_TIER_STATE_KEY}" "plus"
  network_state_set "${WARP_PLUS_LICENSE_STATE_KEY}" "${key}"
  log "WARP tier target di-set: plus"
  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_reconnect_regenerate() {
  local target key
  title
  echo "4) Network Controls > WARP Controls > Reconnect/Regenerate"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  target="$(warp_tier_state_target_get)"
  if [[ "${target}" != "free" && "${target}" != "plus" ]]; then
    target="free"
  fi

  if [[ "${target}" == "plus" ]]; then
    key="$(warp_plus_license_state_get)"
    key="$(echo "${key}" | tr -d '[:space:]')"
    if [[ -z "${key}" ]]; then
      warn "Target plus aktif, tapi license key kosong. Gunakan menu Switch ke WARP Plus dulu."
      hr
      pause
      return 0
    fi
    if ! warp_wgcf_build_profile plus "${key}"; then
      hr
      pause
      return 0
    fi
  else
    if ! warp_wgcf_build_profile free; then
      hr
      pause
      return 0
    fi
  fi

  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  log "Reconnect/regenerate selesai untuk target tier: ${target}"
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_menu() {
  while true; do
    title
    echo "4) Network Controls > WARP Controls > WARP Tier (Free/Plus)"
    hr
    warp_tier_show_status
    hr
    echo "  1) Show status"
    echo "  2) Switch ke WARP Free"
    echo "  3) Switch ke WARP Plus"
    echo "  4) Reconnect/Regenerate sesuai target"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        title
        echo "4) Network Controls > WARP Controls > WARP Tier Status"
        hr
        warp_tier_show_status
        hr
        pause
        ;;
      2) warp_tier_switch_free ;;
      3) warp_tier_switch_plus ;;
      4) warp_tier_reconnect_regenerate ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_controls_menu() {
  while true; do
    title
    echo "4) Network Controls > WARP Controls"
    hr
    echo "  1) WARP (wireproxy) status"
    echo "  2) Restart WARP (wireproxy)"
    echo "  3) WARP Global"
    echo "  4) WARP per-user"
    echo "  5) WARP per-protocol inbounds"
    echo "  6) WARP per-Geosite/Domain"
    echo "  7) WARP Tier (Free/Plus)"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) warp_status ;;
      2)
        title
        echo "Restart wireproxy"
        hr
        if svc_exists wireproxy; then
          svc_restart wireproxy || true
        else
          warn "wireproxy.service tidak terdeteksi"
        fi
        hr
        pause
        ;;
      3) warp_global_menu ;;
      4) warp_per_user_menu ;;
      5) warp_per_inbounds_menu ;;
      6) warp_domain_geosite_menu ;;
      7) warp_tier_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

domain_geosite_menu() {
  need_python3
  while true; do
    title
    echo "4) Network Controls > Domain/Geosite Routing (Direct List)"
    hr
    echo "Template (readonly):"
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
tpl=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != 'direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
    tpl=dom
    break
if not isinstance(tpl, list):
  tpl=[]
for i,d in enumerate([x for x in tpl if isinstance(x,str)] , start=1):
  print(f"  {i:>2}. {d}")
PY
    hr

    echo "Editable (custom direct list):"
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
custom=None
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type')!='field':
    continue
  if r.get('outboundTag')!='direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom=[x for x in dom if isinstance(x,str) and x!='regexp:^$']
    break
if not isinstance(custom, list):
  custom=[]
if not custom:
  print("  (kosong)")
else:
  for i,d in enumerate(custom, start=1):
    print(f"  {i:>2}. {d}")
PY
    hr

    echo "  1) Add domain/geosite ke custom list"
    echo "  2) Remove domain/geosite dari custom list"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Masukkan entry (contoh: geosite:twitter / example.com) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"
        if [[ -z "${ent}" ]]; then
          warn "Entry kosong"
          pause
          continue
        fi
        if [[ "${ent}" == "regexp:^$" ]]; then
          warn "Entry reserved"
          pause
          continue
        fi
        need_python3
        ensure_path_writable "${XRAY_ROUTING_CONF}"
        local backup tmp
        backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
        tmp="${WORK_DIR}/30-routing.json.tmp"
        (
          flock -x 200
          python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${ent}"
import json, sys
src, dst, ent = sys.argv[1:4]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

# Find template direct rule
tpl_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type')!='field': continue
  if r.get('outboundTag')!='direct': continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
    tpl_idx=i
    break

# Find/create custom rule
custom_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type')!='field': continue
  if r.get('outboundTag')!='direct': continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom_idx=i
    break

if custom_idx is None:
  newr={"type":"field","domain":["regexp:^$"],"outboundTag":"direct"}
  insert_at = (tpl_idx + 1) if tpl_idx is not None else len(rules)
  rules.insert(insert_at, newr)
  custom_idx=insert_at

r=rules[custom_idx]
dom=r.get('domain') or []
if not isinstance(dom, list):
  dom=[]
if 'regexp:^$' not in dom:
  dom.insert(0,'regexp:^$')
if ent not in dom:
  dom.append(ent)
r['domain']=dom
rules[custom_idx]=r

routing['rules']=rules
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
          xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
        ) 200>"${ROUTING_LOCK_FILE}" || {
          (
            flock -x 200
            cp -a "${backup}" "${XRAY_ROUTING_CONF}"
          ) 200>"${ROUTING_LOCK_FILE}"
          die "Gagal update routing (rollback ke backup: ${backup})"
        }
        svc_restart xray || true
        if ! svc_wait_active xray 20; then
          (
            flock -x 200
            cp -a "${backup}" "${XRAY_ROUTING_CONF}"
          ) 200>"${ROUTING_LOCK_FILE}"
          systemctl restart xray || true
          die "xray tidak aktif setelah tambah custom domain direct. Config di-rollback ke backup: ${backup}"
        fi
        log "Entry ditambahkan: ${ent}"
        pause
        ;;
      2)
        read -r -p "Hapus nomor entry (lihat daftar) (atau kembali): " no
        if is_back_choice "${no}"; then
          continue
        fi
        if [[ -z "${no}" || ! "${no}" =~ ^[0-9]+$ || "${no}" -le 0 ]]; then
          warn "Nomor tidak valid"
          pause
          continue
        fi
        need_python3
        ensure_path_writable "${XRAY_ROUTING_CONF}"
        local backup tmp
        backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
        tmp="${WORK_DIR}/30-routing.json.tmp"
        (
          flock -x 200
          python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${no}"
import json, sys
src, dst, no = sys.argv[1:4]
no=int(no)
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

custom_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): 
    continue
  if r.get('type')!='field':
    continue
  if r.get('outboundTag')!='direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom_idx=i
    break
if custom_idx is None:
  raise SystemExit("Custom list belum ada")

r=rules[custom_idx]
dom=[x for x in (r.get('domain') or []) if isinstance(x,str)]
entries=[x for x in dom if x!='regexp:^$']
if no > len(entries):
  raise SystemExit("Nomor di luar range")
target=entries[no-1]
dom=[x for x in dom if x!=target]
# Ensure marker exists
if 'regexp:^$' not in dom:
  dom.insert(0,'regexp:^$')
r['domain']=dom
rules[custom_idx]=r

routing['rules']=rules
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
          xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}"
        ) 200>"${ROUTING_LOCK_FILE}" || {
          (
            flock -x 200
            cp -a "${backup}" "${XRAY_ROUTING_CONF}"
          ) 200>"${ROUTING_LOCK_FILE}"
          die "Gagal update routing (rollback ke backup: ${backup})"
        }
        svc_restart xray || true
        if ! svc_wait_active xray 20; then
          (
            flock -x 200
            cp -a "${backup}" "${XRAY_ROUTING_CONF}"
          ) 200>"${ROUTING_LOCK_FILE}"
          systemctl restart xray || true
          die "xray tidak aktif setelah hapus custom domain direct. Config di-rollback ke backup: ${backup}"
        fi
        log "Entry dihapus"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}


# -------------------------
# DNS Settings
# -------------------------
xray_dns_status_get() {
  # output:
  # primary=<...>
  # secondary=<...>
  # strategy=<...>
  # cache=on|off
  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    echo "primary="
    echo "secondary="
    echo "strategy="
    echo "cache=on"
    return 0
  fi

  python3 - <<'PY' "${XRAY_DNS_CONF}" 2>/dev/null || true
import json, sys

src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

dns=cfg.get('dns') or {}
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers') or []
if not isinstance(servers, list):
  servers=[]

def server_addr(s):
  if isinstance(s, str):
    return s
  if isinstance(s, dict):
    a=s.get('address')
    if isinstance(a, str):
      return a
  return ''

primary=server_addr(servers[0]) if len(servers) > 0 else ''
secondary=server_addr(servers[1]) if len(servers) > 1 else ''

qs=dns.get('queryStrategy')
strategy=qs if isinstance(qs, str) else ''

disable_cache=dns.get('disableCache')
cache='off' if bool(disable_cache) else 'on'

print('primary=' + primary)
print('secondary=' + secondary)
print('strategy=' + strategy)
print('cache=' + cache)
PY
}

xray_dns_set_primary() {
  local val="$1"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_config "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers')
if not isinstance(servers, list):
  servers=[]

def set_server(idx, v):
  while len(servers) <= idx:
    servers.append("")
  if isinstance(servers[idx], dict):
    servers[idx]['address']=v
  else:
    servers[idx]=v

if val:
  set_server(0, val)

dns['servers']=servers
cfg['dns']=dns

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_DNS_CONF}"
    die "Gagal update Primary DNS (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_DNS_CONF}" "${backup}" "dns primary"
}

xray_dns_set_secondary() {
  local val="$1"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_config "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers')
if not isinstance(servers, list):
  servers=[]

def set_server(idx, v):
  while len(servers) <= idx:
    servers.append("")
  if isinstance(servers[idx], dict):
    servers[idx]['address']=v
  else:
    servers[idx]=v

if val:
  if len(servers) == 0:
    # isi default primary jika kosong
    set_server(0, "1.1.1.1")
  set_server(1, val)

dns['servers']=servers
cfg['dns']=dns

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_DNS_CONF}"
    die "Gagal update Secondary DNS (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_DNS_CONF}" "${backup}" "dns secondary"
}

xray_dns_set_query_strategy() {
  local val="$1"
  local tmp backup

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_config "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

if val:
  dns['queryStrategy']=val

cfg['dns']=dns
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_DNS_CONF}"
    die "Gagal update Query Strategy (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_DNS_CONF}" "${backup}" "dns queryStrategy"
}

xray_dns_toggle_cache() {
  local tmp backup
  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_config "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}"
import json, sys

src, dst = sys.argv[1:3]
with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

cur=bool(dns.get('disableCache'))
dns['disableCache']=not cur

cfg['dns']=dns
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_DNS_CONF}"
    die "Gagal toggle DNS cache (rollback ke backup: ${backup})"
  }

  xray_restart_or_rollback_file "${XRAY_DNS_CONF}" "${backup}" "dns cache"
}

dns_show_status() {
  local primary secondary strategy cache
  primary="$(xray_dns_status_get | awk -F'=' '/^primary=/{print $2; exit}' 2>/dev/null || true)"
  secondary="$(xray_dns_status_get | awk -F'=' '/^secondary=/{print $2; exit}' 2>/dev/null || true)"
  strategy="$(xray_dns_status_get | awk -F'=' '/^strategy=/{print $2; exit}' 2>/dev/null || true)"
  cache="$(xray_dns_status_get | awk -F'=' '/^cache=/{print $2; exit}' 2>/dev/null || true)"

  if [[ "${cache}" == "on" ]]; then
    cache="ON"
  else
    cache="OFF"
  fi

  [[ -n "${primary}" ]] || primary="-"
  [[ -n "${secondary}" ]] || secondary="-"
  [[ -n "${strategy}" ]] || strategy="-"

  title
  echo "DNS Status"
  hr
  echo
  printf "Primary DNS     : %s\n" "${primary}"
  printf "Secondary DNS   : %s\n" "${secondary}"
  printf "Query Strategy  : %s\n" "${strategy}"
  printf "Cache           : %s\n" "${cache}"
  echo
  hr
  pause
}

dns_settings_menu() {
  while true; do
    title
    echo "4) Network Controls > DNS Settings"
    hr
    echo "  1) Set Primary DNS"
    echo "  2) Set Secondary DNS"
    echo "  3) Set Query Strategy"
    echo "  4) Toggle DNS Cache"
    echo "  5) Show DNS Status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Primary DNS (contoh 1.1.1.1) (atau kembali): " d
        if is_back_choice "${d}"; then
          continue
        fi
        d="$(echo "${d}" | tr -d '[:space:]')"
        [[ -n "${d}" ]] || { warn "Primary DNS kosong" ; pause ; continue ; }
        xray_dns_set_primary "${d}"
        log "Primary DNS updated"
        pause
        ;;
      2)
        read -r -p "Secondary DNS (contoh 8.8.8.8) (atau kembali): " d
        if is_back_choice "${d}"; then
          continue
        fi
        d="$(echo "${d}" | tr -d '[:space:]')"
        [[ -n "${d}" ]] || { warn "Secondary DNS kosong" ; pause ; continue ; }
        xray_dns_set_secondary "${d}"
        log "Secondary DNS updated"
        pause
        ;;
      3)
        read -r -p "Query Strategy (UseIP/UseIPv4/UseIPv6/PreferIPv4/PreferIPv6) (atau kembali): " qs
        if is_back_choice "${qs}"; then
          continue
        fi
        qs="$(echo "${qs}" | tr -d '[:space:]')"
        case "${qs}" in
          UseIP|UseIPv4|UseIPv6|PreferIPv4|PreferIPv6)
            xray_dns_set_query_strategy "${qs}"
            log "Query Strategy updated: ${qs}"
            pause
            ;;
          *)
            warn "Query Strategy tidak valid"
            pause
            ;;
        esac
        ;;
      4)
        xray_dns_toggle_cache
        log "DNS Cache toggled"
        pause
        ;;
      5) dns_show_status ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

dns_addons_menu() {
  while true; do
    title
    echo "4) Network Controls > DNS Add-ons"
    hr
    if [[ -f "${XRAY_DNS_CONF}" ]]; then
      echo "DNS conf: ${XRAY_DNS_CONF}"
      echo "Tip: gunakan editor untuk perubahan advanced (nano)."
      hr
      sed -n '1,200p' "${XRAY_DNS_CONF}" || true
      hr
    else
      warn "DNS conf tidak ditemukan: ${XRAY_DNS_CONF}"
      hr
    fi
    echo "  1) Open DNS config with nano"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        if have_cmd nano; then
          nano "${XRAY_DNS_CONF}"
          svc_restart xray || true
          if ! svc_wait_active xray 20; then
            warn "xray tidak aktif setelah edit manual DNS config."
            systemctl status xray --no-pager 2>/dev/null || true
          fi
          pause
        else
          warn "nano tidak tersedia"
          pause
        fi
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

network_diagnostics_menu() {
  while true; do
    title
    echo "4) Network Controls > Diagnostics"
    hr
    echo "  1) Show summary (routing/balancer/observatory)"
    echo "  2) Validate conf.d JSON (jq)"
    echo "  3) xray run -test -confdir (syntax check)"
    echo "  4) Show wireproxy + xray + nginx status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) network_show_summary ;;
      2)
        title
        echo "Validate JSON"
        hr
        check_xray_config_json || true
        hr
        pause
        ;;
      3)
        title
        echo "xray config test (confdir)"
        hr
        if have_cmd xray; then
          xray run -test -confdir "${XRAY_CONFDIR}" 2>&1 || true
        else
          warn "xray binary tidak ditemukan"
        fi
        hr
        pause
        ;;
      4)
        title
        echo "Service status (wireproxy, xray, nginx)"
        hr
        if svc_exists wireproxy; then
          systemctl status wireproxy --no-pager || true
        else
          warn "wireproxy.service tidak terdeteksi"
        fi
        hr
        systemctl status xray --no-pager || true
        hr
        systemctl status nginx --no-pager || true
        hr
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

network_menu() {
  while true; do
    title
    echo "4) Network Controls"
    hr
    echo "  1) Egress Mode & Balancer"
    echo "  2) WARP Controls"
    echo "  3) DNS Settings"
    echo "  4) DNS Advanced (Editor)"
    echo "  5) Diagnostics"
    echo "  0) Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) egress_menu_simple ;;
      2) warp_controls_menu ;;
      3) dns_settings_menu ;;
      4) dns_addons_menu ;;
      5) network_diagnostics_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

# -------------------------
# Speedtest
# -------------------------
speedtest_bin_get() {
  if have_cmd speedtest; then
    echo "speedtest"
    return 0
  fi
  if [[ -x /snap/bin/speedtest ]]; then
    echo "/snap/bin/speedtest"
    return 0
  fi
  echo ""
}

speedtest_run_now() {
  title
  echo "6) Speedtest > Run Speedtest"
  hr

  local speedtest_bin
  speedtest_bin="$(speedtest_bin_get)"
  if [[ -z "${speedtest_bin}" ]]; then
    warn "speedtest belum tersedia. Jalankan setup.sh untuk install speedtest via snap."
    hr
    pause
    return 0
  fi

  echo "Menjalankan: ${speedtest_bin} --accept-license --accept-gdpr"
  echo
  if ! "${speedtest_bin}" --accept-license --accept-gdpr; then
    warn "Speedtest gagal dijalankan."
  fi
  hr
  pause
}

speedtest_show_version() {
  title
  echo "6) Speedtest > Version"
  hr

  local speedtest_bin
  speedtest_bin="$(speedtest_bin_get)"
  if [[ -z "${speedtest_bin}" ]]; then
    warn "speedtest belum tersedia."
    hr
    pause
    return 0
  fi

  if ! "${speedtest_bin}" --version 2>/dev/null; then
    warn "Tidak bisa membaca versi speedtest."
  fi
  hr
  pause
}

speedtest_menu() {
  while true; do
    title
    echo "6) Speedtest"
    hr
    echo "  1) Run Speedtest (Ookla)"
    echo "  2) Show Speedtest Version"
    echo "  0) Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) speedtest_run_now ;;
      2) speedtest_show_version ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

# -------------------------
# Security
# - TLS & Certificate
# - Fail2ban Protection
# - System Hardening Status
# - Security Overview
# -------------------------
cert_openssl_info() {
  if ! have_cmd openssl; then
    warn "openssl tidak tersedia"
    return 1
  fi
  if [[ ! -f "${CERT_FULLCHAIN}" ]]; then
    warn "Cert tidak ditemukan: ${CERT_FULLCHAIN}"
    return 1
  fi
  openssl x509 -in "${CERT_FULLCHAIN}" -noout     -subject -issuer -serial -startdate -enddate -fingerprint -sha256 2>/dev/null || return 1
  return 0
}

cert_expiry_days_left() {
  # prints integer days left, or empty on error
  if ! have_cmd openssl; then
    echo ""
    return 0
  fi
  if [[ ! -f "${CERT_FULLCHAIN}" ]]; then
    echo ""
    return 0
  fi

  local end end_ts cur_ts diff
  end="$(openssl x509 -in "${CERT_FULLCHAIN}" -noout -enddate 2>/dev/null | sed -e 's/^notAfter=//')"
  if [[ -z "${end}" ]]; then
    echo ""
    return 0
  fi

  end_ts="$(date -d "${end}" +%s 2>/dev/null || true)"
  cur_ts="$(date +%s 2>/dev/null || true)"
  if [[ -z "${end_ts}" || -z "${cur_ts}" ]]; then
    echo ""
    return 0
  fi
  diff=$(( (end_ts - cur_ts) / 86400 ))
  echo "${diff}"
}

cert_menu_show_info() {
  title
  echo "TLS & Certificate > Show Certificate Info"
  hr
  if ! cert_openssl_info; then
    warn "Gagal membaca info sertifikat"
  fi
  hr
  pause
}

cert_menu_check_expiry() {
  title
  echo "TLS & Certificate > Check Expiry"
  hr
  local days
  days="$(cert_expiry_days_left)"
  if [[ -z "${days}" ]]; then
    warn "Tidak dapat menghitung masa berlaku TLS"
  else
    if (( days < 0 )); then
      echo "TLS Expiry : Expired"
    else
      echo "TLS Expiry : ${days} days"
    fi
  fi
  hr
  pause
}

acme_sh_path_get() {
  if [[ -x "/root/.acme.sh/acme.sh" ]]; then
    echo "/root/.acme.sh/acme.sh"
    return 0
  fi
  if have_cmd acme.sh; then
    command -v acme.sh
    return 0
  fi
  echo ""
}

cert_menu_renew() {
  title
  echo "TLS & Certificate > Renew Certificate"
  hr

  local acme
  acme="$(acme_sh_path_get)"
  if [[ -z "${acme}" ]]; then
    warn "acme.sh tidak ditemukan. Pastikan setup.sh sudah memasang acme.sh."
    hr
    pause
    return 0
  fi

  export PATH="/root/.acme.sh:${PATH}"
  local domain
  domain="$(detect_domain)"
  if [[ -z "${domain}" ]]; then
    warn "Domain aktif tidak terdeteksi."
    hr
    pause
    return 0
  fi

  echo "Domain terdeteksi: ${domain}"
  hr
  echo "Menjalankan acme.sh renew..."
  echo

  local renew_ok="false"
  local port80_conflict="false"
  local renew_log
  renew_log="$(mktemp)"

  if "${acme}" --cron --force 2>&1 | tee "${renew_log}"; then
    renew_ok="true"
  else
    if grep -Eqi "port 80 is already used|Please stop it first" "${renew_log}"; then
      port80_conflict="true"
    fi
  fi
  rm -f "${renew_log}" >/dev/null 2>&1 || true

  if [[ "${renew_ok}" != "true" ]]; then
    if [[ "${port80_conflict}" == "true" ]]; then
      warn "Terdeteksi konflik port 80. Menghentikan web service sementara untuk retry renew..."
      local -a stopped_services=()
      local svc
      for svc in nginx apache2 caddy lighttpd; do
        if svc_exists "${svc}" && svc_is_active "${svc}"; then
          stopped_services+=("${svc}")
          systemctl stop "${svc}" >/dev/null 2>&1 || true
        fi
      done

      if "${acme}" --renew -d "${domain}" --force 2>&1; then
        renew_ok="true"
      fi

      for svc in "${stopped_services[@]}"; do
        if svc_exists "${svc}"; then
          systemctl start "${svc}" >/dev/null 2>&1 || warn "Gagal restore service: ${svc}"
        fi
      done
    else
      warn "acme.sh --cron --force gagal, mencoba renew domain spesifik..."
      if "${acme}" --renew -d "${domain}" --force 2>&1; then
        renew_ok="true"
      fi
    fi
  fi

  if [[ "${renew_ok}" != "true" ]]; then
    warn "Renew gagal. Cek output di atas."
    hr
    pause
    return 0
  fi

  echo
  log "Renew certificate selesai (cek expiry untuk memastikan)."
  hr
  pause
}

cert_menu_reload_nginx() {
  title
  echo "TLS & Certificate > Reload Nginx"
  hr
  if ! svc_exists nginx; then
    warn "nginx.service tidak terdeteksi"
    hr
    pause
    return 0
  fi

  if systemctl reload nginx 2>/dev/null; then
    log "nginx reload: OK"
  else
    warn "nginx reload gagal, mencoba restart..."
    systemctl restart nginx 2>/dev/null || true
    if svc_is_active nginx; then
      log "nginx restart: OK"
    else
      warn "nginx masih tidak aktif"
    fi
  fi
  hr
  pause
}

security_tls_menu() {
  while true; do
    title
    echo "TLS & Certificate"
    hr
    echo "  1) Show Certificate Info"
    echo "  2) Check Expiry"
    echo "  3) Renew Certificate"
    echo "  4) Reload Nginx"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) cert_menu_show_info ;;
      2) cert_menu_check_expiry ;;
      3) cert_menu_renew ;;
      4) cert_menu_reload_nginx ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

fail2ban_client_ready() {
  if ! have_cmd fail2ban-client; then
    return 1
  fi
  return 0
}

fail2ban_jails_list_get() {
  # prints jail names one per line
  if ! fail2ban_client_ready; then
    return 0
  fi
  local out line
  out="$(fail2ban-client status 2>/dev/null || true)"
  [[ -n "${out}" ]] || return 0

  # Format output fail2ban bisa memakai prefix "|-" atau "`-" dan separator
  # setelah ":" bisa berupa spasi/tab, jadi parsing harus longgar.
  line="$(printf '%s\n' "${out}" | sed -nE 's/.*[Jj]ail list[[:space:]]*:[[:space:]]*//p' | head -n1)"
  line="${line//$'\r'/}"
  [[ -n "${line}" ]] || return 0

  printf '%s\n' "${line}" \
    | tr ',' '\n' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | grep -E '.+' || true
}

fail2ban_jail_banned_counts_get() {
  # args: jail -> prints: current|total
  local jail="$1"
  if ! fail2ban_client_ready; then
    echo "0|0"
    return 0
  fi
  local out cur tot
  out="$(fail2ban-client status "${jail}" 2>/dev/null || true)"
  # Output fail2ban bisa memakai tab/spasi campuran setelah ":".
  # Parsing dibuat longgar agar "Currently banned" dan "Total banned" selalu terbaca.
  cur="$(printf '%s\n' "${out}" | sed -nE 's/.*Currently banned:[[:space:]]*([0-9]+).*/\1/p' | head -n1)"
  tot="$(printf '%s\n' "${out}" | sed -nE 's/.*Total banned:[[:space:]]*([0-9]+).*/\1/p' | head -n1)"
  [[ -n "${cur}" ]] || cur="0"
  [[ -n "${tot}" ]] || tot="0"
  echo "${cur}|${tot}"
}

fail2ban_total_banned_get() {
  if ! fail2ban_client_ready; then
    echo "0"
    return 0
  fi
  local total=0 jail counts cur
  while IFS= read -r jail; do
    counts="$(fail2ban_jail_banned_counts_get "${jail}")"
    cur="${counts%%|*}"
    [[ "${cur}" =~ ^[0-9]+$ ]] || cur=0
    total=$((total + cur))
  done < <(fail2ban_jails_list_get)
  echo "${total}"
}

fail2ban_menu_show_jail_status() {
  title
  echo "Fail2ban Protection > Show Jail Status"
  hr

  if ! svc_exists fail2ban; then
    warn "fail2ban.service tidak terdeteksi"
  fi

  if ! fail2ban_client_ready; then
    warn "fail2ban-client tidak tersedia"
    hr
    pause
    return 0
  fi

  fail2ban-client status 2>/dev/null || true
  hr

  local jails=()
  while IFS= read -r j; do
    [[ -n "${j}" ]] && jails+=("${j}")
  done < <(fail2ban_jails_list_get)

  if (( ${#jails[@]} == 0 )); then
    warn "Tidak ada jail yang terdeteksi."
    hr
    pause
    return 0
  fi

  printf "%-30s %-12s %-12s\n" "JAIL" "BANNED" "TOTAL"
  printf "%-30s %-12s %-12s\n" "------------------------------" "------------" "------------"
  local jail counts cur tot
  for jail in "${jails[@]}"; do
    counts="$(fail2ban_jail_banned_counts_get "${jail}")"
    cur="${counts%%|*}"
    tot="${counts##*|}"
    printf "%-30s %-12s %-12s\n" "${jail}" "${cur}" "${tot}"
  done
  hr
  pause
}

fail2ban_menu_show_banned_ip() {
  title
  echo "Fail2ban Protection > Show Banned IP"
  hr
  if ! fail2ban_client_ready; then
    warn "fail2ban-client tidak tersedia"
    hr
    pause
    return 0
  fi

  local jails=()
  while IFS= read -r j; do
    [[ -n "${j}" ]] && jails+=("${j}")
  done < <(fail2ban_jails_list_get)

  if (( ${#jails[@]} == 0 )); then
    warn "Tidak ada jail yang terdeteksi."
    hr
    pause
    return 0
  fi

  local jail ips
  for jail in "${jails[@]}"; do
    echo "[${jail}]"
    ips="$(fail2ban-client get "${jail}" banip 2>/dev/null || true)"
    if [[ -z "${ips}" ]]; then
      echo "  (kosong)"
    else
      echo "${ips}" | tr ' ' '\n' | sed -E 's/^/  - /'
    fi
    echo
  done
  hr
  pause
}

fail2ban_menu_unban_ip() {
  title
  echo "Fail2ban Protection > Unban IP"
  hr
  if ! fail2ban_client_ready; then
    warn "fail2ban-client tidak tersedia"
    hr
    pause
    return 0
  fi

  local jails=()
  while IFS= read -r j; do
    [[ -n "${j}" ]] && jails+=("${j}")
  done < <(fail2ban_jails_list_get)

  if (( ${#jails[@]} == 0 )); then
    warn "Tidak ada jail yang terdeteksi."
    hr
    pause
    return 0
  fi

  echo "Daftar jail:"
  local i
  for i in "${!jails[@]}"; do
    printf "  %d) %s\n" "$((i + 1))" "${jails[$i]}"
  done
  echo "  0) Back"
  hr

  read -r -p "Pilih jail (1-${#jails[@]}/0): " c
  if is_back_choice "${c}"; then
    return 0
  fi
  [[ "${c}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
  if (( c < 1 || c > ${#jails[@]} )); then
    warn "Pilihan jail di luar range"
    pause
    return 0
  fi
  local jail
  jail="${jails[$((c - 1))]}"

  read -r -p "IP yang ingin di-unban (atau kembali): " ip
  if is_back_choice "${ip}"; then
    return 0
  fi
  if [[ -z "${ip}" ]]; then
    warn "IP kosong"
    pause
    return 0
  fi

  if fail2ban-client set "${jail}" unbanip "${ip}" 2>/dev/null; then
    log "Unban sukses: ${ip} (${jail})"
  else
    warn "Unban gagal. Pastikan jail & IP valid."
  fi
  hr
  pause
}

fail2ban_menu_restart() {
  title
  echo "Fail2ban Protection > Restart Fail2ban"
  hr
  if ! svc_exists fail2ban; then
    warn "fail2ban.service tidak terdeteksi"
    hr
    pause
    return 0
  fi

  systemctl restart fail2ban 2>/dev/null || true
  if svc_is_active fail2ban; then
    log "fail2ban: active"
  else
    warn "fail2ban: inactive"
  fi
  hr
  pause
}

security_fail2ban_menu() {
  while true; do
    title
    echo "Fail2ban Protection"
    hr
    echo "  1) Show Jail Status"
    echo "  2) Show Banned IP"
    echo "  3) Unban IP"
    echo "  4) Restart Fail2ban"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) fail2ban_menu_show_jail_status ;;
      2) fail2ban_menu_show_banned_ip ;;
      3) fail2ban_menu_unban_ip ;;
      4) fail2ban_menu_restart ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

hardening_check_bbr() {
  title
  echo "System Hardening Status > Check BBR"
  hr
  if ! have_cmd sysctl; then
    warn "sysctl tidak tersedia"
    hr
    pause
    return 0
  fi

  local cc qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"

  echo "tcp_congestion_control : ${cc:-"-"}"
  echo "default_qdisc          : ${qdisc:-"-"}"
  echo
  if [[ "${cc}" == "bbr" ]]; then
    echo "BBR : Enabled"
  else
    echo "BBR : Disabled"
  fi
  hr
  pause
}

swap_status_pretty_get() {
  # prints: "<n>GB Active" or "Disabled"
  if ! have_cmd free; then
    echo "Unknown"
    return 0
  fi
  local bytes
  bytes="$(free -b 2>/dev/null | awk '/^Swap:/ {print $2; exit}' || true)"
  [[ -n "${bytes}" ]] || bytes="0"
  if [[ ! "${bytes}" =~ ^[0-9]+$ ]]; then
    bytes="0"
  fi
  if (( bytes <= 0 )); then
    echo "Disabled"
    return 0
  fi
  local gb
  gb=$(( (bytes + 1024**3 - 1) / (1024**3) ))
  echo "${gb}GB Active"
}

hardening_check_swap() {
  title
  echo "System Hardening Status > Check Swap"
  hr
  if ! have_cmd free; then
    warn "free tidak tersedia"
    hr
    pause
    return 0
  fi

  free -h || true
  hr
  echo "Swap : $(swap_status_pretty_get)"
  hr
  pause
}

hardening_check_ulimit() {
  title
  echo "System Hardening Status > Check Ulimit"
  hr
  local cur
  cur="$(ulimit -n 2>/dev/null || echo "-")"
  echo "Shell ulimit -n : ${cur}"
  echo
  if svc_exists xray; then
    local lim
    lim="$(systemctl show -p LimitNOFILE --value xray 2>/dev/null || true)"
    echo "xray LimitNOFILE: ${lim:-"-"}"
  fi
  hr
  pause
}

hardening_check_chrony() {
  title
  echo "System Hardening Status > Check Chrony"
  hr
  if svc_exists chrony; then
    echo "$(svc_status_line chrony)"
    hr
    systemctl status chrony --no-pager || true
  elif svc_exists chronyd; then
    echo "$(svc_status_line chronyd)"
    hr
    systemctl status chronyd --no-pager || true
  else
    warn "chrony/chronyd service tidak terdeteksi"
  fi
  hr
  pause
}

security_hardening_menu() {
  while true; do
    title
    echo "System Hardening Status"
    hr
    echo "  1) Check BBR"
    echo "  2) Check Swap"
    echo "  3) Check Ulimit"
    echo "  4) Check Chrony"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) hardening_check_bbr ;;
      2) hardening_check_swap ;;
      3) hardening_check_ulimit ;;
      4) hardening_check_chrony ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

bbr_enabled_bool() {
  if ! have_cmd sysctl; then
    return 1
  fi
  local cc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  [[ "${cc}" == "bbr" ]]
}

fail2ban_jail_active_bool() {
  # args: jail name
  local jail="$1"
  if ! fail2ban_client_ready; then
    return 1
  fi
  fail2ban-client status "${jail}" >/dev/null 2>&1
}

security_overview_menu() {
  title
  echo "Security Overview"
  hr

  local tls_days tls_line
  tls_days="$(cert_expiry_days_left)"
  if [[ -z "${tls_days}" ]]; then
    tls_line="-"
  else
    if (( tls_days < 0 )); then
      tls_line="Expired"
    else
      tls_line="${tls_days} days"
    fi
  fi

  local f2b_line banned ssh_line nginx_line rec_line
  if svc_is_active fail2ban 2>/dev/null; then
    f2b_line="Active"
  else
    f2b_line="Inactive"
  fi

  banned="$(fail2ban_total_banned_get)"
  [[ -n "${banned}" ]] || banned="0"

  if fail2ban_jail_active_bool sshd; then
    ssh_line="Active"
  else
    ssh_line="Inactive"
  fi

  if fail2ban_jail_active_bool nginx-bad-request-access || fail2ban_jail_active_bool nginx-bad-request-error; then
    nginx_line="Active"
  else
    nginx_line="Inactive"
  fi

  if fail2ban_jail_active_bool recidive; then
    rec_line="Active"
  else
    rec_line="Inactive"
  fi

  local bbr_line
  if bbr_enabled_bool; then
    bbr_line="Enabled"
  else
    bbr_line="Disabled"
  fi

  local swap_line
  swap_line="$(swap_status_pretty_get)"

  echo
  echo "TLS Expiry        : ${tls_line}"
  echo "Fail2ban          : ${f2b_line}"
  echo "Banned IP         : ${banned}"
  echo "SSH Protection    : ${ssh_line}"
  echo "Nginx Protection  : ${nginx_line}"
  echo "Recidive          : ${rec_line}"
  echo "BBR               : ${bbr_line}"
  echo "Swap              : ${swap_line}"
  hr
  pause
}

fail2ban_menu() {
  while true; do
    title
    echo "7) Security"
    hr
    echo "  1) TLS & Certificate"
    echo "  2) Fail2ban Protection"
    echo "  3) System Hardening Status"
    echo "  4) Security Overview"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) security_tls_menu ;;
      2) security_fail2ban_menu ;;
      3) security_hardening_menu ;;
      4) security_overview_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}
# -------------------------
# Wireproxy helpers
# -------------------------
wireproxy_status_menu() {
  title
  echo "8) Maintenance > Wireproxy (WARP) Status"
  hr

  if ! svc_exists wireproxy; then
    warn "wireproxy.service tidak ditemukan. Pastikan setup.sh sudah dijalankan."
    hr
    pause
    return 0
  fi

  # Status service
  if svc_is_active wireproxy; then
    log "wireproxy : active ✅"
  else
    warn "wireproxy : INACTIVE ❌"
  fi

  # PID & uptime (best-effort)
  local pid uptime_str
  pid="$(systemctl show -p MainPID --value wireproxy 2>/dev/null || true)"
  if [[ -n "${pid}" && "${pid}" != "0" ]]; then
    log "PID       : ${pid}"
    uptime_str="$(ps -o etime= -p "${pid}" 2>/dev/null | tr -d ' ' || true)"
    [[ -n "${uptime_str}" ]] && log "Uptime    : ${uptime_str}"
  fi

  # Cek SOCKS5 port 40000 (wireproxy bind address)
  hr
  if have_cmd ss; then
    if ss -lntp 2>/dev/null | grep -q ':40000'; then
      log "Port 40000 (SOCKS5) : LISTENING ✅"
    else
      warn "Port 40000 (SOCKS5) : NOT listening ❌"
    fi
  else
    warn "ss tidak tersedia, tidak bisa cek port 40000"
  fi

  # Cek konektivitas WARP via wireproxy (opsional, timeout singkat)
  hr
  log "Test koneksi via WARP proxy (curl --socks5 127.0.0.1:40000, timeout 5s)..."
  if have_cmd curl; then
    local warp_ip
    warp_ip="$(curl -fsSL --socks5 127.0.0.1:40000 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${warp_ip}" ]]; then
      log "WARP outbound IP : ${warp_ip} ✅"
    else
      warn "WARP outbound IP : gagal (wireproxy mungkin tidak terhubung ke WARP)"
    fi
  else
    warn "curl tidak tersedia, skip test koneksi WARP"
  fi

  hr
  echo "Konfigurasi : /etc/wireproxy/config.conf"
  echo "Log service :"
  journalctl -u wireproxy --no-pager -n 30 2>/dev/null || true
  hr
  pause
}

wireproxy_restart_menu() {
  title
  echo "8) Maintenance > Restart Wireproxy (WARP)"
  hr

  if ! svc_exists wireproxy; then
    warn "wireproxy.service tidak ditemukan."
    hr
    pause
    return 0
  fi

  svc_restart wireproxy
  hr
  pause
}

daemon_status_menu() {
  title
  echo "8) Maintenance > Daemon Status"
  hr

  local daemons=("xray" "nginx" "xray-expired" "xray-quota" "xray-limit-ip" "xray-speed" "wireproxy")
  local d
  for d in "${daemons[@]}"; do
    if svc_exists "${d}"; then
      echo "$(svc_status_line "${d}")"
    else
      echo "N/A  - ${d} (not installed)"
    fi
  done
  hr

  echo "Log terakhir daemon:"
  hr
  for d in "xray-expired" "xray-quota" "xray-limit-ip" "xray-speed"; do
    if svc_exists "${d}"; then
      echo "--- ${d} (5 baris terakhir) ---"
      journalctl -u "${d}" --no-pager -n 5 2>/dev/null || true
    fi
  done
  hr

  echo "  1) Restart xray-expired"
  echo "  2) Restart xray-quota"
  echo "  3) Restart xray-limit-ip"
  echo "  4) Restart xray-speed"
  echo "  5) Restart semua daemon (xray-expired + xray-quota + xray-limit-ip + xray-speed)"
  echo "  0) Back"
  hr
  if ! read -r -p "Pilih: " c; then
    echo
    return 0
  fi
  case "${c}" in
    1)
      if svc_exists xray-expired; then svc_restart xray-expired ; else warn "xray-expired tidak terpasang" ; fi
      pause
      ;;
    2)
      if svc_exists xray-quota; then svc_restart xray-quota ; else warn "xray-quota tidak terpasang" ; fi
      pause
      ;;
    3)
      if svc_exists xray-limit-ip; then svc_restart xray-limit-ip ; else warn "xray-limit-ip tidak terpasang" ; fi
      pause
      ;;
    4)
      if svc_exists xray-speed; then svc_restart xray-speed ; else warn "xray-speed tidak terpasang" ; fi
      pause
      ;;
    5)
      for d in xray-expired xray-quota xray-limit-ip xray-speed; do
        if svc_exists "${d}"; then
          svc_restart "${d}"
        else
          warn "${d} tidak terpasang, skip"
        fi
      done
      pause
      ;;
    0|kembali|k|back|b) return 0 ;;
    *) warn "Pilihan tidak valid" ; sleep 1 ;;
  esac
}

# -------------------------
# Maintenance
# -------------------------
maintenance_menu() {
  while true; do
    title
    echo "8) Maintenance"
    hr
    echo "  1. Restart xray"
    echo "  2. Restart nginx"
    echo "  3. Restart all (xray+nginx)"
    echo "  4. View xray logs (tail)"
    echo "  5. View nginx logs (tail)"
    echo "  6. Wireproxy (WARP) Status & Monitor"
    echo "  7. Restart wireproxy (WARP)"
    echo "  8. Daemon Status & Restart (xray-expired / xray-quota / xray-limit-ip / xray-speed)"
    echo "  0. Back (kembali)"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) svc_restart xray ; pause ;;
      2) svc_restart nginx ; pause ;;
      3) svc_restart xray ; svc_restart nginx ; pause ;;
      4) title ; tail_logs xray 160 ; hr ; pause ;;
      5) title ; tail_logs nginx 160 ; hr ; pause ;;
      6) wireproxy_status_menu ;;
      7) wireproxy_restart_menu ;;
      8) daemon_status_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

# -------------------------
# Main menu
# -------------------------
main_menu() {
  while true; do
    title
    main_menu_info_header_print
    echo "Main Menu"
    hr
    echo "  1) Status & Diagnostics"
    echo "  2) User Management"
    echo "  3) Quota & Access Control"
    echo "  4) Network Controls"
    echo "  5) Domain Control"
    echo "  6) Speedtest"
    echo "  7) Security"
    echo "  8) Maintenance"
    echo "  0) Exit (kembali)"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      exit 0
    fi
    case "${c}" in
      1) run_action "Status & Diagnostics" sanity_check_now ;;
      2) run_action "User Management" user_menu ;;
      3) run_action "Quota & Access Control" quota_menu ;;
      4) run_action "Network Controls" network_menu ;;
      5) run_action "Domain Control" domain_control_menu ;;
      6) run_action "Speedtest" speedtest_menu ;;
      7) run_action "Security" fail2ban_menu ;;
      8) run_action "Maintenance" maintenance_menu ;;
      0|kembali|k|back|b) exit 0 ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

main() {
  need_root
  init_runtime_dirs
  ensure_account_quota_dirs
  quota_migrate_dates_to_dateonly
  main_menu
}

main "$@"
