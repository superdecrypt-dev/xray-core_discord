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
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
CERT_DIR="/opt/cert"
CERT_FULLCHAIN="${CERT_DIR}/fullchain.pem"
CERT_PRIVKEY="${CERT_DIR}/privkey.pem"
CLIENT_INFO="/root/xray-client-info.txt"

# Account store (read-only source for Menu 2)
ACCOUNT_ROOT="/opt/account"
ACCOUNT_PROTO_DIRS=("vless" "vmess" "trojan")

# Quota metadata store (Menu 2 add/delete)
QUOTA_ROOT="/opt/quota"
QUOTA_PROTO_DIRS=("vless" "vmess" "trojan")

# Direktori kerja untuk operasi aman (atomic write)
WORK_DIR="/var/lib/xray-manage"
mkdir -p "${WORK_DIR}"
chmod 700 "${WORK_DIR}"

# Direktori laporan/export
REPORT_DIR="/var/log/xray-manage"
mkdir -p "${REPORT_DIR}"
chmod 700 "${REPORT_DIR}"

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
  # Ambil public IP dari ip-api.com (best-effort), fallback ke detect_public_ip
  local ip=""
  if have_cmd curl; then
    ip="$(curl -fsSL --max-time 5 "https://ip-api.com/line/?fields=query" 2>/dev/null || true)"
  elif have_cmd wget; then
    ip="$(wget -qO- --timeout=5 "https://ip-api.com/line/?fields=query" 2>/dev/null || true)"
  fi

  if [[ -z "${ip}" || ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    warn "Gagal fetch IP dari ip-api.com, fallback ke deteksi lokal"
    ip="$(detect_public_ip)"
  fi
  echo "${ip}"
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
svc_is_active() {
  local svc="$1"
  systemctl is-active --quiet "${svc}"
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
  systemctl restart "${svc}"
  if svc_is_active "${svc}"; then
    log "Restart sukses: ${svc}"
  else
    warn "Restart dilakukan, tapi status masih tidak aktif: ${svc}"
  fi
}

svc_restart_if_exists() {
  local svc="$1"
  if systemctl cat "${svc}" >/dev/null 2>&1; then
    systemctl restart "${svc}" >/dev/null 2>&1 || true
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

account_collect_files() {
  ACCOUNT_FILES=()
  ACCOUNT_FILE_PROTOS=()

  local proto dir f u key
  declare -A seen=()

  for proto in "${ACCOUNT_PROTO_DIRS[@]}"; do
    dir="${ACCOUNT_ROOT}/${proto}"
    [[ -d "${dir}" ]] || continue
    while IFS= read -r -d '' f; do
      u="$(account_parse_username_from_file "${f}" "${proto}")"
      key="${proto}:${u}"
      if [[ -n "${seen[${key}]:-}" ]]; then
        continue
      fi
      seen["${key}"]=1
      ACCOUNT_FILES+=("${f}")
      ACCOUNT_FILE_PROTOS+=("${proto}")
    done < <(find "${dir}" -maxdepth 1 -type f -name '*.txt' -print0 2>/dev/null | sort -z)
  done
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
  local qf="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  if [[ ! -f "${qf}" ]]; then
    qf="${QUOTA_ROOT}/${proto}/${username}.json"
  fi
  if [[ ! -f "${qf}" ]]; then
    echo "-|-|-|-|-"
    return 0
  fi

  python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|-|-|-|-")
  raise SystemExit(0)

ql=int(d.get("quota_limit") or 0)
quota_gb=int(round(ql/(1024**3))) if ql else 0
expired=d.get("expired_at") or "-"
created=d.get("created_at") or "-"
st=d.get("status") or {}
ip_en=bool(st.get("ip_limit_enabled"))
ip_lim=int(st.get("ip_limit") or 0)
print(f"{quota_gb}|{expired}|{created}|{str(ip_en).lower()}|{ip_lim}")
PY
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

    printf "%-4s %-8s %-18s %-10s %-19s %-7s\n" "$((i + 1))" "${proto}" "${username}" "${quota_gb} GB" "${expired}" "${ip_show}"
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

  local n f
  read -r -p "Masukkan NO untuk view (atau kembali): " n
  if is_back_choice "${n}"; then
    return 0
  fi
  [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
  if (( n < 1 || n > ${#ACCOUNT_FILES[@]} )); then
    warn "NO di luar range"
    pause
    return 0
  fi

  f="${ACCOUNT_FILES[$((n - 1))]}"
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

  local matches=() proto dir
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
  if nginx -t; then
    log "nginx -t: OK"
  else
    die "nginx -t: GAGAL"
  fi
}

check_xray_config_json() {
  if ! have_cmd jq; then
    warn "jq tidak tersedia, lewati validasi JSON"
    return 0
  fi

  local ok=1 f
  for f in     "${XRAY_LOG_CONF}"     "${XRAY_API_CONF}"     "${XRAY_DNS_CONF}"     "${XRAY_INBOUNDS_CONF}"     "${XRAY_OUTBOUNDS_CONF}"     "${XRAY_ROUTING_CONF}"     "${XRAY_POLICY_CONF}"     "${XRAY_STATS_CONF}"; do
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

  check_files || true
  hr
  check_nginx_config
  check_xray_config_json
  check_tls_expiry
  hr

  echo "Listeners (ringkas):"
  show_listeners_compact
  hr
  echo "[OK] Sanity check selesai (lihat WARN bila ada)."
  pause
}

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



xray_add_client() {
  # args: protocol username uuid_or_pass
  local proto="$1"
  local username="$2"
  local cred="$3"

  local email="${username}@${proto}"
  need_python3

  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || die "Xray inbounds conf tidak ditemukan: ${XRAY_INBOUNDS_CONF}"
  ensure_path_writable "${XRAY_INBOUNDS_CONF}"

  local backup tmp
  backup="$(xray_backup_config "${XRAY_INBOUNDS_CONF}")"
  tmp="${WORK_DIR}/10-inbounds.json.tmp"

  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${tmp}" "${proto}" "${email}" "${cred}"
import json, sys, uuid
src, dst, proto, email, cred = sys.argv[1:6]

with open(src, 'r', encoding='utf-8') as f:
  cfg=json.load(f)

inbounds = cfg.get('inbounds', [])
if not isinstance(inbounds, list):
  raise SystemExit("Invalid config: inbounds is not a list")

# Check existing username in matching protocol clients
def iter_clients_for_protocol(p):
  for ib in inbounds:
    if ib.get('protocol') != p:
      continue
    st = ib.get('settings') or {}
    clients = st.get('clients')
    if isinstance(clients, list):
      for c in clients:
        yield c

for c in iter_clients_for_protocol(proto):
  if c.get('email') == email:
    raise SystemExit(f"user sudah ada di config untuk {proto}: {email}")

# Build client object by protocol
if proto in ('vless','vmess'):
  client = {'id': cred, 'email': email}
  # Many configs expect flow only for vless; we keep minimal.
elif proto == 'trojan':
  client = {'password': cred, 'email': email}
else:
  raise SystemExit("Unsupported protocol: " + proto)

updated=False
for ib in inbounds:
  if ib.get('protocol') != proto:
    continue
  st = ib.setdefault('settings', {})
  clients = st.get('clients')
  if clients is None:
    st['clients']=[]
    clients = st['clients']
  if not isinstance(clients, list):
    continue
  clients.append(client)
  updated=True

if not updated:
  raise SystemExit(f"Tidak menemukan inbound protocol {proto} dengan settings.clients")

with open(dst, 'w', encoding='utf-8') as f:
  json.dump(cfg, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_INBOUNDS_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_INBOUNDS_CONF}"
    die "Gagal menulis config (rollback ke backup: ${backup})"
  }

  # restart xray to apply
  svc_restart xray || true
  if ! svc_is_active xray; then
    cp -a "${backup}" "${XRAY_INBOUNDS_CONF}"
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

  local backup_inb backup_rt tmp_inb tmp_rt
  backup_inb="$(xray_backup_config "${XRAY_INBOUNDS_CONF}")"
  backup_rt="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp_inb="${WORK_DIR}/10-inbounds.json.tmp"
  tmp_rt="${WORK_DIR}/30-routing.json.tmp"

  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${XRAY_ROUTING_CONF}" "${tmp_inb}" "${tmp_rt}" "${proto}" "${email}"
import json, os, sys
inb_src, rt_src, inb_dst, rt_dst, proto, email = sys.argv[1:7]

with open(inb_src, 'r', encoding='utf-8') as f:
  inb_cfg = json.load(f)
with open(rt_src, 'r', encoding='utf-8') as f:
  rt_cfg = json.load(f)

inbounds = inb_cfg.get('inbounds', [])
if not isinstance(inbounds, list):
  raise SystemExit("Invalid inbounds config: inbounds is not a list")

removed = 0
for ib in inbounds:
  if ib.get('protocol') != proto:
    continue
  st = ib.get('settings') or {}
  clients = st.get('clients')
  if not isinstance(clients, list):
    continue
  before = len(clients)
  clients[:] = [c for c in clients if c.get('email') != email]
  removed += (before - len(clients))
  st['clients'] = clients
  ib['settings'] = st

if removed == 0:
  raise SystemExit(f"Tidak menemukan user untuk dihapus: {email} ({proto})")

routing = (rt_cfg.get('routing') or {})
rules = routing.get('rules')
if isinstance(rules, list):
  markers = {"dummy-block-user","dummy-quota-user","dummy-limit-user"}
  for r in rules:
    if not isinstance(r, dict):
      continue
    if r.get('outboundTag') != 'blocked':
      continue
    u = r.get('user')
    if not isinstance(u, list):
      continue
    if not any(m in u for m in markers):
      continue
    r['user'] = [x for x in u if x != email]
  routing['rules'] = rules
  rt_cfg['routing'] = routing

with open(inb_dst, 'w', encoding='utf-8') as f:
  json.dump(inb_cfg, f, ensure_ascii=False, indent=2)
  f.write("\n")
with open(rt_dst, 'w', encoding='utf-8') as f:
  json.dump(rt_cfg, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY

  xray_write_file_atomic "${XRAY_INBOUNDS_CONF}" "${tmp_inb}" || {
    cp -a "${backup_inb}" "${XRAY_INBOUNDS_CONF}"
    cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    die "Gagal menulis inbounds conf (rollback ke backup)."
  }

  xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp_rt}" || {
    cp -a "${backup_inb}" "${XRAY_INBOUNDS_CONF}"
    cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    die "Gagal menulis routing conf (rollback ke backup)."
  }

  svc_restart xray || true
  if ! svc_is_active xray; then
    cp -a "${backup_inb}" "${XRAY_INBOUNDS_CONF}"
    cp -a "${backup_rt}" "${XRAY_ROUTING_CONF}"
    systemctl restart xray || true
    die "xray tidak aktif setelah delete user. Config di-rollback ke backup."
  fi
}

xray_routing_set_user_in_marker() {
  # args: marker email on|off
  local marker="$1"
  local email="$2"
  local state="$3"

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  local backup tmp
  backup="$(xray_backup_config "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  local out changed
  out="$(python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${marker}" "${email}" "${state}"
import json, sys
src, dst, marker, email, state = sys.argv[1:6]

with open(src, 'r', encoding='utf-8') as f:
  cfg = json.load(f)

routing = cfg.get('routing') or {}
rules = routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules is not a list")

target = None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != 'blocked':
    continue
  u = r.get('user')
  if not isinstance(u, list):
    continue
  if marker in u:
    target = r
    break

if target is None:
  raise SystemExit(f"Tidak menemukan routing rule outboundTag=blocked dengan marker: {marker}")

users = target.get('user') or []
if not isinstance(users, list):
  users = []

# pastikan marker selalu ada dan di posisi awal
if marker not in users:
  users.insert(0, marker)
else:
  users = [marker] + [x for x in users if x != marker]

changed = False
if state == 'on':
  if email not in users:
    users.append(email)
    changed = True
elif state == 'off':
  new_users = [x for x in users if x != email]
  if new_users != users:
    users = new_users
    changed = True
else:
  raise SystemExit("state harus 'on' atau 'off'")

target['user'] = users
routing['rules'] = rules
cfg['routing'] = routing

if changed:
  with open(dst, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
    f.write("\n")

print("changed=1" if changed else "changed=0")
PY
)" || {
    cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    die "Gagal memproses routing: ${XRAY_ROUTING_CONF}"
  }

  changed="$(printf '%s\n' "${out}" | tail -n 1 | awk -F'=' '/^changed=/{print $2; exit}')"
  if [[ "${changed}" != "1" ]]; then
    return 0
  fi

  xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
    cp -a "${backup}" "${XRAY_ROUTING_CONF}"
    die "Gagal menulis routing (rollback ke backup: ${backup})"
  }

  svc_restart xray || true
  if ! svc_is_active xray; then
    cp -a "${backup}" "${XRAY_ROUTING_CONF}"
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

write_account_artifacts() {
  # args: protocol username cred quota_bytes days ip_limit_enabled ip_limit_value
  local proto="$1"
  local username="$2"
  local cred="$3"
  local quota_bytes="$4"
  local days="$5"
  local ip_enabled="$6"
  local ip_limit="$7"

  ensure_account_quota_dirs
  need_python3

  local domain ip created expired
  domain="$(detect_domain)"
  ip="$(detect_public_ip_ipapi)"
  created="$(now_ts)"
  expired="$(date -d "+${days} days" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')"

  local acc_file quota_file
  acc_file="${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"
  quota_file="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"

  # Extract endpoints from xray config
  local endpoints
  endpoints="$(xray_extract_endpoints "${proto}" || true)"

  python3 - <<'PY' "${acc_file}" "${quota_file}" "${domain}" "${ip}" "${username}" "${proto}" "${cred}" "${quota_bytes}" "${created}" "${expired}" "${days}" "${ip_enabled}" "${ip_limit}" "${endpoints}"
import sys, json, base64, urllib.parse, datetime
acc_file, quota_file, domain, ip, username, proto, cred, quota_bytes, created_at, expired_at, days, ip_enabled, ip_limit, endpoints = sys.argv[1:15]
quota_bytes=int(quota_bytes)
days=int(float(days)) if str(days).strip() else 0
ip_enabled = str(ip_enabled).lower() in ("1","true","yes","y","on")
try:
  ip_limit_int=int(ip_limit)
except Exception:
  ip_limit_int=0

# Parse endpoints lines: network|value
ep={}
for line in (endpoints or "").splitlines():
  if "|" not in line:
    continue
  net,val=line.split("|",1)
  if net and net not in ep:
    ep[net]=val


# Override endpoints dengan path publik standar
PUBLIC = {
  "vless": {"ws": "/vless-ws", "httpupgrade": "/vless-hup", "grpc": "vless-grpc"},
  "vmess": {"ws": "/vmess-ws", "httpupgrade": "/vmess-hup", "grpc": "vmess-grpc"},
  "trojan": {"ws": "/trojan-ws", "httpupgrade": "/trojan-hup", "grpc": "trojan-grpc"},
}
for k,v in (PUBLIC.get(proto) or {}).items():
  ep[k]=v


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
for net in ("ws","httpupgrade","grpc"):
  if net not in ep:
    continue
  val=ep.get(net,"")
  if proto=="vless":
    links[net]=vless_link(net,val)
  elif proto=="vmess":
    links[net]=vmess_link(net,val)
  elif proto=="trojan":
    links[net]=trojan_link(net,val)

quota_gb = quota_bytes/(1024**3) if quota_bytes else 0

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
lines.append(f"Quota Limit : {quota_gb:.0f} GB")
lines.append(f"Expired     : {days} days")
lines.append(f"Valid Until : {expired_at}")
lines.append(f"Created     : {created_at}")
lines.append(f"IP Limit    : {'ON' if ip_enabled else 'OFF'}" + (f" ({ip_limit_int})" if ip_enabled else ""))
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
  "quota_used": 0,
  "created_at": created_at,
  "expired_at": expired_at,
  "status": {
    "manual_block": False,
    "quota_exhausted": False,
    "ip_limit_enabled": ip_enabled,
    "ip_limit": ip_limit_int if ip_enabled else 0,
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


delete_account_artifacts() {
  # args: protocol username
  local proto="$1"
  local username="$2"

  local acc_file acc_file_legacy quota_file quota_file_legacy
  acc_file="${ACCOUNT_ROOT}/${proto}/${username}@${proto}.txt"
  acc_file_legacy="${ACCOUNT_ROOT}/${proto}/${username}.txt"
  quota_file="${QUOTA_ROOT}/${proto}/${username}@${proto}.json"
  quota_file_legacy="${QUOTA_ROOT}/${proto}/${username}.json"

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

  delete_one_file "${acc_file}"
  delete_one_file "${acc_file_legacy}"
  delete_one_file "${quota_file}"
  delete_one_file "${quota_file_legacy}"
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
  local quota_bytes
  quota_bytes="$(bytes_from_gb "${quota_gb}")"

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

  hr
  echo "Ringkasan:"
  echo "  Username : ${username}"
  echo "  Protocol : ${proto}"
  echo "  Email    : ${username}@${proto}"
  echo "  Expired  : ${days} hari"
  echo "  Quota    : ${quota_gb} GB"
  echo "  IP Limit : ${ip_enabled} $( [[ "${ip_enabled}" == "true" ]] && echo "(${ip_limit})" )"
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
  write_account_artifacts "${proto}" "${username}" "${cred}" "${quota_bytes}" "${days}" "${ip_enabled}" "${ip_limit}"

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
  xray_delete_client "${proto}" "${username}"
  delete_account_artifacts "${proto}" "${username}"

  title
  echo "Delete user selesai ✅"
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

    echo "  view) View file"
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
      *) warn "Pilihan tidak valid" ; sleep 1 ; return 0 ;;
    esac
  done
}




user_export_links_menu() {
  ensure_account_quota_dirs

  local page=0
  while true; do
    title
    echo "User Management > Export client links"
    hr

    account_collect_files
    ACCOUNT_PAGE="${page}"
    account_print_table_page "${ACCOUNT_PAGE}"
    hr

    echo "Masukkan NO untuk export/view, atau ketik next/previous/kembali"
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      return 0
    fi

    case "${c}" in
      next|n)
        local pages
        pages="$(account_total_pages)"
        if (( pages > 0 && page < pages - 1 )); then page=$((page + 1)); fi
        continue
        ;;
      previous|p|prev)
        if (( page > 0 )); then page=$((page - 1)); fi
        continue
        ;;
    esac

    if [[ ! "${c}" =~ ^[0-9]+$ ]]; then
      warn "Input tidak valid"
      sleep 1
      continue
    fi

    local idx
    idx=$((c - 1))
    if (( idx < 0 || idx >= ${#ACCOUNT_FILES[@]} )); then
      warn "NO di luar range"
      sleep 1
      continue
    fi

    local f base ts outdir out
    f="${ACCOUNT_FILES[$idx]}"
    base="$(basename "${f}")"
    ts="$(date +%Y%m%d-%H%M%S)"
    outdir="${REPORT_DIR}/export-${ts}"
    out="${outdir}/${base}"

    title
    echo "Export: ${f}"
    hr
    echo "  1) Tampilkan di layar"
    echo "  2) Simpan salinan ke ${out}"
    echo "  3) Tampilkan + simpan"
    echo "  kembali) Back"
    hr
    read -r -p "Pilih: " a
    if is_back_choice "${a}"; then
      continue
    fi

    case "${a}" in
      1)
        if have_cmd less; then
          less -R "${f}"
        else
          cat "${f}"
        fi
        ;;
      2)
        mkdir -p "${outdir}"
        chmod 700 "${outdir}" || true
        cp -a "${f}" "${out}"
        chmod 600 "${out}" || true
        log "Disimpan: ${out}"
        ;;
      3)
        if have_cmd less; then
          less -R "${f}"
        else
          cat "${f}"
        fi
        mkdir -p "${outdir}"
        chmod 700 "${outdir}" || true
        cp -a "${f}" "${out}"
        chmod 600 "${out}" || true
        log "Disimpan: ${out}"
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac

    pause
  done
}


user_menu() {
  while true; do
    title
    echo "2) User Management (Xray Accounts)"
    hr
    echo "  1. Add user"
    echo "  2. Delete user"
    echo "  3. List users (read-only)"
    echo "  4. Export client links"
    echo "  0. Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) user_add_menu ;;
      2) user_del_menu ;;
      3) user_list_menu ;;
      4) user_export_links_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ; return 0 ;;
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
    if echo "${u}" | tr '[:upper:]' '[:lower:]' | grep -qi -- "${q}"; then
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

u=str(d.get("username") or "-")
ql=int(d.get("quota_limit") or 0)
qu=int(d.get("quota_used") or 0)

# Limit tampil integer GB (GiB).
ql_gb=int(round(ql/(1024**3))) if ql else 0
ql_disp=f"{ql_gb} GB" if ql_gb else "0 GB"

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

st=d.get("status") or {}
ip_en=bool(st.get("ip_limit_enabled"))
try:
  ip_lim=int(st.get("ip_limit") or 0)
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
  # prints: username|quota_limit_disp|quota_used_disp|expired_at_date|ip_limit_onoff|ip_limit_value|block_reason
  local qf="$1"
  need_python3
  python3 - <<'PY' "${qf}"
import json, sys
p=sys.argv[1]
try:
  d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
  print("-|0 GB|0 B|-|OFF|0|-")
  raise SystemExit(0)

u=str(d.get("username") or "-")
ql=int(d.get("quota_limit") or 0)
qu=int(d.get("quota_used") or 0)

ql_gb=int(round(ql/(1024**3))) if ql else 0
ql_disp=f"{ql_gb} GB" if ql_gb else "0 GB"

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

st=d.get("status") or {}
ip_en=bool(st.get("ip_limit_enabled"))
try:
  ip_lim=int(st.get("ip_limit") or 0)
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

print(f"{u}|{ql_disp}|{qu_disp}|{exp_date}|{'ON' if ip_en else 'OFF'}|{ip_lim}|{reason}")
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
st = d.get("status") or {}
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
st = d.get("status") or {}
v = st.get(k, 0)
try:
  print(int(v))
except Exception:
  print("0")
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
st = d.get("status") or {}
v = st.get("lock_reason") or ""
print(str(v))
PY
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
    printf "%-4s %-8s %-18s %-10s %-12s %-10s\n" "$((i + 1))" "${proto}" "${username}" "${ql_disp}" "${qu_disp}" "${exp_date}"

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
  local qf="$1"
  local code="$2"
  need_python3

  python3 - <<PY "${qf}"
import json, sys, os, tempfile
p=sys.argv[1]
code = """${code}"""

with open(p, 'r', encoding='utf-8') as f:
  d=json.load(f)

ns={"d": d}
exec(code, ns, ns)

out=json.dumps(ns["d"], ensure_ascii=False, indent=2) + "\n"

dirn=os.path.dirname(p) or "."
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
print(json.dumps(d, ensure_ascii=False, indent=2))
PY
  fi
  hr
  pause
}

quota_edit_flow() {
  # args: view_no (1-based within filtered list)
  local view_no="$1"

  [[ "${view_no}" =~ ^[0-9]+$ ]] || { warn "Input bukan angka"; pause; return 0; }
  local total="${#QUOTA_VIEW_INDEXES[@]}"
  if (( view_no < 1 || view_no > total )); then
    warn "NO di luar range"
    pause
    return 0
  fi

  local list_pos real_idx qf proto
  list_pos=$((view_no - 1))
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

    local fields username ql_disp qu_disp exp_date ip_state ip_lim block_reason
    fields="$(quota_read_detail_fields "${qf}")"
    username="${fields%%|*}"
    fields="${fields#*|}"
    ql_disp="${fields%%|*}"
    fields="${fields#*|}"
    qu_disp="${fields%%|*}"
    fields="${fields#*|}"
    exp_date="${fields%%|*}"
    fields="${fields#*|}"
    ip_state="${fields%%|*}"
    fields="${fields#*|}"
    ip_lim="${fields%%|*}"
    block_reason="${fields##*|}"

    echo "Username     : ${username}"
    echo "Quota Limit  : ${ql_disp}"
    echo "Quota Used   : ${qu_disp}"
    echo "Expired At   : ${exp_date}"
    echo "IP Limit     : ${ip_state}"
    echo "Block Reason : ${block_reason}"
    echo "IP Limit Max : ${ip_lim}"
    hr

    echo "  1) View JSON"
    echo "  2) Set Quota Limit (GB)"
    echo "  3) Reset Quota Used (set 0)"
    echo "  4) Manual Block/Unblock (toggle)"
    echo "  5) IP Limit Enable/Disable (toggle)"
    echo "  6) Set IP Limit (angka)"
    echo "  7) Unlock IP Lock"
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
        quota_atomic_update_file "${qf}" "d['quota_limit']=int(${qb})"
        log "Quota limit diubah: ${gb_num} GB"
        pause
        ;;
      3)
        quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); d['quota_used']=0; st['quota_exhausted']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); lr=('manual' if mb else ('quota' if qe else ('ip_limit' if il else ''))); st['lock_reason']=lr; (st.__setitem__('locked_at', st.get('locked_at') or now) if lr else st.pop('locked_at', None))"
        xray_routing_set_user_in_marker "dummy-quota-user" "${username}" off
        log "Quota used di-reset: 0 (status quota dibersihkan)"
        pause
        ;;
      4)
        local st_mb
        st_mb="$(quota_get_status_bool "${qf}" "manual_block")"
        if [[ "${st_mb}" == "true" ]]; then
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); st['manual_block']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); lr=('manual' if mb else ('quota' if qe else ('ip_limit' if il else ''))); st['lock_reason']=lr; (st.__setitem__('locked_at', st.get('locked_at') or now) if lr else st.pop('locked_at', None))"
          xray_routing_set_user_in_marker "dummy-block-user" "${username}" off
          log "Manual block: OFF"
        else
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); st['manual_block']=True; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); st['lock_reason']='manual'; st['locked_at']=st.get('locked_at') or now"
          xray_routing_set_user_in_marker "dummy-block-user" "${username}" on
          log "Manual block: ON"
        fi
        pause
        ;;
      5)
        local ip_on
        ip_on="$(quota_get_status_bool "${qf}" "ip_limit_enabled")"
        if [[ "${ip_on}" == "true" ]]; then
          quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); st['ip_limit_enabled']=False; st['ip_limit_locked']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); lr=('manual' if mb else ('quota' if qe else ('ip_limit' if il else ''))); st['lock_reason']=lr; (st.__setitem__('locked_at', st.get('locked_at') or now) if lr else st.pop('locked_at', None))"
          xray_routing_set_user_in_marker "dummy-limit-user" "${username}" off
          /usr/local/bin/limit-ip unlock "${username}" >/dev/null 2>&1 || true
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
        /usr/local/bin/limit-ip unlock "${username}" >/dev/null 2>&1 || true
        quota_atomic_update_file "${qf}" "from datetime import datetime; st=d.setdefault('status',{}); st['ip_limit_locked']=False; now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'); mb=bool(st.get('manual_block')); qe=bool(st.get('quota_exhausted')); il=bool(st.get('ip_limit_locked')); lr=('manual' if mb else ('quota' if qe else ('ip_limit' if il else ''))); st['lock_reason']=lr; (st.__setitem__('locked_at', st.get('locked_at') or now) if lr else st.pop('locked_at', None))"
        xray_routing_set_user_in_marker "dummy-limit-user" "${username}" off
        svc_restart_any xray-limit-ip xray-limit >/dev/null 2>&1 || true
        log "IP lock di-unlock"
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
# Network add-ons (WARP, routing) (read-only/opsional)
# -------------------------
warp_status() {
  title
  echo "WARP (wireproxy) status"
  hr
  if systemctl list-unit-files | grep -q '^wireproxy\.service'; then
    systemctl status wireproxy --no-pager || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  pause
}

network_menu() {
  while true; do
    title
    echo "4) Network / Proxy Add-ons"
    hr
    echo "  1. WARP status"
    echo "  2. Restart WARP (wireproxy) (opsional)"
    echo "  3. Show sysctl BBR (read-only)"
    echo "  0. Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) warp_status ;;
      2)
        title
        echo "Restart wireproxy"
        hr
        if systemctl list-unit-files | grep -q '^wireproxy\.service'; then
          svc_restart wireproxy || true
        else
          warn "wireproxy.service tidak terdeteksi"
        fi
        hr
        pause
        ;;
      3)
        title
        echo "sysctl TCP/BBR info"
        hr
        sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true
        sysctl net.core.default_qdisc 2>/dev/null || true
        hr
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ; return 0 ;;
    esac
  done
}

# -------------------------
# Security (fail2ban) (opsional)
# -------------------------
fail2ban_menu() {
  while true; do
    title
    echo "5) Security"
    hr
    echo "  1. Fail2ban status"
    echo "  2. Fail2ban jail list"
    echo "  3. Unban IP (TODO)"
    echo "  0. Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        title
        systemctl status fail2ban --no-pager || true
        hr
        pause
        ;;
      2)
        title
        if have_cmd fail2ban-client; then
          fail2ban-client status || true
        else
          warn "fail2ban-client tidak ada"
        fi
        hr
        pause
        ;;
      3)
        title
        echo "TODO: unban IP"
        hr
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ; return 0 ;;
    esac
  done
}

# -------------------------
# Maintenance
# -------------------------
maintenance_menu() {
  while true; do
    title
    echo "6) Maintenance"
    hr
    echo "  1. Restart xray"
    echo "  2. Restart nginx"
    echo "  3. Restart all (xray+nginx)"
    echo "  4. View xray logs (tail)"
    echo "  5. View nginx logs (tail)"
    echo "  0. Back (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) svc_restart xray ; pause ;;
      2) svc_restart nginx ; pause ;;
      3) svc_restart xray ; svc_restart nginx ; pause ;;
      4) title ; tail_logs xray 160 ; hr ; pause ;;
      5) title ; tail_logs nginx 160 ; hr ; pause ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ; return 0 ;;
    esac
  done
}

# -------------------------
# Main menu
# -------------------------
main_menu() {
  while true; do
    title
    echo "Main Menu"
    hr
    echo "  1) Status & Diagnostics"
    echo "  2) User Management"
    echo "  3) Quota & Access Control"
    echo "  4) Network / Proxy Add-ons"
    echo "  5) Security"
    echo "  6) Maintenance"
    echo "  0) Exit (kembali)"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) run_action "Status & Diagnostics" sanity_check_now ;;
      2) run_action "User Management" user_menu ;;
      3) run_action "Quota & Access Control" quota_menu ;;
      4) run_action "Network / Proxy Add-ons" network_menu ;;
      5) run_action "Security" fail2ban_menu ;;
      6) run_action "Maintenance" maintenance_menu ;;
      0|kembali|k|back|b) exit 0 ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

main() {
  need_root
  ensure_account_quota_dirs
  main_menu
}

main "$@"
