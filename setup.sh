#!/usr/bin/env bash
set -euo pipefail

# Harden PATH untuk mencegah PATH hijacking saat script dijalankan sebagai root.
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

trap 'rc=$?; echo "[ERROR] line ${LINENO}: ${BASH_COMMAND} (exit ${rc})" >&2; exit ${rc}' ERR

# =========================
# Setup-only autoscript:
# Xray + Nginx (nginx.org repo) + acme.sh
# VLESS/VMess/Trojan over WS/HTTPUpgrade/gRPC
# Public paths fixed, internal ports & paths randomized
# Cert saved to /opt/cert/fullchain.pem & /opt/cert/privkey.pem
# Supports: Ubuntu >= 20.04, Debian >= 11, KVM only
# =========================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[0;37m'
NC='\033[0m'

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_CONFDIR="/usr/local/etc/xray/conf.d"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
CERT_DIR="/opt/cert"
CERT_FULLCHAIN="${CERT_DIR}/fullchain.pem"
CERT_PRIVKEY="${CERT_DIR}/privkey.pem"
SPEED_POLICY_ROOT="/opt/speed"
SPEED_STATE_DIR="/var/lib/xray-speed"
SPEED_CONFIG_DIR="/etc/xray-speed"
SPEED_PROTO_DIRS=("vless" "vmess" "trojan")
OBS_CONFIG_DIR="/etc/xray-observe"
OBS_CONFIG_FILE="${OBS_CONFIG_DIR}/config.env"
OBS_STATE_DIR="/var/lib/xray-observe"
OBS_LOG_DIR="/var/log/xray-observe"
DOMAIN_GUARD_CONFIG_DIR="/etc/xray-domain-guard"
DOMAIN_GUARD_CONFIG_FILE="${DOMAIN_GUARD_CONFIG_DIR}/config.env"
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ}"
# Daftar domain induk yang disediakan (private)
PROVIDED_ROOT_DOMAINS=(
"vyxara1.web.id"
"vyxara2.web.id"
"vyxara1.qzz.io"
"vyxara2.qzz.io"
)

# NOTE: Script ini dipakai pribadi. Isi token di atas jika tidak memakai env var.
# ACME_CERT_MODE:
# - standalone: issue cert for DOMAIN via standalone (port 80)
# - dns_cf_wildcard: issue wildcard cert for ACME_ROOT_DOMAIN via dns_cf
ACME_CERT_MODE="standalone"
ACME_ROOT_DOMAIN=""
CF_ZONE_ID=""
CF_ACCOUNT_ID=""
VPS_IPV4=""
CF_PROXIED="false"
XRAY_INSTALL_REF="${XRAY_INSTALL_REF:-e741a4f56d368afbb9e5be3361b40c4552d3710d}"
ACME_SH_INSTALL_REF="${ACME_SH_INSTALL_REF:-f39d066ced0271d87790dc426556c1e02a88c91b}"
XRAY_INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/XTLS/Xray-install/${XRAY_INSTALL_REF}/install-release.sh"
ACME_SH_SCRIPT_URL="https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_SH_INSTALL_REF}/acme.sh"
ACME_SH_TARBALL_URL="https://codeload.github.com/acmesh-official/acme.sh/tar.gz/${ACME_SH_INSTALL_REF}"
ACME_SH_DNS_CF_HOOK_URL="https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_SH_INSTALL_REF}/dnsapi/dns_cf.sh"
XRAY_INSTALL_SCRIPT_SHA256="${XRAY_INSTALL_SCRIPT_SHA256:-7f70c95f6b418da8b4f4883343d602964915e28748993870fd554383afdbe555}"
ACME_SH_SCRIPT_SHA256="${ACME_SH_SCRIPT_SHA256:-3c15d539f2b670040c67b596161297ef4e402a969e686ee53d5a083923e761db}"
ACME_SH_TARBALL_SHA256="${ACME_SH_TARBALL_SHA256:-3be27ab630d5dd53439a46e56cbe77d998b788c3f0a3eb6b95cdd77e074389a9}"
ACME_SH_DNS_CF_HOOK_SHA256="${ACME_SH_DNS_CF_HOOK_SHA256:-9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8}"
CUSTOM_GEOSITE_URL="${CUSTOM_GEOSITE_URL:-https://github.com/superdecrypt-dev/custom-geosite-xray/raw/main/custom.dat}"
CUSTOM_GEOSITE_SHA256="${CUSTOM_GEOSITE_SHA256:-}"
XRAY_ASSET_DIR="/usr/local/share/xray"
CUSTOM_GEOSITE_DEST="${XRAY_ASSET_DIR}/custom.dat"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MANAGE_MODULES_SRC_DIR="${SCRIPT_DIR}/opt/manage"
MANAGE_MODULES_DST_DIR="/opt/manage"
MANAGE_BUNDLE_URL="${MANAGE_BUNDLE_URL:-https://raw.githubusercontent.com/superdecrypt-dev/autoscript/main/manage_bundle.zip}"
MANAGE_BUNDLE_SHA256="${MANAGE_BUNDLE_SHA256:-}"
MANAGE_BIN="${MANAGE_BIN:-/usr/local/bin/manage}"

die() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
  exit 1
}

ok() {
  echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

declare -a _EXIT_CLEANUP_FNS=()

run_exit_cleanups() {
  local rc=$?
  local fn
  for fn in "${_EXIT_CLEANUP_FNS[@]}"; do
    if declare -F "$fn" >/dev/null 2>&1; then
      "$fn" || true
    fi
  done
  return "$rc"
}

register_exit_cleanup() {
  local fn="$1"
  local existing
  for existing in "${_EXIT_CLEANUP_FNS[@]}"; do
    [[ "$existing" == "$fn" ]] && return 0
  done
  _EXIT_CLEANUP_FNS+=("$fn")
}

trap run_exit_cleanups EXIT

safe_clear() {
  # clear bisa gagal pada shell non-interaktif (TERM tidak ada).
  if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
    clear || true
  fi
}

ui_hr() {
  local w="${COLUMNS:-80}"
  local line
  if [[ ! "${w}" =~ ^[0-9]+$ ]]; then
    w=80
  fi
  if (( w < 60 )); then
    w=60
  fi
  printf -v line '%*s' "${w}" ''
  line="${line// /-}"
  echo -e "${DIM}${line}${NC}"
}

ui_header() {
  local text="$1"
  safe_clear
  ui_hr
  echo -e "${BOLD}${CYAN}${text}${NC}"
  ui_hr
}

download_file_or_die() {
  local url="$1"
  local out="$2"
  local expected_sha="${3:-}"
  local label="${4:-$url}"

  if ! download_file_with_sha_check "${url}" "${out}" "${expected_sha}" "${label}"; then
    die "Gagal download/verify: ${label}"
  fi
}

download_file_with_sha_check() {
  local url="$1"
  local out="$2"
  local expected_sha="${3:-}"
  local label="${4:-$url}"
  local actual_sha=""

  if ! curl -fsSL --connect-timeout 15 --max-time 120 "${url}" -o "${out}"; then
    rm -f "${out}" >/dev/null 2>&1 || true
    return 1
  fi
  if [[ ! -s "${out}" ]]; then
    warn "File hasil download kosong: ${label}"
    rm -f "${out}" >/dev/null 2>&1 || true
    return 1
  fi

  if [[ -n "${expected_sha}" ]]; then
    if ! command -v sha256sum >/dev/null 2>&1; then
      warn "sha256sum tidak tersedia untuk verifikasi checksum: ${label}"
      rm -f "${out}" >/dev/null 2>&1 || true
      return 1
    fi
    actual_sha="$(sha256sum "${out}" | awk '{print tolower($1)}')"
    if [[ -z "${actual_sha}" || "${actual_sha}" != "${expected_sha,,}" ]]; then
      warn "Checksum mismatch: ${label}"
      warn "  expected: ${expected_sha,,}"
      warn "  actual  : ${actual_sha:-<empty>}"
      rm -f "${out}" >/dev/null 2>&1 || true
      return 1
    fi
  fi
  return 0
}

service_enable_restart_checked() {
  local svc="$1"
  systemctl enable "$svc" --now >/dev/null 2>&1 || return 1
  systemctl restart "$svc" >/dev/null 2>&1 || return 1
  systemctl is-active --quiet "$svc" || return 1
  return 0
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Jalankan sebagai root."
}

check_os() {
  [[ -f /etc/os-release ]] || die "Tidak menemukan /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  local id="${ID:-}"
  local ver="${VERSION_ID:-}"
  local codename="${VERSION_CODENAME:-}"

  # Gunakan awk (selalu tersedia, tidak butuh python3) agar check_os bisa
  # dipanggil sebelum install_base_deps menginstall python3.
  if [[ "$id" == "ubuntu" ]]; then
    local ok_ver
    ok_ver="$(awk "BEGIN { print (\"${ver}\" + 0 >= 20.04) ? 1 : 0 }")"
    [[ "$ok_ver" == "1" ]] || die "Ubuntu minimal 20.04. Versi terdeteksi: $ver"
    ok "OS: Ubuntu $ver ($codename)"
  elif [[ "$id" == "debian" ]]; then
    local major="${ver%%.*}"
    [[ "${major:-0}" -ge 11 ]] 2>/dev/null || die "Debian minimal 11. Versi terdeteksi: $ver"
    ok "OS: Debian $ver ($codename)"
  else
    die "OS tidak didukung: $id. Hanya Ubuntu >=20.04 atau Debian >=11."
  fi
}

ensure_dpkg_consistent() {
  wait_for_dpkg_lock || die "Timeout menunggu lock dpkg/apt."

  local audit
  audit="$(dpkg --audit 2>/dev/null || true)"
  if [[ -n "${audit//[[:space:]]/}" ]]; then
    warn "Status dpkg tidak konsisten. Menjalankan pemulihan: dpkg --configure -a"
    dpkg --configure -a || die "Gagal memulihkan status dpkg."
  fi

  # Coba perbaiki dependency yang belum tuntas tanpa menghentikan flow jika tidak perlu.
  apt_get_with_lock_retry -f install -y >/dev/null 2>&1 || true
}

wait_for_dpkg_lock() {
  local timeout=300
  local waited=0
  local step=3
  local lock_files=(
    /var/lib/dpkg/lock-frontend
    /var/lib/dpkg/lock
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )

  command -v fuser >/dev/null 2>&1 || return 0

  while true; do
    local busy=0
    local lf
    for lf in "${lock_files[@]}"; do
      if [[ -e "$lf" ]] && fuser "$lf" >/dev/null 2>&1; then
        busy=1
        break
      fi
    done

    if [[ "$busy" -eq 0 ]]; then
      return 0
    fi

    if (( waited >= timeout )); then
      return 1
    fi

    sleep "$step"
    waited=$((waited + step))
  done
}

apt_get_with_lock_retry() {
  local max_attempts=8
  local attempt=1
  local tmp rc

  while (( attempt <= max_attempts )); do
    wait_for_dpkg_lock || true
    tmp="$(mktemp)"
    # Hindari process substitution tee karena bisa race saat baca file log lock.
    # Simpan output dulu ke file, lalu tampilkan ulang agar grep lock deterministik.
    set +e
    apt-get "$@" >"$tmp" 2>&1
    rc=$?
    set -e
    cat "$tmp"
    if (( rc == 0 )); then
      rm -f "$tmp" >/dev/null 2>&1 || true
      return 0
    fi

    if grep -qiE "Could not get lock|Unable to acquire the dpkg frontend lock|Unable to lock the administration directory" "$tmp"; then
      warn "APT lock masih dipakai proses lain. Retry ${attempt}/${max_attempts} ..."
      rm -f "$tmp" >/dev/null 2>&1 || true
      sleep 3
      attempt=$((attempt + 1))
      continue
    fi

    rm -f "$tmp" >/dev/null 2>&1 || true
    return "$rc"
  done

  return 1
}

install_base_deps() {
  export DEBIAN_FRONTEND=noninteractive
  ensure_dpkg_consistent
  apt_get_with_lock_retry update -y
  apt_get_with_lock_retry install -y curl ca-certificates unzip openssl socat cron gpg lsb-release python3 iproute2 jq dnsutils
  ok "Dependency dasar terpasang."
}

need_python3() {
  if command -v python3 >/dev/null 2>&1; then
    return 0
  fi

  warn "python3 belum terpasang. Memasang python3..."
  export DEBIAN_FRONTEND=noninteractive
  ensure_dpkg_consistent
  apt_get_with_lock_retry update -y
  apt_get_with_lock_retry install -y python3 || die "Gagal memasang python3."
}


# =========================
# Domain menu v2 (Cloudflare)
# =========================

confirm_yn() {
  local prompt="$1"
  local ans
  while true; do
    read -r -p "$prompt (y/n): " ans
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

  [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || die "CLOUDFLARE_API_TOKEN belum di-set. Isi token Cloudflare di setup.sh atau export env CLOUDFLARE_API_TOKEN."

  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local resp code body trimmed

  if [[ -n "$data" ]]; then
    resp="$(curl -sS -L -X "$method" "$url"       -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"       -H "Content-Type: application/json"       --connect-timeout 10       --max-time 30       --data "$data"       -w $'\n%{http_code}' || true)"
  else
    resp="$(curl -sS -L -X "$method" "$url"       -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"       -H "Content-Type: application/json"       --connect-timeout 10       --max-time 30       -w $'\n%{http_code}' || true)"
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


cf_list_zones() {
  cf_api GET "/zones?per_page=50" | jq -r '
  if .success == true then
    .result[] | "\(.id)	\(.name)"
  else
  empty
  end
  '
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
cf_get_a_record_by_name() {
  local zone_id="$1"
  local name="$2"
  local json

  json="$(cf_api GET "/zones/${zone_id}/dns_records?type=A&name=${name}&per_page=100" || true)"
  if [[ -z "${json:-}" ]]; then
    return 0
  fi

  if ! echo "$json" | jq -e '.success == true' >/dev/null 2>&1; then
    return 1
  fi

  echo "$json" | jq -r '.result[] | "\(.id)	\(.content)"' | head -n 1
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

  echo "$json" | jq -r '.result[] | "\(.id)	\(.name)"'
}
cf_delete_record() {
  local zone_id="$1"
  local record_id="$2"
  cf_api DELETE "/zones/${zone_id}/dns_records/${record_id}" >/dev/null || die "Gagal delete DNS record Cloudflare: $record_id"
}

cf_create_a_record() {
  local zone_id="$1"
  local name="$2"
  local ip="$3"
  local proxied="${4:-false}"

  # proxied harus "true" atau "false"
  if [[ "$proxied" != "true" && "$proxied" != "false" ]]; then
    proxied="false"
  fi

  local payload
  payload="$(cat <<EOF
{"type":"A","name":"$name","content":"$ip","ttl":1,"proxied":$proxied}
EOF
  )"
  cf_api POST "/zones/${zone_id}/dns_records" "$payload" >/dev/null || die "Gagal membuat A record Cloudflare untuk $name"
}
gen_subdomain_random() {
  rand_str 5
}

validate_subdomain() {
  # Allow nested subdomain labels, tapi setiap label wajib valid DNS:
  # - 1..63 chars
  # - hanya [a-z0-9-]
  # - tidak boleh diawali/diakhiri '-'
  local s="$1"
  [[ -n "$s" ]] || return 1
  [[ "$s" == "${s,,}" ]] || return 1
  [[ "$s" != *" "* ]] || return 1
  [[ "$s" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$ ]] || return 1
  return 0
}

cf_prepare_subdomain_a_record() {
  local zone_id="$1"
  local fqdn="$2"
  local ip="$3"
  local proxied="${4:-false}"

  ok "Validasi DNS A record Cloudflare untuk: $fqdn"

  # 1) Cek apakah FQDN sudah punya A record
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
          ok "Melanjutkan proses."
          return 0
        fi
        die "Dibatalkan oleh pengguna."
      fi

      if [[ "$any_diff" == "1" ]]; then
        die "Subdomain $fqdn sudah ada di Cloudflare tetapi IP berbeda (${rec_ips[*]}). Gunakan nama subdomain lain."
      fi
    fi
  fi

# 2) Sesuai desain sebelumnya: hapus A record lain di zone yang IP-nya sama (kecuali fqdn target)
local same_ip=()
mapfile -t same_ip < <(cf_list_a_records_by_ip "$zone_id" "$ip" || true)
if [[ ${#same_ip[@]} -gt 0 ]]; then
  local line
  for line in "${same_ip[@]}"; do
    local rid="${line%%$'	'*}"
    local rname="${line#*$'	'}"
    if [[ "$rname" != "$fqdn" ]]; then
      warn "Ditemukan A record lain dengan IP sama ($ip): $rname -> $ip"
      warn "Menghapus A record: $rname"
      cf_delete_record "$zone_id" "$rid"
    fi
  done
fi

ok "Membuat DNS A record: $fqdn -> $ip"
cf_create_a_record "$zone_id" "$fqdn" "$ip" "$proxied"
}
domain_menu_v2() {
  ui_header "Konfigurasi Domain TLS"
  echo -e "${DIM}Pilih metode domain untuk proses setup.${NC}"
  echo -e "  ${CYAN}1)${NC} Input domain manual"
  echo -e "  ${CYAN}2)${NC} Gunakan domain yang disediakan"
  ui_hr

  local choice=""
  while true; do
    read -r -p "Pilih opsi (1-2): " choice
    case "$choice" in
      1|2) break ;;
      *) echo "Pilihan tidak valid." ;;
    esac
  done

  if [[ "$choice" == "1" ]]; then
    # Input domain sendiri (standalone)
    local re='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
    while true; do
      read -r -p "Masukkan domain: " DOMAIN
      DOMAIN="${DOMAIN,,}"

      [[ -n "${DOMAIN:-}" ]] || {
        echo "Domain tidak boleh kosong."
        continue
      }

      if [[ "$DOMAIN" =~ $re ]]; then
        ok "Domain valid: $DOMAIN"
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

# Gunakan domain yang disediakan (Cloudflare)
VPS_IPV4="$(get_public_ipv4)"
ok "Public IPv4 VPS: $VPS_IPV4"

[[ ${#PROVIDED_ROOT_DOMAINS[@]} -gt 0 ]] || die "Daftar domain induk (PROVIDED_ROOT_DOMAINS) kosong."

echo
echo -e "${BOLD}Pilih domain induk${NC}"
local i=1
local root=""
for root in "${PROVIDED_ROOT_DOMAINS[@]}"; do
  echo -e "  ${CYAN}${i})${NC} $root"
  i=$((i+1))
done

local pick=""
while true; do
  read -r -p "Pilih nomor domain induk (1-${#PROVIDED_ROOT_DOMAINS[@]}): " pick
  [[ "$pick" =~ ^[0-9]+$ ]] || { echo "Input harus angka."; continue; }
  [[ "$pick" -ge 1 && "$pick" -le ${#PROVIDED_ROOT_DOMAINS[@]} ]] || { echo "Di luar range."; continue; }
  break
done

ACME_ROOT_DOMAIN="${PROVIDED_ROOT_DOMAINS[$((pick-1))]}"
ok "Domain induk terpilih: $ACME_ROOT_DOMAIN"

CF_ZONE_ID="$(cf_get_zone_id_by_name "$ACME_ROOT_DOMAIN" || true)"
[[ -n "${CF_ZONE_ID:-}" ]] || die "Zone Cloudflare untuk $ACME_ROOT_DOMAIN tidak ditemukan / token tidak punya akses (butuh Zone:Read + DNS:Edit)."
CF_ACCOUNT_ID="$(cf_get_account_id_by_zone "$CF_ZONE_ID" || true)"
[[ -n "${CF_ACCOUNT_ID:-}" ]] || warn "Tidak bisa ambil CF_ACCOUNT_ID dari zone (acme.sh dns_cf mungkin tetap bisa jalan tanpa ini)."


echo
echo -e "${BOLD}Pilih metode pembuatan subdomain${NC}"
echo -e "  ${CYAN}1)${NC} Generate acak"
echo -e "  ${CYAN}2)${NC} Input manual"

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
  ok "Subdomain acak: $sub"
else
while true; do
  read -r -p "Masukkan nama subdomain: " sub
  sub="${sub,,}"
  if validate_subdomain "$sub"; then
    ok "Subdomain valid: $sub"
    break
  fi
  echo "Subdomain tidak valid. Gunakan huruf kecil, angka, titik, dan strip (-)."
done
fi


echo
if confirm_yn "Aktifkan Cloudflare proxy (orange cloud) untuk DNS A record?"; then
  CF_PROXIED="true"
  ok "Cloudflare proxy: ON (proxied=true)"
else
CF_PROXIED="false"
ok "Cloudflare proxy: OFF (proxied=false)"
fi
DOMAIN="${sub}.${ACME_ROOT_DOMAIN}"
ok "Domain final: $DOMAIN"

cf_prepare_subdomain_a_record "$CF_ZONE_ID" "$DOMAIN" "$VPS_IPV4" "$CF_PROXIED"

ACME_CERT_MODE="dns_cf_wildcard"
ok "Mode sertifikat: wildcard dns_cf untuk ${DOMAIN} (meliputi *.$DOMAIN)"
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

is_port_free() {
  local p="$1"
  ! ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
}

# Registry port yang sudah dipesan dalam sesi ini, disimpan di temp file.
# Wajib pakai temp file (bukan array) karena pick_port dipanggil via $(pick_port)
# yang menjalankan subshell — perubahan array di dalam subshell TIDAK kembali ke
# parent shell, sehingga array biasa tidak bisa dipakai untuk dedup lintas panggilan.
# Temp file di filesystem bersifat shared dan persisten lintas subshell.
_PICK_PORT_REGISTRY="$(mktemp)"

cleanup_pick_port_registry() {
  [[ -n "${_PICK_PORT_REGISTRY:-}" ]] || return 0
  rm -f -- "${_PICK_PORT_REGISTRY}" 2>/dev/null || true
}
register_exit_cleanup cleanup_pick_port_registry

pick_port() {
  local p tries=0
  local max_tries=10000
  while (( tries < max_tries )); do
    p=$(( 20000 + RANDOM % 40000 ))
    # Cek: tidak sedang LISTEN dan belum pernah dipesan di sesi ini
    if is_port_free "$p" && ! grep -qxF "$p" "${_PICK_PORT_REGISTRY}" 2>/dev/null; then
      echo "$p" >> "${_PICK_PORT_REGISTRY}"
      echo "$p"
      return 0
    fi
    tries=$((tries + 1))
  done
  die "Gagal mendapatkan port kosong setelah ${max_tries} percobaan."
}

stop_conflicting_services() {
  systemctl stop nginx 2>/dev/null || true
  systemctl stop apache2 2>/dev/null || true
  systemctl stop caddy 2>/dev/null || true
  systemctl stop lighttpd 2>/dev/null || true
}

install_nginx_official_repo() {
  # shellcheck disable=SC1091
  . /etc/os-release

  local codename
  codename="${VERSION_CODENAME:-}"
  [[ -n "$codename" ]] || codename="$(lsb_release -sc 2>/dev/null || true)"
  [[ -n "$codename" ]] || die "Gagal mendeteksi codename OS."

  ensure_dpkg_consistent
  apt_get_with_lock_retry remove -y nginx nginx-common nginx-full nginx-core 2>/dev/null || true

  mkdir -p /usr/share/keyrings
  local key_tmp key_gpg_tmp
  key_tmp="$(mktemp)"
  key_gpg_tmp="$(mktemp)"

  curl -fsSL https://nginx.org/keys/nginx_signing.key -o "$key_tmp"
  gpg --dearmor <"$key_tmp" >"$key_gpg_tmp"
  install -m 644 "$key_gpg_tmp" /usr/share/keyrings/nginx-archive-keyring.gpg

  rm -f "$key_tmp" "$key_gpg_tmp"

  local distro
  if [[ "$ID" == "ubuntu" ]]; then
    distro="ubuntu"
  elif [[ "$ID" == "debian" ]]; then
    distro="debian"
  else
    die "OS tidak didukung untuk repo nginx.org"
  fi

cat > /etc/apt/sources.list.d/nginx.list <<EOF
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/mainline/${distro}/ ${codename} nginx
EOF

cat > /etc/apt/preferences.d/99nginx <<'EOF'
Package: *
Pin: origin nginx.org
Pin-Priority: 900
EOF

apt_get_with_lock_retry update -y
apt_get_with_lock_retry install -y nginx jq
ok "Nginx terpasang dari repo resmi nginx.org (mainline)."
}

install_acme_and_issue_cert() {
  local EMAIL
  EMAIL="$(rand_email)"
  ok "Email acme.sh (acak): $EMAIL"

  stop_conflicting_services

  # Prefer source bundle (termasuk folder dnsapi/deploy/notify), bukan single-file.
  # Ini mencegah error wildcard: "Cannot find DNS API hook for: dns_cf".
  local acme_tmpdir acme_src_dir acme_tgz acme_install_log
  acme_tmpdir="$(mktemp -d)"
  acme_tgz="${acme_tmpdir}/acme.tar.gz"
  acme_install_log="${acme_tmpdir}/acme-install.log"
  acme_src_dir=""

  if download_file_with_sha_check "${ACME_SH_TARBALL_URL}" "${acme_tgz}" "${ACME_SH_TARBALL_SHA256}" "acme.sh tarball"; then
    if tar -xzf "${acme_tgz}" -C "${acme_tmpdir}" >/dev/null 2>&1; then
      acme_src_dir="$(find "${acme_tmpdir}" -maxdepth 1 -type d -name 'acme.sh-*' -print -quit)"
    fi
  fi

  if [[ -z "${acme_src_dir:-}" || ! -f "${acme_src_dir}/acme.sh" ]]; then
    warn "Source bundle acme.sh tidak tersedia, fallback ke single-file installer."
    acme_src_dir="${acme_tmpdir}/acme-single"
    mkdir -p "${acme_src_dir}"
    download_file_or_die "${ACME_SH_SCRIPT_URL}" "${acme_src_dir}/acme.sh" "${ACME_SH_SCRIPT_SHA256}" "acme.sh script"
  fi

  chmod 700 "${acme_src_dir}/acme.sh"
  if ! (cd "${acme_src_dir}" && bash ./acme.sh --install --home /root/.acme.sh --accountemail "$EMAIL") >"${acme_install_log}" 2>&1; then
    warn "Install acme.sh gagal. Ringkasan log:"
    sed -n '1,120p' "${acme_install_log}" >&2 || true
    rm -rf "${acme_tmpdir}" >/dev/null 2>&1 || true
    die "Gagal install acme.sh dari ref ${ACME_SH_INSTALL_REF}."
  fi
  rm -rf "${acme_tmpdir}" >/dev/null 2>&1 || true

  export PATH="/root/.acme.sh:$PATH"
  [[ -x /root/.acme.sh/acme.sh ]] || die "acme.sh tidak ditemukan setelah proses install."
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null || true

  mkdir -p "$CERT_DIR"
  chmod 700 "$CERT_DIR"

  if [[ "${ACME_CERT_MODE:-standalone}" == "dns_cf_wildcard" ]]; then
    [[ -n "${ACME_ROOT_DOMAIN:-}" ]] || die "ACME_ROOT_DOMAIN kosong (mode dns_cf_wildcard)."
    [[ -n "${DOMAIN:-}" ]] || die "DOMAIN kosong (mode dns_cf_wildcard)."
    [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]] || die "CLOUDFLARE_API_TOKEN kosong untuk mode wildcard dns_cf."
    ok "Issue sertifikat wildcard untuk ${DOMAIN} via acme.sh (dns_cf)..."

    # Beberapa instalasi lama tidak membawa dnsapi hook. Pulihkan otomatis jika hilang.
    if [[ ! -s /root/.acme.sh/dnsapi/dns_cf.sh ]]; then
      warn "dns_cf hook tidak ditemukan, mencoba bootstrap dari ref ${ACME_SH_INSTALL_REF} ..."
      mkdir -p /root/.acme.sh/dnsapi
      download_file_or_die "${ACME_SH_DNS_CF_HOOK_URL}" /root/.acme.sh/dnsapi/dns_cf.sh "${ACME_SH_DNS_CF_HOOK_SHA256}" "acme dns_cf hook"
      chmod 700 /root/.acme.sh/dnsapi/dns_cf.sh >/dev/null 2>&1 || true
    fi
    [[ -s /root/.acme.sh/dnsapi/dns_cf.sh ]] || die "Hook dns_cf tetap tidak ditemukan setelah bootstrap."

    # Fail-fast agar error token/scope lebih jelas sebelum acme.sh issue.
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
    ok "Issue sertifikat untuk $DOMAIN via acme.sh (standalone port 80)..."
    /root/.acme.sh/acme.sh --issue --force --standalone -d "$DOMAIN" --httpport 80 \
    || die "Gagal issue sertifikat (pastikan port 80 terbuka & DNS domain mengarah ke VPS)."

    /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$CERT_PRIVKEY" \
    --fullchain-file "$CERT_FULLCHAIN" \
    --reloadcmd "systemctl restart nginx || true" >/dev/null
  fi

  chmod 600 "$CERT_PRIVKEY" "$CERT_FULLCHAIN"

  ok "Sertifikat tersimpan:"
  ok "  - $CERT_FULLCHAIN"
  ok "  - $CERT_PRIVKEY"
}

install_xray() {
  ok "Install Xray-core..."
  local xray_installer
  xray_installer="$(mktemp)"
  download_file_or_die "${XRAY_INSTALL_SCRIPT_URL}" "${xray_installer}" "${XRAY_INSTALL_SCRIPT_SHA256}" "xray installer script"
  chmod 700 "${xray_installer}"
  bash "${xray_installer}" install >/dev/null \
    || { rm -f "${xray_installer}" >/dev/null 2>&1 || true; die "Gagal install Xray dari ref ${XRAY_INSTALL_REF}."; }
  rm -f "${xray_installer}" >/dev/null 2>&1 || true

  command -v xray >/dev/null 2>&1 || die "Xray tidak terpasang."
  ok "Xray-core terpasang."
}

write_xray_config() {
  local UUID TROJAN_PASS
  UUID="$(cat /proc/sys/kernel/random/uuid)"
  TROJAN_PASS="$(rand_str 24)"

  local P_VLESS_WS P_VMESS_WS P_TROJAN_WS
  local P_VLESS_HUP P_VMESS_HUP P_TROJAN_HUP
  local P_VLESS_GRPC P_VMESS_GRPC P_TROJAN_GRPC
  local P_API

  P_VLESS_WS="$(pick_port)"
  P_VMESS_WS="$(pick_port)"
  P_TROJAN_WS="$(pick_port)"
  P_VLESS_HUP="$(pick_port)"
  P_VMESS_HUP="$(pick_port)"
  P_TROJAN_HUP="$(pick_port)"
  P_VLESS_GRPC="$(pick_port)"
  P_VMESS_GRPC="$(pick_port)"
  P_TROJAN_GRPC="$(pick_port)"
  P_API="10080"

  if ! is_port_free "$P_API"; then
    warn "Port API Xray (${P_API}) sedang dipakai. Mencoba stop service xray lama..."
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop xray >/dev/null 2>&1 || true
      sleep 1
    fi
  fi
  is_port_free "$P_API" || die "Port API Xray ($P_API) sedang dipakai. Bebaskan port ini atau ubah konfigurasi."

  local I_VLESS_WS I_VMESS_WS I_TROJAN_WS
  local I_VLESS_HUP I_VMESS_HUP I_TROJAN_HUP
  local I_VLESS_GRPC I_VMESS_GRPC I_TROJAN_GRPC

  I_VLESS_WS="/$(rand_str 14)"
  I_VMESS_WS="/$(rand_str 14)"
  I_TROJAN_WS="/$(rand_str 14)"
  I_VLESS_HUP="/$(rand_str 14)"
  I_VMESS_HUP="/$(rand_str 14)"
  I_TROJAN_HUP="/$(rand_str 14)"
  I_VLESS_GRPC="$(rand_str 12)"
  I_VMESS_GRPC="$(rand_str 12)"
  I_TROJAN_GRPC="$(rand_str 12)"

  mkdir -p "$(dirname "$XRAY_CONFIG")"

  cat > "$XRAY_CONFIG" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ]
  },
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": [
          "geosite:apple",
          "geosite:meta",
          "geosite:google",
          "geosite:openai",
          "geosite:spotify",
          "geosite:netflix",
          "geosite:reddit"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": [
          "dummy-warp-inbounds"
        ],
        "outboundTag": "warp"
      },
      {
        "type": "field",
        "inboundTag": [
          "dummy-direct-inbounds"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "user": [
          "dummy-warp-user"
        ],
        "outboundTag": "warp"
      },
      {
        "type": "field",
        "user": [
          "dummy-direct-user"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "user": [
          "dummy-block-user"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "user": [
          "dummy-quota-user"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "user": [
          "dummy-limit-user"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "port": "1-65535",
        "outboundTag": "direct"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${P_API},
      "protocol": "dokodemo-door",
      "tag": "api",
      "settings": {
        "address": "127.0.0.1"
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VLESS_WS},
      "protocol": "vless",
      "tag": "default@vless-ws",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "default@vless-ws"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "${I_VLESS_WS}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VMESS_WS},
      "protocol": "vmess",
      "tag": "default@vmess-ws",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0,
            "email": "default@vmess-ws"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "${I_VMESS_WS}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_TROJAN_WS},
      "protocol": "trojan",
      "tag": "default@trojan-ws",
      "settings": {
        "clients": [
          {
            "password": "${TROJAN_PASS}",
            "email": "default@trojan-ws"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "${I_TROJAN_WS}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VLESS_HUP},
      "protocol": "vless",
      "tag": "default@vless-hup",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "default@vless-hup"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "${I_VLESS_HUP}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VMESS_HUP},
      "protocol": "vmess",
      "tag": "default@vmess-hup",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0,
            "email": "default@vmess-hup"
          }
        ]
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "${I_VMESS_HUP}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_TROJAN_HUP},
      "protocol": "trojan",
      "tag": "default@trojan-hup",
      "settings": {
        "clients": [
          {
            "password": "${TROJAN_PASS}",
            "email": "default@trojan-hup"
          }
        ]
      },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": {
          "path": "${I_TROJAN_HUP}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VLESS_GRPC},
      "protocol": "vless",
      "tag": "default@vless-grpc",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "default@vless-grpc"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "${I_VLESS_GRPC}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_VMESS_GRPC},
      "protocol": "vmess",
      "tag": "default@vmess-grpc",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "alterId": 0,
            "email": "default@vmess-grpc"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "${I_VMESS_GRPC}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "listen": "127.0.0.1",
      "port": ${P_TROJAN_GRPC},
      "protocol": "trojan",
      "tag": "default@trojan-grpc",
      "settings": {
        "clients": [
          {
            "password": "${TROJAN_PASS}",
            "email": "default@trojan-grpc"
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "${I_TROJAN_GRPC}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    },
    {
      "protocol": "socks",
      "tag": "warp",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": 40000
          }
        ]
      }
    }
  ]
}
EOF

  mkdir -p /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log

  local xr_user xr_group
  xr_user="$(systemctl show -p User --value xray 2>/dev/null || true)"
  if [[ -z "${xr_user:-}" || "$xr_user" == "n/a" ]]; then
    xr_user="root"
  fi
  xr_group="$(id -gn "$xr_user" 2>/dev/null || echo "$xr_user")"

  chown "$xr_user:$xr_group" "$XRAY_CONFIG" >/dev/null 2>&1 || true
  chown "$xr_user:$xr_group" /var/log/xray >/dev/null 2>&1 || true
  chown "$xr_user:$xr_group" /var/log/xray/access.log /var/log/xray/error.log >/dev/null 2>&1 || true

  chmod 640 "$XRAY_CONFIG"
  chmod 750 /var/log/xray
  chmod 640 /var/log/xray/access.log /var/log/xray/error.log


  # Validasi config sebelum dipakai (hindari exit "diam-diam").
  local test_log
  test_log="$(mktemp "/tmp/xray-config-test.XXXXXX.log")"
  if ! xray run -test -config "$XRAY_CONFIG" >"$test_log" 2>&1; then
    tail -n 200 "$test_log" >&2 || true
    die "Xray config test gagal. Lihat: $test_log"
  fi
  rm -f "$test_log" >/dev/null 2>&1 || true

  # Tidak perlu enable/restart xray di sini.
  # configure_xray_service_confdir (dipanggil setelah write_xray_modular_configs)
  # akan meng-install unit file yang benar (-confdir) dan merestart xray satu kali.
  ok "Config Xray (monolitik) dibuat & divalidasi. Service akan dimulai setelah dipecah ke conf.d."
  declare -gx XR_UUID="$UUID"
  declare -gx XR_TROJAN_PASS="$TROJAN_PASS"
  declare -gx XR_API_PORT="$P_API"

  declare -gx P_VLESS_WS="$P_VLESS_WS"
  declare -gx P_VMESS_WS="$P_VMESS_WS"
  declare -gx P_TROJAN_WS="$P_TROJAN_WS"
  declare -gx P_VLESS_HUP="$P_VLESS_HUP"
  declare -gx P_VMESS_HUP="$P_VMESS_HUP"
  declare -gx P_TROJAN_HUP="$P_TROJAN_HUP"
  declare -gx P_VLESS_GRPC="$P_VLESS_GRPC"
  declare -gx P_VMESS_GRPC="$P_VMESS_GRPC"
  declare -gx P_TROJAN_GRPC="$P_TROJAN_GRPC"

  declare -gx I_VLESS_WS="$I_VLESS_WS"
  declare -gx I_VMESS_WS="$I_VMESS_WS"
  declare -gx I_TROJAN_WS="$I_TROJAN_WS"
  declare -gx I_VLESS_HUP="$I_VLESS_HUP"
  declare -gx I_VMESS_HUP="$I_VMESS_HUP"
  declare -gx I_TROJAN_HUP="$I_TROJAN_HUP"
  declare -gx I_VLESS_GRPC="$I_VLESS_GRPC"
  declare -gx I_VMESS_GRPC="$I_VMESS_GRPC"
  declare -gx I_TROJAN_GRPC="$I_TROJAN_GRPC"
}
write_xray_modular_configs() {
  ok "Membuat konfigurasi modular Xray-core (conf.d)..."
  mkdir -p "${XRAY_CONFDIR}"
  need_python3

  python3 - <<'PY' "${XRAY_CONFIG}" "${XRAY_CONFDIR}"
import json
import os
import sys

src, outdir = sys.argv[1:3]

with open(src, "r", encoding="utf-8") as f:
  cfg = json.load(f)

routing = cfg.get("routing") or {}
inbounds_fresh = cfg.get("inbounds") or []
if not isinstance(inbounds_fresh, list):
  inbounds_fresh = []

def load_json_silent(path):
  try:
    with open(path, "r", encoding="utf-8") as fh:
      return json.load(fh)
  except Exception:
    return {}

def extract_wireguard_inbounds(doc):
  if not isinstance(doc, dict):
    return []
  arr = doc.get("inbounds")
  if not isinstance(arr, list):
    return []
  out = []
  for ib in arr:
    if not isinstance(ib, dict):
      continue
    if str(ib.get("protocol") or "").strip().lower() != "wireguard":
      continue
    out.append(ib)
  return out

# Hardening migrate:
# preserve existing wireguard inbound dari config modular lama (10/11)
# agar setup rerun tidak menghapus WG inbound yang sudah aktif.
existing_10 = load_json_silent(os.path.join(outdir, "10-inbounds.json"))
existing_11 = load_json_silent(os.path.join(outdir, "11-wireguard-inbound.json"))
wg_candidates = extract_wireguard_inbounds(existing_10) + extract_wireguard_inbounds(existing_11)

def wireguard_identity(ib):
  if not isinstance(ib, dict):
    return ""
  tag = str(ib.get("tag") or "").strip()
  if tag:
    return f"tag:{tag}"
  settings = ib.get("settings") if isinstance(ib.get("settings"), dict) else {}
  secret = str(settings.get("secretKey") or "").strip()
  listen = str(ib.get("listen") or "").strip()
  try:
    port = int(ib.get("port") or 0)
  except Exception:
    port = 0
  return f"anon:{listen}:{port}:{secret}"

seen_wg_ids = set()
for ib in inbounds_fresh:
  if not isinstance(ib, dict):
    continue
  if str(ib.get("protocol") or "").strip().lower() != "wireguard":
    continue
  seen_wg_ids.add(wireguard_identity(ib))

for wg_ib in wg_candidates:
  ident = wireguard_identity(wg_ib)
  if ident in seen_wg_ids:
    continue
  inbounds_fresh.append(wg_ib)
  seen_wg_ids.add(ident)

parts = [
  ("00-log.json", {"log": cfg.get("log") or {}}),
  ("01-api.json", {"api": cfg.get("api") or {}}),
  ("02-dns.json", {"dns": cfg.get("dns") or {}}),
  ("10-inbounds.json", {"inbounds": inbounds_fresh}),
  ("20-outbounds.json", {"outbounds": cfg.get("outbounds") or []}),
  ("30-routing.json", {"routing": routing}),
  ("40-policy.json", {"policy": cfg.get("policy") or {}}),
  ("50-stats.json", {"stats": cfg.get("stats") or {}}),
  # 60-observatory.json dibutuhkan manage.sh (XRAY_OBSERVATORY_CONF).
  # Dibuat kosong dulu; manage.sh akan mengisinya saat fitur observatory diaktifkan.
  ("60-observatory.json", {"observatory": cfg.get("observatory") or {}}),
]

os.makedirs(outdir, exist_ok=True)

for name, obj in parts:
  path = os.path.join(outdir, name)
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as wf:
    json.dump(obj, wf, ensure_ascii=False, indent=2)
    wf.write("\n")
  os.replace(tmp, path)

# Hardening migrate:
# Unified WG inbound sekarang berada di 10-inbounds.json.
# Jika file legacy 11-wireguard-inbound.json masih ada, netralkan agar
# tidak double-load inbound WireGuard (duplicate tag/port).
legacy_wg = os.path.join(outdir, "11-wireguard-inbound.json")
if os.path.isfile(legacy_wg):
  legacy_bak = f"{legacy_wg}.legacy.bak"
  if not os.path.exists(legacy_bak):
    try:
      with open(legacy_wg, "rb") as rf, open(legacy_bak, "wb") as wf:
        wf.write(rf.read())
    except Exception:
      pass

  tmp = f"{legacy_wg}.tmp"
  with open(tmp, "w", encoding="utf-8") as wf:
    json.dump({"inbounds": []}, wf, ensure_ascii=False, indent=2)
    wf.write("\n")
  os.replace(tmp, legacy_wg)
PY

  chmod 640 "${XRAY_CONFDIR}"/*.json 2>/dev/null || true
  ok "Konfigurasi modular siap:"
  ok "  - ${XRAY_CONFDIR}/00-log.json"
  ok "  - ${XRAY_CONFDIR}/01-api.json"
  ok "  - ${XRAY_CONFDIR}/02-dns.json"
  ok "  - ${XRAY_CONFDIR}/10-inbounds.json"
  ok "  - ${XRAY_CONFDIR}/20-outbounds.json"
  ok "  - ${XRAY_CONFDIR}/30-routing.json"
  ok "  - ${XRAY_CONFDIR}/40-policy.json"
  ok "  - ${XRAY_CONFDIR}/50-stats.json"
  ok "  - ${XRAY_CONFDIR}/60-observatory.json"
}

ensure_xray_service_user() {
  # Dedicated non-root service account for xray runtime.
  getent group xray >/dev/null 2>&1 || groupadd --system xray
  if ! id -u xray >/dev/null 2>&1; then
    local nologin_bin
    nologin_bin="$(command -v nologin 2>/dev/null || true)"
    [[ -n "${nologin_bin:-}" ]] || nologin_bin="/usr/sbin/nologin"
    useradd --system --gid xray --home-dir /var/lib/xray --create-home --shell "${nologin_bin}" xray
  fi
}

configure_xray_service_confdir() {
  ok "Mengatur xray.service agar memakai -confdir (systemd drop-in) ..."

  local xray_bin
  xray_bin="$(command -v xray || true)"
  [[ -n "${xray_bin:-}" ]] || xray_bin="/usr/local/bin/xray"
  ensure_xray_service_user

  # Hilangkan warning systemd "Special user nobody configured" dari unit utama.
  local frag
  frag="$(systemctl show -p FragmentPath --value xray 2>/dev/null || true)"
  if [[ -n "${frag:-}" && -f "${frag}" ]]; then
    sed -i 's/^User=nobody$/User=xray/' "${frag}" 2>/dev/null || true
  fi

  # Bersihkan drop-in yang mungkin konflik
  mkdir -p /etc/systemd/system/xray.service.d
  rm -f /etc/systemd/system/xray.service.d/*.conf 2>/dev/null || true

  cat > /etc/systemd/system/xray.service.d/10-confdir.conf <<EOF
[Service]
# Reset agar tidak ada duplikasi ExecStart dari unit utama
ExecStart=
ExecStartPre=
ExecStartPre=${xray_bin} run -test -confdir ${XRAY_CONFDIR}
ExecStart=${xray_bin} run -confdir ${XRAY_CONFDIR}

# Jalankan sebagai user dedicated xray (non-root).
User=xray
Group=xray
DynamicUser=no

ReadWritePaths=/var/log/xray
LogsDirectory=xray
LogsDirectoryMode=0755
EOF

  systemctl daemon-reload

  # Pastikan permission conf.d bisa dibaca oleh user xray
  mkdir -p /usr/local/etc/xray "${XRAY_CONFDIR}"
  chown root:xray /usr/local/etc/xray "${XRAY_CONFDIR}" >/dev/null 2>&1 || true
  chmod 750 /usr/local/etc/xray "${XRAY_CONFDIR}" >/dev/null 2>&1 || true
  chown root:xray "${XRAY_CONFDIR}"/*.json >/dev/null 2>&1 || true
  chmod 640 "${XRAY_CONFDIR}"/*.json >/dev/null 2>&1 || true

  # Pastikan direktori & file log ada
  mkdir -p /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  chown xray:xray /var/log/xray /var/log/xray/access.log /var/log/xray/error.log >/dev/null 2>&1 || true
  chmod 750 /var/log/xray
  chmod 640 /var/log/xray/access.log /var/log/xray/error.log

  # Test konfigurasi confdir sebelum restart
  if ! "${xray_bin}" run -test -confdir "${XRAY_CONFDIR}" >/dev/null 2>&1; then
    "${xray_bin}" run -test -confdir "${XRAY_CONFDIR}" || true
    die "Konfigurasi confdir Xray invalid."
  fi

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || { journalctl -u xray -n 200 --no-pager >&2 || true; die "Gagal restart xray"; }
  ok "xray.service di-enable dan berhasil direstart dengan -confdir."

  # Setelah Xray berjalan menggunakan conf.d, config.json tidak diperlukan lagi.
  if [[ -f "${XRAY_CONFIG}" ]]; then
    rm -f "${XRAY_CONFIG}" 2>/dev/null || true
    ok "Konfigurasi bawaan dihapus: ${XRAY_CONFIG}"
  fi
}


detect_nginx_user() {
  if id -u nginx >/dev/null 2>&1; then
    echo "nginx"
    return 0
  fi
  if id -u www-data >/dev/null 2>&1; then
    echo "www-data"
    return 0
  fi
  echo "root"
}

write_nginx_main_conf() {
  local nginx_user
  nginx_user="$(detect_nginx_user)"

  # Hindari konflik dari default server bawaan paket nginx.org
  rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true
  # Hindari warning/konflik dari xray.conf lama saat validasi nginx -t awal.
  rm -f "${NGINX_CONF}" 2>/dev/null || true

  cat > /etc/nginx/nginx.conf <<EOF
user ${nginx_user};
worker_processes 1;
pid /var/run/nginx.pid;

events {
  worker_connections 1024;
  multi_accept on;
  use epoll;
}

http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                  '\$status \$body_bytes_sent "\$http_referer" '
                  '"\$http_user_agent" "\$http_x_forwarded_for"';

  access_log /var/log/nginx/access.log main;
  error_log /var/log/nginx/error.log warn;

  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;

  keepalive_timeout 20;
  keepalive_requests 1000;

  types_hash_max_size 2048;
  server_tokens off;

  client_body_buffer_size 16k;
  client_header_buffer_size 1k;
  large_client_header_buffers 2 8k;

  gzip off;

  include /etc/nginx/conf.d/*.conf;
}
EOF

  nginx -t || die "Konfigurasi /etc/nginx/nginx.conf invalid."
  ok "Nginx main config ditulis: /etc/nginx/nginx.conf (optimized 1 vCPU / 1GB RAM)."
}

write_nginx_config() {
  [[ -f "$CERT_FULLCHAIN" && -f "$CERT_PRIVKEY" ]] || die "Sertifikat tidak ditemukan di $CERT_DIR."

  cat > "$NGINX_CONF" <<EOF
# Map Connection Upgrade
map \$http_upgrade \$connection_upgrade {
  default upgrade;
  ''      close;
}

# 1) Map Public Path -> INTERNAL PORT
map \$uri \$internal_port {
  default 0;

  ~^/vless-ws(?:/|\$)    ${P_VLESS_WS};
  ~^/vmess-ws(?:/|\$)    ${P_VMESS_WS};
  ~^/trojan-ws(?:/|\$)   ${P_TROJAN_WS};

  ~^/vless-hup(?:/|\$)   ${P_VLESS_HUP};
  ~^/vmess-hup(?:/|\$)   ${P_VMESS_HUP};
  ~^/trojan-hup(?:/|\$)  ${P_TROJAN_HUP};

  # gRPC requests usually come as /<serviceName>/Tun, so match prefix
  ~^/vless-grpc(?:/|\$)  ${P_VLESS_GRPC};
  ~^/vmess-grpc(?:/|\$)  ${P_VMESS_GRPC};
  ~^/trojan-grpc(?:/|\$) ${P_TROJAN_GRPC};

}

# 2) Map Public Path -> INTERNAL PATH (WebSocket, HTTPUpgrade)
map \$uri \$internal_path {
  default "";

  ~^/vless-ws(?:/|\$)    ${I_VLESS_WS};
  ~^/vmess-ws(?:/|\$)    ${I_VMESS_WS};
  ~^/trojan-ws(?:/|\$)   ${I_TROJAN_WS};

  ~^/vless-hup(?:/|\$)   ${I_VLESS_HUP};
  ~^/vmess-hup(?:/|\$)   ${I_VMESS_HUP};
  ~^/trojan-hup(?:/|\$)  ${I_TROJAN_HUP};
}

# 3) Map Public Path -> gRPC Service Name
map \$uri \$grpc_service_name {
  default "";

  ~^/vless-grpc(?:/|\$)  ${I_VLESS_GRPC};
  ~^/vmess-grpc(?:/|\$)  ${I_VMESS_GRPC};
  ~^/trojan-grpc(?:/|\$) ${I_TROJAN_GRPC};
}

server {
  listen 80;
  listen [::]:80;
  listen 443 ssl;
  listen [::]:443 ssl;
	http2 on;
  server_name ${DOMAIN};

  if (\$scheme = http) { return 301 https://\$host\$request_uri; }

  ssl_certificate ${CERT_DIR}/fullchain.pem;
  ssl_certificate_key ${CERT_DIR}/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

  # --- WebSocket ---
  location ~ ^/(vless|vmess|trojan)-ws(?:/|\$) {
    # capture map results BEFORE rewrite changes \$uri
    set \$up_port \$internal_port;
    set \$up_path \$internal_path;

    if (\$up_port = 0) { return 404; }
    if (\$up_path = "") { return 404; }
    if (\$http_upgrade !~* websocket) { return 404; }

    proxy_redirect off;
    rewrite ^ \$up_path break;
    proxy_pass http://127.0.0.1:\$up_port;

    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # Tanpa timeout ini, nginx menutup koneksi idle setelah 60 detik (default).
    # Koneksi VPN/tunnel umumnya idle saat tidak ada traffic aktif, sehingga
    # client akan terus-menerus reconnect. 7 hari cukup untuk koneksi persisten.
    proxy_read_timeout 7d;
    proxy_send_timeout 7d;
  }

  # --- HTTPUpgrade ---
  location ~ ^/(vless|vmess|trojan)-hup(?:/|\$) {
    set \$up_port \$internal_port;
    set \$up_path \$internal_path;

    if (\$up_port = 0) { return 404; }
    if (\$up_path = "") { return 404; }

    proxy_redirect off;
    rewrite ^ \$up_path break;
    proxy_pass http://127.0.0.1:\$up_port;

    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    proxy_read_timeout 7d;
    proxy_send_timeout 7d;
  }

  # --- gRPC ---
  location ~ ^/(vless|vmess|trojan)-grpc(?:/|\$) {
    set \$up_port \$internal_port;
    set \$svc \$grpc_service_name;

    if (\$up_port = 0) { return 404; }
    if (\$svc = "") { return 404; }

    # normalize to /<serviceName>/Tun
    rewrite ^ /\$svc/Tun break;
    grpc_pass grpc://127.0.0.1:\$up_port;

    grpc_set_header Host \$host;
    grpc_set_header X-Real-IP \$remote_addr;
    grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # Default grpc_read_timeout nginx = 60 detik. gRPC streaming (multiplexed)
    # juga idle saat tidak ada traffic aktif — tanpa ini koneksi akan ter-reset.
    grpc_read_timeout 7d;
    grpc_send_timeout 7d;
  }

  # Default: hide everything else
  location / {
    return 404;
  }
}

EOF

  nginx -t || die "Konfigurasi Nginx invalid."
  systemctl enable nginx --now
  systemctl restart nginx
  ok "Nginx reverse proxy aktif (public paths -> internal port/path via map \$uri)."
}


# =========================
# Add-ons: WARP (wgcf + wireproxy), fail2ban aggressive, BBR, swap, ulimit, chrony
# NOTE: Bagian valid yang sudah ada tidak diubah. Add-on ini hanya menambah setup.
# =========================

install_extra_deps() {
  export DEBIAN_FRONTEND=noninteractive

  # Hindari warning dpkg-statoverride saat install chrony di beberapa distro.
  mkdir -p /var/log/chrony

  ensure_dpkg_consistent
  apt_get_with_lock_retry install -y jq fail2ban chrony tar expect logrotate nftables
  ok "Dependency tambahan terpasang (jq, fail2ban, chrony, expect, logrotate, nftables)."
}

install_speedtest_snap() {
  ok "Install speedtest via snap..."

  if command -v speedtest >/dev/null 2>&1; then
    ok "speedtest sudah tersedia: $(command -v speedtest)"
    return 0
  fi

  export DEBIAN_FRONTEND=noninteractive
  if ! command -v snap >/dev/null 2>&1; then
    apt-get install -y snapd || die "Gagal install snapd."
  fi

  systemctl enable --now snapd.socket >/dev/null 2>&1 || true
  systemctl enable --now snapd.service >/dev/null 2>&1 || true

  if [[ ! -e /snap ]]; then
    ln -s /var/lib/snapd/snap /snap >/dev/null 2>&1 || true
  fi

  export PATH="${PATH}:/snap/bin"

  local i
  for i in {1..15}; do
    if snap version >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  snap version >/dev/null 2>&1 || die "snapd belum siap. Cek: systemctl status snapd --no-pager"

  if ! snap list speedtest >/dev/null 2>&1; then
    snap install speedtest || die "Gagal install speedtest via snap."
  fi

  hash -r || true
  if command -v speedtest >/dev/null 2>&1 || [[ -x /snap/bin/speedtest ]]; then
    ok "speedtest terpasang via snap."
  else
    warn "speedtest terpasang, namun binary belum ada di PATH shell saat ini. Gunakan /snap/bin/speedtest."
  fi
}

install_fail2ban_aggressive() {
  ok "Enable fail2ban..."

  if service_enable_restart_checked fail2ban; then
    ok "fail2ban aktif. Konfigurasi jail.local aggressive akan diterapkan setelah Nginx siap."
  else
    warn "fail2ban belum aktif (akan dicoba lagi setelah jail.local diterapkan)."
  fi
}

ensure_fail2ban_nginx_filters() {
  # Buat filter minimal jika distro tidak menyediakannya
  mkdir -p /etc/fail2ban/filter.d

  if [[ ! -f /etc/fail2ban/filter.d/nginx-http-auth.conf ]]; then
    cat > /etc/fail2ban/filter.d/nginx-http-auth.conf <<'EOF'
[Definition]
failregex = ^\s*\[error\] .*? user ".*?": password mismatch, client: <HOST>.*$
            ^\s*\[error\] .*? user ".*?": was not found in ".*?", client: <HOST>.*$
ignoreregex =
EOF
  fi

  if [[ ! -f /etc/fail2ban/filter.d/nginx-botsearch.conf ]]; then
    cat > /etc/fail2ban/filter.d/nginx-botsearch.conf <<'EOF'
[Definition]
failregex = ^<HOST> - .* \"(GET|POST|HEAD).*(wp-login\.php|xmlrpc\.php|\.env|phpmyadmin|admin\.php|setup\.php|HNAP1|boaform) .*\"
            ^<HOST> - .* \"(GET|POST|HEAD).*(\.git/|\.svn/|\.hg/|\.DS_Store) .*\"
ignoreregex =
EOF
  fi

  if [[ ! -f /etc/fail2ban/filter.d/nginx-bad-request.conf ]]; then
    cat > /etc/fail2ban/filter.d/nginx-bad-request.conf <<'EOF'
[Definition]

failregex = ^<HOST> - .* "(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH).*" (400|401|403|404|405|444) .*
            ^<HOST> - .* "(GET|POST|HEAD|PUT|DELETE).* (wp-login\.php|xmlrpc\.php|\.env|phpmyadmin|HNAP1|admin|manager)" .*
            ^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[error\]\s+\d+#\d+:\s+\*\d+\s+client sent invalid request.*client:\s+<HOST>.*$
            ^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[error\]\s+\d+#\d+:\s+\*\d+\s+client sent invalid method.*client:\s+<HOST>.*$
            ^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[error\]\s+\d+#\d+:\s+\*\d+\s+invalid host in request.*client:\s+<HOST>.*$
            ^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[error\]\s+\d+#\d+:\s+\*\d+\s+request.*invalid.*client:\s+<HOST>.*$

ignoreregex =
EOF
  fi

}

configure_fail2ban_aggressive_jails() {
  ok "Konfigurasi fail2ban mode aggressive (sshd, nginx-http-auth, nginx-botsearch, recidive)..."

  ensure_fail2ban_nginx_filters

  mkdir -p /etc/fail2ban
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1d
findtime = 10m
maxretry = 3
# backend = auto: deteksi otomatis terbaik untuk file-based logs (nginx, fail2ban.log).
# Jangan pakai backend=systemd di [DEFAULT] karena nginx (dari nginx.org repo) log ke
# /var/log/nginx/*.log (file), BUKAN ke systemd journal. Dengan backend=systemd,
# fail2ban mengabaikan logpath dan baca dari journal sehingga nginx jails dan
# recidive tidak berfungsi sama sekali.
backend  = auto
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
mode     = aggressive
# sshd log ke systemd journal di distro modern, override backend khusus untuk jail ini.
backend  = systemd
logpath  = %(sshd_log)s
maxretry = 3
findtime = 10m
bantime  = 1d

[nginx-bad-request-access]
enabled  = true
port     = http,https
filter   = nginx-bad-request
logpath  = /var/log/nginx/access.log
maxretry = 20
findtime = 60
bantime  = 1h

[nginx-bad-request-error]
enabled  = true
port     = http,https
filter   = nginx-bad-request
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 2h

[recidive]
enabled  = true
# recidive membaca fail2ban.log (file), backend=auto sudah tepat dari [DEFAULT].
logpath  = /var/log/fail2ban.log
bantime  = 7d
findtime = 1d
maxretry = 5
EOF

  service_enable_restart_checked fail2ban || die "Gagal mengaktifkan fail2ban setelah menerapkan jail.local."
  ok "fail2ban jails aggressive diterapkan."
}


enable_bbr() {
  ok "Enable TCP BBR..."

  cat > /etc/sysctl.d/99-custom-net.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  sysctl --system >/dev/null 2>&1 || true
  ok "TCP BBR diset (fq + bbr)."
}

setup_swap_2gb() {
  ok "Setup swap 2GB..."

  if swapon --show 2>/dev/null | awk '{print $1}' | grep -qx "/swapfile"; then
    ok "Swapfile sudah aktif, skip."
    return 0
  fi

  if [[ ! -f /swapfile ]]; then
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi

  if ! swapon /swapfile >/dev/null 2>&1; then
    warn "Gagal mengaktifkan /swapfile (kernel/permission/fs constraint)."
  fi
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab

  cat > /etc/sysctl.d/99-custom-vm.conf <<'EOF'
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF

  sysctl --system >/dev/null 2>&1 || true
  if swapon --show 2>/dev/null | awk '{print $1}' | grep -qx "/swapfile"; then
    ok "Swap 2GB aktif."
  else
    warn "Swap belum aktif. Lanjut tanpa swap."
  fi
}

tune_ulimit() {
  ok "Tuning ulimit..."

  mkdir -p /etc/security/limits.d
  cat > /etc/security/limits.d/99-custom-limits.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc  1048576
* hard nproc  1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  mkdir -p /etc/systemd/system.conf.d
  cat > /etc/systemd/system.conf.d/99-custom-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF

  systemctl daemon-reexec >/dev/null 2>&1 || true
  ok "ulimit limits ditambahkan (perlu relogin/reboot untuk full effect)."
}

setup_time_sync_chrony() {
  ok "Setup time sync (chrony)..."

  systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
  systemctl enable chrony --now >/dev/null 2>&1 || true
  systemctl restart chrony >/dev/null 2>&1 || true
  ok "chrony aktif."
}

get_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armhf) echo "armv7" ;;
    *) die "Arsitektur tidak didukung: $arch" ;;
  esac
}

github_latest_asset_url() {
  # $1 = owner/repo, $2 = asset name contains (substring)
  python3 - "$1" "$2" <<'PY'
import json, sys, urllib.request
repo = sys.argv[1]
match = sys.argv[2]
url = f"https://api.github.com/repos/{repo}/releases/latest"
req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
with urllib.request.urlopen(req, timeout=30) as r:
  data = json.loads(r.read().decode("utf-8"))
for a in data.get("assets", []):
  name = a.get("name", "")
  if match in name:
    print(a.get("browser_download_url", ""))
    sys.exit(0)
sys.exit(1)
PY
}

install_wgcf() {
  if command -v wgcf >/dev/null 2>&1; then
    ok "wgcf sudah terpasang, skip."
    return 0
  fi

  ok "Install wgcf..."
  local arch match url
  arch="$(get_arch)"

  case "$arch" in
    amd64) match="linux_amd64" ;;
    arm64) match="linux_arm64" ;;
    armv7) match="linux_armv7" ;;
  esac

  url="$(github_latest_asset_url "ViRb3/wgcf" "$match")" || die "Gagal mengambil URL release wgcf."
  curl -fsSL "$url" -o /usr/local/bin/wgcf || die "Gagal download wgcf."
  chmod +x /usr/local/bin/wgcf
  ok "wgcf terpasang."
}

install_wireproxy() {
  if command -v wireproxy >/dev/null 2>&1; then
    ok "wireproxy sudah terpasang, skip."
    return 0
  fi

  ok "Install wireproxy..."
  local arch match url tmpdir tgz bin
  arch="$(get_arch)"

  case "$arch" in
    amd64) match="wireproxy_linux_amd64.tar.gz" ;;
    arm64) match="wireproxy_linux_arm64.tar.gz" ;;
    armv7) match="wireproxy_linux_arm.tar.gz" ;;
  esac

  # NOTE: release assets tersedia di whyvl/wireproxy
  url="$(github_latest_asset_url "whyvl/wireproxy" "$match")" || die "Gagal mengambil URL release wireproxy."
  tmpdir="$(mktemp -d)"
  tgz="${tmpdir}/wireproxy.tar.gz"

  curl -fsSL "$url" -o "$tgz" || die "Gagal download wireproxy."
  tar -xzf "$tgz" -C "$tmpdir" >/dev/null 2>&1 || die "Gagal extract wireproxy."
  bin="$(find "$tmpdir" -type f -name wireproxy -print -quit)"
  [[ -n "${bin:-}" && -f "$bin" ]] || die "Binary wireproxy tidak ditemukan setelah extract."
  install -m 755 "$bin" /usr/local/bin/wireproxy

  rm -rf "$tmpdir"
  ok "wireproxy terpasang."
}

setup_wgcf() {
  ok "Setup wgcf (register & generate)..."

  mkdir -p /etc/wgcf

  # Jika /etc/wgcf pernah menjadi file, pindahkan agar tidak bikin exit diam-diam saat pushd.
  if [[ -e /etc/wgcf && ! -d /etc/wgcf ]]; then
    mv -f /etc/wgcf "/etc/wgcf.bak.$(date +%s)" || true
    mkdir -p /etc/wgcf
  fi

  pushd /etc/wgcf >/dev/null || die "Gagal masuk ke /etc/wgcf."

  if [[ ! -f wgcf-account.toml ]]; then
    local reg_log
    reg_log="$(mktemp "/tmp/wgcf-register.XXXXXX.log")"

    # wgcf versi baru kadang pakai prompt berbasis TTY (arrow-keys). `yes |` sering tidak efektif.
    if command -v expect >/dev/null 2>&1; then
      expect <<'EOF' >"$reg_log" 2>&1 || true
set timeout 180
log_user 1
spawn wgcf register
# Coba accept prompt dengan Enter / y
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
      # Fallback legacy (lebih rentan), tapi tetap kita log.
      set +o pipefail
      yes | wgcf register >"$reg_log" 2>&1 || true
      set -o pipefail
    fi

    [[ -f wgcf-account.toml ]] || {
      tail -n 120 "$reg_log" >&2 || true
      die "wgcf register gagal. Lihat log: $reg_log"
    }
    rm -f "$reg_log" >/dev/null 2>&1 || true
  fi

  local gen_log
  gen_log="$(mktemp "/tmp/wgcf-generate.XXXXXX.log")"
  wgcf generate >"$gen_log" 2>&1 || {
    tail -n 120 "$gen_log" >&2 || true
    die "wgcf generate gagal. Lihat log: $gen_log"
  }
  [[ -f wgcf-profile.conf ]] || {
    tail -n 120 "$gen_log" >&2 || true
    die "wgcf-profile.conf tidak ditemukan setelah generate."
  }
  rm -f "$gen_log" >/dev/null 2>&1 || true

  popd >/dev/null || die "Gagal kembali dari /etc/wgcf."
  ok "wgcf selesai."
}

setup_wireproxy() {
  ok "Setup wireproxy..."

  mkdir -p /etc/wireproxy
  cp -f /etc/wgcf/wgcf-profile.conf /etc/wireproxy/config.conf

  # wireproxy v1.0.9 memakai section [Socks5], bukan [Socks].
  # Rebuild section SOCKS agar idempotent dan menghindari salah format lama.
  local wp_conf="/etc/wireproxy/config.conf"
  local wp_tmp
  wp_tmp="$(mktemp)"
  awk '
    BEGIN { drop=0 }
    /^\[(Socks|Socks5)\]$/ { drop=1; next }
    /^\[.*\]$/ { drop=0 }
    drop { next }
    { print }
  ' "$wp_conf" > "$wp_tmp"
  cat >> "$wp_tmp" <<'EOF'

[Socks5]
BindAddress = 127.0.0.1:40000
EOF
  install -m 600 "$wp_tmp" "$wp_conf"
  rm -f "$wp_tmp"

  cat > /etc/systemd/system/wireproxy.service <<'EOF'
[Unit]
Description=Wireproxy (WARP) SOCKS5 Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wireproxy -c /etc/wireproxy/config.conf
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  service_enable_restart_checked wireproxy || die "wireproxy gagal diaktifkan. Cek: journalctl -u wireproxy -n 100 --no-pager"
  ok "wireproxy service aktif."
}

cleanup_wgcf_files() {
  ok "Cleanup file wgcf (wgcf-profile.conf & wgcf-account.toml)..."

  rm -f /etc/wgcf/wgcf-profile.conf /etc/wgcf/wgcf-account.toml || true
  ok "Cleanup wgcf selesai."
}

enable_cron_service() {
  ok "Enable cron..."

  local cron_svc=""
  if service_enable_restart_checked cron; then
    cron_svc="cron"
  elif service_enable_restart_checked crond; then
    cron_svc="crond"
  else
    die "Gagal mengaktifkan cron maupun crond."
  fi

  ok "cron aktif (${cron_svc})."
}

setup_xray_geodata_updater() {
  ok "Setup updater geodata Xray-core (24 jam)..."

  cat > /usr/local/bin/xray-update-geodata <<EOF
#!/usr/bin/env bash
set -euo pipefail

URL="${XRAY_INSTALL_SCRIPT_URL}"
URL_SHA256="${XRAY_INSTALL_SCRIPT_SHA256}"
CUSTOM_URL="${CUSTOM_GEOSITE_URL}"
CUSTOM_SHA256="${CUSTOM_GEOSITE_SHA256}"
CUSTOM_DEST="${CUSTOM_GEOSITE_DEST}"
tmp="\$(mktemp)"
tmp_custom="\$(mktemp)"
cleanup() {
  rm -f "\${tmp}" >/dev/null 2>&1 || true
  rm -f "\${tmp_custom}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl -fsSL --connect-timeout 15 --max-time 120 "\${URL}" -o "\${tmp}"
if [[ -n "\${URL_SHA256}" ]]; then
  got="\$(sha256sum "\${tmp}" | awk '{print tolower(\$1)}')"
  [[ "\${got}" == "\${URL_SHA256,,}" ]] || {
    echo "[xray-update-geodata] checksum mismatch installer geodata" >&2
    echo " expected=\${URL_SHA256,,}" >&2
    echo " actual=\${got}" >&2
    exit 1
  }
fi
bash "\${tmp}" install-geodata >/dev/null 2>&1

mkdir -p "\$(dirname "\${CUSTOM_DEST}")"
curl -fsSL --connect-timeout 15 --max-time 120 "\${CUSTOM_URL}" -o "\${tmp_custom}"
[[ -s "\${tmp_custom}" ]] || { echo "[xray-update-geodata] custom.dat kosong: \${CUSTOM_URL}" >&2; exit 1; }
if [[ -n "\${CUSTOM_SHA256}" ]]; then
  got_custom="\$(sha256sum "\${tmp_custom}" | awk '{print tolower(\$1)}')"
  [[ "\${got_custom}" == "\${CUSTOM_SHA256,,}" ]] || {
    echo "[xray-update-geodata] checksum mismatch custom geosite" >&2
    echo " expected=\${CUSTOM_SHA256,,}" >&2
    echo " actual=\${got_custom}" >&2
    exit 1
  }
fi
install -m 644 "\${tmp_custom}" "\${CUSTOM_DEST}"
EOF

  chmod +x /usr/local/bin/xray-update-geodata

  cat > /etc/cron.d/xray-update-geodata <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 4 * * * root /usr/local/bin/xray-update-geodata >/dev/null 2>&1
EOF

  ok "Cron geodata updater terpasang: /etc/cron.d/xray-update-geodata"


  ok "Menjalankan update geodata pertama kali..."
  /usr/local/bin/xray-update-geodata || die "Gagal update geodata pertama kali (cek koneksi ke github.com)."
  ok "Update geodata pertama kali selesai."

}

install_custom_geosite_adblock() {
  ok "Download custom geosite adblock (custom.dat)..."
  mkdir -p "${XRAY_ASSET_DIR}"

  local tmp
  tmp="$(mktemp)"
  download_file_or_die "${CUSTOM_GEOSITE_URL}" "${tmp}" "${CUSTOM_GEOSITE_SHA256}" "custom geosite"
  [[ -s "${tmp}" ]] || {
    rm -f "${tmp}" >/dev/null 2>&1 || true
    die "File custom geosite kosong: ${CUSTOM_GEOSITE_URL}"
  }

  install -m 644 "${tmp}" "${CUSTOM_GEOSITE_DEST}"
  rm -f "${tmp}" >/dev/null 2>&1 || true
  ok "custom.dat tersimpan di: ${CUSTOM_GEOSITE_DEST}"
}

setup_logrotate() {
  ok "Setup logrotate (nginx & xray)..."

  cat > /etc/logrotate.d/xray-nginx <<'EOF'
/var/log/nginx/*.log /var/log/xray/*.log {
  daily
  rotate 7
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF

  # Jika ada mekanisme cron truncate lama, hapus supaya tidak double.
  rm -f /etc/cron.d/cleanup-xray-nginx-logs /usr/local/bin/cleanup-xray-nginx-logs 2>/dev/null || true

  ok "Logrotate aktif: /etc/logrotate.d/xray-nginx"
}

install_management_scripts() {
  ok "Menyiapkan script manajemen (placeholder) ..."

  mkdir -p /opt/account/vless /opt/account/vmess /opt/account/trojan
  mkdir -p /opt/quota/vless /opt/quota/vmess /opt/quota/trojan
  chmod 700 /opt/account /opt/account/vless /opt/account/vmess /opt/account/trojan
  chmod 700 /opt/quota  /opt/quota/vless  /opt/quota/vmess  /opt/quota/trojan

  cat > /usr/local/bin/xray-expired <<'EOF'
#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone

XRAY_CONFIG_DEFAULT   = "/usr/local/etc/xray/conf.d/30-routing.json"
XRAY_INBOUNDS_DEFAULT = "/usr/local/etc/xray/conf.d/10-inbounds.json"
XRAY_ROUTING_DEFAULT  = "/usr/local/etc/xray/conf.d/30-routing.json"
ACCOUNT_ROOT = "/opt/account"
QUOTA_ROOT = "/opt/quota"
SPEED_ROOT = "/opt/speed"
PROTO_DIRS = ("vless", "vmess", "trojan")

def now_utc():
  return datetime.now(timezone.utc)

def parse_iso8601(value):
  if not value:
    return None
  s = str(value).strip()
  if s.endswith("Z"):
    s = s[:-1] + "+00:00"
  try:
    dt = datetime.fromisoformat(s)
  except Exception:
    return None
  if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)
  return dt

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def save_json_atomic(path, data):
  # BUG-10 fix: use mkstemp (unique name) instead of fixed "{path}.tmp"
  # to prevent concurrent writers from corrupting each other's tmp file.
  import tempfile
  dirn = os.path.dirname(path) or "."
  st_mode = None
  st_uid = None
  st_gid = None
  try:
    st = os.stat(path)
    st_mode = st.st_mode & 0o777
    st_uid = st.st_uid
    st_gid = st.st_gid
  except FileNotFoundError:
    pass
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st_mode is not None:
      os.chmod(tmp, st_mode)
    if st_uid is not None and st_gid is not None:
      try:
        os.chown(tmp, st_uid, st_gid)
      except PermissionError:
        pass
    os.replace(tmp, path)
  except Exception:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass
    raise

ROUTING_LOCK_PATH = "/var/lock/xray-routing.lock"

def save_routing_atomic_locked(inbounds_path, inb_data, routing_path, rt_data):
  """BUG-15 note: xray-expired has a 4-argument signature (inbounds + routing) because
  it writes BOTH files atomically in one lock. The other daemons (user-block, xray-quota,
  limit-ip) use a 2-argument signature (config_path, cfg) because they only write routing.
  These signatures are intentionally different — do NOT unify without careful review.
  Tulis kedua file config secara atomik dengan file lock untuk cegah race condition
  dengan daemon lain (xray-quota, limit-ip) yang juga bisa menulis routing config."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      save_json_atomic(inbounds_path, inb_data)
      save_json_atomic(routing_path, rt_data)
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def restart_xray():
  subprocess.run(
    ["systemctl", "restart", "xray"],
    check=False,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )

def remove_user_from_inbounds(cfg, username):
  changed = False
  inbounds = cfg.get("inbounds") or []
  for inbound in inbounds:
    settings = inbound.get("settings") or {}
    clients = settings.get("clients")
    if not isinstance(clients, list):
      continue
    new_clients = []
    for c in clients:
      if c.get("email") == username:
        changed = True
        continue
      new_clients.append(c)
    settings["clients"] = new_clients
    inbound["settings"] = settings
  return changed

def remove_user_from_rules(cfg, username):
  # Hanya bersihkan dari rule yang mengandung dummy markers (manajemen user).
  # Konsisten dengan manage.sh xray_delete_client — custom rules non-marker
  # tidak disentuh agar tidak kehilangan konfigurasi routing lain.
  changed = False
  markers = {
    "dummy-block-user", "dummy-quota-user", "dummy-limit-user",
    "dummy-warp-user", "dummy-direct-user",
  }
  speed_marker_prefix = "dummy-speed-user-"
  rules = ((cfg.get("routing") or {}).get("rules")) or []
  for rule in rules:
    users = rule.get("user")
    if not isinstance(users, list):
      continue
    # Lewati rule yang bukan milik sistem manajemen user
    is_managed = any(m in users for m in markers)
    if not is_managed:
      for u in users:
        if isinstance(u, str) and u.startswith(speed_marker_prefix):
          is_managed = True
          break
    if not is_managed:
      continue
    if username in users:
      rule["user"] = [u for u in users if u != username]
      changed = True
  return changed

def iter_quota_files():
  for proto in PROTO_DIRS:
    d = os.path.join(QUOTA_ROOT, proto)
    if not os.path.isdir(d):
      continue
    for name in os.listdir(d):
      if name.endswith(".json"):
        yield proto, os.path.join(d, name)

def quota_key_from_path(path):
  return os.path.splitext(os.path.basename(path))[0]

def canonical_email(proto, user_key):
  # Legacy quota file bisa bernama "username.json" (tanpa @proto).
  # Untuk operasi config Xray, normalisasikan ke format email "username@proto".
  if not user_key:
    return user_key
  if "@" in user_key:
    return user_key
  return f"{user_key}@{proto}"

def is_expired(meta, ts):
  exp = parse_iso8601(meta.get("expired_at") if isinstance(meta, dict) else None)
  if exp is None:
    return False
  return exp <= ts

def _remove_file(path):
  try:
    if os.path.exists(path):
      os.remove(path)
  except Exception:
    pass

def delete_user_artifacts(proto, user_key, quota_path):
  # 1) quota json: /opt/quota/<proto>/<username@proto>.json
  _remove_file(quota_path)

  # 2) account txt (format baru): /opt/account/<proto>/<username@proto>.txt
  _remove_file(os.path.join(ACCOUNT_ROOT, proto, f"{user_key}.txt"))

  # 3) account txt (format lama/legacy): /opt/account/<proto>/<username>.txt
  # Konsisten dengan manage.sh delete_account_artifacts yang juga hapus keduanya.
  bare = user_key.split("@")[0] if "@" in user_key else user_key
  if bare != user_key:
    _remove_file(os.path.join(ACCOUNT_ROOT, proto, f"{bare}.txt"))

  # 4) quota json legacy: /opt/quota/<proto>/<username>.json
  # Jika ada sisa file lama, bersihkan juga.
  if bare != user_key:
    _remove_file(os.path.join(QUOTA_ROOT, proto, f"{bare}.json"))

  # 5) speed policy (format baru + fallback legacy)
  speed_candidates = {
    os.path.join(SPEED_ROOT, proto, f"{user_key}.json"),
    os.path.join(SPEED_ROOT, proto, f"{bare}@{proto}.json"),
    os.path.join(SPEED_ROOT, proto, f"{bare}.json"),
  }
  for sp in speed_candidates:
    _remove_file(sp)

def run_once(inbounds_path, routing_path, dry_run=False):
  ts = now_utc()
  expired = []  # list[(proto, user_key, quota_path)]

  for proto, path in iter_quota_files():
    try:
      meta = load_json(path)
    except Exception:
      continue

    user_key = quota_key_from_path(path)
    if isinstance(meta, dict):
      u2 = meta.get("username")
      # Prioritaskan meta["username"] jika ada dan tidak kosong.
      # Field ini selalu ditulis manage.sh sebagai "username@proto".
      if isinstance(u2, str) and u2.strip():
        user_key = u2.strip()
    if not user_key:
      continue

    if is_expired(meta, ts):
      expired.append((proto, user_key, path))

  if not expired:
    return 0

  if dry_run:
    for _, user_key, _ in expired:
      print(user_key)
    return 0

  # PENTING: reload inbounds dan routing dari disk sebelum modifikasi+save
  # untuk menghindari overwrite perubahan concurrent dari manage.sh atau daemon lain.
  try:
    inb_cfg = load_json(inbounds_path)
    rt_cfg = load_json(routing_path)
  except Exception:
    return 0

  # Re-check expiry setelah reload disk: cegah race condition dengan
  # manage.sh extend-expiry yang mungkin sudah update quota file
  # antara scan awal dan reload config ini.
  ts2 = now_utc()
  confirmed = []
  for proto, user_key, qpath in expired:
    try:
      meta_fresh = load_json(qpath)
    except FileNotFoundError:
      # File sudah dihapus pihak lain — tetap lanjut bersihkan dari config.
      confirmed.append((proto, user_key, qpath))
      continue
    except Exception:
      continue
    if is_expired(meta_fresh, ts2):
      confirmed.append((proto, user_key, qpath))
    # Jika tidak lagi expired (sudah di-extend), lewati.

  if not confirmed:
    return 0

  # PENTING: reload inbounds dan routing dari disk sebelum modifikasi+save
  # untuk menghindari overwrite perubahan concurrent dari manage.sh atau daemon lain.
  try:
    inb_cfg = load_json(inbounds_path)
    rt_cfg = load_json(routing_path)
  except Exception:
    return 0

  changed_inb = False
  changed_rt = False
  for proto, user_key, _ in confirmed:
    email_key = canonical_email(proto, user_key)
    changed_inb = remove_user_from_inbounds(inb_cfg, email_key) or changed_inb
    changed_rt = remove_user_from_rules(rt_cfg, email_key) or changed_rt

  # BUG-04 fix: save config FIRST, delete artifacts only on success.
  # Previously artifacts were deleted before save, causing permanent inconsistency
  # if save failed (disk full, xray crash, etc.): files gone but user still in config.
  config_saved = False
  if changed_inb or changed_rt:
    try:
      save_routing_atomic_locked(inbounds_path, inb_cfg, routing_path, rt_cfg)
      config_saved = True
    except Exception:
      # Config save failed — do NOT delete artifacts to avoid orphan state.
      return 0
    restart_xray()

  # Delete artifacts only after config has been saved successfully.
  # If nothing changed in config (user wasn't in inbounds/routing), still clean up.
  for proto, user_key, qpath in confirmed:
    delete_user_artifacts(proto, user_key, qpath)

  return 0

def main():
  ap = argparse.ArgumentParser(prog="xray-expired")
  ap.add_argument("--inbounds", default=XRAY_INBOUNDS_DEFAULT)
  ap.add_argument("--routing", default=XRAY_ROUTING_DEFAULT)
  ap.add_argument("--interval", type=int, default=2)
  ap.add_argument("--once", action="store_true")
  ap.add_argument("--dry-run", action="store_true")
  args = ap.parse_args()

  if args.once:
    return run_once(args.inbounds, args.routing, dry_run=args.dry_run)

  interval = max(1, int(args.interval))
  while True:
    try:
      run_once(args.inbounds, args.routing, dry_run=args.dry_run)
    except Exception:
      pass
    time.sleep(interval)

if __name__ == "__main__":
  raise SystemExit(main())
EOF
  chmod +x /usr/local/bin/xray-expired

  cat > /usr/local/bin/limit-ip <<'EOF'
#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

XRAY_CONFIG_DEFAULT = "/usr/local/etc/xray/conf.d/30-routing.json"
QUOTA_ROOT = "/opt/quota"
PROTO_DIRS = ("vless", "vmess", "trojan")
XRAY_ACCESS_LOG = "/var/log/xray/access.log"

EMAIL_RE = re.compile(r"(?:email|user)\s*[:=]\s*([A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9._-]{1,128})")
# BUG-07 fix: added IPv6 support. Previously only IPv4 was matched, so clients
# connecting via IPv6 were never detected and ip-limit never triggered for them.
# New pattern matches:
#   IPv4:  "from 1.2.3.4:12345"
#   IPv6:  "from [::1]:12345" or "from 2001:db8::1:12345" (bare, without brackets)
IP_RE = re.compile(
  r"\bfrom\s+"
  r"(?:"
    r"\[([0-9a-fA-F:]{2,39})\]:\d{1,5}"       # [IPv6]:port
    r"|(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}"      # IPv4:port
    r"|([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}):\d{1,5}"  # bare IPv6:port
  r")"
)

def extract_ip_from_match(m):
  """Extract IP string from IP_RE match (handles IPv4 and IPv6 groups)."""
  if m is None:
    return None
  return m.group(1) or m.group(2) or m.group(3)

def safe_int(v, default=0):
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

def now_iso():
  return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def save_json_atomic(path, data):
  # BUG-10 fix: use mkstemp (unique name) instead of fixed "{path}.tmp"
  # to prevent concurrent writers from corrupting each other's tmp file.
  import tempfile
  dirn = os.path.dirname(path) or "."
  st_mode = None
  st_uid = None
  st_gid = None
  try:
    st = os.stat(path)
    st_mode = st.st_mode & 0o777
    st_uid = st.st_uid
    st_gid = st.st_gid
  except FileNotFoundError:
    pass
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st_mode is not None:
      os.chmod(tmp, st_mode)
    if st_uid is not None and st_gid is not None:
      try:
        os.chown(tmp, st_uid, st_gid)
      except PermissionError:
        pass
    os.replace(tmp, path)
  except Exception:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass
    raise

ROUTING_LOCK_PATH = "/var/lock/xray-routing.lock"

def save_routing_atomic_locked(config_path, cfg):
  """Tulis routing config secara atomik dengan file lock bersama."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      save_json_atomic(config_path, cfg)
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def load_and_modify_routing_locked(config_path, modify_fn):
  """BUG-01 fix: acquire lock FIRST, then reload config from disk, apply modify_fn, save.
  Prevents last-write-wins race condition with other daemons."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      cfg = load_json(config_path)
      changed = modify_fn(cfg)
      if changed:
        save_json_atomic(config_path, cfg)
      return changed, cfg
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def find_marker_rule(cfg, marker, outbound_tag):
  # BUG-FIX: fungsi ini wajib ada di limit-ip — sebelumnya hanya terdefinisi
  # di xray-quota sehingga limit-ip crash NameError saat startup/watch/unlock.
  rules = ((cfg.get("routing") or {}).get("rules")) or []
  for r in rules:
    if r.get("type") != "field":
      continue
    if r.get("outboundTag") != outbound_tag:
      continue
    users = r.get("user") or []
    if isinstance(users, list) and marker in users:
      return r
  return None

def restart_xray():
  subprocess.run(["systemctl", "restart", "xray"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ensure_user(rule, username, marker=None):
  users = rule.get("user") or []
  if not isinstance(users, list):
    users = []
  if marker is not None and marker not in users:
    users.insert(0, marker)
  if username not in users:
    users.append(username)
    rule["user"] = users
    return True
  rule["user"] = users
  return False

def remove_user(rule, username):
  users = rule.get("user") or []
  if not isinstance(users, list) or username not in users:
    return False
  rule["user"] = [u for u in users if u != username]
  return True

def quota_paths(username):
  """Kembalikan semua path quota JSON yang cocok untuk username.
  Mendukung format baru (username@proto.json) dan lama (username.json).
  Jika username berisi '@', hanya cari di proto yang sesuai (bukan semua proto).
  Jika bare username, coba username@proto.json dulu di semua proto lalu fallback legacy."""
  paths = []
  if "@" in username:
    # Full email (mis. "alice@vless"): ekstrak proto dari email, cari hanya di proto itu.
    # Ini menghindari false-positive lookup ke proto yang salah (mis. alice@vless.json
    # dicari di /opt/quota/vmess/ dan /opt/quota/trojan/ yang pasti tidak ada).
    parts = username.split("@", 1)
    email_proto = parts[1] if len(parts) == 2 else ""
    # Cari di proto yang cocok dengan email terlebih dulu
    if email_proto in PROTO_DIRS:
      p = os.path.join(QUOTA_ROOT, email_proto, f"{username}.json")
      if os.path.isfile(p):
        paths.append(p)
    # Fallback: iterasi semua proto (antisipasi file di tempat yang tidak terduga)
    if not paths:
      for proto in PROTO_DIRS:
        if proto == email_proto:
          continue  # sudah dicek di atas
        p = os.path.join(QUOTA_ROOT, proto, f"{username}.json")
        if os.path.isfile(p) and p not in paths:
          paths.append(p)
  else:
    # Bare username: coba username@proto.json (format baru manage.sh) lalu fallback legacy
    for proto in PROTO_DIRS:
      candidates = [
        os.path.join(QUOTA_ROOT, proto, f"{username}@{proto}.json"),
        os.path.join(QUOTA_ROOT, proto, f"{username}.json"),
      ]
      for p in candidates:
        if os.path.isfile(p) and p not in paths:
          paths.append(p)
  return paths

def get_status(username):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    if not isinstance(meta, dict):
      continue
    st_raw = meta.get("status") if isinstance(meta, dict) else {}
    st = st_raw if isinstance(st_raw, dict) else {}
    return st
  return {}

def set_status(username, enabled=None, limit=None):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    if not isinstance(meta, dict):
      continue
    st_raw = meta.get("status") if isinstance(meta, dict) else {}
    st = st_raw if isinstance(st_raw, dict) else {}
    if enabled is not None:
      st["ip_limit_enabled"] = bool(enabled)
    if limit is not None:
      st["ip_limit"] = int(limit)
    st.setdefault("ip_limit_locked", False)
    meta["status"] = st
    save_json_atomic(p, meta)

def lock_user(username):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    if not isinstance(meta, dict):
      continue
    st_raw = meta.get("status") if isinstance(meta, dict) else {}
    st = st_raw if isinstance(st_raw, dict) else {}
    st["ip_limit_locked"] = True
    # Hanya set lock_reason='ip_limit' jika tidak ada lock prioritas lebih tinggi
    # BUG-FIX #5: prioritas seragam: manual > quota > ip_limit (komentar lama salah).
    # lock_user hanya cek manual_block karena saat ip_limit trigger, quota belum tentu exhausted;
    # xray-quota akan set lock_reason=quota jika memang quota exhausted juga.
    if not bool(st.get("manual_block", False)):
      st["lock_reason"] = "ip_limit"
      st["locked_at"] = now_iso()
    elif not st.get("locked_at"):
      st["locked_at"] = now_iso()
    meta["status"] = st
    save_json_atomic(p, meta)

def unlock_user(username):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    if not isinstance(meta, dict):
      continue
    st_raw = meta.get("status") if isinstance(meta, dict) else {}
    st = st_raw if isinstance(st_raw, dict) else {}
    st["ip_limit_locked"] = False
    if st.get("lock_reason") == "ip_limit":
      # Turunkan lock_reason ke lock lain yang masih aktif (jika ada),
      # agar status display di manage.sh tetap akurat.
      if bool(st.get("manual_block", False)):
        st["lock_reason"] = "manual"
      elif bool(st.get("quota_exhausted", False)):
        st["lock_reason"] = "quota"
      else:
        st["lock_reason"] = ""
        st["locked_at"] = ""
    meta["status"] = st
    save_json_atomic(p, meta)

def parse_line(line):
  m1 = EMAIL_RE.search(line)
  m2 = IP_RE.search(line)
  if not m1 or not m2:
    return None, None
  # BUG-07 fix: use helper to extract IP from whichever group matched (IPv4/IPv6)
  ip = extract_ip_from_match(m2)
  if not ip:
    return None, None
  return m1.group(1), ip

def tail_follow(path):
  p = subprocess.Popen(["tail", "-n", "0", "-F", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
  try:
    for line in p.stdout:
      yield line.rstrip("\n")
  finally:
    try:
      p.terminate()
    except Exception:
      pass

def watch(config_path, marker, window_seconds):
  # Verifikasi marker tersedia saat startup
  try:
    _cfg_init = load_json(config_path)
  except Exception as e:
    print(f"[limit-ip] Gagal load config: {e}", file=sys.stderr)
    return 1
  if find_marker_rule(_cfg_init, marker, "blocked") is None:
    print(f"[limit-ip] Marker rule tidak ditemukan: {marker}", file=sys.stderr)
    return 1

  seen = {}  # user -> ip -> last_seen_epoch
  last_restart = 0.0
  min_restart_interval = 15.0
  event_count = 0
  # Cleanup seluruh seen dict dilakukan setiap N event, bukan setiap event,
  # untuk menghindari O(users*ips) overhead pada traffic tinggi.
  CLEANUP_INTERVAL = 200

  for line in tail_follow(XRAY_ACCESS_LOG):
    user, ip = parse_line(line)
    if not user or not ip:
      continue

    st = get_status(user)
    if not st:
      continue
    if not bool(st.get("ip_limit_enabled", False)):
      continue
    lim = safe_int(st.get("ip_limit", 0), 0)
    if lim <= 0:
      continue
    if bool(st.get("ip_limit_locked", False)):
      continue

    now = time.time()
    bucket = seen.setdefault(user, {})
    bucket[ip] = now

    event_count += 1
    if event_count >= CLEANUP_INTERVAL:
      # Periodik cleanup: hapus entry kadaluarsa dari semua user sekaligus
      event_count = 0
      cutoff = now - float(window_seconds)
      for u in list(seen.keys()):
        ips = seen[u]
        for ip2 in [k for k, ts in ips.items() if ts < cutoff]:
          del ips[ip2]
        if not ips:
          del seen[u]

    if len(seen.get(user, {})) > lim:
      lock_user(user)
      # Setelah lock, hapus entry user dari seen agar tidak lock berulang
      # sebelum xray-limit-ip service di-restart.
      seen.pop(user, None)
      # PENTING: reload config dari disk sebelum save untuk menghindari
      # overwrite perubahan concurrent dari manage.sh atau daemon lain.
      # BUG-01 fix: use load_and_modify_routing_locked (read inside lock)
      def do_lock(cfg):
        rule = find_marker_rule(cfg, marker, "blocked")
        if rule is None:
          return False
        return ensure_user(rule, user, marker)
      changed, _ = load_and_modify_routing_locked(config_path, do_lock)
      if changed:
        if now - last_restart >= min_restart_interval:
          restart_xray()
          last_restart = now

  return 0

def cli():
  ap = argparse.ArgumentParser(prog="limit-ip")
  sub = ap.add_subparsers(dest="cmd", required=True)

  p_set = sub.add_parser("set")
  p_set.add_argument("username")
  p_set.add_argument("--enable", action="store_true")
  p_set.add_argument("--disable", action="store_true")
  p_set.add_argument("--limit", type=int)

  p_unlock = sub.add_parser("unlock")
  p_unlock.add_argument("username")

  p_watch = sub.add_parser("watch")
  p_watch.add_argument("--config", default=XRAY_CONFIG_DEFAULT)
  p_watch.add_argument("--marker", default="dummy-limit-user")
  p_watch.add_argument("--window-seconds", type=int, default=600)

  args = ap.parse_args()

  if args.cmd == "set":
    if args.enable and args.disable:
      ap.error("Pilih salah satu: --enable atau --disable")
    enabled = None
    if args.enable:
      enabled = True
    if args.disable:
      enabled = False
    set_status(args.username, enabled=enabled, limit=args.limit)
    print("OK")
    return 0

  if args.cmd == "unlock":
    unlock_user(args.username)
    # BUG-01 fix: read routing config INSIDE lock, same pattern as other daemons
    def do_unlock(cfg):
      rule = find_marker_rule(cfg, "dummy-limit-user", "blocked")
      if rule is None:
        return False
      return remove_user(rule, args.username)
    changed, _ = load_and_modify_routing_locked(XRAY_CONFIG_DEFAULT, do_unlock)
    if changed:
      restart_xray()
    print("OK")
    return 0

  if args.cmd == "watch":
    return watch(args.config, args.marker, args.window_seconds)

  return 0

if __name__ == "__main__":
  raise SystemExit(cli())
EOF
  chmod +x /usr/local/bin/limit-ip

  cat > /usr/local/bin/user-block <<'EOF'
#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from datetime import datetime, timezone

XRAY_CONFIG_DEFAULT = "/usr/local/etc/xray/conf.d/30-routing.json"
QUOTA_ROOT = "/opt/quota"
PROTO_DIRS = ("vless", "vmess", "trojan")

def now_iso():
  return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def save_json_atomic(path, data):
  # BUG-10 fix: use mkstemp (unique name) instead of fixed "{path}.tmp"
  # to prevent concurrent writers from corrupting each other's tmp file.
  import tempfile
  dirn = os.path.dirname(path) or "."
  st_mode = None
  st_uid = None
  st_gid = None
  try:
    st = os.stat(path)
    st_mode = st.st_mode & 0o777
    st_uid = st.st_uid
    st_gid = st.st_gid
  except FileNotFoundError:
    pass
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st_mode is not None:
      os.chmod(tmp, st_mode)
    if st_uid is not None and st_gid is not None:
      try:
        os.chown(tmp, st_uid, st_gid)
      except PermissionError:
        pass
    os.replace(tmp, path)
  except Exception:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass
    raise

ROUTING_LOCK_PATH = "/var/lock/xray-routing.lock"

def save_routing_atomic_locked(config_path, cfg):
  """Tulis routing config secara atomik dengan file lock bersama."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      save_json_atomic(config_path, cfg)
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def load_and_modify_routing_locked(config_path, modify_fn):
  """BUG-01 fix: acquire lock, reload config from disk, apply modify_fn, save.
  This prevents last-write-wins race condition when multiple daemons write routing.
  Returns (changed: bool, cfg: dict)."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      # Reload from disk while holding the lock — picks up any concurrent changes
      cfg = load_json(config_path)
      changed = modify_fn(cfg)
      if changed:
        save_json_atomic(config_path, cfg)
      return changed, cfg
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def restart_xray():
  # BUG-FIX: fungsi ini wajib ada di user-block — sebelumnya tidak terdefinisi
  # sehingga user-block crash NameError saat block/unblock dipanggil.
  subprocess.run(["systemctl", "restart", "xray"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def find_marker_rule(cfg, marker, outbound_tag):
  # BUG-FIX: fungsi ini wajib ada di user-block — sebelumnya hanya terdefinisi
  # di xray-quota sehingga user-block crash NameError saat modify() dijalankan.
  rules = ((cfg.get("routing") or {}).get("rules")) or []
  for r in rules:
    if r.get("type") != "field":
      continue
    if r.get("outboundTag") != outbound_tag:
      continue
    users = r.get("user") or []
    if isinstance(users, list) and marker in users:
      return r
  return None

def ensure_user(rule, username, marker):
  # BUG-FIX: fungsi ini wajib ada di user-block — sebelumnya tidak terdefinisi.
  users = rule.get("user") or []
  if not isinstance(users, list):
    users = []
  if marker not in users:
    users.insert(0, marker)
  if username not in users:
    users.append(username)
    rule["user"] = users
    return True
  rule["user"] = users
  return False

def remove_user(rule, username):
  # BUG-FIX: fungsi ini wajib ada di user-block — sebelumnya tidak terdefinisi.
  users = rule.get("user") or []
  if not isinstance(users, list) or username not in users:
    return False
  rule["user"] = [u for u in users if u != username]
  return True

def quota_paths_for_user(username):
  """Kembalikan path quota JSON untuk username.
  Mendukung format baru (username@proto.json) dan lama (username.json).
  Jika username berisi '@', prioritaskan proto yang sesuai sebelum fallback ke semua proto."""
  paths = []
  if "@" in username:
    parts = username.split("@", 1)
    email_proto = parts[1] if len(parts) == 2 else ""
    if email_proto in PROTO_DIRS:
      p = os.path.join(QUOTA_ROOT, email_proto, f"{username}.json")
      if os.path.isfile(p):
        paths.append(p)
    if not paths:
      for proto in PROTO_DIRS:
        if proto == email_proto:
          continue
        p = os.path.join(QUOTA_ROOT, proto, f"{username}.json")
        if os.path.isfile(p) and p not in paths:
          paths.append(p)
  else:
    for proto in PROTO_DIRS:
      candidates = [
        os.path.join(QUOTA_ROOT, proto, f"{username}@{proto}.json"),
        os.path.join(QUOTA_ROOT, proto, f"{username}.json"),
      ]
      for p in candidates:
        if os.path.isfile(p) and p not in paths:
          paths.append(p)
  return paths

def update_quota_status(username, manual_block):
  for p in quota_paths_for_user(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    if not isinstance(meta, dict):
      continue
    st_raw = meta.get("status") if isinstance(meta, dict) else {}
    st = st_raw if isinstance(st_raw, dict) else {}
    st["manual_block"] = bool(manual_block)
    if manual_block:
      st["lock_reason"] = "manual"
      st["locked_at"] = now_iso()
    else:
      if st.get("lock_reason") == "manual":
        # BUG-05 fix: correct priority order is manual > quota > ip_limit.
        # Previously ip_limit was checked before quota (wrong order).
        if bool(st.get("quota_exhausted", False)):
          st["lock_reason"] = "quota"
        elif bool(st.get("ip_limit_locked", False)):
          st["lock_reason"] = "ip_limit"
        else:
          st["lock_reason"] = ""
          st["locked_at"] = ""
    meta["status"] = st
    save_json_atomic(p, meta)

def main():
  ap = argparse.ArgumentParser(prog="user-block")
  ap.add_argument("action", choices=["block", "unblock"])
  ap.add_argument("username")
  ap.add_argument("--config", default=XRAY_CONFIG_DEFAULT)
  ap.add_argument("--marker", default="dummy-block-user")
  args = ap.parse_args()

  # BUG-01 fix: use load_and_modify_routing_locked so config is read INSIDE the
  # exclusive lock. Previously cfg was loaded before acquiring the lock, allowing
  # concurrent daemons (xray-quota, limit-ip) to overwrite changes made here.
  marker = args.marker
  username = args.username
  action = args.action

  def modify(cfg):
    rule = find_marker_rule(cfg, marker, "blocked")
    if rule is None:
      raise SystemExit(f"Marker rule not found: {marker}")
    if action == "block":
      return ensure_user(rule, username, marker)
    else:
      return remove_user(rule, username)

  changed, _ = load_and_modify_routing_locked(args.config, modify)

  # Update quota file status (outside lock — quota files have their own atomicity)
  if action == "block":
    update_quota_status(username, True)
  else:
    update_quota_status(username, False)

  if changed:
    restart_xray()

  print("OK")

if __name__ == "__main__":
  main()
EOF
  chmod +x /usr/local/bin/user-block


  cat > /usr/local/bin/xray-quota <<'EOF'
#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone

XRAY_CONFIG_DEFAULT = "/usr/local/etc/xray/conf.d/30-routing.json"
API_SERVER_DEFAULT = "127.0.0.1:10080,127.0.0.1:10085"
API_SERVER_FALLBACKS = ("127.0.0.1:10080", "127.0.0.1:10085")
QUOTA_ROOT = "/opt/quota"
PROTO_DIRS = ("vless", "vmess", "trojan")

GB_DECIMAL = 1000 ** 3
GB_BINARY = 1024 ** 3

def now_iso():
  return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def save_json_atomic(path, data):
  # BUG-10 fix: use mkstemp (unique name) instead of fixed "{path}.tmp"
  # to prevent concurrent writers from corrupting each other's tmp file.
  import tempfile
  dirn = os.path.dirname(path) or "."
  st_mode = None
  st_uid = None
  st_gid = None
  try:
    st = os.stat(path)
    st_mode = st.st_mode & 0o777
    st_uid = st.st_uid
    st_gid = st.st_gid
  except FileNotFoundError:
    pass
  fd, tmp = tempfile.mkstemp(prefix=".tmp.", suffix=".json", dir=dirn)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2)
      f.write("\n")
      f.flush()
      os.fsync(f.fileno())
    if st_mode is not None:
      os.chmod(tmp, st_mode)
    if st_uid is not None and st_gid is not None:
      try:
        os.chown(tmp, st_uid, st_gid)
      except PermissionError:
        pass
    os.replace(tmp, path)
  except Exception:
    try:
      if os.path.exists(tmp):
        os.remove(tmp)
    except Exception:
      pass
    raise

ROUTING_LOCK_PATH = "/var/lock/xray-routing.lock"

def save_routing_atomic_locked(config_path, cfg):
  """Tulis routing config secara atomik dengan file lock bersama."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      save_json_atomic(config_path, cfg)
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def load_and_modify_routing_locked(config_path, modify_fn):
  """Acquire lock, reload config from disk, apply modify_fn, then save atomically.
  Mencegah race condition last-write-wins antar daemon yang menulis routing."""
  import fcntl
  os.makedirs(os.path.dirname(ROUTING_LOCK_PATH) or "/var/lock", exist_ok=True)
  with open(ROUTING_LOCK_PATH, "w") as lf:
    try:
      fcntl.flock(lf, fcntl.LOCK_EX)
      cfg = load_json(config_path)
      changed = modify_fn(cfg)
      if changed:
        save_json_atomic(config_path, cfg)
      return changed, cfg
    finally:
      fcntl.flock(lf, fcntl.LOCK_UN)

def restart_xray():
  subprocess.run(["systemctl", "restart", "xray"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def parse_int(v):
  try:
    if v is None:
      return 0
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s = str(v).strip()
    if s == "":
      return 0
    return int(float(s))
  except Exception:
    return 0

def normalize_quota_limit(meta, raw_limit):
  unit_raw = (meta.get("quota_unit") if isinstance(meta, dict) else "") or ""
  unit = str(unit_raw).strip().lower()

  # Preserve unit string asli agar tidak overwrite 'binary' -> 'gib' di file JSON.
  # Kembalikan (raw_limit, unit_string_asli, bytes_per_gb).
  # manage.sh menulis "binary"; daemon ini tidak boleh mengubahnya menjadi "gib"
  # karena keduanya berarti hal yang sama (1024**3) tapi label jadi tidak konsisten.

  # Binary unit group (GiB = 1024^3)
  if unit in ("gib", "binary", "1024", "gibibyte"):
    return raw_limit, unit, GB_BINARY

  # Decimal unit group (GB = 1000^3)
  if unit in ("decimal", "gb", "1000", "gigabyte"):
    return raw_limit, unit, GB_DECIMAL

  # Heuristic (backward compat):
  # If limit is an exact multiple of decimal GB but not GiB, keep decimal.
  if raw_limit > 0 and raw_limit % GB_DECIMAL == 0 and raw_limit % GB_BINARY != 0:
    return raw_limit, "decimal", GB_DECIMAL

  # Default: treat as GiB bytes (1 GB = 1073741824 B)
  return raw_limit, "binary", GB_BINARY

def find_marker_rule(cfg, marker, outbound_tag):
  rules = ((cfg.get("routing") or {}).get("rules")) or []
  for r in rules:
    if r.get("type") != "field":
      continue
    if r.get("outboundTag") != outbound_tag:
      continue
    users = r.get("user") or []
    if isinstance(users, list) and marker in users:
      return r
  return None

def ensure_user(rule, username, marker):
  users = rule.get("user") or []
  if not isinstance(users, list):
    users = []
  if marker not in users:
    users.insert(0, marker)
  if username not in users:
    users.append(username)
    rule["user"] = users
    return True
  rule["user"] = users
  return False

def remove_user(rule, username):
  users = rule.get("user") or []
  if not isinstance(users, list) or username not in users:
    return False
  rule["user"] = [u for u in users if u != username]
  return True

def iter_quota_files():
  for proto in PROTO_DIRS:
    d = os.path.join(QUOTA_ROOT, proto)
    if not os.path.isdir(d):
      continue
    for name in os.listdir(d):
      if name.endswith(".json"):
        yield proto, os.path.join(d, name)

def _api_server_candidates(api_server):
  ordered = []
  raw = str(api_server or "").strip()
  if raw:
    for part in raw.split(","):
      cand = part.strip()
      if cand and cand not in ordered:
        ordered.append(cand)
  for cand in API_SERVER_FALLBACKS:
    if cand not in ordered:
      ordered.append(cand)
  return ordered

def fetch_all_user_traffic(api_server):
  # Xray stats name format (bytes):
  # - user>>>[email]>>>traffic>>>uplink
  # - user>>>[email]>>>traffic>>>downlink
  candidates = _api_server_candidates(api_server)
  data = None
  last_error = ""

  for server in candidates:
    try:
      out = subprocess.check_output(
        ["xray", "api", "statsquery", f"--server={server}", "--pattern", "user>>>"],
        text=True,
        stderr=subprocess.DEVNULL,
      )
      data = json.loads(out)
      break
    except subprocess.CalledProcessError as e:
      last_error = f"exit {e.returncode} @ {server}"
      continue
    except FileNotFoundError:
      import sys
      print(f"[xray-quota] WARN: perintah 'xray' tidak ditemukan. Quota tidak diupdate.", file=sys.stderr)
      return {}
    except json.JSONDecodeError as e:
      last_error = f"JSON decode error @ {server}: {e}"
      continue
    except Exception as e:
      last_error = f"error @ {server}: {e}"
      continue

  if data is None:
    import sys
    shown = ", ".join(candidates)
    print(
      f"[xray-quota] WARN: xray api statsquery gagal untuk semua endpoint [{shown}]. "
      f"Detail terakhir: {last_error or 'tidak ada detail'}. Quota tidak diupdate siklus ini.",
      file=sys.stderr,
    )
    return {}

  traffic = {}  # email -> {"uplink": int, "downlink": int}
  for it in data.get("stat") or []:
    name = it.get("name") if isinstance(it, dict) else None
    if not isinstance(name, str):
      continue
    parts = name.split(">>>")
    if len(parts) < 4:
      continue
    if parts[0] != "user" or parts[2] != "traffic":
      continue
    email = parts[1]
    direction = parts[3]
    val = parse_int(it.get("value") if isinstance(it, dict) else None)
    d = traffic.setdefault(email, {"uplink": 0, "downlink": 0})
    if direction == "uplink":
      d["uplink"] = val
    elif direction == "downlink":
      d["downlink"] = val

  totals = {}
  for email, d in traffic.items():
    totals[email] = parse_int(d.get("uplink")) + parse_int(d.get("downlink"))
  return totals

def ensure_quota_status(meta, exhausted, q_limit, q_used, q_unit, bpg):
  st_raw = meta.get("status") if isinstance(meta, dict) else {}
  st = st_raw if isinstance(st_raw, dict) else {}
  changed = False

  prev_used = parse_int(meta.get("quota_used"))
  # BUG-11 fix: removed unconditional max(prev_used, api_used).
  # Previously quota_used could never decrease, so a manual reset to 0 from
  # Menu 3 would be immediately overwritten by the daemon with the old high value.
  # New logic: trust api_used when it is positive (xray stats are live).
  # Only fall back to prev_used if api_used is 0, which likely means xray was
  # restarted and stats were reset — in that case keep prev_used to avoid
  # losing accumulated usage data. If admin has explicitly reset quota_used via
  # Menu 3, they should also restart xray so stats reset to 0 simultaneously.
  api_used_int = parse_int(q_used)
  if api_used_int > 0:
    q_used_eff = api_used_int
  else:
    # api returns 0: xray just restarted or no traffic. Keep accumulated value.
    q_used_eff = prev_used

  if meta.get("quota_limit") != q_limit:
    meta["quota_limit"] = q_limit
    changed = True

  if meta.get("quota_used") != q_used_eff:
    meta["quota_used"] = q_used_eff
    changed = True

  if meta.get("quota_unit") != q_unit:
    meta["quota_unit"] = q_unit
    changed = True
  if parse_int(meta.get("quota_bytes_per_gb")) != parse_int(bpg):
    meta["quota_bytes_per_gb"] = int(bpg)
    changed = True

  if bool(st.get("quota_exhausted", False)) != bool(exhausted):
    st["quota_exhausted"] = bool(exhausted)
    changed = True

  if exhausted:
    # Hanya set lock_reason = "quota" jika tidak ada lock lain yang lebih prioritas.
    # BUG-FIX #5: Seragamkan urutan prioritas dengan manage.sh dan user-block:
    # manual > quota > ip_limit  (bukan: manual > ip_limit > quota seperti sebelumnya)
    # Jangan overwrite lock_reason "manual" yang sedang aktif.
    cur_reason    = st.get("lock_reason") or ""
    manual_active = bool(st.get("manual_block", False))
    iplimit_active = bool(st.get("ip_limit_locked", False))
    if manual_active:
      if cur_reason != "manual":
        st["lock_reason"] = "manual"
        changed = True
    else:
      # quota lebih prioritas dari ip_limit (konsisten dengan manage.sh BUG-05 fix)
      if cur_reason != "quota":
        st["lock_reason"] = "quota"
        changed = True
    if not st.get("locked_at"):
      st["locked_at"] = now_iso()
      changed = True
  else:
    # Quota tidak exhausted: bersihkan flag quota jika sebelumnya dikunci karena quota.
    # Jangan sentuh lock_reason lain (manual, ip_limit) — hanya bersihkan milik quota.
    if st.get("lock_reason") == "quota":
      # BUG-FIX #5: Turunkan ke lock_reason berikutnya dengan urutan yang seragam:
      # manual > quota > ip_limit
      if bool(st.get("manual_block", False)):
        st["lock_reason"] = "manual"
      elif bool(st.get("ip_limit_locked", False)):
        st["lock_reason"] = "ip_limit"
      else:
        st["lock_reason"] = ""
        st["locked_at"] = ""
      changed = True

  meta["status"] = st
  return changed

def run_once(config_path, marker, api_server, dry_run=False):
  try:
    cfg = load_json(config_path)
  except Exception:
    return 0

  rule = find_marker_rule(cfg, marker, "blocked")
  if rule is None:
    return 0

  totals = fetch_all_user_traffic(api_server)

  changed_cfg = False
  exhausted_users = []
  ok_users = []

  for _, path in iter_quota_files():
    try:
      meta = load_json(path)
    except Exception:
      continue

    username = os.path.splitext(os.path.basename(path))[0]
    if isinstance(meta, dict):
      u2 = meta.get("username")
      if isinstance(u2, str) and u2.strip():
        username = u2.strip()
    if not username:
      continue

    raw_limit = parse_int(meta.get("quota_limit") if isinstance(meta, dict) else 0)
    q_limit, q_unit, bpg = normalize_quota_limit(meta, raw_limit) if isinstance(meta, dict) else (raw_limit, "decimal", GB_DECIMAL)
    prev_used = parse_int(meta.get("quota_used") if isinstance(meta, dict) else 0)
    api_used = parse_int(totals.get(username, 0))
    # Sinkron dengan ensure_quota_status: gunakan nilai API saat >0,
    # fallback ke nilai lama saat API 0 (mis. setelah restart xray).
    q_used = api_used if api_used > 0 else prev_used

    exhausted = (q_limit > 0 and q_used >= q_limit)
    meta_changed = ensure_quota_status(meta, exhausted, q_limit, q_used, q_unit, bpg) if isinstance(meta, dict) else False

    if meta_changed and not dry_run:
      try:
        save_json_atomic(path, meta)
      except Exception:
        pass

    if exhausted:
      exhausted_users.append(username)
    else:
      ok_users.append(username)

  if not exhausted_users and not ok_users:
    return 0

  if dry_run:
    return 0

  # BUG-FIX #4: Gunakan load_and_modify_routing_locked agar load + modify + save
  # semua terjadi di dalam satu exclusive lock yang sama. Pola sebelumnya
  # (load di luar lock, save di dalam lock) membuka race condition: daemon lain
  # bisa menulis routing config antara load cfg_fresh dan akuisisi lock save,
  # sehingga perubahan mereka ter-overwrite. Dengan load_and_modify_routing_locked,
  # reload dari disk terjadi setelah lock acquired — perubahan concurrent aman.
  captured_exhausted = list(dict.fromkeys(exhausted_users))  # stable unique
  captured_ok = list(dict.fromkeys(ok_users))  # stable unique

  def do_block(cfg_live):
    rule_live = find_marker_rule(cfg_live, marker, "blocked")
    if rule_live is None:
      return False
    changed = False
    for username in captured_exhausted:
      if ensure_user(rule_live, username, marker):
        changed = True
    for username in captured_ok:
      if remove_user(rule_live, username):
        changed = True
    return changed

  try:
    changed_cfg, _ = load_and_modify_routing_locked(config_path, do_block)
  except Exception:
    return 0

  if changed_cfg:
    restart_xray()

  return 0

def main():
  ap = argparse.ArgumentParser(prog="xray-quota")
  sub = ap.add_subparsers(dest="cmd", required=True)

  p_once = sub.add_parser("once")
  p_once.add_argument("--config", default=XRAY_CONFIG_DEFAULT)
  p_once.add_argument("--marker", default="dummy-quota-user")
  p_once.add_argument("--api-server", default=API_SERVER_DEFAULT)
  p_once.add_argument("--dry-run", action="store_true")

  p_watch = sub.add_parser("watch")
  p_watch.add_argument("--config", default=XRAY_CONFIG_DEFAULT)
  p_watch.add_argument("--marker", default="dummy-quota-user")
  p_watch.add_argument("--api-server", default=API_SERVER_DEFAULT)
  p_watch.add_argument("--interval", type=int, default=2)
  p_watch.add_argument("--dry-run", action="store_true")

  args = ap.parse_args()

  if args.cmd == "once":
    return run_once(args.config, args.marker, args.api_server, dry_run=args.dry_run)

  interval = max(2, int(args.interval))
  while True:
    try:
      run_once(args.config, args.marker, args.api_server, dry_run=args.dry_run)
    except Exception:
      pass
    time.sleep(interval)

if __name__ == "__main__":
  raise SystemExit(main())

EOF
  chmod +x /usr/local/bin/xray-quota
  cat > /etc/systemd/system/xray-expired.service <<'EOF'
[Unit]
Description=Xray expired cleaner (real-time)
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray-expired --inbounds /usr/local/etc/xray/conf.d/10-inbounds.json --routing /usr/local/etc/xray/conf.d/30-routing.json --interval 2
Restart=always
RestartSec=2
Nice=10

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/xray-limit-ip.service <<'EOF'
[Unit]
Description=Xray limit IP watcher (real-time)
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/limit-ip watch --config /usr/local/etc/xray/conf.d/30-routing.json --marker dummy-limit-user --window-seconds 600
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/xray-quota.service <<'EOF'
[Unit]
Description=Xray quota watcher (metadata -> auto block)
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray-quota watch --config /usr/local/etc/xray/conf.d/30-routing.json --marker dummy-quota-user --interval 2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  if ! service_enable_restart_checked xray-expired; then
    journalctl -u xray-expired -n 120 --no-pager >&2 || true
    die "xray-expired gagal diaktifkan. Cek log di atas."
  fi
  if ! service_enable_restart_checked xray-limit-ip; then
    journalctl -u xray-limit-ip -n 120 --no-pager >&2 || true
    die "xray-limit-ip gagal diaktifkan. Cek log di atas."
  fi
  if ! service_enable_restart_checked xray-quota; then
    journalctl -u xray-quota -n 120 --no-pager >&2 || true
    die "xray-quota gagal diaktifkan. Cek log di atas."
  fi

  ok "Script manajemen siap:"
  ok "  - /usr/local/bin/xray-expired (service: xray-expired)"
  ok "  - /usr/local/bin/limit-ip     (service: xray-limit-ip)"
  ok "  - /usr/local/bin/user-block   (CLI)"
  ok "  - /usr/local/bin/xray-quota    (service: xray-quota)"
}

install_xray_speed_limiter_foundation() {
  ok "Setup fondasi speed limiter per-user (xray-speed)..."

  mkdir -p "${SPEED_POLICY_ROOT}" "${SPEED_STATE_DIR}" "${SPEED_CONFIG_DIR}"
  chmod 700 "${SPEED_POLICY_ROOT}" "${SPEED_STATE_DIR}" "${SPEED_CONFIG_DIR}" || true

  local proto
  for proto in "${SPEED_PROTO_DIRS[@]}"; do
    mkdir -p "${SPEED_POLICY_ROOT}/${proto}"
    chmod 700 "${SPEED_POLICY_ROOT}/${proto}" || true
  done

  cat > "${SPEED_CONFIG_DIR}/config.json" <<EOF
{
  "iface": "",
  "ifb_iface": "ifb1",
  "policy_root": "${SPEED_POLICY_ROOT}",
  "state_file": "${SPEED_STATE_DIR}/state.json",
  "default_rate_mbit": 10000
}
EOF
  chmod 600 "${SPEED_CONFIG_DIR}/config.json" || true

  cat > /usr/local/bin/xray-speed <<'EOF'
#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TABLE_NAME = "xray_speed"
MARK_MIN = 1000
MARK_MAX = 59999


def now_iso():
  return datetime.now(timezone.utc).isoformat()


def run(cmd, check=True):
  return subprocess.run(
    cmd,
    check=check,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )


def run_input(cmd, text, check=True):
  return subprocess.run(
    cmd,
    input=text,
    text=True,
    check=check,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )


def detect_iface():
  p = subprocess.run(
    ["ip", "route", "show", "default", "0.0.0.0/0"],
    check=False,
    capture_output=True,
    text=True,
  )
  if p.returncode == 0:
    for line in (p.stdout or "").splitlines():
      parts = line.strip().split()
      for i, tok in enumerate(parts):
        if tok == "dev" and i + 1 < len(parts):
          return parts[i + 1]

  p2 = subprocess.run(
    ["ip", "-br", "link"],
    check=False,
    capture_output=True,
    text=True,
  )
  if p2.returncode == 0:
    for line in (p2.stdout or "").splitlines():
      cols = line.split()
      if not cols:
        continue
      if cols[0] != "lo":
        return cols[0]
  return ""


def parse_mbit(v):
  try:
    n = float(v)
  except Exception:
    return 0.0
  if n <= 0:
    return 0.0
  return round(n, 3)


def boolify(v):
  if isinstance(v, bool):
    return v
  if isinstance(v, (int, float)):
    return bool(v)
  s = str(v or "").strip().lower()
  return s in ("1", "true", "yes", "on", "y")


def load_json(path, default=None):
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:
    return default


def save_json_atomic(path, data):
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  tmp = f"{path}.tmp.{os.getpid()}"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write("\n")
    f.flush()
    os.fsync(f.fileno())
  os.replace(tmp, path)


def load_config(path):
  try:
    with open(path, "r", encoding="utf-8") as f:
      cfg = json.load(f)
  except FileNotFoundError:
    raise RuntimeError(f"Config xray-speed tidak ditemukan: {path}")
  except json.JSONDecodeError as e:
    raise RuntimeError(f"Config xray-speed invalid JSON di {path} (line {e.lineno}, col {e.colno}): {e.msg}")
  except Exception as e:
    raise RuntimeError(f"Gagal membaca config xray-speed {path}: {e}")

  if not isinstance(cfg, dict):
    raise RuntimeError(f"Config xray-speed harus object JSON: {path}")

  raw_default_rate = cfg.get("default_rate_mbit", 10000)
  try:
    default_rate = int(raw_default_rate)
  except Exception:
    raise RuntimeError("default_rate_mbit pada config xray-speed harus integer > 0")
  if default_rate < 1:
    raise RuntimeError("default_rate_mbit pada config xray-speed harus > 0")

  return {
    "iface": str(cfg.get("iface") or "").strip(),
    "ifb_iface": str(cfg.get("ifb_iface") or "ifb1").strip() or "ifb1",
    "policy_root": str(cfg.get("policy_root") or "/opt/speed").strip() or "/opt/speed",
    "state_file": str(cfg.get("state_file") or "/var/lib/xray-speed/state.json").strip() or "/var/lib/xray-speed/state.json",
    "default_rate_mbit": default_rate,
  }


def iter_policy_files(policy_root):
  root = Path(policy_root)
  if not root.exists():
    return
  for proto_dir in sorted(root.iterdir()):
    if not proto_dir.is_dir():
      continue
    proto = proto_dir.name
    for fp in sorted(proto_dir.glob("*.json")):
      yield proto, fp


def load_policies(policy_root):
  policies = []
  seen_mark = set()
  for proto, fp in iter_policy_files(policy_root):
    data = load_json(str(fp), default={})
    if not isinstance(data, dict):
      continue

    enabled = boolify(data.get("enabled", True))
    if not enabled:
      continue

    try:
      mark = int(data.get("mark", 0))
    except Exception:
      mark = 0
    if mark < 1000 or mark > 59999:
      continue
    if mark in seen_mark:
      continue

    up = parse_mbit(data.get("up_mbit", 0))
    down = parse_mbit(data.get("down_mbit", 0))
    if up <= 0 or down <= 0:
      continue

    user = str(data.get("username") or data.get("email") or fp.stem).strip() or fp.stem

    seen_mark.add(mark)
    policies.append({
      "proto": proto,
      "file": str(fp),
      "username": user,
      "mark": mark,
      "up_mbit": up,
      "down_mbit": down,
    })

  policies.sort(key=lambda x: (x["mark"], x["username"]))
  return policies


def resolve_cmd(*candidates):
  for c in candidates:
    p = shutil.which(c)
    if p:
      return p
    if c.startswith("/") and os.path.isfile(c) and os.access(c, os.X_OK):
      return c
  return ""


def ensure_deps():
  missing = []
  if not resolve_cmd("ip"):
    missing.append("ip")
  if not resolve_cmd("tc"):
    missing.append("tc")
  if not resolve_cmd("nft"):
    missing.append("nft")
  if not resolve_cmd("modprobe", "/usr/sbin/modprobe", "/sbin/modprobe"):
    missing.append("modprobe")
  if missing:
    raise RuntimeError(f"Missing command(s): {', '.join(missing)}")


def ensure_ifb(ifb_iface):
  modprobe_cmd = resolve_cmd("modprobe", "/usr/sbin/modprobe", "/sbin/modprobe")
  if not modprobe_cmd:
    raise RuntimeError("Missing command: modprobe")
  run([modprobe_cmd, "ifb"], check=False)
  run(["ip", "link", "add", ifb_iface, "type", "ifb"], check=False)
  run(["ip", "link", "set", ifb_iface, "up"], check=True)


def flush_tc(iface, ifb_iface):
  run(["tc", "qdisc", "del", "dev", iface, "root"], check=False)
  run(["tc", "qdisc", "del", "dev", iface, "ingress"], check=False)
  run(["tc", "qdisc", "del", "dev", ifb_iface, "root"], check=False)


def flush_nft():
  run(["nft", "delete", "table", "inet", TABLE_NAME], check=False)


def apply_nft():
  rules = f"""table inet {TABLE_NAME} {{
  chain output {{
    type route hook output priority mangle; policy accept;
    meta mark >= {MARK_MIN} meta mark <= {MARK_MAX} ct mark set meta mark
  }}
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    ct mark >= {MARK_MIN} ct mark <= {MARK_MAX} meta mark set ct mark
  }}
}}
"""
  flush_nft()
  run_input(["nft", "-f", "-"], rules, check=True)


def mbit_text(v):
  n = float(v)
  if abs(n - int(n)) < 1e-9:
    return f"{int(n)}mbit"
  return f"{n:.3f}mbit"


def qdisc_show(dev):
  p = subprocess.run(
    ["tc", "qdisc", "show", "dev", dev],
    check=False,
    capture_output=True,
    text=True,
  )
  if p.returncode != 0:
    return ""
  return p.stdout or ""


def tc_is_speed_managed(iface, ifb_iface):
  # Hindari menghapus qdisc milik sistem lain saat policy kosong.
  out_iface = qdisc_show(iface)
  out_ifb = qdisc_show(ifb_iface)
  return (
    "qdisc htb 1:" in out_iface and
    "qdisc ingress ffff:" in out_iface and
    "qdisc htb 2:" in out_ifb
  )


def apply_tc(iface, ifb_iface, default_rate_mbit, policies):
  if not policies:
    flush_tc(iface, ifb_iface)
    return []

  ensure_ifb(ifb_iface)
  flush_tc(iface, ifb_iface)

  default_rate = mbit_text(max(1000.0, float(default_rate_mbit)))

  run(["tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "999"], check=True)
  run(["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:999", "htb", "rate", default_rate, "ceil", default_rate], check=True)
  run(["tc", "qdisc", "replace", "dev", iface, "parent", "1:999", "handle", "1999:", "fq_codel"], check=False)

  run(["tc", "qdisc", "replace", "dev", iface, "handle", "ffff:", "ingress"], check=True)

  # Download path fix:
  # Copy conntrack mark -> skb mark BEFORE mirroring ingress packets to IFB.
  # This allows fw filter on IFB (handle <mark>) to classify per-user download traffic.
  ingress_v4 = [
    "tc", "filter", "replace", "dev", iface, "parent", "ffff:", "protocol", "ip",
    "u32", "match", "u32", "0", "0"
  ]
  try:
    run(ingress_v4 + ["action", "connmark", "action", "mirred", "egress", "redirect", "dev", ifb_iface], check=True)
  except Exception:
    # Fallback for kernels without act_connmark support (keeps previous behavior).
    run(ingress_v4 + ["action", "mirred", "egress", "redirect", "dev", ifb_iface], check=True)

  ingress_v6 = [
    "tc", "filter", "replace", "dev", iface, "parent", "ffff:", "protocol", "ipv6",
    "u32", "match", "u32", "0", "0"
  ]
  try:
    run(ingress_v6 + ["action", "connmark", "action", "mirred", "egress", "redirect", "dev", ifb_iface], check=True)
  except Exception:
    run(ingress_v6 + ["action", "mirred", "egress", "redirect", "dev", ifb_iface], check=False)

  run(["tc", "qdisc", "replace", "dev", ifb_iface, "root", "handle", "2:", "htb", "default", "999"], check=True)
  run(["tc", "class", "replace", "dev", ifb_iface, "parent", "2:", "classid", "2:999", "htb", "rate", default_rate, "ceil", default_rate], check=True)
  run(["tc", "qdisc", "replace", "dev", ifb_iface, "parent", "2:999", "handle", "2999:", "fq_codel"], check=False)

  applied = []
  minor = 100
  for p in policies:
    if minor > 4094:
      break
    up = mbit_text(p["up_mbit"])
    down = mbit_text(p["down_mbit"])
    class_e = f"1:{minor}"
    class_i = f"2:{minor}"
    qh_e = f"{minor + 1000}:"
    qh_i = f"{minor + 2000}:"
    mark = str(int(p["mark"]))

    run(["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", class_e, "htb", "rate", up, "ceil", up], check=True)
    run(["tc", "qdisc", "replace", "dev", iface, "parent", class_e, "handle", qh_e, "fq_codel"], check=False)
    run(["tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "ip", "handle", mark, "fw", "flowid", class_e], check=True)
    run(["tc", "filter", "replace", "dev", iface, "parent", "1:", "protocol", "ipv6", "handle", mark, "fw", "flowid", class_e], check=False)

    run(["tc", "class", "replace", "dev", ifb_iface, "parent", "2:", "classid", class_i, "htb", "rate", down, "ceil", down], check=True)
    run(["tc", "qdisc", "replace", "dev", ifb_iface, "parent", class_i, "handle", qh_i, "fq_codel"], check=False)
    run(["tc", "filter", "replace", "dev", ifb_iface, "parent", "2:", "protocol", "ip", "handle", mark, "fw", "flowid", class_i], check=True)
    run(["tc", "filter", "replace", "dev", ifb_iface, "parent", "2:", "protocol", "ipv6", "handle", mark, "fw", "flowid", class_i], check=False)

    applied.append({
      "username": p["username"],
      "proto": p["proto"],
      "mark": p["mark"],
      "class_minor": minor,
      "up_mbit": p["up_mbit"],
      "down_mbit": p["down_mbit"],
    })
    minor += 1

  return applied


def write_state(state_file, data):
  payload = {
    "updated_at": now_iso(),
    **data,
  }
  save_json_atomic(state_file, payload)


def build_snapshot(cfg):
  iface = cfg["iface"] or detect_iface()
  if not iface:
    raise RuntimeError("Tidak bisa mendeteksi interface utama (default route).")
  policies = load_policies(cfg["policy_root"])
  snapshot = {
    "iface": iface,
    "ifb_iface": cfg["ifb_iface"],
    "default_rate_mbit": int(cfg["default_rate_mbit"]),
    "policies": policies,
  }
  raw = json.dumps(snapshot, sort_keys=True, ensure_ascii=False).encode("utf-8")
  digest = hashlib.sha256(raw).hexdigest()
  return snapshot, digest


def apply_snapshot(cfg, snapshot, dry_run=False):
  iface = snapshot["iface"]
  ifb_iface = snapshot["ifb_iface"]
  policies = snapshot["policies"]
  default_rate_mbit = snapshot["default_rate_mbit"]

  if dry_run:
    write_state(cfg["state_file"], {
      "ok": True,
      "dry_run": True,
      "iface": iface,
      "ifb_iface": ifb_iface,
      "policy_count": len(policies),
      "applied": [],
    })
    return 0

  ensure_deps()
  tc_cleanup = "none"
  if policies:
    apply_nft()
    applied = apply_tc(iface, ifb_iface, default_rate_mbit, policies)
    tc_cleanup = "managed_active"
  else:
    if tc_is_speed_managed(iface, ifb_iface):
      flush_tc(iface, ifb_iface)
      tc_cleanup = "flushed_managed"
    else:
      tc_cleanup = "skipped_foreign_tc"
    flush_nft()
    applied = []

  write_state(cfg["state_file"], {
    "ok": True,
    "dry_run": False,
    "iface": iface,
    "ifb_iface": ifb_iface,
    "policy_count": len(applied),
    "applied": applied,
    "tc_cleanup": tc_cleanup,
  })
  return 0


def run_once(cfg_path, dry_run=False):
  cfg = load_config(cfg_path)
  snapshot, _ = build_snapshot(cfg)
  return apply_snapshot(cfg, snapshot, dry_run=dry_run)


def run_watch(cfg_path, interval):
  sleep_s = max(2, int(interval))
  last_digest = ""
  state_file_fallback = "/var/lib/xray-speed/state.json"
  while True:
    cfg = None
    try:
      cfg = load_config(cfg_path)
      snapshot, digest = build_snapshot(cfg)
      if digest != last_digest:
        apply_snapshot(cfg, snapshot, dry_run=False)
        last_digest = digest
    except Exception as e:
      st_file = state_file_fallback
      if isinstance(cfg, dict):
        st_file = str(cfg.get("state_file") or state_file_fallback)
      try:
        write_state(st_file, {
          "ok": False,
          "error": str(e),
        })
      except Exception:
        pass
    time.sleep(sleep_s)


def show_status(cfg_path):
  cfg = load_config(cfg_path)
  st = load_json(cfg["state_file"], default={}) or {}
  print(json.dumps(st, ensure_ascii=False, indent=2))
  return 0


def do_flush(cfg_path):
  cfg = load_config(cfg_path)
  iface = cfg["iface"] or detect_iface()
  if not iface:
    raise RuntimeError("Tidak bisa mendeteksi interface utama.")
  ensure_deps()
  flush_tc(iface, cfg["ifb_iface"])
  flush_nft()
  write_state(cfg["state_file"], {
    "ok": True,
    "flushed": True,
    "iface": iface,
    "ifb_iface": cfg["ifb_iface"],
  })
  return 0


def main():
  ap = argparse.ArgumentParser(prog="xray-speed")
  sub = ap.add_subparsers(dest="cmd", required=True)

  p_once = sub.add_parser("once")
  p_once.add_argument("--config", default="/etc/xray-speed/config.json")
  p_once.add_argument("--dry-run", action="store_true")

  p_watch = sub.add_parser("watch")
  p_watch.add_argument("--config", default="/etc/xray-speed/config.json")
  p_watch.add_argument("--interval", type=int, default=5)

  p_status = sub.add_parser("status")
  p_status.add_argument("--config", default="/etc/xray-speed/config.json")

  p_flush = sub.add_parser("flush")
  p_flush.add_argument("--config", default="/etc/xray-speed/config.json")

  args = ap.parse_args()
  if args.cmd == "once":
    return run_once(args.config, dry_run=args.dry_run)
  if args.cmd == "watch":
    return run_watch(args.config, args.interval)
  if args.cmd == "status":
    return show_status(args.config)
  if args.cmd == "flush":
    return do_flush(args.config)
  return 1


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    raise SystemExit(0)
  except Exception as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1)
EOF
  chmod +x /usr/local/bin/xray-speed

  cat > /etc/systemd/system/xray-speed.service <<'EOF'
[Unit]
Description=Xray per-user speed limiter (tc + nft)
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray-speed watch --config /etc/xray-speed/config.json --interval 5
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  if service_enable_restart_checked xray-speed; then
    ok "Speed limiter foundation aktif:"
    ok "  - policy root: ${SPEED_POLICY_ROOT}/{vless,vmess,trojan}"
    ok "  - config: ${SPEED_CONFIG_DIR}/config.json"
    ok "  - binary: /usr/local/bin/xray-speed"
    ok "  - service: xray-speed"
  else
    warn "xray-speed service gagal aktif otomatis. Fitur ini opsional dan bisa diaktifkan manual setelah setup:"
    warn "  systemctl status xray-speed --no-pager"
    warn "  journalctl -u xray-speed -n 100 --no-pager"
    systemctl disable --now xray-speed >/dev/null 2>&1 || true
  fi
}

install_observability_alerting() {
  ok "Setup observability & alerting (xray-observe)..."

  mkdir -p "${OBS_CONFIG_DIR}" "${OBS_STATE_DIR}" "${OBS_LOG_DIR}"
  chmod 700 "${OBS_CONFIG_DIR}" "${OBS_STATE_DIR}" "${OBS_LOG_DIR}" || true

  cat > "${OBS_CONFIG_FILE}" <<'EOF'
# URL webhook opsional. Jika kosong, alert hanya ditulis ke log lokal.
ALERT_WEBHOOK_URL=""
# Batas warning masa berlaku cert (hari).
CERT_WARN_DAYS=14
# Kirim alert hanya saat payload berubah (anti-spam).
ALERT_ONLY_ON_CHANGE=1
# Jika 1, mismatch DNS->IP asal diabaikan bila resolve ke IP Cloudflare (proxied).
ALLOW_CLOUDFLARE_PROXY_MISMATCH=1
EOF
  chmod 600 "${OBS_CONFIG_FILE}" || true

  cat > /usr/local/bin/xray-observe <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

CONFIG_FILE="/etc/xray-observe/config.env"
STATE_DIR="/var/lib/xray-observe"
LOG_DIR="/var/log/xray-observe"
ALERT_LOG="${LOG_DIR}/alerts.log"
REPORT_FILE="${STATE_DIR}/last-report.txt"
LAST_ALERT_HASH_FILE="${STATE_DIR}/last-alert.sha256"
CERT_FILE="/opt/cert/fullchain.pem"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
XRAY_CONFDIR="/usr/local/etc/xray/conf.d"

ALERT_WEBHOOK_URL=""
CERT_WARN_DAYS=14
ALERT_ONLY_ON_CHANGE=1
ALLOW_CLOUDFLARE_PROXY_MISMATCH=1

declare -a ISSUES=()
CRITICAL_COUNT=0
WARN_COUNT=0
CHECKED_AT_UTC="-"
DOMAIN_VALUE="-"
VPS_IP_VALUE="-"
CERT_DAYS_VALUE="unknown"

bool_is_true() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "1" || "${v}" == "true" || "${v}" == "yes" || "${v}" == "on" || "${v}" == "y" ]]
}

safe_int() {
  local raw="${1:-}" fallback="${2:-0}"
  if [[ "${raw}" =~ ^-?[0-9]+$ ]]; then
    echo "${raw}"
  else
    echo "${fallback}"
  fi
}

is_private_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  case "${ip}" in
    10.*|127.*|169.254.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2[0-9].*|172.30.*|172.31.*|0.*)
      return 0
      ;;
  esac
  return 1
}

is_public_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  if is_private_ipv4 "${ip}"; then
    return 1
  fi
  return 0
}

is_cloudflare_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "${ip}" <<'PY' >/dev/null 2>&1
import ipaddress
import sys

ip = sys.argv[1]
cf_ranges = (
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
)

try:
  addr = ipaddress.ip_address(ip)
except Exception:
  raise SystemExit(1)

for cidr in cf_ranges:
  if addr in ipaddress.ip_network(cidr):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

all_dns_ips_are_cloudflare() {
  [[ "$#" -gt 0 ]] || return 1
  local ip
  for ip in "$@"; do
    if ! is_cloudflare_ipv4 "${ip}"; then
      return 1
    fi
  done
  return 0
}

svc_exists() {
  local svc="$1"
  local load
  load="$(systemctl show -p LoadState --value "${svc}" 2>/dev/null || true)"
  [[ -n "${load}" && "${load}" != "not-found" ]]
}

detect_domain() {
  local dom=""
  if [[ -s "/etc/xray/domain" ]]; then
    dom="$(head -n1 /etc/xray/domain 2>/dev/null | tr -d '\r' | awk '{print $1}' | tr -d ';' || true)"
  fi
  if [[ -z "${dom}" && -f "${NGINX_CONF}" ]]; then
    dom="$(grep -E '^[[:space:]]*server_name[[:space:]]+' "${NGINX_CONF}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/;.*$//' | awk '{print $1}' | tr -d ';' || true)"
  fi
  echo "${dom}"
}

detect_vps_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -4fsSL --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  fi
  if command -v ip >/dev/null 2>&1; then
    [[ -n "${ip}" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="0.0.0.0"
  fi
  echo "${ip:-0.0.0.0}"
}

cert_days_left() {
  if [[ ! -s "${CERT_FILE}" ]]; then
    echo ""
    return 0
  fi
  local end end_ts now_ts
  end="$(openssl x509 -in "${CERT_FILE}" -noout -enddate 2>/dev/null | sed -e 's/^notAfter=//')"
  [[ -n "${end}" ]] || { echo ""; return 0; }
  end_ts="$(date -d "${end}" +%s 2>/dev/null || true)"
  now_ts="$(date +%s 2>/dev/null || true)"
  [[ -n "${end_ts}" && -n "${now_ts}" ]] || { echo ""; return 0; }
  echo $(( (end_ts - now_ts) / 86400 ))
}

add_issue() {
  local level="$1"
  shift
  local msg="$*"
  ISSUES+=("${level}: ${msg}")
  if [[ "${level}" == "CRITICAL" ]]; then
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
  else
    WARN_COUNT=$((WARN_COUNT + 1))
  fi
}

send_webhook() {
  local msg="$1"
  [[ -n "${ALERT_WEBHOOK_URL:-}" ]] || return 0
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi
  local payload=""
  if command -v python3 >/dev/null 2>&1; then
    payload="$(printf '%s' "${msg}" | python3 -c 'import json,sys; print(json.dumps({"text": sys.stdin.read()}, ensure_ascii=False))' 2>/dev/null || true)"
  fi
  [[ -n "${payload}" ]] || payload="{\"text\":\"xray-observe alert\"}"
  curl -fsS --connect-timeout 5 --max-time 12 -H "Content-Type: application/json" -d "${payload}" "${ALERT_WEBHOOK_URL}" >/dev/null 2>&1 || true
}

emit_alert_if_needed() {
  if (( CRITICAL_COUNT == 0 && WARN_COUNT == 0 )); then
    return 0
  fi
  local level="WARN"
  if (( CRITICAL_COUNT > 0 )); then
    level="CRITICAL"
  fi

  local msg="[${level}] xray-observe host=$(hostname) domain=${DOMAIN_VALUE} ip=${VPS_IP_VALUE} critical=${CRITICAL_COUNT} warn=${WARN_COUNT}"
  local it
  for it in "${ISSUES[@]}"; do
    msg+=$'\n'"- ${it}"
  done

  local sum=""
  sum="$(printf '%s' "${msg}" | sha256sum 2>/dev/null | awk '{print $1}' || true)"
  if [[ -z "${sum}" ]]; then
    sum="$(printf '%s' "${msg}" | md5sum 2>/dev/null | awk '{print $1}' || true)"
  fi

  mkdir -p "${STATE_DIR}" "${LOG_DIR}"
  touch "${ALERT_LOG}"
  chmod 600 "${ALERT_LOG}" || true

  if bool_is_true "${ALERT_ONLY_ON_CHANGE}" && [[ -n "${sum}" && -s "${LAST_ALERT_HASH_FILE}" ]]; then
    local last
    last="$(head -n1 "${LAST_ALERT_HASH_FILE}" 2>/dev/null || true)"
    if [[ "${last}" == "${sum}" ]]; then
      return 0
    fi
  fi

  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "${msg}" >> "${ALERT_LOG}"
  if [[ -n "${sum}" ]]; then
    printf '%s\n' "${sum}" > "${LAST_ALERT_HASH_FILE}"
    chmod 600 "${LAST_ALERT_HASH_FILE}" || true
  fi
  send_webhook "${msg}"
}

write_report() {
  mkdir -p "${STATE_DIR}"
  {
    echo "checked_at=${CHECKED_AT_UTC}"
    echo "host=$(hostname)"
    echo "domain=${DOMAIN_VALUE}"
    echo "vps_ip=${VPS_IP_VALUE}"
    echo "cert_days_left=${CERT_DAYS_VALUE}"
    echo "critical=${CRITICAL_COUNT}"
    echo "warn=${WARN_COUNT}"
    local it
    for it in "${ISSUES[@]}"; do
      echo "issue=${it}"
    done
  } > "${REPORT_FILE}"
  chmod 600 "${REPORT_FILE}" || true
}

run_checks() {
  ISSUES=()
  CRITICAL_COUNT=0
  WARN_COUNT=0
  CHECKED_AT_UTC="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  DOMAIN_VALUE="$(detect_domain)"
  [[ -n "${DOMAIN_VALUE}" ]] || DOMAIN_VALUE="-"
  VPS_IP_VALUE="$(detect_vps_ip)"
  [[ -n "${VPS_IP_VALUE}" ]] || VPS_IP_VALUE="0.0.0.0"

  local svc
  for svc in xray nginx; do
    if ! systemctl is-active --quiet "${svc}" >/dev/null 2>&1; then
      add_issue "CRITICAL" "Service ${svc} tidak active"
    fi
  done

  for svc in xray-expired xray-quota xray-limit-ip xray-speed; do
    if svc_exists "${svc}" && ! systemctl is-active --quiet "${svc}" >/dev/null 2>&1; then
      add_issue "WARN" "Service ${svc} inactive"
    fi
  done

  if command -v xray >/dev/null 2>&1; then
    local out filtered first_line
    if ! out="$(xray run -test -confdir "${XRAY_CONFDIR}" 2>&1)"; then
      filtered="$(printf '%s\n' "${out}" | grep -Ev 'common/errors: The feature .* is deprecated' || true)"
      first_line="$(printf '%s\n' "${filtered}" | head -n1 || true)"
      [[ -n "${first_line}" ]] || first_line="Lihat log xray untuk detail."
      add_issue "CRITICAL" "xray conf test gagal: ${first_line}"
    fi
  else
    add_issue "WARN" "Binary xray tidak ditemukan"
  fi

  local cert_days
  cert_days="$(cert_days_left)"
  CERT_DAYS_VALUE="${cert_days:-unknown}"
  if [[ -z "${cert_days}" ]]; then
    add_issue "CRITICAL" "File cert TLS tidak tersedia atau tidak bisa dibaca"
  elif (( cert_days < 0 )); then
    add_issue "CRITICAL" "Sertifikat TLS sudah expired (${cert_days} hari)"
  elif (( cert_days < CERT_WARN_DAYS )); then
    add_issue "WARN" "Sertifikat TLS tinggal ${cert_days} hari"
  fi

  if [[ "${DOMAIN_VALUE}" == "-" || "${DOMAIN_VALUE}" != *.* ]]; then
    add_issue "WARN" "Domain aktif belum valid (${DOMAIN_VALUE})"
  else
    local -a dns_ips=()
    if command -v getent >/dev/null 2>&1; then
      mapfile -t dns_ips < <(getent ahostsv4 "${DOMAIN_VALUE}" 2>/dev/null | awk '{print $1}' | sort -u || true)
    fi
    if (( ${#dns_ips[@]} == 0 )); then
      add_issue "WARN" "DNS A domain ${DOMAIN_VALUE} tidak ter-resolve"
    elif is_public_ipv4 "${VPS_IP_VALUE}"; then
      local matched="0"
      local dip
      for dip in "${dns_ips[@]}"; do
        if [[ "${dip}" == "${VPS_IP_VALUE}" ]]; then
          matched="1"
          break
        fi
      done
      if [[ "${matched}" != "1" ]]; then
        if (( ALLOW_CLOUDFLARE_PROXY_MISMATCH == 1 )) && all_dns_ips_are_cloudflare "${dns_ips[@]}"; then
          :
        else
          add_issue "WARN" "DNS A ${DOMAIN_VALUE} tidak match IP VPS ${VPS_IP_VALUE} (kemungkinan proxied/CDN)"
        fi
      fi
    fi
  fi
}

print_summary() {
  echo "xray-observe"
  echo "  checked_at : ${CHECKED_AT_UTC}"
  echo "  domain     : ${DOMAIN_VALUE}"
  echo "  vps_ip     : ${VPS_IP_VALUE}"
  echo "  cert_days  : ${CERT_DAYS_VALUE}"
  echo "  critical   : ${CRITICAL_COUNT}"
  echo "  warn       : ${WARN_COUNT}"
  if (( ${#ISSUES[@]} > 0 )); then
    local it
    for it in "${ISSUES[@]}"; do
      echo "  - ${it}"
    done
  fi
}

show_status() {
  if [[ -s "${REPORT_FILE}" ]]; then
    cat "${REPORT_FILE}"
  else
    echo "Belum ada report. Jalankan: xray-observe once"
  fi
  if [[ -s "${ALERT_LOG}" ]]; then
    echo
    echo "Recent alerts:"
    tail -n 20 "${ALERT_LOG}" || true
  fi
}

load_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    . "${CONFIG_FILE}"
  fi
  CERT_WARN_DAYS="$(safe_int "${CERT_WARN_DAYS:-14}" 14)"
  if (( CERT_WARN_DAYS < 1 )); then
    CERT_WARN_DAYS=14
  fi
  if bool_is_true "${ALERT_ONLY_ON_CHANGE:-1}"; then
    ALERT_ONLY_ON_CHANGE=1
  else
    ALERT_ONLY_ON_CHANGE=0
  fi
  if bool_is_true "${ALLOW_CLOUDFLARE_PROXY_MISMATCH:-1}"; then
    ALLOW_CLOUDFLARE_PROXY_MISMATCH=1
  else
    ALLOW_CLOUDFLARE_PROXY_MISMATCH=0
  fi
}

main() {
  local cmd="${1:-once}"
  mkdir -p "${STATE_DIR}" "${LOG_DIR}"
  touch "${ALERT_LOG}"
  chmod 600 "${ALERT_LOG}" || true
  load_config

  case "${cmd}" in
    once)
      run_checks
      write_report
      emit_alert_if_needed
      print_summary
      if (( CRITICAL_COUNT > 0 )); then
        return 1
      fi
      return 0
      ;;
    status)
      show_status
      return 0
      ;;
    *)
      echo "Usage: xray-observe [once|status]" >&2
      return 2
      ;;
  esac
}

main "$@"
EOF
  chmod +x /usr/local/bin/xray-observe

  cat > /etc/systemd/system/xray-observe.service <<'EOF'
[Unit]
Description=Xray observability snapshot
After=network-online.target xray.service nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xray-observe once
SuccessExitStatus=0 1
EOF

  cat > /etc/systemd/system/xray-observe.timer <<'EOF'
[Unit]
Description=Run xray-observe periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=xray-observe.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  if systemctl enable --now xray-observe.timer >/dev/null 2>&1; then
    systemctl start xray-observe.service >/dev/null 2>&1 || true
    ok "Observability aktif:"
    ok "  - binary: /usr/local/bin/xray-observe"
    ok "  - config: ${OBS_CONFIG_FILE}"
    ok "  - timer : xray-observe.timer (5 menit)"
  else
    warn "Gagal mengaktifkan xray-observe.timer. Cek: systemctl status xray-observe.timer --no-pager"
  fi
}

sync_manage_modules_layout() {
  local tmpdir bundle_file downloaded="0" bundle_expected_sha=""
  tmpdir="$(mktemp -d)"
  bundle_file="${tmpdir}/manage_bundle.zip"
  bundle_expected_sha="${MANAGE_BUNDLE_SHA256:-}"

  install_bot_installer_if_present() {
    # args: src_path dst_path label
    local src_path="$1"
    local dst_path="$2"
    local label="$3"
    if [[ -f "${src_path}" ]]; then
      mkdir -p "$(dirname "${dst_path}")"
      install -m 0755 "${src_path}" "${dst_path}"
      chown root:root "${dst_path}" 2>/dev/null || true
      ok "Installer ${label} disegarkan: ${dst_path}"
    fi
  }

  ok "Sinkronisasi modular manage ke ${MANAGE_MODULES_DST_DIR} ..."

  if download_file_with_sha_check "${MANAGE_BUNDLE_URL}" "${bundle_file}" "${bundle_expected_sha}" "manage_bundle.zip"; then
    downloaded="1"
    ok "manage_bundle.zip berhasil diunduh dari repo."
  else
    warn "Gagal unduh/verifikasi manage_bundle.zip dari repo: ${MANAGE_BUNDLE_URL}"
  fi

  if [[ "${downloaded}" == "1" ]]; then
    if python3 - "${bundle_file}" "${MANAGE_MODULES_DST_DIR}" "${MANAGE_BIN}" "${SCRIPT_DIR}" <<'PY'
import os
import sys
import zipfile

zip_path, dst_root, manage_bin, local_root = sys.argv[1:5]
mapping = {
  "env.sh": "core/env.sh",
  "router.sh": "core/router.sh",
  "ui.sh": "core/ui.sh",
  "analytics.sh": "features/analytics.sh",
  "backup.sh": "features/backup.sh",
  "domain.sh": "features/domain.sh",
  "maintenance.sh": "features/maintenance.sh",
  "network.sh": "features/network.sh",
  "users.sh": "features/users.sh",
  "domain_menu.sh": "menus/domain_menu.sh",
  "main_menu.sh": "menus/main_menu.sh",
  "maintenance_menu.sh": "menus/maintenance_menu.sh",
  "wg_inbound_menu.sh": "menus/wg_inbound_menu.sh",
  "network_menu.sh": "menus/network_menu.sh",
  "user_menu.sh": "menus/user_menu.sh",
  "main.sh": "app/main.sh",
}

os.makedirs(dst_root, exist_ok=True)

def basename_index(names):
  idx = {}
  dup = set()
  for n in names:
    base = os.path.basename(n)
    if base in idx:
      dup.add(base)
    else:
      idx[base] = n
  return idx, dup

def read_file(path):
  with open(path, "rb") as fh:
    return fh.read()

with zipfile.ZipFile(zip_path, "r") as zf:
  members = [n for n in zf.namelist() if not n.endswith("/")]
  base_map, duplicates = basename_index(members)
  if duplicates:
    print("duplicate entries in zip: " + ", ".join(sorted(duplicates)), file=sys.stderr)
    raise SystemExit(2)

  missing = [name for name in mapping if name not in base_map]
  if missing:
    print("missing module files in zip: " + ", ".join(sorted(missing)), file=sys.stderr)
    raise SystemExit(3)

  payload = {}
  for src_name, dst_rel in mapping.items():
    src_member = base_map[src_name]
    data = zf.read(src_member)
    payload[src_name] = data

  manage_data = None
  if "manage.sh" in base_map:
    manage_data = zf.read(base_map["manage.sh"])

  # Guard anti bundle stale: jika setup dijalankan dari repo yang punya source lokal,
  # pastikan isi bundle identik. Jika tidak, paksa fallback ke source lokal.
  local_manage = os.path.join(local_root, "manage.sh")
  local_modules_root = os.path.join(local_root, "opt", "manage")
  mismatch = []
  if os.path.isfile(local_manage) and manage_data is not None:
    if read_file(local_manage) != manage_data:
      mismatch.append("manage.sh")
  for src_name, dst_rel in mapping.items():
    local_path = os.path.join(local_modules_root, dst_rel)
    if os.path.isfile(local_path) and read_file(local_path) != payload[src_name]:
      mismatch.append(src_name)
  if mismatch:
    print("bundle differs from local source: " + ", ".join(sorted(mismatch)), file=sys.stderr)
    raise SystemExit(4)

  for src_name, dst_rel in mapping.items():
    dst_path = os.path.join(dst_root, dst_rel)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "wb") as fh:
      fh.write(payload[src_name])
    os.chmod(dst_path, 0o644)

  if manage_data is not None:
    manage_dir = os.path.dirname(manage_bin)
    if manage_dir:
      os.makedirs(manage_dir, exist_ok=True)
    with open(manage_bin, "wb") as fh:
      fh.write(manage_data)
    os.chmod(manage_bin, 0o755)

for sub in ("core", "features", "menus", "app"):
  path = os.path.join(dst_root, sub)
  if os.path.isdir(path):
    os.chmod(path, 0o755)
os.chmod(dst_root, 0o755)
PY
    then
      chown -R root:root "${MANAGE_MODULES_DST_DIR}" 2>/dev/null || true
      chown root:root "${MANAGE_BIN}" 2>/dev/null || true
      install_bot_installer_if_present "${SCRIPT_DIR}/install-discord-bot.sh" "/usr/local/bin/install-discord-bot" "Discord"
      install_bot_installer_if_present "${SCRIPT_DIR}/install-telegram-bot.sh" "/usr/local/bin/install-telegram-bot" "Telegram"
      ok "Template modular manage siap di: ${MANAGE_MODULES_DST_DIR}"
      ok "Binary manage disegarkan dari bundle: ${MANAGE_BIN}"
      rm -rf "${tmpdir}" >/dev/null 2>&1 || true
      return 0
    fi
    warn "Ekstrak manage_bundle.zip gagal; fallback ke source lokal."
  fi

  if [[ ! -d "${MANAGE_MODULES_SRC_DIR}" ]]; then
    rm -rf "${tmpdir}" >/dev/null 2>&1 || true
    die "Sinkronisasi modular manage gagal total: bundle gagal/invalid dan source lokal tidak ditemukan (${MANAGE_MODULES_SRC_DIR})."
  fi

  mkdir -p "${MANAGE_MODULES_DST_DIR}"
  cp -a "${MANAGE_MODULES_SRC_DIR}/." "${MANAGE_MODULES_DST_DIR}/"
  find "${MANAGE_MODULES_DST_DIR}" -type d -exec chmod 755 {} + 2>/dev/null || true
  find "${MANAGE_MODULES_DST_DIR}" -type f -name '*.sh' -exec chmod 644 {} + 2>/dev/null || true
  chown -R root:root "${MANAGE_MODULES_DST_DIR}" 2>/dev/null || true
  if [[ -f "${SCRIPT_DIR}/manage.sh" ]]; then
    mkdir -p "$(dirname "${MANAGE_BIN}")"
    install -m 0755 "${SCRIPT_DIR}/manage.sh" "${MANAGE_BIN}"
    chown root:root "${MANAGE_BIN}" 2>/dev/null || true
    ok "Binary manage disegarkan dari source lokal: ${MANAGE_BIN}"
  fi
  install_bot_installer_if_present "${SCRIPT_DIR}/install-discord-bot.sh" "/usr/local/bin/install-discord-bot" "Discord"
  install_bot_installer_if_present "${SCRIPT_DIR}/install-telegram-bot.sh" "/usr/local/bin/install-telegram-bot" "Telegram"
  ok "Template modular manage siap di: ${MANAGE_MODULES_DST_DIR} (fallback lokal)"
  rm -rf "${tmpdir}" >/dev/null 2>&1 || true
}

install_domain_cert_guard() {
  ok "Setup domain & cert guard (xray-domain-guard)..."

  mkdir -p "${DOMAIN_GUARD_CONFIG_DIR}" "${OBS_LOG_DIR}"
  chmod 700 "${DOMAIN_GUARD_CONFIG_DIR}" "${OBS_LOG_DIR}" || true

  cat > "${DOMAIN_GUARD_CONFIG_FILE}" <<'EOF'
# Warning jika cert <= nilai ini (hari)
CERT_WARN_DAYS=14
# Jika renew-if-needed dipanggil, renewal dipicu jika cert <= nilai ini (hari)
RENEW_BELOW_DAYS=7
# 1=izinkan auto renew by timer, 0=check-only (disarankan default)
AUTO_RENEW=0
# Jika 1, mismatch DNS->IP asal diabaikan bila resolve ke IP Cloudflare (proxied).
ALLOW_CLOUDFLARE_PROXY_MISMATCH=1
EOF
  chmod 600 "${DOMAIN_GUARD_CONFIG_FILE}" || true

  cat > /usr/local/bin/xray-domain-guard <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

CONFIG_FILE="/etc/xray-domain-guard/config.env"
CERT_FILE="/opt/cert/fullchain.pem"
KEY_FILE="/opt/cert/privkey.pem"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
LOG_FILE="/var/log/xray-observe/domain-guard.log"

CERT_WARN_DAYS=14
RENEW_BELOW_DAYS=7
AUTO_RENEW=0
ALLOW_CLOUDFLARE_PROXY_MISMATCH=1

declare -a ISSUES=()
CHECK_RESULT=0
DOMAIN_VALUE="-"
VPS_IP_VALUE="0.0.0.0"
CERT_DAYS_VALUE="unknown"

bool_is_true() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "1" || "${v}" == "true" || "${v}" == "yes" || "${v}" == "on" || "${v}" == "y" ]]
}

safe_int() {
  local raw="${1:-}" fallback="${2:-0}"
  if [[ "${raw}" =~ ^-?[0-9]+$ ]]; then
    echo "${raw}"
  else
    echo "${fallback}"
  fi
}

is_private_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  case "${ip}" in
    10.*|127.*|169.254.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2[0-9].*|172.30.*|172.31.*|0.*)
      return 0
      ;;
  esac
  return 1
}

is_public_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  if is_private_ipv4 "${ip}"; then
    return 1
  fi
  return 0
}

is_cloudflare_ipv4() {
  local ip="${1:-}"
  [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "${ip}" <<'PY' >/dev/null 2>&1
import ipaddress
import sys

ip = sys.argv[1]
cf_ranges = (
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
)

try:
  addr = ipaddress.ip_address(ip)
except Exception:
  raise SystemExit(1)

for cidr in cf_ranges:
  if addr in ipaddress.ip_network(cidr):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

all_dns_ips_are_cloudflare() {
  [[ "$#" -gt 0 ]] || return 1
  local ip
  for ip in "$@"; do
    if ! is_cloudflare_ipv4 "${ip}"; then
      return 1
    fi
  done
  return 0
}

load_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    . "${CONFIG_FILE}"
  fi
  CERT_WARN_DAYS="$(safe_int "${CERT_WARN_DAYS:-14}" 14)"
  RENEW_BELOW_DAYS="$(safe_int "${RENEW_BELOW_DAYS:-7}" 7)"
  AUTO_RENEW="$(safe_int "${AUTO_RENEW:-0}" 0)"
  if bool_is_true "${ALLOW_CLOUDFLARE_PROXY_MISMATCH:-1}"; then
    ALLOW_CLOUDFLARE_PROXY_MISMATCH=1
  else
    ALLOW_CLOUDFLARE_PROXY_MISMATCH=0
  fi
  if (( CERT_WARN_DAYS < 1 )); then
    CERT_WARN_DAYS=14
  fi
  if (( RENEW_BELOW_DAYS < 1 )); then
    RENEW_BELOW_DAYS=7
  fi
}

detect_domain() {
  local dom=""
  if [[ -s "/etc/xray/domain" ]]; then
    dom="$(head -n1 /etc/xray/domain 2>/dev/null | tr -d '\r' | awk '{print $1}' | tr -d ';' || true)"
  fi
  if [[ -z "${dom}" && -f "${NGINX_CONF}" ]]; then
    dom="$(grep -E '^[[:space:]]*server_name[[:space:]]+' "${NGINX_CONF}" 2>/dev/null | head -n1 | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/;.*$//' | awk '{print $1}' | tr -d ';' || true)"
  fi
  echo "${dom}"
}

detect_vps_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -4fsSL --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  fi
  if command -v ip >/dev/null 2>&1; then
    [[ -n "${ip}" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip="0.0.0.0"
  fi
  echo "${ip:-0.0.0.0}"
}

cert_days_left() {
  if [[ ! -s "${CERT_FILE}" ]]; then
    echo ""
    return 0
  fi
  local end end_ts now_ts
  end="$(openssl x509 -in "${CERT_FILE}" -noout -enddate 2>/dev/null | sed -e 's/^notAfter=//')"
  [[ -n "${end}" ]] || { echo ""; return 0; }
  end_ts="$(date -d "${end}" +%s 2>/dev/null || true)"
  now_ts="$(date +%s 2>/dev/null || true)"
  [[ -n "${end_ts}" && -n "${now_ts}" ]] || { echo ""; return 0; }
  echo $(( (end_ts - now_ts) / 86400 ))
}

acme_sh_path_get() {
  if [[ -x "/root/.acme.sh/acme.sh" ]]; then
    echo "/root/.acme.sh/acme.sh"
    return 0
  fi
  if command -v acme.sh >/dev/null 2>&1; then
    command -v acme.sh
    return 0
  fi
  echo ""
}

append_log() {
  mkdir -p "$(dirname "${LOG_FILE}")"
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >> "${LOG_FILE}"
  chmod 600 "${LOG_FILE}" || true
}

add_issue() {
  local msg="$1"
  local sev="${2:-warn}"
  ISSUES+=("${sev^^}: ${msg}")
  if [[ "${sev}" == "critical" ]]; then
    CHECK_RESULT=2
  elif (( CHECK_RESULT < 1 )); then
    CHECK_RESULT=1
  fi
}

cert_matches_domain() {
  local domain="$1"
  [[ -n "${domain}" && -s "${CERT_FILE}" ]] || return 1
  local san
  san="$(openssl x509 -in "${CERT_FILE}" -noout -ext subjectAltName 2>/dev/null || true)"
  [[ -n "${san}" ]] || return 1
  if echo "${san}" | grep -Fq "DNS:${domain}"; then
    return 0
  fi
  if echo "${san}" | grep -Fq "DNS:*.${domain}"; then
    return 0
  fi
  local wildcard=""
  if [[ "${domain}" == *.* ]]; then
    wildcard="*.${domain#*.}"
    if echo "${san}" | grep -Fq "DNS:${wildcard}"; then
      return 0
    fi
  fi
  return 1
}

run_check() {
  CHECK_RESULT=0
  ISSUES=()
  DOMAIN_VALUE="$(detect_domain)"
  [[ -n "${DOMAIN_VALUE}" ]] || DOMAIN_VALUE="-"
  VPS_IP_VALUE="$(detect_vps_ip)"
  [[ -n "${VPS_IP_VALUE}" ]] || VPS_IP_VALUE="0.0.0.0"

  if [[ ! -s "${CERT_FILE}" || ! -s "${KEY_FILE}" ]]; then
    add_issue "File cert/key TLS belum lengkap di /opt/cert" "critical"
  fi

  local cert_days
  cert_days="$(cert_days_left)"
  CERT_DAYS_VALUE="${cert_days:-unknown}"
  if [[ -z "${cert_days}" ]]; then
    add_issue "Gagal membaca masa berlaku cert TLS" "critical"
  elif (( cert_days < 0 )); then
    add_issue "Cert TLS sudah expired (${cert_days} hari)" "critical"
  elif (( cert_days <= CERT_WARN_DAYS )); then
    add_issue "Cert TLS mendekati expired (${cert_days} hari)" "warn"
  fi

  if [[ "${DOMAIN_VALUE}" == "-" || "${DOMAIN_VALUE}" != *.* ]]; then
    add_issue "Domain aktif belum valid (${DOMAIN_VALUE})" "warn"
  else
    if ! cert_matches_domain "${DOMAIN_VALUE}"; then
      add_issue "SAN cert tidak memuat domain aktif ${DOMAIN_VALUE}" "warn"
    fi
    local -a dns_ips=()
    if command -v getent >/dev/null 2>&1; then
      mapfile -t dns_ips < <(getent ahostsv4 "${DOMAIN_VALUE}" 2>/dev/null | awk '{print $1}' | sort -u || true)
    fi
    if (( ${#dns_ips[@]} == 0 )); then
      add_issue "DNS A ${DOMAIN_VALUE} tidak ter-resolve" "warn"
    elif is_public_ipv4 "${VPS_IP_VALUE}"; then
      local matched="0" dip
      for dip in "${dns_ips[@]}"; do
        if [[ "${dip}" == "${VPS_IP_VALUE}" ]]; then
          matched="1"
          break
        fi
      done
      if [[ "${matched}" != "1" ]]; then
        if (( ALLOW_CLOUDFLARE_PROXY_MISMATCH == 1 )) && all_dns_ips_are_cloudflare "${dns_ips[@]}"; then
          :
        else
          add_issue "DNS A ${DOMAIN_VALUE} tidak match IP VPS ${VPS_IP_VALUE} (mungkin proxied/CDN)" "warn"
        fi
      fi
    fi
  fi

  if ! systemctl is-active --quiet nginx >/dev/null 2>&1; then
    add_issue "nginx service tidak active" "critical"
  fi

  append_log "check domain=${DOMAIN_VALUE} ip=${VPS_IP_VALUE} cert_days=${CERT_DAYS_VALUE} result=${CHECK_RESULT}"
}

renew_if_needed() {
  local force_mode="${1:-0}"
  local cert_days
  cert_days="$(cert_days_left)"
  if [[ -z "${cert_days}" ]]; then
    cert_days=0
  fi

  if (( force_mode != 1 && cert_days > RENEW_BELOW_DAYS )); then
    append_log "renew skipped cert_days=${cert_days} threshold=${RENEW_BELOW_DAYS}"
    return 0
  fi

  if (( AUTO_RENEW != 1 && force_mode != 1 )); then
    append_log "renew skipped AUTO_RENEW=0"
    return 0
  fi

  local domain acme
  domain="$(detect_domain)"
  if [[ -z "${domain}" ]]; then
    append_log "renew failed domain empty"
    return 1
  fi

  acme="$(acme_sh_path_get)"
  if [[ -z "${acme}" ]]; then
    append_log "renew failed acme.sh missing"
    return 1
  fi

  export PATH="/root/.acme.sh:${PATH}"
  local ok="0"
  if "${acme}" --renew -d "${domain}" --force >/dev/null 2>&1; then
    ok="1"
  elif "${acme}" --cron --force >/dev/null 2>&1; then
    ok="1"
  fi

  if [[ "${ok}" != "1" ]]; then
    append_log "renew command failed domain=${domain}"
    return 1
  fi

  if ! "${acme}" --install-cert -d "${domain}" \
    --key-file "${KEY_FILE}" \
    --fullchain-file "${CERT_FILE}" \
    --reloadcmd "systemctl restart nginx || true" >/dev/null 2>&1; then
    append_log "install-cert failed domain=${domain}"
    return 1
  fi

  append_log "renew success domain=${domain}"
  return 0
}

print_summary() {
  echo "xray-domain-guard"
  echo "  domain     : ${DOMAIN_VALUE}"
  echo "  vps_ip     : ${VPS_IP_VALUE}"
  echo "  cert_days  : ${CERT_DAYS_VALUE}"
  echo "  result     : ${CHECK_RESULT}"
  if (( ${#ISSUES[@]} > 0 )); then
    local it
    for it in "${ISSUES[@]}"; do
      echo "  - ${it}"
    done
  fi
}

show_status() {
  if [[ -s "${LOG_FILE}" ]]; then
    tail -n 40 "${LOG_FILE}" || true
  else
    echo "Belum ada log domain guard."
  fi
}

main() {
  load_config
  local cmd="${1:-check}"
  case "${cmd}" in
    check)
      run_check
      print_summary
      return "${CHECK_RESULT}"
      ;;
    renew-if-needed)
      local force_mode=0
      if [[ "${2:-}" == "--force" ]]; then
        force_mode=1
      fi
      renew_if_needed "${force_mode}" || true
      run_check
      print_summary
      return "${CHECK_RESULT}"
      ;;
    status)
      show_status
      return 0
      ;;
    *)
      echo "Usage: xray-domain-guard [check|renew-if-needed [--force]|status]" >&2
      return 2
      ;;
  esac
}

main "$@"
EOF
  chmod +x /usr/local/bin/xray-domain-guard

  cat > /etc/systemd/system/xray-domain-guard.service <<'EOF'
[Unit]
Description=Xray domain and cert guard
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xray-domain-guard renew-if-needed
SuccessExitStatus=0 1 2
EOF

  cat > /etc/systemd/system/xray-domain-guard.timer <<'EOF'
[Unit]
Description=Run xray-domain-guard periodically

[Timer]
OnBootSec=3min
OnUnitActiveSec=12h
AccuracySec=1min
Unit=xray-domain-guard.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  if systemctl enable --now xray-domain-guard.timer >/dev/null 2>&1; then
    systemctl start xray-domain-guard.service >/dev/null 2>&1 || true
    ok "Domain & cert guard aktif:"
    ok "  - binary: /usr/local/bin/xray-domain-guard"
    ok "  - config: ${DOMAIN_GUARD_CONFIG_FILE}"
    ok "  - timer : xray-domain-guard.timer (12 jam)"
  else
    warn "Gagal mengaktifkan xray-domain-guard.timer. Cek: systemctl status xray-domain-guard.timer --no-pager"
  fi
}

sanity_check() {
  local failed=0

  # Core services (must be active)
  if systemctl is-active --quiet xray; then
    ok "sanity: xray active"
  else
    warn "sanity: xray NOT active"
    systemctl status xray --no-pager >&2 || true
    journalctl -u xray -n 200 --no-pager >&2 || true
    failed=1
  fi

  if systemctl is-active --quiet nginx; then
    ok "sanity: nginx active"
  else
    warn "sanity: nginx NOT active"
    systemctl status nginx --no-pager >&2 || true
    journalctl -u nginx -n 200 --no-pager >&2 || true
    failed=1
  fi

  # Config sanity (non-fatal if tools missing)
  if command -v nginx >/dev/null 2>&1; then
    if nginx -t >/dev/null 2>&1; then
      ok "sanity: nginx -t OK"
    else
      warn "sanity: nginx -t FAILED"
      nginx -t >&2 || true
      failed=1
    fi
  fi

  if command -v jq >/dev/null 2>&1 && [[ -f "${XRAY_CONFDIR}/10-inbounds.json" ]]; then
    if jq -e . "${XRAY_CONFDIR}/10-inbounds.json" >/dev/null 2>&1; then
      ok "sanity: xray config JSON OK"
    else
      warn "sanity: xray config JSON INVALID"
      jq -e . "${XRAY_CONFDIR}/10-inbounds.json" >&2 || true
      failed=1
    fi
  fi

  # Cert presence (TLS termination depends on these)
  if [[ -s "/opt/cert/fullchain.pem" && -s "/opt/cert/privkey.pem" ]]; then
    ok "sanity: TLS cert files present"
  else
    warn "sanity: TLS cert files missing under /opt/cert"
    failed=1
  fi

  # Listener hints (informational only)
  if ss -lntp 2>/dev/null | grep -q ':443'; then
    ok "sanity: port 443 is listening"
  else
    warn "sanity: port 443 not detected as listening (check nginx)"
  fi

  if [[ "$failed" -ne 0 ]]; then
    die "Sanity check gagal. Lihat log di atas."
  fi
}

main() {
  safe_clear
  need_root
  check_os
  install_base_deps
  need_python3
  install_extra_deps
  install_speedtest_snap
  enable_cron_service
  setup_time_sync_chrony
  install_fail2ban_aggressive
  enable_bbr
  setup_swap_2gb
  tune_ulimit
  install_wgcf
  install_wireproxy
  setup_wgcf
  setup_wireproxy
  cleanup_wgcf_files
  domain_menu_v2
  install_nginx_official_repo
  write_nginx_main_conf
  install_acme_and_issue_cert
  install_xray
  setup_xray_geodata_updater
  install_custom_geosite_adblock
  write_xray_config
  write_xray_modular_configs
  configure_xray_service_confdir
  write_nginx_config
  install_management_scripts
  sync_manage_modules_layout
  install_xray_speed_limiter_foundation
  install_observability_alerting
  install_domain_cert_guard
  setup_logrotate
  configure_fail2ban_aggressive_jails
  sanity_check
  ok "Setup telah selesai ✅"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
