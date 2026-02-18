#!/usr/bin/env bash
set -euo pipefail

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
NC='\033[0m'

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XRAY_CONFDIR="/usr/local/etc/xray/conf.d"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
CERT_DIR="/opt/cert"
CERT_FULLCHAIN="${CERT_DIR}/fullchain.pem"
CERT_PRIVKEY="${CERT_DIR}/privkey.pem"
CLOUDFLARE_API_TOKEN="ZEbavEuJawHqX4-Jwj-L5Vj0nHOD-uPXtdxsMiAZ"

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
ACME_WILDCARD_DOMAIN=""
CF_ZONE_ID=""
VPS_IPV4=""
CF_PROXIED="false"

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

  if [[ "$id" == "ubuntu" ]]; then
    python3 - <<PY
import sys
v=float("$ver")
sys.exit(0 if v>=20.04 else 1)
PY
    [[ $? -eq 0 ]] || die "Ubuntu minimal 20.04. Versi terdeteksi: $ver"
    ok "OS: Ubuntu $ver ($codename)"
  elif [[ "$id" == "debian" ]]; then
    python3 - <<PY
import sys
v=int("$ver".split('.')[0])
sys.exit(0 if v>=11 else 1)
PY
    [[ $? -eq 0 ]] || die "Debian minimal 11. Versi terdeteksi: $ver"
    ok "OS: Debian $ver ($codename)"
  else
  die "OS tidak didukung: $id. Hanya Ubuntu >=20.04 atau Debian >=11."
fi
}

install_base_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates unzip openssl socat cron gpg lsb-release python3 iproute2 jq dnsutils
  ok "Dependency dasar terpasang."
}

need_python3() {
  if command -v python3 >/dev/null 2>&1; then
    return 0
  fi

  warn "python3 belum terpasang. Memasang python3..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 || die "Gagal memasang python3."
}

domain_menu() {
  echo "============================================"
  echo "   INPUT DOMAIN (wajib untuk TLS) 🌐"
  echo "============================================"
  echo "Contoh domain valid: example.com / sub.example.com"
  echo

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
      break
    else
    echo "Domain tidak valid. Coba lagi."
  fi
done
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
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}' || true)"
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
  # allow: lowercase letters, digits, dot, dash; no spaces; no uppercase
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
        ok "Lanjut."
        return 0
      fi
      die "Dibatalkan oleh user."
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
  echo "============================================"
  echo "   INPUT DOMAIN (TLS) 🌐"
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
        ACME_WILDCARD_DOMAIN=""
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
echo "Pilih domain induk"
local i=1
local root=""
for root in "${PROVIDED_ROOT_DOMAINS[@]}"; do
  echo "  $i. $root"
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
  ok "Subdomain generated: $sub"
else
while true; do
  read -r -p "Masukkan nama subdomain: " sub
  sub="${sub,,}"
  if validate_subdomain "$sub"; then
    ok "Subdomain valid: $sub"
    break
  fi
  echo "Subdomain tidak valid. Hanya huruf kecil, angka, titik, dan strip (-). Tanpa spasi/kapital/karakter aneh."
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
ACME_WILDCARD_DOMAIN="$DOMAIN"
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

pick_port() {
  local p
  while true; do
    p=$(( 20000 + RANDOM % 40000 ))
    if is_port_free "$p"; then
      echo "$p"
      return 0
    fi
  done
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

  apt-get remove -y nginx nginx-common nginx-full nginx-core 2>/dev/null || true

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
deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/${distro}/ ${codename} nginx
EOF

cat > /etc/apt/preferences.d/99nginx <<'EOF'
Package: *
Pin: origin nginx.org
Pin-Priority: 900
EOF

apt-get update -y
apt-get install -y nginx jq
ok "Nginx terpasang dari repo resmi nginx.org (mainline)."
}

install_acme_and_issue_cert() {
  local EMAIL
  EMAIL="$(rand_email)"
  ok "Email acme.sh (acak): $EMAIL"

  stop_conflicting_services

  curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" >/dev/null
  export PATH="/root/.acme.sh:$PATH"
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null || true

  mkdir -p "$CERT_DIR"
  chmod 700 "$CERT_DIR"

  if [[ "${ACME_CERT_MODE:-standalone}" == "dns_cf_wildcard" ]]; then
    [[ -n "${ACME_ROOT_DOMAIN:-}" ]] || die "ACME_ROOT_DOMAIN kosong (mode dns_cf_wildcard)."
    [[ -n "${DOMAIN:-}" ]] || die "DOMAIN kosong (mode dns_cf_wildcard)."
    ok "Issue sertifikat wildcard untuk ${DOMAIN} via acme.sh (dns_cf)..."

    export CF_Token="$CLOUDFLARE_API_TOKEN"

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
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install >/dev/null
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
    "loglevel": "info"
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
          "dummy-inbounds"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "user": [
          "dummy-user"
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
      "protocol": "freedom",
      "tag": "api"
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


  # Validasi config sebelum restart service (hindari exit "diam-diam")
  local test_log="/tmp/xray-config-test.log"
  if ! xray run -test -config "$XRAY_CONFIG" >"$test_log" 2>&1; then
    tail -n 200 "$test_log" >&2 || true
    die "Xray config test gagal. Lihat: $test_log"
  fi

  systemctl enable xray --now || { systemctl status xray --no-pager >&2 || true; die "Gagal enable/start xray"; }
  systemctl restart xray || { journalctl -u xray -n 200 --no-pager >&2 || true; die "Gagal restart xray"; }
  ok "Config Xray dibuat & service direstart."
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

def ensure_default_balancer(routing: dict):
  if not isinstance(routing, dict):
    return
  balancers = routing.get("balancers")
  if not isinstance(balancers, list):
    balancers = []
  if any(isinstance(b, dict) and b.get("tag") == "egress-balance" for b in balancers):
    routing["balancers"] = balancers
    return
  balancers.append({
    "tag": "egress-balance",
    "selector": ["direct", "warp"],
    "strategy": {"type": "random"}
  })
  routing["balancers"] = balancers

def ensure_default_observatory(cfg: dict):
  if not isinstance(cfg, dict):
    return {}
  obs = cfg.get("observatory")
  if isinstance(obs, dict) and obs:
    return obs
  # Default observatory (untuk balancer type: leastPing / leastLoad).
  return {
    "subjectSelector": ["direct", "warp"],
    "probeUrl": "https://www.cloudflare.com/cdn-cgi/trace",
    "probeInterval": "30s",
    "enableConcurrency": True
  }

routing = cfg.get("routing") or {}
if isinstance(routing, dict):
  ensure_default_balancer(routing)
else:
  routing = {}

parts = [
  ("00-log.json", {"log": cfg.get("log") or {}}),
  ("01-api.json", {"api": cfg.get("api") or {}}),
  ("02-dns.json", {"dns": cfg.get("dns") or {}}),
  ("10-inbounds.json", {"inbounds": cfg.get("inbounds") or []}),
  ("20-outbounds.json", {"outbounds": cfg.get("outbounds") or []}),
  ("30-routing.json", {"routing": routing}),
  ("40-policy.json", {"policy": cfg.get("policy") or {}}),
  ("50-stats.json", {"stats": cfg.get("stats") or {}}),
  ("60-observatory.json", {"observatory": ensure_default_observatory(cfg)}),
]

os.makedirs(outdir, exist_ok=True)

for name, obj in parts:
  path = os.path.join(outdir, name)
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as wf:
    json.dump(obj, wf, ensure_ascii=False, indent=2)
    wf.write("\n")
  os.replace(tmp, path)
PY

  chmod 600 "${XRAY_CONFDIR}"/*.json 2>/dev/null || true
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

configure_xray_service_confdir() {
  ok "Mengatur xray.service agar memakai -confdir ..."

  # Wajib bersih dari drop-in agar tidak ada ExecStart/User yang menimpa.
  if [[ -d /etc/systemd/system/xray.service.d ]]; then
    rm -rf /etc/systemd/system/xray.service.d/* 2>/dev/null || true
    rmdir /etc/systemd/system/xray.service.d 2>/dev/null || true
  fi
  if [[ -d /etc/systemd/system/xray@.service.d ]]; then
    rm -rf /etc/systemd/system/xray@.service.d/* 2>/dev/null || true
    rmdir /etc/systemd/system/xray@.service.d 2>/dev/null || true
  fi

  local xray_bin unit_dst frag
  xray_bin="$(command -v xray || true)"
  [[ -n "${xray_bin}" ]] || xray_bin="/usr/local/bin/xray"

  unit_dst="/etc/systemd/system/xray.service"
  frag="$(systemctl show -p FragmentPath --value xray 2>/dev/null || true)"
  if [[ -z "${frag:-}" || "${frag:-}" == "n/a" ]]; then
    frag="/lib/systemd/system/xray.service"
  fi

  # Jika unit asli berada di /lib, copy ke /etc agar bisa kita modifikasi.
  if [[ ! -f "${unit_dst}" && -f "${frag}" ]]; then
    cp -f "${frag}" "${unit_dst}"
  fi
  [[ -f "${unit_dst}" ]] || die "Tidak menemukan unit file xray.service untuk diubah."

  # 1) Ubah ExecStart utama ke -confdir
  if grep -qE '^[[:space:]]*ExecStart=' "${unit_dst}"; then
    sed -i -E "s|^[[:space:]]*ExecStart=.*$|ExecStart=${xray_bin} run -confdir ${XRAY_CONFDIR}|g" "${unit_dst}"
  else
    sed -i -E "/^\[Service\]/a ExecStart=${xray_bin} run -confdir ${XRAY_CONFDIR}" "${unit_dst}"
  fi

  # 2) Hapus User/Group spesial (mis. nobody) agar tidak memblok akses file log.
  sed -i -E '/^[[:space:]]*User=/d; /^[[:space:]]*Group=/d' "${unit_dst}"
  sed -i -E '/^[[:space:]]*DynamicUser=/d' "${unit_dst}"

  # 3) Pastikan systemd mengizinkan write ke /var/log/xray.
  if grep -qE '^[[:space:]]*ReadWritePaths=' "${unit_dst}"; then
    if ! grep -qE '^[[:space:]]*ReadWritePaths=.*\b/var/log/xray\b' "${unit_dst}"; then
      sed -i -E 's|^[[:space:]]*ReadWritePaths=(.*)$|ReadWritePaths=\1 /var/log/xray|g' "${unit_dst}"
    fi
  else
    sed -i -E "/^\[Service\]/a ReadWritePaths=/var/log/xray" "${unit_dst}"
  fi

  # 4) Pastikan direktori & file log dapat dibuat/ditulis.
  mkdir -p /var/log/xray
  chmod 755 /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  chmod 644 /var/log/xray/access.log /var/log/xray/error.log

  systemctl daemon-reload

  # Test konfigurasi confdir sebelum restart
  if ! "${xray_bin}" run -test -confdir "${XRAY_CONFDIR}" >/dev/null 2>&1; then
    "${xray_bin}" run -test -confdir "${XRAY_CONFDIR}" || true
    die "Konfigurasi confdir Xray invalid."
  fi

  systemctl restart xray >/dev/null 2>&1 || { journalctl -u xray -n 200 --no-pager >&2 || true; die "Gagal restart xray"; }
  ok "xray.service sudah memakai -confdir dan berhasil direstart."

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

# 2) Map Public Path -> INTERNAL PATH (WebSocket & HTTPUpgrade)
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

  apt-get install -y jq fail2ban chrony tar expect logrotate
  ok "Dependency tambahan terpasang (jq, fail2ban, chrony, expect, logrotate)."
}

install_fail2ban_aggressive() {
  ok "Enable fail2ban..."

  systemctl enable fail2ban --now >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  ok "fail2ban aktif. Konfigurasi jail.local aggressive akan diterapkan setelah Nginx siap."
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
}

configure_fail2ban_aggressive_jails() {
  ok "Konfigurasi fail2ban mode aggressive (sshd, nginx-http-auth, nginx-botsearch, recidive)..."

  ensure_fail2ban_nginx_filters

  mkdir -p /etc/fail2ban
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1d
findtime = 10m
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
mode = aggressive
port = ssh
logpath = %(sshd_log)s

[nginx-http-auth]
enabled = true
mode = aggressive
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
mode = aggressive
port = http,https
logpath = /var/log/nginx/access.log

[recidive]
enabled = true
mode = aggressive
logpath = /var/log/fail2ban.log
bantime = 7d
findtime = 1d
maxretry = 5
EOF

  systemctl enable fail2ban --now >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
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

  swapon /swapfile >/dev/null 2>&1 || true
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab

  cat > /etc/sysctl.d/99-custom-vm.conf <<'EOF'
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF

  sysctl --system >/dev/null 2>&1 || true
  ok "Swap 2GB aktif."
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
    local reg_log="/tmp/wgcf-register.log"

    # wgcf versi baru kadang pakai prompt berbasis TTY (arrow-keys). `yes |` sering tidak efektif.
    if command -v expect >/dev/null 2>&1; then
      expect <<'EOF' >"$reg_log" 2>&1
set timeout 180
log_user 1
spawn wgcf register
# Coba accept prompt dengan Enter / y
expect {
  -re {Use the arrow keys.*} { send "
"; exp_continue }
  -re {Do you agree.*} { send "
"; exp_continue }
  -re {\(y/n\)} { send "y
"; exp_continue }
  -re {Yes/No} { send "
"; exp_continue }
  -re {accept} { send "
"; exp_continue }
  eof
}
EOF
    else
    # Fallback legacy (lebih rentan), tapi tetap kita log.
    set +o pipefail
    yes | wgcf register >"$reg_log" 2>&1
    set -o pipefail
  fi

  [[ -f wgcf-account.toml ]] || {
    tail -n 120 "$reg_log" >&2 || true
    die "wgcf register gagal. Lihat log: $reg_log"
  }
fi

local gen_log="/tmp/wgcf-generate.log"
wgcf generate >"$gen_log" 2>&1 || {
  tail -n 120 "$gen_log" >&2 || true
  die "wgcf generate gagal. Lihat log: $gen_log"
}
[[ -f wgcf-profile.conf ]] || {
  tail -n 120 "$gen_log" >&2 || true
  die "wgcf-profile.conf tidak ditemukan setelah generate."
}

popd >/dev/null || die "Gagal kembali dari /etc/wgcf."
ok "wgcf selesai."
}

setup_wireproxy() {
  ok "Setup wireproxy..."

  mkdir -p /etc/wireproxy
  cp -f /etc/wgcf/wgcf-profile.conf /etc/wireproxy/config.conf

  # Tambahkan socks bind sesuai requirement:
  # [Socks] BindAddress = 127.0.0.1:40000
  if ! grep -q '^\[Socks\]' /etc/wireproxy/config.conf; then
    cat >> /etc/wireproxy/config.conf <<'EOF'

[Socks]
BindAddress = 127.0.0.1:40000
EOF
  fi

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
  systemctl enable wireproxy --now >/dev/null 2>&1 || true
  systemctl restart wireproxy >/dev/null 2>&1 || true
  ok "wireproxy service aktif."
}

cleanup_wgcf_files() {
  ok "Cleanup file wgcf (wgcf-profile.conf & wgcf-account.toml)..."

  rm -f /etc/wgcf/wgcf-profile.conf /etc/wgcf/wgcf-account.toml || true
  ok "Cleanup wgcf selesai."
}

enable_cron_service() {
  ok "Enable cron..."

  systemctl enable cron --now >/dev/null 2>&1 \
  || systemctl enable crond --now >/dev/null 2>&1 \
  || true
  systemctl restart cron >/dev/null 2>&1 || systemctl restart crond >/dev/null 2>&1 || true

  ok "cron aktif."
}

setup_log_cleanup() {
  ok "Setup auto remove log Xray & Nginx (24 jam)..."

  cat > /usr/local/bin/cleanup-xray-nginx-logs <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

truncate_log() {
  local f="$1"
  if [[ -f "$f" ]]; then
    : > "$f"
  fi
}

truncate_log /var/log/xray/access.log
truncate_log /var/log/xray/error.log
truncate_log /var/log/nginx/access.log
truncate_log /var/log/nginx/error.log

# Hapus log rotate lama (kalau ada)
find /var/log/nginx -maxdepth 1 -type f \( -name "access.log.*" -o -name "error.log.*" -o -name "*.gz" \) -mtime +0 -delete 2>/dev/null || true
find /var/log/xray -maxdepth 1 -type f \( -name "*.log.*" -o -name "*.gz" \) -mtime +0 -delete 2>/dev/null || true
EOF

  chmod +x /usr/local/bin/cleanup-xray-nginx-logs

  cat > /etc/cron.d/cleanup-xray-nginx-logs <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root /usr/local/bin/cleanup-xray-nginx-logs >/dev/null 2>&1
EOF

  ok "Cron log cleanup terpasang: /etc/cron.d/cleanup-xray-nginx-logs"
}

setup_xray_geodata_updater() {
  ok "Setup updater geodata Xray-core (24 jam)..."

  cat > /usr/local/bin/xray-update-geodata <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata >/dev/null 2>&1
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

  cat > /usr/local/bin/xray-expired <<'EOF'
#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone

XRAY_CONFIG_DEFAULT = "/usr/local/etc/xray/conf.d/30-routing.json"
ACCOUNT_ROOT = "/opt/account"
QUOTA_ROOT = "/opt/quota"
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
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
  os.replace(tmp, path)

def restart_xray():
  subprocess.run(
    ["systemctl", "restart", "xray"],
    check=False,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
  )

def remove_user_from_inbounds(cfg, username):
  changed_inb = False
  changed_rt = False
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
  changed_inb = False
  changed_rt = False
  rules = ((cfg.get("routing") or {}).get("rules")) or []
  for rule in rules:
    users = rule.get("user")
    if not isinstance(users, list):
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

def is_expired(meta, ts):
  exp = parse_iso8601(meta.get("expired_at") if isinstance(meta, dict) else None)
  if exp is None:
    return False
  return exp <= ts

def delete_user_artifacts(proto, user_key, quota_path):
  # 1) quota json: /opt/quota/<proto>/<username@protocol>.json
  try:
    if os.path.exists(quota_path):
      os.remove(quota_path)
  except Exception:
    pass

  # 2) account txt: /opt/account/<proto>/<username@protocol>.txt
  acc = os.path.join(ACCOUNT_ROOT, proto, f"{user_key}.txt")
  try:
    if os.path.exists(acc):
      os.remove(acc)
  except Exception:
    pass

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
      if isinstance(u2, str) and "@" in u2:
        user_key = u2.strip()
    if not user_key:
      continue

    if is_expired(meta, ts):
      expired.append((proto, user_key, path))

  if not expired:
    return 0

  try:
    inb_cfg = load_json(inbounds_path)
    rt_cfg = load_json(routing_path)
  except Exception:
    return 0

  changed_inb = False
  changed_rt = False
  for _, user_key, _ in expired:
    changed_inb = remove_user_from_inbounds(inb_cfg, user_key) or changed_inb
    changed_rt = remove_user_from_rules(rt_cfg, user_key) or changed_rt

  if dry_run:
    for _, user_key, _ in expired:
      print(user_key)
    return 0

  for proto, user_key, qpath in expired:
    delete_user_artifacts(proto, user_key, qpath)

  changed_any = changed_inb or changed_rt
  if changed_any and not dry_run:
    save_json_atomic(inbounds_path, inb_cfg)
    save_json_atomic(routing_path, rt_cfg)
    restart_xray()

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

  # Legacy wrapper for backward compatibility
  cat > /usr/local/bin/user-expired <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/bin/xray-expired "$@"
EOF
  chmod +x /usr/local/bin/user-expired

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
IP_RE = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\:\d{1,5}\b")

def now_iso():
  return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path):
  with open(path, "r", encoding="utf-8") as f:
    return json.load(f)

def save_json_atomic(path, data):
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
  os.replace(tmp, path)

def restart_xray():
  subprocess.run(["systemctl", "restart", "xray"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

def ensure_user(rule, username):
  users = rule.get("user") or []
  if not isinstance(users, list):
    users = []
  if username not in users:
    users.append(username)
    rule["user"] = users
    return True
  return False

def remove_user(rule, username):
  users = rule.get("user") or []
  if not isinstance(users, list) or username not in users:
    return False
  rule["user"] = [u for u in users if u != username]
  return True

def quota_paths(username):
  paths = []
  for proto in PROTO_DIRS:
    p = os.path.join(QUOTA_ROOT, proto, f"{username}.json")
    if os.path.isfile(p):
      paths.append(p)
  return paths

def get_status(username):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    return meta.get("status") or {}
  return {}

def set_status(username, enabled=None, limit=None):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    st = meta.get("status") or {}
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
    st = meta.get("status") or {}
    st["ip_limit_locked"] = True
    st["lock_reason"] = "ip_limit"
    st["locked_at"] = now_iso()
    meta["status"] = st
    save_json_atomic(p, meta)

def unlock_user(username):
  for p in quota_paths(username):
    try:
      meta = load_json(p)
    except Exception:
      continue
    st = meta.get("status") or {}
    st["ip_limit_locked"] = False
    if st.get("lock_reason") == "ip_limit":
      st["lock_reason"] = None
      st["locked_at"] = ""
    meta["status"] = st
    save_json_atomic(p, meta)

def parse_line(line):
  m1 = EMAIL_RE.search(line)
  m2 = IP_RE.search(line)
  if not m1 or not m2:
    return None, None
  return m1.group(1), m2.group(1)

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
  cfg = load_json(config_path)
  rule = find_marker_rule(cfg, marker, "blocked")
  if rule is None:
    print(f"Marker rule not found: {marker}", file=sys.stderr)
    return 1

  seen = {}  # user -> ip -> last_seen_epoch
  last_restart = 0.0
  min_restart_interval = 15.0

  for line in tail_follow(XRAY_ACCESS_LOG):
    user, ip = parse_line(line)
    if not user or not ip:
      continue

    st = get_status(user)
    if not st:
      continue
    if not bool(st.get("ip_limit_enabled", False)):
      continue
    lim = int(st.get("ip_limit", 0) or 0)
    if lim <= 0:
      continue
    if bool(st.get("ip_limit_locked", False)):
      continue

    now = time.time()
    bucket = seen.setdefault(user, {})
    bucket[ip] = now

    cutoff = now - float(window_seconds)
    for u, ips in list(seen.items()):
      for ip2, ts in list(ips.items()):
        if ts < cutoff:
          ips.pop(ip2, None)
      if not ips:
        seen.pop(u, None)

    if len(seen.get(user, {})) > lim:
      lock_user(user)
      changed = ensure_user(rule, user)
      if changed:
        save_json_atomic(config_path, cfg)
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
    cfg = load_json(XRAY_CONFIG_DEFAULT)
    rule = find_marker_rule(cfg, "dummy-limit-user", "blocked")
    if rule is not None and remove_user(rule, args.username):
      save_json_atomic(XRAY_CONFIG_DEFAULT, cfg)
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
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
  os.replace(tmp, path)

def restart_xray():
  subprocess.run(["systemctl", "restart", "xray"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

def update_quota_status(username, manual_block):
  for proto in PROTO_DIRS:
    p = os.path.join(QUOTA_ROOT, proto, f"{username}.json")
    if not os.path.isfile(p):
      continue
    try:
      meta = load_json(p)
    except Exception:
      continue
    st = meta.get("status") or {}
    st["manual_block"] = bool(manual_block)
    if manual_block:
      st["lock_reason"] = "manual"
      st["locked_at"] = now_iso()
    else:
      if st.get("lock_reason") == "manual":
        st["lock_reason"] = None
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

  cfg = load_json(args.config)
  rule = find_marker_rule(cfg, args.marker, "blocked")
  if rule is None:
    raise SystemExit(f"Marker rule not found: {args.marker}")

  changed = False
  if args.action == "block":
    changed = ensure_user(rule, args.username, args.marker)
    update_quota_status(args.username, True)
  else:
    changed = remove_user(rule, args.username)
    update_quota_status(args.username, False)

  if changed:
    save_json_atomic(args.config, cfg)
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
API_SERVER_DEFAULT = "127.0.0.1:10080"
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
  tmp = f"{path}.tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
  os.replace(tmp, path)

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

  # Explicit binary unit (GiB)
  if unit in ("gib", "binary", "1024", "gibibyte"):
    return raw_limit, "gib", GB_BINARY

  # Explicit decimal unit (GB, 1000^3)
  if unit in ("decimal", "gb", "1000", "gigabyte"):
    return raw_limit, "decimal", GB_DECIMAL

  # Heuristic (backward compat):
  # If limit is an exact multiple of decimal GB but not GiB, keep decimal.
  if raw_limit > 0 and raw_limit % GB_DECIMAL == 0 and raw_limit % GB_BINARY != 0:
    return raw_limit, "decimal", GB_DECIMAL

  # Default: treat as GiB bytes (1 GB = 1073741824 B)
  return raw_limit, "gib", GB_BINARY

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

def iter_quota_files():
  for proto in PROTO_DIRS:
    d = os.path.join(QUOTA_ROOT, proto)
    if not os.path.isdir(d):
      continue
    for name in os.listdir(d):
      if name.endswith(".json"):
        yield proto, os.path.join(d, name)

def fetch_all_user_traffic(api_server):
  # Xray stats name format (bytes):
  # - user>>>[email]>>>traffic>>>uplink
  # - user>>>[email]>>>traffic>>>downlink
  try:
    out = subprocess.check_output(
      ["xray", "api", "statsquery", f"--server={api_server}", "--pattern", "user>>>"],
      text=True,
      stderr=subprocess.DEVNULL,
    )
    data = json.loads(out)
  except Exception:
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
  st = meta.get("status") or {}
  changed = False

  prev_used = parse_int(meta.get("quota_used"))
  q_used_eff = max(prev_used, parse_int(q_used))

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
    if st.get("lock_reason") != "quota":
      st["lock_reason"] = "quota"
      changed = True
    if not st.get("locked_at"):
      st["locked_at"] = now_iso()
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
    q_used = max(prev_used, api_used)

    exhausted = (q_limit > 0 and q_used >= q_limit)
    meta_changed = ensure_quota_status(meta, exhausted, q_limit, q_used, q_unit, bpg) if isinstance(meta, dict) else False

    if meta_changed and not dry_run:
      try:
        save_json_atomic(path, meta)
      except Exception:
        pass

    if exhausted:
      if ensure_user(rule, username, marker):
        changed_cfg = True

  if changed_cfg and not dry_run:
    try:
      save_json_atomic(config_path, cfg)
    except Exception:
      return 0
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
  systemctl enable xray-expired --now >/dev/null 2>&1 || true
  systemctl enable xray-limit-ip --now >/dev/null 2>&1 || true
  systemctl enable xray-quota --now >/dev/null 2>&1 || true
  systemctl restart xray-expired >/dev/null 2>&1 || true
  systemctl restart xray-limit-ip >/dev/null 2>&1 || true
  systemctl restart xray-quota >/dev/null 2>&1 || true

  ok "Script manajemen siap:"
  ok "  - /usr/local/bin/user-expired (service: xray-expired)"
  ok "  - /usr/local/bin/limit-ip     (service: xray-limit-ip)"
  ok "  - /usr/local/bin/user-block   (CLI)"
  ok "  - /usr/local/bin/xray-quota    (service: xray-quota)"
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

  if command -v jq >/dev/null 2>&1 && [[ -f "$XRAY_CONFIG" ]]; then
    if jq -e . "$XRAY_CONFIG" >/dev/null 2>&1; then
      ok "sanity: xray config JSON OK"
    else
      warn "sanity: xray config JSON INVALID"
      jq -e . "$XRAY_CONFIG" >&2 || true
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
  need_root
  check_os
  install_base_deps
  need_python3
  install_extra_deps
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
  write_xray_config
  write_xray_modular_configs
  configure_xray_service_confdir
  write_nginx_config
  install_management_scripts
  setup_logrotate
  configure_fail2ban_aggressive_jails
  sanity_check
  ok "Setup telah selesai ✅"
}

main "$@"
