#!/usr/bin/env bash
set -euo pipefail

SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

on_err() {
  local rc="$?"
  echo "[ERROR] line ${BASH_LINENO[0]}: ${BASH_COMMAND} (exit ${rc})" >&2
  exit "${rc}"
}
trap on_err ERR

if [[ -t 1 ]]; then
  UI_RESET='\033[0m'
  UI_BOLD='\033[1m'
  UI_ACCENT='\033[0;36m'
  UI_MUTED='\033[0;37m'
  UI_WARN='\033[1;33m'
  UI_ERR='\033[0;31m'
  UI_OK='\033[0;32m'
else
  UI_RESET=''
  UI_BOLD=''
  UI_ACCENT=''
  UI_MUTED=''
  UI_WARN=''
  UI_ERR=''
  UI_OK=''
fi

BOT_HOME="${BOT_HOME:-/opt/bot-telegram}"
BOT_ENV_DIR="${BOT_ENV_DIR:-/etc/xray-telegram-bot}"
BOT_ENV_FILE="${BOT_ENV_FILE:-${BOT_ENV_DIR}/bot.env}"
BOT_STATE_DIR="${BOT_STATE_DIR:-/var/lib/xray-telegram-bot}"
BOT_LOG_DIR="${BOT_LOG_DIR:-/var/log/xray-telegram-bot}"

BACKEND_SERVICE="xray-telegram-backend"
GATEWAY_SERVICE="xray-telegram-gateway"
MONITOR_SERVICE="xray-telegram-monitor"

SRC_OWNER="${BOT_SOURCE_OWNER:-superdecrypt-dev}"
SRC_REPO="${BOT_SOURCE_REPO:-autoscript}"
SRC_REF="${BOT_SOURCE_REF:-main}"
SRC_ARCHIVE_DEFAULT_URL="https://github.com/${SRC_OWNER}/${SRC_REPO}/raw/${SRC_REF}/bot_telegram.zip"
SRC_ARCHIVE_URL="${BOT_SOURCE_ARCHIVE_URL:-${SRC_ARCHIVE_DEFAULT_URL}}"
SRC_ARCHIVE_SHA256="${BOT_SOURCE_ARCHIVE_SHA256:-c3e056cd869b85fbab99e4a96f6950d716f533e0c7031939d2218d5f72a7c000}"
SRC_ARCHIVE_SHA256_URL="${BOT_SOURCE_ARCHIVE_SHA256_URL:-}"
ALLOW_UNVERIFIED_ARCHIVE="${BOT_ALLOW_UNVERIFIED_ARCHIVE:-1}"

OS_DEPS=(
  curl
  ca-certificates
  tar
  unzip
  jq
  rsync
  git
  bash
  python3
  python3-venv
  python3-pip
)

log() { echo -e "${UI_ACCENT}[telegram-installer]${UI_RESET} $*"; }
ok() { echo -e "${UI_OK}[OK]${UI_RESET} $*"; }
warn() { echo -e "${UI_WARN}[WARN]${UI_RESET} $*" >&2; }
die() { echo -e "${UI_ERR}[ERROR]${UI_RESET} $*" >&2; exit 1; }
BACK_INPUT_SENTINEL="__BACK__$(date +%s%N)_${RANDOM}_${RANDOM}__"
CONFIGURE_ENV_CANCELLED=0

hr() {
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
  echo -e "${UI_MUTED}${line}${UI_RESET}"
}

safe_clear() {
  if [[ -t 1 ]] && command -v clear >/dev/null 2>&1; then
    clear || true
  fi
}

pause() {
  read -r -p "Tekan ENTER untuk kembali..." _ || true
}

run_action() {
  # Jalankan aksi dalam subshell agar error tidak langsung menutup menu.
  # args: label cmd...
  local label="$1"
  shift || true

  local rc=0
  set +e
  ( set -euo pipefail; "$@" )
  rc=$?
  set -euo pipefail

  if (( rc != 0 )); then
    warn "${label} gagal (rc=${rc})."
  fi
  return 0
}

is_back_choice() {
  local v="${1:-}"
  v="$(echo "${v}" | tr '[:upper:]' '[:lower:]')"
  [[ "${v}" == "0" || "${v}" == "kembali" || "${v}" == "k" || "${v}" == "back" || "${v}" == "b" ]]
}

cancel_env_config() {
  CONFIGURE_ENV_CANCELLED=1
  warn "Konfigurasi env dibatalkan (kembali)."
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Jalankan script sebagai root."
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

normalize_path() {
  local path="$1"
  if command_exists realpath; then
    realpath -m -- "${path}" 2>/dev/null || printf '%s\n' "${path}"
    return 0
  fi
  if command_exists readlink; then
    readlink -m -- "${path}" 2>/dev/null || printf '%s\n' "${path}"
    return 0
  fi
  printf '%s\n' "${path}"
}

assert_safe_delete_target() {
  local target="$1"
  local label="${2:-path}"
  local resolved

  [[ -n "${target}" ]] || die "Path ${label} kosong; batalkan uninstall."
  resolved="$(normalize_path "${target}")"
  [[ -n "${resolved}" ]] || die "Path ${label} tidak valid: ${target}"
  [[ "${resolved}" == /* ]] || die "Path ${label} harus absolut: ${resolved}"
  if [[ "${resolved}" == *$'\n'* || "${resolved}" == *$'\r'* ]]; then
    die "Path ${label} tidak valid (mengandung newline)."
  fi

  case "${resolved}" in
    "/"|"/."|"/.."|"/bin"|"/boot"|"/dev"|"/etc"|"/home"|"/lib"|"/lib64"|"/media"|"/mnt"|"/opt"|"/proc"|"/root"|"/run"|"/sbin"|"/srv"|"/sys"|"/tmp"|"/usr"|"/var")
      die "Path ${label} terlalu berbahaya untuk dihapus: ${resolved}"
      ;;
  esac
}

mask_secret() {
  local s="$1"
  local n
  n="${#s}"
  if [[ -z "$s" ]]; then
    echo "(kosong)"
    return 0
  fi
  if (( n <= 6 )); then
    echo "******"
    return 0
  fi
  echo "${s:0:3}...${s: -3}"
}

get_env_value() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  awk -v key="$key" -F= '$1==key {print substr($0, index($0,"=")+1); exit}' "$file"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp

  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    die "Nilai env untuk ${key} tidak valid (mengandung newline)."
  fi

  mkdir -p "$(dirname "$file")"
  [[ -f "$file" ]] || touch "$file"

  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { done=0 }
    $0 ~ ("^" key "=") { print key "=" value; done=1; next }
    { print }
    END { if (!done) print key "=" value }
  ' "$file" > "$tmp"

  install -m 600 "$tmp" "$file"
  rm -f "$tmp" >/dev/null 2>&1 || true
}

prompt_with_default() {
  local prompt="$1"
  local def="$2"
  local out
  read -r -p "${prompt} [${def}]: " out || true
  echo "${out:-$def}"
}

prompt_with_default_or_back() {
  local prompt="$1"
  local def="$2"
  local out
  read -r -p "${prompt} [${def}] (atau kembali): " out || true
  if is_back_choice "${out}"; then
    echo "${BACK_INPUT_SENTINEL}"
    return 0
  fi
  echo "${out:-$def}"
}

prompt_yes_no() {
  local prompt="$1"
  local ans
  while true; do
    if ! read -r -p "${prompt} (y/n): " ans; then
      echo
      warn "Input ditutup (EOF). Aksi dibatalkan."
      return 1
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) echo "Masukkan y atau n." ;;
    esac
  done
}

prompt_yes_no_or_back() {
  local prompt="$1"
  local ans
  while true; do
    if ! read -r -p "${prompt} (y/n/kembali): " ans; then
      echo
      warn "Input ditutup (EOF). Kembali ke menu."
      return 2
    fi
    case "${ans,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      0|kembali|k|back|b) return 2 ;;
      *) echo "Masukkan y, n, atau kembali." ;;
    esac
  done
}

prompt_secret() {
  local prompt="$1"
  local out
  read -r -s -p "${prompt}: " out || true
  # Tampilkan newline prompt ke stderr agar command substitution tidak menangkapnya.
  printf '\n' >&2
  printf '%s\n' "$out"
}

prompt_secret_or_back() {
  local prompt="$1"
  local out
  read -r -s -p "${prompt} (atau kembali): " out || true
  # Tampilkan newline prompt ke stderr agar command substitution tidak menangkapnya.
  printf '\n' >&2
  if is_back_choice "${out}"; then
    printf '%s\n' "${BACK_INPUT_SENTINEL}"
    return 0
  fi
  printf '%s\n' "$out"
}

generate_secret() {
  if command_exists openssl; then
    openssl rand -hex 24
  else
    date +%s%N | sha256sum | awk '{print $1}'
  fi
}

ensure_env_file() {
  mkdir -p "${BOT_HOME}" "${BOT_ENV_DIR}" "${BOT_STATE_DIR}" "${BOT_LOG_DIR}"

  if [[ ! -f "${BOT_ENV_FILE}" ]]; then
    cat > "${BOT_ENV_FILE}" <<ENVEOF
INTERNAL_SHARED_SECRET=
TELEGRAM_BOT_TOKEN=
TELEGRAM_BOT_USERNAME=
TELEGRAM_DEFAULT_CHAT_ID=
TELEGRAM_ADMIN_CHAT_IDS=
TELEGRAM_ADMIN_USER_IDS=
TELEGRAM_ALLOW_UNRESTRICTED_ACCESS=false
TELEGRAM_ACTION_COOLDOWN_SECONDS=1
TELEGRAM_CLEANUP_COOLDOWN_SECONDS=30
TELEGRAM_MAX_INPUT_LENGTH=128
BACKEND_BASE_URL=http://127.0.0.1:8080
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8080
COMMANDS_FILE=${BOT_HOME}/shared/commands.json
ENABLE_DANGEROUS_ACTIONS=true
ENVEOF
    chmod 600 "${BOT_ENV_FILE}"
    ok "File env dibuat: ${BOT_ENV_FILE}"
  else
    chmod 600 "${BOT_ENV_FILE}" || true
  fi
}

validate_required_env() {
  local missing=()
  local key val admin_chat_ids admin_user_ids allow_unrestricted
  for key in INTERNAL_SHARED_SECRET TELEGRAM_BOT_TOKEN; do
    val="$(get_env_value "$key" "${BOT_ENV_FILE}")"
    [[ -n "${val}" ]] || missing+=("$key")
  done

  if (( ${#missing[@]} > 0 )); then
    warn "Env belum lengkap: ${missing[*]}"
    return 1
  fi

  admin_chat_ids="$(get_env_value TELEGRAM_ADMIN_CHAT_IDS "${BOT_ENV_FILE}")"
  admin_user_ids="$(get_env_value TELEGRAM_ADMIN_USER_IDS "${BOT_ENV_FILE}")"
  allow_unrestricted="$(printf '%s' "$(get_env_value TELEGRAM_ALLOW_UNRESTRICTED_ACCESS "${BOT_ENV_FILE}")" | tr '[:upper:]' '[:lower:]')"
  if [[ -z "${admin_chat_ids}" && -z "${admin_user_ids}" && "${allow_unrestricted}" != "true" ]]; then
    warn "Admin ACL kosong. Isi TELEGRAM_ADMIN_* atau set TELEGRAM_ALLOW_UNRESTRICTED_ACCESS=true (tidak direkomendasikan)."
  fi
  return 0
}

service_unit_exists() {
  local svc="$1"
  systemctl cat "${svc}.service" >/dev/null 2>&1
}

timer_unit_exists() {
  local timer="$1"
  systemctl cat "${timer}.timer" >/dev/null 2>&1
}

show_service_status() {
  local svc="$1"
  local active enabled

  active="$(systemctl is-active "${svc}" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "${svc}" 2>/dev/null || true)"

  [[ -n "${active}" ]] || active="unknown"
  [[ -n "${enabled}" ]] || enabled="unknown"

  printf "%-24s active=%-10s enabled=%s\n" "${svc}" "${active}" "${enabled}"
}

install_dependencies() {
  need_root

  if ! command_exists apt-get; then
    die "Script ini saat ini mendukung distro berbasis apt (Ubuntu/Debian)."
  fi

  export DEBIAN_FRONTEND=noninteractive
  log "Install dependency OS/runtime..."
  apt-get update -y
  apt-get install -y "${OS_DEPS[@]}"

  ok "Dependency berhasil dipasang."
  echo "Versi runtime:"
  echo "- python3: $(python3 --version 2>/dev/null || echo 'n/a')"
}

configure_env_interactive() {
  need_root
  ensure_env_file
  CONFIGURE_ENV_CANCELLED=0

  local current_token current_secret current_bot_username current_default_chat_id current_admin_chat_ids current_admin_user_ids current_dangerous current_allow_unrestricted
  local token bot_username default_chat_id admin_chat_ids admin_user_ids dangerous allow_unrestricted secret_input
  local final_token final_secret staged_env

  current_token="$(get_env_value TELEGRAM_BOT_TOKEN "${BOT_ENV_FILE}")"
  current_secret="$(get_env_value INTERNAL_SHARED_SECRET "${BOT_ENV_FILE}")"
  current_bot_username="$(get_env_value TELEGRAM_BOT_USERNAME "${BOT_ENV_FILE}")"
  current_default_chat_id="$(get_env_value TELEGRAM_DEFAULT_CHAT_ID "${BOT_ENV_FILE}")"
  current_admin_chat_ids="$(get_env_value TELEGRAM_ADMIN_CHAT_IDS "${BOT_ENV_FILE}")"
  current_admin_user_ids="$(get_env_value TELEGRAM_ADMIN_USER_IDS "${BOT_ENV_FILE}")"
  current_dangerous="$(get_env_value ENABLE_DANGEROUS_ACTIONS "${BOT_ENV_FILE}")"
  current_allow_unrestricted="$(get_env_value TELEGRAM_ALLOW_UNRESTRICTED_ACCESS "${BOT_ENV_FILE}")"

  echo "Konfigurasi env: ${BOT_ENV_FILE}"
  echo "- TELEGRAM_BOT_TOKEN: $(mask_secret "${current_token}")"
  echo "- INTERNAL_SHARED_SECRET: $(mask_secret "${current_secret}")"

  token="$(prompt_secret_or_back "Masukkan TELEGRAM_BOT_TOKEN (kosong=pertahankan yang lama)")"
  if [[ "${token}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  if [[ -n "${token}" ]]; then
    final_token="${token}"
  else
    final_token="${current_token}"
  fi

  bot_username="$(prompt_with_default_or_back "TELEGRAM_BOT_USERNAME (opsional, tanpa @)" "${current_bot_username}")"
  if [[ "${bot_username}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  default_chat_id="$(prompt_with_default_or_back "TELEGRAM_DEFAULT_CHAT_ID (opsional)" "${current_default_chat_id}")"
  if [[ "${default_chat_id}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  admin_chat_ids="$(prompt_with_default_or_back "TELEGRAM_ADMIN_CHAT_IDS (opsional, pisahkan koma)" "${current_admin_chat_ids}")"
  if [[ "${admin_chat_ids}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  admin_user_ids="$(prompt_with_default_or_back "TELEGRAM_ADMIN_USER_IDS (opsional, pisahkan koma)" "${current_admin_user_ids}")"
  if [[ "${admin_user_ids}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  dangerous="$(prompt_with_default_or_back "ENABLE_DANGEROUS_ACTIONS (true/false)" "${current_dangerous}")"
  if [[ "${dangerous}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi
  allow_unrestricted="$(prompt_with_default_or_back "TELEGRAM_ALLOW_UNRESTRICTED_ACCESS (true/false)" "${current_allow_unrestricted}")"
  if [[ "${allow_unrestricted}" == "${BACK_INPUT_SENTINEL}" ]]; then
    cancel_env_config
    return 0
  fi

  if [[ -z "${current_secret}" ]]; then
    secret_input="$(generate_secret)"
    final_secret="${secret_input}"
    ok "INTERNAL_SHARED_SECRET digenerate otomatis."
  else
    final_secret="${current_secret}"
  fi

  staged_env="$(mktemp "${BOT_ENV_DIR}/bot.env.staged.XXXXXX")"
  if [[ -f "${BOT_ENV_FILE}" ]]; then
    cp "${BOT_ENV_FILE}" "${staged_env}"
  fi

  set_env_value TELEGRAM_BOT_TOKEN "${final_token}" "${staged_env}"
  set_env_value INTERNAL_SHARED_SECRET "${final_secret}" "${staged_env}"
  set_env_value TELEGRAM_BOT_USERNAME "${bot_username}" "${staged_env}"
  set_env_value TELEGRAM_DEFAULT_CHAT_ID "${default_chat_id}" "${staged_env}"
  set_env_value TELEGRAM_ADMIN_CHAT_IDS "${admin_chat_ids}" "${staged_env}"
  set_env_value TELEGRAM_ADMIN_USER_IDS "${admin_user_ids}" "${staged_env}"
  set_env_value ENABLE_DANGEROUS_ACTIONS "${dangerous:-true}" "${staged_env}"
  set_env_value TELEGRAM_ALLOW_UNRESTRICTED_ACCESS "${allow_unrestricted:-false}" "${staged_env}"

  set_env_value BACKEND_BASE_URL "http://127.0.0.1:8080" "${staged_env}"
  set_env_value BACKEND_HOST "127.0.0.1" "${staged_env}"
  set_env_value BACKEND_PORT "8080" "${staged_env}"
  set_env_value COMMANDS_FILE "${BOT_HOME}/shared/commands.json" "${staged_env}"

  chmod 600 "${staged_env}" || true
  mv -f "${staged_env}" "${BOT_ENV_FILE}"
  chmod 600 "${BOT_ENV_FILE}" || true
  validate_required_env || warn "Beberapa field wajib belum terisi."
  ok "Konfigurasi env selesai."
}

change_telegram_token() {
  need_root
  ensure_env_file

  local current masked new_token confirm
  current="$(get_env_value TELEGRAM_BOT_TOKEN "${BOT_ENV_FILE}")"
  masked="$(mask_secret "${current}")"

  echo "Token saat ini: ${masked}"
  new_token="$(prompt_secret_or_back "Masukkan token Telegram baru")"
  if [[ "${new_token}" == "${BACK_INPUT_SENTINEL}" ]]; then
    warn "Ganti token dibatalkan (kembali)."
    return 0
  fi
  [[ -n "${new_token}" ]] || die "Token baru tidak boleh kosong."

  confirm="$(prompt_secret_or_back "Ulangi token untuk konfirmasi")"
  if [[ "${confirm}" == "${BACK_INPUT_SENTINEL}" ]]; then
    warn "Ganti token dibatalkan (kembali)."
    return 0
  fi
  [[ "${new_token}" == "${confirm}" ]] || die "Konfirmasi token tidak sama."

  set_env_value TELEGRAM_BOT_TOKEN "${new_token}" "${BOT_ENV_FILE}"
  chmod 600 "${BOT_ENV_FILE}" || true
  ok "Token berhasil diperbarui di ${BOT_ENV_FILE}."

  local restart_rc=0
  if prompt_yes_no_or_back "Restart service bot sekarang"; then
    start_or_restart_services
  else
    restart_rc=$?
    if (( restart_rc == 2 )); then
      warn "Lewati restart service (kembali)."
    fi
  fi
}

validate_source_tree() {
  local src="$1"
  [[ -d "${src}" ]] || die "Source bot tidak ditemukan: ${src}"
  [[ -f "${src}/gateway-py/requirements.txt" ]] || die "Source invalid: gateway-py/requirements.txt tidak ditemukan"
  [[ -f "${src}/gateway-py/app/main.py" ]] || die "Source invalid: gateway-py/app/main.py tidak ditemukan"
  [[ -f "${src}/backend-py/requirements.txt" ]] || die "Source invalid: backend-py/requirements.txt tidak ditemukan"
  [[ -f "${src}/shared/commands.json" ]] || die "Source invalid: shared/commands.json tidak ditemukan"
  [[ -f "${src}/systemd/xray-telegram-backend.service.tpl" ]] || die "Source invalid: template backend service tidak ditemukan"
  [[ -f "${src}/systemd/xray-telegram-gateway.service.tpl" ]] || die "Source invalid: template gateway service tidak ditemukan"
}

extract_source_archive() {
  local archive="$1"
  local dst="$2"
  local archive_lower
  archive_lower="$(echo "${archive}" | tr '[:upper:]' '[:lower:]')"

  if [[ "${archive_lower}" == *.zip ]]; then
    python3 - "${archive}" "${dst}" <<'PY' || die "Gagal extract archive zip."
import sys
import zipfile

archive_path = sys.argv[1]
dest_path = sys.argv[2]

with zipfile.ZipFile(archive_path, "r") as zf:
  zf.extractall(dest_path)
PY
    return 0
  fi

  tar -xzf "${archive}" -C "${dst}" || die "Gagal extract archive tar.gz."
}

resolve_archive_checksum() {
  local archive="$1"
  local checksum_file="$2"
  local expected actual

  expected="$(echo "${SRC_ARCHIVE_SHA256}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
  if [[ -z "${expected}" && -n "${SRC_ARCHIVE_SHA256_URL}" ]]; then
    log "Download checksum file: ${SRC_ARCHIVE_SHA256_URL}"
    if curl -fsSL --connect-timeout 15 --max-time 60 "${SRC_ARCHIVE_SHA256_URL}" -o "${checksum_file}"; then
      expected="$(awk '{print tolower($1)}' "${checksum_file}" | grep -E '^[0-9a-f]{64}$' | head -n1 || true)"
    else
      warn "Checksum file tidak bisa diunduh dari ${SRC_ARCHIVE_SHA256_URL}."
    fi
  fi

  if [[ -z "${expected}" ]]; then
    if [[ "${ALLOW_UNVERIFIED_ARCHIVE}" == "1" ]]; then
      warn "Checksum source tidak tersedia; lanjut TANPA verifikasi (BOT_ALLOW_UNVERIFIED_ARCHIVE=1)."
      return 0
    fi
    die "Checksum source tidak tersedia. Set BOT_SOURCE_ARCHIVE_SHA256 (disarankan) atau BOT_SOURCE_ARCHIVE_SHA256_URL. Untuk bypass (tidak direkomendasikan), set BOT_ALLOW_UNVERIFIED_ARCHIVE=1."
  fi

  command_exists sha256sum || die "sha256sum tidak tersedia untuk verifikasi integritas source archive."
  actual="$(sha256sum "${archive}" | awk '{print tolower($1)}')"
  [[ "${actual}" == "${expected}" ]] || die "Checksum source archive tidak cocok. expected=${expected}, actual=${actual}"
  ok "Checksum source archive valid."
}

deploy_or_update_files() {
  need_root

  local cmd
  for cmd in curl tar rsync python3; do
    command_exists "${cmd}" || die "Dependency '${cmd}' belum tersedia. Jalankan menu 2) Install Dependencies."
  done

  local tmp archive checksum_file src_root src_dir archive_ext archive_url_no_query
  tmp="$(mktemp -d /tmp/bot-telegram-src.XXXXXX)"
  archive_url_no_query="${SRC_ARCHIVE_URL%%\?*}"
  archive_ext="tar.gz"
  if [[ "${archive_url_no_query,,}" == *.zip ]]; then
    archive_ext="zip"
  fi
  archive="${tmp}/src.${archive_ext}"
  checksum_file="${tmp}/src.archive.sha256"

  log "Download source archive: ${SRC_ARCHIVE_URL}"
  curl -fsSL --connect-timeout 15 --max-time 180 "${SRC_ARCHIVE_URL}" -o "${archive}" || die "Gagal download archive source."
  resolve_archive_checksum "${archive}" "${checksum_file}"

  log "Extract archive..."
  extract_source_archive "${archive}" "${tmp}"

  src_root="$(find "${tmp}" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  [[ -n "${src_root}" ]] || die "Tidak menemukan root folder hasil extract."

  # Support dua layout archive:
  # 1) Repo archive: <root>/bot-telegram/...
  # 2) Bot-only archive: <root>/gateway-py, <root>/backend-py, ...
  if [[ -d "${src_root}/bot-telegram" ]]; then
    src_dir="${src_root}/bot-telegram"
  else
    src_dir="${src_root}"
  fi
  validate_source_tree "${src_dir}"

  mkdir -p "${BOT_HOME}" "${BOT_STATE_DIR}" "${BOT_LOG_DIR}" "${BOT_ENV_DIR}"

  log "Sync source ke ${BOT_HOME}"
  rsync -a --delete \
    --exclude '.env' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "${src_dir}/" "${BOT_HOME}/"

  rm -rf "${tmp}" >/dev/null 2>&1 || true

  log "Install dependency Python backend"
  if [[ ! -d "${BOT_HOME}/.venv" ]]; then
    python3 -m venv "${BOT_HOME}/.venv"
  fi
  "${BOT_HOME}/.venv/bin/pip" install --upgrade pip >/dev/null
  "${BOT_HOME}/.venv/bin/pip" install -r "${BOT_HOME}/backend-py/requirements.txt"
  "${BOT_HOME}/.venv/bin/pip" install -r "${BOT_HOME}/gateway-py/requirements.txt"

  log "Validasi syntax Python (backend + gateway)"
  local backend_py_files=() gateway_py_files=()
  mapfile -t backend_py_files < <(find "${BOT_HOME}/backend-py/app" -name '*.py')
  mapfile -t gateway_py_files < <(find "${BOT_HOME}/gateway-py/app" -name '*.py')
  if (( ${#backend_py_files[@]} > 0 )); then
    python3 -m py_compile "${backend_py_files[@]}"
  fi
  if (( ${#gateway_py_files[@]} > 0 )); then
    python3 -m py_compile "${gateway_py_files[@]}"
  fi

  ensure_env_file
  if [[ ! -f "${BOT_HOME}/.env" ]]; then
    cp "${BOT_ENV_FILE}" "${BOT_HOME}/.env" || true
  fi

  chmod -R go-rwx "${BOT_ENV_DIR}" || true
  ok "Deploy/update bot files selesai."
}

install_or_update_systemd() {
  need_root
  command_exists systemctl || die "systemctl tidak tersedia di host ini."

  local backend_tpl gateway_tpl monitor_tpl monitor_timer_tpl
  local backend_dst gateway_dst monitor_dst monitor_timer_dst
  backend_tpl="${BOT_HOME}/systemd/xray-telegram-backend.service.tpl"
  gateway_tpl="${BOT_HOME}/systemd/xray-telegram-gateway.service.tpl"
  monitor_tpl="${BOT_HOME}/systemd/${MONITOR_SERVICE}.service.tpl"
  monitor_timer_tpl="${BOT_HOME}/systemd/${MONITOR_SERVICE}.timer.tpl"
  backend_dst="/etc/systemd/system/${BACKEND_SERVICE}.service"
  gateway_dst="/etc/systemd/system/${GATEWAY_SERVICE}.service"
  monitor_dst="/etc/systemd/system/${MONITOR_SERVICE}.service"
  monitor_timer_dst="/etc/systemd/system/${MONITOR_SERVICE}.timer"

  [[ -f "${backend_tpl}" ]] || die "Template tidak ditemukan: ${backend_tpl}"
  [[ -f "${gateway_tpl}" ]] || die "Template tidak ditemukan: ${gateway_tpl}"

  sed \
    -e "s#/opt/bot-telegram#${BOT_HOME}#g" \
    -e "s#/etc/xray-telegram-bot/bot.env#${BOT_ENV_FILE}#g" \
    "${backend_tpl}" > "${backend_dst}"

  sed \
    -e "s#/opt/bot-telegram#${BOT_HOME}#g" \
    -e "s#/etc/xray-telegram-bot/bot.env#${BOT_ENV_FILE}#g" \
    "${gateway_tpl}" > "${gateway_dst}"

  if [[ -f "${monitor_tpl}" ]]; then
    sed \
      -e "s#/opt/bot-telegram#${BOT_HOME}#g" \
      -e "s#/etc/xray-telegram-bot/bot.env#${BOT_ENV_FILE}#g" \
      "${monitor_tpl}" > "${monitor_dst}"
  fi

  if [[ -f "${monitor_timer_tpl}" ]]; then
    sed \
      -e "s#/opt/bot-telegram#${BOT_HOME}#g" \
      -e "s#/etc/xray-telegram-bot/bot.env#${BOT_ENV_FILE}#g" \
      "${monitor_timer_tpl}" > "${monitor_timer_dst}"
  fi

  chmod 644 "${backend_dst}" "${gateway_dst}"
  [[ -f "${monitor_dst}" ]] && chmod 644 "${monitor_dst}"
  [[ -f "${monitor_timer_dst}" ]] && chmod 644 "${monitor_timer_dst}"

  systemctl daemon-reload
  systemctl enable "${BACKEND_SERVICE}" "${GATEWAY_SERVICE}" >/dev/null 2>&1 || true
  if [[ -f "${monitor_dst}" && -f "${monitor_timer_dst}" ]]; then
    systemctl enable "${MONITOR_SERVICE}.timer" >/dev/null 2>&1 || true
    systemctl restart "${MONITOR_SERVICE}.timer" >/dev/null 2>&1 || true
  fi

  ok "Systemd service terpasang/terupdate."
  show_service_status "${BACKEND_SERVICE}"
  show_service_status "${GATEWAY_SERVICE}"
  if [[ -f "${monitor_dst}" && -f "${monitor_timer_dst}" ]]; then
    show_service_status "${MONITOR_SERVICE}.timer"
  fi
}

start_or_restart_services() {
  need_root
  command_exists systemctl || die "systemctl tidak tersedia di host ini."

  service_unit_exists "${BACKEND_SERVICE}" || die "Service ${BACKEND_SERVICE}.service belum terpasang. Jalankan menu 6 dulu."
  service_unit_exists "${GATEWAY_SERVICE}" || die "Service ${GATEWAY_SERVICE}.service belum terpasang. Jalankan menu 6 dulu."

  systemctl restart "${BACKEND_SERVICE}"
  systemctl restart "${GATEWAY_SERVICE}"
  if timer_unit_exists "${MONITOR_SERVICE}"; then
    systemctl restart "${MONITOR_SERVICE}.timer" >/dev/null 2>&1 || true
  fi

  ok "Service bot di-restart."
  show_service_status "${BACKEND_SERVICE}"
  show_service_status "${GATEWAY_SERVICE}"
  if timer_unit_exists "${MONITOR_SERVICE}"; then
    show_service_status "${MONITOR_SERVICE}.timer"
  fi
}

status_services() {
  need_root
  command_exists systemctl || die "systemctl tidak tersedia di host ini."

  echo "Status service bot Telegram"
  hr
  show_service_status "${BACKEND_SERVICE}"
  show_service_status "${GATEWAY_SERVICE}"
  if timer_unit_exists "${MONITOR_SERVICE}"; then
    show_service_status "${MONITOR_SERVICE}.timer"
  fi
  hr

  local token
  token="$(get_env_value TELEGRAM_BOT_TOKEN "${BOT_ENV_FILE}")"
  echo "Env file : ${BOT_ENV_FILE}"
  echo "Token    : $(mask_secret "${token}")"
  echo "Bot home : ${BOT_HOME}"
}

view_logs_menu() {
  need_root
  command_exists journalctl || die "journalctl tidak tersedia."

  local c lines
  lines="$(prompt_with_default "Jumlah baris log" "80")"
  [[ "${lines}" =~ ^[0-9]+$ ]] || lines="80"

  echo "Pilih log service:"
  echo "  1) ${BACKEND_SERVICE}"
  echo "  2) ${GATEWAY_SERVICE}"
  echo "  3) Keduanya"
  echo "  0) Kembali"
  read -r -p "Pilih: " c || true

  case "${c}" in
    1)
      journalctl -u "${BACKEND_SERVICE}" --no-pager -n "${lines}" || true
      ;;
    2)
      journalctl -u "${GATEWAY_SERVICE}" --no-pager -n "${lines}" || true
      ;;
    3)
      journalctl -u "${BACKEND_SERVICE}" --no-pager -n "${lines}" || true
      hr
      journalctl -u "${GATEWAY_SERVICE}" --no-pager -n "${lines}" || true
      ;;
    0|back|kembali|k|b)
      return 0
      ;;
    *)
      warn "Pilihan tidak valid."
      ;;
  esac
}

uninstall_bot() {
  need_root
  command_exists systemctl || die "systemctl tidak tersedia di host ini."

  echo "Anda akan menghapus instalasi bot Telegram secara bersih dari sistem ini."
  echo "- Service: ${BACKEND_SERVICE}, ${GATEWAY_SERVICE}, ${MONITOR_SERVICE}.timer"
  echo "- Bot home: ${BOT_HOME}"
  echo "- Env file: ${BOT_ENV_FILE}"
  echo "- Runtime : ${BOT_STATE_DIR}, ${BOT_LOG_DIR}"
  echo "- Package OS/runtime (python/dll): TIDAK dihapus"
  read -r -p "Ketik HAPUS untuk lanjut (atau kembali): " confirm || true
  if is_back_choice "${confirm}"; then
    warn "Batal uninstall (kembali)."
    return 0
  fi
  [[ "${confirm}" == "HAPUS" ]] || {
    warn "Batal uninstall."
    return 0
  }

  systemctl stop "${BACKEND_SERVICE}" "${GATEWAY_SERVICE}" >/dev/null 2>&1 || true
  systemctl stop "${MONITOR_SERVICE}.timer" "${MONITOR_SERVICE}" >/dev/null 2>&1 || true
  systemctl disable "${BACKEND_SERVICE}" "${GATEWAY_SERVICE}" "${MONITOR_SERVICE}.timer" >/dev/null 2>&1 || true

  rm -f \
    "/etc/systemd/system/${BACKEND_SERVICE}.service" \
    "/etc/systemd/system/${GATEWAY_SERVICE}.service" \
    "/etc/systemd/system/${MONITOR_SERVICE}.service" \
    "/etc/systemd/system/${MONITOR_SERVICE}.timer" >/dev/null 2>&1 || true

  rm -rf \
    "/etc/systemd/system/${BACKEND_SERVICE}.service.d" \
    "/etc/systemd/system/${GATEWAY_SERVICE}.service.d" \
    "/etc/systemd/system/${MONITOR_SERVICE}.service.d" \
    "/etc/systemd/system/${MONITOR_SERVICE}.timer.d" >/dev/null 2>&1 || true

  systemctl daemon-reload || true
  systemctl reset-failed "${BACKEND_SERVICE}" "${GATEWAY_SERVICE}" "${MONITOR_SERVICE}" >/dev/null 2>&1 || true

  assert_safe_delete_target "${BOT_HOME}" "BOT_HOME"
  assert_safe_delete_target "${BOT_ENV_DIR}" "BOT_ENV_DIR"
  assert_safe_delete_target "${BOT_STATE_DIR}" "BOT_STATE_DIR"
  assert_safe_delete_target "${BOT_LOG_DIR}" "BOT_LOG_DIR"

  rm -rf "${BOT_HOME}" "${BOT_ENV_DIR}" "${BOT_STATE_DIR}" "${BOT_LOG_DIR}"
  rm -rf /tmp/bot-telegram-src.* >/dev/null 2>&1 || true

  ok "Uninstall bersih selesai (package OS/runtime tetap terpasang)."
}

quick_setup_all_in_one() {
  need_root
  echo "Quick Setup akan menjalankan:"
  echo "1) Install dependencies"
  echo "2) Configure env/token"
  echo "3) Deploy/update source ke ${BOT_HOME}"
  echo "4) Install/update systemd"
  echo "5) Start/restart service"
  hr

  local quick_rc=0
  if prompt_yes_no_or_back "Lanjutkan Quick Setup sekarang"; then
    :
  else
    quick_rc=$?
    if (( quick_rc == 2 )); then
      warn "Quick setup dibatalkan (kembali)."
      return 0
    fi
    warn "Quick setup dibatalkan."
    return 0
  fi

  install_dependencies
  configure_env_interactive
  if (( CONFIGURE_ENV_CANCELLED == 1 )); then
    warn "Quick setup dihentikan karena konfigurasi env dibatalkan (kembali)."
    return 0
  fi
  validate_required_env || die "Env belum lengkap. Isi dulu data wajib."
  deploy_or_update_files
  install_or_update_systemd
  start_or_restart_services
  status_services

  ok "Quick setup selesai."
}

show_header() {
  safe_clear
  echo -e "${UI_BOLD}${UI_ACCENT}Xray Telegram Bot Installer${UI_RESET}"
  echo -e "${UI_MUTED}Host: $(hostname) | Script: ${0##*/}${UI_RESET}"
  hr
  echo -e "${UI_BOLD}${UI_ACCENT}Main Menu${UI_RESET}"
  echo -e "${UI_MUTED}Target deploy : ${BOT_HOME}${UI_RESET}"
  echo -e "${UI_MUTED}Env file      : ${BOT_ENV_FILE}${UI_RESET}"
  echo -e "${UI_MUTED}Source archive: ${SRC_ARCHIVE_URL}${UI_RESET}"
  hr
}

menu_loop() {
  need_root
  while true; do
    show_header
    echo -e "  ${UI_ACCENT}1)${UI_RESET} Quick Setup Bot Telegram (All-in-One)"
    echo -e "  ${UI_ACCENT}2)${UI_RESET} Install Dependencies"
    echo -e "  ${UI_ACCENT}3)${UI_RESET} Configure Bot (.env)"
    echo -e "  ${UI_ACCENT}4)${UI_RESET} Ganti Telegram Bot Token"
    echo -e "  ${UI_ACCENT}5)${UI_RESET} Deploy/Update Bot Files"
    echo -e "  ${UI_ACCENT}6)${UI_RESET} Install/Update systemd Services"
    echo -e "  ${UI_ACCENT}7)${UI_RESET} Start/Restart Services"
    echo -e "  ${UI_ACCENT}8)${UI_RESET} Status Services"
    echo -e "  ${UI_ACCENT}9)${UI_RESET} View Logs"
    echo -e " ${UI_ACCENT}10)${UI_RESET} Uninstall Bot (Clean, keep packages)"
    echo -e "  ${UI_ACCENT}0)${UI_RESET} Kembali"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      return 0
    fi

    case "${c}" in
      1) run_action "Quick Setup Bot Telegram" quick_setup_all_in_one; pause ;;
      2) run_action "Install Dependencies" install_dependencies; pause ;;
      3) run_action "Configure Bot (.env)" configure_env_interactive; pause ;;
      4) run_action "Ganti Telegram Bot Token" change_telegram_token; pause ;;
      5) run_action "Deploy/Update Bot Files" deploy_or_update_files; pause ;;
      6) run_action "Install/Update systemd Services" install_or_update_systemd; pause ;;
      7) run_action "Start/Restart Services" start_or_restart_services; pause ;;
      8) run_action "Status Services" status_services; pause ;;
      9) run_action "View Logs" view_logs_menu; pause ;;
      10) run_action "Uninstall Bot" uninstall_bot; pause ;;
      0|back|kembali|k|b) return 0 ;;
      *) warn "Pilihan tidak valid."; sleep 1 ;;
    esac
  done
}

usage() {
  cat <<USAGE
Usage:
  $0 menu
  $0 quick-setup
  $0 install-deps
  $0 configure-env
  $0 update-token
  $0 deploy
  $0 install-systemd
  $0 restart
  $0 status
  $0 logs
  $0 uninstall
USAGE
}

main() {
  local cmd="${1:-menu}"
  case "${cmd}" in
    menu) menu_loop ;;
    quick-setup) quick_setup_all_in_one ;;
    install-deps) install_dependencies ;;
    configure-env) configure_env_interactive ;;
    update-token) change_telegram_token ;;
    deploy) deploy_or_update_files ;;
    install-systemd) install_or_update_systemd ;;
    restart) start_or_restart_services ;;
    status) status_services ;;
    logs) view_logs_menu ;;
    uninstall) uninstall_bot ;;
    -h|--help|help) usage ;;
    *) usage; die "Command tidak dikenal: ${cmd}" ;;
  esac
}

main "$@"
