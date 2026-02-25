#!/usr/bin/env bash
set -euo pipefail

SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

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

SERVICE_NAMES=("xray-telegram-gateway")

log() { echo -e "${UI_ACCENT}[telegram-installer]${UI_RESET} $*"; }
ok() { echo -e "${UI_OK}[OK]${UI_RESET} $*"; }
warn() { echo -e "${UI_WARN}[WARN]${UI_RESET} $*" >&2; }
die() { echo -e "${UI_ERR}[ERROR]${UI_RESET} $*" >&2; exit 1; }

hr() {
  local w="${COLUMNS:-80}"
  local line
  [[ "${w}" =~ ^[0-9]+$ ]] || w=80
  (( w < 60 )) && w=60
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

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Jalankan script sebagai root."
}

service_status_line() {
  local svc="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "N/A  - ${svc} (systemctl tidak tersedia)"
    return 0
  fi
  local st
  st="$(systemctl is-active "${svc}" 2>/dev/null || true)"
  case "${st}" in
    active) echo "OK   - ${svc}: active" ;;
    inactive) echo "WARN - ${svc}: inactive" ;;
    failed) echo "FAIL - ${svc}: failed" ;;
    *) echo "N/A  - ${svc}: ${st:-not-installed}" ;;
  esac
}

title() {
  safe_clear
  echo -e "${UI_BOLD}Xray Telegram Bot Installer (Placeholder)${UI_RESET}"
  echo "Host: $(hostname 2>/dev/null || echo -n '-')" 
  hr
}

placeholder_step() {
  local label="$1"
  title
  echo "${label}"
  hr
  warn "Fitur ini masih placeholder (kerangka awal), belum menjalankan perubahan sistem."
  echo
  echo "Rencana implementasi:"
  echo "  - Deploy source bot Telegram ke ${BOT_HOME}"
  echo "  - Simpan env di ${BOT_ENV_FILE}"
  echo "  - Gunakan state dir ${BOT_STATE_DIR} dan log dir ${BOT_LOG_DIR}"
  echo "  - Kelola service: ${SERVICE_NAMES[*]}"
  hr
  pause
}

show_status() {
  title
  echo "Status Bot Telegram (placeholder)"
  hr
  local svc
  for svc in "${SERVICE_NAMES[@]}"; do
    service_status_line "${svc}"
  done
  hr
  echo "Path rencana deploy:"
  echo "  BOT_HOME     : ${BOT_HOME}"
  echo "  BOT_ENV_FILE : ${BOT_ENV_FILE}"
  echo "  BOT_STATE_DIR: ${BOT_STATE_DIR}"
  echo "  BOT_LOG_DIR  : ${BOT_LOG_DIR}"
  hr
}

menu() {
  while true; do
    title
    echo -e "${UI_BOLD}${UI_ACCENT}Install BOT Telegram${UI_RESET}"
    hr
    echo "  1) Quick Setup Bot Telegram (Placeholder)"
    echo "  2) Install Dependencies (Placeholder)"
    echo "  3) Configure Bot (.env) (Placeholder)"
    echo "  4) Ganti Telegram Bot Token (Placeholder)"
    echo "  5) Deploy/Update Bot Files (Placeholder)"
    echo "  6) Install/Update systemd Services (Placeholder)"
    echo "  7) Start/Restart Services (Placeholder)"
    echo "  8) Status Services"
    echo "  9) View Logs (Placeholder)"
    echo " 10) Uninstall Bot (Placeholder)"
    echo "  0) Back"
    hr

    local c
    if ! read -r -p "Pilih: " c; then
      echo
      return 0
    fi

    case "${c}" in
      1) placeholder_step "1) Quick Setup Bot Telegram" ;;
      2) placeholder_step "2) Install Dependencies" ;;
      3) placeholder_step "3) Configure Bot (.env)" ;;
      4) placeholder_step "4) Ganti Telegram Bot Token" ;;
      5) placeholder_step "5) Deploy/Update Bot Files" ;;
      6) placeholder_step "6) Install/Update systemd Services" ;;
      7) placeholder_step "7) Start/Restart Services" ;;
      8) show_status; pause ;;
      9) placeholder_step "9) View Logs" ;;
      10) placeholder_step "10) Uninstall Bot" ;;
      0|kembali|k|back|b) return 0 ;;
      *) warn "Pilihan tidak valid"; sleep 1 ;;
    esac
  done
}

usage() {
  cat <<'EOF'
Usage: install-telegram-bot [menu|status|help]
  menu   : buka menu installer placeholder
  status : tampilkan status service placeholder
  help   : tampilkan bantuan
EOF
}

main() {
  need_root
  case "${1:-menu}" in
    menu) menu ;;
    status) show_status ;;
    help|-h|--help) usage ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
