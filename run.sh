#!/usr/bin/env bash
set -euo pipefail

# Harden PATH untuk mencegah PATH hijacking saat script dijalankan sebagai root.
SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

# ============================================================
# run.sh — Installer otomatis Xray VPN Server
# Repo: https://github.com/superdecrypt-dev/autoscript
# ============================================================

# -------------------------
# Konstanta
# -------------------------
REPO_URL="https://github.com/superdecrypt-dev/autoscript.git"
REPO_DIR="/opt/autoscript"
MANAGE_BIN="/usr/local/bin/manage"
MANAGE_MODULES_SRC_DIR="${REPO_DIR}/opt/manage"
MANAGE_MODULES_DST_DIR="/opt/manage"
BOT_INSTALLER_BIN="/usr/local/bin/install-discord-bot"
TELEGRAM_INSTALLER_BIN="/usr/local/bin/install-telegram-bot"
DISCORD_BOT_HOME="/opt/bot-discord"
DISCORD_BOT_SRC_DIR="${REPO_DIR}/bot-discord"

# -------------------------
# Warna output
# -------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -------------------------
# Helpers
# -------------------------
log()  { echo -e "${CYAN}[run]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

hr() { echo "------------------------------------------------------------"; }

repo_has_local_changes() {
  local dir="$1"
  git -C "${dir}" diff --quiet --ignore-submodules -- || return 0
  git -C "${dir}" diff --cached --quiet --ignore-submodules -- || return 0
  if [[ -n "$(git -C "${dir}" ls-files --others --exclude-standard 2>/dev/null || true)" ]]; then
    return 0
  fi
  return 1
}

reclone_repo_with_backup() {
  local target="$1"
  local backup=""
  backup="${target}.backup.$(date +%Y%m%d%H%M%S)"

  warn "Repositori existing memiliki perubahan lokal. Menyimpan backup ke: ${backup}"
  mv "${target}" "${backup}" || die "Gagal backup repositori lama: ${target}"

  log "Mengkloning ulang repositori bersih ke ${target} ..."
  if ! git clone --depth=1 "${REPO_URL}" "${target}" 2>&1; then
    die "Gagal re-clone repositori setelah backup. Backup tersedia di: ${backup}"
  fi
  ok "Repositori bersih berhasil dibuat ulang."
  ok "Backup repositori lama tersimpan di: ${backup}"
}

# -------------------------
# Validasi
# -------------------------
check_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Script ini harus dijalankan sebagai root.\n  Coba: sudo bash run.sh"
  fi
}

check_os() {
  [[ -f /etc/os-release ]] || die "Tidak menemukan /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release

  local id="${ID:-}"
  local ver="${VERSION_ID:-}"
  local codename="${VERSION_CODENAME:-}"

  if [[ "${id}" == "ubuntu" ]]; then
    local ok_ver
    ok_ver="$(awk "BEGIN { print (\"${ver}\" + 0 >= 20.04) ? 1 : 0 }")"
    [[ "${ok_ver}" == "1" ]] || die "Ubuntu minimal 20.04. Versi terdeteksi: ${ver}"
    ok "OS: Ubuntu ${ver} (${codename})"
  elif [[ "${id}" == "debian" ]]; then
    local major="${ver%%.*}"
    [[ "${major:-0}" -ge 11 ]] 2>/dev/null || die "Debian minimal 11. Versi terdeteksi: ${ver}"
    ok "OS: Debian ${ver} (${codename})"
  else
    die "OS tidak didukung: ${id}. Hanya Ubuntu >=20.04 atau Debian >=11."
  fi
}

check_deps() {
  local missing=()
  for cmd in git bash; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      missing+=("${cmd}")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Dependency berikut tidak ditemukan: ${missing[*]}"
    log "Mencoba menginstal dependency yang hilang..."
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${missing[@]}" || die "Gagal menginstal: ${missing[*]}"
    ok "Dependency berhasil dipasang."
  fi
}

# -------------------------
# Langkah instalasi
# -------------------------
clone_repo() {
  mkdir -p "$(dirname "${REPO_DIR}")"

  if [[ -d "${REPO_DIR}" && ! -d "${REPO_DIR}/.git" ]]; then
    if [[ -z "$(find "${REPO_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
      rmdir "${REPO_DIR}" || true
    else
      die "Direktori ${REPO_DIR} sudah ada tetapi bukan git repo. Bersihkan/rename dulu lalu jalankan ulang."
    fi
  fi

  if [[ -d "${REPO_DIR}/.git" ]]; then
    log "Memperbarui repositori di ${REPO_DIR} ..."
    if ! git -C "${REPO_DIR}" pull --ff-only origin main 2>&1; then
      if repo_has_local_changes "${REPO_DIR}"; then
        warn "Update gagal karena working tree tidak bersih."
        reclone_repo_with_backup "${REPO_DIR}"
        return 0
      fi
      die "Gagal update repositori di ${REPO_DIR}. Penyebab bukan perubahan lokal; cek koneksi/remote lalu coba lagi."
    fi
    ok "Repositori berhasil diperbarui."
    return 0
  fi

  log "Mengkloning repositori ke ${REPO_DIR} ..."
  local clone_err=""
  if ! clone_err="$(git clone --depth=1 "${REPO_URL}" "${REPO_DIR}" 2>&1)"; then
    if grep -Eqi 'could not create work tree dir|permission denied|operation not permitted|read-only file system' <<<"${clone_err}"; then
      die "Gagal mengkloning repositori: ${REPO_URL}\n  Penyebab: path tujuan tidak bisa ditulis (${REPO_DIR}). Cek permission/ownership direktori.\n  Detail git: ${clone_err}"
    fi
    die "Gagal mengkloning repositori: ${REPO_URL}\n  Pastikan server memiliki koneksi internet dan URL repo benar.\n  Detail git: ${clone_err}"
  fi
  ok "Repositori berhasil diunduh."
}

install_manage() {
  local src="${REPO_DIR}/manage.sh"
  local bot_installer_src="${REPO_DIR}/install-discord-bot.sh"
  local telegram_installer_src="${REPO_DIR}/install-telegram-bot.sh"

  [[ -f "${src}" ]] || die "File manage.sh tidak ditemukan di repositori."
  [[ -f "${bot_installer_src}" ]] || die "File install-discord-bot.sh tidak ditemukan di repositori."
  [[ -f "${telegram_installer_src}" ]] || die "File install-telegram-bot.sh tidak ditemukan di repositori."

  log "Menginstal 'manage' ke ${MANAGE_BIN} ..."
  install -m 0755 "${src}" "${MANAGE_BIN}"
  ok "Perintah 'manage' tersedia di: ${MANAGE_BIN}"

  if [[ -d "${MANAGE_MODULES_SRC_DIR}" ]]; then
    log "Sinkronisasi modul manage ke ${MANAGE_MODULES_DST_DIR} ..."
    mkdir -p "${MANAGE_MODULES_DST_DIR}"
    cp -a "${MANAGE_MODULES_SRC_DIR}/." "${MANAGE_MODULES_DST_DIR}/"
    find "${MANAGE_MODULES_DST_DIR}" -type d -exec chmod 755 {} + 2>/dev/null || true
    find "${MANAGE_MODULES_DST_DIR}" -type f -name '*.sh' -exec chmod 644 {} + 2>/dev/null || true
    chown -R root:root "${MANAGE_MODULES_DST_DIR}" 2>/dev/null || true
    ok "Modul manage tersedia di: ${MANAGE_MODULES_DST_DIR}"
  else
    warn "Template modul manage tidak ditemukan di repo (${MANAGE_MODULES_SRC_DIR}); lewati sinkronisasi."
  fi

  log "Menginstal installer bot Discord ke ${BOT_INSTALLER_BIN} ..."
  install -m 0755 "${bot_installer_src}" "${BOT_INSTALLER_BIN}"
  ok "Installer bot Discord tersedia di: ${BOT_INSTALLER_BIN}"

  log "Menginstal installer bot Telegram (placeholder) ke ${TELEGRAM_INSTALLER_BIN} ..."
  install -m 0755 "${telegram_installer_src}" "${TELEGRAM_INSTALLER_BIN}"
  ok "Installer bot Telegram tersedia di: ${TELEGRAM_INSTALLER_BIN}"
}

seed_discord_bot_home() {
  if [[ ! -d "${DISCORD_BOT_SRC_DIR}" ]]; then
    warn "Source bot Discord tidak ditemukan di repo (${DISCORD_BOT_SRC_DIR}); lewati bootstrap /opt/bot-discord."
    return 0
  fi

  if [[ -d "${DISCORD_BOT_HOME}" ]] && [[ -n "$(find "${DISCORD_BOT_HOME}" -mindepth 1 -maxdepth 1 2>/dev/null || true)" ]]; then
    ok "Bot home sudah ada: ${DISCORD_BOT_HOME}"
    return 0
  fi

  log "Menyiapkan source awal bot Discord ke ${DISCORD_BOT_HOME} ..."
  mkdir -p "${DISCORD_BOT_HOME}"
  cp -a "${DISCORD_BOT_SRC_DIR}/." "${DISCORD_BOT_HOME}/"
  chown -R root:root "${DISCORD_BOT_HOME}" 2>/dev/null || true
  ok "Bootstrap bot Discord selesai: ${DISCORD_BOT_HOME}"
}

cleanup_repo_after_success() {
  if [[ "${KEEP_REPO_AFTER_INSTALL:-0}" == "1" ]]; then
    warn "KEEP_REPO_AFTER_INSTALL=1 -> lewati hapus source repo (${REPO_DIR})."
    return 0
  fi

  if [[ ! -d "${REPO_DIR}" ]]; then
    return 0
  fi

  local resolved=""
  if command -v readlink >/dev/null 2>&1; then
    resolved="$(readlink -f -- "${REPO_DIR}" 2>/dev/null || true)"
  fi
  [[ -n "${resolved}" ]] || resolved="${REPO_DIR}"

  case "${resolved}" in
    "/"|"/."|"/.."|"/bin"|"/boot"|"/dev"|"/etc"|"/home"|"/lib"|"/lib64"|"/media"|"/mnt"|"/opt"|"/proc"|"/root"|"/run"|"/sbin"|"/srv"|"/sys"|"/tmp"|"/usr"|"/var")
      die "Menolak hapus path berbahaya: ${resolved}"
      ;;
  esac

  if [[ "${PWD}/" == "${resolved}/"* ]]; then
    cd /
  fi

  rm -rf -- "${resolved}"
  ok "Source repo dibersihkan setelah instalasi: ${resolved}"
}

run_setup() {
  local setup="${REPO_DIR}/setup.sh"

  [[ -f "${setup}" ]] || die "File setup.sh tidak ditemukan di repositori."

  log "Menjalankan setup.sh dalam 3 detik ..."
  sleep 3
  hr
  bash "${setup}"
  hr
  ok "setup.sh selesai dijalankan."
}

# -------------------------
# Main
# -------------------------
main() {
  echo
  echo -e "${BOLD}============================================================${NC}"
  echo -e "${BOLD}   Xray VPN Server — Installer Otomatis${NC}"
  echo -e "${BOLD}============================================================${NC}"
  echo

  check_root
  check_os
  check_deps
  clone_repo
  install_manage
  seed_discord_bot_home
  run_setup
  cleanup_repo_after_success

  echo
  echo -e "${BOLD}============================================================${NC}"
  ok "Instalasi selesai."
  echo
  echo -e "  Gunakan perintah berikut untuk membuka menu manajemen:"
  echo -e "  ${BOLD}sudo manage / manage${NC}"
  echo -e "${BOLD}============================================================${NC}"
  echo
}

main "$@"
