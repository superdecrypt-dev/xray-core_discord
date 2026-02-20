#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# run.sh — Installer otomatis Xray VPN Server
# Repo: https://github.com/superdecrypt-dev/xray-core_discord
# ============================================================

# -------------------------
# Konstanta
# -------------------------
REPO_URL="https://github.com/superdecrypt-dev/xray-core_discord.git"
REPO_DIR="/tmp/xray-core_discord_$$"
MANAGE_BIN="/usr/local/bin/manage"

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

cleanup() {
  if [[ -d "${REPO_DIR}" ]]; then
    log "Membersihkan direktori sementara: ${REPO_DIR}"
    rm -rf "${REPO_DIR}"
  fi
}

# Jalankan cleanup saat script selesai (normal maupun error)
trap cleanup EXIT

# -------------------------
# Validasi
# -------------------------
check_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Script ini harus dijalankan sebagai root.\n  Coba: sudo bash run.sh"
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
  log "Mengkloning repositori ke ${REPO_DIR} ..."
  if ! git clone --depth=1 "${REPO_URL}" "${REPO_DIR}" 2>&1; then
    die "Gagal mengkloning repositori: ${REPO_URL}\n  Pastikan server memiliki koneksi internet dan URL repo benar."
  fi
  ok "Repositori berhasil diunduh."
}

install_manage() {
  local src="${REPO_DIR}/manage.sh"

  [[ -f "${src}" ]] || die "File manage.sh tidak ditemukan di repositori."

  log "Menginstal 'manage' ke ${MANAGE_BIN} ..."
  install -m 0755 "${src}" "${MANAGE_BIN}"
  ok "Perintah 'manage' tersedia di: ${MANAGE_BIN}"
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
  check_deps
  clone_repo
  install_manage
  run_setup

  echo
  echo -e "${BOLD}============================================================${NC}"
  ok "Instalasi selesai!"
  echo
  echo -e "  Gunakan perintah berikut untuk membuka menu manajemen:"
  echo -e "  ${BOLD}sudo manage${NC}"
  echo -e "${BOLD}============================================================${NC}"
  echo
}

main "$@"
