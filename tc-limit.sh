#!/usr/bin/env bash
set -Eeuo pipefail

# tc-limit.sh — Interactive tc bandwidth limiter (Egress + Ingress via IFB)
# Persist config: /etc/tc-limit.conf
# Optional boot apply: systemd service /etc/systemd/system/tc-limit.service

CONFIG_FILE="/etc/tc-limit.conf"
SERVICE_FILE="/etc/systemd/system/tc-limit.service"
INSTALL_PATH="/usr/local/sbin/tc-limit"
IFB_DEV="ifb0"

# Rate bounds shown in menu + enforced in input validation (mbit only; edit in /etc/tc-limit.conf if needed)
RATE_MIN_DEFAULT="1mbit"
RATE_MAX_DEFAULT="10000mbit"
RATE_MIN="$RATE_MIN_DEFAULT"
RATE_MAX="$RATE_MAX_DEFAULT"

# HTB tuning (Opsi A / r2q):
# - HTB will warn "quantum is big" when shaping very high rates (e.g. ~1Gbit) with default r2q.
# - Default: "auto" (compute r2q from rate to keep quantum ~60KB, and not below ~2*MTU).
# - Override by setting HTB_R2Q="2134" (or any integer) in /etc/tc-limit.conf.
HTB_R2Q_DEFAULT="auto"
HTB_QUANTUM_TARGET=60000   # bytes (~60KB)
MTU_FALLBACK=1500
HTB_R2Q="$HTB_R2Q_DEFAULT"


die()  { echo "❌ $*" >&2; exit 1; }
info() { echo "ℹ️  $*"; }
ok()   { echo "✅ $*"; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Jalankan sebagai root (pakai sudo)."; }
need_cmd()  { command -v "$1" >/dev/null 2>&1 || die "Command tidak ada: $1 (install iproute2)."; }

detect_iface() {
  local dev
  dev="$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)"
  if [[ -z "${dev:-}" ]]; then
    dev="$(ip -br link | awk '$1!="lo"{print $1; exit}')"
  fi
  echo "${dev:-}"
}

valid_rate() {
  # Accept ONLY: number + mbit (e.g. 20mbit, 1000mbit, 12.5mbit)
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?mbit$ ]]
}

ensure_rate_bounds() {
  # Ensure RATE_MIN/RATE_MAX exist and are sane; otherwise fall back to defaults.
  if ! valid_rate "${RATE_MIN:-}"; then RATE_MIN="$RATE_MIN_DEFAULT"; fi
  if ! valid_rate "${RATE_MAX:-}"; then RATE_MAX="$RATE_MAX_DEFAULT"; fi

  local min_bps max_bps
  min_bps="$(rate_to_bps "$RATE_MIN")"
  max_bps="$(rate_to_bps "$RATE_MAX")"
  if [[ "$min_bps" -le 0 || "$max_bps" -le 0 || "$min_bps" -gt "$max_bps" ]]; then
    RATE_MIN="$RATE_MIN_DEFAULT"
    RATE_MAX="$RATE_MAX_DEFAULT"
  fi
}

rate_in_bounds() {
  local RATE="$1"
  local min_bps max_bps rate_bps
  min_bps="$(rate_to_bps "$RATE_MIN")"
  max_bps="$(rate_to_bps "$RATE_MAX")"
  rate_bps="$(rate_to_bps "$RATE")"
  [[ "$rate_bps" -ge "$min_bps" && "$rate_bps" -le "$max_bps" ]]
}

# ---- HTB r2q helpers ----
get_mtu() {
  local DEV="$1"
  ip -o link show dev "$DEV" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}'
}

rate_to_bps() {
  # Convert tc rate string (e.g. 1000mbit, 12.5mbit) -> integer bits/sec (decimal units).
  # Input is intentionally restricted to "*mbit" to prevent typos.
  local RATE="$1"
  if [[ "$RATE" =~ ^([0-9]+([.][0-9]+)?)mbit$ ]]; then
    local num="${BASH_REMATCH[1]}"
    awk -v n="$num" 'BEGIN{printf "%.0f", n*1000000}'
    return 0
  fi
  echo 0
}

calc_r2q_auto() {
  # Choose r2q so quantum ~= HTB_QUANTUM_TARGET bytes, but not below ~2*MTU.
  local DEV="$1" RATE="$2"

  local mtu bps bytes target minq r2q_target r2q_max r2q
  mtu="$(get_mtu "$DEV")"
  [[ -n "${mtu:-}" ]] || mtu="$MTU_FALLBACK"

  bps="$(rate_to_bps "$RATE")"
  if [[ "$bps" -le 0 ]]; then
    echo 10
    return 0
  fi

  bytes=$((bps / 8))
  target="$HTB_QUANTUM_TARGET"
  minq=$((mtu * 2))
  [[ "$minq" -ge 3000 ]] || minq=3000

  r2q_target="$(awk -v bytes="$bytes" -v target="$target" 'BEGIN{print int((bytes+target-1)/target)}')"
  r2q_max="$(awk -v bytes="$bytes" -v minq="$minq" 'BEGIN{print int(bytes/minq)}')"

  r2q="$(awk -v t="$r2q_target" -v mx="$r2q_max" 'BEGIN{
    r=t;
    if (mx>0 && r>mx) r=mx;
    minr=10;
    if (mx>0 && mx<minr) minr=mx;
    if (minr<1) minr=1;
    if (r<minr) r=minr;
    print r;
  }')"

  echo "$r2q"
}

resolve_r2q() {
  # If HTB_R2Q is numeric, use it. Otherwise auto-calc per rate.
  local DEV="$1" RATE="$2"
  if [[ "${HTB_R2Q:-}" =~ ^[0-9]+$ ]]; then
    echo "$HTB_R2Q"
  else
    calc_r2q_auto "$DEV" "$RATE"
  fi
}

cleanup_tc() {
  local DEV="$1"
  tc qdisc del dev "$DEV" root    2>/dev/null || true
  tc qdisc del dev "$DEV" ingress 2>/dev/null || true
  tc qdisc del dev "$IFB_DEV" root 2>/dev/null || true
}

setup_egress() {
  local DEV="$1" RATE_OUT="$2" R2Q="$3"
  info "Set EGRESS (OUT) $DEV = $RATE_OUT (r2q=$R2Q)"
  tc qdisc replace dev "$DEV" root handle 1: htb default 10 r2q "$R2Q"
  tc class replace dev "$DEV" parent 1: classid 1:10 htb rate "$RATE_OUT" ceil "$RATE_OUT"
  tc qdisc replace dev "$DEV" parent 1:10 handle 10: fq_codel
}

setup_ifb() {
  info "Aktifkan IFB ($IFB_DEV)"
  modprobe ifb 2>/dev/null || die "modprobe ifb gagal (kernel mungkin tidak punya IFB)."
  modprobe act_mirred 2>/dev/null || true
  modprobe sch_ingress 2>/dev/null || true

  ip link add "$IFB_DEV" type ifb 2>/dev/null || true
  ip link set "$IFB_DEV" up
}

setup_ingress_redirect() {
  local DEV="$1"
  info "Redirect INGRESS (IN) dari $DEV -> $IFB_DEV"
  tc qdisc replace dev "$DEV" handle ffff: ingress

  # IPv4 (wajib)
  tc filter replace dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev "$IFB_DEV" \
    || die "Gagal tambah filter mirred (cek module act_mirred / kernel support)."

  # IPv6 (opsional; kalau gagal tidak fatal)
  tc filter replace dev "$DEV" parent ffff: protocol ipv6 u32 match u32 0 0 \
    action mirred egress redirect dev "$IFB_DEV" 2>/dev/null || true
}

setup_ingress_shape() {
  local RATE_IN="$1" R2Q="$2"
  info "Set INGRESS (IN) $IFB_DEV = $RATE_IN (r2q=$R2Q)"
  tc qdisc replace dev "$IFB_DEV" root handle 2: htb default 20 r2q "$R2Q"
  tc class replace dev "$IFB_DEV" parent 2: classid 2:20 htb rate "$RATE_IN" ceil "$RATE_IN"
  tc qdisc replace dev "$IFB_DEV" parent 2:20 handle 20: fq_codel
}

apply_limits() {
  local DEV="$1" RATE_OUT="$2" RATE_IN="$3"
  [[ -n "$DEV" ]] || die "Interface tidak ketemu."
  ip link show "$DEV" >/dev/null 2>&1 || die "Interface tidak valid: $DEV"

  ensure_rate_bounds
  rate_in_bounds "$RATE_OUT" || die "RATE_OUT di luar batas: min $RATE_MIN, max $RATE_MAX"
  rate_in_bounds "$RATE_IN"  || die "RATE_IN di luar batas: min $RATE_MIN, max $RATE_MAX"

  local R2Q_OUT R2Q_IN
  R2Q_OUT="$(resolve_r2q "$DEV" "$RATE_OUT")"
  R2Q_IN="$(resolve_r2q "$DEV" "$RATE_IN")"
  info "HTB r2q resolved: OUT=$R2Q_OUT | IN=$R2Q_IN (HTB_R2Q=${HTB_R2Q})"

  cleanup_tc "$DEV"
  setup_egress "$DEV" "$RATE_OUT" "$R2Q_OUT"
  setup_ifb
  setup_ingress_redirect "$DEV"
  setup_ingress_shape "$RATE_IN" "$R2Q_IN"
  ok "Limit aktif di $DEV (OUT=$RATE_OUT, IN=$RATE_IN)"
}

remove_limits() {
  local DEV="$1"
  [[ -n "$DEV" ]] || die "Interface tidak ketemu."
  info "Hapus limit dari $DEV dan $IFB_DEV"
  cleanup_tc "$DEV"
  ip link set "$IFB_DEV" down 2>/dev/null || true
  ip link del "$IFB_DEV" 2>/dev/null || true
  ok "Limit dihapus."
}

show_status() {
  local DEV="$1"
  echo "==== iface: $DEV ===="
  tc -s qdisc show dev "$DEV" 2>/dev/null || true
  echo
  tc -s class show dev "$DEV" 2>/dev/null || true
  echo
  echo "==== ifb: $IFB_DEV ===="
  tc -s qdisc show dev "$IFB_DEV" 2>/dev/null || true
  echo
  tc -s class show dev "$IFB_DEV" 2>/dev/null || true
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    RATE_MIN="${RATE_MIN:-$RATE_MIN_DEFAULT}"
    RATE_MAX="${RATE_MAX:-$RATE_MAX_DEFAULT}"
    HTB_R2Q="${HTB_R2Q:-$HTB_R2Q_DEFAULT}"
  else
    RATE_OUT=""
    RATE_IN=""
    DEV_MODE="auto"
    RATE_MIN="$RATE_MIN_DEFAULT"
    RATE_MAX="$RATE_MAX_DEFAULT"
    HTB_R2Q="$HTB_R2Q_DEFAULT"
  fi
  ensure_rate_bounds
}

load_policy() {
  # Load only shaping policy (bounds + HTB_R2Q) without overwriting RATE_OUT/RATE_IN.
  if [[ -f "$CONFIG_FILE" ]]; then
    while IFS= read -r line; do
      case "$line" in
        RATE_MIN=*|RATE_MAX=*|HTB_R2Q=*)
          eval "$line"
          ;;
      esac
    done < <(grep -E '^(RATE_MIN|RATE_MAX|HTB_R2Q)=' "$CONFIG_FILE" 2>/dev/null || true)
  fi
  RATE_MIN="${RATE_MIN:-$RATE_MIN_DEFAULT}"
  RATE_MAX="${RATE_MAX:-$RATE_MAX_DEFAULT}"
  HTB_R2Q="${HTB_R2Q:-$HTB_R2Q_DEFAULT}"
  ensure_rate_bounds
}

save_config() {
  local RATE_OUT="$1" RATE_IN="$2" DEV_MODE="${3:-auto}" \
        HTB_R2Q_SAVE="${4:-$HTB_R2Q_DEFAULT}" \
        RATE_MIN_SAVE="${5:-$RATE_MIN}" \
        RATE_MAX_SAVE="${6:-$RATE_MAX}"

  umask 077
  cat >"$CONFIG_FILE" <<EOF
# tc-limit config
DEV_MODE="$DEV_MODE"   # "auto" recommended
RATE_OUT="$RATE_OUT"
RATE_IN="$RATE_IN"
RATE_MIN="$RATE_MIN_SAVE" # input min bound shown in menu
RATE_MAX="$RATE_MAX_SAVE" # input max bound shown in menu
HTB_R2Q="$HTB_R2Q_SAVE"    # "auto" or integer (e.g., 2134 for ~1Gbit)
EOF
  ok "Config tersimpan: $CONFIG_FILE"
}

boot_enabled() {
  systemctl is-enabled tc-limit.service >/dev/null 2>&1
}

install_self() {
  if [[ "$(realpath "$0")" != "$INSTALL_PATH" ]]; then
    info "Install script ke $INSTALL_PATH"
    install -m 0755 "$0" "$INSTALL_PATH"
  fi
}

install_service() {
  install_self
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=TC bandwidth limiter (Egress+Ingress via IFB)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_PATH apply --config
ExecStop=$INSTALL_PATH remove --auto

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now tc-limit.service
  ok "Auto-apply saat boot AKTIF (tc-limit.service)."
}

disable_service() {
  systemctl disable --now tc-limit.service 2>/dev/null || true
  ok "Auto-apply saat boot NONAKTIF."
}

prompt_rate() {
  local label="$1" val=""
  ensure_rate_bounds
  while true; do
    read -r -p "$label (min $RATE_MIN, max $RATE_MAX; format: angka+mbit, contoh: 1000mbit): " val
    [[ -n "$val" ]] || { echo "⚠️  Tidak boleh kosong."; continue; }

    if ! valid_rate "$val"; then
      echo "❌ Format salah. Wajib angka + mbit (contoh: 1000mbit atau 12.5mbit)."
      continue
    fi

    if ! rate_in_bounds "$val"; then
      echo "❌ Di luar batas: minimal $RATE_MIN, maksimal $RATE_MAX."
      continue
    fi

    echo "$val"
    return 0
  done
}

prompt_rate_mbit_simple() {
  # For changing RATE_MIN/RATE_MAX only (no bound check here).
  local label="$1" val=""
  while true; do
    read -r -p "$label (format: angka+mbit, contoh: 1mbit / 10000mbit): " val
    [[ -n "$val" ]] || { echo "⚠️  Tidak boleh kosong."; continue; }

    if ! valid_rate "$val"; then
      echo "❌ Format salah. Wajib angka + mbit (contoh: 1000mbit atau 12.5mbit)."
      continue
    fi

    echo "$val"
    return 0
  done
}


menu() {
  need_root
  need_cmd tc; need_cmd ip; need_cmd modprobe; need_cmd systemctl

  while true; do
    local DEV; DEV="$(detect_iface)"
    load_config
    local cfg_out="${RATE_OUT:-<belum diset>}"
    local cfg_in="${RATE_IN:-<belum diset>}"
    local cfg_r2q="${HTB_R2Q:-auto}"
    local boot="OFF"
    boot_enabled && boot="ON"

    echo
    echo "=============================="
    echo "🚦 TC Bandwidth Limiter (Menu)"
    echo "=============================="
    echo "🔌 Interface terdeteksi : ${DEV:-<tidak ada>}"
    echo "💾 Config tersimpan      : OUT=$cfg_out | IN=$cfg_in | DEV_MODE=${DEV_MODE:-auto} | HTB_R2Q=$cfg_r2q"
    echo "📏 Batas rate input      : MIN=$RATE_MIN | MAX=$RATE_MAX"
    echo "🧩 Auto-apply saat boot  : $boot"
    echo "------------------------------"
    echo "1) Set limit (manual) + APPLY sekarang"

    echo "2) APPLY dari config tersimpan"

    echo "3) STATUS (tc -s)"

    echo "4) REMOVE limit"

    echo "5) SAVE config saja (tanpa apply)"

    echo "6) Ubah batas MIN/MAX (validasi input)"

    echo "7) ENABLE auto-apply saat boot (systemd)"

    echo "8) DISABLE auto-apply saat boot"

    echo "9) Lihat isi config"

    echo "10) Keluar"

    echo "------------------------------"


    read -r -p "Pilih [1-10]: " choice
    case "${choice:-}" in
      1)
        local out in
        out="$(prompt_rate "Masukkan LIMIT OUT (Egress)")"
        in="$(prompt_rate "Masukkan LIMIT IN  (Ingress)")"
        save_config "$out" "$in" "auto" "$HTB_R2Q" "$RATE_MIN" "$RATE_MAX"
        apply_limits "$DEV" "$out" "$in"
        ;;
      2)
        if [[ -z "${RATE_OUT:-}" || -z "${RATE_IN:-}" ]]; then
          echo "❌ Config belum lengkap. Pilih menu (1) dulu."
        else
          apply_limits "$DEV" "$RATE_OUT" "$RATE_IN"
        fi
        ;;
      3)
        show_status "$DEV"
        ;;
      4)
        remove_limits "$DEV"
        ;;
      5)
        local out2 in2
        out2="$(prompt_rate "Masukkan LIMIT OUT (Egress)")"
        in2="$(prompt_rate "Masukkan LIMIT IN  (Ingress)")"
        save_config "$out2" "$in2" "auto" "$HTB_R2Q" "$RATE_MIN" "$RATE_MAX"
        ;;
      6)
        local new_min new_max
        echo "🧮 Ubah batas input (format: angka+mbit). Contoh: MIN=1mbit, MAX=10000mbit"
        new_min="$(prompt_rate_mbit_simple "Masukkan RATE_MIN")"
        while true; do
          new_max="$(prompt_rate_mbit_simple "Masukkan RATE_MAX")"
          if [[ "$(rate_to_bps "$new_min")" -le "$(rate_to_bps "$new_max")" ]]; then
            break
          fi
          echo "❌ RATE_MAX harus >= RATE_MIN."
        done

        RATE_MIN="$new_min"
        RATE_MAX="$new_max"
        save_config "${RATE_OUT:-}" "${RATE_IN:-}" "${DEV_MODE:-auto}" "$HTB_R2Q" "$RATE_MIN" "$RATE_MAX"
        ok "Batas tersimpan. Berlaku untuk input/apply berikutnya."
        ;;
      7)
        if [[ ! -f "$CONFIG_FILE" ]]; then
          echo "❌ Belum ada config. Simpan config dulu (menu 1/5)."
        else
          install_service
        fi
        ;;
      8)
        disable_service
        ;;
      9)
        if [[ -f "$CONFIG_FILE" ]]; then
          echo "----- $CONFIG_FILE -----"
          cat "$CONFIG_FILE"
          echo "------------------------"
        else
          echo "⚠️  Config belum ada."
        fi
        ;;
      10)
        ok "Bye 👋"
        exit 0
        ;;
*)
        echo "⚠️  Pilihan tidak valid."
        ;;
    esac
  done
}

# -------------------------
# CLI (non-interactive)
# -------------------------
cmd="${1:-}"
case "${cmd:-}" in
  ""|menu)
    menu
    ;;
  apply)
    need_root; need_cmd tc; need_cmd ip; need_cmd modprobe
    if [[ "${2:-}" == "--config" ]]; then
      load_config
      [[ -n "${RATE_OUT:-}" && -n "${RATE_IN:-}" ]] || die "Config belum ada/invalid: $CONFIG_FILE"
      DEV="$(detect_iface)"
      apply_limits "$DEV" "$RATE_OUT" "$RATE_IN"
    else
      RATE_OUT="${2:-}"; RATE_IN="${3:-}"; DEV="${4:-$(detect_iface)}"
      [[ -n "$RATE_OUT" && -n "$RATE_IN" ]] || die "Usage: apply <RATE_OUT> <RATE_IN> [iface]"

      load_policy

      valid_rate "$RATE_OUT" || die "RATE_OUT invalid. Wajib angka + mbit (contoh: 12.5mbit)"
      valid_rate "$RATE_IN"  || die "RATE_IN invalid. Wajib angka + mbit (contoh: 12.5mbit)"

      rate_in_bounds "$RATE_OUT" || die "RATE_OUT di luar batas: min $RATE_MIN, max $RATE_MAX"
      rate_in_bounds "$RATE_IN"  || die "RATE_IN di luar batas: min $RATE_MIN, max $RATE_MAX"

      apply_limits "$DEV" "$RATE_OUT" "$RATE_IN"
    fi
    ;;
  remove)
    need_root; need_cmd tc; need_cmd ip
    if [[ "${2:-}" == "--auto" ]]; then
      DEV="$(detect_iface)"
    else
      DEV="${2:-$(detect_iface)}"
    fi
    remove_limits "$DEV"
    ;;
  status)
    need_cmd tc; need_cmd ip
    DEV="${2:-$(detect_iface)}"
    show_status "$DEV"
    ;;
  *)
    cat <<EOF
Usage:
  sudo $0            # menu interaktif
  sudo $0 menu
  sudo $0 apply --config
  sudo $0 apply <RATE_OUT> <RATE_IN> [iface]
  sudo $0 remove [iface]
  sudo $0 status [iface]

Contoh rate: 20mbit, 1000mbit, 12.5mbit
EOF
    exit 1
    ;;
esac