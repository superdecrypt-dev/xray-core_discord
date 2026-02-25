# shellcheck shell=bash
# Maintenance
# -------------------------
maintenance_menu() {
  while true; do
    title
    echo "9) Maintenance"
    hr
    echo "  1. Restart xray"
    echo "  2. Restart nginx"
    echo "  3. Restart all (xray+nginx)"
    echo "  4. View xray logs (tail)"
    echo "  5. View nginx logs (tail)"
    echo "  6. Wireproxy (WARP) Status (ringkas)"
    echo "  7. Restart wireproxy (WARP)"
    echo "  8. Daemon Status & Restart (xray-expired / xray-quota / xray-limit-ip / xray-speed)"
    echo "  0. Kembali"
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
