# Traffic Analytics
# - Sumber data: metadata quota /opt/quota/{vless,vmess,trojan}/*.json
# - Menggunakan quota_used sebagai dasar traffic usage.
# -------------------------
traffic_analytics_dataset_build_to_file() {
  # args: output_json_file
  local out_file="$1"
  need_python3
  python3 - <<'PY' "${QUOTA_ROOT}" "${out_file}" "${QUOTA_PROTO_DIRS[@]}"
import json
import os
import sys
from datetime import datetime, timezone

quota_root = sys.argv[1]
out_file = sys.argv[2]
protos = [p.strip() for p in sys.argv[3:] if p.strip()]

def to_int(v, default=0):
  try:
    if v is None:
      return default
    if isinstance(v, bool):
      return int(v)
    if isinstance(v, (int, float)):
      return int(v)
    s = str(v).strip()
    if not s:
      return default
    return int(float(s))
  except Exception:
    return default

entries = []
proto_summary = {p: {"users": 0, "used_bytes": 0, "quota_bytes": 0} for p in protos}

for proto in protos:
  pdir = os.path.join(quota_root, proto)
  if not os.path.isdir(pdir):
    continue

  chosen = {}
  for name in os.listdir(pdir):
    if not name.endswith(".json"):
      continue
    stem = name[:-5]
    uname = stem.split("@", 1)[0] if "@" in stem else stem
    key = uname.strip()
    if not key:
      continue
    has_at = "@" in stem
    prev = chosen.get(key)
    if prev is None or (has_at and not prev["has_at"]):
      chosen[key] = {"name": name, "has_at": has_at}

  for uname in sorted(chosen.keys(), key=lambda x: x.lower()):
    name = chosen[uname]["name"]
    path = os.path.join(pdir, name)
    try:
      with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
      if not isinstance(data, dict):
        data = {}
    except Exception:
      data = {}

    username = str(data.get("username") or uname).strip() or uname
    used_bytes = to_int(data.get("quota_used"), 0)
    quota_bytes = to_int(data.get("quota_limit"), 0)
    if used_bytes < 0:
      used_bytes = 0
    if quota_bytes < 0:
      quota_bytes = 0
    expired_at = str(data.get("expired_at") or "-")

    entry = {
      "username": username,
      "proto": proto,
      "used_bytes": used_bytes,
      "quota_bytes": quota_bytes,
      "expired_at": expired_at,
      "source_file": path,
    }
    entries.append(entry)

    proto_summary[proto]["users"] += 1
    proto_summary[proto]["used_bytes"] += used_bytes
    proto_summary[proto]["quota_bytes"] += quota_bytes

entries.sort(key=lambda x: (-int(x["used_bytes"]), str(x["username"]).lower(), str(x["proto"]).lower()))

total_users = len(entries)
total_used_bytes = sum(int(e["used_bytes"]) for e in entries)
total_quota_bytes = sum(int(e["quota_bytes"]) for e in entries)

payload = {
  "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "quota_root": quota_root,
  "total_users": total_users,
  "total_used_bytes": total_used_bytes,
  "total_quota_bytes": total_quota_bytes,
  "protocols": proto_summary,
  "top_users": entries,
}

tmp = f"{out_file}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(payload, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, out_file)
print(out_file)
PY
}

traffic_analytics_dataset_make_tmp() {
  local tmp
  tmp="$(mktemp "${WORK_DIR}/traffic-analytics.XXXXXX.json")" || die "Gagal membuat file dataset analytics."
  if ! traffic_analytics_dataset_build_to_file "${tmp}" >/dev/null; then
    rm -f "${tmp}" >/dev/null 2>&1 || true
    return 1
  fi
  echo "${tmp}"
}

traffic_analytics_overview_show() {
  title
  echo "12) Traffic Analytics > Overview"
  hr

  local dataset
  if ! dataset="$(traffic_analytics_dataset_make_tmp)"; then
    warn "Gagal membangun dataset traffic analytics."
    hr
    pause
    return 0
  fi

  need_python3
  python3 - <<'PY' "${dataset}"
import json
import sys

path = sys.argv[1]
try:
  data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
  print("Dataset analytics tidak valid.")
  raise SystemExit(0)

def human_bytes(v):
  try:
    n = int(v)
  except Exception:
    n = 0
  if n >= 1024**4:
    return f"{n/(1024**4):.2f} TiB"
  if n >= 1024**3:
    return f"{n/(1024**3):.2f} GiB"
  if n >= 1024**2:
    return f"{n/(1024**2):.2f} MiB"
  if n >= 1024:
    return f"{n/1024:.2f} KiB"
  return f"{n} B"

generated = data.get("generated_at_utc") or "-"
total_users = int(data.get("total_users") or 0)
total_used = int(data.get("total_used_bytes") or 0)
total_quota = int(data.get("total_quota_bytes") or 0)
avg_used = int(total_used / total_users) if total_users > 0 else 0

print(f"Generated UTC : {generated}")
print(f"Total Users   : {total_users}")
print(f"Total Used    : {human_bytes(total_used)}")
print(f"Total Quota   : {human_bytes(total_quota)}")
print(f"Avg/User Used : {human_bytes(avg_used)}")
print()
print("By Protocol:")

protocols = data.get("protocols") or {}
for proto in ("vless", "vmess", "trojan"):
  info = protocols.get(proto) or {}
  users = int(info.get("users") or 0)
  used = int(info.get("used_bytes") or 0)
  quota = int(info.get("quota_bytes") or 0)
  print(f"  {proto.upper():<6} users={users:<4} used={human_bytes(used):<12} quota={human_bytes(quota)}")

print()
print("Top 5 Users:")
top = (data.get("top_users") or [])[:5]
if not top:
  print("  (kosong)")
else:
  for i, row in enumerate(top, start=1):
    user = str(row.get("username") or "-")
    proto = str(row.get("proto") or "-").upper()
    used = human_bytes(row.get("used_bytes") or 0)
    print(f"  {i:>2}. {user:<20} {proto:<6} {used}")
PY

  rm -f "${dataset}" >/dev/null 2>&1 || true
  hr
  pause
}

traffic_analytics_top_users_show() {
  title
  echo "12) Traffic Analytics > Top Users by Usage"
  hr

  local n
  read -r -p "Tampilkan top berapa user? (default 15, max 200, atau kembali): " n
  if is_back_choice "${n}"; then
    return 0
  fi
  if [[ -z "${n}" ]]; then
    n=15
  fi
  [[ "${n}" =~ ^[0-9]+$ ]] || { warn "Input harus angka."; hr; pause; return 0; }
  if (( n < 1 )); then n=1; fi
  if (( n > 200 )); then n=200; fi

  local dataset
  if ! dataset="$(traffic_analytics_dataset_make_tmp)"; then
    warn "Gagal membangun dataset traffic analytics."
    hr
    pause
    return 0
  fi

  need_python3
  python3 - <<'PY' "${dataset}" "${n}"
import json
import sys

path, top_n = sys.argv[1], int(sys.argv[2])
try:
  data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
  print("Dataset analytics tidak valid.")
  raise SystemExit(0)

def human_bytes(v):
  try:
    n = int(v)
  except Exception:
    n = 0
  if n >= 1024**4:
    return f"{n/(1024**4):.2f} TiB"
  if n >= 1024**3:
    return f"{n/(1024**3):.2f} GiB"
  if n >= 1024**2:
    return f"{n/(1024**2):.2f} MiB"
  if n >= 1024:
    return f"{n/1024:.2f} KiB"
  return f"{n} B"

rows = (data.get("top_users") or [])[:top_n]
if not rows:
  print("Belum ada data traffic user.")
  raise SystemExit(0)

print(f"{'NO':<4} {'PROTO':<8} {'USERNAME':<20} {'USED':<12} {'QUOTA':<12} {'USE%':>6} {'EXPIRED':<10}")
print(f"{'-'*4:<4} {'-'*8:<8} {'-'*20:<20} {'-'*12:<12} {'-'*12:<12} {'-'*6:>6} {'-'*10:<10}")
for i, row in enumerate(rows, start=1):
  proto = str(row.get("proto") or "-").upper()
  user = str(row.get("username") or "-")
  used = int(row.get("used_bytes") or 0)
  quota = int(row.get("quota_bytes") or 0)
  exp = str(row.get("expired_at") or "-")[:10]
  if quota > 0:
    pct = f"{(used * 100.0 / quota):.1f}"
  else:
    pct = "-"
  print(f"{i:<4} {proto:<8} {user[:20]:<20} {human_bytes(used):<12} {human_bytes(quota):<12} {pct:>6} {exp:<10}")
PY

  rm -f "${dataset}" >/dev/null 2>&1 || true
  hr
  pause
}

traffic_analytics_search_user_show() {
  title
  echo "12) Traffic Analytics > Search User Traffic"
  hr

  local q
  read -r -p "Cari username/proto (atau kembali): " q
  if is_back_choice "${q}"; then
    return 0
  fi
  q="$(echo "${q}" | awk '{$1=$1;print}')"
  [[ -n "${q}" ]] || { warn "Keyword kosong."; hr; pause; return 0; }

  local dataset
  if ! dataset="$(traffic_analytics_dataset_make_tmp)"; then
    warn "Gagal membangun dataset traffic analytics."
    hr
    pause
    return 0
  fi

  need_python3
  python3 - <<'PY' "${dataset}" "${q}"
import json
import sys

path, query = sys.argv[1], sys.argv[2].strip().lower()
try:
  data = json.load(open(path, "r", encoding="utf-8"))
except Exception:
  print("Dataset analytics tidak valid.")
  raise SystemExit(0)

def human_bytes(v):
  try:
    n = int(v)
  except Exception:
    n = 0
  if n >= 1024**4:
    return f"{n/(1024**4):.2f} TiB"
  if n >= 1024**3:
    return f"{n/(1024**3):.2f} GiB"
  if n >= 1024**2:
    return f"{n/(1024**2):.2f} MiB"
  if n >= 1024:
    return f"{n/1024:.2f} KiB"
  return f"{n} B"

rows = []
for row in (data.get("top_users") or []):
  username = str(row.get("username") or "")
  proto = str(row.get("proto") or "")
  token = f"{username}@{proto}".lower()
  if query in token:
    rows.append(row)

if not rows:
  print("Tidak ada user yang cocok dengan keyword.")
  raise SystemExit(0)

print(f"Ditemukan {len(rows)} user.")
print(f"{'NO':<4} {'PROTO':<8} {'USERNAME':<20} {'USED':<12} {'QUOTA':<12} {'USE%':>6} {'EXPIRED':<10}")
print(f"{'-'*4:<4} {'-'*8:<8} {'-'*20:<20} {'-'*12:<12} {'-'*12:<12} {'-'*6:>6} {'-'*10:<10}")
for i, row in enumerate(rows[:200], start=1):
  proto = str(row.get("proto") or "-").upper()
  user = str(row.get("username") or "-")
  used = int(row.get("used_bytes") or 0)
  quota = int(row.get("quota_bytes") or 0)
  exp = str(row.get("expired_at") or "-")[:10]
  if quota > 0:
    pct = f"{(used * 100.0 / quota):.1f}"
  else:
    pct = "-"
  print(f"{i:<4} {proto:<8} {user[:20]:<20} {human_bytes(used):<12} {human_bytes(quota):<12} {pct:>6} {exp:<10}")
PY

  rm -f "${dataset}" >/dev/null 2>&1 || true
  hr
  pause
}

traffic_analytics_export_json() {
  title
  echo "12) Traffic Analytics > Export JSON Report"
  hr

  local dataset out
  if ! dataset="$(traffic_analytics_dataset_make_tmp)"; then
    warn "Gagal membangun dataset traffic analytics."
    hr
    pause
    return 0
  fi

  out="${REPORT_DIR}/traffic-analytics-$(date +%Y%m%d-%H%M%S).json"
  if cp -f "${dataset}" "${out}"; then
    chmod 600 "${out}" >/dev/null 2>&1 || true
    log "Report tersimpan: ${out}"
  else
    warn "Gagal menyimpan report ke: ${out}"
  fi

  rm -f "${dataset}" >/dev/null 2>&1 || true
  hr
  pause
}

traffic_analytics_menu() {
  while true; do
    title
    echo "12) Traffic Analytics"
    hr
    echo "  1) Overview"
    echo "  2) Top Users by Usage"
    echo "  3) Search User Traffic"
    echo "  4) Export JSON Report"
    echo "  0) Kembali"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) traffic_analytics_overview_show ;;
      2) traffic_analytics_top_users_show ;;
      3) traffic_analytics_search_user_show ;;
      4) traffic_analytics_export_json ;;
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
    svc_status_line chrony
    hr
    systemctl status chrony --no-pager || true
  elif svc_exists chronyd; then
    svc_status_line chronyd
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
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
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
  echo "Info log    : disembunyikan agar tampilan ringkas"
  echo
  echo "  1) Lihat log wireproxy (20 baris)"
  echo "  0) Back"
  hr
  if ! read -r -p "Pilih: " c; then
    echo
    return 0
  fi
  case "${c}" in
    1) daemon_log_tail_show wireproxy 20 ;;
    0|kembali|k|back|b) : ;;
    *) warn "Pilihan tidak valid" ; sleep 1 ;;
  esac
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

daemon_log_tail_show() {
  # args: service_name [lines]
  local svc="$1"
  local lines="${2:-20}"
  title
  echo "8) Maintenance > Log ${svc}"
  hr
  if svc_exists "${svc}"; then
    journalctl -u "${svc}" --no-pager -n "${lines}" 2>/dev/null || true
  else
    warn "${svc}.service tidak terpasang"
  fi
  hr
  pause
}

install_discord_bot_menu() {
  local installer_cmd="/usr/local/bin/install-discord-bot"
  title
  echo "9) Install BOT Discord"
  hr

  if [[ ! -x "${installer_cmd}" ]]; then
    warn "Installer bot Discord tidak ditemukan / tidak executable:"
    echo "  ${installer_cmd}"
    echo
    echo "Hint: jalankan ulang run.sh agar installer ikut dipasang."
    hr
    pause
    return 0
  fi

  echo "Menjalankan installer:"
  echo "  ${installer_cmd} menu"
  hr
  if ! "${installer_cmd}" menu; then
    warn "Installer bot Discord keluar dengan status error."
    hr
    pause
  fi
  return 0
}

daemon_status_menu() {
  title
  echo "8) Maintenance > Daemon Status"
  hr

  local daemons=("xray" "nginx" "xray-expired" "xray-quota" "xray-limit-ip" "xray-speed" "wireproxy")
  local d
  for d in "${daemons[@]}"; do
    if svc_exists "${d}"; then
      svc_status_line "${d}"
    else
      echo "N/A  - ${d} (not installed)"
    fi
  done
  hr

  echo "Info: log daemon disembunyikan agar tampilan ringkas."
  hr

  echo "  1) Restart xray-expired"
  echo "  2) Restart xray-quota"
  echo "  3) Restart xray-limit-ip"
  echo "  4) Restart xray-speed"
  echo "  5) Restart semua daemon (xray-expired + xray-quota + xray-limit-ip + xray-speed)"
  echo "  6) Lihat log xray-expired (20 baris)"
  echo "  7) Lihat log xray-quota (20 baris)"
  echo "  8) Lihat log xray-limit-ip (20 baris)"
  echo "  9) Lihat log xray-speed (20 baris)"
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
    6) daemon_log_tail_show xray-expired 20 ;;
    7) daemon_log_tail_show xray-quota 20 ;;
    8) daemon_log_tail_show xray-limit-ip 20 ;;
    9) daemon_log_tail_show xray-speed 20 ;;
    0|kembali|k|back|b) return 0 ;;
    *) warn "Pilihan tidak valid" ; sleep 1 ;;
  esac
}

# -------------------------
