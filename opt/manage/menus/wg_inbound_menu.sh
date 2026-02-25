# shellcheck shell=bash

WG_INBOUND_ROOT="${WG_INBOUND_ROOT:-/opt/wg-inbound}"
WG_INBOUND_META="${WG_INBOUND_META:-${WG_INBOUND_ROOT}/peers.json}"
WG_INBOUND_CLIENT_DIR="${WG_INBOUND_CLIENT_DIR:-${WG_INBOUND_ROOT}/clients}"
WG_INBOUND_CONF="${WG_INBOUND_CONF:-${XRAY_CONFDIR}/11-wireguard-inbound.json}"
WG_INBOUND_DEFAULT_ADDR="${WG_INBOUND_DEFAULT_ADDR:-10.66.66.1/24}"
WG_INBOUND_DEFAULT_PORT="${WG_INBOUND_DEFAULT_PORT:-443}"
WG_INBOUND_DEFAULT_MTU="${WG_INBOUND_DEFAULT_MTU:-1420}"
WG_INBOUND_DEFAULT_KEEPALIVE="${WG_INBOUND_DEFAULT_KEEPALIVE:-25}"
WG_INBOUND_DEFAULT_DNS="${WG_INBOUND_DEFAULT_DNS:-1.1.1.1,8.8.8.8}"
WG_INBOUND_TAG="${WG_INBOUND_TAG:-wg-inbound}"


wg_inbound_trim() {
  local raw="${1:-}"
  printf '%s' "${raw}" | awk '{$1=$1;print}'
}


wg_inbound_validate_username() {
  local username="${1:-}"
  [[ "${username}" =~ ^[A-Za-z0-9._-]{3,32}$ ]]
}


wg_inbound_endpoint_host_detect() {
  local host
  host="$(detect_domain)"
  host="$(echo "${host}" | awk '{print $1}' | tr -d ';')"
  if [[ -z "${host}" || "${host}" == "-" ]]; then
    host="$(detect_public_ip)"
  fi
  [[ -n "${host}" ]] || host="127.0.0.1"
  echo "${host}"
}


wg_inbound_try_install_wg_tools() {
  # Best-effort bootstrap untuk host yang belum punya wireguard-tools.
  if have_cmd wg; then
    return 0
  fi
  if ! have_cmd apt-get; then
    return 1
  fi

  warn "Command 'wg' tidak ditemukan. Mencoba install wireguard-tools..."

  local rc=0
  set +e
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Use-Pty=0 wireguard-tools >/dev/null 2>&1
  rc=$?
  set -e

  if (( rc != 0 )); then
    set +e
    DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Use-Pty=0 wireguard-tools >/dev/null 2>&1
    rc=$?
    set -e
  fi

  if (( rc == 0 )) && have_cmd wg; then
    log "wireguard-tools berhasil dipasang."
    return 0
  fi

  warn "Install wireguard-tools gagal. Lanjut fallback ke 'xray x25519'."
  return 1
}


wg_inbound_generate_keypair() {
  local priv pub out
  if ! have_cmd wg; then
    wg_inbound_try_install_wg_tools || true
  fi

  if have_cmd wg; then
    priv="$(wg genkey 2>/dev/null || true)"
    if [[ -n "${priv}" ]]; then
      pub="$(printf '%s' "${priv}" | wg pubkey 2>/dev/null || true)"
      if [[ -n "${pub}" ]]; then
        printf '%s|%s\n' "${priv}" "${pub}"
        return 0
      fi
    fi
  fi

  if have_cmd xray; then
    # Sebagian build xray menulis output ke stderr; gabungkan stdout+stderr.
    out="$(xray x25519 2>&1 || true)"
    priv="$(printf '%s\n' "${out}" | sed -nE 's/^[Pp]rivate([[:space:]]+[Kk]ey)?[[:space:]]*:[[:space:]]*([A-Za-z0-9+\/=]+).*$/\2/p' | head -n1)"
    pub="$(printf '%s\n' "${out}" | sed -nE 's/^[Pp]ublic([[:space:]]+[Kk]ey)?[[:space:]]*:[[:space:]]*([A-Za-z0-9+\/=]+).*$/\2/p' | head -n1)"
    if [[ -n "${priv}" && -n "${pub}" ]]; then
      printf '%s|%s\n' "${priv}" "${pub}"
      return 0
    fi
  fi

  return 1
}


wg_inbound_generate_psk() {
  local psk
  if have_cmd wg; then
    psk="$(wg genpsk 2>/dev/null || true)"
    if [[ -n "${psk}" ]]; then
      printf '%s\n' "${psk}"
      return 0
    fi
  fi
  if have_cmd openssl; then
    psk="$(openssl rand -base64 32 2>/dev/null | tr -d '\n' || true)"
    if [[ -n "${psk}" ]]; then
      printf '%s\n' "${psk}"
      return 0
    fi
  fi
  return 1
}


wg_inbound_ensure_layout() {
  mkdir -p "${WG_INBOUND_ROOT}" "${WG_INBOUND_CLIENT_DIR}"
  chmod 700 "${WG_INBOUND_ROOT}" "${WG_INBOUND_CLIENT_DIR}" 2>/dev/null || true
}


wg_inbound_ensure_conf_seed() {
  local d
  d="$(dirname "${WG_INBOUND_CONF}")"
  mkdir -p "${d}"
  if [[ ! -f "${WG_INBOUND_CONF}" ]]; then
    cat > "${WG_INBOUND_CONF}" <<'EOF'
{
  "inbounds": []
}
EOF
    chmod 640 "${WG_INBOUND_CONF}" 2>/dev/null || true
    if getent group xray >/dev/null 2>&1; then
      chown root:xray "${WG_INBOUND_CONF}" 2>/dev/null || true
    fi
  fi
}


wg_inbound_meta_init_if_missing() {
  local keypair server_priv server_pub
  wg_inbound_ensure_layout
  need_python3
  if [[ -f "${WG_INBOUND_META}" ]]; then
    return 0
  fi

  keypair="$(wg_inbound_generate_keypair)" || {
    warn "Gagal generate keypair WireGuard. Install manual: apt-get install -y wireguard-tools"
    warn "Atau pastikan subcommand 'xray x25519' tersedia."
    return 1
  }
  server_priv="${keypair%%|*}"
  server_pub="${keypair#*|}"

  python3 - <<'PY' \
    "${WG_INBOUND_META}" \
    "${server_priv}" \
    "${server_pub}" \
    "${WG_INBOUND_DEFAULT_ADDR}" \
    "${WG_INBOUND_DEFAULT_PORT}" \
    "${WG_INBOUND_DEFAULT_MTU}" \
    "${WG_INBOUND_DEFAULT_KEEPALIVE}" \
    "${WG_INBOUND_DEFAULT_DNS}" \
    "${WG_INBOUND_TAG}"
import json
import os
import sys
from datetime import datetime, timezone

(
  path,
  server_priv,
  server_pub,
  address,
  port_raw,
  mtu_raw,
  keepalive_raw,
  dns,
  tag,
) = sys.argv[1:10]

try:
  port = int(port_raw)
except Exception:
  port = 443
if port < 1 or port > 65535:
  port = 443

try:
  mtu = int(mtu_raw)
except Exception:
  mtu = 1420
if mtu < 1200 or mtu > 9000:
  mtu = 1420

try:
  keepalive = int(keepalive_raw)
except Exception:
  keepalive = 25
if keepalive < 0 or keepalive > 600:
  keepalive = 25

meta = {
  "version": 1,
  "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
  "server": {
    "private_key": str(server_priv),
    "public_key": str(server_pub),
    "address": str(address),
    "port": int(port),
    "mtu": int(mtu),
    "keepalive_sec": int(keepalive),
    "dns": str(dns),
    "tag": str(tag or "wg-inbound"),
    "listen": "0.0.0.0",
  },
  "peers": [],
}

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_bootstrap() {
  wg_inbound_meta_init_if_missing || return 1
  wg_inbound_ensure_conf_seed || return 1
  return 0
}


wg_inbound_meta_peer_exists() {
  local username="${1:-}"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}"
import json
import sys

path, username = sys.argv[1:3]
try:
  meta = json.load(open(path, "r", encoding="utf-8"))
except Exception:
  raise SystemExit(2)

for peer in (meta.get("peers") or []):
  if str(peer.get("username") or "") == username:
    raise SystemExit(0)
raise SystemExit(1)
PY
}


wg_inbound_meta_next_ip() {
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}"
import ipaddress
import json
import sys

path = sys.argv[1]
meta = json.load(open(path, "r", encoding="utf-8"))
server = meta.get("server") or {}
address = str(server.get("address") or "").strip()
if not address:
  raise SystemExit(2)

iface = ipaddress.ip_interface(address)
net = iface.network
server_ip = iface.ip
used = {server_ip}

for peer in (meta.get("peers") or []):
  raw = str(peer.get("allowed_ip") or "").strip()
  if not raw:
    continue
  try:
    used.add(ipaddress.ip_interface(raw).ip)
  except Exception:
    continue

for host in net.hosts():
  if host in used:
    continue
  print(f"{host}/32")
  raise SystemExit(0)

raise SystemExit(3)
PY
}


wg_inbound_meta_add_peer() {
  # args: username allowed_ip client_priv client_pub psk
  local username="$1"
  local allowed_ip="$2"
  local client_priv="$3"
  local client_pub="$4"
  local psk="$5"
  need_python3
  python3 - <<'PY' \
    "${WG_INBOUND_META}" \
    "${username}" \
    "${allowed_ip}" \
    "${client_priv}" \
    "${client_pub}" \
    "${psk}"
import json
import os
import sys
from datetime import datetime, timezone

path, username, allowed_ip, client_priv, client_pub, psk = sys.argv[1:7]
meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers")
if not isinstance(peers, list):
  peers = []
  meta["peers"] = peers

for p in peers:
  if str(p.get("username") or "") == username:
    raise SystemExit(10)
  if str(p.get("allowed_ip") or "") == allowed_ip:
    raise SystemExit(11)
  if str(p.get("client_public_key") or "") == client_pub:
    raise SystemExit(12)

peers.append(
  {
    "username": username,
    "allowed_ip": allowed_ip,
    "client_private_key": client_priv,
    "client_public_key": client_pub,
    "preshared_key": psk,
    "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "quota_bytes": 0,
    "quota_used_bytes": 0,
    "ip_lock_enabled": False,
    "speed_enabled": False,
    "speed_down_mbit": 0.0,
    "speed_up_mbit": 0.0,
  }
)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_meta_delete_peer() {
  local username="$1"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}"
import json
import os
import sys

path, username = sys.argv[1:3]
meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers")
if not isinstance(peers, list):
  raise SystemExit(2)

new_peers = [p for p in peers if str(p.get("username") or "") != username]
if len(new_peers) == len(peers):
  raise SystemExit(3)
meta["peers"] = new_peers

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_meta_set_quota_bytes() {
  local username="$1"
  local quota_bytes="$2"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}" "${quota_bytes}"
import json
import os
import sys

path, username, quota_raw = sys.argv[1:4]
try:
  quota = int(quota_raw)
except Exception:
  quota = 0
if quota < 0:
  quota = 0

meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers") or []
found = False
for p in peers:
  if str(p.get("username") or "") == username:
    p["quota_bytes"] = quota
    used = int(p.get("quota_used_bytes") or 0)
    if used > quota and quota > 0:
      p["quota_used_bytes"] = quota
    found = True
    break
if not found:
  raise SystemExit(3)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_meta_reset_quota_used() {
  local username="$1"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}"
import json
import os
import sys

path, username = sys.argv[1:3]
meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers") or []
found = False
for p in peers:
  if str(p.get("username") or "") == username:
    p["quota_used_bytes"] = 0
    found = True
    break
if not found:
  raise SystemExit(3)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_meta_toggle_ip_lock() {
  local username="$1"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}"
import json
import os
import sys

path, username = sys.argv[1:3]
meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers") or []
state = None
for p in peers:
  if str(p.get("username") or "") == username:
    now = bool(p.get("ip_lock_enabled"))
    p["ip_lock_enabled"] = (not now)
    state = p["ip_lock_enabled"]
    break
if state is None:
  raise SystemExit(3)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
print("ON" if state else "OFF")
PY
}


wg_inbound_meta_set_speed_limit() {
  local username="$1"
  local down="$2"
  local up="$3"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}" "${down}" "${up}"
import json
import os
import sys

path, username, down_raw, up_raw = sys.argv[1:5]
try:
  down = float(down_raw)
except Exception:
  down = 0.0
try:
  up = float(up_raw)
except Exception:
  up = 0.0
if down <= 0 or up <= 0:
  raise SystemExit(4)

meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers") or []
found = False
for p in peers:
  if str(p.get("username") or "") == username:
    p["speed_down_mbit"] = down
    p["speed_up_mbit"] = up
    p["speed_enabled"] = True
    found = True
    break
if not found:
  raise SystemExit(3)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY
}


wg_inbound_meta_toggle_speed_limit() {
  local username="$1"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${username}"
import json
import os
import sys

path, username = sys.argv[1:3]
meta = json.load(open(path, "r", encoding="utf-8"))
peers = meta.get("peers") or []
state = None
for p in peers:
  if str(p.get("username") or "") == username:
    now = bool(p.get("speed_enabled"))
    p["speed_enabled"] = (not now)
    state = p["speed_enabled"]
    break
if state is None:
  raise SystemExit(3)

tmp = f"{path}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  json.dump(meta, f, ensure_ascii=False, indent=2)
  f.write("\n")
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, path)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
print("ON" if state else "OFF")
PY
}


wg_inbound_meta_print_summary() {
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}"
import json
import sys

path = sys.argv[1]
meta = json.load(open(path, "r", encoding="utf-8"))
server = meta.get("server") or {}
peers = meta.get("peers") or []

print(f"TAG={server.get('tag') or 'wg-inbound'}")
print(f"LISTEN={server.get('listen') or '0.0.0.0'}")
print(f"PORT={int(server.get('port') or 443)}")
print(f"ADDRESS={server.get('address') or '-'}")
print(f"MTU={int(server.get('mtu') or 1420)}")
print(f"DNS={server.get('dns') or '-'}")
print(f"KEEPALIVE={int(server.get('keepalive_sec') or 25)}")
print(f"PEERS={len(peers)}")
print(f"SERVER_PUB={server.get('public_key') or '-'}")
PY
}


wg_inbound_meta_print_table() {
  local query="${1:-}"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${query}"
import json
import sys

path, query = sys.argv[1:3]
query = (query or "").strip().lower()
meta = json.load(open(path, "r", encoding="utf-8"))
rows = []
for p in (meta.get("peers") or []):
  username = str(p.get("username") or "")
  allowed_ip = str(p.get("allowed_ip") or "")
  token = f"{username} {allowed_ip}".lower()
  if query and query not in token:
    continue
  rows.append({
    "username": username,
    "allowed_ip": allowed_ip,
    "created_at_utc": str(p.get("created_at_utc") or "-"),
    "quota_bytes": int(p.get("quota_bytes") or 0),
    "quota_used_bytes": int(p.get("quota_used_bytes") or 0),
    "ip_lock_enabled": bool(p.get("ip_lock_enabled")),
    "speed_enabled": bool(p.get("speed_enabled")),
    "speed_down_mbit": float(p.get("speed_down_mbit") or 0.0),
    "speed_up_mbit": float(p.get("speed_up_mbit") or 0.0),
  })

rows.sort(key=lambda x: x["username"].lower())

def fmt_gb(v):
  if v <= 0:
    return "0"
  g = v / (1024**3)
  if abs(g - round(g)) < 1e-9:
    return str(int(round(g)))
  return f"{g:.2f}".rstrip("0").rstrip(".")

if not rows:
  print("(belum ada peer)")
  raise SystemExit(0)

print(f"{'NO':<4} {'USERNAME':<20} {'IP':<18} {'QUOTA(GB)':<10} {'USED(GB)':<9} {'IPLOCK':<7} {'SPEED':<5} {'CREATED':<19}")
print(f"{'-'*4:<4} {'-'*20:<20} {'-'*18:<18} {'-'*10:<10} {'-'*9:<9} {'-'*7:<7} {'-'*5:<5} {'-'*19:<19}")
for i, row in enumerate(rows, start=1):
  speed = "ON" if row["speed_enabled"] else "OFF"
  iplock = "ON" if row["ip_lock_enabled"] else "OFF"
  created = row["created_at_utc"].replace("T", " ").replace("Z", "")[:19]
  print(
    f"{i:<4} {row['username'][:20]:<20} {row['allowed_ip'][:18]:<18} "
    f"{fmt_gb(row['quota_bytes']):<10} {fmt_gb(row['quota_used_bytes']):<9} "
    f"{iplock:<7} {speed:<5} {created:<19}"
  )
PY
}


wg_inbound_write_client_config() {
  # args: username endpoint_host
  local username="$1"
  local endpoint_host="$2"
  need_python3
  python3 - <<'PY' \
    "${WG_INBOUND_META}" \
    "${WG_INBOUND_CLIENT_DIR}" \
    "${username}" \
    "${endpoint_host}"
import json
import os
import sys

meta_path, out_dir, username, endpoint_host = sys.argv[1:5]
meta = json.load(open(meta_path, "r", encoding="utf-8"))
server = meta.get("server") or {}
port = int(server.get("port") or 443)
mtu = int(server.get("mtu") or 1420)
keepalive = int(server.get("keepalive_sec") or 25)
dns = str(server.get("dns") or "1.1.1.1,8.8.8.8").strip()
server_pub = str(server.get("public_key") or "").strip()
if not server_pub:
  raise SystemExit(2)

target = None
for p in (meta.get("peers") or []):
  if str(p.get("username") or "") == username:
    target = p
    break
if target is None:
  raise SystemExit(3)

client_priv = str(target.get("client_private_key") or "").strip()
allowed_ip = str(target.get("allowed_ip") or "").strip()
psk = str(target.get("preshared_key") or "").strip()
if not client_priv or not allowed_ip:
  raise SystemExit(4)

lines = []
lines.append(f"# WireGuard client config for {username}")
lines.append("[Interface]")
lines.append(f"PrivateKey = {client_priv}")
lines.append(f"Address = {allowed_ip}")
if dns:
  lines.append(f"DNS = {dns}")
if mtu > 0:
  lines.append(f"MTU = {mtu}")
lines.append("")
lines.append("[Peer]")
lines.append(f"PublicKey = {server_pub}")
if psk:
  lines.append(f"PresharedKey = {psk}")
lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
lines.append(f"Endpoint = {endpoint_host}:{port}")
if keepalive > 0:
  lines.append(f"PersistentKeepalive = {keepalive}")
lines.append("")

os.makedirs(out_dir, exist_ok=True)
out_file = os.path.join(out_dir, f"{username}.conf")
tmp = f"{out_file}.tmp.{os.getpid()}"
with open(tmp, "w", encoding="utf-8") as f:
  f.write("\n".join(lines))
  f.flush()
  os.fsync(f.fileno())
os.replace(tmp, out_file)
try:
  os.chmod(out_file, 0o600)
except Exception:
  pass
print(out_file)
PY
}


wg_inbound_build_config_tmp() {
  # args: out_path
  local out_path="$1"
  need_python3
  python3 - <<'PY' "${WG_INBOUND_META}" "${out_path}"
import ipaddress
import json
import os
import sys

meta_path, out_path = sys.argv[1:3]
meta = json.load(open(meta_path, "r", encoding="utf-8"))
server = meta.get("server") or {}
peers_src = meta.get("peers") or []

server_priv = str(server.get("private_key") or "").strip()
server_addr_raw = str(server.get("address") or "").strip()
if not server_priv or not server_addr_raw:
  raise SystemExit(2)
try:
  # Metadata bisa menyimpan /24 untuk perhitungan pool IP peer, tapi Xray
  # wireguard inbound butuh alamat interface host (/32 IPv4 atau /128 IPv6).
  iface = ipaddress.ip_interface(server_addr_raw)
except Exception:
  raise SystemExit(2)
if iface.version == 4:
  server_addr = f"{iface.ip}/32"
else:
  server_addr = f"{iface.ip}/128"

port = int(server.get("port") or 443)
if port < 1 or port > 65535:
  port = 443
mtu = int(server.get("mtu") or 1420)
if mtu < 1200 or mtu > 9000:
  mtu = 1420

tag = str(server.get("tag") or "wg-inbound").strip() or "wg-inbound"
listen = str(server.get("listen") or "0.0.0.0").strip() or "0.0.0.0"

peers = []
for p in peers_src:
  pub = str(p.get("client_public_key") or "").strip()
  allowed = str(p.get("allowed_ip") or "").strip()
  psk = str(p.get("preshared_key") or "").strip()
  if not pub or not allowed:
    continue
  item = {
    "publicKey": pub,
    "allowedIPs": [allowed],
  }
  if psk:
    item["preSharedKey"] = psk
  peers.append(item)

cfg = {
  "inbounds": [
    {
      "listen": listen,
      "port": port,
      "protocol": "wireguard",
      "tag": tag,
      "settings": {
        "secretKey": server_priv,
        "address": [server_addr],
        "mtu": mtu,
        "peers": peers,
      },
      "sniffing": {
        "enabled": False,
      },
    }
  ]
}

with open(out_path, "w", encoding="utf-8") as f:
  json.dump(cfg, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY
}


wg_inbound_conf_write_atomic() {
  # args: src_tmp dst
  local src_tmp="$1"
  local dst="$2"
  local dir base target mode uid gid xray_gid
  dir="$(dirname "${dst}")"
  base="$(basename "${dst}")"
  target="${dir}/.${base}.new.$$"

  mkdir -p "${dir}" 2>/dev/null || return 1
  # WG inbound config wajib readable oleh service user/group xray.
  mode='640'
  uid='0'
  gid='0'
  if getent group xray >/dev/null 2>&1; then
    xray_gid="$(getent group xray | awk -F: '{print $3; exit}')"
    if [[ -n "${xray_gid}" ]]; then
      gid="${xray_gid}"
    fi
  fi

  cp -f "${src_tmp}" "${target}" || return 1
  chmod "${mode}" "${target}" 2>/dev/null || chmod 600 "${target}" || true
  chown "${uid}:${gid}" "${target}" 2>/dev/null || chown 0:0 "${target}" || true
  mv -f "${target}" "${dst}" || {
    rm -f "${target}" 2>/dev/null || true
    return 1
  }
  return 0
}


wg_inbound_apply_runtime_from_meta() {
  local tmp_cfg tmp_log
  tmp_cfg="$(mktemp "/tmp/wg-inbound-conf.XXXXXX.json")" || return 1
  tmp_log="$(mktemp "/tmp/wg-inbound-test.XXXXXX.log")" || {
    rm -f "${tmp_cfg}" >/dev/null 2>&1 || true
    return 1
  }

  if ! wg_inbound_build_config_tmp "${tmp_cfg}"; then
    rm -f "${tmp_cfg}" "${tmp_log}" >/dev/null 2>&1 || true
    return 1
  fi
  if ! wg_inbound_conf_write_atomic "${tmp_cfg}" "${WG_INBOUND_CONF}"; then
    rm -f "${tmp_cfg}" "${tmp_log}" >/dev/null 2>&1 || true
    return 1
  fi

  if ! xray run -test -confdir "${XRAY_CONFDIR}" >"${tmp_log}" 2>&1; then
    tail -n 80 "${tmp_log}" 2>/dev/null || true
    rm -f "${tmp_cfg}" "${tmp_log}" >/dev/null 2>&1 || true
    return 1
  fi

  svc_restart xray || true
  if ! svc_wait_active xray 20; then
    rm -f "${tmp_cfg}" "${tmp_log}" >/dev/null 2>&1 || true
    return 1
  fi

  rm -f "${tmp_cfg}" "${tmp_log}" >/dev/null 2>&1 || true
  return 0
}


wg_inbound_prompt_username() {
  local prompt="${1:-Username peer (atau kembali): }"
  local username
  read -r -p "${prompt}" username
  if is_back_choice "${username}"; then
    return 1
  fi
  username="$(wg_inbound_trim "${username}")"
  if [[ -z "${username}" ]]; then
    warn "Username tidak boleh kosong."
    return 1
  fi
  if ! wg_inbound_validate_username "${username}"; then
    warn "Username tidak valid. Gunakan 3-32 karakter [a-zA-Z0-9._-]."
    return 1
  fi
  printf '%s\n' "${username}"
  return 0
}


wg_inbound_status_show() {
  title
  echo "3) WG Inbound Management > WG Status"
  hr

  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi

  local summary_lines key value service_state
  summary_lines="$(wg_inbound_meta_print_summary 2>/dev/null || true)"
  if [[ -z "${summary_lines}" ]]; then
    warn "Metadata WG inbound tidak bisa dibaca."
    hr
    pause
    return 0
  fi

  while IFS='=' read -r key value; do
    case "${key}" in
      TAG) printf "%-16s: %s\n" "Inbound Tag" "${value}" ;;
      LISTEN) printf "%-16s: %s\n" "Listen" "${value}" ;;
      PORT) printf "%-16s: %s\n" "UDP Port" "${value}" ;;
      ADDRESS) printf "%-16s: %s\n" "Server Address" "${value}" ;;
      MTU) printf "%-16s: %s\n" "MTU" "${value}" ;;
      DNS) printf "%-16s: %s\n" "Client DNS" "${value}" ;;
      KEEPALIVE) printf "%-16s: %s\n" "Keepalive" "${value}" ;;
      PEERS) printf "%-16s: %s\n" "Total Peers" "${value}" ;;
      SERVER_PUB) printf "%-16s: %s\n" "Server PubKey" "${value}" ;;
    esac
  done <<< "${summary_lines}"

  service_state="$(svc_state xray)"
  printf "%-16s: %s\n" "xray service" "${service_state:-unknown}"
  printf "%-16s: %s\n" "Config File" "${WG_INBOUND_CONF}"
  printf "%-16s: %s\n" "Metadata File" "${WG_INBOUND_META}"
  printf "%-16s: %s\n" "Client Config Dir" "${WG_INBOUND_CLIENT_DIR}"
  hr
  echo "Catatan: enforcement quota/ip-lock/speed masih metadata-only (belum aktif runtime)."
  hr
  pause
}


wg_inbound_list_peers() {
  title
  echo "3) WG Inbound Management > List/Search Peer"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi

  local q
  read -r -p "Keyword username/IP (kosongkan untuk semua, atau kembali): " q
  if is_back_choice "${q}"; then
    return 0
  fi
  q="$(wg_inbound_trim "${q}")"

  if ! wg_inbound_meta_print_table "${q}"; then
    warn "Gagal membaca daftar peer."
  fi
  hr
  pause
}


wg_inbound_add_peer() {
  title
  echo "3) WG Inbound Management > Add Peer"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi

  local username
  if ! username="$(wg_inbound_prompt_username "Username peer baru (atau kembali): ")"; then
    return 0
  fi
  if wg_inbound_meta_peer_exists "${username}"; then
    warn "Username sudah ada: ${username}"
    hr
    pause
    return 0
  fi

  local allowed_ip keypair client_priv client_pub psk
  allowed_ip="$(wg_inbound_meta_next_ip 2>/dev/null || true)"
  if [[ -z "${allowed_ip}" ]]; then
    warn "Tidak ada slot IP peer yang tersedia pada network WG."
    hr
    pause
    return 0
  fi

  keypair="$(wg_inbound_generate_keypair)" || {
    warn "Gagal generate keypair client."
    hr
    pause
    return 0
  }
  client_priv="${keypair%%|*}"
  client_pub="${keypair#*|}"
  psk="$(wg_inbound_generate_psk 2>/dev/null || true)"

  echo "Preview peer baru:"
  echo "  Username   : ${username}"
  echo "  Allowed IP : ${allowed_ip}"
  hr
  if ! confirm_yn "Lanjut tambah peer ini?"; then
    return 0
  fi

  local backup_meta backup_conf endpoint_host out_conf
  backup_meta="$(mktemp "${WORK_DIR}/wg-meta.prev.XXXXXX")" || {
    warn "Gagal menyiapkan backup metadata."
    hr
    pause
    return 0
  }
  backup_conf="$(mktemp "${WORK_DIR}/wg-conf.prev.XXXXXX")" || {
    rm -f "${backup_meta}" >/dev/null 2>&1 || true
    warn "Gagal menyiapkan backup config."
    hr
    pause
    return 0
  }
  cp -a "${WG_INBOUND_META}" "${backup_meta}" || true
  cp -a "${WG_INBOUND_CONF}" "${backup_conf}" || true

  if ! wg_inbound_meta_add_peer "${username}" "${allowed_ip}" "${client_priv}" "${client_pub}" "${psk}"; then
    warn "Gagal menambah peer ke metadata."
    restore_file_if_exists "${backup_meta}" "${WG_INBOUND_META}"
    restore_file_if_exists "${backup_conf}" "${WG_INBOUND_CONF}"
    rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
    hr
    pause
    return 0
  fi

  if ! wg_inbound_apply_runtime_from_meta; then
    warn "Gagal apply runtime WG inbound. Mengembalikan perubahan..."
    restore_file_if_exists "${backup_meta}" "${WG_INBOUND_META}"
    restore_file_if_exists "${backup_conf}" "${WG_INBOUND_CONF}"
    systemctl restart xray >/dev/null 2>&1 || true
    rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
    hr
    pause
    return 0
  fi

  endpoint_host="$(wg_inbound_endpoint_host_detect)"
  out_conf="$(wg_inbound_write_client_config "${username}" "${endpoint_host}" 2>/dev/null || true)"

  rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
  log "Peer WG berhasil ditambahkan: ${username}"
  log "Client config: ${out_conf:-${WG_INBOUND_CLIENT_DIR}/${username}.conf}"
  hr
  pause
}


wg_inbound_delete_peer() {
  title
  echo "3) WG Inbound Management > Delete Peer"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi

  wg_inbound_meta_print_table "" || true
  hr

  local username
  if ! username="$(wg_inbound_prompt_username "Username peer yang dihapus (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  if ! confirm_yn "Yakin hapus peer ${username}?"; then
    return 0
  fi

  local backup_meta backup_conf
  backup_meta="$(mktemp "${WORK_DIR}/wg-meta.prev.XXXXXX")" || {
    warn "Gagal menyiapkan backup metadata."
    hr
    pause
    return 0
  }
  backup_conf="$(mktemp "${WORK_DIR}/wg-conf.prev.XXXXXX")" || {
    rm -f "${backup_meta}" >/dev/null 2>&1 || true
    warn "Gagal menyiapkan backup config."
    hr
    pause
    return 0
  }
  cp -a "${WG_INBOUND_META}" "${backup_meta}" || true
  cp -a "${WG_INBOUND_CONF}" "${backup_conf}" || true

  if ! wg_inbound_meta_delete_peer "${username}"; then
    warn "Gagal menghapus peer dari metadata."
    restore_file_if_exists "${backup_meta}" "${WG_INBOUND_META}"
    restore_file_if_exists "${backup_conf}" "${WG_INBOUND_CONF}"
    rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
    hr
    pause
    return 0
  fi

  if ! wg_inbound_apply_runtime_from_meta; then
    warn "Gagal apply runtime WG inbound. Mengembalikan perubahan..."
    restore_file_if_exists "${backup_meta}" "${WG_INBOUND_META}"
    restore_file_if_exists "${backup_conf}" "${WG_INBOUND_CONF}"
    systemctl restart xray >/dev/null 2>&1 || true
    rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
    hr
    pause
    return 0
  fi

  rm -f "${WG_INBOUND_CLIENT_DIR}/${username}.conf" >/dev/null 2>&1 || true
  rm -f "${backup_meta}" "${backup_conf}" >/dev/null 2>&1 || true
  log "Peer WG berhasil dihapus: ${username}"
  hr
  pause
}


wg_inbound_set_quota_menu() {
  title
  echo "3) WG Inbound Management > Set Quota"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username quota_gb quota_bytes
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  read -r -p "Quota limit (GB, contoh 50 / 120.5, atau kembali): " quota_gb
  if is_back_choice "${quota_gb}"; then
    return 0
  fi
  quota_gb="$(wg_inbound_trim "${quota_gb}")"
  if [[ -z "${quota_gb}" ]]; then
    warn "Quota tidak boleh kosong."
    hr
    pause
    return 0
  fi
  if ! [[ "${quota_gb}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    warn "Format quota tidak valid."
    hr
    pause
    return 0
  fi

  quota_bytes="$(bytes_from_gb "${quota_gb}")"
  if ! wg_inbound_meta_set_quota_bytes "${username}" "${quota_bytes}"; then
    warn "Gagal menyimpan quota metadata."
    hr
    pause
    return 0
  fi

  log "Quota metadata diset untuk ${username}: ${quota_gb} GB"
  warn "Catatan: enforcement quota WG inbound belum aktif (metadata-only)."
  hr
  pause
}


wg_inbound_reset_quota_used_menu() {
  title
  echo "3) WG Inbound Management > Reset Quota Used"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  if ! wg_inbound_meta_reset_quota_used "${username}"; then
    warn "Gagal reset quota_used metadata."
    hr
    pause
    return 0
  fi
  log "quota_used metadata direset untuk ${username}."
  warn "Catatan: enforcement quota WG inbound belum aktif (metadata-only)."
  hr
  pause
}


wg_inbound_toggle_ip_lock_menu() {
  title
  echo "3) WG Inbound Management > IP/Endpoint Lock (IP Limit)"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username state
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  state="$(wg_inbound_meta_toggle_ip_lock "${username}" 2>/dev/null || true)"
  if [[ -z "${state}" ]]; then
    warn "Gagal toggle IP lock metadata."
    hr
    pause
    return 0
  fi
  log "IP/Endpoint lock metadata untuk ${username}: ${state}"
  warn "Catatan: enforcement IP lock WG inbound belum aktif (metadata-only)."
  hr
  pause
}


wg_inbound_set_speed_limit_menu() {
  title
  echo "3) WG Inbound Management > Set Speed Limit"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username down up
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  read -r -p "Speed down (Mbps, contoh 20): " down
  if is_back_choice "${down}"; then
    return 0
  fi
  read -r -p "Speed up (Mbps, contoh 10): " up
  if is_back_choice "${up}"; then
    return 0
  fi
  down="$(wg_inbound_trim "${down}")"
  up="$(wg_inbound_trim "${up}")"

  if ! [[ "${down}" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! [[ "${up}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    warn "Nilai speed harus angka positif."
    hr
    pause
    return 0
  fi

  if ! wg_inbound_meta_set_speed_limit "${username}" "${down}" "${up}"; then
    warn "Gagal menyimpan speed metadata."
    hr
    pause
    return 0
  fi
  log "Speed limit metadata untuk ${username}: DOWN=${down} Mbps, UP=${up} Mbps (ON)"
  warn "Catatan: enforcement speed WG inbound belum aktif (metadata-only)."
  hr
  pause
}


wg_inbound_toggle_speed_limit_menu() {
  title
  echo "3) WG Inbound Management > Toggle Speed Limit"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username state
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  state="$(wg_inbound_meta_toggle_speed_limit "${username}" 2>/dev/null || true)"
  if [[ -z "${state}" ]]; then
    warn "Gagal toggle speed metadata."
    hr
    pause
    return 0
  fi
  log "Speed limit metadata untuk ${username}: ${state}"
  warn "Catatan: enforcement speed WG inbound belum aktif (metadata-only)."
  hr
  pause
}


wg_inbound_export_client_menu() {
  title
  echo "3) WG Inbound Management > Export Client Config"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi
  wg_inbound_meta_print_table "" || true
  hr

  local username endpoint out
  if ! username="$(wg_inbound_prompt_username "Username peer (atau kembali): ")"; then
    return 0
  fi
  if ! wg_inbound_meta_peer_exists "${username}"; then
    warn "Peer tidak ditemukan: ${username}"
    hr
    pause
    return 0
  fi

  endpoint="$(wg_inbound_endpoint_host_detect)"
  out="$(wg_inbound_write_client_config "${username}" "${endpoint}" 2>/dev/null || true)"
  if [[ -z "${out}" ]]; then
    warn "Gagal menulis file config client."
    hr
    pause
    return 0
  fi

  log "Client config tersimpan: ${out}"
  log "Endpoint dipakai: ${endpoint}"
  hr
  pause
}


wg_inbound_reload_menu() {
  title
  echo "3) WG Inbound Management > Reload WG Inbound"
  hr
  if ! wg_inbound_bootstrap; then
    warn "Gagal inisialisasi WG inbound metadata."
    hr
    pause
    return 0
  fi

  local backup_conf
  backup_conf="$(mktemp "${WORK_DIR}/wg-conf.prev.XXXXXX")" || {
    warn "Gagal menyiapkan backup config."
    hr
    pause
    return 0
  }
  cp -a "${WG_INBOUND_CONF}" "${backup_conf}" || true

  if ! wg_inbound_apply_runtime_from_meta; then
    warn "Reload gagal. Restore config WG inbound dari backup."
    restore_file_if_exists "${backup_conf}" "${WG_INBOUND_CONF}"
    systemctl restart xray >/dev/null 2>&1 || true
    rm -f "${backup_conf}" >/dev/null 2>&1 || true
    hr
    pause
    return 0
  fi

  rm -f "${backup_conf}" >/dev/null 2>&1 || true
  log "WG inbound berhasil direload."
  hr
  pause
}


wg_inbound_menu() {
  while true; do
    title
    echo "3) WG Inbound Management"
    hr
    echo "  1) WG Status"
    echo "  2) Add Peer"
    echo "  3) List/Search Peer"
    echo "  4) Delete Peer"
    echo "  5) Set Quota"
    echo "  6) Reset Quota Used"
    echo "  7) IP/Endpoint Lock (IP Limit)"
    echo "  8) Set Speed Limit"
    echo "  9) Toggle Speed Limit"
    echo " 10) Export Client Config"
    echo " 11) Reload WG Inbound"
    echo "  0) Kembali"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) wg_inbound_status_show ;;
      2) wg_inbound_add_peer ;;
      3) wg_inbound_list_peers ;;
      4) wg_inbound_delete_peer ;;
      5) wg_inbound_set_quota_menu ;;
      6) wg_inbound_reset_quota_used_menu ;;
      7) wg_inbound_toggle_ip_lock_menu ;;
      8) wg_inbound_set_speed_limit_menu ;;
      9) wg_inbound_toggle_speed_limit_menu ;;
      10) wg_inbound_export_client_menu ;;
      11) wg_inbound_reload_menu ;;
      0|kembali|k|back|b) break ;;
      *) invalid_choice ;;
    esac
  done
}
