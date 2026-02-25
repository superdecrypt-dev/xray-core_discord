# shellcheck shell=bash
# Network Controls
# - Egress mode: direct / warp / balancer
# - Balancer: tag "egress-balance"
# - Observatory: conf.d/60-observatory.json (untuk leastPing/leastLoad)
# - WARP: global / per-user / per-protocol (inbound)
# - Domain/Geosite: direct exceptions (editable list, template tetap readonly)
# - Adblock: custom geosite ext:custom.dat:adblock (enable/disable)
# -------------------------
warp_status() {
  title
  echo "WARP (wireproxy) status"
  hr
  if svc_exists wireproxy; then
    systemctl status wireproxy --no-pager || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  pause
}

network_state_file() {
  echo "${WORK_DIR}/network_state.json"
}

network_state_get() {
  # args: key
  local key="$1"
  local f
  f="$(network_state_file)"
  if [[ ! -f "${f}" ]]; then
    return 0
  fi
  python3 - <<'PY' "${f}" "${key}" 2>/dev/null || true
import json, sys
path, key = sys.argv[1:3]
try:
  with open(path,'r',encoding='utf-8') as f:
    d=json.load(f)
except Exception:
  d={}
v=d.get(key)
if v is None:
  raise SystemExit(0)
print(v)
PY
}

network_state_set() {
  # args: key value
  local key="$1"
  local val="$2"
  local f tmp
  f="$(network_state_file)"
  tmp="${WORK_DIR}/network_state.json.tmp"
  need_python3
  python3 - <<'PY' "${f}" "${tmp}" "${key}" "${val}"
import json, os, sys
path, tmp, key, val = sys.argv[1:5]
d={}
try:
  if os.path.exists(path):
    with open(path,'r',encoding='utf-8') as f:
      d=json.load(f) or {}
except Exception:
  d={}
d[key]=val
with open(tmp,'w',encoding='utf-8') as f:
  json.dump(d,f,ensure_ascii=False,indent=2)
  f.write("\n")
os.replace(tmp, path)
PY
  chmod 600 "${f}" 2>/dev/null || true
}

validate_email_user() {
  # args: email (username@protocol)
  local email="${1:-}"
  [[ "${email}" =~ ^[A-Za-z0-9._-]+@(vless|vmess|trojan)$ ]]
}

is_default_xray_email_or_tag() {
  # Default/bawaan Xray (disembunyikan dari menu WARP per-user):
  # default@(vless|vmess|trojan)-(ws|hup|grpc)
  local s="${1:-}"
  [[ "${s}" =~ ^default@(vless|vmess|trojan)-(ws|hup|grpc)$ ]]
}

is_readonly_geosite_domain() {
  # Geosite ini readonly (jangan disentuh), tampilkan di menu tapi jangan diubah:
  # apple, meta, google, openai, spotify, netflix, reddit
  local ent="${1:-}"
  case "${ent}" in
    geosite:apple|geosite:meta|geosite:google|geosite:openai|geosite:spotify|geosite:netflix|geosite:reddit)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

xray_routing_readonly_geosite_rule_print() {
  # Menampilkan rule geosite template (readonly) dari 30-routing.json
  # Rule ini dibuat oleh setup_modular.sh dan TIDAK boleh diedit dari menu.
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys

src=sys.argv[1]
targets=[
  "geosite:apple",
  "geosite:meta",
  "geosite:google",
  "geosite:openai",
  "geosite:spotify",
  "geosite:netflix",
  "geosite:reddit",
]
tset=set(targets)

try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

rules=((cfg.get("routing") or {}).get("rules") or [])
found=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get("type") != "field":
    continue
  dom=r.get("domain") or []
  if not isinstance(dom, list):
    continue
  if any(isinstance(x,str) and x in tset for x in dom):
    found=r
    break

if not found:
  print("  (rule readonly geosite tidak ditemukan)")
  raise SystemExit(0)

out="-"
if isinstance(found.get("outboundTag"), str) and found.get("outboundTag"):
  out=found.get("outboundTag")
elif isinstance(found.get("balancerTag"), str) and found.get("balancerTag"):
  out="balancer:" + found.get("balancerTag")

print(f"OutboundTag : {out} (readonly)")
dom=found.get("domain") or []
for i, x in enumerate(targets, start=1):
  if x in dom:
    print(f"  {i:>2}. {x}")
PY
}


xray_routing_default_rule_get() {
  # prints: mode=<direct|warp|balancer|unknown> tag=<tag-or-empty> balancer=<balancerTag-or-empty>
  need_python3
  python3 - <<'PY' "${XRAY_ROUTING_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules') or []
mode='unknown'
tag=''
bal=''
def is_default_rule(r):
  if not isinstance(r, dict):
    return False
  if r.get('type') != 'field':
    return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'):
    return False
  # Heuristic: default catch-all has only port + outboundTag/balancerTag
  return True

target=None
for r in rules:
  if is_default_rule(r):
    target=r
# pick last matching
if isinstance(target, dict):
  if 'balancerTag' in target and isinstance(target.get('balancerTag'), str) and target.get('balancerTag'):
    mode='balancer'
    bal=target.get('balancerTag','')
  else:
    ot=target.get('outboundTag')
    if isinstance(ot, str) and ot:
      tag=ot
      if ot == 'warp':
        mode='warp'
      elif ot == 'direct':
        mode='direct'
      else:
        mode='unknown'
print(f"mode={mode}")
print(f"tag={tag}")
print(f"balancer={bal}")
PY
}

xray_routing_default_rule_set() {
  # args: mode direct|warp|balancer
  local mode="$1"
  local tmp backup rc
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OUTBOUNDS_CONF}" "${tmp}" "${mode}" "${SPEED_OUTBOUND_TAG_PREFIX}" || exit 1
import json, sys
src, ob_src, dst, mode, speed_out_prefix = sys.argv[1:6]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)

routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    idx=i

if idx is None:
  raise SystemExit("Default rule (port 1-65535) tidak ditemukan")

try:
  with open(ob_src,'r',encoding='utf-8') as f:
    ob_cfg=json.load(f)
except Exception:
  ob_cfg={}

def list_outbound_tags():
  out=[]
  seen=set()
  for o in (ob_cfg.get('outbounds') or []):
    if not isinstance(o, dict):
      continue
    t=o.get('tag')
    if not isinstance(t, str):
      continue
    t=t.strip()
    if not t or t in seen:
      continue
    seen.add(t)
    out.append(t)
  return out

def pick_default_selector(tags):
  deny={"api","blocked"}
  sel=[]
  for t in ("direct","warp"):
    if t in tags and t not in sel:
      sel.append(t)
  if not sel:
    for t in tags:
      if t in deny:
        continue
      if speed_out_prefix and isinstance(t, str) and t.startswith(speed_out_prefix):
        continue
      if t in sel:
        continue
      sel.append(t)
      if len(sel) >= 2:
        break
  return sel

r=rules[idx]
if mode == 'direct':
  r.pop('balancerTag', None)
  r['outboundTag']='direct'
elif mode == 'warp':
  r.pop('balancerTag', None)
  r['outboundTag']='warp'
elif mode == 'balancer':
  tags=list_outbound_tags()
  balancers=routing.get('balancers')
  if not isinstance(balancers, list):
    balancers=[]

  b=None
  for it in balancers:
    if isinstance(it, dict) and it.get('tag') == 'egress-balance':
      b=it
      break

  if b is None:
    b={"tag":"egress-balance","selector":[],"strategy":{"type":"random"}}
    balancers.insert(0,b)

  raw_sel=b.get('selector')
  if not isinstance(raw_sel, list):
    raw_sel=[]

  deny={"api","blocked"}
  valid_sel=[]
  seen=set()
  for t in raw_sel:
    if not isinstance(t, str):
      continue
    t=t.strip()
    if not t:
      continue
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t not in tags:
      continue
    if t in seen:
      continue
    seen.add(t)
    valid_sel.append(t)

  if not valid_sel:
    valid_sel=pick_default_selector(tags)
  if not valid_sel:
    raise SystemExit("Tidak ada outbound valid untuk balancer egress-balance.")

  b['selector']=valid_sel
  st=b.get('strategy')
  if not isinstance(st, dict):
    st={}
  if not isinstance(st.get('type'), str) or not st.get('type'):
    st['type']='random'
  b['strategy']=st
  routing['balancers']=balancers

  r.pop('outboundTag', None)
  r['balancerTag']='egress-balance'
else:
  raise SystemExit("Mode tidak dikenal: " + mode)

rules[idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }

    if ! xray_confdir_syntax_test; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 87
    fi

    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update routing (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update routing default. Config di-rollback ke backup: ${backup}" \
    "Konfigurasi xray invalid setelah update routing default. Config di-rollback ke backup: ${backup}"

  speed_policy_resync_after_egress_change || return 1
}

xray_routing_balancer_get() {
  # prints: strategy=<type> selector=<comma-separated>
  need_python3
  python3 - <<'PY' "${XRAY_ROUTING_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
balancers=routing.get('balancers') or []
b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if not isinstance(b, dict):
  print("strategy=")
  print("selector=")
  raise SystemExit(0)
st=(b.get('strategy') or {})
stype=st.get('type') if isinstance(st, dict) else ''
sel=b.get('selector') or []
if not isinstance(sel, list):
  sel=[]
sel=[str(x) for x in sel if str(x).strip()]
print("strategy=" + (str(stype) if stype is not None else ""))
print("selector=" + ",".join(sel))
PY
}

xray_routing_balancer_set_strategy() {
  # args: strategy type
  local stype="$1"
  local tmp backup rc
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${stype}" || exit 1
import json, sys
src, dst, stype = sys.argv[1:4]
allowed={"random","roundRobin","leastPing","leastLoad"}
if stype not in allowed:
  raise SystemExit("Strategy invalid. Pilihan: " + ", ".join(sorted(allowed)))

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
balancers=routing.get('balancers')
if not isinstance(balancers, list):
  balancers=[]

b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if b is None:
  b={"tag":"egress-balance","selector":["direct","warp"],"strategy":{"type":"random"}}
  balancers.insert(0,b)

b.setdefault('strategy', {})
if not isinstance(b['strategy'], dict):
  b['strategy']={}
b['strategy']['type']=stype

routing['balancers']=balancers
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update balancer (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update balancer strategy. Config di-rollback ke backup: ${backup}"

  speed_policy_resync_after_egress_change || return 1
}

xray_routing_balancer_set_selector_from_outbounds() {
  # args: comma-separated or "auto"
  local mode="${1:-auto}"
  local tmp backup rc
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  [[ -f "${XRAY_OUTBOUNDS_CONF}" ]] || die "Xray outbounds conf tidak ditemukan: ${XRAY_OUTBOUNDS_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"

  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OUTBOUNDS_CONF}" "${tmp}" "${mode}" "${SPEED_OUTBOUND_TAG_PREFIX}" || exit 1
import json, sys
rt_src, ob_src, dst, mode, speed_out_prefix = sys.argv[1:6]
with open(rt_src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
with open(ob_src,'r',encoding='utf-8') as f:
  ob=json.load(f)

def list_outbound_tags():
  out=[]
  for o in (ob.get('outbounds') or []):
    if not isinstance(o, dict):
      continue
    tag=o.get('tag')
    if isinstance(tag, str) and tag.strip():
      out.append(tag.strip())
  return out

routing=(cfg.get('routing') or {})
balancers=routing.get('balancers')
if not isinstance(balancers, list):
  balancers=[]
b=None
for it in balancers:
  if isinstance(it, dict) and it.get('tag') == 'egress-balance':
    b=it
    break
if b is None:
  b={"tag":"egress-balance","selector":["direct","warp"],"strategy":{"type":"random"}}
  balancers.insert(0,b)

sel=[]
if mode == 'auto':
  tags=list_outbound_tags()
  # Exclude internal/system tags
  deny={"api","blocked"}
  seen=set()
  for t in tags:
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t in seen:
      continue
    seen.add(t)
    sel.append(t)
else:
  deny={"api","blocked"}
  known=set(list_outbound_tags())
  seen=set()
  for x in mode.split(","):
    t=x.strip()
    if not t:
      continue
    if t in deny:
      continue
    if speed_out_prefix and t.startswith(speed_out_prefix):
      continue
    if t not in known:
      continue
    if t in seen:
      continue
    seen.add(t)
    sel.append(t)

if not sel:
  raise SystemExit("Selector kosong. Gunakan auto atau isi tag outbound valid non-speed dipisah koma.")

b['selector']=sel
routing['balancers']=balancers
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update selector balancer (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update balancer selector. Config di-rollback ke backup: ${backup}"

  speed_policy_resync_after_egress_change || return 1
}

xray_observatory_get() {
  # prints: probeURL=... interval=... concurrency=true|false subjectSelector=comma-separated
  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    echo "probeURL="
    echo "interval="
    echo "concurrency="
    echo "subjectSelector="
    return 0
  fi
  need_python3
  python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}"
import json, sys
src=sys.argv[1]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
obs=cfg.get('observatory') or {}
if not isinstance(obs, dict):
  obs={}
probe=obs.get('probeURL') or obs.get('probeUrl') or ''
interval=obs.get('probeInterval') or ''
con=obs.get('enableConcurrency')
sub=obs.get('subjectSelector') or []
if not isinstance(sub, list):
  sub=[]
sub=[str(x) for x in sub if str(x).strip()]
print("probeURL=" + str(probe))
print("interval=" + str(interval))
print("concurrency=" + ("true" if bool(con) else "false"))
print("subjectSelector=" + ",".join(sub))
PY
}

xray_observatory_set_basic() {
  # args: probeURL interval enableConcurrency(true/false)
  local probe="$1"
  local interval="$2"
  local conc="$3"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    # Create empty file with safe perms
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_OBSERVATORY_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${probe}" "${interval}" "${conc}"
import json, sys
src, dst, probe, interval, conc = sys.argv[1:6]
conc = str(conc).lower() in ("1","true","yes","y","on")
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f) if f.readable() else {}
if not isinstance(cfg, dict):
  cfg={}
obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}
if probe.strip():
  obs['probeURL']=probe.strip()
if interval.strip():
  obs['probeInterval']=interval.strip()
obs['enableConcurrency']=bool(conc)
if 'subjectSelector' not in obs:
  obs['subjectSelector']=[]
cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${OBS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update observatory (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update observatory. Config di-rollback ke backup: ${backup}"
  return 0
}


xray_observatory_set_probe_url() {
  # args: probeURL
  local probe="$1"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_OBSERVATORY_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${probe}"
import json, sys
src, dst, probe = sys.argv[1:4]
probe = str(probe).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

if probe:
  obs['probeURL']=probe

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${OBS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update probeURL (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update observatory probeURL. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_observatory_set_interval() {
  # args: interval (contoh: 30s / 10m)
  local interval="$1"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_OBSERVATORY_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}" "${interval}"
import json, sys
src, dst, interval = sys.argv[1:4]
interval = str(interval).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

if interval:
  obs['probeInterval']=interval

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${OBS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update interval (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update observatory interval. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_observatory_toggle_concurrency() {
  local tmp backup rc
  need_python3

  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_OBSERVATORY_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_OBSERVATORY_CONF}" "${tmp}"
import json, sys
src, dst = sys.argv[1:3]

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}

cur=bool(obs.get('enableConcurrency'))
obs['enableConcurrency']=not cur

cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${OBS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal toggle concurrency (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah toggle observatory concurrency. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_observatory_sync_subject_selector_from_balancer() {
  local tmp backup rc
  need_python3

  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  if [[ ! -f "${XRAY_OBSERVATORY_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_OBSERVATORY_CONF}"
    echo '{}' > "${XRAY_OBSERVATORY_CONF}"
  fi

  ensure_path_writable "${XRAY_OBSERVATORY_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_OBSERVATORY_CONF}")"
  tmp="${WORK_DIR}/60-observatory.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_OBSERVATORY_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OBSERVATORY_CONF}" "${tmp}"
import json, sys
rt, obs_src, dst = sys.argv[1:4]
with open(rt,'r',encoding='utf-8') as f:
  rt_cfg=json.load(f)
routing=(rt_cfg.get('routing') or {})
balancers=routing.get('balancers') or []
sel=[]
for b in balancers:
  if isinstance(b, dict) and b.get('tag') == 'egress-balance':
    s=b.get('selector') or []
    if isinstance(s, list):
      sel=[str(x) for x in s if str(x).strip()]
    break

with open(obs_src,'r',encoding='utf-8') as f:
  cfg=json.load(f) if f.readable() else {}
if not isinstance(cfg, dict):
  cfg={}
obs=cfg.get('observatory')
if not isinstance(obs, dict):
  obs={}
obs['subjectSelector']=sel
cfg['observatory']=obs
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_OBSERVATORY_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_OBSERVATORY_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${OBS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal sync subjectSelector (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah sync observatory subjectSelector. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_routing_rule_toggle_user_outbound() {
  # args: marker outboundTag email on|off
  local marker="$1"
  local outbound="$2"
  local email="$3"
  local onoff="$4"
  local tmp backup rc

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${marker}" "${outbound}" "${email}" "${onoff}" || exit 1
import json, sys
src, dst, marker, outbound, email, onoff = sys.argv[1:7]
enable = (onoff.lower() == 'on')

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

default_idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    default_idx=i

if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan, tidak bisa insert rule baru")

rule_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type') != 'field': continue
  if r.get('outboundTag') != outbound: continue
  u=r.get('user') or []
  # BUG-13 fix: explicitly require rule has a 'user' field (not 'inboundTag').
  # Without this check, a per-inbound rule with the same outboundTag could be
  # mistakenly matched and modified when looking for a per-user rule.
  if not isinstance(u, list) or 'inboundTag' in r:
    continue
  if marker in u:
    rule_idx=i
    break

if rule_idx is None:
  # Insert before default rule
  newr={"type":"field","user":[marker],"outboundTag":outbound}
  rules.insert(default_idx, newr)
  rule_idx=default_idx

r=rules[rule_idx]
u=r.get('user') or []
if not isinstance(u, list):
  u=[]
# Ensure marker is first
u=[x for x in u if x != marker]
u.insert(0, marker)

if enable:
  if email not in u:
    u.append(email)
else:
  u=[x for x in u if x != email]
  # Keep marker only

r['user']=u
rules[rule_idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update routing (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update routing per-user warp/direct. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_routing_rule_toggle_inbounds_outbound() {
  # args: marker outboundTag comma_inboundTags on|off
  local marker="$1"
  local outbound="$2"
  local tags_csv="$3"
  local onoff="$4"
  local tmp backup rc

  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${marker}" "${outbound}" "${tags_csv}" "${onoff}" || exit 1
import json, sys
src, dst, marker, outbound, tags_csv, onoff = sys.argv[1:7]
enable = (onoff.lower() == 'on')
tags=[t.strip() for t in tags_csv.split(",") if t.strip()]

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing config: routing.rules bukan list")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

default_idx=None
for i,r in enumerate(rules):
  if is_default_rule(r):
    default_idx=i
if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan, tidak bisa insert rule baru")

rule_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type') != 'field': continue
  if r.get('outboundTag') != outbound: continue
  ib=r.get('inboundTag') or []
  if isinstance(ib, list) and marker in ib:
    rule_idx=i
    break

if rule_idx is None:
  newr={"type":"field","inboundTag":[marker],"outboundTag":outbound}
  rules.insert(default_idx, newr)
  rule_idx=default_idx

r=rules[rule_idx]
ib=r.get('inboundTag') or []
if not isinstance(ib, list):
  ib=[]
# Ensure marker first
ib=[x for x in ib if x != marker]
ib.insert(0, marker)

if enable:
  for t in tags:
    if t not in ib:
      ib.append(t)
else:
  ib=[x for x in ib if x not in tags]
  # Keep marker only

r['inboundTag']=ib
rules[rule_idx]=r
routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update routing (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update routing per-inbound warp/direct. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_list_inbounds_tags_by_protocol() {
  # args: proto
  local proto="$1"
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${proto}"
import json, sys
src, proto = sys.argv[1:3]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
tags=[]
for ib in cfg.get('inbounds', []) or []:
  if not isinstance(ib, dict):
    continue
  if ib.get('protocol') != proto:
    continue
  tag=ib.get('tag')
  if isinstance(tag, str) and tag.strip():
    tags.append(tag.strip())
print(",".join(tags))
PY
}

xray_inbounds_all_tags_get() {
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
tags=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  tag=ib.get('tag')
  if isinstance(tag, str) and tag.strip():
    tags.add(tag.strip())
for t in sorted(tags):
  print(t)
PY
}


network_show_summary() {
  title
  echo "Network / Proxy Summary"
  hr

  if [[ -f "${XRAY_ROUTING_CONF}" ]]; then
    xray_routing_default_rule_get
    hr
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get
    hr
  else
    warn "Routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  fi

  echo "Observatory:"
  xray_observatory_get
  hr

  if svc_exists wireproxy; then
    svc_status_line wireproxy
  else
    echo "wireproxy: (tidak terpasang)"
  fi
  hr
  pause
}

egress_menu() {
  while true; do
    title
    echo "4) Network Controls > Egress Mode & Balancer"
    hr
    xray_routing_default_rule_get || true
    echo ""
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get || true
    echo ""
    echo "Observatory:"
    xray_observatory_get || true
    hr

    echo "  1) Set default egress: DIRECT"
    echo "  2) Set default egress: WARP"
    echo "  3) Set default egress: BALANCER (egress-balance)"
    echo "  4) Set balancer strategy (random/roundRobin/leastPing/leastLoad)"
    echo "  5) Set balancer selector (auto dari outbounds)"
    echo "  6) Set balancer selector (manual: tag1,tag2,...)"
    echo "  7) Observatory: set probeURL/interval/concurrency"
    echo "  8) Observatory: sync subjectSelector dari balancer selector"
    echo "  0) Back"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) xray_routing_default_rule_set direct ; log "Default egress: DIRECT" ; pause ;;
      2) xray_routing_default_rule_set warp ; log "Default egress: WARP" ; pause ;;
      3) xray_routing_default_rule_set balancer ; log "Default egress: BALANCER" ; pause ;;
      4)
        read -r -p "Strategy (random/roundRobin/leastPing/leastLoad) (atau kembali): " st
        if is_back_choice "${st}"; then
          continue
        fi
        xray_routing_balancer_set_strategy "${st}"
        log "Balancer strategy updated: ${st}"
        pause
        ;;
      5)
        xray_routing_balancer_set_selector_from_outbounds auto
        log "Balancer selector di-set: auto"
        pause
        ;;
      6)
        read -r -p "Selector tags (tag1,tag2,...) (atau kembali): " sel
        if is_back_choice "${sel}"; then
          continue
        fi
        xray_routing_balancer_set_selector_from_outbounds "${sel}"
        log "Balancer selector updated"
        pause
        ;;
      7)
        read -r -p "probeURL (contoh https://www.google.com/generate_204) (atau kembali): " purl
        if is_back_choice "${purl}"; then
          continue
        fi
        read -r -p "probeInterval (contoh 30s) (atau kembali): " pint
        if is_back_choice "${pint}"; then
          continue
        fi
        read -r -p "enableConcurrency (true/false) (atau kembali): " pcon
        if is_back_choice "${pcon}"; then
          continue
        fi
        xray_observatory_set_basic "${purl}" "${pint}" "${pcon}"
        log "Observatory updated"
        pause
        ;;
      8)
        xray_observatory_sync_subject_selector_from_balancer
        log "Observatory subjectSelector disinkronkan"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}


# -------------------------
# Egress Mode & Balancer (revisi menu sederhana)
# -------------------------
egress_show_detailed_status() {
  title
  echo "Egress Detailed Status"
  hr
  if [[ -f "${XRAY_ROUTING_CONF}" ]]; then
    xray_routing_default_rule_get || true
    hr
    echo "Balancer (egress-balance):"
    xray_routing_balancer_get || true
    hr
  else
    warn "Routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
    hr
  fi

  echo "Observatory:"
  xray_observatory_get || true
  hr
  pause
}

egress_set_mode_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Set Egress Mode"
    hr
    printf "Current Egress Mode: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) DIRECT"
    echo "  2) WARP"
    echo "  3) BALANCER"
    echo "  0) Back"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1)
        xray_routing_default_rule_set direct
        log "Egress Mode di-set: DIRECT"
        pause
        ;;
      2)
        xray_routing_default_rule_set warp
        log "Egress Mode di-set: WARP"
        pause
        ;;
      3)
        xray_routing_default_rule_set balancer
        log "Egress Mode di-set: BALANCER (egress-balance)"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_balancer_settings_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Balancer Settings (egress-balance)"
    hr
    xray_routing_balancer_get || true
    hr
    echo "  1) Set Strategy"
    echo "  2) Set Selector (auto)"
    echo "  3) Set Selector (manual)"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Strategy (random/roundRobin/leastPing/leastLoad) (atau kembali): " st
        if is_back_choice "${st}"; then
          continue
        fi
        case "${st}" in
          random|roundRobin|leastPing|leastLoad)
            xray_routing_balancer_set_strategy "${st}"
            log "Balancer strategy updated: ${st}"
            pause
            ;;
          *)
            warn "Strategy tidak valid"
            pause
            ;;
        esac
        ;;
      2)
        xray_routing_balancer_set_selector_from_outbounds auto
        log "Balancer selector di-set: auto"
        pause
        ;;
      3)
        read -r -p "Selector tags (tag1,tag2,...) (atau kembali): " sel
        if is_back_choice "${sel}"; then
          continue
        fi
        xray_routing_balancer_set_selector_from_outbounds "${sel}"
        log "Balancer selector updated"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_observatory_settings_menu() {
  while true; do
    title
    echo "Egress Mode & Balancer > Observatory Settings"
    hr

    local probe interval conc subj
    probe="$(xray_observatory_get | awk -F'=' '/^probeURL=/{print $2; exit}' 2>/dev/null || true)"
    interval="$(xray_observatory_get | awk -F'=' '/^interval=/{print $2; exit}' 2>/dev/null || true)"
    conc="$(xray_observatory_get | awk -F'=' '/^concurrency=/{print $2; exit}' 2>/dev/null || true)"
    subj="$(xray_observatory_get | awk -F'=' '/^subjectSelector=/{print $2; exit}' 2>/dev/null || true)"

    echo "probeURL        : ${probe}"
    echo "interval        : ${interval}"
    echo "concurrency     : ${conc}"
    echo "subjectSelector : ${subj}"
    hr

    echo "  1) Set probeURL"
    echo "  2) Set interval"
    echo "  3) Toggle concurrency"
    echo "  4) Sync subjectSelector from balancer"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "probeURL (contoh https://www.google.com/generate_204) (atau kembali): " purl
        if is_back_choice "${purl}"; then
          continue
        fi
        xray_observatory_set_probe_url "${purl}"
        log "probeURL updated"
        pause
        ;;
      2)
        read -r -p "interval (contoh 30s / 10m) (atau kembali): " pint
        if is_back_choice "${pint}"; then
          continue
        fi
        xray_observatory_set_interval "${pint}"
        log "interval updated"
        pause
        ;;
      3)
        xray_observatory_toggle_concurrency
        log "concurrency toggled"
        pause
        ;;
      4)
        xray_observatory_sync_subject_selector_from_balancer
        log "Observatory subjectSelector disinkronkan"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

egress_menu_simple() {
  while true; do
    title
    echo "4) Network Controls > Egress Mode & Balancer"
    hr
    printf "Current Egress Mode: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) Set Egress Mode"
    echo "  2) Balancer Settings"
    echo "  3) Observatory Settings"
    echo "  4) Show Detailed Status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) egress_set_mode_menu ;;
      2) egress_balancer_settings_menu ;;
      3) egress_observatory_settings_menu ;;
      4) egress_show_detailed_status ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_global_mode_get() {
  xray_routing_default_rule_get | awk -F'=' '/^mode=/{print $2; exit}' 2>/dev/null || true
}

warp_global_mode_pretty_get() {
  local mode bal
  mode="$(warp_global_mode_get)"
  bal="$(xray_routing_default_rule_get | awk -F'=' '/^balancer=/{print $2; exit}' 2>/dev/null || true)"
  case "${mode}" in
    warp) echo "warp" ;;
    direct) echo "direct" ;;
    balancer)
      if [[ -n "${bal}" ]]; then
        echo "balancer (${bal})"
      else
        echo "balancer"
      fi
      ;;
    *) echo "unknown" ;;
  esac
}

xray_routing_rule_user_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
out=[]
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  u=r.get('user') or []
  if not isinstance(u, list):
    continue
  if marker in u:
    for x in u:
      if isinstance(x, str) and x and x != marker:
        out.append(x)
    break
for x in out:
  print(x)
PY
}

xray_routing_rule_inbound_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
out=[]
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  ib=r.get('inboundTag') or []
  if not isinstance(ib, list):
    continue
  if marker in ib:
    for x in ib:
      if isinstance(x, str) and x and x != marker:
        out.append(x)
    break
for x in out:
  print(x)
PY
}

xray_routing_custom_domain_list_get() {
  # args: marker outboundTag
  local marker="$1"
  local outbound="$2"
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${marker}" "${outbound}" 2>/dev/null || true
import json, sys
src, marker, outbound = sys.argv[1:4]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
custom=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != outbound:
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and marker in dom:
    custom=[x for x in dom if isinstance(x, str) and x and x != marker]
    break
if not isinstance(custom, list):
  custom=[]
for x in custom:
  print(x)
PY
}

xray_inbounds_all_client_emails_get() {
  need_python3
  [[ -f "${XRAY_INBOUNDS_CONF}" ]] || return 0
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
emails=set()
for ib in (cfg.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  st=(ib.get('settings') or {})
  clients=st.get('clients') or []
  if not isinstance(clients, list):
    continue
  for c in clients:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if isinstance(em, str) and em.strip():
      emails.add(em.strip())
for em in sorted(emails):
  print(em)
PY
}

warp_controls_summary() {
  local global wire_state
  global="$(warp_global_mode_pretty_get)"
  if svc_exists wireproxy; then
    if svc_is_active wireproxy; then
      wire_state="active"
    else
      wire_state="inactive"
    fi
  else
    wire_state="not-installed"
  fi

  local wu du wi di dd wd
  wu="$(xray_routing_rule_user_list_get "dummy-warp-user" "warp" | wc -l | tr -d ' ')"
  du="$(xray_routing_rule_user_list_get "dummy-direct-user" "direct" | wc -l | tr -d ' ')"
  wi="$(xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" | wc -l | tr -d ' ')"
  di="$(xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" | wc -l | tr -d ' ')"
  dd="$(xray_routing_custom_domain_list_get "regexp:^$" "direct" | wc -l | tr -d ' ')"
  wd="$(xray_routing_custom_domain_list_get "regexp:^\$WARP" "warp" | wc -l | tr -d ' ')"

  echo "WARP Global : ${global}"
  echo "wireproxy   : ${wire_state}"
  echo "Override    : user warp=${wu}, user direct=${du} | inbound warp=${wi}, inbound direct=${di}"
  echo "Domain list : direct=${dd}, warp=${wd}"
}

warp_controls_report() {
  title
  echo "WARP status report (detail)"
  hr
  warp_controls_summary || true
  hr

  need_python3
  python3 - <<'PY' "${XRAY_INBOUNDS_CONF}" "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
inb_path, routing_path = sys.argv[1:3]

def load_json(path):
  try:
    with open(path,'r',encoding='utf-8') as f:
      return json.load(f)
  except Exception:
    return {}

inb=load_json(inb_path)
rt=load_json(routing_path)

rules=((rt.get('routing') or {}).get('rules') or [])

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

def get_default_mode():
  target=None
  for r in rules:
    if is_default_rule(r):
      target=r
  mode='unknown'
  bal=''
  if isinstance(target, dict):
    bt=target.get('balancerTag')
    if isinstance(bt, str) and bt:
      mode='balancer'
      bal=bt
    else:
      ot=target.get('outboundTag')
      if ot == 'warp':
        mode='warp'
      elif ot == 'direct':
        mode='direct'
      elif isinstance(ot, str) and ot:
        mode='unknown'
      else:
        mode='unknown'
  return mode, bal

def rule_list_user(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    u=r.get('user') or []
    if isinstance(u, list) and marker in u:
      return [x for x in u if isinstance(x,str) and x and x != marker]
  return []

def rule_list_inbound(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    ib=r.get('inboundTag') or []
    if isinstance(ib, list) and marker in ib:
      return [x for x in ib if isinstance(x,str) and x and x != marker]
  return []

def rule_list_domain(marker, outbound):
  for r in rules:
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and marker in dom:
      return [x for x in dom if isinstance(x,str) and x and x != marker]
  return []

mode, bal = get_default_mode()
default_label = mode
if mode == 'balancer' and bal:
  default_label = f'balancer({bal})'

warp_users=set(rule_list_user('dummy-warp-user','warp'))
direct_users=set(rule_list_user('dummy-direct-user','direct'))
warp_inb=set(rule_list_inbound('dummy-warp-inbounds','warp'))
direct_inb=set(rule_list_inbound('dummy-direct-inbounds','direct'))
direct_dom=rule_list_domain('regexp:^$','direct')
warp_dom=rule_list_domain('regexp:^$WARP','warp')

# Collect client emails (and protocol)
clients=[]
for ib in (inb.get('inbounds') or []):
  if not isinstance(ib, dict):
    continue
  proto=ib.get('protocol')
  st=(ib.get('settings') or {})
  cls=st.get('clients') or []
  if not isinstance(cls, list):
    continue
  for c in cls:
    if not isinstance(c, dict):
      continue
    em=c.get('email')
    if isinstance(em, str) and em.strip():
      clients.append((em.strip(), proto if isinstance(proto,str) else ''))

# unique keep stable sorted
clients_sorted=sorted(set(clients), key=lambda x: (x[0], x[1]))

def eff_mode_for_email(email):
  if email in direct_users:
    return 'direct'
  if email in warp_users:
    return 'warp'
  if mode in ('warp','direct'):
    return mode
  return default_label

print("Per-user effective mode:")
print(f"{'Email':<28} {'Proto':<8} {'Effective':<12} {'Override':<10}")
print("-"*62)
for em, proto in clients_sorted:
  override=''
  if em in direct_users:
    override='direct'
  elif em in warp_users:
    override='warp'
  eff=eff_mode_for_email(em)
  print(f"{em:<28} {proto:<8} {eff:<12} {override:<10}")
if not clients_sorted:
  print("(tidak ada client ditemukan dari 10-inbounds.json)")

print()
print("Per-inboundTag effective mode:")
print(f"{'InboundTag':<28} {'Proto':<8} {'Effective':<12} {'Override':<10}")
print("-"*62)

def inbounds_tags_by_proto():
  out=[]
  for ib in (inb.get('inbounds') or []):
    if not isinstance(ib, dict):
      continue
    tag=ib.get('tag')
    proto=ib.get('protocol')
    if isinstance(tag,str) and tag.strip():
      out.append((tag.strip(), proto if isinstance(proto,str) else ''))
  return sorted(set(out), key=lambda x: (x[1], x[0]))

def eff_mode_for_inbound(tag):
  if tag in direct_inb:
    return 'direct'
  if tag in warp_inb:
    return 'warp'
  if mode in ('warp','direct'):
    return mode
  return default_label

tags=inbounds_tags_by_proto()
for tag, proto in tags:
  override=''
  if tag in direct_inb:
    override='direct'
  elif tag in warp_inb:
    override='warp'
  eff=eff_mode_for_inbound(tag)
  print(f"{tag:<28} {proto:<8} {eff:<12} {override:<10}")
if not tags:
  print("(tidak ada inbound tag ditemukan dari 10-inbounds.json)")

print()
print("Custom Domain/Geosite Lists:")
print("  Direct (custom):")
if direct_dom:
  for x in direct_dom:
    print(f"    - {x}")
else:
  print("    (kosong)")
print("  WARP (custom):")
if warp_dom:
  for x in warp_dom:
    print(f"    - {x}")
else:
  print("    (kosong)")
PY
  hr
  pause
}

xray_routing_custom_domain_entry_set_mode() {
  # args: mode direct|warp|off entry
  local mode="$1"
  local ent="$2"
  local tmp backup rc
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${mode}" "${ent}" || exit 1
import json, sys
src, dst, mode, ent = sys.argv[1:5]
mode=mode.lower().strip()
ent=ent.strip()

with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)

routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

def is_default_rule(r):
  # BUG-14 fix: added additional checks to reduce false positives.
  # A rule with port='1-65535' alone is ambiguous; we also require that
  # it has no 'user', 'domain', 'ip', or 'protocol' filters (which would
  # indicate a more specific rule rather than the catch-all default).
  if not isinstance(r, dict): return False
  if r.get('type') != 'field': return False
  port=str(r.get('port','')).strip()
  if port not in ('1-65535','0-65535'): return False
  # A genuine catch-all default rule should not have specific user/domain/ip/protocol filters
  if r.get('user') or r.get('domain') or r.get('ip') or r.get('protocol'):
    return False
  return True

def find_default_idx():
  idx=None
  for i,r in enumerate(rules):
    if is_default_rule(r):
      idx=i
  return idx

def find_template_direct_idx():
  for i,r in enumerate(rules):
    if not isinstance(r, dict): 
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != 'direct':
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
      return i
  return None

def find_domain_rule_idx(outbound, marker):
  for i,r in enumerate(rules):
    if not isinstance(r, dict):
      continue
    if r.get('type') != 'field':
      continue
    if r.get('outboundTag') != outbound:
      continue
    dom=r.get('domain') or []
    if isinstance(dom, list) and marker in dom:
      return i
  return None

def ensure_domain_rule(outbound, marker, insert_at):
  idx=find_domain_rule_idx(outbound, marker)
  if idx is not None:
    return idx
  newr={"type":"field","domain":[marker],"outboundTag":outbound}
  rules.insert(insert_at, newr)
  return insert_at

def normalize_rule(idx, marker, desired_present):
  r=rules[idx]
  dom=r.get('domain') or []
  if not isinstance(dom, list):
    dom=[]
  # keep marker first
  dom=[x for x in dom if x != marker]
  dom.insert(0, marker)
  # remove ent
  dom=[x for x in dom if x != ent]
  if desired_present:
    dom.append(ent)
  r['domain']=dom
  rules[idx]=r

default_idx=find_default_idx()
if default_idx is None:
  raise SystemExit("Default rule tidak ditemukan")

tpl_idx=find_template_direct_idx()
# Base insertion point: after template direct if exists, else before default
base=(tpl_idx + 1) if tpl_idx is not None else default_idx

direct_marker='regexp:^$'
warp_marker='regexp:^$WARP'

direct_idx=find_domain_rule_idx('direct', direct_marker)
warp_idx=find_domain_rule_idx('warp', warp_marker)

# Insert order: template direct -> custom direct -> custom warp -> default
# Ensure direct rule position
if mode == 'direct':
  if direct_idx is None:
    direct_idx=ensure_domain_rule('direct', direct_marker, base)
    if direct_idx <= default_idx:
      default_idx += 1
    if warp_idx is not None and warp_idx >= direct_idx:
      pass
  # Ensure warp rule exists only if already exists; don't create unless needed
  if warp_idx is not None:
    normalize_rule(warp_idx, warp_marker, False)
  normalize_rule(direct_idx, direct_marker, True)

elif mode == 'warp':
  # ensure warp rule after direct rule if direct exists, else after template
  if direct_idx is not None:
    # ensure warp inserted after direct rule
    base_warp = direct_idx + 1
  else:
    base_warp = base
  if warp_idx is None:
    warp_idx=ensure_domain_rule('warp', warp_marker, base_warp)
    if warp_idx <= default_idx:
      default_idx += 1
  if direct_idx is not None:
    normalize_rule(direct_idx, direct_marker, False)
  normalize_rule(warp_idx, warp_marker, True)

elif mode == 'off':
  if direct_idx is not None:
    normalize_rule(direct_idx, direct_marker, False)
  if warp_idx is not None:
    normalize_rule(warp_idx, warp_marker, False)
else:
  raise SystemExit("Mode harus direct|warp|off")

routing['rules']=rules
cfg['routing']=routing

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${ROUTING_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update routing (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update custom domain mode. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_routing_adblock_rule_get() {
  # prints: enabled=<0|1> outbound=<tag|balancer:tag|-> duplicates=<n> domains=<n>
  need_python3
  if [[ ! -f "${XRAY_ROUTING_CONF}" ]]; then
    echo "enabled=0"
    echo "outbound=-"
    echo "duplicates=0"
    echo "domains=0"
    return 0
  fi
  python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${ADBLOCK_GEOSITE_ENTRY}" 2>/dev/null || true
import json
import sys

src, entry = sys.argv[1:3]

try:
  with open(src, "r", encoding="utf-8") as f:
    cfg = json.load(f)
except Exception:
  print("enabled=0")
  print("outbound=-")
  print("duplicates=0")
  print("domains=0")
  raise SystemExit(0)

rules = ((cfg.get("routing") or {}).get("rules") or [])
targets = []
for i, r in enumerate(rules):
  if not isinstance(r, dict):
    continue
  if r.get("type") != "field":
    continue
  dom = r.get("domain") or []
  if not isinstance(dom, list):
    continue
  if any(isinstance(x, str) and x.strip() == entry for x in dom):
    targets.append((i, r))

if not targets:
  print("enabled=0")
  print("outbound=-")
  print("duplicates=0")
  print("domains=0")
  raise SystemExit(0)

r = targets[0][1]
out = "-"
ot = r.get("outboundTag")
if isinstance(ot, str) and ot.strip():
  out = ot.strip()
else:
  bt = r.get("balancerTag")
  if isinstance(bt, str) and bt.strip():
    out = "balancer:" + bt.strip()

dom = r.get("domain") or []
dom_count = 0
if isinstance(dom, list):
  dom_count = sum(1 for x in dom if isinstance(x, str) and x.strip())

print("enabled=1")
print(f"outbound={out}")
print(f"duplicates={max(0, len(targets) - 1)}")
print(f"domains={dom_count}")
PY
}

adblock_custom_dat_status_get() {
  if [[ -s "${CUSTOM_GEOSITE_DAT}" ]]; then
    echo "ready"
  else
    echo "missing"
  fi
}

xray_routing_adblock_rule_set() {
  # args: blocked|direct|warp|balancer|off
  local mode="${1:-}"
  local backup tmp out changed rc
  need_python3
  [[ -f "${XRAY_ROUTING_CONF}" ]] || die "Xray routing conf tidak ditemukan: ${XRAY_ROUTING_CONF}"
  if [[ "${mode,,}" == "balancer" ]]; then
    [[ -f "${XRAY_OUTBOUNDS_CONF}" ]] || die "Xray outbounds conf tidak ditemukan: ${XRAY_OUTBOUNDS_CONF}"
  fi
  ensure_path_writable "${XRAY_ROUTING_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
  tmp="${WORK_DIR}/30-routing-adblock.json.tmp"

  set +e
  out="$(
    (
      flock -x 200
      cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
      py_out="$(
        python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${XRAY_OUTBOUNDS_CONF}" "${tmp}" "${mode}" "${ADBLOCK_GEOSITE_ENTRY}" "${ADBLOCK_BALANCER_TAG}"
import json
import sys

src, out_src, dst, mode, entry, bal_tag = sys.argv[1:7]
mode = mode.strip().lower()
if mode not in ("blocked", "direct", "warp", "balancer", "off"):
  raise SystemExit("Mode harus blocked|direct|warp|balancer|off")

with open(src, "r", encoding="utf-8") as f:
  cfg = json.load(f)

routing = cfg.get("routing") or {}
rules = routing.get("rules")
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")
balancers = routing.get("balancers")
if not isinstance(balancers, list):
  balancers = []

before = json.dumps(cfg, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def is_default_rule(r):
  if not isinstance(r, dict):
    return False
  if r.get("type") != "field":
    return False
  port = str(r.get("port", "")).strip()
  if port not in ("1-65535", "0-65535"):
    return False
  if r.get("user") or r.get("domain") or r.get("ip") or r.get("protocol"):
    return False
  return True

def find_default_idx():
  idx = None
  for i, r in enumerate(rules):
    if is_default_rule(r):
      idx = i
  return idx

def find_template_direct_idx():
  for i, r in enumerate(rules):
    if not isinstance(r, dict):
      continue
    if r.get("type") != "field":
      continue
    if r.get("outboundTag") != "direct":
      continue
    dom = r.get("domain") or []
    if isinstance(dom, list) and ("geosite:apple" in dom or "geosite:google" in dom):
      return i
  return None

def has_entry(r):
  if not isinstance(r, dict):
    return False
  if r.get("type") != "field":
    return False
  dom = r.get("domain") or []
  if not isinstance(dom, list):
    return False
  for x in dom:
    if isinstance(x, str) and x.strip() == entry:
      return True
  return False

def get_outbound_tags():
  try:
    with open(out_src, "r", encoding="utf-8") as f:
      out_cfg = json.load(f)
  except Exception as e:
    raise SystemExit(f"Gagal membaca outbounds: {e}")
  outbounds = out_cfg.get("outbounds")
  if not isinstance(outbounds, list):
    outbounds = []
  tags = []
  for o in outbounds:
    if not isinstance(o, dict):
      continue
    t = o.get("tag")
    if isinstance(t, str) and t.strip():
      tags.append(t.strip())
  return tags

idxs = [i for i, r in enumerate(rules) if has_entry(r)]

if mode == "off":
  if idxs:
    rm = set(idxs)
    rules = [r for i, r in enumerate(rules) if i not in rm]
else:
  if len(idxs) > 1:
    rm = set(idxs[1:])
    rules = [r for i, r in enumerate(rules) if i not in rm]

  primary_idx = None
  for i, r in enumerate(rules):
    if has_entry(r):
      primary_idx = i
      break

  if primary_idx is None:
    default_idx = find_default_idx()
    tpl_idx = find_template_direct_idx()
    insert_at = default_idx if default_idx is not None else len(rules)
    if tpl_idx is not None and tpl_idx < insert_at:
      insert_at = tpl_idx + 1
    rules.insert(insert_at, {
      "type": "field",
      "domain": [entry],
      "outboundTag": "blocked"
    })
    primary_idx = insert_at

  rule = rules[primary_idx]
  if not isinstance(rule, dict):
    rule = {}
  dom = rule.get("domain")
  if not isinstance(dom, list):
    dom = []

  cleaned = [entry]
  seen = {entry}
  for x in dom:
    if not isinstance(x, str):
      continue
    x = x.strip()
    if not x or x in seen:
      continue
    cleaned.append(x)
    seen.add(x)

  rule["type"] = "field"
  rule["domain"] = cleaned
  if mode == "balancer":
    rule.pop("outboundTag", None)
    rule["balancerTag"] = bal_tag
  else:
    rule.pop("balancerTag", None)
    rule["outboundTag"] = mode
  rules[primary_idx] = rule

  default_idx = find_default_idx()
  if default_idx is not None and primary_idx > default_idx:
    moved = rules.pop(primary_idx)
    rules.insert(default_idx, moved)

clean_balancers = []
found_bal = None
for b in balancers:
  if not isinstance(b, dict):
    continue
  t = b.get("tag")
  if isinstance(t, str) and t.strip() == bal_tag:
    if found_bal is None:
      found_bal = dict(b)
    continue
  clean_balancers.append(b)

if mode == "balancer":
  known = set(get_outbound_tags())
  if not {"direct", "warp"}.issubset(known):
    raise SystemExit("Outbound direct/warp wajib ada untuk mode balancer adblock.")
  selector = ["direct", "warp"]

  if found_bal is None:
    found_bal = {"tag": bal_tag}
  found_bal["selector"] = selector
  st = found_bal.get("strategy")
  if not isinstance(st, dict):
    st = {}
  typ = st.get("type")
  if not isinstance(typ, str) or not typ.strip():
    st = {"type": "random"}
  found_bal["strategy"] = st
  clean_balancers.insert(0, found_bal)

routing["rules"] = rules
routing["balancers"] = clean_balancers
cfg["routing"] = routing
after = json.dumps(cfg, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
changed = 1 if after != before else 0
print(f"changed={changed}")

with open(dst, "w", encoding="utf-8") as f:
  json.dump(cfg, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY
      )" || exit 1
      printf '%s\n' "${py_out}"
      changed_local="$(xray_txn_changed_flag "${py_out}")"

      xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
        restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
        exit 1
      }

      if [[ "${changed_local}" == "1" ]]; then
        svc_restart xray || true
        if ! svc_wait_active xray 20; then
          restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
          systemctl restart xray || true
          exit 86
        fi
      fi
    ) 200>"${ROUTING_LOCK_FILE}"
  )"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update adblock routing (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update adblock routing. Config di-rollback ke backup: ${backup}"

  changed="$(xray_txn_changed_flag "${out}")"
  if [[ "${changed}" != "1" ]]; then
    return 0
  fi
  return 0
}

adblock_menu() {
  need_python3
  while true; do
    local st enabled outbound duplicates asset_status
    st="$(xray_routing_adblock_rule_get 2>/dev/null || true)"
    enabled="$(printf '%s\n' "${st}" | awk -F'=' '/^enabled=/{print $2; exit}')"
    outbound="$(printf '%s\n' "${st}" | awk -F'=' '/^outbound=/{sub(/^outbound=/,""); print; exit}')"
    duplicates="$(printf '%s\n' "${st}" | awk -F'=' '/^duplicates=/{print $2; exit}')"
    asset_status="$(adblock_custom_dat_status_get)"

    title
    echo "4) Network Controls > Adblock (Custom Geosite)"
    hr
    printf "Geosite File : %s\n" "${CUSTOM_GEOSITE_DAT}"
    printf "Asset Status : %s\n" "${asset_status}"
    printf "Rule Entry   : %s\n" "${ADBLOCK_GEOSITE_ENTRY}"
    if [[ "${enabled}" == "1" ]]; then
      printf "Rule Status  : ON\n"
    else
      printf "Rule Status  : OFF\n"
    fi
    printf "OutboundTag  : %s\n" "${outbound:--}"
    if [[ -n "${duplicates}" && "${duplicates}" != "0" ]]; then
      printf "Duplicates   : %s (akan dibersihkan saat update)\n" "${duplicates}"
    fi
    hr
    echo "  1) Enable -> balancer (direct+warp)"
    echo "  2) Disable (hapus rule)"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        if [[ ! -s "${CUSTOM_GEOSITE_DAT}" ]]; then
          warn "custom.dat belum tersedia. Jalankan setup.sh dulu untuk download custom geosite."
          pause
          continue
        fi
        xray_routing_adblock_rule_set balancer
        log "Adblock diaktifkan ke balancer ${ADBLOCK_BALANCER_TAG} (${ADBLOCK_GEOSITE_ENTRY})"
        pause
        ;;
      2)
        xray_routing_adblock_rule_set off
        log "Adblock dinonaktifkan (rule dihapus: ${ADBLOCK_GEOSITE_ENTRY})"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_global_menu() {
  while true; do
    title
    echo "WARP Controls > WARP Global"
    hr
    printf "Status WARP Global: %s\n" "$(warp_global_mode_pretty_get)"
    hr
    echo "  1) direct"
    echo "  2) warp"
    echo "  0) kembali"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        xray_routing_default_rule_set direct
        log "WARP Global di-set ke DIRECT"
        pause
        return 0
        ;;
      2)
        xray_routing_default_rule_set warp
        log "WARP Global di-set ke WARP"
        pause
        return 0
        ;;
      0|kembali|k|back|b) return 0 ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_user_set_effective_mode() {
  local email="$1"
  local desired="$2" # direct|warp

  if is_default_xray_email_or_tag "${email}"; then
    warn "User default Xray bersifat readonly: ${email}"
    return 0
  fi

  local in_warp="no"
  local in_direct="no"
  if xray_routing_rule_user_list_get "dummy-warp-user" "warp" 2>/dev/null | grep -Fxq "${email}"; then
    in_warp="yes"
  fi
  if xray_routing_rule_user_list_get "dummy-direct-user" "direct" 2>/dev/null | grep -Fxq "${email}"; then
    in_direct="yes"
  fi

  case "${desired}" in
    direct)
      if [[ "${in_warp}" == "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-warp-user" "warp" "${email}" off
      fi
      if [[ "${in_direct}" != "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-direct-user" "direct" "${email}" on
      fi
      ;;
    warp)
      if [[ "${in_direct}" == "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-direct-user" "direct" "${email}" off
      fi
      if [[ "${in_warp}" != "yes" ]]; then
        xray_routing_rule_toggle_user_outbound "dummy-warp-user" "warp" "${email}" on
      fi
      ;;
    *) warn "Mode user harus direct|warp" ;;
  esac
}


warp_per_user_menu() {
  need_python3

  local page=0
  local page_size=10

  while true; do
    mapfile -t all_users_raw < <(xray_inbounds_all_client_emails_get 2>/dev/null || true)

    local all_users=()
    local u
    for u in "${all_users_raw[@]}"; do
      if is_default_xray_email_or_tag "${u}"; then
        continue
      fi
      all_users+=("${u}")
    done

    if (( ${#all_users[@]} == 0 )); then
      title
      echo "WARP Controls > WARP per-user"
      hr
      warn "Tidak menemukan user non-default dari config inbounds."
      hr
      pause
      return 0
    fi

    mapfile -t warp_override < <(xray_routing_rule_user_list_get "dummy-warp-user" "warp" 2>/dev/null || true)
    mapfile -t direct_override < <(xray_routing_rule_user_list_get "dummy-direct-user" "direct" 2>/dev/null || true)

    declare -A warp_set=()
    declare -A direct_set=()

    for u in "${warp_override[@]}"; do
      [[ -n "${u}" ]] && warp_set["${u}"]=1
    done
    for u in "${direct_override[@]}"; do
      [[ -n "${u}" ]] && direct_set["${u}"]=1
    done

    local global_mode default_mode
    global_mode="$(warp_global_mode_get || true)"
    case "${global_mode}" in
      warp) default_mode="warp" ;;
      direct) default_mode="direct" ;;
      balancer) default_mode="balancer" ;;
      *) default_mode="unknown" ;;
    esac

    local total pages start end i row email status
    total="${#all_users[@]}"
    pages=$(( (total + page_size - 1) / page_size ))
    if (( page < 0 )); then page=0; fi
    if (( page >= pages )); then page=$((pages - 1)); fi
    start=$((page * page_size))
    end=$((start + page_size))
    if (( end > total )); then end=total; fi

    title
    echo "WARP Controls > WARP per-user"
    hr
    printf "WARP Global: %s
" "$(warp_global_mode_pretty_get)"
    hr
    printf "%-4s %-32s %-7s
" "No" "User" "Status"
    printf "%-4s %-32s %-7s
" "----" "--------------------------------" "-------"

    for (( i=start; i<end; i++ )); do
      row=$((i - start + 1))
      email="${all_users[$i]}"

      if [[ -n "${direct_set[${email}]:-}" ]]; then
        status="direct"
      elif [[ -n "${warp_set[${email}]:-}" ]]; then
        status="warp"
      else
        status="${default_mode}"
      fi

      printf "%-4s %-32s %-7s
" "${row}" "${email}" "${status}"
    done

    echo
    echo "Halaman: $((page + 1))/${pages} | Total user: ${total}"
    if (( pages > 1 )); then
      echo "Toggle: next / previous / 0 kembali"
    else
      echo "Toggle: 0 kembali"
    fi
    hr
    read -r -p "Pilih No untuk ubah (atau next/previous/kembali): " c

    if is_back_choice "${c}"; then
      return 0
    fi

    case "${c}" in
      next|n)
        if (( page < pages - 1 )); then
          page=$((page + 1))
        fi
        continue
        ;;
      previous|prev|p)
        if (( page > 0 )); then
          page=$((page - 1))
        fi
        continue
        ;;
    esac

    if [[ ! "${c}" =~ ^[0-9]+$ ]]; then
      warn "Input tidak valid"
      sleep 1
      continue
    fi

    if (( c < 1 || c > (end - start) )); then
      warn "No di luar range"
      sleep 1
      continue
    fi

    email="${all_users[$((start + c - 1))]}"

    local cur_status
    if [[ -n "${direct_set[${email}]:-}" ]]; then
      cur_status="direct"
    elif [[ -n "${warp_set[${email}]:-}" ]]; then
      cur_status="warp"
    else
      cur_status="${default_mode}"
    fi

    while true; do
      title
      echo "WARP Controls > WARP per-user"
      hr
      echo "User   : ${email}"
      echo "Status : ${cur_status}"
      hr
      echo "  1) direct"
      echo "  2) warp"
      echo "  0) kembali"
      hr
      read -r -p "Pilih: " s

      if is_back_choice "${s}"; then
        break
      fi

      case "${s}" in
        1)
          warp_user_set_effective_mode "${email}" direct
          log "Per-user di-set DIRECT: ${email}"
          pause
          break
          ;;
        2)
          warp_user_set_effective_mode "${email}" warp
          log "Per-user di-set WARP: ${email}"
          pause
          break
          ;;
        *) warn "Pilihan tidak valid" ; sleep 1 ;;
      esac
    done
  done
}


warp_inbound_set_effective_mode() {
  local tag="$1"
  local desired="$2" # direct|warp

  if [[ "${tag}" == "api" ]]; then
    warn "Inbound internal (api) bersifat readonly: ${tag}"
    return 0
  fi

  local in_warp="no"
  local in_direct="no"
  if xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" 2>/dev/null | grep -Fxq "${tag}"; then
    in_warp="yes"
  fi
  if xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" 2>/dev/null | grep -Fxq "${tag}"; then
    in_direct="yes"
  fi

  case "${desired}" in
    direct)
      if [[ "${in_warp}" == "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-warp-inbounds" "warp" "${tag}" off
      fi
      if [[ "${in_direct}" != "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-direct-inbounds" "direct" "${tag}" on
      fi
      ;;
    warp)
      if [[ "${in_direct}" == "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-direct-inbounds" "direct" "${tag}" off
      fi
      if [[ "${in_warp}" != "yes" ]]; then
        xray_routing_rule_toggle_inbounds_outbound "dummy-warp-inbounds" "warp" "${tag}" on
      fi
      ;;
    *) warn "Mode inbound harus direct|warp" ;;
  esac
}


warp_per_inbounds_menu() {
  need_python3

  while true; do
    mapfile -t all_tags_raw < <(xray_inbounds_all_tags_get 2>/dev/null || true)

    local tags=()
    local t
    for t in "${all_tags_raw[@]}"; do
      if [[ "${t}" == "api" ]]; then
        continue
      fi
      tags+=("${t}")
    done

    if (( ${#tags[@]} == 0 )); then
      title
      echo "WARP Controls > WARP per-protocol inbounds"
      hr
      warn "Tidak ada inbound yang bisa diatur."
      hr
      pause
      return 0
    fi

    mapfile -t warp_override < <(xray_routing_rule_inbound_list_get "dummy-warp-inbounds" "warp" 2>/dev/null || true)
    mapfile -t direct_override < <(xray_routing_rule_inbound_list_get "dummy-direct-inbounds" "direct" 2>/dev/null || true)

    declare -A warp_set=()
    declare -A direct_set=()

    for t in "${warp_override[@]}"; do
      [[ -n "${t}" ]] && warp_set["${t}"]=1
    done
    for t in "${direct_override[@]}"; do
      [[ -n "${t}" ]] && direct_set["${t}"]=1
    done

    local global_mode default_mode
    global_mode="$(warp_global_mode_get || true)"
    case "${global_mode}" in
      warp) default_mode="warp" ;;
      direct) default_mode="direct" ;;
      balancer) default_mode="balancer" ;;
      *) default_mode="unknown" ;;
    esac

    title
    echo "WARP Controls > WARP per-protocol inbounds"
    hr
    printf "WARP Global: %s
" "$(warp_global_mode_pretty_get)"
    hr
    printf "%-4s %-28s %-7s
" "No" "Protocol (Inbound Tag)" "Status"
    printf "%-4s %-28s %-7s
" "----" "----------------------------" "-------"

    local i status
    for (( i=0; i<${#tags[@]}; i++ )); do
      t="${tags[$i]}"

      if [[ -n "${direct_set[${t}]:-}" ]]; then
        status="direct"
      elif [[ -n "${warp_set[${t}]:-}" ]]; then
        status="warp"
      else
        status="${default_mode}"
      fi

      printf "%-4s %-28s %-7s
" "$((i + 1))" "${t}" "${status}"
    done

    hr
    echo "Pilih No untuk ubah (direct/warp), atau 0 kembali"
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      return 0
    fi

    if [[ ! "${c}" =~ ^[0-9]+$ ]]; then
      warn "Input tidak valid"
      sleep 1
      continue
    fi
    if (( c < 1 || c > ${#tags[@]} )); then
      warn "No di luar range"
      sleep 1
      continue
    fi

    t="${tags[$((c - 1))]}"

    local cur_status
    if [[ -n "${direct_set[${t}]:-}" ]]; then
      cur_status="direct"
    elif [[ -n "${warp_set[${t}]:-}" ]]; then
      cur_status="warp"
    else
      cur_status="${default_mode}"
    fi

    while true; do
      title
      echo "WARP Controls > WARP per-protocol inbounds"
      hr
      echo "Inbound : ${t}"
      echo "Status  : ${cur_status}"
      hr
      echo "  1) direct"
      echo "  2) warp"
      echo "  0) kembali"
      hr
      read -r -p "Pilih: " s

      if is_back_choice "${s}"; then
        break
      fi

      case "${s}" in
        1)
          warp_inbound_set_effective_mode "${t}" direct
          log "Per-inbounds di-set DIRECT: ${t}"
          pause
          break
          ;;
        2)
          warp_inbound_set_effective_mode "${t}" warp
          log "Per-inbounds di-set WARP: ${t}"
          pause
          break
          ;;
        *) warn "Pilihan tidak valid" ; sleep 1 ;;
      esac
    done
  done
}


warp_domain_geosite_menu() {
  need_python3

  local mode="direct"

  while true; do
    title
    echo "WARP Controls > WARP per-Geosite/Domain"
    hr
    echo "Status: ${mode}"
    hr

    echo "Readonly (template) geosite:"
    xray_routing_readonly_geosite_rule_print || true
    hr

    local header ent
    local -a lst_raw=()
    local -a lst=()

    if [[ "${mode}" == "warp" ]]; then
      header="Custom WARP list:"
      mapfile -t lst_raw < <(xray_routing_custom_domain_list_get "regexp:^\$WARP" "warp" 2>/dev/null || true)
    else
      header="Custom DIRECT list:"
      mapfile -t lst_raw < <(xray_routing_custom_domain_list_get "regexp:^$" "direct" 2>/dev/null || true)
    fi

    for ent in "${lst_raw[@]}"; do
      lst+=("${ent}")
    done

    echo "${header}"
    if (( ${#lst[@]} == 0 )); then
      echo "  (kosong)"
    else
      local i
      for (( i=0; i<${#lst[@]}; i++ )); do
        ent="${lst[$i]}"
        if is_readonly_geosite_domain "${ent}"; then
          printf "  %2d. %s (readonly)\n" "$((i + 1))" "${ent}"
        else
          printf "  %2d. %s\n" "$((i + 1))" "${ent}"
        fi
      done
    fi
    hr

    echo "  1) direct"
    echo "  2) warp"
    echo "  3) tambah domain"
    echo "  4) hapus domain"
    echo "  0) kembali"
    hr
    read -r -p "Pilih: " c

    if is_back_choice "${c}"; then
      break
    fi

    case "${c}" in
      1) mode="direct" ;;
      2) mode="warp" ;;
      3)
        read -r -p "Entry (contoh: geosite:twitter / example.com) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"
        if [[ -z "${ent}" || "${ent}" == "regexp:^$" || "${ent}" == "regexp:^\$WARP" ]]; then
          warn "Entry tidak valid / reserved"
          pause
          continue
        fi
        if is_readonly_geosite_domain "${ent}"; then
          warn "Readonly geosite tidak boleh diubah dari menu ini: ${ent}"
          pause
          continue
        fi
        xray_routing_custom_domain_entry_set_mode "${mode}" "${ent}"
        log "Entry di-set ${mode^^}: ${ent}"
        pause
        ;;
      4)
        if (( ${#lst[@]} == 0 )); then
          warn "List kosong"
          pause
          continue
        fi
        read -r -p "Entry yang dihapus (No atau teks) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"

        if [[ "${ent}" =~ ^[0-9]+$ ]]; then
          if (( ent < 1 || ent > ${#lst[@]} )); then
            warn "No tidak ditemukan"
            pause
            continue
          fi
          ent="${lst[$((ent - 1))]}"
        fi

        if [[ -z "${ent}" || "${ent}" == "regexp:^$" || "${ent}" == "regexp:^\$WARP" ]]; then
          warn "Entry tidak valid / reserved"
          pause
          continue
        fi
        if is_readonly_geosite_domain "${ent}"; then
          warn "Readonly geosite tidak bisa dihapus dari menu ini: ${ent}"
          pause
          continue
        fi

        xray_routing_custom_domain_entry_set_mode off "${ent}"
        log "Entry dihapus (OFF): ${ent}"
        pause
        ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}



warp_tier_state_target_get() {
  local raw
  raw="$(network_state_get "${WARP_TIER_STATE_KEY}" 2>/dev/null || true)"
  raw="$(echo "${raw}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "${raw}" in
    free|plus) echo "${raw}" ;;
    *) echo "unknown" ;;
  esac
}

warp_plus_license_state_get() {
  network_state_get "${WARP_PLUS_LICENSE_STATE_KEY}" 2>/dev/null | tr -d '\r' || true
}

warp_plus_license_mask() {
  local key="${1:-}"
  local len
  key="$(echo "${key}" | tr -d '[:space:]')"
  len="${#key}"
  if (( len <= 8 )); then
    echo "${key}"
    return 0
  fi
  echo "${key:0:4}****${key:len-4:4}"
}

warp_trace_field_get() {
  # args: field_name
  local field="${1:-}"
  local bind_addr trace
  [[ -n "${field}" ]] || return 0
  [[ -f "${WIREPROXY_CONF}" ]] || return 0
  if ! have_cmd curl; then
    return 0
  fi
  bind_addr="$(awk -F'=' '
    /^[[:space:]]*BindAddress[[:space:]]*=/ {
      v=$2
      gsub(/[[:space:]]/, "", v)
      print v
      exit
    }
  ' "${WIREPROXY_CONF}" 2>/dev/null || true)"
  [[ -n "${bind_addr}" ]] || bind_addr="127.0.0.1:40000"

  trace="$(curl -fsS --max-time 8 --socks5 "${bind_addr}" "https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null || true)"
  [[ -n "${trace}" ]] || return 0
  echo "${trace}" | awk -F= -v k="${field}" '$1==k {print $2; exit}'
}

warp_live_tier_get() {
  local warpv
  warpv="$(warp_trace_field_get warp | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "${warpv}" in
    plus) echo "plus" ;;
    on) echo "free" ;;
    off) echo "off" ;;
    *) echo "unknown" ;;
  esac
}

warp_wireproxy_socks_block_get() {
  if [[ ! -f "${WIREPROXY_CONF}" ]]; then
    cat <<'EOF'
[Socks5]
BindAddress = 127.0.0.1:40000
EOF
    return 0
  fi

  awk '
    BEGIN { inblk=0; found=0 }
    /^[[:space:]]*\[(Socks|Socks5)\][[:space:]]*$/ {
      inblk=1
      if (found==0) {
        print "[Socks5]"
        found=1
      }
      next
    }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      inblk=0
      next
    }
    inblk { print; next }
    END {
      if (found==0) {
        print "[Socks5]"
        print "BindAddress = 127.0.0.1:40000"
      }
    }
  ' "${WIREPROXY_CONF}" 2>/dev/null
}

warp_wireproxy_apply_profile() {
  # args: wgcf_profile_path
  local profile="${1:-}"
  local tmp backup socks_block ts
  [[ -n "${profile}" && -f "${profile}" ]] || {
    warn "Profile wgcf tidak ditemukan: ${profile}"
    return 1
  }

  mkdir -p "$(dirname "${WIREPROXY_CONF}")"
  tmp="$(mktemp)"
  socks_block="$(warp_wireproxy_socks_block_get)"

  awk '
    BEGIN { drop=0 }
    /^[[:space:]]*\[(Socks|Socks5)\][[:space:]]*$/ { drop=1; next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { drop=0 }
    drop { next }
    { print }
  ' "${profile}" > "${tmp}"
  printf "\n%s\n" "${socks_block}" >> "${tmp}"

  if [[ -f "${WIREPROXY_CONF}" ]]; then
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="${WIREPROXY_CONF}.bak.${ts}"
    cp -f "${WIREPROXY_CONF}" "${backup}" 2>/dev/null || true
  fi

  if ! install -m 600 "${tmp}" "${WIREPROXY_CONF}"; then
    rm -f "${tmp}" 2>/dev/null || true
    warn "Gagal menulis wireproxy config: ${WIREPROXY_CONF}"
    return 1
  fi
  rm -f "${tmp}" 2>/dev/null || true
  return 0
}

warp_wgcf_register_noninteractive() {
  local reg_log
  reg_log="$(mktemp "/tmp/wgcf-register-manage.XXXXXX.log")"

  mkdir -p "${WGCF_DIR}"
  pushd "${WGCF_DIR}" >/dev/null || {
    warn "Gagal masuk ke ${WGCF_DIR}"
    return 1
  }

  if [[ -f "wgcf-account.toml" ]]; then
    popd >/dev/null || true
    return 0
  fi

  if have_cmd expect; then
    expect <<'EOF' >"${reg_log}" 2>&1 || true
set timeout 180
log_user 1
spawn wgcf register
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
    set +o pipefail
    yes | wgcf register >"${reg_log}" 2>&1 || true
    set -o pipefail
  fi

  popd >/dev/null || true
  if [[ ! -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    warn "wgcf register gagal. Log: ${reg_log}"
    tail -n 60 "${reg_log}" >&2 || true
    return 1
  fi
  rm -f "${reg_log}" >/dev/null 2>&1 || true
  return 0
}

warp_wgcf_build_profile() {
  # args: tier [license_key]
  local tier="${1:-free}"
  local license_key="${2:-}"
  local gen_log upd_log
  gen_log="$(mktemp "/tmp/wgcf-generate-manage.XXXXXX.log")"
  upd_log="$(mktemp "/tmp/wgcf-update-manage.XXXXXX.log")"

  mkdir -p "${WGCF_DIR}"
  if [[ ! -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    if ! warp_wgcf_register_noninteractive; then
      return 1
    fi
  fi

  pushd "${WGCF_DIR}" >/dev/null || {
    warn "Gagal masuk ke ${WGCF_DIR}"
    return 1
  }

  if [[ "${tier}" == "plus" ]]; then
    license_key="$(echo "${license_key}" | tr -d '[:space:]')"
    if [[ -z "${license_key}" ]]; then
      popd >/dev/null || true
      warn "License key WARP+ kosong"
      return 1
    fi
    if ! wgcf update --license-key "${license_key}" >"${upd_log}" 2>&1; then
      popd >/dev/null || true
      warn "wgcf update --license-key gagal. Log: ${upd_log}"
      tail -n 60 "${upd_log}" >&2 || true
      return 1
    fi
  fi

  if ! wgcf generate -p "${WGCF_DIR}/wgcf-profile.conf" >"${gen_log}" 2>&1; then
    popd >/dev/null || true
    warn "wgcf generate gagal. Log: ${gen_log}"
    tail -n 60 "${gen_log}" >&2 || true
    return 1
  fi
  popd >/dev/null || true

  if [[ ! -s "${WGCF_DIR}/wgcf-profile.conf" ]]; then
    warn "wgcf-profile.conf tidak ditemukan setelah generate"
    return 1
  fi
  rm -f "${gen_log}" "${upd_log}" >/dev/null 2>&1 || true
  return 0
}

warp_tier_show_status() {
  local target live svc_state license_raw license_masked
  target="$(warp_tier_state_target_get)"
  live="$(warp_live_tier_get)"
  license_raw="$(warp_plus_license_state_get)"
  license_masked="$(warp_plus_license_mask "${license_raw}")"
  if svc_exists wireproxy; then
    svc_state="$(svc_state wireproxy)"
  else
    svc_state="not-installed"
  fi

  printf "Target Tier   : %s\n" "${target}"
  printf "Live Tier     : %s\n" "${live}"
  printf "wireproxy     : %s\n" "${svc_state}"
  if [[ -n "${license_raw}" ]]; then
    printf "WARP+ License : %s\n" "${license_masked}"
  else
    printf "WARP+ License : (kosong)\n"
  fi
}

warp_tier_switch_free() {
  title
  echo "4) Network Controls > WARP Controls > Switch ke WARP Free"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  mkdir -p "${WGCF_DIR}"
  if [[ -f "${WGCF_DIR}/wgcf-account.toml" ]]; then
    cp -f "${WGCF_DIR}/wgcf-account.toml" "${WGCF_DIR}/wgcf-account.toml.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  fi
  rm -f "${WGCF_DIR}/wgcf-account.toml" "${WGCF_DIR}/wgcf-profile.conf" 2>/dev/null || true

  if ! warp_wgcf_register_noninteractive; then
    hr
    pause
    return 0
  fi
  if ! warp_wgcf_build_profile free; then
    hr
    pause
    return 0
  fi
  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  network_state_set "${WARP_TIER_STATE_KEY}" "free"
  log "WARP tier target di-set: free"
  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_switch_plus() {
  local saved_key key masked
  title
  echo "4) Network Controls > WARP Controls > Switch ke WARP Plus"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  saved_key="$(warp_plus_license_state_get)"
  masked="$(warp_plus_license_mask "${saved_key}")"
  if [[ -n "${saved_key}" ]]; then
    echo "License tersimpan: ${masked}"
    read -r -p "Input WARP+ License Key (Enter=pakai tersimpan, atau kembali): " key
    if is_back_choice "${key}"; then
      return 0
    fi
    key="$(echo "${key}" | tr -d '[:space:]')"
    [[ -n "${key}" ]] || key="${saved_key}"
  else
    read -r -p "Input WARP+ License Key (atau kembali): " key
    if is_back_choice "${key}"; then
      return 0
    fi
    key="$(echo "${key}" | tr -d '[:space:]')"
  fi

  if [[ -z "${key}" ]]; then
    warn "License key WARP+ kosong"
    hr
    pause
    return 0
  fi

  if ! warp_wgcf_build_profile plus "${key}"; then
    hr
    pause
    return 0
  fi
  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  network_state_set "${WARP_TIER_STATE_KEY}" "plus"
  network_state_set "${WARP_PLUS_LICENSE_STATE_KEY}" "${key}"
  log "WARP tier target di-set: plus"
  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_reconnect_regenerate() {
  local target key
  title
  echo "4) Network Controls > WARP Controls > Reconnect/Regenerate"
  hr

  if ! have_cmd wgcf; then
    warn "wgcf tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi
  if ! have_cmd wireproxy; then
    warn "wireproxy tidak ditemukan. Jalankan setup.sh terlebih dulu."
    hr
    pause
    return 0
  fi

  target="$(warp_tier_state_target_get)"
  if [[ "${target}" != "free" && "${target}" != "plus" ]]; then
    target="free"
  fi

  if [[ "${target}" == "plus" ]]; then
    key="$(warp_plus_license_state_get)"
    key="$(echo "${key}" | tr -d '[:space:]')"
    if [[ -z "${key}" ]]; then
      warn "Target plus aktif, tapi license key kosong. Gunakan menu Switch ke WARP Plus dulu."
      hr
      pause
      return 0
    fi
    if ! warp_wgcf_build_profile plus "${key}"; then
      hr
      pause
      return 0
    fi
  else
    if ! warp_wgcf_build_profile free; then
      hr
      pause
      return 0
    fi
  fi

  if ! warp_wireproxy_apply_profile "${WGCF_DIR}/wgcf-profile.conf"; then
    hr
    pause
    return 0
  fi

  if svc_exists wireproxy; then
    svc_restart wireproxy || true
  else
    warn "wireproxy.service tidak terdeteksi"
  fi
  log "Reconnect/regenerate selesai untuk target tier: ${target}"
  hr
  warp_tier_show_status
  hr
  pause
}

warp_tier_menu() {
  while true; do
    title
    echo "4) Network Controls > WARP Controls > WARP Tier (Free/Plus)"
    hr
    warp_tier_show_status
    hr
    echo "  1) Show status"
    echo "  2) Switch ke WARP Free"
    echo "  3) Switch ke WARP Plus"
    echo "  4) Reconnect/Regenerate sesuai target"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        title
        echo "4) Network Controls > WARP Controls > WARP Tier Status"
        hr
        warp_tier_show_status
        hr
        pause
        ;;
      2) warp_tier_switch_free ;;
      3) warp_tier_switch_plus ;;
      4) warp_tier_reconnect_regenerate ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

warp_controls_menu() {
  while true; do
    title
    echo "4) Network Controls > WARP Controls"
    hr
    echo "  1) WARP (wireproxy) status"
    echo "  2) Restart WARP (wireproxy)"
    echo "  3) WARP Global"
    echo "  4) WARP per-user"
    echo "  5) WARP per-protocol inbounds"
    echo "  6) WARP per-Geosite/Domain"
    echo "  7) WARP Tier (Free/Plus)"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) warp_status ;;
      2)
        title
        echo "Restart wireproxy"
        hr
        if svc_exists wireproxy; then
          svc_restart wireproxy || true
        else
          warn "wireproxy.service tidak terdeteksi"
        fi
        hr
        pause
        ;;
      3) warp_global_menu ;;
      4) warp_per_user_menu ;;
      5) warp_per_inbounds_menu ;;
      6) warp_domain_geosite_menu ;;
      7) warp_tier_menu ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

domain_geosite_menu() {
  need_python3
  while true; do
    title
    echo "4) Network Controls > Domain/Geosite Routing (Direct List)"
    hr
    echo "Template (readonly):"
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
tpl=None
for r in rules:
  if not isinstance(r, dict):
    continue
  if r.get('type') != 'field':
    continue
  if r.get('outboundTag') != 'direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
    tpl=dom
    break
if not isinstance(tpl, list):
  tpl=[]
for i,d in enumerate([x for x in tpl if isinstance(x,str)] , start=1):
  print(f"  {i:>2}. {d}")
PY
    hr

    echo "Editable (custom direct list):"
    python3 - <<'PY' "${XRAY_ROUTING_CONF}" 2>/dev/null || true
import json, sys
src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)
rules=((cfg.get('routing') or {}).get('rules') or [])
custom=None
for r in rules:
  if not isinstance(r, dict): 
    continue
  if r.get('type')!='field':
    continue
  if r.get('outboundTag')!='direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom=[x for x in dom if isinstance(x,str) and x!='regexp:^$']
    break
if not isinstance(custom, list):
  custom=[]
if not custom:
  print("  (kosong)")
else:
  for i,d in enumerate(custom, start=1):
    print(f"  {i:>2}. {d}")
PY
    hr

    echo "  1) Add domain/geosite ke custom list"
    echo "  2) Remove domain/geosite dari custom list"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Masukkan entry (contoh: geosite:twitter / example.com) (atau kembali): " ent
        if is_back_choice "${ent}"; then
          continue
        fi
        ent="$(echo "${ent}" | tr -d '[:space:]')"
        if [[ -z "${ent}" ]]; then
          warn "Entry kosong"
          pause
          continue
        fi
        if [[ "${ent}" == "regexp:^$" ]]; then
          warn "Entry reserved"
          pause
          continue
        fi
        need_python3
        ensure_path_writable "${XRAY_ROUTING_CONF}"
        local backup tmp rc
        backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
        tmp="${WORK_DIR}/30-routing.json.tmp"
        set +e
        (
          flock -x 200
          cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
          python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${ent}" || exit 1
import json, sys
src, dst, ent = sys.argv[1:4]
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

# Find template direct rule
tpl_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type')!='field': continue
  if r.get('outboundTag')!='direct': continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and ('geosite:apple' in dom or 'geosite:google' in dom):
    tpl_idx=i
    break

# Find/create custom rule
custom_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): continue
  if r.get('type')!='field': continue
  if r.get('outboundTag')!='direct': continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom_idx=i
    break

if custom_idx is None:
  newr={"type":"field","domain":["regexp:^$"],"outboundTag":"direct"}
  insert_at = (tpl_idx + 1) if tpl_idx is not None else len(rules)
  rules.insert(insert_at, newr)
  custom_idx=insert_at

r=rules[custom_idx]
dom=r.get('domain') or []
if not isinstance(dom, list):
  dom=[]
if 'regexp:^$' not in dom:
  dom.insert(0,'regexp:^$')
if ent not in dom:
  dom.append(ent)
r['domain']=dom
rules[custom_idx]=r

routing['rules']=rules
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
          xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
            restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
            exit 1
          }
          svc_restart xray || true
          if ! svc_wait_active xray 20; then
            restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
            systemctl restart xray || true
            exit 86
          fi
        ) 200>"${ROUTING_LOCK_FILE}"
        rc=$?
        set -e
        xray_txn_rc_or_die "${rc}" \
          "Gagal update routing (rollback ke backup: ${backup})" \
          "xray tidak aktif setelah tambah custom domain direct. Config di-rollback ke backup: ${backup}"
        log "Entry ditambahkan: ${ent}"
        pause
        ;;
      2)
        read -r -p "Hapus nomor entry (lihat daftar) (atau kembali): " no
        if is_back_word_choice "${no}"; then
          continue
        fi
        if [[ -z "${no}" || ! "${no}" =~ ^[0-9]+$ || "${no}" -le 0 ]]; then
          warn "Nomor tidak valid"
          pause
          continue
        fi
        need_python3
        ensure_path_writable "${XRAY_ROUTING_CONF}"
        local backup tmp rc
        backup="$(xray_backup_path_prepare "${XRAY_ROUTING_CONF}")"
        tmp="${WORK_DIR}/30-routing.json.tmp"
        set +e
        (
          flock -x 200
          cp -a "${XRAY_ROUTING_CONF}" "${backup}" || exit 1
          python3 - <<'PY' "${XRAY_ROUTING_CONF}" "${tmp}" "${no}" || exit 1
import json, sys
src, dst, no = sys.argv[1:4]
no=int(no)
with open(src,'r',encoding='utf-8') as f:
  cfg=json.load(f)
routing=(cfg.get('routing') or {})
rules=routing.get('rules')
if not isinstance(rules, list):
  raise SystemExit("Invalid routing.rules")

custom_idx=None
for i,r in enumerate(rules):
  if not isinstance(r, dict): 
    continue
  if r.get('type')!='field':
    continue
  if r.get('outboundTag')!='direct':
    continue
  dom=r.get('domain') or []
  if isinstance(dom, list) and 'regexp:^$' in dom:
    custom_idx=i
    break
if custom_idx is None:
  raise SystemExit("Custom list belum ada")

r=rules[custom_idx]
dom=[x for x in (r.get('domain') or []) if isinstance(x,str)]
entries=[x for x in dom if x!='regexp:^$']
if no > len(entries):
  raise SystemExit("Nomor di luar range")
target=entries[no-1]
dom=[x for x in dom if x!=target]
# Ensure marker exists
if 'regexp:^$' not in dom:
  dom.insert(0,'regexp:^$')
r['domain']=dom
rules[custom_idx]=r

routing['rules']=rules
cfg['routing']=routing
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
          xray_write_file_atomic "${XRAY_ROUTING_CONF}" "${tmp}" || {
            restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
            exit 1
          }
          svc_restart xray || true
          if ! svc_wait_active xray 20; then
            restore_file_if_exists "${backup}" "${XRAY_ROUTING_CONF}"
            systemctl restart xray || true
            exit 86
          fi
        ) 200>"${ROUTING_LOCK_FILE}"
        rc=$?
        set -e
        xray_txn_rc_or_die "${rc}" \
          "Gagal update routing (rollback ke backup: ${backup})" \
          "xray tidak aktif setelah hapus custom domain direct. Config di-rollback ke backup: ${backup}"
        log "Entry dihapus"
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}


# -------------------------
# DNS Settings
# -------------------------
xray_dns_status_get() {
  # output:
  # primary=<...>
  # secondary=<...>
  # strategy=<...>
  # cache=on|off
  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    echo "primary="
    echo "secondary="
    echo "strategy="
    echo "cache=on"
    return 0
  fi

  python3 - <<'PY' "${XRAY_DNS_CONF}" 2>/dev/null || true
import json, sys

src=sys.argv[1]
try:
  with open(src,'r',encoding='utf-8') as f:
    cfg=json.load(f)
except Exception:
  raise SystemExit(0)

dns=cfg.get('dns') or {}
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers') or []
if not isinstance(servers, list):
  servers=[]

def server_addr(s):
  if isinstance(s, str):
    return s
  if isinstance(s, dict):
    a=s.get('address')
    if isinstance(a, str):
      return a
  return ''

primary=server_addr(servers[0]) if len(servers) > 0 else ''
secondary=server_addr(servers[1]) if len(servers) > 1 else ''

qs=dns.get('queryStrategy')
strategy=qs if isinstance(qs, str) else ''

disable_cache=dns.get('disableCache')
cache='off' if bool(disable_cache) else 'on'

print('primary=' + primary)
print('secondary=' + secondary)
print('strategy=' + strategy)
print('cache=' + cache)
PY
}

xray_dns_set_primary() {
  local val="$1"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_DNS_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers')
if not isinstance(servers, list):
  servers=[]

def set_server(idx, v):
  while len(servers) <= idx:
    servers.append("")
  if isinstance(servers[idx], dict):
    servers[idx]['address']=v
  else:
    servers[idx]=v

if val:
  set_server(0, val)

dns['servers']=servers
cfg['dns']=dns

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${DNS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update Primary DNS (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update dns primary. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_dns_set_secondary() {
  local val="$1"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_DNS_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

servers=dns.get('servers')
if not isinstance(servers, list):
  servers=[]

def set_server(idx, v):
  while len(servers) <= idx:
    servers.append("")
  if isinstance(servers[idx], dict):
    servers[idx]['address']=v
  else:
    servers[idx]=v

if val:
  if len(servers) == 0:
    # isi default primary jika kosong
    set_server(0, "1.1.1.1")
  set_server(1, val)

dns['servers']=servers
cfg['dns']=dns

with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${DNS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update Secondary DNS (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update dns secondary. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_dns_set_query_strategy() {
  local val="$1"
  local tmp backup rc

  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_DNS_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}" "${val}"
import json, sys

src, dst, val = sys.argv[1:4]
val=str(val).strip()

with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

if val:
  dns['queryStrategy']=val

cfg['dns']=dns
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${DNS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal update Query Strategy (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update dns queryStrategy. Config di-rollback ke backup: ${backup}"
  return 0
}

xray_dns_toggle_cache() {
  local tmp backup rc
  need_python3

  if [[ ! -f "${XRAY_DNS_CONF}" ]]; then
    install -m 600 -o root -g root /dev/null "${XRAY_DNS_CONF}"
    echo '{"dns":{}}' > "${XRAY_DNS_CONF}"
  fi

  ensure_path_writable "${XRAY_DNS_CONF}"
  backup="$(xray_backup_path_prepare "${XRAY_DNS_CONF}")"
  tmp="${WORK_DIR}/02-dns.json.tmp"

  set +e
  (
    flock -x 200
    cp -a "${XRAY_DNS_CONF}" "${backup}" || exit 1
    python3 - <<'PY' "${XRAY_DNS_CONF}" "${tmp}"
import json, sys

src, dst = sys.argv[1:3]
with open(src,'r',encoding='utf-8') as f:
  try:
    cfg=json.load(f)
  except Exception:
    cfg={}

if not isinstance(cfg, dict):
  cfg={}

dns=cfg.get('dns')
if not isinstance(dns, dict):
  dns={}

cur=bool(dns.get('disableCache'))
dns['disableCache']=not cur

cfg['dns']=dns
with open(dst,'w',encoding='utf-8') as f:
  json.dump(cfg,f,ensure_ascii=False,indent=2)
  f.write("\n")
PY
    xray_write_file_atomic "${XRAY_DNS_CONF}" "${tmp}" || {
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      exit 1
    }
    svc_restart xray || true
    if ! svc_wait_active xray 20; then
      restore_file_if_exists "${backup}" "${XRAY_DNS_CONF}"
      systemctl restart xray || true
      exit 86
    fi
  ) 200>"${DNS_LOCK_FILE}"
  rc=$?
  set -e

  xray_txn_rc_or_die "${rc}" \
    "Gagal toggle DNS cache (rollback ke backup: ${backup})" \
    "xray tidak aktif setelah update dns cache. Config di-rollback ke backup: ${backup}"
  return 0
}

dns_show_status() {
  local primary secondary strategy cache
  primary="$(xray_dns_status_get | awk -F'=' '/^primary=/{print $2; exit}' 2>/dev/null || true)"
  secondary="$(xray_dns_status_get | awk -F'=' '/^secondary=/{print $2; exit}' 2>/dev/null || true)"
  strategy="$(xray_dns_status_get | awk -F'=' '/^strategy=/{print $2; exit}' 2>/dev/null || true)"
  cache="$(xray_dns_status_get | awk -F'=' '/^cache=/{print $2; exit}' 2>/dev/null || true)"

  if [[ "${cache}" == "on" ]]; then
    cache="ON"
  else
    cache="OFF"
  fi

  [[ -n "${primary}" ]] || primary="-"
  [[ -n "${secondary}" ]] || secondary="-"
  [[ -n "${strategy}" ]] || strategy="-"

  title
  echo "DNS Status"
  hr
  echo
  printf "Primary DNS     : %s\n" "${primary}"
  printf "Secondary DNS   : %s\n" "${secondary}"
  printf "Query Strategy  : %s\n" "${strategy}"
  printf "Cache           : %s\n" "${cache}"
  echo
  hr
  pause
}

dns_settings_menu() {
  while true; do
    title
    echo "4) Network Controls > DNS Settings"
    hr
    echo "  1) Set Primary DNS"
    echo "  2) Set Secondary DNS"
    echo "  3) Set Query Strategy"
    echo "  4) Toggle DNS Cache"
    echo "  5) Show DNS Status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        read -r -p "Primary DNS (contoh 1.1.1.1) (atau kembali): " d
        if is_back_choice "${d}"; then
          continue
        fi
        d="$(echo "${d}" | tr -d '[:space:]')"
        [[ -n "${d}" ]] || { warn "Primary DNS kosong" ; pause ; continue ; }
        xray_dns_set_primary "${d}"
        log "Primary DNS updated"
        pause
        ;;
      2)
        read -r -p "Secondary DNS (contoh 8.8.8.8) (atau kembali): " d
        if is_back_choice "${d}"; then
          continue
        fi
        d="$(echo "${d}" | tr -d '[:space:]')"
        [[ -n "${d}" ]] || { warn "Secondary DNS kosong" ; pause ; continue ; }
        xray_dns_set_secondary "${d}"
        log "Secondary DNS updated"
        pause
        ;;
      3)
        read -r -p "Query Strategy (UseIP/UseIPv4/UseIPv6/PreferIPv4/PreferIPv6) (atau kembali): " qs
        if is_back_choice "${qs}"; then
          continue
        fi
        qs="$(echo "${qs}" | tr -d '[:space:]')"
        case "${qs}" in
          UseIP|UseIPv4|UseIPv6|PreferIPv4|PreferIPv6)
            xray_dns_set_query_strategy "${qs}"
            log "Query Strategy updated: ${qs}"
            pause
            ;;
          *)
            warn "Query Strategy tidak valid"
            pause
            ;;
        esac
        ;;
      4)
        xray_dns_toggle_cache
        log "DNS Cache toggled"
        pause
        ;;
      5) dns_show_status ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

dns_addons_menu() {
  while true; do
    title
    echo "4) Network Controls > DNS Add-ons"
    hr
    if [[ -f "${XRAY_DNS_CONF}" ]]; then
      echo "DNS conf: ${XRAY_DNS_CONF}"
      echo "Tip: gunakan editor untuk perubahan advanced (nano)."
      hr
      sed -n '1,200p' "${XRAY_DNS_CONF}" || true
      hr
    else
      warn "DNS conf tidak ditemukan: ${XRAY_DNS_CONF}"
      hr
    fi
    echo "  1) Open DNS config with nano"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1)
        if have_cmd nano; then
          nano "${XRAY_DNS_CONF}"
          svc_restart xray || true
          if ! svc_wait_active xray 20; then
            warn "xray tidak aktif setelah edit manual DNS config."
            systemctl status xray --no-pager 2>/dev/null || true
          fi
          pause
        else
          warn "nano tidak tersedia"
          pause
        fi
        ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

network_diagnostics_menu() {
  while true; do
    title
    echo "4) Network Controls > Diagnostics"
    hr
    echo "  1) Show summary (routing/balancer/observatory)"
    echo "  2) Validate conf.d JSON (jq)"
    echo "  3) xray run -test -confdir (syntax check)"
    echo "  4) Show wireproxy + xray + nginx status"
    echo "  0) Back"
    hr
    read -r -p "Pilih: " c
    case "${c}" in
      1) network_show_summary ;;
      2)
        title
        echo "Validate JSON"
        hr
        check_xray_config_json || true
        hr
        pause
        ;;
      3)
        title
        echo "xray config test (confdir)"
        hr
        if xray_confdir_syntax_test_pretty; then
          log "Syntax conf.d: OK"
        else
          warn "Syntax conf.d: GAGAL"
        fi
        hr
        pause
        ;;
      4)
        title
        echo "Service status (wireproxy, xray, nginx)"
        hr
        if svc_exists wireproxy; then
          systemctl status wireproxy --no-pager || true
        else
          warn "wireproxy.service tidak terdeteksi"
        fi
        hr
        systemctl status xray --no-pager || true
        hr
        systemctl status nginx --no-pager || true
        hr
        pause
        ;;
      0|kembali|k|back|b) break ;;
      *) invalid_choice ;;
    esac
  done
}

network_menu() {
  while true; do
    title
    echo "4) Network Controls"
    hr
    echo "  1) Egress Mode & Balancer"
    echo "  2) WARP Controls"
    echo "  3) DNS Settings"
    echo "  4) DNS Advanced (Editor)"
    echo "  5) Diagnostics"
    echo "  6) Adblock (Custom Geosite)"
    echo "  0) Kembali"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) egress_menu_simple ;;
      2) warp_controls_menu ;;
      3) dns_settings_menu ;;
      4) dns_addons_menu ;;
      5) network_diagnostics_menu ;;
      6) adblock_menu ;;
      0|kembali|k|back|b) break ;;
      *) invalid_choice ;;
    esac
  done
}

# -------------------------
# Speedtest
# -------------------------
speedtest_bin_get() {
  if have_cmd speedtest; then
    echo "speedtest"
    return 0
  fi
  if [[ -x /snap/bin/speedtest ]]; then
    echo "/snap/bin/speedtest"
    return 0
  fi
  echo ""
}

speedtest_run_now() {
  title
  echo "6) Speedtest > Run Speedtest"
  hr

  local speedtest_bin
  speedtest_bin="$(speedtest_bin_get)"
  if [[ -z "${speedtest_bin}" ]]; then
    warn "speedtest belum tersedia. Jalankan setup.sh untuk install speedtest via snap."
    hr
    pause
    return 0
  fi

  echo "Menjalankan: ${speedtest_bin} --accept-license --accept-gdpr"
  echo
  if ! "${speedtest_bin}" --accept-license --accept-gdpr; then
    warn "Speedtest gagal dijalankan."
  fi
  hr
  pause
}

speedtest_show_version() {
  title
  echo "6) Speedtest > Version"
  hr

  local speedtest_bin
  speedtest_bin="$(speedtest_bin_get)"
  if [[ -z "${speedtest_bin}" ]]; then
    warn "speedtest belum tersedia."
    hr
    pause
    return 0
  fi

  if ! "${speedtest_bin}" --version 2>/dev/null; then
    warn "Tidak bisa membaca versi speedtest."
  fi
  hr
  pause
}

speedtest_menu() {
  while true; do
    title
    echo "6) Speedtest"
    hr
    echo "  1) Run Speedtest (Ookla)"
    echo "  2) Show Speedtest Version"
    echo "  0) Kembali"
    hr
    if ! read -r -p "Pilih: " c; then
      echo
      break
    fi
    case "${c}" in
      1) speedtest_run_now ;;
      2) speedtest_show_version ;;
      0|kembali|k|back|b) break ;;
      *) warn "Pilihan tidak valid" ; sleep 1 ;;
    esac
  done
}

# -------------------------
