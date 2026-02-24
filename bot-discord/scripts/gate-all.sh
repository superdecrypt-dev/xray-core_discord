#!/usr/bin/env bash
set -euo pipefail

BOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
REPO_DIR="$(cd -- "${BOT_DIR}/.." >/dev/null 2>&1 && pwd -P)"

PROFILE="${1:-local}"
PROD_INSTANCE="${PROD_INSTANCE:-xray-itg-1771777921}"
STAGING_INSTANCE="${STAGING_INSTANCE:-xray-stg-gate3-1771864485}"

log() {
  printf '[gate-all] %s\n' "$*"
}

die() {
  printf '[gate-all] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "command tidak ditemukan: $1"
}

run_gate_1() {
  log "Gate 1: Static & Build"

  python3 -m py_compile $(find "${BOT_DIR}/backend-py/app" -name '*.py')

  python3 - <<'PY'
import json
from pathlib import Path
p = Path("bot-discord/shared/commands.json")
obj = json.loads(p.read_text(encoding="utf-8"))
print(f"gate1_commands_json_ok menus={len(obj.get('menus', []))}")
PY

  (
    cd "${BOT_DIR}/gateway-ts"
    npm run build
  )
}

run_gate_2() {
  log "Gate 2: API Smoke (service layer)"

  python3 - <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path("bot-discord/backend-py").resolve()))
from app.services import menu_5_domain

settings_on = type("S", (), {"enable_dangerous_actions": True})()
settings_off = type("S", (), {"enable_dangerous_actions": False})()

cases = [
    ("domain_info_success", "domain_info", {}, settings_on, "ok"),
    ("setup_domain_custom_invalid_domain", "setup_domain_custom", {"domain": "abc"}, settings_on, "setup_domain_custom_failed"),
    ("setup_domain_cloudflare_invalid_root", "setup_domain_cloudflare", {"root_domain": "999"}, settings_on, "setup_domain_cloudflare_failed"),
    ("strict_bool_proxied_invalid", "setup_domain_cloudflare", {"root_domain": "999", "proxied": "abc"}, settings_on, "setup_domain_cloudflare_failed"),
    ("dangerous_action_blocked", "setup_domain_custom", {"domain": "vpn.example.com"}, settings_off, "forbidden"),
]

bad = []
for name, action, params, settings, expect_code in cases:
    res = menu_5_domain.handle(action, params, settings)
    ok = bool(res.get("code") == expect_code or (expect_code == "ok" and res.get("ok") is True))
    print(f"gate2_{name}={'PASS' if ok else 'FAIL'} code={res.get('code')} ok={res.get('ok')}")
    if not ok:
        bad.append(name)

original_cf = menu_5_domain.system_mutations.op_domain_setup_cloudflare
captured = {}
contract_ok = False
try:
    def fake_cf(*, root_domain_input, subdomain_mode, subdomain, proxied, allow_existing_same_ip):
        captured["root_domain_input"] = root_domain_input
        captured["subdomain_mode"] = subdomain_mode
        captured["subdomain"] = subdomain
        captured["proxied"] = proxied
        captured["allow_existing_same_ip"] = allow_existing_same_ip
        return True, "Domain Control - Set Domain (Cloudflare Wizard)", "mocked"

    menu_5_domain.system_mutations.op_domain_setup_cloudflare = fake_cf
    res_contract = menu_5_domain.handle(
        "setup_domain_cloudflare",
        {
            "root_domain": "vyxara1.web.id",
            "subdomain_mode": "manual",
            "subdomain": "gate2-test",
            "proxied": "abc",
            "allow_existing_same_ip": "xyz",
        },
        settings_on,
    )
    warnings = ((res_contract.get("data") or {}).get("warnings") or [])
    contract_ok = bool(
        res_contract.get("ok") is True
        and captured.get("proxied") is False
        and captured.get("allow_existing_same_ip") is False
        and isinstance(warnings, list)
        and len(warnings) >= 2
    )
finally:
    menu_5_domain.system_mutations.op_domain_setup_cloudflare = original_cf

print(f"gate2_bool_invalid_warn_default={'PASS' if contract_ok else 'FAIL'}")
if not contract_ok:
    bad.append("bool_invalid_warn_default")

if bad:
    raise SystemExit(f"gate2_failed={','.join(bad)}")
PY
}

run_gate_3() {
  log "Gate 3: Integration non-produksi (local uvicorn HTTP)"

  local log_file="${BOT_DIR}/runtime/logs/backend-gate3-gateall.log"
  (
    cd "${BOT_DIR}/backend-py"
    export INTERNAL_SHARED_SECRET="gate3-gateall-secret"
    export BACKEND_HOST="127.0.0.1"
    export BACKEND_PORT="18082"
    export COMMANDS_FILE="${BOT_DIR}/shared/commands.json"
    export ENABLE_DANGEROUS_ACTIONS="true"
    "${BOT_DIR}/.venv/bin/uvicorn" app.main:app --host "${BACKEND_HOST}" --port "${BACKEND_PORT}" >"${log_file}" 2>&1 &
    local uv_pid="$!"
    trap 'kill "${uv_pid}" >/dev/null 2>&1 || true' EXIT

    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:18082/health" >/dev/null 2>&1; then
        break
      fi
      sleep 0.25
    done

    python3 - <<'PY'
import json
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18082"
SECRET = "gate3-gateall-secret"

def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.getcode(), json.loads(r.read().decode("utf-8", "ignore"))

def post(path, payload, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.getcode(), json.loads(r.read().decode("utf-8", "ignore"))

def get_allow_error(path, headers=None):
    try:
        return get(path, headers)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8", "ignore"))

checks = []
def rec(name, ok):
    checks.append((name, bool(ok)))
    print(f"gate3_{name}={'PASS' if ok else 'FAIL'}")

s, b = get("/health")
rec("health", s == 200 and b.get("status") == "ok")
s, b = get("/api/main-menu", headers={"X-Internal-Shared-Secret": SECRET})
menu_ids = [str(m.get("id")) for m in (b.get("menus") or []) if isinstance(m, dict)]
rec("main_menu_auth", s == 200 and b.get("menu_count", 0) >= 9 and "12" in menu_ids)
s, b = get_allow_error("/api/main-menu")
rec("auth_guard", s == 401)
s, b = post("/api/menu/5/action", {"action": "domain_info", "params": {}}, headers={"X-Internal-Shared-Secret": SECRET})
rec("menu5_domain_info", s == 200 and b.get("code") == "ok")
s, b = post("/api/menu/1/action", {"action": "observe_status", "params": {}}, headers={"X-Internal-Shared-Secret": SECRET})
rec("menu1_observe_status", s == 200 and b.get("code") == "ok")
s, b = post("/api/menu/12/action", {"action": "overview", "params": {}}, headers={"X-Internal-Shared-Secret": SECRET})
rec("menu12_overview", s == 200 and b.get("code") == "ok")

if not all(ok for _, ok in checks):
    raise SystemExit("gate3_failed")
PY
  )
}

run_gate_3_1() {
  log "Gate 3.1: Integration produksi (${PROD_INSTANCE})"
  need_cmd lxc

  lxc exec "${PROD_INSTANCE}" -- bash -lc '
set -euo pipefail
source /etc/xray-discord-bot/bot.env
export INTERNAL_SHARED_SECRET
python3 - <<'"'"'PY'"'"'
import json, os, urllib.request, urllib.error
BASE="http://127.0.0.1:8080"
SECRET=os.environ.get("INTERNAL_SHARED_SECRET","")

def get(path, headers=None):
    req=urllib.request.Request(BASE+path, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.getcode(), json.loads(r.read().decode("utf-8","ignore"))

def post(path, payload, headers=None):
    req=urllib.request.Request(
        BASE+path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type":"application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.getcode(), json.loads(r.read().decode("utf-8","ignore"))

def get_allow_error(path, headers=None):
    try:
        return get(path, headers)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8","ignore"))

checks=[]
def rec(name, ok):
    checks.append((name, bool(ok)))
    status_text = "PASS" if ok else "FAIL"
    print(f"gate3_1_{name}={status_text}")

s,b=get("/health")
rec("health", s==200 and b.get("status")=="ok")
s,b=get("/api/main-menu", headers={"X-Internal-Shared-Secret":SECRET})
menu_ids=[str(m.get("id")) for m in (b.get("menus") or []) if isinstance(m, dict)]
rec("main_menu_auth", s==200 and b.get("menu_count", 0)>=9 and "12" in menu_ids)
s,b=get_allow_error("/api/main-menu")
rec("auth_guard", s==401)
s,b=post("/api/menu/5/action", {"action":"domain_info","params":{}}, headers={"X-Internal-Shared-Secret":SECRET})
rec("menu5_domain_info", s==200 and b.get("code")=="ok")
s,b=post("/api/menu/1/action", {"action":"observe_status","params":{}}, headers={"X-Internal-Shared-Secret":SECRET})
rec("menu1_observe_status", s==200 and b.get("code")=="ok")
s,b=post("/api/menu/12/action", {"action":"overview","params":{}}, headers={"X-Internal-Shared-Secret":SECRET})
rec("menu12_overview", s==200 and b.get("code")=="ok")

if not all(ok for _,ok in checks):
    raise SystemExit("gate3_1_failed")
PY
'
}

run_gate_4() {
  log "Gate 4: Negative/Failure (${STAGING_INSTANCE})"
  need_cmd lxc

  lxc exec "${STAGING_INSTANCE}" -- bash -lc '
set -euo pipefail
source /etc/xray-discord-bot/bot.env
export INTERNAL_SHARED_SECRET
python3 - <<'"'"'PY'"'"'
import json, os, urllib.request, urllib.error
BASE="http://127.0.0.1:8080"
SECRET=os.environ.get("INTERNAL_SHARED_SECRET","")

def request(method, path, payload=None, auth=True):
    headers={"Content-Type":"application/json"}
    if auth:
        headers["X-Internal-Shared-Secret"]=SECRET
    data=None
    if payload is not None:
        data=json.dumps(payload).encode("utf-8")
    req=urllib.request.Request(BASE+path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.getcode(), json.loads(r.read().decode("utf-8","ignore"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8","ignore"))

checks=[]
def rec(name, ok):
    checks.append((name, bool(ok)))
    status_text = "PASS" if ok else "FAIL"
    print(f"gate4_{name}={status_text}")

s,b=request("GET","/api/main-menu", auth=False)
rec("auth_guard", s==401)
s,b=request("POST","/api/menu/5/action", {"action":"setup_domain_cloudflare","params":{"root_domain":"999","proxied":"abc"}}, auth=True)
rec("invalid_bool", s==200 and b.get("code")=="setup_domain_cloudflare_failed")
s,b=request("POST","/api/menu/5/action", {"action":"setup_domain_cloudflare","params":{"root_domain":"999"}}, auth=True)
rec("invalid_root", s==200 and b.get("code")=="setup_domain_cloudflare_failed")

if not all(ok for _,ok in checks):
    raise SystemExit("gate4_failed")
PY
'
}

run_gate_5() {
  log "Gate 5: Discord E2E UX (server-side checks)"
  need_cmd lxc

  lxc exec "${PROD_INSTANCE}" -- bash -lc '
set -euo pipefail
systemctl show xray-discord-gateway -p ActiveState -p SubState -p NRestarts --no-pager
source /etc/xray-discord-bot/bot.env
export RESP_JSON="$(curl -fsS --max-time 20 -H "Authorization: Bot ${DISCORD_BOT_TOKEN}" -H "User-Agent: xray-discord-gateway/1.0" "https://discord.com/api/v10/applications/${DISCORD_APPLICATION_ID}/guilds/${DISCORD_GUILD_ID}/commands")"
python3 - <<'"'"'PY'"'"'
import json, os
data = json.loads(os.environ["RESP_JSON"])
names = sorted(str(x.get("name") or "") for x in data if isinstance(x, dict))
print("gate5_commands=" + ",".join(names))
if "panel" not in names:
    raise SystemExit("gate5_panel_missing")
PY
'
}

run_gate_6() {
  log "Gate 6: Regression produksi (read-only menu smoke)"
  need_cmd lxc

  lxc exec "${PROD_INSTANCE}" -- bash -lc '
set -euo pipefail
source /etc/xray-discord-bot/bot.env
export INTERNAL_SHARED_SECRET
python3 - <<'"'"'PY'"'"'
import json, os, urllib.request, urllib.error
BASE="http://127.0.0.1:8080"
SECRET=os.environ.get("INTERNAL_SHARED_SECRET","")
cases=[
  ("1","overview",{}),
  ("1","observe_status",{}),
  ("2","list_users",{}),
  ("3","summary",{}),
  ("4","egress_summary",{}),
  ("5","domain_info",{}),
  ("5","domain_guard_status",{}),
  ("6","version",{}),
  ("7","sysctl_summary",{}),
  ("8","service_status",{}),
  ("12","overview",{}),
]

def post(menu, action, params):
    req=urllib.request.Request(
      BASE+f"/api/menu/{menu}/action",
      data=json.dumps({"action":action,"params":params}).encode("utf-8"),
      headers={"Content-Type":"application/json","X-Internal-Shared-Secret":SECRET},
      method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
      return r.getcode(), json.loads(r.read().decode("utf-8","ignore"))

ok_all=True
for menu, action, params in cases:
    s,b=post(menu, action, params)
    ok=(s==200 and isinstance(b,dict) and "ok" in b and "code" in b and "title" in b)
    status_text = "PASS" if ok else "FAIL"
    print(f"gate6_menu{menu}_{action}={status_text}")
    ok_all=ok_all and ok
if not ok_all:
    raise SystemExit("gate6_failed")
PY
'
}

run_local_bundle() {
  run_gate_1
  run_gate_2
  run_gate_3
}

run_prod_bundle() {
  run_gate_3_1
  run_gate_5
  run_gate_6
}

run_all_bundle() {
  run_local_bundle
  run_gate_4
  run_prod_bundle
}

case "${PROFILE}" in
  local) run_local_bundle ;;
  prod) run_prod_bundle ;;
  all) run_all_bundle ;;
  *)
    cat <<EOF
Usage: $(basename "$0") [local|prod|all]
  local : Gate 1,2,3 (workspace/staging local uvicorn)
  prod  : Gate 3.1,5,6 (instance produksi via LXC)
  all   : Gate 1-6 (Gate 4 via STAGING_INSTANCE)

Env override:
  PROD_INSTANCE=${PROD_INSTANCE}
  STAGING_INSTANCE=${STAGING_INSTANCE}
EOF
    exit 1
    ;;
esac

log "Selesai profile=${PROFILE}"
