#!/usr/bin/env bash
set -euo pipefail

BOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
export BOT_DIR

log() {
  printf '[telegram-gate] %s\n' "$*"
}

die() {
  printf '[telegram-gate] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "command tidak ditemukan: $1"
}

need_cmd python3

log "Gate 1: Python syntax compile"
mapfile -t BACKEND_PY_FILES < <(find "${BOT_DIR}/backend-py/app" -name '*.py')
mapfile -t GATEWAY_PY_FILES < <(find "${BOT_DIR}/gateway-py/app" -name '*.py')
if (( ${#BACKEND_PY_FILES[@]} > 0 )); then
  python3 -m py_compile "${BACKEND_PY_FILES[@]}"
fi
if (( ${#GATEWAY_PY_FILES[@]} > 0 )); then
  python3 -m py_compile "${GATEWAY_PY_FILES[@]}"
fi

log "Gate 2: commands.json schema sanity"
python3 - <<'PY'
import json
import os
from pathlib import Path

p = Path(os.environ['BOT_DIR']) / 'shared' / 'commands.json'
obj = json.loads(p.read_text(encoding='utf-8'))
menus = obj.get('menus')
if not isinstance(menus, list) or len(menus) < 8:
    raise SystemExit('commands_invalid')
print(f'commands_ok menus={len(menus)}')
PY

if [[ -x "${BOT_DIR}/.venv/bin/python" ]]; then
  log "Gate 3: backend API smoke"
  LOG_FILE="${BOT_DIR}/runtime/logs/backend-gate.log"
  mkdir -p "$(dirname "${LOG_FILE}")"

  (
    cd "${BOT_DIR}/backend-py"
    export INTERNAL_SHARED_SECRET='telegram-gate-secret'
    export BACKEND_HOST='127.0.0.1'
    export BACKEND_PORT='18084'
    export COMMANDS_FILE="${BOT_DIR}/shared/commands.json"
    "${BOT_DIR}/.venv/bin/uvicorn" app.main:app --host "${BACKEND_HOST}" --port "${BACKEND_PORT}" >"${LOG_FILE}" 2>&1 &
    uv_pid="$!"
    trap 'kill "${uv_pid}" >/dev/null 2>&1 || true' EXIT

    for _ in $(seq 1 80); do
      if curl -fsS -H "X-Internal-Shared-Secret: ${INTERNAL_SHARED_SECRET}" "http://127.0.0.1:18084/health" >/dev/null 2>&1; then
        break
      fi
      sleep 0.25
    done

    python3 - <<'PY'
import json
import urllib.request
import urllib.error

BASE='http://127.0.0.1:18084'
SECRET='telegram-gate-secret'

def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {}, method='GET')
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.getcode(), json.loads(r.read().decode('utf-8', 'ignore'))

def post(path, payload, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json', **(headers or {})},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.getcode(), json.loads(r.read().decode('utf-8', 'ignore'))

checks = []

def rec(name, ok):
    checks.append(bool(ok))
    status = 'PASS' if ok else 'FAIL'
    print(f'gate_{name}={status}')

s, b = get('/health', headers={'X-Internal-Shared-Secret': SECRET})
rec('health', s == 200 and b.get('status') == 'ok')
s, b = get('/api/main-menu', headers={'X-Internal-Shared-Secret': SECRET})
menu_ids = [str(m.get('id')) for m in (b.get('menus') or []) if isinstance(m, dict)]
rec('main_menu', s == 200 and len(menu_ids) >= 8)
s, b = post('/api/menu/1/action', {'action': 'overview', 'params': {}}, headers={'X-Internal-Shared-Secret': SECRET})
rec('menu1_overview', s == 200 and b.get('code') == 'ok')

if not all(checks):
    raise SystemExit('gate_failed')
PY
  )
else
  log "Gate 3 dilewati (.venv belum tersedia)."
fi

log "Semua gate selesai."
