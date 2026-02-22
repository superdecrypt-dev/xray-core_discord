#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
LOG_DIR="${BASE_DIR}/runtime/logs"
TMP_DIR="${BASE_DIR}/runtime/tmp"

mkdir -p "${LOG_DIR}" "${TMP_DIR}" "${BASE_DIR}/runtime/locks"

if [[ -f "${TMP_DIR}/backend.pid" ]] && kill -0 "$(cat "${TMP_DIR}/backend.pid")" 2>/dev/null; then
  echo "backend sudah jalan (pid $(cat "${TMP_DIR}/backend.pid"))"
else
  (
    cd "${BASE_DIR}"
    if [[ ! -d .venv ]]; then
      python3 -m venv .venv
    fi
    . .venv/bin/activate
    pip install -r backend-py/requirements.txt >/dev/null
    cd backend-py
    uvicorn app.main:app --host 127.0.0.1 --port 8080 >"${LOG_DIR}/backend-dev.log" 2>&1 &
    echo $! >"${TMP_DIR}/backend.pid"
  )
  echo "backend started (pid $(cat "${TMP_DIR}/backend.pid"))"
fi

if [[ -f "${TMP_DIR}/gateway.pid" ]] && kill -0 "$(cat "${TMP_DIR}/gateway.pid")" 2>/dev/null; then
  echo "gateway sudah jalan (pid $(cat "${TMP_DIR}/gateway.pid"))"
else
  (
    cd "${BASE_DIR}/gateway-ts"
    npm install >/dev/null
    npm run dev >"${LOG_DIR}/gateway-dev.log" 2>&1 &
    echo $! >"${TMP_DIR}/gateway.pid"
  )
  echo "gateway started (pid $(cat "${TMP_DIR}/gateway.pid"))"
fi

echo "dev services aktif. cek log di ${LOG_DIR}"
