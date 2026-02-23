#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
ENV_FILE="${BASE_DIR}/.env"
LOG_DIR="${BASE_DIR}/runtime/logs"
TMP_DIR="${BASE_DIR}/runtime/tmp"
BACKEND_LOG="${LOG_DIR}/backend-dev.log"
GATEWAY_LOG="${LOG_DIR}/gateway-dev.log"
BACKEND_PID_FILE="${TMP_DIR}/backend.pid"
GATEWAY_PID_FILE="${TMP_DIR}/gateway.pid"

mkdir -p "${LOG_DIR}" "${TMP_DIR}" "${BASE_DIR}/runtime/locks"

pid_is_running() {
  local pid="${1:-}"
  [[ "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" 2>/dev/null
}

cleanup_stale_pid() {
  local pid_file="$1"
  if [[ -f "${pid_file}" ]]; then
    local pid
    pid="$(cat "${pid_file}" 2>/dev/null || true)"
    if ! pid_is_running "${pid}"; then
      rm -f "${pid_file}"
    fi
  fi
}

load_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
  fi
}

wait_backend_ready() {
  local host="${BACKEND_HOST:-127.0.0.1}"
  local port="${BACKEND_PORT:-8080}"
  local url="http://${host}:${port}/health"

  if ! command -v curl >/dev/null 2>&1; then
    sleep 2
    return 0
  fi

  for _ in $(seq 1 40); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_gateway_ready() {
  local pid_file="$1"
  local log_file="$2"
  local pid

  for _ in $(seq 1 60); do
    pid="$(cat "${pid_file}" 2>/dev/null || true)"
    if ! pid_is_running "${pid}"; then
      echo "gateway gagal start. cek log: ${log_file}"
      tail -n 40 "${log_file}" 2>/dev/null || true
      return 1
    fi
    if grep -q "\\[gateway\\] logged in as " "${log_file}" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done

  echo "gateway belum ready setelah timeout. cek log: ${log_file}"
  tail -n 40 "${log_file}" 2>/dev/null || true
  return 1
}

load_env_file
cleanup_stale_pid "${BACKEND_PID_FILE}"
cleanup_stale_pid "${GATEWAY_PID_FILE}"

started_backend=0

if [[ -f "${BACKEND_PID_FILE}" ]] && pid_is_running "$(cat "${BACKEND_PID_FILE}")"; then
  echo "backend sudah jalan (pid $(cat "${BACKEND_PID_FILE}"))"
else
  (
    cd "${BASE_DIR}"
    if [[ ! -d .venv ]]; then
      python3 -m venv .venv
    fi
    . .venv/bin/activate
    pip install -r backend-py/requirements.txt >/dev/null
    cd backend-py
    uvicorn app.main:app --host "${BACKEND_HOST:-127.0.0.1}" --port "${BACKEND_PORT:-8080}" >"${BACKEND_LOG}" 2>&1 &
    echo $! >"${BACKEND_PID_FILE}"
  )
  started_backend=1
  if ! wait_backend_ready; then
    echo "backend gagal ready. cek log: ${BACKEND_LOG}"
    tail -n 40 "${BACKEND_LOG}" 2>/dev/null || true
    pid="$(cat "${BACKEND_PID_FILE}" 2>/dev/null || true)"
    if pid_is_running "${pid}"; then
      kill "${pid}" || true
    fi
    rm -f "${BACKEND_PID_FILE}"
    exit 1
  fi
  echo "backend started (pid $(cat "${BACKEND_PID_FILE}"))"
fi

if [[ -f "${GATEWAY_PID_FILE}" ]] && pid_is_running "$(cat "${GATEWAY_PID_FILE}")"; then
  echo "gateway sudah jalan (pid $(cat "${GATEWAY_PID_FILE}"))"
else
  (
    cd "${BASE_DIR}/gateway-ts"
    npm install >/dev/null
    npm run dev >"${GATEWAY_LOG}" 2>&1 &
    echo $! >"${GATEWAY_PID_FILE}"
  )

  if ! wait_gateway_ready "${GATEWAY_PID_FILE}" "${GATEWAY_LOG}"; then
    rm -f "${GATEWAY_PID_FILE}"
    if [[ "${started_backend}" -eq 1 ]]; then
      pid="$(cat "${BACKEND_PID_FILE}" 2>/dev/null || true)"
      if pid_is_running "${pid}"; then
        kill "${pid}" || true
      fi
      rm -f "${BACKEND_PID_FILE}"
    fi
    exit 1
  fi
  echo "gateway started (pid $(cat "${GATEWAY_PID_FILE}"))"
fi

echo "dev services aktif. cek log di ${LOG_DIR}"
