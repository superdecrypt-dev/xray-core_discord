#!/usr/bin/env bash
set -euo pipefail

SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

BACKEND_SERVICE="${BACKEND_SERVICE:-xray-discord-backend}"
GATEWAY_SERVICE="${GATEWAY_SERVICE:-xray-discord-gateway}"
BACKEND_BASE_URL="${BACKEND_BASE_URL:-http://127.0.0.1:8080}"
BACKEND_HEALTH_URL="${BACKEND_HEALTH_URL:-${BACKEND_BASE_URL%/}/health}"
BOT_LOG_DIR="${BOT_LOG_DIR:-/var/log/xray-discord-bot}"
BOT_MONITOR_LOG_FILE="${BOT_MONITOR_LOG_FILE:-${BOT_LOG_DIR}/monitor-lite.log}"
BOT_MONITOR_MAX_LINES="${BOT_MONITOR_MAX_LINES:-1000}"

QUIET=0
if [[ "${1:-}" == "-q" || "${1:-}" == "--quiet" ]]; then
  QUIET=1
fi

if command -v flock >/dev/null 2>&1; then
  exec 9>"/run/xray-discord-monitor.lock"
  flock -n 9 || exit 0
fi

log_line() {
  local line="$1"
  mkdir -p "${BOT_LOG_DIR}"
  printf '%s\n' "${line}" >> "${BOT_MONITOR_LOG_FILE}"

  if [[ "${BOT_MONITOR_MAX_LINES}" =~ ^[0-9]+$ ]] && (( BOT_MONITOR_MAX_LINES > 0 )); then
    local current_lines
    current_lines="$(wc -l < "${BOT_MONITOR_LOG_FILE}" 2>/dev/null || echo 0)"
    if (( current_lines > BOT_MONITOR_MAX_LINES )); then
      tail -n "${BOT_MONITOR_MAX_LINES}" "${BOT_MONITOR_LOG_FILE}" > "${BOT_MONITOR_LOG_FILE}.tmp"
      mv "${BOT_MONITOR_LOG_FILE}.tmp" "${BOT_MONITOR_LOG_FILE}"
    fi
  fi
}

check_service() {
  local unit="$1"
  local state
  state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  [[ -n "${state}" ]] || state="unknown"
  if [[ "${state}" == "active" ]]; then
    printf '%s\n' "active"
    return 0
  fi
  printf '%s\n' "${state}"
  return 1
}

check_health() {
  local body
  body="$(curl -fsS --max-time 8 "${BACKEND_HEALTH_URL}" 2>/dev/null || true)"
  if [[ -n "${body}" ]] && printf '%s' "${body}" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    printf '%s\n' "ok"
    return 0
  fi
  printf '%s\n' "fail"
  return 1
}

backend_state="unknown"
gateway_state="unknown"
health_state="unknown"
fail_count=0

if backend_state="$(check_service "${BACKEND_SERVICE}")"; then
  :
else
  fail_count=$((fail_count + 1))
fi

if gateway_state="$(check_service "${GATEWAY_SERVICE}")"; then
  :
else
  fail_count=$((fail_count + 1))
fi

if health_state="$(check_health)"; then
  :
else
  fail_count=$((fail_count + 1))
fi

level="OK"
if (( fail_count > 0 )); then
  level="FAIL"
fi

ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
message="${ts} ${level} backend=${backend_state} gateway=${gateway_state} health=${health_state}"

if (( QUIET == 0 )); then
  echo "${message}"
fi

log_line "${message}"
if command -v logger >/dev/null 2>&1; then
  logger -t xray-discord-monitor "${message}"
fi

if (( fail_count > 0 )); then
  exit 1
fi
exit 0
