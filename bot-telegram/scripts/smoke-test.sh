#!/usr/bin/env bash
set -euo pipefail

BACKEND_SERVICE="${BACKEND_SERVICE:-xray-telegram-backend}"
GATEWAY_SERVICE="${GATEWAY_SERVICE:-xray-telegram-gateway}"
BACKEND_BASE_URL="${BACKEND_BASE_URL:-http://127.0.0.1:8080}"
SECRET="${INTERNAL_SHARED_SECRET:-}"

if [[ -z "${SECRET}" ]]; then
  echo "[smoke] INTERNAL_SHARED_SECRET belum diset" >&2
  exit 1
fi

echo "[smoke] service state"
systemctl is-active "${BACKEND_SERVICE}" || true
systemctl is-active "${GATEWAY_SERVICE}" || true

echo "[smoke] backend health"
curl -fsS --max-time 8 "${BACKEND_BASE_URL%/}/health"

echo "[smoke] auth guard + menu endpoint"
curl -fsS --max-time 8 -H "X-Internal-Shared-Secret: ${SECRET}" "${BACKEND_BASE_URL%/}/api/main-menu" >/dev/null

echo "[smoke] PASS"
