#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
ENV_FILE="${BASE_DIR}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

BACKEND_BASE_URL="${BACKEND_BASE_URL:-http://127.0.0.1:8080}"
INTERNAL_SHARED_SECRET="${INTERNAL_SHARED_SECRET:-}"

if [[ -z "${INTERNAL_SHARED_SECRET}" ]]; then
  echo "INTERNAL_SHARED_SECRET kosong. isi dulu di .env"
  exit 1
fi

echo "== health =="
curl -fsS "${BACKEND_BASE_URL}/health" | sed 's/.*/&/'

echo
echo "== menu 1 overview =="
curl -fsS -X POST "${BACKEND_BASE_URL}/api/menu/1/action" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Shared-Secret: ${INTERNAL_SHARED_SECRET}" \
  -d '{"action":"overview","params":{}}' | sed 's/.*/&/'
