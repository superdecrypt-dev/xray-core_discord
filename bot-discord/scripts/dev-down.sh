#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd -P)"
TMP_DIR="${BASE_DIR}/runtime/tmp"

for name in gateway backend; do
  pid_file="${TMP_DIR}/${name}.pid"
  if [[ -f "${pid_file}" ]]; then
    pid="$(cat "${pid_file}")"
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" || true
      echo "stopped ${name} (pid ${pid})"
    else
      echo "${name} pid stale (${pid})"
    fi
    rm -f "${pid_file}"
  else
    echo "${name} tidak sedang jalan"
  fi
done
