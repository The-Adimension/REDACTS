#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Wait for REDCap to be ready before running Playwright tests
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

REDCAP_URL="${REDCAP_BASE_URL:-http://redcap-dast-app}"
MAX_WAIT="${MAX_WAIT_SECONDS:-120}"
ELAPSED=0

echo "[dast] Waiting for REDCap at ${REDCAP_URL} ..."

until curl -sf -o /dev/null "${REDCAP_URL}/redcap/" 2>/dev/null; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "${ELAPSED}" -ge "${MAX_WAIT}" ]; then
        echo "[dast] ERROR: REDCap not ready after ${MAX_WAIT}s"
        exit 1
    fi
    echo "[dast]   ... waiting (${ELAPSED}s)"
done

echo "[dast] REDCap ready after ${ELAPSED}s. Running tests..."
exec "$@"
