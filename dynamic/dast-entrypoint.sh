#!/bin/bash
# REDACTS DAST - Docker Container Entrypoint
# Sets up the REDCap directory structure, bootstraps the schema, and
# generates database.php from environment variables before Apache.
set -euo pipefail

: "${REDCAP_VERSION:?REDCAP_VERSION is required}"
: "${REDCAP_DB_PASS:?REDCAP_DB_PASS is required}"

DB_HOST="${REDCAP_DB_HOST:-db}"
DB_PORT="${REDCAP_DB_PORT:-3306}"
DB_NAME="${REDCAP_DB_NAME:-redcap}"
DB_USER="${REDCAP_DB_USER:-redcap}"

# mariadb client wrapper: disposable test stack uses unencrypted local
# transport; --skip-ssl prevents the new client default of forcing TLS.
mdb() {
    mariadb --skip-ssl -h "${DB_HOST}" -P "${DB_PORT}" \
        -u "${DB_USER}" -p"${REDCAP_DB_PASS}" "$@"
}
SALT="${REDCAP_SALT:-$(openssl rand -hex 32)}"
EXTERNAL_PORT="${EXTERNAL_PORT:-8585}"
BASE_URL="${REDCAP_BASE_URL:-http://localhost:${EXTERNAL_PORT}/redcap/}"

# Set up REDCap directory structure

REDCAP_ROOT="/var/www/html/redcap"

mkdir -p "${REDCAP_ROOT}"

# Copy source files from build context into web root. The Vanderbilt
# source-repo layout (install.php, Classes/, Config/, ...) lives at
# the top level - we re-host it under a versioned sub-folder so
# REDCap's checkREDCapVersionRedirect() in System.php (which compares
# basename(dirname(dirname(__FILE__))) to "redcap_v${VERSION}") does
# not enter an infinite redirect loop on /Home/index.php.
if [ ! -f "${REDCAP_ROOT}/install.php" ]; then
    cp -a /opt/redcap-source/. "${REDCAP_ROOT}/"
fi

VERSIONED_DIR="${REDCAP_ROOT}/redcap_v${REDCAP_VERSION}"
if [ ! -f "${VERSIONED_DIR}/install.php" ]; then
    mkdir -p "${VERSIONED_DIR}"
    cp -a /opt/redcap-source/. "${VERSIONED_DIR}/"
fi

# Create writable directories
mkdir -p "${REDCAP_ROOT}/edocs" "${REDCAP_ROOT}/temp"

# Generate database.php (both root and docroot)

cat > "${REDCAP_ROOT}/database.php" << DBPHP
<?php
\$hostname = '${DB_HOST}:${DB_PORT}';
\$db       = '${DB_NAME}';
\$username = '${DB_USER}';
\$password = '${REDCAP_DB_PASS}';
\$db_socket = null;
\$salt     = '${SALT}';
DBPHP

# A copy at the docroot is required by REDCap's database connection
# fallback path, which references /var/www/html/database.php.
cp "${REDCAP_ROOT}/database.php" /var/www/html/database.php

# Fix permissions

chown -R www-data:www-data "${REDCAP_ROOT}" /var/www/html/database.php
chmod 600 "${REDCAP_ROOT}/database.php" /var/www/html/database.php

# Wait for the database to accept connections

echo "[DAST] Waiting for ${DB_HOST}:${DB_PORT} ..."
for i in $(seq 1 60); do
    if mdb -e "SELECT 1" "${DB_NAME}" >/dev/null 2>&1; then
        echo "[DAST] Database reachable after ${i}s"
        break
    fi
    sleep 1
done

# Bootstrap schema (only on first boot)

TABLE_COUNT=$(mdb -N -B -e \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}' AND table_name='redcap_config'" 2>/dev/null || echo 0)

if [ "${TABLE_COUNT}" = "0" ]; then
    echo "[DAST] Loading REDCap schema (install.sql + install_data.sql)..."
    SQL_DIR="${REDCAP_ROOT}/Resources/sql"
    if [ -f "${SQL_DIR}/install.sql" ] && [ -f "${SQL_DIR}/install_data.sql" ]; then
        cat "${SQL_DIR}/install.sql" "${SQL_DIR}/install_data.sql" | mdb "${DB_NAME}"
        echo "[DAST] Schema loaded"
    else
        echo "[DAST] WARNING: install.sql/install_data.sql not found in ${SQL_DIR}" >&2
    fi
else
    echo "[DAST] Schema already present - skipping bootstrap"
fi

# Apply REDACTS DAST runtime configuration
# Mirror the install.php auto-install side effects without relying on
# install.php (which only renders setup instructions for this layout).

mdb "${DB_NAME}" <<EOSQL || true
UPDATE redcap_config SET value='${REDCAP_VERSION}'
    WHERE field_name='redcap_version';
UPDATE redcap_config SET value='${BASE_URL}'
    WHERE field_name='redcap_base_url';
UPDATE redcap_config SET value='none'
    WHERE field_name='auth_meth_global';
UPDATE redcap_config SET value='0'
    WHERE field_name='redcap_base_url_display_error_on_mismatch';
EOSQL

echo "[DAST] REDCap v${REDCAP_VERSION} ready - starting Apache"

# Hand off to CMD (apache2-foreground)
exec "$@"
