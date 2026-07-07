#!/bin/sh
set -eu

fail() {
  echo "backup: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

json_value() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

table_count() {
  table="$1"
  psql -X -q -t -A -v ON_ERROR_STOP=1 -c "select count(*) from ${table};" 2>/dev/null || printf 'null'
}

safe_positive_integer() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*) printf '%s' "$fallback" ;;
    *) printf '%s' "$value" ;;
  esac
}

cleanup_retention_tier() {
  tier="$1"
  days="$2"

  [ "$BACKUP_RETENTION_ENABLED" = "true" ] || return 0
  [ "$days" -gt 0 ] 2>/dev/null || return 0

  find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type f \
    \( -name "${BACKUP_PREFIX}_${tier}_*.tar.gz" \
       -o -name "${BACKUP_PREFIX}_${tier}_*.tar.gz.sha256" \
       -o -name "${BACKUP_PREFIX}_${tier}_*.tar.gz.enc" \
       -o -name "${BACKUP_PREFIX}_${tier}_*.tar.gz.enc.sha256" \
       -o -name "${BACKUP_PREFIX}_${tier}_*.tar.gz.gpg" \
       -o -name "${BACKUP_PREFIX}_${tier}_*.tar.gz.gpg.sha256" \) \
    -mtime +"$days" -exec rm -f -- {} \;
}

require_command pg_dump
require_command psql
require_command tar
require_command sha256sum
require_command find
require_command wc

PGHOST="${PGHOST:-${DB_HOST:-}}"
PGPORT="${PGPORT:-${DB_PORT:-5432}}"
PGDATABASE="${PGDATABASE:-${DB_NAME:-}}"
PGUSER="${PGUSER:-${DB_USER:-}}"
if [ -z "${PGPASSWORD:-}" ] && [ -n "${DB_PASSWORD:-}" ]; then
  PGPASSWORD="$DB_PASSWORD"
  export PGPASSWORD
fi
export PGHOST PGPORT PGDATABASE PGUSER

: "${PGHOST:?PGHOST or DB_HOST is required}"
: "${PGDATABASE:?PGDATABASE or DB_NAME is required}"
: "${PGUSER:?PGUSER or DB_USER is required}"

BACKUP_DIR="${BACKUP_DIR:-/backups}"
MEDIA_ROOT="${MEDIA_ROOT:-/app/media}"
BACKUP_PREFIX="${BACKUP_PREFIX:-soc_ticket}"
BACKUP_TIER="${BACKUP_TIER:-manual}"
BACKUP_RETENTION_ENABLED="${BACKUP_RETENTION_ENABLED:-true}"
BACKUP_RETENTION_HOURLY_DAYS="$(safe_positive_integer "${BACKUP_RETENTION_HOURLY_DAYS:-2}" 2)"
BACKUP_RETENTION_DAILY_DAYS="$(safe_positive_integer "${BACKUP_RETENTION_DAILY_DAYS:-30}" 30)"
BACKUP_RETENTION_WEEKLY_DAYS="$(safe_positive_integer "${BACKUP_RETENTION_WEEKLY_DAYS:-84}" 84)"
BACKUP_RETENTION_MONTHLY_DAYS="$(safe_positive_integer "${BACKUP_RETENTION_MONTHLY_DAYS:-365}" 365)"
BACKUP_ENCRYPTION="${BACKUP_ENCRYPTION:-none}"
APP_VERSION="${APP_VERSION:-unknown}"

case "$BACKUP_TIER" in
  hourly|daily|weekly|monthly|manual) ;;
  *) fail "BACKUP_TIER must be one of: hourly, daily, weekly, monthly, manual" ;;
esac

case "$BACKUP_ENCRYPTION" in
  none|openssl|gpg) ;;
  *) fail "BACKUP_ENCRYPTION must be one of: none, openssl, gpg" ;;
esac

mkdir -p "$BACKUP_DIR"
[ -d "$BACKUP_DIR" ] || fail "BACKUP_DIR is not a directory: $BACKUP_DIR"
[ "$BACKUP_DIR" != "/" ] || fail "BACKUP_DIR must not be /"

LOCK_DIR="$BACKUP_DIR/.backup.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  fail "another backup appears to be running; lock exists at $LOCK_DIR"
fi

STAGING_DIR=''
cleanup() {
  [ -n "$STAGING_DIR" ] && [ -d "$STAGING_DIR" ] && rm -rf "$STAGING_DIR"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_NAME="${BACKUP_PREFIX}_${BACKUP_TIER}_${TIMESTAMP}"
STAGING_DIR="$BACKUP_DIR/.${BACKUP_NAME}.staging"
PACKAGE_DIR="$STAGING_DIR/package"
ARCHIVE_PATH="$BACKUP_DIR/${BACKUP_NAME}.tar.gz"

mkdir -p "$PACKAGE_DIR"

echo "backup: dumping PostgreSQL database ${PGDATABASE} from ${PGHOST}"
pg_dump --format=custom --no-owner --no-acl --file="$PACKAGE_DIR/database.dump"

echo "backup: archiving media from ${MEDIA_ROOT}"
if [ -d "$MEDIA_ROOT" ]; then
  MEDIA_PARENT="$(dirname "$MEDIA_ROOT")"
  MEDIA_BASE="$(basename "$MEDIA_ROOT")"
  MEDIA_FILE_COUNT="$(find "$MEDIA_ROOT" -type f | wc -l | tr -d ' ')"
  tar -C "$MEDIA_PARENT" -czf "$PACKAGE_DIR/media.tar.gz" "$MEDIA_BASE"
else
  MEDIA_FILE_COUNT=0
  EMPTY_MEDIA_DIR="$STAGING_DIR/empty-media"
  mkdir -p "$EMPTY_MEDIA_DIR"
  tar -C "$EMPTY_MEDIA_DIR" -czf "$PACKAGE_DIR/media.tar.gz" .
fi

TICKET_COUNT="$(table_count incidents_ticket)"
TICKET_LOG_COUNT="$(table_count incidents_ticketlog)"
TRIAGE_COUNT="$(table_count incidents_triagerecord)"
PROJECT_INCIDENT_COUNT="$(table_count incidents_projectincident)"
ATTACHMENT_COUNT="$(table_count incidents_ticketattachment)"
WAZUH_ALERT_COUNT="$(table_count wazuh_ingest_wazuhalert)"
INGEST_WATERMARK_COUNT="$(table_count wazuh_ingest_ingestwatermark)"
USER_COUNT="$(table_count auth_user)"

cat > "$PACKAGE_DIR/counts.env" <<EOF_COUNTS
TICKET_COUNT=$TICKET_COUNT
TICKET_LOG_COUNT=$TICKET_LOG_COUNT
TRIAGE_COUNT=$TRIAGE_COUNT
PROJECT_INCIDENT_COUNT=$PROJECT_INCIDENT_COUNT
ATTACHMENT_COUNT=$ATTACHMENT_COUNT
WAZUH_ALERT_COUNT=$WAZUH_ALERT_COUNT
INGEST_WATERMARK_COUNT=$INGEST_WATERMARK_COUNT
USER_COUNT=$USER_COUNT
MEDIA_FILE_COUNT=$MEDIA_FILE_COUNT
EOF_COUNTS

cat > "$PACKAGE_DIR/manifest.json" <<EOF_MANIFEST
{
  "backup_name": "$(json_value "$BACKUP_NAME")",
  "backup_tier": "$(json_value "$BACKUP_TIER")",
  "created_at_utc": "$(json_value "$TIMESTAMP")",
  "source": {
    "pg_host": "$(json_value "$PGHOST")",
    "pg_database": "$(json_value "$PGDATABASE")",
    "pg_user": "$(json_value "$PGUSER")",
    "media_root": "$(json_value "$MEDIA_ROOT")",
    "app_version": "$(json_value "$APP_VERSION")"
  },
  "counts": {
    "tickets": $TICKET_COUNT,
    "ticket_logs": $TICKET_LOG_COUNT,
    "triage_records": $TRIAGE_COUNT,
    "project_incidents": $PROJECT_INCIDENT_COUNT,
    "ticket_attachments": $ATTACHMENT_COUNT,
    "wazuh_alerts": $WAZUH_ALERT_COUNT,
    "ingest_watermarks": $INGEST_WATERMARK_COUNT,
    "users": $USER_COUNT,
    "media_files": $MEDIA_FILE_COUNT
  }
}
EOF_MANIFEST

(
  cd "$PACKAGE_DIR"
  sha256sum database.dump media.tar.gz manifest.json counts.env > checksums.sha256
)

echo "backup: creating package ${ARCHIVE_PATH}"
tar -C "$PACKAGE_DIR" -czf "$ARCHIVE_PATH" .
sha256sum "$ARCHIVE_PATH" > "${ARCHIVE_PATH}.sha256"

FINAL_PATH="$ARCHIVE_PATH"
if [ "$BACKUP_ENCRYPTION" = "openssl" ]; then
  require_command openssl
  ENCRYPTED_PATH="${ARCHIVE_PATH}.enc"
  if [ -n "${BACKUP_ENCRYPTION_PASSWORD_FILE:-}" ]; then
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
      -in "$ARCHIVE_PATH" -out "$ENCRYPTED_PATH" \
      -pass "file:${BACKUP_ENCRYPTION_PASSWORD_FILE}"
  elif [ -n "${BACKUP_ENCRYPTION_PASSWORD:-}" ]; then
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 \
      -in "$ARCHIVE_PATH" -out "$ENCRYPTED_PATH" \
      -pass "env:BACKUP_ENCRYPTION_PASSWORD"
  else
    fail "openssl encryption requires BACKUP_ENCRYPTION_PASSWORD_FILE or BACKUP_ENCRYPTION_PASSWORD"
  fi
  rm -f "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sha256"
  sha256sum "$ENCRYPTED_PATH" > "${ENCRYPTED_PATH}.sha256"
  FINAL_PATH="$ENCRYPTED_PATH"
elif [ "$BACKUP_ENCRYPTION" = "gpg" ]; then
  require_command gpg
  : "${BACKUP_GPG_RECIPIENT:?BACKUP_GPG_RECIPIENT is required for gpg encryption}"
  ENCRYPTED_PATH="${ARCHIVE_PATH}.gpg"
  gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" \
    --output "$ENCRYPTED_PATH" "$ARCHIVE_PATH"
  rm -f "$ARCHIVE_PATH" "${ARCHIVE_PATH}.sha256"
  sha256sum "$ENCRYPTED_PATH" > "${ENCRYPTED_PATH}.sha256"
  FINAL_PATH="$ENCRYPTED_PATH"
else
  echo "backup: encryption disabled; set BACKUP_ENCRYPTION=openssl or gpg for production" >&2
fi

cleanup_retention_tier hourly "$BACKUP_RETENTION_HOURLY_DAYS"
cleanup_retention_tier daily "$BACKUP_RETENTION_DAILY_DAYS"
cleanup_retention_tier weekly "$BACKUP_RETENTION_WEEKLY_DAYS"
cleanup_retention_tier monthly "$BACKUP_RETENTION_MONTHLY_DAYS"

echo "backup: completed ${FINAL_PATH}"
