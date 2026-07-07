#!/bin/sh
set -eu

fail() {
  echo "restore-verify: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

safe_db_name() {
  value="$1"
  case "$value" in
    ''|*[!A-Za-z0-9_]*)
      fail "unsafe database name: $value"
      ;;
  esac
}

sql_string() {
  printf "%s" "$1" | sed "s/'/''/g"
}

table_count() {
  db="$1"
  table="$2"
  psql -X -q -t -A -v ON_ERROR_STOP=1 -d "$db" -c "select count(*) from ${table};" 2>/dev/null || printf 'null'
}

assert_count() {
  label="$1"
  expected="$2"
  actual="$3"

  if [ "$expected" = "null" ]; then
    echo "restore-verify: ${label}: expected count unavailable, restored=${actual}"
    return 0
  fi

  [ "$expected" = "$actual" ] || fail "${label} count mismatch: expected ${expected}, restored ${actual}"
  echo "restore-verify: ${label}: ${actual}"
}

require_command pg_restore
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
: "${PGUSER:?PGUSER or DB_USER is required}"

BACKUP_FILE="${1:-${BACKUP_FILE:-}}"
[ -n "$BACKUP_FILE" ] || fail "set BACKUP_FILE or pass a backup archive path"
[ -f "$BACKUP_FILE" ] || fail "backup archive not found: $BACKUP_FILE"

RESTORE_DB="${RESTORE_DB:-${PGDATABASE:-ticketdata}_restoretest}"
PGMAINTENANCE_DB="${PGMAINTENANCE_DB:-postgres}"
RESTORE_DROP_AFTER_TEST="${RESTORE_DROP_AFTER_TEST:-false}"

safe_db_name "$RESTORE_DB"
safe_db_name "$PGMAINTENANCE_DB"

WORK_ROOT="${RESTORE_WORK_DIR:-/tmp/soc-ticket-restore-verify}"
mkdir -p "$WORK_ROOT"
WORK_DIR="$(mktemp -d "$WORK_ROOT/restore.XXXXXX")"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

ARCHIVE_TO_EXTRACT="$BACKUP_FILE"
case "$BACKUP_FILE" in
  *.tar.gz.enc)
    require_command openssl
    ARCHIVE_TO_EXTRACT="$WORK_DIR/backup.tar.gz"
    if [ -n "${BACKUP_ENCRYPTION_PASSWORD_FILE:-}" ]; then
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
        -in "$BACKUP_FILE" -out "$ARCHIVE_TO_EXTRACT" \
        -pass "file:${BACKUP_ENCRYPTION_PASSWORD_FILE}"
    elif [ -n "${BACKUP_ENCRYPTION_PASSWORD:-}" ]; then
      openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
        -in "$BACKUP_FILE" -out "$ARCHIVE_TO_EXTRACT" \
        -pass "env:BACKUP_ENCRYPTION_PASSWORD"
    else
      fail "encrypted backup requires BACKUP_ENCRYPTION_PASSWORD_FILE or BACKUP_ENCRYPTION_PASSWORD"
    fi
    ;;
  *.tar.gz.gpg)
    require_command gpg
    ARCHIVE_TO_EXTRACT="$WORK_DIR/backup.tar.gz"
    gpg --batch --yes --decrypt --output "$ARCHIVE_TO_EXTRACT" "$BACKUP_FILE"
    ;;
esac

EXTRACT_DIR="$WORK_DIR/package"
mkdir -p "$EXTRACT_DIR"
tar -C "$EXTRACT_DIR" -xzf "$ARCHIVE_TO_EXTRACT"

(
  cd "$EXTRACT_DIR"
  sha256sum -c checksums.sha256
)

[ -f "$EXTRACT_DIR/database.dump" ] || fail "database.dump missing from backup"
[ -f "$EXTRACT_DIR/media.tar.gz" ] || fail "media.tar.gz missing from backup"
[ -f "$EXTRACT_DIR/counts.env" ] || fail "counts.env missing from backup"

. "$EXTRACT_DIR/counts.env"

RESTORE_DB_SQL="$(sql_string "$RESTORE_DB")"

echo "restore-verify: recreating database ${RESTORE_DB}"
psql -X -v ON_ERROR_STOP=1 -d "$PGMAINTENANCE_DB" -c \
  "select pg_terminate_backend(pid) from pg_stat_activity where datname = '${RESTORE_DB_SQL}' and pid <> pg_backend_pid();" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d "$PGMAINTENANCE_DB" -c "drop database if exists \"${RESTORE_DB}\";" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d "$PGMAINTENANCE_DB" -c "create database \"${RESTORE_DB}\" owner \"${PGUSER}\";" >/dev/null

echo "restore-verify: restoring database dump"
pg_restore --no-owner --no-acl --dbname="$RESTORE_DB" "$EXTRACT_DIR/database.dump"

RESTORED_TICKET_COUNT="$(table_count "$RESTORE_DB" incidents_ticket)"
RESTORED_TICKET_LOG_COUNT="$(table_count "$RESTORE_DB" incidents_ticketlog)"
RESTORED_TRIAGE_COUNT="$(table_count "$RESTORE_DB" incidents_triagerecord)"
RESTORED_PROJECT_INCIDENT_COUNT="$(table_count "$RESTORE_DB" incidents_projectincident)"
RESTORED_ATTACHMENT_COUNT="$(table_count "$RESTORE_DB" incidents_ticketattachment)"
RESTORED_WAZUH_ALERT_COUNT="$(table_count "$RESTORE_DB" wazuh_ingest_wazuhalert)"
RESTORED_INGEST_WATERMARK_COUNT="$(table_count "$RESTORE_DB" wazuh_ingest_ingestwatermark)"
RESTORED_USER_COUNT="$(table_count "$RESTORE_DB" auth_user)"

assert_count tickets "$TICKET_COUNT" "$RESTORED_TICKET_COUNT"
assert_count ticket_logs "$TICKET_LOG_COUNT" "$RESTORED_TICKET_LOG_COUNT"
assert_count triage_records "$TRIAGE_COUNT" "$RESTORED_TRIAGE_COUNT"
assert_count project_incidents "$PROJECT_INCIDENT_COUNT" "$RESTORED_PROJECT_INCIDENT_COUNT"
assert_count ticket_attachments "$ATTACHMENT_COUNT" "$RESTORED_ATTACHMENT_COUNT"
assert_count wazuh_alerts "$WAZUH_ALERT_COUNT" "$RESTORED_WAZUH_ALERT_COUNT"
assert_count ingest_watermarks "$INGEST_WATERMARK_COUNT" "$RESTORED_INGEST_WATERMARK_COUNT"
assert_count users "$USER_COUNT" "$RESTORED_USER_COUNT"

MEDIA_VERIFY_DIR="$WORK_DIR/media"
mkdir -p "$MEDIA_VERIFY_DIR"
tar -C "$MEDIA_VERIFY_DIR" -xzf "$EXTRACT_DIR/media.tar.gz"
RESTORED_MEDIA_FILE_COUNT="$(find "$MEDIA_VERIFY_DIR" -type f | wc -l | tr -d ' ')"
assert_count media_files "$MEDIA_FILE_COUNT" "$RESTORED_MEDIA_FILE_COUNT"

if [ "$RESTORE_DROP_AFTER_TEST" = "true" ]; then
  echo "restore-verify: dropping ${RESTORE_DB}"
  psql -X -v ON_ERROR_STOP=1 -d "$PGMAINTENANCE_DB" -c \
    "select pg_terminate_backend(pid) from pg_stat_activity where datname = '${RESTORE_DB_SQL}' and pid <> pg_backend_pid();" >/dev/null
  psql -X -v ON_ERROR_STOP=1 -d "$PGMAINTENANCE_DB" -c "drop database if exists \"${RESTORE_DB}\";" >/dev/null
fi

echo "restore-verify: backup is restorable"
