#!/bin/sh
set -eu

# Runs on the BACKUP VM. Prunes the pulled archive by tier, independently of
# production's own retention — this copy is deliberately kept LONGER, because
# it is the one that survives loss of the production host.
#
# Deliberately separate from backup.sh's cleanup: production pruning must never
# propagate here (that is exactly what ransomware would exploit).
#
# See docs/operations/backup-vm-handbook.md.

fail() {
  echo "prune-archive: $*" >&2
  exit 1
}

safe_positive_integer() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*) printf '%s' "$fallback" ;;
    *) printf '%s' "$value" ;;
  esac
}

ARCHIVE_DIR="${ARCHIVE_DIR:-/srv/soc-ticket/archive}"
BACKUP_PREFIX="${BACKUP_PREFIX:-soc_ticket}"
ARCHIVE_PRUNE_ENABLED="${ARCHIVE_PRUNE_ENABLED:-true}"
DRY_RUN="${DRY_RUN:-false}"

# Longer than production's 2/30/84/365. The monthly tier drives the statutory
# floor (Computer Crime Act ≥ 90 days); confirm against the retention schedule
# compliance settles — see backup-storage-decision-brief.md.
ARCHIVE_RETENTION_HOURLY_DAYS="$(safe_positive_integer "${ARCHIVE_RETENTION_HOURLY_DAYS:-7}" 7)"
ARCHIVE_RETENTION_DAILY_DAYS="$(safe_positive_integer "${ARCHIVE_RETENTION_DAILY_DAYS:-90}" 90)"
ARCHIVE_RETENTION_WEEKLY_DAYS="$(safe_positive_integer "${ARCHIVE_RETENTION_WEEKLY_DAYS:-180}" 180)"
ARCHIVE_RETENTION_MONTHLY_DAYS="$(safe_positive_integer "${ARCHIVE_RETENTION_MONTHLY_DAYS:-1095}" 1095)"
ARCHIVE_RETENTION_MANUAL_DAYS="$(safe_positive_integer "${ARCHIVE_RETENTION_MANUAL_DAYS:-90}" 90)"
# Quarantined files are damaged transfers, not backups. Clear them out so they
# do not silently consume the disk.
ARCHIVE_QUARANTINE_DAYS="$(safe_positive_integer "${ARCHIVE_QUARANTINE_DAYS:-14}" 14)"

[ -d "$ARCHIVE_DIR" ] || fail "ARCHIVE_DIR is not a directory: $ARCHIVE_DIR"
[ "$ARCHIVE_DIR" != "/" ] || fail "ARCHIVE_DIR must not be /"
[ "$ARCHIVE_PRUNE_ENABLED" = "true" ] || { echo "prune-archive: disabled"; exit 0; }

prune_tier() {
  tier="$1"
  days="$2"

  [ "$days" -gt 0 ] 2>/dev/null || return 0

  if [ "$DRY_RUN" = "true" ]; then
    find "$ARCHIVE_DIR" -mindepth 1 -maxdepth 1 -type f \
      -name "${BACKUP_PREFIX}_${tier}_*" -mtime +"$days" \
      -exec echo "prune-archive: WOULD REMOVE {}" \;
    return 0
  fi

  find "$ARCHIVE_DIR" -mindepth 1 -maxdepth 1 -type f \
    -name "${BACKUP_PREFIX}_${tier}_*" -mtime +"$days" \
    -print -exec rm -f -- {} \;
}

echo "prune-archive: pruning ${ARCHIVE_DIR} (dry_run=${DRY_RUN})"
prune_tier hourly  "$ARCHIVE_RETENTION_HOURLY_DAYS"
prune_tier daily   "$ARCHIVE_RETENTION_DAILY_DAYS"
prune_tier weekly  "$ARCHIVE_RETENTION_WEEKLY_DAYS"
prune_tier monthly "$ARCHIVE_RETENTION_MONTHLY_DAYS"
prune_tier manual  "$ARCHIVE_RETENTION_MANUAL_DAYS"

QUARANTINE_DIR="$ARCHIVE_DIR/.quarantine"
if [ -d "$QUARANTINE_DIR" ] && [ "$ARCHIVE_QUARANTINE_DAYS" -gt 0 ]; then
  if [ "$DRY_RUN" = "true" ]; then
    find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type f \
      -mtime +"$ARCHIVE_QUARANTINE_DAYS" -exec echo "prune-archive: WOULD REMOVE {}" \;
  else
    find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type f \
      -mtime +"$ARCHIVE_QUARANTINE_DAYS" -print -exec rm -f -- {} \;
  fi
fi

echo "prune-archive: completed"
