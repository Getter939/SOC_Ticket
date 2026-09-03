#!/bin/sh
set -eu

# Runs on the BACKUP VM. Asserts that a recent archive of each required tier
# actually arrived, and exits non-zero if not.
#
# This exists because the dangerous failure mode of any backup system is
# SILENCE: the pull job dies, nobody notices, and the gap is discovered during
# a restore. Wire this to a timer with OnFailure= so a stalled pull is loud.
#
# See docs/archive/backup-vm-handbook.md.

fail() {
  echo "check-freshness: $*" >&2
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
# Space-separated "tier:max_age_hours" pairs. Defaults allow one missed daily
# run plus a couple of hours of slack before alerting.
FRESHNESS_CHECKS="${FRESHNESS_CHECKS:-daily:26 weekly:180}"
# Warn when the archive filesystem is filling up; a full disk stops the pull
# just as effectively as a broken key.
MIN_FREE_PERCENT="$(safe_positive_integer "${MIN_FREE_PERCENT:-15}" 15)"

[ -d "$ARCHIVE_DIR" ] || fail "ARCHIVE_DIR is not a directory: $ARCHIVE_DIR"

PROBLEMS=0

for check in $FRESHNESS_CHECKS; do
  tier="${check%%:*}"
  max_hours="${check##*:}"
  max_hours="$(safe_positive_integer "$max_hours" 26)"
  max_minutes=$((max_hours * 60))

  newest="$(find "$ARCHIVE_DIR" -mindepth 1 -maxdepth 1 -type f \
    -name "${BACKUP_PREFIX}_${tier}_*.tar.gz*" ! -name '*.sha256' \
    -mmin -"$max_minutes" -print 2>/dev/null | head -n 1)"

  if [ -n "$newest" ]; then
    echo "check-freshness: ${tier}: OK ($(basename "$newest"))"
  else
    echo "check-freshness: ${tier}: STALE — no archive newer than ${max_hours}h in ${ARCHIVE_DIR}" >&2
    PROBLEMS=$((PROBLEMS + 1))
  fi
done

QUARANTINE_DIR="$ARCHIVE_DIR/.quarantine"
if [ -d "$QUARANTINE_DIR" ]; then
  quarantined="$(find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
  if [ "$quarantined" -gt 0 ]; then
    echo "check-freshness: ${quarantined} file(s) in quarantine — transfers failing verification" >&2
    PROBLEMS=$((PROBLEMS + 1))
  fi
fi

if command -v df >/dev/null 2>&1; then
  used_percent="$(df -P "$ARCHIVE_DIR" | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
  free_percent=$((100 - used_percent))
  if [ "$free_percent" -lt "$MIN_FREE_PERCENT" ]; then
    echo "check-freshness: only ${free_percent}% free on the archive filesystem (floor ${MIN_FREE_PERCENT}%)" >&2
    PROBLEMS=$((PROBLEMS + 1))
  else
    echo "check-freshness: disk: OK (${free_percent}% free)"
  fi
fi

[ "$PROBLEMS" -eq 0 ] || fail "${PROBLEMS} problem(s) found"

echo "check-freshness: all checks passed"
