#!/bin/sh
set -eu

# Runs on the BACKUP VM (never on production). Pulls new backup archives from
# the production host over SSH, verifies each archive's SHA-256, and quarantines
# anything that does not match so the next run re-fetches it.
#
# Pull, not push: production holds no credentials for this host, so a
# compromised production VM cannot reach in and delete the archives. Deletions
# are never mirrored (no --delete), so pruning on prod does not prune here.
#
# See docs/operations/backup-vm-handbook.md.

fail() {
  echo "pull-archives: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

safe_positive_integer() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*) printf '%s' "$fallback" ;;
    *) printf '%s' "$value" ;;
  esac
}

# The .sha256 files are written on production with the *container's* path
# (/backups/...), so `sha256sum -c` would look for a file that does not exist
# here. Compare the hash field directly instead.
hash_of() {
  sha256sum "$1" | awk '{print $1}'
}

expected_hash() {
  awk '{print $1; exit}' "$1"
}

require_command rsync
require_command ssh
require_command sha256sum
require_command awk
require_command find

REMOTE="${REMOTE:?REMOTE is required, e.g. socpull@prod-host}"
# With an rrsync forced command the path is relative to the rrsync root, so the
# default './' means "the whole backup directory". Set an absolute path only if
# the key is not restricted by rrsync.
REMOTE_DIR="${REMOTE_DIR:-./}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/srv/soc-ticket/archive}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_PORT="${SSH_PORT:-22}"
BACKUP_PREFIX="${BACKUP_PREFIX:-soc_ticket}"
# An archive that arrives without its checksum may still have been mid-write on
# production. Give it this long to settle before treating it as damaged.
ARCHIVE_GRACE_MINUTES="$(safe_positive_integer "${ARCHIVE_GRACE_MINUTES:-30}" 30)"

[ -f "$SSH_KEY" ] || fail "ssh key not found: $SSH_KEY"

mkdir -p "$ARCHIVE_DIR"
[ -d "$ARCHIVE_DIR" ] || fail "ARCHIVE_DIR is not a directory: $ARCHIVE_DIR"
[ "$ARCHIVE_DIR" != "/" ] || fail "ARCHIVE_DIR must not be /"

QUARANTINE_DIR="$ARCHIVE_DIR/.quarantine"
mkdir -p "$QUARANTINE_DIR"

LOCK_DIR="$ARCHIVE_DIR/.pull.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  fail "another pull appears to be running; lock exists at $LOCK_DIR"
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT INT TERM

echo "pull-archives: pulling from ${REMOTE}:${REMOTE_DIR} into ${ARCHIVE_DIR}"

# --ignore-existing: archives are immutable once written (the timestamp is in
#   the filename), so never re-transfer or overwrite one we already hold.
# --exclude='.*'  : skip the lock directory and in-progress .staging trees.
# No --delete     : retention here is independent of production's.
rsync --archive --ignore-existing --human-readable \
  --exclude='.*' \
  -e "ssh -i ${SSH_KEY} -p ${SSH_PORT} -o BatchMode=yes -o StrictHostKeyChecking=yes" \
  "${REMOTE}:${REMOTE_DIR}" "${ARCHIVE_DIR}/"

QUARANTINED=0
VERIFIED=0

for archive in "$ARCHIVE_DIR"/${BACKUP_PREFIX}_*.tar.gz "$ARCHIVE_DIR"/${BACKUP_PREFIX}_*.tar.gz.enc "$ARCHIVE_DIR"/${BACKUP_PREFIX}_*.tar.gz.gpg; do
  [ -f "$archive" ] || continue
  sumfile="${archive}.sha256"

  if [ ! -f "$sumfile" ]; then
    # No checksum yet. Either it is still being written on production (fine,
    # wait) or it arrived damaged and its checksum never followed (not fine).
    if [ -n "$(find "$archive" -maxdepth 0 -mmin +"$ARCHIVE_GRACE_MINUTES" 2>/dev/null)" ]; then
      echo "pull-archives: QUARANTINE $(basename "$archive") — no checksum after ${ARCHIVE_GRACE_MINUTES}m" >&2
      mv -f "$archive" "$QUARANTINE_DIR/"
      QUARANTINED=$((QUARANTINED + 1))
    else
      echo "pull-archives: $(basename "$archive") has no checksum yet; leaving it for the next run"
    fi
    continue
  fi

  if [ "$(hash_of "$archive")" = "$(expected_hash "$sumfile")" ]; then
    VERIFIED=$((VERIFIED + 1))
  else
    echo "pull-archives: QUARANTINE $(basename "$archive") — SHA-256 mismatch" >&2
    mv -f "$archive" "$QUARANTINE_DIR/"
    mv -f "$sumfile" "$QUARANTINE_DIR/"
    QUARANTINED=$((QUARANTINED + 1))
  fi
done

echo "pull-archives: ${VERIFIED} archive(s) verified, ${QUARANTINED} quarantined"

if [ "$QUARANTINED" -gt 0 ]; then
  fail "${QUARANTINED} archive(s) failed verification and were moved to ${QUARANTINE_DIR}; they will be re-pulled next run"
fi

echo "pull-archives: completed"
