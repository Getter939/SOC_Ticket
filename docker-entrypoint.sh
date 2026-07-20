#!/bin/sh
set -eu

# Named volumes are mounted as root. Prepare their writable directories before
# dropping privileges so Django can collect static assets and store evidence,
# while the application server itself never runs as root.
if [ "${RUN_AS_APPUSER:-false}" = "true" ] && [ "$(id -u)" -eq 0 ]; then
    mkdir -p /app/staticfiles /app/media
    chown -R appuser:appuser /app/staticfiles /app/media
    exec runuser -u appuser -- "$@"
fi

exec "$@"
