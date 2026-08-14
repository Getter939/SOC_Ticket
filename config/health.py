"""Liveness/readiness endpoint for the production reverse proxy and monitoring.

Deliberately unauthenticated: whatever polls this runs before anyone can log in,
and a health check that needs a session cannot report that sessions are broken.
That makes the response body a public surface, so it carries no exception text,
no hostname, no settings and no schema detail — only whether the process is up
and whether it can reach its database.

`version` is opt-in via APP_VERSION so a deployment can be identified after a
release without leaking a git SHA on a server where nobody set it.
"""
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from decouple import config

APP_VERSION = config('APP_VERSION', default='unknown')


@require_GET
def healthz(request):
    """Report process liveness plus database reachability.

    200 when the database answers, 503 when it does not. The distinction
    matters during a boot race: Waitress depends on the PostgreSQL service, but
    the service reporting "Running" precedes it accepting connections, so a
    plain 200-if-the-process-is-up check would call the app healthy while every
    real request 500s.
    """
    database = 'ok'
    healthy = True

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
    except Exception:
        # The reason belongs in the log, not in an unauthenticated response.
        # LOGGING routes django.request/django.db failures to disk already.
        database = 'error'
        healthy = False

    response = JsonResponse(
        {
            'status': 'ok' if healthy else 'degraded',
            'database': database,
            'version': APP_VERSION,
        },
        status=200 if healthy else 503,
    )
    # A cached health check reports the past, which is worse than no check.
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response
