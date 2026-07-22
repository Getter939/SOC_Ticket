"""Daily queue-snapshot computation (Layer ③, Phase 2).

Captures the OPEN ticket queue as of a point in time, bucketed by backlog age
and OLA pressure. The OLA thresholds are imported from ``apps.incidents.ola`` so
the snapshot's buckets are identical to the live dashboard's — the single source
of truth is never duplicated here.
"""
from datetime import timedelta

from django.utils import timezone

from apps.incidents import ola
from apps.incidents.models import Ticket
from apps.reporting.models import SnapshotQueueDaily

# Backlog age buckets (open duration = now − created_at).
AGE_0_1D = '0-1d'
AGE_1_3D = '1-3d'
AGE_3_7D = '3-7d'
AGE_7D_PLUS = '7d+'

# OLA bucket for a ticket with no contain deadline (notification-only Med/Low).
OLA_NONE = 'none'


def age_bucket(created_at, now):
    age = now - created_at
    if age < timedelta(days=1):
        return AGE_0_1D
    if age < timedelta(days=3):
        return AGE_1_3D
    if age < timedelta(days=7):
        return AGE_3_7D
    return AGE_7D_PLUS


def ola_bucket(contain_deadline, now):
    """Classify a contain deadline into the same buckets as
    ``apps.incidents.ola.bucket_case`` — with an explicit ``none`` for the
    notification-only tickets that helper deliberately excludes."""
    if contain_deadline is None:
        return OLA_NONE
    urgent_edge = now + timedelta(hours=ola.URGENT_HOURS)
    due_soon_edge = now + timedelta(hours=ola.DUE_SOON_HOURS)
    if contain_deadline < now:
        return ola.OVERDUE
    if contain_deadline <= urgent_edge:
        return ola.DUE_1H
    if contain_deadline <= due_soon_edge:
        return ola.DUE_4H
    return ola.ON_TRACK


def compute_snapshot_rows(now=None, snapshot_date=None):
    """Return unsaved ``SnapshotQueueDaily`` rows for the open queue as of ``now``.

    ``snapshot_date`` defaults to the local (Asia/Bangkok) date of ``now``.
    """
    now = now or timezone.now()
    snapshot_date = snapshot_date or timezone.localdate(now)

    open_tickets = (
        Ticket.objects
        .exclude(status__in=Ticket.TERMINAL_STATUSES)
        .only('status', 'severity', 'created_at', 'ola_contain_deadline')
    )

    tally = {}
    for t in open_tickets:
        key = (
            t.status,
            t.severity,
            age_bucket(t.created_at, now),
            ola_bucket(t.ola_contain_deadline, now),
        )
        tally[key] = tally.get(key, 0) + 1

    return [
        SnapshotQueueDaily(
            snapshot_date=snapshot_date,
            status=status, severity=severity,
            age_bucket=ab, ola_bucket=ob, open_count=count,
        )
        for (status, severity, ab, ob), count in tally.items()
    ]
