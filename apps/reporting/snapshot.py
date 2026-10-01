"""Daily queue-snapshot computation (Layer ③, Phase 2).

Captures the OPEN ticket queue as of a point in time, bucketed by backlog age
and OLA pressure. The OLA thresholds are imported from ``apps.incidents.ola`` so
the snapshot's buckets are identical to the live dashboard's — the single source
of truth is never duplicated here.
"""
from datetime import timedelta

from django.utils import timezone

from django.db.models import Count, Min, Q

from apps.incidents import ola
from apps.incidents.models import Ticket, TicketSubtask
from apps.reporting.models import (
    SnapshotKpiDaily, SnapshotQueueDaily, SnapshotResponseDaily, SnapshotWorkloadDaily,
)

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


# ── Phase 3b (2026-10-01): figures the queue snapshot cannot give ─────────── #
# Same "open" rules as the live dashboards, so a mart trend and the LIVE number
# beside it agree on the day they overlap.

RESPONSE_AGED_DAYS = 7


def _open_tickets():
    return Ticket.objects.exclude(status__in=Ticket.TERMINAL_STATUSES)


def _open_response_requests():
    """The executive dashboard's ``active_response_q``: an OPEN or IN_PROGRESS
    response request on a ticket that is not closed."""
    return TicketSubtask.objects.filter(
        subtask_type__in=TicketSubtask.RESPONSE_TYPES,
        status__in=(TicketSubtask.STATUS_OPEN, TicketSubtask.STATUS_IN_PROGRESS),
    ).exclude(ticket__status__in=Ticket.TERMINAL_STATUSES)


def compute_kpi_row(now=None, snapshot_date=None):
    """Return the unsaved one-row ``SnapshotKpiDaily`` for the night."""
    now = now or timezone.now()
    snapshot_date = snapshot_date or timezone.localdate(now)
    open_qs = _open_tickets()
    oldest = open_qs.aggregate(m=Min('created_at'))['m']
    responses = _open_response_requests()
    aged_before = now - timedelta(days=RESPONSE_AGED_DAYS)
    return SnapshotKpiDaily(
        snapshot_date=snapshot_date,
        open_tickets=open_qs.count(),
        unassigned_open=open_qs.filter(assigned_to__isnull=True).count(),
        emergency_open_tickets=open_qs.filter(is_emergency=True).count(),
        emergency_open_incidents=open_qs.filter(is_emergency=True).incident_count(),
        oldest_open_hours=(
            max(0, int((now - oldest).total_seconds() // 3600)) if oldest else None),
        response_open=responses.count(),
        response_aged_7d=responses.filter(created_at__lt=aged_before).count(),
        captured_at=now,
    )


def compute_workload_rows(now=None, snapshot_date=None):
    """Return unsaved ``SnapshotWorkloadDaily`` rows: who held the open queue.

    Two holders, as the SOC dashboard's Analyst Workload counts them: the
    assignee (``assigned_to``; NULL = unassigned) and the Tier 2 claimant
    (``t2_claimed_by``, only rows that have one)."""
    now = now or timezone.now()
    snapshot_date = snapshot_date or timezone.localdate(now)
    open_qs = _open_tickets()
    rows = []
    for kind, field, qs in (
        (SnapshotWorkloadDaily.KIND_ASSIGNED, 'assigned_to', open_qs),
        (SnapshotWorkloadDaily.KIND_T2_CLAIMED, 't2_claimed_by',
         open_qs.filter(t2_claimed_by__isnull=False)),
    ):
        grouped = (
            qs.order_by()
            .values(field, f'{field}__username', 'status', 'severity')
            .annotate(c=Count('pk'))
        )
        for r in grouped:
            rows.append(SnapshotWorkloadDaily(
                snapshot_date=snapshot_date, kind=kind,
                user_id=r[field], username=r[f'{field}__username'] or '',
                status=r['status'], severity=r['severity'], open_count=r['c'],
            ))
    return rows


def compute_response_rows(now=None, snapshot_date=None):
    """Return unsaved ``SnapshotResponseDaily`` rows: open response requests by
    function, status, age (over 7 days) and whether the ticket is High/Critical."""
    now = now or timezone.now()
    snapshot_date = snapshot_date or timezone.localdate(now)
    aged_before = now - timedelta(days=RESPONSE_AGED_DAYS)
    grouped = (
        _open_response_requests().order_by()
        .values('subtask_type', 'status')
        .annotate(
            aged_hc=Count('pk', filter=Q(created_at__lt=aged_before,
                                         ticket__severity__in=('Critical', 'High'))),
            aged_other=Count('pk', filter=Q(created_at__lt=aged_before)
                             & ~Q(ticket__severity__in=('Critical', 'High'))),
            fresh_hc=Count('pk', filter=Q(created_at__gte=aged_before,
                                          ticket__severity__in=('Critical', 'High'))),
            fresh_other=Count('pk', filter=Q(created_at__gte=aged_before)
                              & ~Q(ticket__severity__in=('Critical', 'High'))),
        )
    )
    rows = []
    for r in grouped:
        for key, aged, hc in (('aged_hc', True, True), ('aged_other', True, False),
                              ('fresh_hc', False, True), ('fresh_other', False, False)):
            if r[key]:
                rows.append(SnapshotResponseDaily(
                    snapshot_date=snapshot_date, subtask_type=r['subtask_type'],
                    status=r['status'], aged_7d=aged, hc_ticket=hc, open_count=r[key],
                ))
    return rows
