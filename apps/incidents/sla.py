"""SLA-pressure bucketing single source of truth.

Both the dashboard SLA-pressure chart and the ticket-list SLA filter classify
the active queue by time-to-deadline through these helpers. When the SLA policy
changes, edit it in one place here and both surfaces stay in sync.

Note: Ticket.SLA_HOURS still owns the deadline-setting policy (how far out
sla_deadline lands at creation). These knobs only classify how close an
existing deadline is to now().
"""
from datetime import timedelta

from django.db.models import Case, CharField, Q, Value, When

OVERDUE = 'overdue'
DUE_1H = 'due_1h'
DUE_4H = 'due_4h'
ON_TRACK = 'on_track'

# Policy knobs: hours from now.
# A deadline <= URGENT_HOURS away is "due <= 1h"; <= DUE_SOON_HOURS away is
# the wider at-risk window; anything further out (or null) is on-track.
URGENT_HOURS = 1
DUE_SOON_HOURS = 4

# Presentation: order, label, urgency color (red -> green ramp).
SLA_BUCKETS = [
    (OVERDUE, 'Overdue', '#dc3545'),
    (DUE_1H, 'Due <= 1h', '#fd7e14'),
    (DUE_4H, 'Due 1-4h', '#ffc107'),
    (ON_TRACK, 'On-track', '#198754'),
]
BUCKET_KEYS = {key for key, _, _ in SLA_BUCKETS}


def _edges(now):
    """Return the urgent and due-soon cutoffs measured from ``now``."""
    return now + timedelta(hours=URGENT_HOURS), now + timedelta(hours=DUE_SOON_HOURS)


def bucket_case(now):
    """ORM ``Case`` annotating each row with its SLA bucket key.

    A null sla_deadline (rare because Ticket.save() auto-sets it) falls into
    ON_TRACK.
    """
    t1, t4 = _edges(now)
    return Case(
        When(sla_deadline__lt=now, then=Value(OVERDUE)),
        When(sla_deadline__lte=t1, then=Value(DUE_1H)),
        When(sla_deadline__lte=t4, then=Value(DUE_4H)),
        default=Value(ON_TRACK),
        output_field=CharField(),
    )


def bucket_filter(bucket_key, now):
    """Return a ``Q`` selecting tickets in one bucket.

    Unknown keys return an empty ``Q``. The rules stay deliberately consistent
    with :func:`bucket_case`, including the null-deadline -> on-track rule.
    """
    t1, t4 = _edges(now)
    if bucket_key == OVERDUE:
        return Q(sla_deadline__lt=now)
    if bucket_key == DUE_1H:
        return Q(sla_deadline__gte=now, sla_deadline__lte=t1)
    if bucket_key == DUE_4H:
        return Q(sla_deadline__gt=t1, sla_deadline__lte=t4)
    if bucket_key == ON_TRACK:
        return Q(sla_deadline__gt=t4) | Q(sla_deadline__isnull=True)
    return Q()
