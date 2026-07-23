"""OLA-pressure bucketing single source of truth.

Both the dashboard OLA-pressure chart and the ticket-list OLA filter classify
the active queue by time-to-deadline through these helpers. When the OLA policy
changes, edit it in one place here and both surfaces stay in sync.

These helpers bucket on the CONTAIN/resolve deadline (``ola_contain_deadline``).
Medium/Low severities have no contain deadline (notification-only), so they are
NOT bucketed here — callers should exclude null-contain rows (the dashboard
filters ``ola_contain_deadline__isnull=False`` before annotating).

Note: Ticket.OLA_TARGETS owns the deadline-setting policy (how far out each
deadline lands at creation, per severity). These knobs only classify how close
an existing contain deadline is to now().
"""
from datetime import timedelta

from django.db.models import Case, CharField, Q, Value, When
from django.utils import timezone

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
OLA_BUCKETS = [
    (OVERDUE, 'Overdue', '#dc3545'),
    (DUE_1H, 'Due <= 1h', '#fd7e14'),
    (DUE_4H, 'Due 1-4h', '#ffc107'),
    (ON_TRACK, 'On-track', '#198754'),
]
BUCKET_KEYS = {key for key, _, _ in OLA_BUCKETS}
BUCKET_BG = {key: color for key, _, color in OLA_BUCKETS}
# Amber needs dark text to stay readable; the rest carry white.
BUCKET_FG = {
    OVERDUE: '#ffffff', DUE_1H: '#ffffff', DUE_4H: '#212529', ON_TRACK: '#ffffff',
}


def _edges(now):
    """Return the urgent and due-soon cutoffs measured from ``now``."""
    return now + timedelta(hours=URGENT_HOURS), now + timedelta(hours=DUE_SOON_HOURS)


def bucket_case(now):
    """ORM ``Case`` annotating each row with its OLA (contain) bucket key.

    Assumes rows have a non-null ``ola_contain_deadline`` (callers pre-filter
    the notification-only Medium/Low tickets); a null would fall into ON_TRACK.
    """
    t1, t4 = _edges(now)
    return Case(
        When(ola_contain_deadline__lt=now, then=Value(OVERDUE)),
        When(ola_contain_deadline__lte=t1, then=Value(DUE_1H)),
        When(ola_contain_deadline__lte=t4, then=Value(DUE_4H)),
        default=Value(ON_TRACK),
        output_field=CharField(),
    )


def bucket_filter(bucket_key, now):
    """Return a ``Q`` selecting tickets in one contain-OLA bucket.

    Unknown keys return an empty ``Q``. Null-contain tickets (notification-only)
    match no bucket. Kept deliberately consistent with :func:`bucket_case`.
    """
    t1, t4 = _edges(now)
    if bucket_key == OVERDUE:
        return Q(ola_contain_deadline__lt=now)
    if bucket_key == DUE_1H:
        return Q(ola_contain_deadline__gte=now, ola_contain_deadline__lte=t1)
    if bucket_key == DUE_4H:
        return Q(ola_contain_deadline__gt=t1, ola_contain_deadline__lte=t4)
    if bucket_key == ON_TRACK:
        return Q(ola_contain_deadline__gt=t4)
    return Q()


# ---------------------------------------------------------------------- #
# Row-level presentation — the queue tables' OLA column                   #
# ---------------------------------------------------------------------- #

def bucket_for(deadline, now=None):
    """Bucket a single deadline in Python — the row-level twin of bucket_case.

    Kept beside bucket_case deliberately: the two must agree, or a list sorted
    by the ORM bucket would show badges that contradict the ordering.
    """
    if deadline is None:
        return None
    now = now or timezone.now()
    t1, t4 = _edges(now)
    if deadline < now:
        return OVERDUE
    if deadline <= t1:
        return DUE_1H
    if deadline <= t4:
        return DUE_4H
    return ON_TRACK


def _humanize(delta):
    """Coarse Thai duration: minutes under an hour, days once past one."""
    total_minutes = int(delta.total_seconds() // 60)
    if total_minutes < 1:
        return 'ไม่ถึง 1 น.'
    days, rem = divmod(total_minutes, 60 * 24)
    hours, minutes = divmod(rem, 60)
    if days:
        return f'{days} ว. {hours} ชม.' if hours else f'{days} ว.'
    if hours:
        return f'{hours} ชม. {minutes} น.' if minutes else f'{hours} ชม.'
    return f'{minutes} น.'


def badge_for(deadline, *, done=False, now=None):
    """Presentation dict for the shared ``incidents/_ola_badge.html`` include.

    Returns None when there is nothing meaningful to show — no deadline at all
    (Medium/Low are notification-only, so they never get a contain deadline) or
    the work is already finished, where a live countdown would be noise.
    """
    if deadline is None or done:
        return None
    now = now or timezone.now()
    bucket = bucket_for(deadline, now)
    delta = deadline - now
    overdue = delta.total_seconds() < 0
    amount = _humanize(abs(delta))
    return {
        'bucket': bucket,
        'bg': BUCKET_BG[bucket],
        'fg': BUCKET_FG[bucket],
        'overdue': overdue,
        'label': f'เกิน {amount}' if overdue else f'เหลือ {amount}',
        'deadline': deadline,
    }
