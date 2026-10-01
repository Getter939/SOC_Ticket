"""Watchdog for the nightly reporting job — catches the night it never ran.

``refresh_reporting`` emails on its own errors, but it can't report a night it
never started (server down, task disabled, credentials expired). Schedule this
a few hours after it — 07:00 for the 00:20 run — and it checks that tonight's
work is actually in the mart:

  - a ``snapshot_kpi_daily`` row for today (written by every successful run,
    even when the queue is empty);
  - a ``hist_alert_daily`` row for yesterday whenever alerts arrived yesterday;
  - ``agg_detection_daily`` up to yesterday, when the Indexer is configured.

Any gap is emailed to ``REPORTING_ALERT_EMAILS`` and the command exits
non-zero, so Task Scheduler's "Last Run Result" flags it too.

    schtasks /create /tn "SOC-Check-Reporting" /sc daily /st 07:00 ^
        /tr "C:\\SOCTicket\\app\\venv\\Scripts\\python.exe C:\\SOCTicket\\app\\manage.py check_reporting_freshness"
"""
from datetime import datetime, time, timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Max
from django.utils import timezone

from apps.reporting.alerts import send_reporting_alert
from apps.reporting.models import AggDetectionDaily, HistAlertDaily, SnapshotKpiDaily
from apps.wazuh_ingest.models import WazuhAlert


def find_problems(today=None):
    """Return a list of human-readable problems (empty = all fresh)."""
    today = today or timezone.localdate()
    yesterday = today - timedelta(days=1)
    problems = []

    if not SnapshotKpiDaily.objects.filter(snapshot_date=today).exists():
        last = SnapshotKpiDaily.objects.aggregate(d=Max('snapshot_date'))['d']
        problems.append(
            f'No nightly snapshot for {today:%Y-%m-%d} '
            f'(last: {last:%Y-%m-%d}).' if last else
            f'No nightly snapshot for {today:%Y-%m-%d}, and none ever written.')

    tz = timezone.get_current_timezone()
    y_start = timezone.make_aware(datetime.combine(yesterday, time.min), tz)
    alerts_yesterday = WazuhAlert.objects.filter(
        timestamp__gte=y_start, timestamp__lt=y_start + timedelta(days=1)).exists()
    if alerts_yesterday and not HistAlertDaily.objects.filter(day=yesterday).exists():
        problems.append(
            f'Alerts arrived on {yesterday:%Y-%m-%d} but the alert funnel history '
            'has no row for that day.')

    if getattr(settings, 'OPENSEARCH_HOST', ''):
        last = AggDetectionDaily.objects.aggregate(d=Max('day'))['d']
        if last is None:
            problems.append('Detection capture has never written a row.')
        elif last < yesterday:
            problems.append(
                f'Detection capture is behind: last day {last:%Y-%m-%d}, expected '
                f'{yesterday:%Y-%m-%d} (a day with no alerts at all would also show this).')
    return problems


class Command(BaseCommand):
    help = 'Check that last night\'s refresh_reporting run landed in the mart; email if not.'

    def handle(self, *args, **options):
        problems = find_problems()
        if not problems:
            self.stdout.write('reporting mart is fresh')
            return
        for p in problems:
            self.stderr.write(p)
        send_reporting_alert('nightly reporting data is missing', problems)
        raise CommandError(f'{len(problems)} freshness problem(s); see above.')
