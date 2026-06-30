"""
Dashboard tests — Change 5.

Coverage:
  - Access control: SOC (staff + manager) sees dashboard; system admin is
    redirected; unauthenticated user hits the login redirect.
  - SLA-breach query: overdue active ticket counted; overdue terminal ticket
    NOT counted; not-yet-due active ticket NOT counted.
  - Metrics: active vs closed split, FP/TP counts and percentages, and the
    who-must-act backlog are correct given known fixture data.

These tests use Django's TestCase (each test wrapped in its own DB
transaction, rolled back on teardown), so ticket data created in one test
does not bleed into another.  Users are created with setUpTestData for
efficiency — they are shared across tests in the same class.
"""
from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket


# ── Helpers ──────────────────────────────────────────────────────────────── #

def _make_user(username, role, email=''):
    """Create a User + UserProfile with the given role."""
    from django.contrib.auth.models import User
    user = User.objects.create_user(username=username, password='pw', email=email)
    UserProfile.objects.create(
        user=user, role=role, department='Test Dept', phone='000-000-0000',
    )
    return user


def _make_ticket(
    status=Ticket.STATUS_NEW,
    sla_offset_hours=None,
    classification='',
):
    """
    Create a Ticket directly (bypassing the state machine).

    sla_offset_hours — if given, overrides the auto-set sla_deadline.
      Positive = future (not breached); negative = past (breached).
      If not given, Ticket.save() auto-sets sla_deadline = now + 48 h.
    """
    kwargs = {
        'device_name':      '192.168.1.1',
        'ip_address':       '10.0.0.1',
        'issue_description': 'Test incident',
        'status':           status,
        'classification':   classification,
    }
    if sla_offset_hours is not None:
        kwargs['sla_deadline'] = timezone.now() + timedelta(hours=sla_offset_hours)
    return Ticket.objects.create(**kwargs)


DASHBOARD_URL = reverse('home')


# ── Access-control tests ─────────────────────────────────────────────────── #

class DashboardAccessTest(TestCase):
    """Change 1: SOC roles see the dashboard; system admins are redirected."""

    @classmethod
    def setUpTestData(cls):
        cls.soc_staff = _make_user('soc_staff_ac',  UserProfile.ROLE_SOC_STAFF)
        cls.soc_mgr   = _make_user('soc_mgr_ac',    UserProfile.ROLE_SOC_MANAGER)
        cls.sys_admin = _make_user('sys_admin_ac',  UserProfile.ROLE_SYSTEM_ADMIN)

    def test_soc_staff_sees_dashboard(self):
        self.client.force_login(self.soc_staff)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/dashboard.html')

    def test_soc_manager_sees_dashboard(self):
        self.client.force_login(self.soc_mgr)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/dashboard.html')

    def test_system_admin_is_redirected(self):
        """System admins must not see org-wide aggregates — redirect to ticket_list."""
        self.client.force_login(self.sys_admin)
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('ticket_list'), fetch_redirect_response=False)

    def test_unauthenticated_user_redirected_to_login(self):
        response = self.client.get(DASHBOARD_URL)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response['Location'])

    def test_superuser_without_profile_sees_dashboard(self):
        from django.contrib.auth.models import User
        superuser = User.objects.create_superuser(
            username='dashboard_superuser',
            email='dashboard-super@example.com',
            password='pw',
        )
        self.client.force_login(superuser)

        response = self.client.get(DASHBOARD_URL)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/dashboard.html')


# ── SLA-breach counting tests ────────────────────────────────────────────── #

class DashboardSLABreachTest(TestCase):
    """
    Change 2: SLA breach count is pure-DB and excludes terminal tickets.

    Each test creates its own tickets; Django's TestCase rolls them back
    automatically, so tests are independent.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_sla', UserProfile.ROLE_SOC_STAFF)

    def _get_sla_count(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']['sla_breaches']

    def test_overdue_active_ticket_is_counted(self):
        """An active ticket whose sla_deadline is in the past must be counted."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 1)

    def test_overdue_ticket_in_terminal_state_not_counted(self):
        """A terminal ticket whose sla_deadline is in the past must NOT be counted."""
        _make_ticket(status=Ticket.STATUS_APPROVED, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 0)

    def test_overdue_closed_event_ticket_not_counted(self):
        """CLOSED_EVENT is also a terminal state — must not appear in SLA breach count."""
        _make_ticket(status=Ticket.STATUS_CLOSED_EVENT, sla_offset_hours=-1)
        self.assertEqual(self._get_sla_count(), 0)

    def test_not_yet_due_active_ticket_not_counted(self):
        """An active ticket with sla_deadline still in the future must NOT be counted."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=24)
        self.assertEqual(self._get_sla_count(), 0)

    def test_mixed_tickets_only_active_overdue_counted(self):
        """Only the overdue-and-active subset contributes to the breach count."""
        _make_ticket(status=Ticket.STATUS_NEW,      sla_offset_hours=-2)   # counted
        _make_ticket(status=Ticket.STATUS_APPROVED, sla_offset_hours=-2)   # NOT counted (terminal)
        _make_ticket(status=Ticket.STATUS_NEW,      sla_offset_hours=48)   # NOT counted (future)
        self.assertEqual(self._get_sla_count(), 1)


# ── Metrics accuracy tests ───────────────────────────────────────────────── #

class DashboardMetricsTest(TestCase):
    """
    Change 3: active/closed split, FP/TP counts, and actionable backlog
    all match the known fixture data.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_metrics', UserProfile.ROLE_SOC_STAFF)

    def _stats(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']

    # ── active / closed split ──────────────────────────────────────────── #

    def test_active_vs_closed_split(self):
        """active = non-terminal; closed = APPROVED + CLOSED_EVENT."""
        _make_ticket(status=Ticket.STATUS_NEW)                  # active
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT) # active
        _make_ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED) # active
        _make_ticket(status=Ticket.STATUS_APPROVED)             # closed (terminal)
        _make_ticket(status=Ticket.STATUS_CLOSED_EVENT)         # closed (terminal)

        s = self._stats()
        self.assertEqual(s['active'], 3)
        self.assertEqual(s['closed'], 2)
        self.assertEqual(s['total'],  5)

    def test_all_active_no_closed(self):
        _make_ticket(status=Ticket.STATUS_NEW)
        _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        s = self._stats()
        self.assertEqual(s['active'], 2)
        self.assertEqual(s['closed'], 0)
        self.assertEqual(s['total'],  2)

    # ── Event/Incident counts and percentages ──────────────────────────── #

    def test_incident_event_counts_and_percentages(self):
        """2 Incident + 1 Event → tp_pct=67 (Incident), fp_pct=33 (Event)."""
        _make_ticket(classification=Ticket.CLASSIFICATION_INCIDENT, status=Ticket.STATUS_APPROVED)
        _make_ticket(classification=Ticket.CLASSIFICATION_INCIDENT, status=Ticket.STATUS_APPROVED)
        _make_ticket(classification=Ticket.CLASSIFICATION_EVENT,    status=Ticket.STATUS_CLOSED_EVENT)
        _make_ticket(status=Ticket.STATUS_NEW)  # unclassified — not counted in ratio

        s = self._stats()
        self.assertEqual(s['tp_count'], 2)
        self.assertEqual(s['fp_count'], 1)
        self.assertEqual(s['tp_pct'],  67)
        self.assertEqual(s['fp_pct'],  33)

    def test_counts_zero_when_no_classifications(self):
        """No closed/classified tickets → all zeros; no ZeroDivisionError."""
        _make_ticket(status=Ticket.STATUS_NEW)
        s = self._stats()
        self.assertEqual(s['tp_count'], 0)
        self.assertEqual(s['fp_count'], 0)
        self.assertEqual(s['tp_pct'],  0)
        self.assertEqual(s['fp_pct'],  0)

    def test_all_incident(self):
        """100% Incident: fp_count=0, tp_pct=100, fp_pct=0."""
        _make_ticket(classification=Ticket.CLASSIFICATION_INCIDENT, status=Ticket.STATUS_APPROVED)
        s = self._stats()
        self.assertEqual(s['tp_count'], 1)
        self.assertEqual(s['fp_count'], 0)
        self.assertEqual(s['tp_pct'],  100)
        self.assertEqual(s['fp_pct'],  0)

    # ── Actionable backlog ─────────────────────────────────────────────── #

    def test_actionable_backlog_correct(self):
        """
        awaiting_admin   = AWAITING_CONTAINMENT count
        awaiting_soc     = CONTAINMENT_REPORTED + T1_REVIEW + ESCALATED_T2
        awaiting_manager = PENDING_MANAGER
        """
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT)  # → admin (×2)
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT)
        _make_ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED)  # → soc (×1)
        _make_ticket(status=Ticket.STATUS_T1_REVIEW)             # → soc (×1)
        _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)       # → manager (×1)
        _make_ticket(status=Ticket.STATUS_NEW)                   # counted nowhere

        s = self._stats()
        self.assertEqual(s['awaiting_admin'],   2)
        self.assertEqual(s['awaiting_soc'],     2)
        self.assertEqual(s['awaiting_manager'], 1)

    def test_backlog_zero_when_no_tickets(self):
        """All backlog counters are 0 when there are no tickets."""
        s = self._stats()
        self.assertEqual(s['awaiting_admin'],   0)
        self.assertEqual(s['awaiting_soc'],     0)
        self.assertEqual(s['awaiting_manager'], 0)


# ── Enterprise KPI tests (corrected logic) ───────────────────────────────── #

class DashboardEnterpriseKPITest(TestCase):
    """
    Corrected enterprise KPIs added to the dashboard stats block:
      - sla_compliance_rate (100% / 0% / None)
      - sla_breach_live (live against-deadline, not time-to-file)
      - sla_at_risk
      - mttr_median / mttr_mean / mttr_n
      - backlog_aging buckets
      - assignee_workload
      - severity_breakdown
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_kpi', UserProfile.ROLE_SOC_STAFF)

    def _stats(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']

    def _resolve(self, ticket, resolved_at, sla_deadline):
        """
        Drive a ticket into a terminal state with a known resolution time.

        Writes a TicketLog row (the dashboard derives resolution time from the
        first terminal-status log entry) and pins created_at / sla_deadline.
        created_at is forced via queryset .update() to bypass auto_now_add.
        """
        from apps.incidents.models import TicketLog
        ticket.status = Ticket.STATUS_APPROVED
        ticket.sla_deadline = sla_deadline
        ticket.save()
        # Pin created_at (auto_now_add ignores assignment on save)
        Ticket.objects.filter(pk=ticket.pk).update(
            created_at=resolved_at - timedelta(hours=2),
        )
        log = TicketLog.objects.create(
            ticket=ticket,
            note='resolved',
            status_at_time=Ticket.STATUS_APPROVED,
            author=self.soc,
        )
        TicketLog.objects.filter(pk=log.pk).update(created_at=resolved_at)
        return ticket

    # ── sla_compliance_rate ────────────────────────────────────────────── #

    def test_compliance_rate_100(self):
        """Resolved before deadline → 100%."""
        now = timezone.now()
        t = _make_ticket(status=Ticket.STATUS_NEW)
        # resolved an hour before the deadline
        self._resolve(t, resolved_at=now - timedelta(hours=2),
                      sla_deadline=now - timedelta(hours=1))
        self.assertEqual(self._stats()['sla_compliance_rate'], 100.0)

    def test_compliance_rate_0(self):
        """Resolved after deadline → 0%."""
        now = timezone.now()
        t = _make_ticket(status=Ticket.STATUS_NEW)
        # resolved an hour AFTER the deadline
        self._resolve(t, resolved_at=now - timedelta(hours=1),
                      sla_deadline=now - timedelta(hours=2))
        self.assertEqual(self._stats()['sla_compliance_rate'], 0.0)

    def test_compliance_rate_none_when_no_resolved(self):
        """No resolved tickets → None (no ZeroDivisionError)."""
        _make_ticket(status=Ticket.STATUS_NEW)   # active only
        self.assertIsNone(self._stats()['sla_compliance_rate'])

    # ── sla_breach_live ────────────────────────────────────────────────── #

    def test_breach_live_counts_overdue_active(self):
        """Active ticket whose deadline is in the past is counted live."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=-1)
        self.assertEqual(self._stats()['sla_breach_live'], 1)

    def test_breach_live_ignores_future_deadline(self):
        """Active ticket whose deadline is still in the future is not counted."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=6)
        self.assertEqual(self._stats()['sla_breach_live'], 0)

    def test_breach_live_ignores_terminal(self):
        """A resolved/terminal ticket past deadline is not a live breach."""
        _make_ticket(status=Ticket.STATUS_APPROVED, sla_offset_hours=-1)
        self.assertEqual(self._stats()['sla_breach_live'], 0)

    # ── sla_at_risk ────────────────────────────────────────────────────── #

    def test_at_risk_within_4h_window(self):
        """Active, not breached, deadline within next 4h → at risk."""
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=2)    # at risk
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=10)   # too far out
        _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=-1)   # already breached
        self.assertEqual(self._stats()['sla_at_risk'], 1)

    # ── MTTR ───────────────────────────────────────────────────────────── #

    def test_mttr_median_known_timestamps(self):
        """Two resolved tickets (2h and 4h) → median 3.0h, mean 3.0h, n=2."""
        now = timezone.now()
        t1 = _make_ticket(status=Ticket.STATUS_NEW)
        t2 = _make_ticket(status=Ticket.STATUS_NEW)
        # _resolve sets created_at = resolved_at - 2h, giving a 2.0h MTTR.
        self._resolve(t1, resolved_at=now - timedelta(days=1),
                      sla_deadline=now)
        # For t2 craft a 4h gap explicitly.
        from apps.incidents.models import TicketLog
        t2.status = Ticket.STATUS_APPROVED
        t2.sla_deadline = now
        t2.save()
        resolved2 = now - timedelta(days=2)
        Ticket.objects.filter(pk=t2.pk).update(
            created_at=resolved2 - timedelta(hours=4))
        log = TicketLog.objects.create(
            ticket=t2, note='resolved',
            status_at_time=Ticket.STATUS_APPROVED, author=self.soc)
        TicketLog.objects.filter(pk=log.pk).update(created_at=resolved2)

        s = self._stats()
        self.assertEqual(s['mttr_n'], 2)
        self.assertEqual(s['mttr_median'], 3.0)
        self.assertEqual(s['mttr_mean'], 3.0)

    def test_mttr_none_when_no_recent_resolved(self):
        """No resolved tickets in the last 30 days → n=0, median/mean None."""
        _make_ticket(status=Ticket.STATUS_NEW)
        s = self._stats()
        self.assertEqual(s['mttr_n'], 0)
        self.assertIsNone(s['mttr_median'])
        self.assertIsNone(s['mttr_mean'])

    # ── backlog_aging ──────────────────────────────────────────────────── #

    def test_backlog_aging_one_per_bucket(self):
        """One active ticket lands in each of fresh / aging / stale."""
        now = timezone.now()
        fresh = _make_ticket(status=Ticket.STATUS_NEW)   # ~now → fresh
        aging = _make_ticket(status=Ticket.STATUS_NEW)
        stale = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=aging.pk).update(
            created_at=now - timedelta(days=2))          # 1–3d → aging
        Ticket.objects.filter(pk=stale.pk).update(
            created_at=now - timedelta(days=5))          # >3d → stale

        buckets = self._stats()['backlog_aging']
        self.assertEqual(buckets['fresh'], 1)
        self.assertEqual(buckets['aging'], 1)
        self.assertEqual(buckets['stale'], 1)

    # ── assignee_workload ──────────────────────────────────────────────── #

    def test_assignee_workload(self):
        """Open + breached counts per assignee, sorted by open desc."""
        from django.contrib.auth.models import User
        analyst = User.objects.create_user(
            username='kpi_analyst', password='pw',
            first_name='Ada', last_name='Lovelace')

        t1 = _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=-1)  # breached
        t2 = _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=6)   # ok
        Ticket.objects.filter(pk__in=[t1.pk, t2.pk]).update(assigned_to=analyst)

        workload = self._stats()['assignee_workload']
        self.assertEqual(len(workload), 1)
        row = workload[0]
        self.assertEqual(row['name'], 'Ada Lovelace')
        self.assertEqual(row['open'], 2)
        self.assertEqual(row['breached'], 1)

    # ── severity_breakdown ─────────────────────────────────────────────── #

    def test_severity_breakdown_sorted_critical_first(self):
        """Active tickets grouped by severity, critical first."""
        _make_ticket(status=Ticket.STATUS_NEW)                       # default High
        low = _make_ticket(status=Ticket.STATUS_NEW)
        crit = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=low.pk).update(severity='Low')
        Ticket.objects.filter(pk=crit.pk).update(severity='Critical')

        breakdown = self._stats()['severity_breakdown']
        labels = [b['label'] for b in breakdown]
        self.assertEqual(labels[0], 'Critical')      # highest rank first
        self.assertEqual(labels[-1], 'Low')          # lowest rank last
        counts = {b['label']: b['count'] for b in breakdown}
        self.assertEqual(counts['Critical'], 1)
        self.assertEqual(counts['High'], 1)
        self.assertEqual(counts['Low'], 1)


# ── Management dashboard (Session 3) — template + context tests ──────────── #

class DashboardManagementViewTest(TestCase):
    """The redesigned management dashboard renders and exposes the new keys."""

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_mgmt', UserProfile.ROLE_SOC_STAFF)

    def setUp(self):
        self.client.force_login(self.soc)

    def _get(self, **params):
        return self.client.get(DASHBOARD_URL, params)

    # ── Stat cards ─────────────────────────────────────────────────────── #

    def test_four_stat_card_labels_present(self):
        """All four management card labels render (STEP 2A)."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn('Total Active Cases', html)
        self.assertIn('Critical Severity', html)
        self.assertIn('Closed This Month', html)
        self.assertIn('Mean Time to Resolve (MTTR)', html)
        # Header timestamp + filter bar still present
        self.assertIn('ข้อมูล ณ เวลา:', html)
        self.assertIn('date_range=today', html)

    # ── Removed sections must be gone ──────────────────────────────────── #

    def test_removed_sections_absent(self):
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertNotIn('Backlog Aging', html)
        self.assertNotIn('สัดส่วน Event / Incident', html)
        self.assertNotIn('Severity Breakdown', html)
        self.assertNotIn('Pipeline View', html)
        self.assertNotIn('chartBacklog', html)

    # ── New sections render ────────────────────────────────────────────── #

    def test_assignee_heatmap_renders(self):
        """Heatmap table + analyst name render when assignee_heatmap is non-empty."""
        from django.contrib.auth.models import User
        analyst = User.objects.create_user(
            username='heat_a', password='pw',
            first_name='Grace', last_name='Hopper')
        t = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=t.pk).update(assigned_to=analyst)

        resp = self._get()
        self.assertTrue(resp.context['assignee_heatmap'])
        html = resp.content.decode()
        self.assertIn('Analyst Workload', html)
        self.assertIn('Grace Hopper', html)

    def test_category_sections_render_even_without_data(self):
        """Pipeline and resolved-by-category sections render (latter as placeholder)."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertNotIn('Avg MTTR by Category', html)   # removed in Session 3C
        self.assertIn('Resolved Tickets by Incident Category', html)
        self.assertIn('Daily Case Volume', html)
        self.assertIn('Recent Active Cases', html)

    def test_pipeline_chart_renders(self):
        """Pipeline stacked-bar replaces the MTTR chart in Row 3L."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn('chartPipeline', html)
        self.assertIn('Pipeline', html)

    def test_pipeline_by_severity_structure_and_zero_fill(self):
        """pipeline_by_severity has statuses/severities/matrix; matrix is zero-filled."""
        # One ticket only touches a single (severity, status) cell — every other
        # status must still be present under every severity (no gaps).
        c = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=c.pk).update(severity='Critical')
        pbs = self._get().context['pipeline_by_severity']

        self.assertEqual(set(pbs), {'statuses', 'severities', 'matrix'})
        status_slugs = [slug for slug, _ in pbs['statuses']]
        # Severities are highest rank first.
        self.assertEqual([s for s, _ in pbs['severities']][0], 'Critical')
        # Every status slug appears under every severity (zero-fill).
        for sev_slug, _ in pbs['severities']:
            self.assertEqual(set(pbs['matrix'][sev_slug]), set(status_slugs))
        # The one ticket landed in exactly its cell.
        self.assertEqual(pbs['matrix']['Critical'][Ticket.STATUS_NEW], 1)
        self.assertEqual(pbs['matrix']['Low'][Ticket.STATUS_NEW], 0)

    def test_pipeline_includes_terminal_statuses(self):
        """Pipeline covers the full funnel, including terminal statuses."""
        _make_ticket(status=Ticket.STATUS_APPROVED)
        pbs = self._get().context['pipeline_by_severity']
        status_slugs = [slug for slug, _ in pbs['statuses']]
        self.assertIn(Ticket.STATUS_APPROVED, status_slugs)
        self.assertIn(Ticket.STATUS_CLOSED_EVENT, status_slugs)

    # ── New context keys ───────────────────────────────────────────────── #

    def test_daily_trend_filtered_zero_filled_no_gaps(self):
        """daily_trend_filtered is a ≤31-item list with no date gaps (zero-fill)."""
        from datetime import datetime
        ctx = self._get().context
        self.assertIn('daily_trend_filtered', ctx)
        trend = ctx['daily_trend_filtered']
        self.assertIsInstance(trend, list)
        self.assertLessEqual(len(trend), 31)
        self.assertIn('date', trend[0])
        self.assertIn('count', trend[0])
        # Default (all-time) → daily mode covering 30 days.
        self.assertEqual(len(trend), 30)
        # Consecutive dates differ by exactly one day (proves zero-fill).
        dates = [datetime.strptime(d['date'], '%Y-%m-%d').date() for d in trend]
        for earlier, later in zip(dates, dates[1:]):
            self.assertEqual((later - earlier).days, 1)

    def test_daily_trend_week_filter_is_seven_days(self):
        """date_range=week → 7 daily buckets."""
        trend = self._get(date_range='week').context['daily_trend_filtered']
        self.assertEqual(len(trend), 7)

    def test_daily_trend_today_filter_is_hourly(self):
        """date_range=today → hourly buckets labelled 'YYYY-MM-DD HH:00'."""
        trend = self._get(date_range='today').context['daily_trend_filtered']
        self.assertTrue(trend)
        self.assertRegex(trend[0]['date'], r'^\d{4}-\d{2}-\d{2} \d{2}:00$')

    def test_recent_cases_page_size_is_15(self):
        """Detail table paginates the FULL active queryset at 15 rows/page."""
        for _ in range(20):
            _make_ticket(status=Ticket.STATUS_NEW)
        page = self._get().context['recent_page']
        self.assertEqual(len(page), 15)             # page 1 shows 15
        self.assertEqual(page.paginator.count, 20)  # but all 20 are reachable
        self.assertEqual(page.paginator.num_pages, 2)

    def test_recent_cases_second_page(self):
        """Page 2 is reachable and holds the remainder."""
        for _ in range(20):
            _make_ticket(status=Ticket.STATUS_NEW)
        page = self._get(page=2).context['recent_page']
        self.assertEqual(page.number, 2)
        self.assertEqual(len(page), 5)

    def test_recent_cases_default_sort_severity_then_created(self):
        """Default order: severity DESC (Critical first), then created_at DESC."""
        low = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=low.pk).update(severity='Low')
        crit = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=crit.pk).update(severity='Critical')
        crit_newer = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=crit_newer.pk).update(severity='Critical')
        rows = list(self._get().context['recent_page'])
        # Critical before Low; among Criticals, newest before older.
        self.assertEqual([r.pk for r in rows], [crit_newer.pk, crit.pk, low.pk])

    def test_recent_cases_header_sort_applies_to_full_queryset(self):
        """?sort=created&dir=asc orders oldest-first across the whole queryset."""
        first = _make_ticket(status=Ticket.STATUS_NEW)
        second = _make_ticket(status=Ticket.STATUS_NEW)
        rows = list(self._get(sort='created', dir='asc').context['recent_page'])
        self.assertEqual([r.pk for r in rows], [first.pk, second.pk])

    def test_recent_cases_status_updated_column(self):
        """Status Updated column renders and status_changed_at is populated."""
        _make_ticket(status=Ticket.STATUS_NEW)
        resp = self._get()
        self.assertIn('Status Updated', resp.content.decode())
        self.assertIsNotNone(resp.context['recent_page'][0].status_changed_at)

    def test_active_critical_counts_critical_only(self):
        a = _make_ticket(status=Ticket.STATUS_NEW)
        b = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=a.pk).update(severity='Critical')
        Ticket.objects.filter(pk=b.pk).update(severity='Low')
        ctx = self._get().context
        self.assertEqual(ctx['active_critical'], 1)
        self.assertEqual(ctx['active_total'], 2)

    def test_critical_soonest_deadline_structure(self):
        t = _make_ticket(status=Ticket.STATUS_NEW, sla_offset_hours=2)
        Ticket.objects.filter(pk=t.pk).update(severity='Critical')
        d = self._get().context['critical_soonest_deadline']
        self.assertIsNotNone(d)
        self.assertEqual(set(d), {'ticket_id', 'minutes_remaining'})
        self.assertGreater(d['minutes_remaining'], 0)

    def test_critical_soonest_deadline_none_without_critical(self):
        _make_ticket(status=Ticket.STATUS_NEW)  # default High, not Critical
        self.assertIsNone(self._get().context['critical_soonest_deadline'])

    def test_resolved_by_category_ignores_status_filter(self):
        """Closed tickets survive a non-terminal status filter (date+severity only)."""
        _make_ticket(status=Ticket.STATUS_APPROVED)
        rbc = self._get(status=Ticket.STATUS_NEW).context['resolved_by_category']
        self.assertTrue(rbc)

    def test_resolved_by_category_groups_by_incident_category(self):
        """resolved_by_category groups by detailed_issue with display labels."""
        # Two closed Malicious Logic + one closed DoS.
        for di in ('Malicious Logic', 'Malicious Logic', 'DoS'):
            t = _make_ticket(status=Ticket.STATUS_APPROVED)
            Ticket.objects.filter(pk=t.pk).update(detailed_issue=di)

        rbc = self._get().context['resolved_by_category']
        self.assertIsInstance(rbc, list)
        # No noisy null/blank labels.
        for row in rbc:
            self.assertNotIn(row['label'], (None, ''))
        labels = {row['label']: row['count'] for row in rbc}
        detail_display = dict(Ticket.DETAILED_ISSUE_CHOICES)
        # Display name (not the raw slug) is used, with correct counts.
        self.assertEqual(labels[detail_display['Malicious Logic']], 2)
        self.assertEqual(labels[detail_display['DoS']], 1)
        # The old Event/Incident classification value must NOT be a label.
        self.assertNotIn('Cyber Event', labels)

    def test_resolved_by_category_excludes_blank_detailed_issue(self):
        """Tickets with blank detailed_issue are dropped (no 'Unknown' bar)."""
        t = _make_ticket(status=Ticket.STATUS_APPROVED)
        Ticket.objects.filter(pk=t.pk).update(detailed_issue='')
        rbc = self._get().context['resolved_by_category']
        self.assertEqual(rbc, [])

    # ── Filters still scope the active counts ──────────────────────────── #

    def test_status_filter_scopes_active_total(self):
        _make_ticket(status=Ticket.STATUS_NEW)
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT)
        self.assertEqual(
            self._get(status=Ticket.STATUS_NEW).context['active_total'], 1)

    def test_intcomma_applied(self):
        """Large counts render with a thousands separator (STEP 5)."""
        Ticket.objects.bulk_create([
            Ticket(ticket_id=f'BULK{i:05d}', device_name='d', ip_address='10.0.0.1',
                   issue_description='x', status=Ticket.STATUS_NEW,
                   sla_deadline=timezone.now() + timedelta(hours=5))
            for i in range(1000)
        ])
        self.assertIn('1,000', self._get().content.decode())
