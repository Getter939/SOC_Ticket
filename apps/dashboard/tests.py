"""
Dashboard tests — Change 5.

Coverage:
  - Access control: SOC (staff + manager) sees dashboard; system admin is
    redirected; unauthenticated user hits the login redirect.
  - Metrics: active count and retained MTTR stats are correct given known
    fixture data.

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
    ola_offset_hours=None,
    classification='',
):
    """
    Create a Ticket directly (bypassing the state machine).

    ola_offset_hours — if given, overrides the auto-set ola_contain_deadline.
      Positive = future (not breached); negative = past (breached).
      If not given, Ticket.save() auto-sets ola_contain_deadline = now + 48 h.
    """
    kwargs = {
        'device_name':      '192.168.1.1',
        'ip_address':       '10.0.0.1',
        'issue_description': 'Test incident',
        'status':           status,
        'classification':   classification,
    }
    if ola_offset_hours is not None:
        kwargs['ola_contain_deadline'] = timezone.now() + timedelta(hours=ola_offset_hours)
    return Ticket.objects.create(**kwargs)


DASHBOARD_URL = reverse('home')
EXECUTIVE_URL = reverse('executive_dashboard')


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

    def test_system_admin_sidebar_hides_dashboard_link(self):
        """System admins work tickets, but must not see the SOC dashboard entry point."""
        self.client.force_login(self.sys_admin)
        response = self.client.get(reverse('ticket_list'))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'data-label="SOC Dashboard"')

    def test_response_team_is_redirected_to_their_queue(self):
        """Response-only access: Forensic / Red Team must not see org-wide
        aggregates (active counts, per-analyst workload, MTTR). Landing on '/'
        after login must bounce them to their own request queue."""
        for username, role in (
            ('forensic_ac', UserProfile.ROLE_FORENSIC),
            ('redteam_ac', UserProfile.ROLE_REDTEAM_MANAGER),
        ):
            with self.subTest(role=role):
                user = _make_user(username, role)
                self.client.force_login(user)
                response = self.client.get(DASHBOARD_URL)
                self.assertEqual(response.status_code, 302)
                self.assertRedirects(
                    response, reverse('response_request_queue'),
                    fetch_redirect_response=False,
                )

    def test_response_team_sidebar_hides_dashboard_link(self):
        forensic = _make_user('forensic_nav', UserProfile.ROLE_FORENSIC)
        self.client.force_login(forensic)
        response = self.client.get(reverse('response_request_queue'))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'data-label="SOC Dashboard"')

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


# ── OLA-breach counting tests ────────────────────────────────────────────── #

# ── Metrics accuracy tests ───────────────────────────────────────────────── #

class DashboardMetricsTest(TestCase):
    """
    The slim dashboard stats block keeps only the active count plus MTTR.
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_metrics', UserProfile.ROLE_SOC_STAFF)

    def _stats(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']

    # ── active / closed split ──────────────────────────────────────────── #

    def test_active_vs_closed_split(self):
        """active = non-terminal; terminal tickets are excluded."""
        _make_ticket(status=Ticket.STATUS_NEW)                  # active
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT) # active
        _make_ticket(status=Ticket.STATUS_CONTAINMENT_REPORTED) # active
        _make_ticket(status=Ticket.STATUS_APPROVED)             # closed (terminal)
        _make_ticket(status=Ticket.STATUS_CLOSED_EVENT)         # closed (terminal)

        s = self._stats()
        self.assertEqual(s['active'], 3)

    def test_all_active_no_closed(self):
        _make_ticket(status=Ticket.STATUS_NEW)
        _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        s = self._stats()
        self.assertEqual(s['active'], 2)

# ── Enterprise KPI tests (corrected logic) ───────────────────────────────── #

class DashboardEnterpriseKPITest(TestCase):
    """
    MTTR values retained in the slim dashboard stats block:
      - mttr_median / mttr_mean / mttr_n
    """

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('soc_kpi', UserProfile.ROLE_SOC_STAFF)

    def _stats(self):
        self.client.force_login(self.soc)
        return self.client.get(DASHBOARD_URL).context['stats']

    def _resolve(self, ticket, resolved_at, ola_contain_deadline):
        """
        Drive a ticket into a terminal state with a known resolution time.

        Writes a TicketLog row (the dashboard derives resolution time from the
        first terminal-status log entry) and pins created_at / ola_contain_deadline.
        created_at is forced via queryset .update() to bypass auto_now_add.
        """
        from apps.incidents.models import TicketLog
        ticket.status = Ticket.STATUS_APPROVED
        ticket.ola_contain_deadline = ola_contain_deadline
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

    # ── MTTR ───────────────────────────────────────────────────────────── #

    def test_mttr_median_known_timestamps(self):
        """Two resolved tickets (2h and 4h) → median 3.0h, mean 3.0h, n=2."""
        now = timezone.now()
        t1 = _make_ticket(status=Ticket.STATUS_NEW)
        t2 = _make_ticket(status=Ticket.STATUS_NEW)
        # _resolve sets created_at = resolved_at - 2h, giving a 2.0h MTTR.
        self._resolve(t1, resolved_at=now - timedelta(days=1),
                      ola_contain_deadline=now)
        # For t2 craft a 4h gap explicitly.
        from apps.incidents.models import TicketLog
        t2.status = Ticket.STATUS_APPROVED
        t2.ola_contain_deadline = now
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
        # The headline figure on this card is stats.mttr_median, so the label
        # says Median; the mean is carried in the sub-line below it.
        self.assertIn('Median Time to Resolve (MTTR)', html)
        self.assertIn('Avg', html)
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
        """Pipeline, OLA pressure, and the trend/table sections all render."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertNotIn('Avg MTTR by Category', html)   # removed in Session 3C
        # The redundant resolved-by-category chart was replaced by OLA pressure.
        self.assertNotIn('Resolved Tickets by Incident Category', html)
        self.assertIn('OLA Pressure', html)
        self.assertIn('Threat Types', html)              # the kept category chart
        self.assertIn('Daily Case Volume', html)
        self.assertIn('Recent Active Cases', html)

    def test_dashboard_auto_refresh_script_renders_with_visibility_guard(self):
        """The dashboard refreshes periodically without interrupting hidden tabs."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn('const AUTO_REFRESH_MS = 300000', html)
        self.assertIn("document.visibilityState !== 'visible'", html)
        self.assertIn('window.location.reload()', html)

    def test_recent_cases_table_persists_state_across_reload(self):
        """The detail table saves its sort/page so the auto-refresh reload
        doesn't reset the manager's view back to defaults."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn("recentCasesTableState", html)
        self.assertIn("sessionStorage.setItem(STORE_KEY", html)
        self.assertIn("sessionStorage.getItem(STORE_KEY", html)

    def test_ola_scope_note_shown_only_to_managers(self):
        """The 'team-wide count, queue-scoped list' OLA note appears for SOC
        managers (whose deep-linked list is restricted) but not other roles."""
        note = 'นับจากทั้งทีม'
        _make_ticket(status=Ticket.STATUS_NEW)
        # SOC staff (self.soc) — list isn't restricted, so no note.
        self.assertNotIn(note, self._get().content.decode())
        # SOC manager — list is scoped to their queue, so the note shows.
        mgr = _make_user('soc_mgr_note', UserProfile.ROLE_SOC_MANAGER)
        self.client.force_login(mgr)
        self.assertIn(note, self.client.get(DASHBOARD_URL).content.decode())

    def test_pipeline_chart_renders(self):
        """Pipeline stacked-bar replaces the MTTR chart in Row 3L."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn('chartPipeline', html)
        self.assertIn('Pipeline', html)

    def test_charts_render_interactive_controls(self):
        """Charts support filtering, toggling, and retaining a selected trend point."""
        _make_ticket(status=Ticket.STATUS_NEW)
        html = self._get().content.decode()
        self.assertIn('applyDashboardFilters', html)
        self.assertIn('chart.toggleDataVisibility', html)
        self.assertIn('dailyChartSelection', html)

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

    def test_pipeline_excludes_terminal_statuses(self):
        """The pipeline is the ACTIVE funnel — terminal statuses are omitted so
        accumulating closed cases don't dwarf the live columns. Closed counts
        live on the 'Closed This Month' KPI tile instead. (2026-07-23)"""
        _make_ticket(status=Ticket.STATUS_APPROVED)
        _make_ticket(status=Ticket.STATUS_CLOSED_EVENT)
        _make_ticket(status=Ticket.STATUS_NEW)
        pbs = self._get().context['pipeline_by_severity']
        status_slugs = [slug for slug, _ in pbs['statuses']]
        self.assertNotIn(Ticket.STATUS_APPROVED, status_slugs)
        self.assertNotIn(Ticket.STATUS_CLOSED_EVENT, status_slugs)
        # …and no terminal column leaks into the matrix.
        for sev_slug, _ in pbs['severities']:
            self.assertNotIn(Ticket.STATUS_APPROVED, pbs['matrix'][sev_slug])
        # Active statuses are still present.
        self.assertIn(Ticket.STATUS_NEW, status_slugs)

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

    def test_recent_cases_sends_full_active_queue(self):
        """Every active case is sent to the template (sort/paginate is client-side),
        and each gets a data-row so the JS can sort + page the whole dataset."""
        for _ in range(20):
            _make_ticket(status=Ticket.STATUS_NEW)
        resp = self._get()
        self.assertEqual(len(resp.context['recent_tickets']), 20)
        self.assertEqual(resp.content.decode().count('<tr data-row'), 20)

    def test_recent_cases_default_sort_severity_then_created(self):
        """Initial order: severity DESC (Critical first), then created_at DESC."""
        low = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=low.pk).update(severity='Low')
        crit = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=crit.pk).update(severity='Critical')
        crit_newer = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=crit_newer.pk).update(severity='Critical')
        rows = list(self._get().context['recent_tickets'])
        # Critical before Low; among Criticals, newest before older.
        self.assertEqual([r.pk for r in rows], [crit_newer.pk, crit.pk, low.pk])

    def test_recent_cases_status_updated_column(self):
        """Status Updated column renders and status_changed_at is populated."""
        _make_ticket(status=Ticket.STATUS_NEW)
        resp = self._get()
        self.assertIn('Status Updated', resp.content.decode())
        self.assertIsNotNone(resp.context['recent_tickets'][0].status_changed_at)

    def test_recent_cases_status_color_pill(self):
        """Each row carries a status-pill (color-coded status badge)."""
        _make_ticket(status=Ticket.STATUS_NEW)
        self.assertIn('status-pill', self._get().content.decode())

    def test_active_critical_counts_critical_only(self):
        a = _make_ticket(status=Ticket.STATUS_NEW)
        b = _make_ticket(status=Ticket.STATUS_NEW)
        Ticket.objects.filter(pk=a.pk).update(severity='Critical')
        Ticket.objects.filter(pk=b.pk).update(severity='Low')
        ctx = self._get().context
        self.assertEqual(ctx['active_critical'], 1)
        self.assertEqual(ctx['active_total'], 2)

    def test_critical_soonest_deadline_structure(self):
        t = _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=2)
        Ticket.objects.filter(pk=t.pk).update(severity='Critical')
        d = self._get().context['critical_soonest_deadline']
        self.assertIsNotNone(d)
        self.assertEqual(
            set(d), {'ticket_id', 'minutes_remaining', 'overdue', 'label'})
        self.assertGreater(d['minutes_remaining'], 0)
        self.assertFalse(d['overdue'])

    def test_critical_soonest_deadline_overdue_reads_as_elapsed(self):
        """
        An overdue deadline must not render as a negative countdown
        ("Soonest: -136,223m left"): the card flags it as overdue and the
        label carries the magnitude only.
        """
        t = _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=-25)
        Ticket.objects.filter(pk=t.pk).update(severity='Critical')
        resp = self._get()
        d = resp.context['critical_soonest_deadline']
        self.assertLess(d['minutes_remaining'], 0)
        self.assertTrue(d['overdue'])
        self.assertNotIn('-', d['label'])
        body = resp.content.decode()
        self.assertIn('overdue by', body)
        self.assertNotIn('m left', body)

    def test_critical_soonest_deadline_none_without_critical(self):
        _make_ticket(status=Ticket.STATUS_NEW)  # default High, not Critical
        self.assertIsNone(self._get().context['critical_soonest_deadline'])

    def test_ola_pressure_buckets_active_by_deadline(self):
        """Active tickets land in the correct time-to-deadline bucket."""
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=-1)   # overdue
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=0.5)  # due ≤1h
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=2)    # due 1–4h
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=10)   # on-track
        buckets = {b['key']: b['count'] for b in self._get().context['ola_pressure']}
        self.assertEqual(buckets['overdue'], 1)
        self.assertEqual(buckets['due_1h'], 1)
        self.assertEqual(buckets['due_4h'], 1)
        self.assertEqual(buckets['on_track'], 1)

    def test_ola_pressure_counts_active_only(self):
        """Terminal tickets are excluded, even if their deadline is in the past."""
        _make_ticket(status=Ticket.STATUS_APPROVED, ola_offset_hours=-1)
        buckets = {b['key']: b['count'] for b in self._get().context['ola_pressure']}
        self.assertEqual(sum(buckets.values()), 0)

    def test_ola_pressure_severity_breakdown(self):
        """Each bucket carries its per-severity mix (for the tooltip / sub-label)."""
        t = _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=-1)
        Ticket.objects.filter(pk=t.pk).update(severity='Critical')
        overdue = next(b for b in self._get().context['ola_pressure']
                       if b['key'] == 'overdue')
        self.assertEqual(overdue['count'], 1)
        sevs = {s['label']: s['count'] for s in overdue['severities']}
        self.assertEqual(sevs.get('Critical'), 1)

    def test_ola_attention_is_overdue_plus_due_1h(self):
        """Headline 'need attention' count = overdue + due-within-1h (not on-track)."""
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=-1)   # overdue
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=0.5)  # due ≤1h
        _make_ticket(status=Ticket.STATUS_NEW, ola_offset_hours=10)   # on-track
        self.assertEqual(self._get().context['ola_attention'], 2)

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
                   ola_contain_deadline=timezone.now() + timedelta(hours=5))
            for i in range(1000)
        ])
        self.assertIn('1,000', self._get().content.decode())


# ── Executive dashboard ─────────────────────────────────────────────────── #

class ExecutiveDashboardViewTest(TestCase):
    """Executive dashboard pipeline and detail-table behavior."""

    @classmethod
    def setUpTestData(cls):
        cls.executive = _make_user('exec_user', UserProfile.ROLE_EXECUTIVE)
        cls.soc = _make_user('soc_exec', UserProfile.ROLE_SOC_STAFF)
        cls.soc_manager = _make_user('soc_mgr_exec', UserProfile.ROLE_SOC_MANAGER)

    def setUp(self):
        self.client.force_login(self.executive)

    def _get(self, **params):
        return self.client.get(EXECUTIVE_URL, params)

    def test_executive_role_can_view_dashboard(self):
        response = self._get()

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/executive.html')

    def test_superuser_can_view_dashboard(self):
        from django.contrib.auth.models import User
        superuser = User.objects.create_superuser(
            username='exec_superuser',
            email='exec-super@example.com',
            password='pw',
        )
        self.client.force_login(superuser)

        response = self._get()

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/executive.html')

    def test_soc_roles_cannot_view_dashboard(self):
        self.client.force_login(self.soc)
        self.assertEqual(self._get().status_code, 403)

        self.client.force_login(self.soc_manager)
        self.assertEqual(self._get().status_code, 403)

    def test_sidebar_link_visible_only_to_executive_or_superuser(self):
        html = self.client.get(DASHBOARD_URL).content.decode()
        self.assertIn('Executive Dashboard', html)

        self.client.force_login(self.soc)
        html = self.client.get(DASHBOARD_URL).content.decode()
        self.assertNotIn('Executive Dashboard', html)

    def _ticket(
        self,
        status=Ticket.STATUS_NEW,
        severity='High',
        emergency=False,
        created_at=None,
    ):
        ticket = _make_ticket(status=status)
        updates = {
            'severity': severity,
            'is_emergency': emergency,
        }
        if created_at is not None:
            updates['created_at'] = created_at
        Ticket.objects.filter(pk=ticket.pk).update(**updates)
        ticket.refresh_from_db()
        return ticket

    def test_pipeline_is_high_critical_only_with_emergency_counts(self):
        self._ticket(
            status=Ticket.STATUS_NEW,
            severity='Critical',
            emergency=True,
        )
        self._ticket(
            status=Ticket.STATUS_AWAITING_CONTAINMENT,
            severity='High',
        )
        self._ticket(
            status=Ticket.STATUS_NEW,
            severity='Medium',
            emergency=True,
        )
        self._ticket(
            status=Ticket.STATUS_CLOSED_EVENT,
            severity='Unknown',
            emergency=True,
        )

        ctx = self._get().context
        pbs = ctx['pipeline_by_severity']
        status_slugs = [slug for slug, _ in pbs['statuses']]

        self.assertEqual(
            [slug for slug, _ in pbs['severities']],
            ['Critical', 'High'],
        )
        self.assertEqual(set(pbs['matrix']), {'Critical', 'High'})
        # Pipeline bars are SANS-IR phases: NEW→Preparation, AWAITING→Containment.
        self.assertEqual(pbs['matrix']['Critical']['PREPARATION'], 1)
        self.assertEqual(
            pbs['matrix']['High']['CONTAINMENT'],
            1,
        )
        self.assertEqual(pbs['emergency_by_status']['PREPARATION'], 1)
        self.assertEqual(sum(pbs['emergency_by_status'].values()), 1)
        self.assertEqual(
            ctx['pipeline_emergency_row'][status_slugs.index('PREPARATION')],
            1,
        )

    def test_top_kpi_counts_all_high_critical_and_omits_emergency_card(self):
        self._ticket(status=Ticket.STATUS_NEW, severity='High')
        self._ticket(status=Ticket.STATUS_APPROVED, severity='Critical')
        self._ticket(status=Ticket.STATUS_NEW, severity='Low', emergency=True)

        resp = self._get()
        html = resp.content.decode()

        self.assertEqual(resp.context['total_hc'], 2)
        self.assertIn('เคสทั้งหมด (High/Critical)', html)
        self.assertNotIn('เคสที่กำลังดำเนินการ (High/Critical)', html)
        self.assertNotIn('<div class="stat-label">เคสฉุกเฉิน (Emergency)</div>', html)

    def test_detail_table_paginates_ten_rows(self):
        for _ in range(12):
            self._ticket()

        first_page = self._get()
        second_page = self._get(page=2)

        self.assertEqual(first_page.context['page_obj'].paginator.per_page, 10)
        self.assertEqual(len(first_page.context['table_tickets']), 10)
        self.assertEqual(len(second_page.context['table_tickets']), 2)

    def test_detail_table_renders_priority_column(self):
        self._ticket(emergency=True)
        self._ticket(emergency=False)

        html = self._get().content.decode()

        self.assertIn('สถานะ Emergency', html)
        self.assertIn('priority-emergency', html)
        self.assertIn('priority-normal', html)

    def test_time_range_filters_chart_progress_and_detail_data(self):
        old_created_at = timezone.now() - timedelta(days=2)
        self._ticket(
            status=Ticket.STATUS_NEW,
            severity='Critical',
            emergency=True,
        )
        self._ticket(
            status=Ticket.STATUS_APPROVED,
            severity='High',
            emergency=True,
            created_at=old_created_at,
        )

        today = self._get(date_range='today')
        today_pbs = today.context['pipeline_by_severity']

        self.assertEqual(today.context['filters']['date_range'], 'today')
        self.assertEqual(today.context['hc_total'], 1)
        self.assertEqual(today.context['hc_open'], 1)
        self.assertEqual(today_pbs['matrix']['Critical']['PREPARATION'], 1)
        # APPROVED is a terminal → Lessons Learned (not Recovery).
        self.assertEqual(today_pbs['matrix']['High']['LESSONS'], 0)
        self.assertEqual(today_pbs['emergency_by_status']['PREPARATION'], 1)
        self.assertEqual(len(today.context['table_tickets']), 1)

        all_time = self._get(date_range='all')
        all_pbs = all_time.context['pipeline_by_severity']

        self.assertEqual(all_time.context['hc_total'], 2)
        self.assertEqual(all_pbs['matrix']['High']['LESSONS'], 1)

    def test_time_range_control_and_chart_links_render(self):
        self._ticket()

        html = self._get(date_range='week').content.decode()

        self.assertIn('date_range=today', html)
        self.assertIn('date_range=month', html)
        self.assertIn("const dateRange = 'week';", html)
        self.assertIn("'?date_range=' + encodeURIComponent(dateRange)", html)
        self.assertIn('pipelineTotalsExec', html)
        self.assertIn('color: tick => emergencyCounts', html)
        self.assertNotIn('roundedRect(ctx', html)
        self.assertNotIn('pipelineLabelsExec', html)
        self.assertNotIn('pipelineAnnotationsExec', html)

    def test_detail_pagination_preserves_filter(self):
        for _ in range(11):
            self._ticket(emergency=True)
        self._ticket(emergency=False)

        html = self._get(date_range='week', f='EMERGENCY').content.decode()

        self.assertIn(
            '?date_range=week&date_from=&date_to=&f=EMERGENCY&page=2#detail-table',
            html,
        )

    # ── Pipeline phase coverage (guards silent-drop bugs) ───────────────── #

    def test_ir_phases_cover_every_status_exactly_once(self):
        """A status missing from _IR_PHASES is silently dropped from the exec
        pipeline chart AND its drill-down filter — the bug that hid
        PENDING_MGR_EVENT_REVIEW until 2026-07-23."""
        from apps.dashboard.views import _IR_PHASES

        covered = [s for _, _, sts in _IR_PHASES for s in sts]
        all_statuses = [s for s, _ in Ticket.STATUS_CHOICES]
        self.assertEqual(sorted(covered), sorted(set(covered)),
                         'a status is in two IR phases')
        self.assertEqual(sorted(covered), sorted(all_statuses),
                         'IR phase coverage != all statuses')

    def test_event_downgrade_review_lands_in_identification(self):
        self._ticket(
            status=Ticket.STATUS_PENDING_MGR_EVENT_REVIEW, severity='Critical',
        )
        pbs = self._get().context['pipeline_by_severity']
        self.assertEqual(pbs['matrix']['Critical']['IDENTIFICATION'], 1)


# ── Monitoring dashboard: analyst workload heatmap ───────────────────────── #

class AnalystHeatmapTest(TestCase):
    """The heatmap answers 'what must this analyst chase?' — so tickets parked
    with the manager / system admin / Tier 2 must not count as their load."""

    @classmethod
    def setUpTestData(cls):
        cls.soc = _make_user('heat_soc', UserProfile.ROLE_SOC_STAFF)

    def setUp(self):
        self.client.force_login(self.soc)

    def _analyst(self, username='heat_an'):
        from django.contrib.auth.models import User
        return User.objects.create_user(
            username=username, password='pw', first_name='Ada', last_name='Lovelace')

    def _assign(self, analyst, status):
        t = _make_ticket(status=status)
        Ticket.objects.filter(pk=t.pk).update(assigned_to=analyst)
        return t

    def _row(self):
        return self.client.get(DASHBOARD_URL).context['assignee_heatmap'][0]

    def test_own_and_blocked_cover_every_active_status_exactly_once(self):
        from apps.dashboard.views import (
            _ANALYST_OWN_STATUSES, _ANALYST_BLOCKED_STATUSES,
        )
        covered = _ANALYST_OWN_STATUSES + _ANALYST_BLOCKED_STATUSES
        active = [
            s for s, _ in Ticket.STATUS_CHOICES
            if s not in Ticket.TERMINAL_STATUSES
        ]
        self.assertEqual(sorted(covered), sorted(set(covered)), 'status in both groups')
        self.assertEqual(sorted(covered), sorted(active), 'coverage != active states')

    def test_columns_are_own_court_only(self):
        from apps.dashboard.views import _ANALYST_OWN_STATUSES
        self._assign(self._analyst(), Ticket.STATUS_NEW)
        ctx = self.client.get(DASHBOARD_URL).context
        self.assertEqual(
            [s for s, _ in ctx['assignee_heatmap_statuses']], _ANALYST_OWN_STATUSES,
        )

    def test_blocked_tickets_do_not_count_as_load(self):
        """Regression: a ticket waiting on the SOC Manager is not analyst load."""
        analyst = self._analyst()
        self._assign(analyst, Ticket.STATUS_PENDING_MGR_TRIAGE)
        self._assign(analyst, Ticket.STATUS_AWAITING_CONTAINMENT)

        row = self._row()
        self.assertEqual(row['load'], 0)
        self.assertEqual(row['blocked'], 2)
        self.assertEqual(row['total'], 2)
        self.assertEqual(row['cells'], [0, 0, 0, 0])  # no own-court work

    def test_own_court_tickets_count_as_load(self):
        analyst = self._analyst()
        self._assign(analyst, Ticket.STATUS_NEW)
        self._assign(analyst, Ticket.STATUS_AWAITING_OWNER)

        row = self._row()
        self.assertEqual(row['load'], 2)
        self.assertEqual(row['blocked'], 0)
        self.assertEqual(row['total'], 2)

    def test_rows_sort_by_actionable_load_not_total(self):
        """An analyst with 5 blocked tickets is less busy than one with 2 real."""
        blocked_heavy = self._analyst('heat_blocked')
        for _ in range(5):
            self._assign(blocked_heavy, Ticket.STATUS_PENDING_MANAGER)
        actually_busy = self._analyst('heat_busy')
        for _ in range(2):
            self._assign(actually_busy, Ticket.STATUS_T1_REVIEW)

        rows = self.client.get(DASHBOARD_URL).context['assignee_heatmap']
        self.assertEqual(rows[0]['name'], 'Ada Lovelace')  # both share a name
        self.assertEqual(rows[0]['load'], 2)     # actionable queue wins
        self.assertEqual(rows[1]['load'], 0)
        self.assertEqual(rows[1]['blocked'], 5)

    def test_terminal_tickets_excluded(self):
        analyst = self._analyst()
        self._assign(analyst, Ticket.STATUS_APPROVED)
        self.assertEqual(self.client.get(DASHBOARD_URL).context['assignee_heatmap'], [])

    def test_blocked_column_renders(self):
        self._assign(self._analyst(), Ticket.STATUS_PENDING_MGR_TRIAGE)
        html = self.client.get(DASHBOARD_URL).content.decode()
        self.assertIn('รอคนอื่น', html)
        self.assertIn('heat-blocked-col', html)


# ── Executive summary: grouped by whose court ────────────────────────────── #

class ExecutiveSummaryCourtTest(TestCase):
    """The summary verdict must see every active state, grouped by who holds
    the ticket — it can never read GOOD while work is queued anywhere."""

    @classmethod
    def setUpTestData(cls):
        cls.executive = _make_user('exec_court', UserProfile.ROLE_EXECUTIVE)

    def setUp(self):
        self.client.force_login(self.executive)

    def _get(self, **params):
        return self.client.get(EXECUTIVE_URL, params)

    def _criteria(self):
        return {c['filter']: c for c in self._get().context['summary_criteria']}

    # Every active status maps to exactly one court group.
    def test_court_groups_cover_every_active_status_exactly_once(self):
        from apps.dashboard.views import _EXEC_COURT_GROUPS

        covered = [s for sts in _EXEC_COURT_GROUPS.values() for s in sts]
        active = [
            s for s, _ in Ticket.STATUS_CHOICES
            if s not in Ticket.TERMINAL_STATUSES
        ]
        self.assertEqual(sorted(covered), sorted(set(covered)), 'a status is in two courts')
        self.assertEqual(sorted(covered), sorted(active), 'court coverage != active states')

    def test_no_active_work_reads_good(self):
        self.assertEqual(self._get().context['overall_status'], 'GOOD')

    def test_owner_lane_is_counted_and_flips_verdict_to_waiting(self):
        """Regression: the owner lane used to be invisible to the verdict."""
        _make_ticket(status=Ticket.STATUS_AWAITING_OWNER)
        ctx = self._get().context
        self.assertEqual(ctx['overall_status'], 'WAITING')
        self.assertEqual(self._criteria()['COURT_EXTERNAL']['count'], 1)

    def test_escalated_and_t1_review_are_counted(self):
        """Regression: ESCALATED_T2 / T1_REVIEW used to be invisible too."""
        _make_ticket(status=Ticket.STATUS_ESCALATED_T2)
        _make_ticket(status=Ticket.STATUS_T1_REVIEW)
        criteria = self._criteria()
        self.assertEqual(criteria['COURT_TIER2']['count'], 1)   # ESCALATED_T2
        self.assertEqual(criteria['COURT_SOC']['count'], 1)     # T1_REVIEW

    def test_manager_court_counts_both_manager_stages(self):
        _make_ticket(status=Ticket.STATUS_PENDING_MGR_TRIAGE)
        _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        self.assertEqual(self._criteria()['COURT_MANAGER']['count'], 2)

    def test_terminal_tickets_are_not_counted_in_any_court(self):
        _make_ticket(status=Ticket.STATUS_APPROVED)
        _make_ticket(status=Ticket.STATUS_CLOSED_EVENT)
        criteria = self._criteria()
        for key in ('COURT_SOC', 'COURT_MANAGER', 'COURT_EXTERNAL', 'COURT_TIER2'):
            self.assertEqual(criteria[key]['count'], 0, key)
        self.assertEqual(self._get().context['overall_status'], 'GOOD')

    def test_ola_overdue_is_a_warning_criterion(self):
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT, ola_offset_hours=-5)
        ctx = self._get().context
        self.assertEqual(self._criteria()['OLA_OVERDUE']['count'], 1)
        self.assertEqual(ctx['overall_status'], 'WARNING')

    def test_ghost_critical_unassigned_criterion_is_gone(self):
        labels = [c['label'] for c in self._get().context['summary_criteria']]
        # 6 court/warning rows + 1 cross-cutting response-team row (see below).
        self.assertEqual(len(labels), 7)
        self.assertNotIn('เคสอันตราย (Critical) ที่ยังไม่มีผู้รับผิดชอบ', labels)

    def test_response_pending_is_a_cross_cutting_criterion(self):
        from apps.incidents.models import TicketSubtask
        # An Incident at PENDING_MANAGER with an open forensic request: counted in
        # the manager court AND the response-team overlay row (intentional).
        t = _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='RCA', status=TicketSubtask.STATUS_IN_PROGRESS,
        )
        criteria = self._criteria()
        self.assertEqual(criteria['RESPONSE_PENDING']['count'], 1)
        self.assertEqual(criteria['COURT_MANAGER']['count'], 1)

    def test_done_response_request_does_not_count(self):
        from apps.incidents.models import TicketSubtask
        t = _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        TicketSubtask.objects.create(
            ticket=t, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='pentest', status=TicketSubtask.STATUS_DONE,
        )
        self.assertEqual(self._criteria()['RESPONSE_PENDING']['count'], 0)

    def test_response_pending_filter_scopes_detail_table(self):
        from apps.incidents.models import TicketSubtask
        blocked = _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)
        TicketSubtask.objects.create(
            ticket=blocked, subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
            title='RCA', status=TicketSubtask.STATUS_OPEN,
        )
        _make_ticket(status=Ticket.STATUS_PENDING_MANAGER)  # no request
        resp = self._get(f='RESPONSE_PENDING')
        self.assertEqual(len(resp.context['table_tickets']), 1)
        self.assertEqual(resp.context['table_tickets'][0].pk, blocked.pk)

    # ── Court deep-link filters ──────────────────────────────────────────── #

    def test_court_filter_scopes_detail_table_to_that_group(self):
        _make_ticket(status=Ticket.STATUS_AWAITING_OWNER)
        _make_ticket(status=Ticket.STATUS_PENDING_MGR_TRIAGE)

        external = self._get(f='COURT_EXTERNAL')
        self.assertEqual(len(external.context['table_tickets']), 1)
        self.assertEqual(
            external.context['table_tickets'][0].status,
            Ticket.STATUS_AWAITING_OWNER,
        )
        self.assertEqual(
            external.context['filter_label'], 'เคสที่รอผู้ดูแลระบบ / เจ้าของระบบ',
        )

        manager = self._get(f='COURT_MANAGER')
        self.assertEqual(len(manager.context['table_tickets']), 1)

    def test_ola_overdue_filter_scopes_detail_table(self):
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT, ola_offset_hours=-5)
        _make_ticket(status=Ticket.STATUS_AWAITING_CONTAINMENT, ola_offset_hours=48)

        resp = self._get(f='OLA_OVERDUE')
        self.assertEqual(len(resp.context['table_tickets']), 1)


# ── Executive detail table: whose court is the ball in ───────────────────── #

class ExecutiveAccountableColumnTest(TestCase):
    """The detail table must name whoever actually holds the ticket now, not
    always the opening Tier 1 analyst."""

    @classmethod
    def setUpTestData(cls):
        cls.executive = _make_user('exec_acct', UserProfile.ROLE_EXECUTIVE)
        cls.analyst = _make_user('acct_t1', UserProfile.ROLE_SOC_STAFF)
        cls.admin = _make_user('acct_admin', UserProfile.ROLE_SYSTEM_ADMIN)

    def setUp(self):
        self.client.force_login(self.executive)

    def _row_html(self, status, **updates):
        t = _make_ticket(status=status)
        updates.setdefault('assigned_to', self.analyst)
        Ticket.objects.filter(pk=t.pk).update(**updates)
        return self.client.get(EXECUTIVE_URL).content.decode()

    def test_manager_stages_show_manager_role_not_analyst(self):
        for status in (Ticket.STATUS_PENDING_MGR_TRIAGE, Ticket.STATUS_PENDING_MANAGER):
            with self.subTest(status=status):
                Ticket.objects.all().delete()
                html = self._row_html(status)
                self.assertIn('ผู้จัดการ SOC', html)
                self.assertNotIn(self.analyst.username, html)

    def test_tier2_verification_stages_show_tier2_role(self):
        for status in (
            Ticket.STATUS_ESCALATED_T2,
            Ticket.STATUS_CONTAINMENT_REPORTED,
            Ticket.STATUS_PENDING_T2_REVIEW,
        ):
            with self.subTest(status=status):
                Ticket.objects.all().delete()
                html = self._row_html(status)
                self.assertIn('Tier 2', html)
                self.assertNotIn(self.analyst.username, html)

    def test_owner_lane_shows_asset_owner(self):
        Ticket.objects.all().delete()
        html = self._row_html(
            Ticket.STATUS_AWAITING_OWNER, asset_owner='ฝ่ายบุคคล',
        )
        self.assertIn('ฝ่ายบุคคล', html)
        self.assertNotIn(self.analyst.username, html)

    def test_owner_lane_without_asset_owner_falls_back_to_role(self):
        Ticket.objects.all().delete()
        html = self._row_html(Ticket.STATUS_OWNER_REMEDIATED, asset_owner='')
        self.assertIn('เจ้าของระบบ', html)

    def test_containment_still_shows_assigned_admin(self):
        Ticket.objects.all().delete()
        html = self._row_html(
            Ticket.STATUS_AWAITING_CONTAINMENT, assigned_admin=self.admin,
        )
        self.assertIn(self.admin.username, html)

    def test_analyst_shown_when_ball_is_in_tier1_court(self):
        Ticket.objects.all().delete()
        html = self._row_html(Ticket.STATUS_NEW)
        self.assertIn(self.analyst.username, html)


# ── UX/visual regression tests (2026-07 audit) ───────────────────────────── #

class HumanizeMinutesTest(TestCase):
    """humanize_minutes renders magnitudes, never signed raw minutes."""

    def test_formats_by_magnitude(self):
        from apps.dashboard.views import humanize_minutes
        cases = [
            (0, '0m'), (45, '45m'), (60, '1h'), (135, '2h 15m'),
            (1440, '1d'), (1560, '1d 2h'),
        ]
        for minutes, expected in cases:
            with self.subTest(minutes=minutes):
                self.assertEqual(humanize_minutes(minutes), expected)

    def test_negative_renders_same_as_positive(self):
        """The sign is the caller's to interpret ('overdue by 2h 15m')."""
        from apps.dashboard.views import humanize_minutes
        self.assertEqual(humanize_minutes(-135), humanize_minutes(135))


class ChartAccessibilityTableMarkupTest(TestCase):
    """
    The chart data-tables must be wrapped in a div.

    .visually-hidden sets width:1px, but on a <table> that is only a *minimum*
    — a bare visually-hidden table still lays out at full content width and
    stretches the document (and the fixed topbar) on mobile.
    """

    def _assert_no_bare_hidden_table(self, template_name):
        from django.template.loader import get_template
        source = get_template(template_name).template.source
        self.assertNotIn('<table class="visually-hidden"', source)
        self.assertIn('<div class="visually-hidden">', source)

    def test_dashboard_hidden_tables_are_wrapped(self):
        self._assert_no_bare_hidden_table('dashboard/dashboard.html')

    def test_executive_hidden_tables_are_wrapped(self):
        self._assert_no_bare_hidden_table('dashboard/executive.html')
