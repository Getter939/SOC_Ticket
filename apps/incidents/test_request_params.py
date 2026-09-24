"""Malformed request parameters get a normal response, not a 500; ticket history
defaults to the local month; the Project Incident page checks visibility before
it acts and shows deletions only to the people who can restore them."""

from datetime import datetime
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase as TestCase
from apps.incidents.models import ProjectIncident, ProjectIncidentAttachment, Ticket
from apps.incidents.tests import _make_t1, _make_t2, _make_ticket, _make_user


class TicketHistoryDateParamsTest(TestCase):
    def setUp(self):
        self.soc = _make_t1('hist_t1')
        self.client.force_login(self.soc)

    def test_malformed_or_impossible_dates_do_not_500(self):
        url = reverse('ticket_history')
        for start, end in (('abc', '2026-01-31'), ('2026-02-31', '2026-03-01'),
                           ('2026-01-01', 'not-a-date')):
            with self.subTest(start=start, end=end):
                response = self.client.get(url, {'start_date': start, 'end_date': end})
                self.assertEqual(response.status_code, 200)

    def test_default_month_is_the_local_month(self):
        """00:30 on 1 Sep in Bangkok is still 31 Aug in UTC. The default range
        must be September, and a ticket opened at 00:10 local on the 1st is in
        it — both used to be computed in UTC."""
        instant = timezone.make_aware(datetime(2026, 9, 1, 0, 30))  # Bangkok
        opened = _make_ticket(status=Ticket.STATUS_CLOSED_EVENT)
        Ticket.objects.filter(pk=opened.pk).update(
            created_at=timezone.make_aware(datetime(2026, 9, 1, 0, 10)),
        )
        with patch('django.utils.timezone.now', return_value=instant):
            response = self.client.get(reverse('ticket_history'))
        self.assertEqual(response.context['start_date'], '2026-09-01')
        self.assertEqual(response.context['end_date'], '2026-09-30')
        self.assertIn(opened.pk, [ticket.pk for ticket in response.context['tickets']])


class NonNumericIdParamsTest(TestCase):
    def setUp(self):
        self.t1 = _make_t1('param_t1')
        self.t2 = _make_t2('param_t2')

    def test_create_ticket_with_non_numeric_triage_id_is_404(self):
        self.client.force_login(self.t1)
        response = self.client.get(reverse('create_ticket'), {'triage_id': 'abc'})
        self.assertEqual(response.status_code, 404)

    def test_create_project_incident_ignores_non_numeric_source_ids(self):
        self.client.force_login(self.t1)
        response = self.client.get(
            reverse('create_project_incident'),
            {'wazuh_alert': 'abc', 'triage_id': '1; drop'},
        )
        self.assertEqual(response.status_code, 200)

    def test_tier2_claim_and_release_with_non_numeric_ticket_id(self):
        self.client.force_login(self.t2)
        for name in ('claim_escalation', 'release_escalation'):
            with self.subTest(view=name):
                response = self.client.post(
                    reverse(name), {'ticket_id': 'abc', 'release_reason': 'x'},
                )
                self.assertRedirects(
                    response, reverse('escalation_queue'), fetch_redirect_response=False,
                )


class ProjectIncidentDetailAccessTest(TestCase):
    def setUp(self):
        self.t1 = _make_t1('proj_t1')
        self.manager = _make_user('proj_mgr', UserProfile.ROLE_SOC_MANAGER)
        self.admin = _make_user('proj_admin', UserProfile.ROLE_SYSTEM_ADMIN)
        self.stranger = _make_user('proj_stranger', UserProfile.ROLE_SYSTEM_ADMIN)
        self.project = ProjectIncident.objects.create(title='Bundle', created_by=self.t1)
        _make_ticket(project_incident=self.project, bundle_suffix='A',
                     assigned_admin=self.admin, created_by=self.t1)
        ProjectIncidentAttachment.all_objects.create(
            project=self.project, file='project_attachments/x/removed.txt',
            original_name='removed.txt', uploaded_by=self.t1,
            deleted_by=self.manager, deleted_at=timezone.now(),
            deleted_reason='wrong host',
        )
        self.url = reverse('project_incident_detail', args=[self.project.pk])

    def test_post_from_a_user_who_sees_no_member_is_404_before_any_action(self):
        self.client.force_login(self.stranger)
        response = self.client.post(self.url, {'action': 'add_project_member'})
        self.assertEqual(response.status_code, 404)

    def test_deleted_evidence_is_listed_only_for_those_who_can_restore(self):
        self.client.force_login(self.admin)
        self.assertEqual(list(self.client.get(self.url).context['deleted_attachments']), [])
        self.client.force_login(self.manager)
        deleted = list(self.client.get(self.url).context['deleted_attachments'])
        self.assertEqual([attachment.original_name for attachment in deleted], ['removed.txt'])
