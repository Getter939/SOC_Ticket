"""Ticket forms must provide the client with the server's idle-session window."""

from django.conf import settings
from django.urls import reverse

from apps.accounts.testing import MFATestCase as TestCase

from .models import Ticket
from .tests import _make_t1, _make_ticket


class TicketFormSessionTimeoutTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.analyst = _make_t1('timeout_analyst')
        cls.ticket = _make_ticket(
            created_by=cls.analyst,
            status=Ticket.STATUS_NEW,
        )

    def setUp(self):
        self.client.force_login(self.analyst)

    def test_create_edit_and_project_forms_enable_the_idle_timer(self):
        urls = (
            reverse('create_ticket'),
            reverse('edit_ticket', args=[self.ticket.pk]),
            reverse('create_project_incident'),
        )
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'id="session-keepalive"')
                self.assertContains(
                    response, f'data-idle="{settings.SESSION_COOKIE_AGE}"',
                )
                self.assertContains(response, 'session:before-redirect')
