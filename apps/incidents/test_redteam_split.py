"""The three Red Team functions share a role but have separate owners."""

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib import admin
from django.contrib.auth.models import User
from django.test import RequestFactory
from django.urls import reverse
from types import SimpleNamespace
from unittest.mock import patch

from apps.accounts.admin import UserAdmin
from apps.accounts.models import UserProfile
from apps.accounts.testing import MFATestCase

from .models import TicketSubtask
from .redteam_assignment import assign_open_hardening_requests
from .subtask_creation import resolve_response_assignee
from .test_subtask_creation import _ticket, _user


class RedTeamSplitTest(MFATestCase):
    @classmethod
    def setUpTestData(cls):
        cls.soc_manager = _user('split-soc-manager', UserProfile.ROLE_SOC_MANAGER)
        cls.responders = {}
        for function in (
            UserProfile.REDTEAM_VA,
            UserProfile.REDTEAM_PENTEST,
            UserProfile.REDTEAM_HARDENING,
        ):
            user = _user(f'split-{function.lower()}', UserProfile.ROLE_REDTEAM_MANAGER)
            user.profile.redteam_function = function
            user.profile.save(update_fields=['redteam_function'])
            cls.responders[function] = user

    def test_each_request_is_routed_to_its_designated_manager(self):
        mapping = (
            (TicketSubtask.TYPE_VA, UserProfile.REDTEAM_VA),
            (TicketSubtask.TYPE_PENTEST, UserProfile.REDTEAM_PENTEST),
            (TicketSubtask.TYPE_HARDENING, UserProfile.REDTEAM_HARDENING),
        )
        for subtask_type, function in mapping:
            with self.subTest(subtask_type=subtask_type):
                self.assertEqual(
                    resolve_response_assignee(subtask_type=subtask_type),
                    self.responders[function],
                )
                wrong = next(user for name, user in self.responders.items() if name != function)
                with self.assertRaises(ValidationError):
                    resolve_response_assignee(subtask_type=subtask_type, chosen=wrong)

    def test_new_request_form_excludes_combined_legacy_types(self):
        from .forms import ResponseRequestForm

        choices = dict(ResponseRequestForm.RESPONSE_TYPE_CHOICES)
        for request_type in (
            TicketSubtask.TYPE_VA,
            TicketSubtask.TYPE_PENTEST,
            TicketSubtask.TYPE_HARDENING,
        ):
            self.assertIn(request_type, choices)
        self.assertNotIn(TicketSubtask.TYPE_VA_PT, choices)
        self.assertNotIn(TicketSubtask.TYPE_INFRA_SEC, choices)

    def test_each_function_has_only_one_designated_manager(self):
        another = _user('split-another-va', UserProfile.ROLE_REDTEAM_MANAGER)
        another.profile.redteam_function = UserProfile.REDTEAM_VA
        with self.assertRaises(ValidationError):
            another.profile.full_clean()

        self.soc_manager.profile.redteam_function = UserProfile.REDTEAM_PENTEST
        with self.assertRaises(ValidationError):
            self.soc_manager.profile.full_clean()

    def test_manager_sees_only_their_function_and_enters_report_number_without_file(self):
        ticket = _ticket()
        requests = {}
        for subtask_type, function in (
            (TicketSubtask.TYPE_VA, UserProfile.REDTEAM_VA),
            (TicketSubtask.TYPE_PENTEST, UserProfile.REDTEAM_PENTEST),
            (TicketSubtask.TYPE_HARDENING, UserProfile.REDTEAM_HARDENING),
        ):
            requests[function] = TicketSubtask.objects.create(
                ticket=ticket, subtask_type=subtask_type, title=subtask_type,
                assigned_to=self.responders[function], created_by=self.soc_manager,
            )

        for function, manager in self.responders.items():
            with self.subTest(function=function):
                self.client.force_login(manager)
                queue = self.client.get(reverse('response_request_queue'))
                self.assertEqual([r.pk for r in queue.context['requests']], [requests[function].pk])
                self.client.post(reverse('accept_subtask', args=[requests[function].pk]))
                requests[function].refresh_from_db()
                self.assertEqual(requests[function].status, TicketSubtask.STATUS_IN_PROGRESS)
                detail = self.client.get(reverse('ticket_detail', args=[ticket.pk]))
                self.assertEqual(detail.status_code, 200)
                self.assertContains(detail, f'id="my-report-number-{requests[function].pk}"')
                self.assertNotContains(detail, 'name="result_file"')
                self.assertNotContains(detail, f'value="{requests[function].expected_report_number}"')

                prefix = requests[function].REPORT_PREFIXES[requests[function].subtask_type]
                number = f'{prefix}-2026-0001'
                self.client.post(reverse('update_subtask', args=[requests[function].pk]), {
                    'status': TicketSubtask.STATUS_DONE,
                    'report_number': number,
                    'result_file': SimpleUploadedFile('report.txt', b'outside the app'),
                })
                requests[function].refresh_from_db()
                self.assertEqual(requests[function].status, TicketSubtask.STATUS_DONE)
                self.assertEqual(requests[function].report_number, number)
                self.assertFalse(requests[function].attachments.exists())

    def test_specialty_restricts_ticket_visibility_even_for_misassigned_rows(self):
        ticket = _ticket()
        TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_PENTEST,
            title='misassigned', assigned_to=self.responders[UserProfile.REDTEAM_VA],
        )
        self.client.force_login(self.responders[UserProfile.REDTEAM_VA])
        self.assertEqual(
            self.client.get(reverse('ticket_detail', args=[ticket.pk])).status_code,
            404,
        )

    def test_open_legacy_hardening_moves_when_manager_is_configured(self):
        ticket = _ticket()
        former_manager = self.responders[UserProfile.REDTEAM_PENTEST]
        hardening_manager = self.responders[UserProfile.REDTEAM_HARDENING]
        open_request = TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_INFRA_SEC,
            title='Harden the host', assigned_to=former_manager,
            status=TicketSubtask.STATUS_IN_PROGRESS,
        )
        completed_request = TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_INFRA_SEC,
            title='Past hardening', assigned_to=former_manager,
            status=TicketSubtask.STATUS_DONE, report_number='older-number',
        )
        combined_request = TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_VA_PT,
            title='Existing VA/PT', assigned_to=former_manager,
        )

        changed = assign_open_hardening_requests(
            manager=hardening_manager, actor=self.soc_manager,
        )
        open_request.refresh_from_db()
        completed_request.refresh_from_db()
        combined_request.refresh_from_db()
        self.assertEqual(changed, 1)
        self.assertEqual(open_request.subtask_type, TicketSubtask.TYPE_HARDENING)
        self.assertEqual(open_request.assigned_to, hardening_manager)
        self.assertEqual(completed_request.subtask_type, TicketSubtask.TYPE_INFRA_SEC)
        self.assertEqual(completed_request.assigned_to, former_manager)
        self.assertEqual(combined_request.subtask_type, TicketSubtask.TYPE_VA_PT)
        self.assertEqual(combined_request.assigned_to, former_manager)
        self.assertEqual(
            set(open_request.field_changes.values_list('field_name', flat=True)),
            {'subtask_type', 'assigned_to'},
        )
        self.assertEqual(
            assign_open_hardening_requests(manager=hardening_manager, actor=self.soc_manager),
            0,
        )

    @patch('apps.accounts.admin.messages.info')
    def test_admin_designation_triggers_open_hardening_conversion(self, info):
        ticket = _ticket()
        former_manager = self.responders[UserProfile.REDTEAM_PENTEST]
        hardening_manager = self.responders[UserProfile.REDTEAM_HARDENING]
        request = TicketSubtask.objects.create(
            ticket=ticket, subtask_type=TicketSubtask.TYPE_INFRA_SEC,
            title='Legacy hardening', assigned_to=former_manager,
        )
        admin_request = RequestFactory().post('/admin/auth/user/')
        admin_request.user = self.soc_manager
        form = SimpleNamespace(instance=hardening_manager, save_m2m=lambda: None)
        UserAdmin(User, admin.site).save_related(admin_request, form, [], True)

        request.refresh_from_db()
        self.assertEqual(request.subtask_type, TicketSubtask.TYPE_HARDENING)
        self.assertEqual(request.assigned_to, hardening_manager)
        info.assert_called_once()
