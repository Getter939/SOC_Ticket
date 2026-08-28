from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from apps.accounts.models import UserProfile

from .models import Ticket, TicketSubtask
from .subtask_creation import (
    create_legacy_subtask,
    create_response_request,
    resolve_response_assignee,
)


def _user(username, role, *, tier='', email=''):
    user = User.objects.create_user(username=username, password='testpass123', email=email)
    UserProfile.objects.create(
        user=user,
        role=role,
        tier=tier,
        department='Test',
        phone='000',
    )
    return user


def _ticket(**overrides):
    values = {
        'device_name': 'subtask-creation-host',
        'ip_address': '192.0.2.185',
        'issue_description': 'Subtask creation service contract',
        'classification': Ticket.CLASSIFICATION_INCIDENT,
    }
    values.update(overrides)
    return Ticket.objects.create(**values)


class _SubtaskForm:
    def __init__(self, subtask_type, title, description='', assigned_to=None):
        self.cleaned_data = {
            'subtask_type': subtask_type,
            'assigned_to': assigned_to,
        }
        self.subtask_type = subtask_type
        self.title = title
        self.description = description

    def save(self, commit=True):
        subtask = TicketSubtask(
            subtask_type=self.subtask_type,
            title=self.title,
            description=self.description,
        )
        if commit:
            subtask.save()
        return subtask


class SubtaskCreationServiceTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.t1 = _user(
            'subtask-creation-t1',
            UserProfile.ROLE_SOC_STAFF,
            tier=UserProfile.TIER_T1,
        )
        cls.manager = _user('subtask-creation-manager', UserProfile.ROLE_SOC_MANAGER)
        cls.forensic = _user(
            'subtask-creation-forensic',
            UserProfile.ROLE_FORENSIC,
            email='forensic@example.com',
        )

    def test_legacy_subtask_is_unassigned_and_has_its_creator(self):
        ticket = _ticket(created_by=self.t1)

        result = create_legacy_subtask(
            ticket=ticket,
            actor=self.t1,
            subtask_form=_SubtaskForm(
                TicketSubtask.TYPE_INVESTIGATION,
                'Collect authentication logs',
                'Preserve logs for correlation.',
            ),
        )

        self.assertEqual(result.subtask.ticket, ticket)
        self.assertEqual(result.subtask.created_by, self.t1)
        self.assertIsNone(result.subtask.assigned_to)
        self.assertFalse(result.subtask.is_response_request)

    @patch('apps.incidents.subtask_creation.notify_response_request_created', return_value=True)
    def test_response_request_auto_assigns_the_only_eligible_responder(self, notify_created):
        ticket = _ticket(created_by=self.t1)

        result = create_response_request(
            ticket=ticket,
            actor=self.manager,
            response_form=_SubtaskForm(
                TicketSubtask.TYPE_FORENSIC_RCA,
                'Preserve forensic disk image',
            ),
        )

        self.assertEqual(result.subtask.assigned_to, self.forensic)
        self.assertEqual(result.subtask.created_by, self.manager)
        self.assertTrue(result.notification_sent)
        notify_created.assert_called_once_with(result.subtask)

    def test_response_assignee_resolution_preserves_each_failure_contract(self):
        with self.assertRaisesMessage(ValidationError, 'ยังไม่มีบัญชีผู้ใช้ในบทบาท'):
            resolve_response_assignee(subtask_type=TicketSubtask.TYPE_VA_PT)

        redteam_a = _user('subtask-creation-redteam-a', UserProfile.ROLE_REDTEAM_MANAGER)
        _user('subtask-creation-redteam-b', UserProfile.ROLE_REDTEAM_MANAGER)
        with self.assertRaisesMessage(ValidationError, 'มากกว่าหนึ่งคน'):
            resolve_response_assignee(subtask_type=TicketSubtask.TYPE_VA_PT)
        with self.assertRaisesMessage(ValidationError, 'ไม่ได้อยู่ในบทบาท'):
            resolve_response_assignee(
                subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                chosen=redteam_a,
            )
        self.assertEqual(
            resolve_response_assignee(
                subtask_type=TicketSubtask.TYPE_FORENSIC_RCA,
                chosen=self.forensic,
            ),
            self.forensic,
        )

    def test_legacy_subtask_endpoint_uses_the_creation_service(self):
        ticket = _ticket(created_by=self.t1)
        self.client.force_login(self.t1)

        response = self.client.post(
            reverse('create_subtask', args=[ticket.pk]),
            {
                'subtask_type': TicketSubtask.TYPE_COUNTERMEASURE,
                'title': 'Block the command-and-control address',
                'description': 'Add the address to the firewall deny list.',
            },
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        subtask = TicketSubtask.objects.get(ticket=ticket)
        self.assertEqual(subtask.created_by, self.t1)
        self.assertIsNone(subtask.assigned_to)

    @patch('apps.incidents.subtask_creation.notify_response_request_created', return_value=True)
    def test_response_request_endpoint_auto_assigns_the_eligible_responder(self, notify_created):
        ticket = _ticket(created_by=self.t1)
        self.client.force_login(self.manager)

        response = self.client.post(
            reverse('create_response_request', args=[ticket.pk]),
            {
                'subtask_type': TicketSubtask.TYPE_FORENSIC_RCA,
                'title': 'Collect the forensic image',
                'description': 'Preserve the disk before remediation.',
                'assigned_to': '',
            },
        )

        self.assertRedirects(response, reverse('ticket_detail', args=[ticket.pk]))
        subtask = TicketSubtask.objects.get(ticket=ticket)
        self.assertEqual(subtask.assigned_to, self.forensic)
        notify_created.assert_called_once_with(subtask)
