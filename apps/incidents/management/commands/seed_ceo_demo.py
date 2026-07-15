"""Stage the CEO demo ticket at AWAITING_CONTAINMENT.

Re-runnable: every run deletes and rebuilds the demo ticket, so a botched
run-through can be reset with one command right before the room fills up.

    py manage.py seed_ceo_demo            # create / reset the demo ticket
    py manage.py seed_ceo_demo --remove   # delete it again afterwards

The ticket is left at AWAITING_CONTAINMENT with a realistic prior history
(T1 raised it -> routed to manager -> manager assigned an admin) so the live
demo only has to walk the last three steps:

    admin contains -> T2 verifies -> manager approves
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.incidents.models import Ticket, TicketLog

REFERENCE_ID = 'DEMO-CEO-001'


class Command(BaseCommand):
    help = 'Create/reset the pre-staged ticket used for the CEO demo.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--remove', action='store_true',
            help='Delete the demo ticket and exit.',
        )

    def _pick(self, role_desc, **filters):
        user = User.objects.filter(**filters).order_by('username').first()
        if not user:
            raise CommandError(
                f'No {role_desc} user found ({filters}). '
                f'Create one before seeding the demo.'
            )
        return user

    @transaction.atomic
    def handle(self, *args, **options):
        existing = Ticket.objects.filter(reference_id=REFERENCE_ID)
        if options['remove']:
            n, _ = existing.delete()
            self.stdout.write(self.style.SUCCESS(
                f'Removed demo ticket ({n} rows).'))
            return

        if existing.exists():
            existing.delete()
            self.stdout.write('Existing demo ticket removed; rebuilding.')

        t1 = self._pick('Tier 1 SOC', profile__role='SOC_STAFF', profile__tier='T1')
        t2 = self._pick('Tier 2 SOC', profile__role='SOC_STAFF', profile__tier='T2')
        manager = self._pick('SOC manager', profile__role='SOC_MANAGER')
        admin = self._pick('system admin', profile__role='SYSTEM_ADMIN')

        now = timezone.now()
        # Raised 25 min ago: the Critical triage OLA (30 min) is still green and
        # visibly ticking, and the 4h containment clock runs live during the demo.
        detected = now - timedelta(minutes=25)

        ticket = Ticket(
            reference_id=REFERENCE_ID,
            incident_name='Ransomware pre-encryption activity on finance file server',
            severity='Critical',
            ncsa_severity='CRITICAL',
            classification='INCIDENT',
            t1_route='ADMIN',
            issue_type='SIEM',
            detailed_issue='Malicious Logic',
            incident_datetime=detected,
            log_source='Wazuh / OpenSearch (rule 100213 — mass file rename)',
            device_name='NT-FS-FIN01',
            ip_address='10.0.188.41',
            mac_address='00:1B:44:11:3A:B7',
            asset_type='Server',
            operating_system='Windows Server 2019 Standard',
            asset_owner='Finance Department — Shared Services',
            issue_description=(
                'Wazuh raised a burst of mass file-rename events on the finance '
                'file server NT-FS-FIN01 (10.0.188.41): 1,240 files renamed to '
                'the extension .lockbit within 90 seconds, immediately after '
                'vssadmin.exe was invoked to delete volume shadow copies. '
                'Pattern matches pre-encryption staging behaviour rather than a '
                'completed encryption run — containment before spread is the '
                'priority.'
            ),
            spread_to_others=True,
            destination_ip='185.220.101.47',
            ioc_details=(
                'SHA256 8f4e2a1c9b7d3e5f6a0c8b2d4e6f1a3c5b7d9e0f2a4c6b8d0e2f4a6c8b0d2e4f\n'
                'C2 185.220.101.47:443 (TOR exit, first seen 2026-07-14)\n'
                'vssadmin.exe delete shadows /all /quiet\n'
                'Dropped: C:\\Users\\Public\\svc_update.exe'
            ),
            mitre_phase='Impact,Defense Evasion',
            action_required=(
                '1. Isolate NT-FS-FIN01 from the network (switch port shutdown).\n'
                '2. Block 185.220.101.47 at the perimeter firewall.\n'
                '3. Preserve memory + disk image before any reboot.\n'
                '4. Confirm backup integrity for the FIN share before restore.'
            ),
            action_precautions=(
                'Do NOT reboot or power off the host — volatile memory is needed '
                'for the forensic timeline. Isolate at the switch instead.'
            ),
            is_emergency=True,
            status=Ticket.STATUS_NEW,
            created_by=t1,
            assigned_to=t1,
        )
        ticket.save()

        # Backdate creation so the OLA clocks read as a live 25-minute-old case
        # (created_at is auto_now_add, so it has to be corrected after save()).
        Ticket.objects.filter(pk=ticket.pk).update(created_at=detected)
        ticket.refresh_from_db()

        # Walk the real state machine so the history tab shows a genuine trail
        # and every permission gate is actually exercised.
        ticket.transition_to(
            Ticket.STATUS_PENDING_MGR_TRIAGE, t1,
            note=('ยืนยันเป็น Incident: พบพฤติกรรมก่อนเข้ารหัสไฟล์บนเซิร์ฟเวอร์การเงิน '
                  'ขอส่งให้ผู้จัดการพิจารณามอบหมายผู้ดูแลระบบด่วน'),
        )
        ticket.transition_to(
            Ticket.STATUS_AWAITING_CONTAINMENT, manager,
            note=(f'รับทราบ — มอบหมายให้ {admin.get_full_name() or admin.username} '
                  f'ดำเนินการ isolate เครื่องและ block C2 ทันที'),
        )

        ticket.assigned_admin = admin
        ticket.acknowledged_at = detected + timedelta(minutes=6)
        ticket.save()

        # Compress the seeded trail into the last ~20 minutes so the history
        # reads as a fast-moving live case rather than three identical stamps.
        logs = list(TicketLog.objects.filter(ticket=ticket).order_by('id'))
        offsets = [2, 9, 18]
        for log, mins in zip(logs, offsets[-len(logs):]):
            TicketLog.objects.filter(pk=log.pk).update(
                created_at=detected + timedelta(minutes=mins))
        Ticket.objects.filter(pk=ticket.pk).update(
            status_changed_at=detected + timedelta(minutes=offsets[-1]))

        ticket.refresh_from_db()
        self.stdout.write(self.style.SUCCESS('\nCEO demo ticket staged.\n'))
        self.stdout.write(f'  Ticket ID   : {ticket.ticket_id}')
        self.stdout.write(f'  Reference   : {ticket.reference_id}')
        self.stdout.write(f'  Status      : {ticket.get_status_display()}')
        self.stdout.write(f'  Severity    : {ticket.severity} (emergency={ticket.is_emergency})')
        self.stdout.write(f'  Raised by   : {t1.username} (T1)')
        self.stdout.write(f'  Assigned to : {admin.username} (system admin)')
        self.stdout.write(f'  Contain OLA : {timezone.localtime(ticket.ola_contain_deadline):%d %b %H:%M}')
        self.stdout.write(
            f'  Needs mgr   : {ticket.requires_manager_verification}')
        self.stdout.write('\nDemo path from here:')
        self.stdout.write(f'  1. {admin.username:12} -> submit containment report')
        self.stdout.write(f'  2. {t2.username:12} -> verify contained -> send to manager')
        self.stdout.write(f'  3. {manager.username:12} -> approve -> closed')
        self.stdout.write('')
