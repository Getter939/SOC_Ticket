from datetime import datetime, time, timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog, TicketSubtask, TriageRecord
from apps.wazuh_ingest.models import WazuhAlert


class Command(BaseCommand):
    help = 'Create a realistic, replaceable three-week SOC demonstration dataset.'

    DEMO_PREFIX = 'DEMO-3W-'
    WAZUH_PREFIX = 'demo-3w-alert-'

    USER_SPECS = [
        ('demo.t1.somchai', 'Somchai', 'Rattanakul', 'somchai.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1, 'SOC Monitoring', '0800001101'),
        ('demo.t1.narisa', 'นริศา', 'จันทนา', 'narisa.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1, 'SOC Monitoring', '0800001102'),
        ('demo.t1.kittipong', 'Kittipong', 'Sae-Tang', 'kittipong.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1, 'SOC Monitoring', '0800001103'),
        ('demo.t1.waranya', 'Waranya', 'Prasert', 'waranya.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1, 'SOC Monitoring', '0800001104'),
        ('demo.t2.pimchanok', 'Pimchanok', 'Viroj', 'pimchanok.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T2, 'SOC Incident Response', '0800001201'),
        ('demo.t2.anawat', 'Anawat', 'Kraisorn', 'anawat.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T2, 'SOC Incident Response', '0800001202'),
        ('demo.t2.siriporn', 'ศิริพร', 'มีชัย', 'siriporn.demo@soc.local',
         UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T2, 'SOC Incident Response', '0800001203'),
        ('demo.admin.endpoint', 'Nattapong', 'Endpoint', 'endpoint.admin.demo@soc.local',
         UserProfile.ROLE_SYSTEM_ADMIN, '', 'Endpoint Engineering', '0800001301'),
        ('demo.admin.server', 'Rachata', 'Server', 'server.admin.demo@soc.local',
         UserProfile.ROLE_SYSTEM_ADMIN, '', 'Server Operations', '0800001302'),
        ('demo.admin.network', 'เฉลิม', 'วงศ์เครือข่าย', 'network.admin.demo@soc.local',
         UserProfile.ROLE_SYSTEM_ADMIN, '', 'Network Operations', '0800001303'),
        ('demo.admin.cloud', 'Methinee', 'Cloud', 'cloud.admin.demo@soc.local',
         UserProfile.ROLE_SYSTEM_ADMIN, '', 'Cloud Platform', '0800001304'),
        ('demo.owner.finance', 'Araya', 'Finance Owner', 'finance.owner.demo@soc.local',
         UserProfile.ROLE_SYSTEM_OWNER, '', 'Finance', '0800001401'),
        ('demo.owner.hr', 'Kanda', 'HR Owner', 'hr.owner.demo@soc.local',
         UserProfile.ROLE_SYSTEM_OWNER, '', 'Human Resources', '0800001402'),
        ('demo.owner.operations', 'ประสงค์', 'วัฒนกิจ', 'operations.owner.demo@soc.local',
         UserProfile.ROLE_SYSTEM_OWNER, '', 'Operations', '0800001403'),
        ('demo.owner.digital', 'Lalita', 'Digital Owner', 'digital.owner.demo@soc.local',
         UserProfile.ROLE_SYSTEM_OWNER, '', 'Digital Services', '0800001404'),
        ('demo.manager.soc', 'ธนา', 'ศรีสุวรรณ', 'manager.demo@soc.local',
         UserProfile.ROLE_SOC_MANAGER, '', 'Security Operations Centre', '0800001501'),
    ]

    SCENARIOS = [
        {
            'device': 'HR-LAPTOP-{n:02d}', 'summary': 'Encoded PowerShell launched from an email attachment',
            'detailed': 'Malicious Logic', 'detail2': 'Suspicious PowerShell', 'type': 'SIEM',
            'phase': 'Execution', 'ioc': 'SHA256: 97d8...e442\nProcess: powershell.exe -enc\nParent: WINWORD.EXE',
        },
        {
            'device': 'FILE-SHARE-{n:02d}', 'summary': 'Rapid file renaming and encryption behavior on shared storage',
            'detailed': 'Malicious Logic', 'detail2': 'Ransomware Behavior', 'type': 'SIEM',
            'phase': 'Impact', 'ioc': 'Extension: .locked\nProcess: updater_tmp.exe\nShare: \\fileserver\\department',
        },
        {
            'device': 'CRM-APP-{n:02d}', 'summary': 'Unusual bulk export of customer records outside business hours',
            'detailed': 'User Intrusion', 'detail2': 'Data Exfiltration', 'type': 'SIEM',
            'phase': 'Exfiltration', 'ioc': 'Account: svc_report\nRows exported: 184,220\nDestination ASN: external hosting',
        },
        {
            'device': 'PUBLIC-WEB-{n:02d}', 'summary': 'Repeated administrative endpoint probing from a hostile address',
            'detailed': 'Unsuccessful Attempt', 'detail2': 'Admin Panel Attempt', 'type': 'External',
            'phase': 'Reconnaissance', 'ioc': 'Paths: /admin, /backup, /.env\nHTTP: 401/403\nUser-Agent: masscan',
        },
        {
            'device': 'VPN-GATEWAY-{n:02d}', 'summary': 'Successful sign-in from geographically inconsistent locations',
            'detailed': 'User Intrusion', 'detail2': 'Impossible Travel', 'type': 'SIEM',
            'phase': 'Initial Access', 'ioc': 'Account: contractor.ops\nLocations: Bangkok / Frankfurt\nInterval: 19 minutes',
        },
        {
            'device': 'EDGE-FW-{n:02d}', 'summary': 'Sustained port scanning against internet-facing services',
            'detailed': 'Reconnaissance', 'detail2': 'Port Scanning', 'type': 'TI',
            'phase': 'Reconnaissance', 'ioc': 'Ports: 22, 80, 443, 3389\nPackets: 9,481\nSource reputation: scanner',
        },
        {
            'device': 'FIN-PC-{n:02d}', 'summary': 'Unapproved remote administration utility installed by a user',
            'detailed': 'Non-Compliance', 'detail2': 'Unauthorized Software', 'type': 'Admin',
            'phase': 'Persistence', 'ioc': 'Package: remote-help.exe\nPublisher: Unknown\nInstall context: local user',
        },
        {
            'device': 'PAYMENT-API-{n:02d}', 'summary': 'Critical externally reported API authorization weakness',
            'detailed': 'Vulnerability', 'detail2': 'Vulnerability Found', 'type': 'External',
            'phase': 'Initial Access', 'ioc': 'Endpoint: /api/v2/invoices/{id}\nFinding: broken object authorization\nCVE: N/A',
        },
        {
            'device': 'CUSTOMER-PORTAL-{n:02d}', 'summary': 'Distributed request flood caused service degradation',
            'detailed': 'DoS', 'detail2': 'DDoS', 'type': 'SIEM',
            'phase': 'Impact', 'ioc': 'Peak: 84,000 req/s\nSources: 1,920 IPs\nTarget: /login',
        },
        {
            'device': 'DNS-RESOLVER-{n:02d}', 'summary': 'Threat intelligence match for communication with malicious infrastructure',
            'detailed': 'Investigating', 'detail2': 'TI Malicious IP', 'type': 'TI',
            'phase': 'Command and Control', 'ioc': 'Domain: sync-update.example.invalid\nIP: 203.0.113.88\nConfidence: High',
        },
        {
            'device': 'BACKUP-SERVER-{n:02d}', 'summary': 'After-hours privileged maintenance generated an anomaly',
            'detailed': 'Explained Anomaly', 'detail2': 'Admin Maintenance', 'type': 'Admin',
            'phase': 'Discovery', 'ioc': 'Change: CHG-DEMO-2204\nAccount: backup.admin\nWindow: approved',
        },
        {
            'device': 'SALES-VDI-{n:02d}', 'summary': 'Endpoint beaconing pattern consistent with command-and-control traffic',
            'detailed': 'Malicious Logic', 'detail2': 'C2 Server', 'type': 'SIEM',
            'phase': 'Command and Control', 'ioc': 'Interval: 60 seconds\nJA3: 72a589da586844d7f0818ce684948eea\nBytes: 247',
        },
    ]

    GENERIC_STATUS_PLAN = (
        [Ticket.STATUS_NEW] * 3
        + [Ticket.STATUS_ESCALATED_T2] * 4
        + [Ticket.STATUS_T1_REVIEW] * 3
        + [Ticket.STATUS_AWAITING_CONTAINMENT] * 7
        + [Ticket.STATUS_CONTAINMENT_REPORTED] * 4
        + [Ticket.STATUS_PENDING_MANAGER] * 3
        + [Ticket.STATUS_APPROVED] * 27
        + [Ticket.STATUS_CLOSED_EVENT] * 16
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset', action='store_true',
            help='Replace only the records tagged as this three-week demo dataset.',
        )
        parser.add_argument(
            '--password', default='Demo@12345',
            help='Password assigned to all demo users (default: Demo@12345).',
        )
        parser.add_argument(
            '--thai-only', action='store_true',
            help='Create or replace only the fully Thai Emergency showcase ticket.',
        )

    def handle(self, *args, **options):
        self.now = timezone.now().replace(second=0, microsecond=0)
        self.ticket_sequences = {}

        if options['thai_only']:
            with transaction.atomic():
                Ticket.objects.filter(
                    reference_id=f'{self.DEMO_PREFIX}THAI-EMERGENCY-001'
                ).delete()
                users = self._create_users(options['password'])
                thai_showcase = self._create_thai_showcase_ticket(users)
            self.stdout.write(self.style.SUCCESS('Thai Emergency showcase ticket is ready.'))
            self.stdout.write(f'Thai Emergency showcase: /incidents/ticket/{thai_showcase.pk}/')
            self.stdout.write(f'Demo password: {options["password"]}')
            self.stdout.write('Tier 1 login: demo.t1.narisa')
            return

        existing = Ticket.objects.filter(reference_id__startswith=self.DEMO_PREFIX).count()
        if existing and not options['reset']:
            raise CommandError(
                f'{existing} demo tickets already exist. Re-run with --reset to replace them.'
            )

        with transaction.atomic():
            if options['reset']:
                self._clear_demo_records()
            users = self._create_users(options['password'])
            showcase = self._create_showcase_ticket(users)
            thai_showcase = self._create_thai_showcase_ticket(users)
            tickets = [showcase, thai_showcase]
            for index, status in enumerate(self.GENERIC_STATUS_PLAN, start=1):
                tickets.append(self._create_generic_ticket(index, status, users))
            alerts = self._create_wazuh_alerts(users, tickets)
            triage_records = self._create_manual_triage(users, tickets)

        active = sum(ticket.status not in Ticket.TERMINAL_STATUSES for ticket in tickets)
        self.stdout.write(self.style.SUCCESS('Three-week production demo dataset is ready.'))
        self.stdout.write(
            str({
                'tickets': len(tickets),
                'active': active,
                'closed': len(tickets) - active,
                'users': len(users),
                'wazuh_alerts': len(alerts),
                'manual_triage': len(triage_records),
            })
        )
        self.stdout.write(f'Dashboard: /')
        self.stdout.write(f'Active task list: /incidents/')
        self.stdout.write(f'Emergency showcase: /incidents/ticket/{showcase.pk}/')
        self.stdout.write(f'Thai Emergency showcase: /incidents/ticket/{thai_showcase.pk}/')
        self.stdout.write(f'Demo password: {options["password"]}')
        self.stdout.write('Tier 1 login: demo.t1.somchai')
        self.stdout.write('Tier 2 login: demo.t2.pimchanok')
        self.stdout.write('System Admin login: demo.admin.server')
        self.stdout.write('SOC Manager login: demo.manager.soc')

    def _clear_demo_records(self):
        TriageRecord.objects.filter(source_reference__startswith=self.DEMO_PREFIX).delete()
        Ticket.objects.filter(reference_id__startswith=self.DEMO_PREFIX).delete()
        WazuhAlert.objects.filter(opensearch_id__startswith=self.WAZUH_PREFIX).delete()

    def _create_users(self, password):
        users = {}
        for spec in self.USER_SPECS:
            username, first, last, email, role, tier, department, phone = spec
            user, _ = User.objects.update_or_create(
                username=username,
                defaults={
                    'first_name': first,
                    'last_name': last,
                    'email': email,
                    'is_active': True,
                },
            )
            user.set_password(password)
            user.save(update_fields=['password'])
            UserProfile.objects.update_or_create(
                user=user,
                defaults={
                    'role': role,
                    'tier': tier,
                    'department': department,
                    'phone': phone,
                    'note': 'Three-week production simulation account',
                },
            )
            users[username] = user
        return users

    def _next_ticket_id(self, opened_at):
        prefix = f'{opened_at.year % 100:02d}{opened_at.month:02d}'
        if prefix not in self.ticket_sequences:
            sequences = []
            for value in Ticket.objects.filter(
                ticket_id__startswith=prefix,
            ).values_list('ticket_id', flat=True):
                suffix = value[len(prefix):]
                if suffix.isdigit():
                    sequences.append(int(suffix))
            self.ticket_sequences[prefix] = max(sequences, default=0)
        self.ticket_sequences[prefix] += 1
        return f'{prefix}{self.ticket_sequences[prefix]:02d}'

    def _create_showcase_ticket(self, users):
        t1 = users['demo.t1.somchai']
        t2 = users['demo.t2.pimchanok']
        admin = users['demo.admin.server']
        owner = users['demo.owner.finance']
        manager = users['demo.manager.soc']
        opened = self.now - timedelta(days=6, hours=4)
        incident_time = opened - timedelta(minutes=26)
        escalated = opened + timedelta(minutes=34)
        approved = opened + timedelta(hours=21, minutes=18)

        ticket = Ticket.objects.create(
            ticket_id=self._next_ticket_id(opened),
            severity='Critical',
            incident_datetime=incident_time,
            reference_id=f'{self.DEMO_PREFIX}EMERGENCY-001',
            device_name='FIN-ERP-PROD-DB01 / SAP Finance Database',
            issue_description=(
                'The SOC detected a valid service-account login followed by high-volume reads '
                'from finance tables and encrypted outbound traffic to infrastructure with a '
                'recent malware reputation. Correlation showed the same account authenticating '
                'from an application server where an unsigned scheduled task had been created.\n\n'
                'Business impact assessment: the affected database supports payment approval, '
                'general ledger posting, and month-end reporting. Initial review identified '
                'potential exposure of vendor bank details and invoice metadata. No evidence of '
                'ledger modification was found, but confidentiality risk was considered critical.'
            ),
            ip_address='10.42.16.21',
            mac_address='02:42:16:21:7A:9C',
            asset_type='Server',
            spread_to_others=True,
            destination_ip='185.220.101.47',
            ioc_details=(
                'Destination IP: 185.220.101.47 (malware infrastructure, high confidence)\n'
                'Domain: cdn-finance-sync.example.invalid\n'
                'Compromised account: svc_finance_etl\n'
                'Scheduled task: FinanceDataSyncUpdate\n'
                'Payload SHA256: 9bc3d5405a741c37c1204f9a6b4d2c403e6a0f728f18820ec9b98547a12d9e31\n'
                'Observed command: rundll32.exe C:\\ProgramData\\fin_sync.dll,Start\n'
                'Outbound volume: 2.8 GB over 17 minutes'
            ),
            mitre_phase='Exfiltration',
            action_required=(
                '1. Isolate FIN-ERP-PROD-DB01 from nonessential network segments.\n'
                '2. Disable and rotate svc_finance_etl credentials and dependent secrets.\n'
                '3. Block the destination IP/domain at firewall, proxy, DNS, and EDR layers.\n'
                '4. Preserve volatile evidence, scheduled-task XML, database audit logs, and EDR telemetry.\n'
                '5. Hunt for the hash, domain, account, and task name across all systems.\n'
                '6. Validate financial-record integrity with the Finance application owner.'
            ),
            action_precautions=(
                'Coordinate isolation with Finance Operations to avoid interrupting payment '
                'settlement. Capture memory before reboot. Do not delete the scheduled task or '
                'payload until forensic copies and hashes have been collected. Rotate credentials '
                'through the approved privileged-access workflow.'
            ),
            remediation_summary=(
                'Investigation confirmed that svc_finance_etl was used from APP-FIN-02 after an '
                'internet-facing middleware account was compromised. The attacker created a '
                'scheduled task that loaded fin_sync.dll and queried invoice/vendor tables. EDR '
                'and database audit logs confirmed staging and attempted exfiltration. The first '
                'containment submission blocked the destination but left an active refresh token '
                'and a second scheduled task on APP-FIN-02; Tier 1 rejected containment.\n\n'
                'The second investigation pass revoked all sessions, rotated application and '
                'database secrets, removed both persistence mechanisms after evidence capture, '
                'rebuilt APP-FIN-02, and found no additional hosts with the indicators. Finance '
                'validated record integrity and Legal/Privacy received the exposure assessment.'
            ),
            containment_report=(
                'Completed countermeasures:\n'
                '- Isolated FIN-ERP-PROD-DB01 and APP-FIN-02 using EDR network containment.\n'
                '- Blocked IP, domain, TLS fingerprint, and payload hash across security controls.\n'
                '- Disabled svc_finance_etl, revoked tokens, and rotated database, vault, and service credentials.\n'
                '- Captured memory/disk evidence and exported database, firewall, proxy, and identity logs.\n'
                '- Rebuilt APP-FIN-02 from the approved image and applied middleware patches.\n'
                '- Ran enterprise-wide indicator hunt: 2,146 endpoints checked, no further matches.\n'
                '- Monitored finance traffic for 12 hours with no recurring beaconing or unauthorized query activity.'
            ),
            status=Ticket.STATUS_APPROVED,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            escalated_to_t2_at=escalated,
            is_emergency=True,
            system_owner=owner,
            assigned_to=t1,
            assigned_admin=admin,
            verified_by=t1,
            verified_at=opened + timedelta(hours=19, minutes=42),
            approved_by=manager,
            approved_at=approved,
            update_notes=(
                'Emergency Incident fully contained after one rejected containment cycle. '
                'Manager verification completed; retain evidence under IR-03 for 365 days.'
            ),
            sla_deadline=incident_time + timedelta(hours=4),
            issue_type='SIEM',
            detailed_issue='Root Intrusion',
            detailed_issue2='Data Exfiltration',
            created_by=t1,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=opened, updated_at=approved)
        ticket.refresh_from_db()

        history = [
            (opened, Ticket.STATUS_NEW, t1,
             'Tier 1 opened the case after correlating database-audit, identity, proxy, and EDR alerts. Severity set to Critical because the affected service processes payment and vendor banking data.'),
            (escalated, Ticket.STATUS_ESCALATED_T2, t1,
             'Escalated to Tier 2 for confirmation. Evidence package included the suspicious service account, 2.8 GB outbound transfer, new scheduled task, payload hash, and destination reputation.'),
            (opened + timedelta(minutes=47), Ticket.STATUS_ESCALATED_T2, t2,
             'Emergency enabled after Tier 2 identified active command-and-control traffic and continuing database reads. Incident commander and Finance duty owner were notified.'),
            (opened + timedelta(hours=1, minutes=38), Ticket.STATUS_T1_REVIEW, t2,
             'Tier 2 confirmed Incident classification. Timeline reconstruction tied the service-account session to APP-FIN-02 and identified likely credential compromise plus persistence. Returned to Tier 1 for accountable admin assignment.'),
            (opened + timedelta(hours=2, minutes=5), Ticket.STATUS_AWAITING_CONTAINMENT, t1,
             'Tier 1 assigned Server Operations. Requested coordinated isolation, evidence capture, credential revocation, destination blocking, and an enterprise indicator hunt before service restoration.'),
            (opened + timedelta(hours=8, minutes=16), Ticket.STATUS_CONTAINMENT_REPORTED, admin,
             'Initial containment report: destination blocked, database host isolated, service account disabled, and memory image collected. APP-FIN-02 remained online for business continuity pending application-owner approval.'),
            (opened + timedelta(hours=9, minutes=4), Ticket.STATUS_AWAITING_CONTAINMENT, t1,
             'Containment rejected as incomplete. Identity logs showed an active refresh token and EDR found a second scheduled task on APP-FIN-02. Returned to System Admin with explicit requirements to revoke sessions, capture the second artifact, and rebuild the middleware host.'),
            (opened + timedelta(hours=17, minutes=20), Ticket.STATUS_CONTAINMENT_REPORTED, admin,
             'Revised containment report: all tokens revoked; service, database, and vault secrets rotated; both persistence tasks preserved then removed; APP-FIN-02 rebuilt; enterprise hunt completed with no additional matches; finance data integrity checks passed.'),
            (opened + timedelta(hours=19, minutes=42), Ticket.STATUS_PENDING_MANAGER, t1,
             'Tier 1 verified containment through fresh EDR telemetry, firewall/proxy review, credential tests, and a 12-hour clean monitoring window. Because the ticket is Critical and Emergency, routed to SOC Manager for final verification.'),
            (approved, Ticket.STATUS_APPROVED, manager,
             'SOC Manager verified evidence completeness, containment effectiveness, business-owner confirmation, and follow-up ownership. Incident approved for closure with a 7-day heightened-monitoring action and a lessons-learned review scheduled.'),
        ]
        for created_at, status, author, note in history:
            self._create_log(ticket, status, author, note, created_at)

        subtask_specs = [
            (TicketSubtask.TYPE_INVESTIGATION, 'Preserve volatile and disk evidence', admin,
             'Capture memory from both hosts, export scheduled-task definitions, and calculate evidence hashes.',
             'Memory and disk images stored in IR evidence vault; SHA256 manifest verified.'),
            (TicketSubtask.TYPE_INVESTIGATION, 'Reconstruct identity and database timeline', t2,
             'Correlate identity provider, database audit, proxy, and EDR events from 24 hours before detection.',
             'Timeline confirmed initial access through APP-FIN-02 and 17-minute collection/exfiltration window.'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'Revoke sessions and rotate credentials', admin,
             'Disable the service account, revoke refresh tokens, and rotate all dependent secrets.',
             'All sessions revoked and six dependent credentials rotated through PAM.'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'Block and hunt indicators enterprise-wide', users['demo.admin.network'],
             'Block infrastructure and search DNS, proxy, firewall, and endpoint telemetry for related indicators.',
             'Controls updated; 2,146 endpoints and 30 days of network telemetry searched with no further matches.'),
            (TicketSubtask.TYPE_INVESTIGATION, 'Validate finance data integrity', owner,
             'Compare ledger and vendor records to signed reconciliation snapshots.',
             'No unauthorized modification found; potential confidentiality exposure documented for Privacy review.'),
        ]
        for offset, spec in enumerate(subtask_specs, start=1):
            kind, title, assignee, description, result = spec
            subtask = TicketSubtask.objects.create(
                ticket=ticket,
                subtask_type=kind,
                title=title,
                description=description,
                status=TicketSubtask.STATUS_DONE,
                assigned_to=assignee,
                result_notes=result,
                created_by=t1,
            )
            sub_created = opened + timedelta(hours=2 + offset)
            TicketSubtask.objects.filter(pk=subtask.pk).update(
                created_at=sub_created,
                updated_at=opened + timedelta(hours=16 + offset),
            )
        return ticket

    def _create_thai_showcase_ticket(self, users):
        t1 = users['demo.t1.narisa']
        t2 = users['demo.t2.siriporn']
        admin = users['demo.admin.network']
        owner = users['demo.owner.operations']
        manager = users['demo.manager.soc']
        yesterday = timezone.localtime(self.now).date() - timedelta(days=1)
        current_tz = timezone.get_current_timezone()

        def at(hour, minute):
            return timezone.make_aware(
                datetime.combine(yesterday, time(hour, minute)),
                current_tz,
            )

        incident_time = at(8, 12)
        opened = at(8, 34)
        escalated = at(9, 6)
        verified = at(17, 42)
        approved = at(18, 25)

        ticket = Ticket.objects.create(
            ticket_id=self._next_ticket_id(opened),
            severity='Critical',
            incident_datetime=incident_time,
            reference_id=f'{self.DEMO_PREFIX}THAI-EMERGENCY-001',
            device_name='ระบบบริหารคลังสินค้า PROD-WMS-01',
            issue_description=(
                'ศูนย์เฝ้าระวังความมั่นคงปลอดภัยไซเบอร์ตรวจพบการเข้าสู่ระบบด้วยบัญชีผู้ดูแลคลังสินค้า '
                'จากหมายเลขไอพีที่ไม่เคยใช้งานมาก่อน หลังจากนั้นมีการเรียกดูข้อมูลสินค้าคงเหลือ '
                'รายการจัดส่ง และข้อมูลคู่ค้าปริมาณมากผิดปกติภายในช่วงเวลา 14 นาที พร้อมพบการเชื่อมต่อ '
                'ออกไปยังเครื่องแม่ข่ายภายนอกที่อยู่ในรายการเฝ้าระวังภัยคุกคาม\n\n'
                'ระบบดังกล่าวเป็นระบบสำคัญที่ใช้ควบคุมการรับสินค้า การจัดเก็บ และการส่งมอบสินค้า '
                'ให้ลูกค้าทั่วประเทศ หากระบบหยุดให้บริการหรือข้อมูลถูกแก้ไขจะส่งผลต่อการดำเนินงานทันที '
                'ทีมวิเคราะห์จึงยกระดับเป็นเหตุฉุกเฉิน สั่งจำกัดการเชื่อมต่อ เก็บรักษาหลักฐานดิจิทัล '
                'และประสานเจ้าของระบบเพื่อยืนยันความถูกต้องของข้อมูลและผลกระทบทางธุรกิจ'
            ),
            ip_address='10.35.8.41',
            mac_address='02:35:08:41:9B:27',
            asset_type='Server',
            spread_to_others=True,
            destination_ip='203.0.113.146',
            ioc_details=(
                'หมายเลขไอพีต้นทางที่ผิดปกติ: 198.51.100.217\n'
                'หมายเลขไอพีปลายทางที่ถูกบล็อก: 203.0.113.146\n'
                'บัญชีที่ได้รับผลกระทบ: wms_admin_ops\n'
                'ชื่อไฟล์ที่ตรวจพบ: inventory_sync_update.ps1\n'
                'ค่าแฮช SHA-256: 42c8aa0fd7b06168cc3d193f5e04982b17283379c53d12210fd4772f18df37a1\n'
                'งานตามกำหนดเวลาที่ผิดปกติ: WMS_Inventory_Sync_Update\n'
                'ปริมาณข้อมูลที่ส่งออก: 1.4 กิกะไบต์ ภายใน 14 นาที'
            ),
            mitre_phase='Exfiltration',
            action_required=(
                '1. จำกัดการเชื่อมต่อของเครื่อง PROD-WMS-01 และเครื่องเชื่อมต่อ WMS-APP-02 ทันที\n'
                '2. ระงับบัญชี wms_admin_ops เพิกถอนโทเคน และเปลี่ยนรหัสผ่านที่เกี่ยวข้องทั้งหมด\n'
                '3. บล็อกหมายเลขไอพี ชื่อโดเมน ค่าแฮช และรูปแบบการเชื่อมต่อที่ตรวจพบ\n'
                '4. เก็บหน่วยความจำ บันทึกเหตุการณ์ และสำเนาไฟล์ต้องสงสัยก่อนดำเนินการลบ\n'
                '5. ตรวจค้นตัวบ่งชี้เดียวกันในเครื่องแม่ข่ายและเครื่องลูกข่ายทุกระบบ\n'
                '6. ให้เจ้าของระบบตรวจสอบความถูกต้องของข้อมูลสินค้าคงเหลือและรายการจัดส่ง'
            ),
            action_precautions=(
                'ต้องประสานหัวหน้าฝ่ายปฏิบัติการคลังสินค้าก่อนตัดการเชื่อมต่อ เพื่อหลีกเลี่ยงการหยุดชะงัก '
                'ของงานจัดส่ง ห้ามลบไฟล์ งานตามกำหนดเวลา หรือบันทึกเหตุการณ์ก่อนจัดเก็บหลักฐานและคำนวณ '
                'ค่าแฮชเรียบร้อย การเปลี่ยนข้อมูลรับรองต้องดำเนินการผ่านระบบบริหารบัญชีสิทธิ์สูงเท่านั้น'
            ),
            remediation_summary=(
                'ผลการตรวจสอบยืนยันว่าบัญชี wms_admin_ops ถูกนำไปใช้จากเครื่อง WMS-APP-02 '
                'หลังจากผู้โจมตีอาศัยช่องโหว่ของส่วนเชื่อมต่อเว็บที่ยังไม่ได้ติดตั้งโปรแกรมแก้ไข '
                'ผู้โจมตีสร้างงานตามกำหนดเวลาเพื่อเรียกใช้สคริปต์ inventory_sync_update.ps1 '
                'รวบรวมข้อมูลสินค้าคงเหลือและรายการจัดส่ง แล้วพยายามส่งข้อมูลออกไปยังเครื่องแม่ข่ายภายนอก\n\n'
                'ทีมผู้ดูแลระบบตรวจสอบบันทึกจากระบบยืนยันตัวตน ไฟร์วอลล์ ระบบป้องกันปลายทาง และฐานข้อมูล '
                'พบกิจกรรมจำกัดอยู่ที่ PROD-WMS-01 และ WMS-APP-02 ไม่พบการเคลื่อนย้ายไปยังระบบอื่น '
                'เจ้าของระบบตรวจสอบยอดสินค้าคงเหลือและรายการจัดส่งแล้ว ไม่พบการแก้ไขหรือลบข้อมูล '
                'แต่ประเมินว่ามีความเสี่ยงด้านการเปิดเผยข้อมูลคู่ค้าและแผนการจัดส่ง จึงส่งรายละเอียดให้ '
                'ฝ่ายกฎหมายและผู้รับผิดชอบด้านข้อมูลส่วนบุคคลพิจารณาต่อ'
            ),
            containment_report=(
                'มาตรการควบคุมและแก้ไขที่ดำเนินการแล้ว:\n'
                '- จำกัดการเชื่อมต่อ PROD-WMS-01 และ WMS-APP-02 ผ่านระบบป้องกันปลายทาง\n'
                '- ระงับบัญชี wms_admin_ops เพิกถอนโทเคนทุกชุด และเปลี่ยนข้อมูลรับรองที่เกี่ยวข้อง\n'
                '- บล็อกหมายเลขไอพีปลายทาง ชื่อโดเมน ค่าแฮช และลายพิมพ์การเชื่อมต่อในทุกจุดควบคุม\n'
                '- เก็บสำเนาหน่วยความจำ ไฟล์ต้องสงสัย งานตามกำหนดเวลา และบันทึกเหตุการณ์พร้อมค่าแฮช\n'
                '- ติดตั้งโปรแกรมแก้ไขส่วนเชื่อมต่อเว็บ และสร้าง WMS-APP-02 ใหม่จากแม่แบบที่ได้รับอนุมัติ\n'
                '- ตรวจค้นตัวบ่งชี้ในเครื่องลูกข่าย 2,146 เครื่องและบันทึกเครือข่ายย้อนหลัง 30 วัน ไม่พบจุดอื่น\n'
                '- เฝ้าระวังการเชื่อมต่อและพฤติกรรมบัญชีต่อเนื่อง 12 ชั่วโมง ไม่พบกิจกรรมผิดปกติซ้ำ'
            ),
            status=Ticket.STATUS_APPROVED,
            classification=Ticket.CLASSIFICATION_INCIDENT,
            escalated_to_t2_at=escalated,
            is_emergency=True,
            system_owner=owner,
            assigned_to=t1,
            assigned_admin=admin,
            verified_by=t1,
            verified_at=verified,
            approved_by=manager,
            approved_at=approved,
            update_notes=(
                'ยืนยันการควบคุมเหตุฉุกเฉินเรียบร้อยแล้ว ผู้จัดการ SOC อนุมัติปิดเคส '
                'และกำหนดให้เฝ้าระวังเพิ่มเติม 7 วัน พร้อมจัดประชุมสรุปบทเรียนจากเหตุการณ์'
            ),
            sla_deadline=incident_time + timedelta(hours=4),
            issue_type='SIEM',
            detailed_issue='Root Intrusion',
            detailed_issue2='Data Exfiltration',
            created_by=t1,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=opened, updated_at=approved)
        ticket.refresh_from_db()

        history = [
            (opened, Ticket.STATUS_NEW, t1,
             'Tier 1 เปิดเคสหลังเชื่อมโยงข้อมูลจากระบบยืนยันตัวตน ไฟร์วอลล์ ฐานข้อมูล และระบบป้องกันปลายทาง พร้อมบันทึกขอบเขตเบื้องต้น เจ้าของระบบ และผลกระทบต่อการจัดส่งสินค้า'),
            (escalated, Ticket.STATUS_ESCALATED_T2, t1,
             'ส่งต่อให้ Tier 2 ตรวจสอบยืนยัน เนื่องจากพบทั้งการใช้บัญชีสิทธิ์สูง การรวบรวมข้อมูลจำนวนมาก และการส่งข้อมูลออกไปยังปลายทางที่มีความเสี่ยง'),
            (at(9, 18), Ticket.STATUS_ESCALATED_T2, t2,
             'เปิดสถานะฉุกเฉินหลังยืนยันว่าการเชื่อมต่อออกยังคงเกิดขึ้นและระบบที่ได้รับผลกระทบเป็นระบบสำคัญต่อการปฏิบัติงานคลังสินค้า แจ้งผู้จัดการเวรและเจ้าของระบบแล้ว'),
            (at(10, 2), Ticket.STATUS_T1_REVIEW, t2,
             'Tier 2 ยืนยันว่าเป็น Incident จากหลักฐานบัญชีถูกนำไปใช้ งานตามกำหนดเวลาที่ไม่ได้รับอนุญาต และรูปแบบการส่งข้อมูลออก ส่งกลับ Tier 1 เพื่อมอบหมายผู้ดูแลระบบ'),
            (at(10, 20), Ticket.STATUS_AWAITING_CONTAINMENT, t1,
             'Tier 1 มอบหมายฝ่ายเครือข่ายและระบบให้จำกัดการเชื่อมต่อ เก็บหลักฐาน ระงับบัญชี บล็อกตัวบ่งชี้ และตรวจสอบการกระจายไปยังระบบอื่น โดยให้ประสานเจ้าของระบบก่อนดำเนินการที่กระทบบริการ'),
            (at(16, 55), Ticket.STATUS_CONTAINMENT_REPORTED, admin,
             'ผู้ดูแลระบบส่งผลการตรวจสอบและมาตรการควบคุมครบถ้วน เครื่องที่ได้รับผลกระทบถูกจำกัดการเชื่อมต่อ บัญชีและโทเคนถูกเพิกถอน ระบบเชื่อมต่อถูกสร้างใหม่ และไม่พบตัวบ่งชี้ในเครื่องอื่น'),
            (verified, Ticket.STATUS_PENDING_MANAGER, t1,
             'Tier 1 ตรวจสอบหลักฐานหลังควบคุม ทดสอบข้อมูลรับรอง ตรวจบันทึกเครือข่าย และยืนยันกับเจ้าของระบบแล้ว ไม่พบกิจกรรมผิดปกติซ้ำ เนื่องจากเป็นเหตุฉุกเฉินระดับวิกฤตจึงส่งให้ผู้จัดการ SOC ตรวจสอบขั้นสุดท้าย'),
            (approved, Ticket.STATUS_APPROVED, manager,
             'ผู้จัดการ SOC ตรวจสอบความครบถ้วนของหลักฐาน ประสิทธิผลของการควบคุม การยืนยันจากเจ้าของระบบ และผู้รับผิดชอบงานติดตามแล้ว อนุมัติปิดเคสและกำหนดเฝ้าระวังเพิ่มเติม 7 วัน'),
        ]
        for created_at, status, author, note in history:
            self._create_log(ticket, status, author, note, created_at)

        subtask_specs = [
            (TicketSubtask.TYPE_INVESTIGATION, 'จัดเก็บหลักฐานดิจิทัล', admin,
             'เก็บหน่วยความจำ ไฟล์ต้องสงสัย งานตามกำหนดเวลา และบันทึกเหตุการณ์จากทั้งสองเครื่อง',
             'จัดเก็บหลักฐานในคลังหลักฐานกลางพร้อมค่าแฮชและบันทึกผู้ครอบครองหลักฐานครบถ้วน'),
            (TicketSubtask.TYPE_INVESTIGATION, 'ตรวจสอบขอบเขตและลำดับเหตุการณ์', t2,
             'เชื่อมโยงข้อมูลยืนยันตัวตน ฐานข้อมูล ไฟร์วอลล์ และระบบป้องกันปลายทาง',
             'ยืนยันขอบเขตอยู่ที่สองเครื่องและจัดทำลำดับเหตุการณ์ตั้งแต่เริ่มเข้าสู่ระบบจนถึงการควบคุม'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'เพิกถอนสิทธิ์และเปลี่ยนข้อมูลรับรอง', admin,
             'ระงับบัญชี เพิกถอนโทเคน และเปลี่ยนรหัสผ่านหรือกุญแจลับของระบบที่เกี่ยวข้อง',
             'เพิกถอนเซสชันทั้งหมดและเปลี่ยนข้อมูลรับรองที่เกี่ยวข้องจำนวนหกรายการเรียบร้อย'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'บล็อกและตรวจค้นตัวบ่งชี้', admin,
             'บล็อกตัวบ่งชี้ในทุกจุดควบคุมและตรวจค้นย้อนหลังในระบบองค์กร',
             'ตรวจค้นเครื่องลูกข่าย 2,146 เครื่องและข้อมูลเครือข่ายย้อนหลัง 30 วัน ไม่พบจุดอื่น'),
        ]
        for offset, spec in enumerate(subtask_specs, start=1):
            kind, title, assignee, description, result = spec
            subtask = TicketSubtask.objects.create(
                ticket=ticket,
                subtask_type=kind,
                title=title,
                description=description,
                status=TicketSubtask.STATUS_DONE,
                assigned_to=assignee,
                result_notes=result,
                created_by=t1,
            )
            TicketSubtask.objects.filter(pk=subtask.pk).update(
                created_at=at(10 + offset, 0),
                updated_at=at(16 + offset // 2, 20),
            )
        return ticket

    def _create_generic_ticket(self, index, status, users):
        scenario = self.SCENARIOS[(index - 1) % len(self.SCENARIOS)]
        t1_users = [users[name] for name in (
            'demo.t1.somchai', 'demo.t1.narisa', 'demo.t1.kittipong', 'demo.t1.waranya',
        )]
        t2_users = [users[name] for name in (
            'demo.t2.pimchanok', 'demo.t2.anawat', 'demo.t2.siriporn',
        )]
        admins = [users[name] for name in (
            'demo.admin.endpoint', 'demo.admin.server', 'demo.admin.network', 'demo.admin.cloud',
        )]
        owners = [users[name] for name in (
            'demo.owner.finance', 'demo.owner.hr', 'demo.owner.operations', 'demo.owner.digital',
        )]
        manager = users['demo.manager.soc']
        t1 = t1_users[index % len(t1_users)]
        t2 = t2_users[index % len(t2_users)]
        admin = admins[index % len(admins)]
        owner = owners[index % len(owners)]

        age_days = (index * 8) % 21
        opened = self.now - timedelta(days=age_days, hours=(index * 3) % 18 + 1)
        is_event = status == Ticket.STATUS_CLOSED_EVENT
        classification = (
            Ticket.CLASSIFICATION_EVENT if is_event else Ticket.CLASSIFICATION_INCIDENT
        )
        severity_cycle = ['Medium', 'High', 'Low', 'High', 'Critical']
        severity = severity_cycle[index % len(severity_cycle)]
        is_emergency = not is_event and index % 10 == 0
        if status == Ticket.STATUS_PENDING_MANAGER:
            severity = 'Critical'
        requires_manager = severity == 'Critical' or is_emergency
        escalated = (
            status in (Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW)
            or index % 3 == 0
            or is_emergency
        )
        path = self._status_path(status, classification, escalated, requires_manager)
        span = max(self.now - opened, timedelta(hours=len(path) + 1))
        interval = min(span / (len(path) + 1), timedelta(hours=12))
        event_times = [opened + interval * position for position in range(len(path))]
        last_time = event_times[-1]

        breach_mode = index % 7
        if breach_mode == 0:
            incident_time = opened - timedelta(hours=5, minutes=10)
        elif breach_mode == 1:
            incident_time = opened - timedelta(hours=3, minutes=35)
        else:
            incident_time = opened - timedelta(minutes=35 + (index % 4) * 25)

        has_admin = (
            classification == Ticket.CLASSIFICATION_INCIDENT
            and status not in (Ticket.STATUS_NEW, Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW)
        )
        verified_time = None
        if Ticket.STATUS_PENDING_MANAGER in path:
            verified_time = event_times[path.index(Ticket.STATUS_PENDING_MANAGER)]
        elif status == Ticket.STATUS_APPROVED and classification == Ticket.CLASSIFICATION_INCIDENT:
            verified_time = event_times[-1]
        approved_by = None
        approved_at = None
        if status == Ticket.STATUS_APPROVED:
            approved_by = manager if requires_manager else t1
            approved_at = last_time

        octet = 20 + index
        ticket = Ticket.objects.create(
            ticket_id=self._next_ticket_id(opened),
            severity=severity,
            incident_datetime=incident_time,
            reference_id=f'{self.DEMO_PREFIX}TKT-{index:03d}',
            device_name=scenario['device'].format(n=index),
            issue_description=(
                f"{scenario['summary']}. Detection was correlated across the available security "
                f"telemetry and reviewed by {t1.get_full_name()}. Scope, business impact, and "
                'required response were recorded so each handoff has clear ownership.'
            ),
            ip_address=f'10.{20 + index % 5}.{1 + index // 25}.{octet % 240 + 10}',
            mac_address=f'02:42:{index % 255:02X}:{(index * 3) % 255:02X}:{(index * 7) % 255:02X}:{(index * 11) % 255:02X}',
            asset_type=['Computer', 'Server', 'Network Device'][index % 3],
            spread_to_others=(index % 4 == 0),
            destination_ip=f'203.0.113.{20 + index % 180}',
            ioc_details=scenario['ioc'],
            mitre_phase=scenario['phase'],
            action_required=(
                'Validate the alert against endpoint, identity, and network telemetry. Preserve '
                'relevant logs, contain confirmed indicators, document scope, and notify the '
                'system owner before any service-impacting action.'
            ),
            action_precautions=(
                'Confirm business dependencies and evidence capture before isolation. Use the '
                'approved change channel for firewall, identity, or production-host changes.'
            ),
            remediation_summary=(
                f"Investigation by {admin.get_full_name()} reviewed authentication, process, and "
                'network evidence. Indicators were scoped to the listed asset and related accounts; '
                'no unrecorded lateral movement was found.'
                if Ticket.STATUS_CONTAINMENT_REPORTED in path else ''
            ),
            containment_report=(
                'Relevant indicators were blocked, credentials were reviewed or rotated, the '
                'affected asset was scanned, and post-containment telemetry showed no recurrence.'
                if Ticket.STATUS_CONTAINMENT_REPORTED in path else ''
            ),
            status=status,
            classification=classification,
            escalated_to_t2_at=(
                event_times[path.index(Ticket.STATUS_ESCALATED_T2)]
                if Ticket.STATUS_ESCALATED_T2 in path else None
            ),
            is_emergency=is_emergency,
            system_owner=owner,
            assigned_to=t1,
            assigned_admin=admin if has_admin or status == Ticket.STATUS_APPROVED else None,
            verified_by=t1 if verified_time else None,
            verified_at=verified_time,
            approved_by=approved_by,
            approved_at=approved_at,
            update_notes='Production simulation: ownership and the latest workflow decision are recorded in the audit trail.',
            sla_deadline=incident_time + timedelta(hours=4),
            issue_type=scenario['type'],
            detailed_issue=scenario['detailed'],
            detailed_issue2=scenario['detail2'],
            created_by=t1,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=opened, updated_at=last_time)
        ticket.refresh_from_db()

        for position, path_status in enumerate(path):
            author = self._author_for_status(path, position, path_status, t1, t2, admin, manager, requires_manager)
            note = self._generic_log_note(path_status, scenario, t1, t2, admin, owner, is_event)
            self._create_log(ticket, path_status, author, note, event_times[position])

        if classification == Ticket.CLASSIFICATION_INCIDENT and has_admin:
            self._create_generic_subtasks(ticket, index, t1, admin, last_time)
        return ticket

    @staticmethod
    def _status_path(status, classification, escalated, requires_manager):
        if status == Ticket.STATUS_NEW:
            return [Ticket.STATUS_NEW]
        path = [Ticket.STATUS_NEW]
        if escalated:
            path.append(Ticket.STATUS_ESCALATED_T2)
            if status == Ticket.STATUS_ESCALATED_T2:
                return path
            if classification == Ticket.CLASSIFICATION_EVENT:
                path.append(Ticket.STATUS_CLOSED_EVENT)
                return path
            path.append(Ticket.STATUS_T1_REVIEW)
            if status == Ticket.STATUS_T1_REVIEW:
                return path
        elif classification == Ticket.CLASSIFICATION_EVENT:
            path.append(Ticket.STATUS_CLOSED_EVENT)
            return path

        path.append(Ticket.STATUS_AWAITING_CONTAINMENT)
        if status == Ticket.STATUS_AWAITING_CONTAINMENT:
            return path
        path.append(Ticket.STATUS_CONTAINMENT_REPORTED)
        if status == Ticket.STATUS_CONTAINMENT_REPORTED:
            return path
        if status == Ticket.STATUS_PENDING_MANAGER:
            path.append(Ticket.STATUS_PENDING_MANAGER)
            return path
        if status == Ticket.STATUS_APPROVED:
            if requires_manager:
                path.append(Ticket.STATUS_PENDING_MANAGER)
            path.append(Ticket.STATUS_APPROVED)
        return path

    @staticmethod
    def _author_for_status(path, position, status, t1, t2, admin, manager, requires_manager):
        if position == 0 or status in (
            Ticket.STATUS_ESCALATED_T2,
            Ticket.STATUS_AWAITING_CONTAINMENT,
            Ticket.STATUS_PENDING_MANAGER,
        ):
            return t1
        if status == Ticket.STATUS_T1_REVIEW:
            return t2
        if status == Ticket.STATUS_CONTAINMENT_REPORTED:
            return admin
        if status == Ticket.STATUS_CLOSED_EVENT:
            return t2 if Ticket.STATUS_ESCALATED_T2 in path else t1
        if status == Ticket.STATUS_APPROVED:
            return manager if requires_manager else t1
        return t1

    @staticmethod
    def _generic_log_note(status, scenario, t1, t2, admin, owner, is_event):
        notes = {
            Ticket.STATUS_NEW: (
                f"{t1.get_full_name()} opened the case after validating the source alert. "
                f"Recorded affected service, initial IoCs, business owner ({owner.get_full_name()}), severity, and response expectations."
            ),
            Ticket.STATUS_ESCALATED_T2: (
                'Tier 1 requested a second opinion because the activity required deeper correlation. '
                'Evidence package included the alert timeline, host context, IoCs, and initial scope.'
            ),
            Ticket.STATUS_T1_REVIEW: (
                f"{t2.get_full_name()} completed Tier 2 review, confirmed Incident classification, "
                'and returned the ticket with correlation findings and recommended containment scope.'
            ),
            Ticket.STATUS_AWAITING_CONTAINMENT: (
                f"Assigned to {admin.get_full_name()} for investigation and containment. "
                'Tier 1 documented required actions, evidence-preservation precautions, and owner coordination.'
            ),
            Ticket.STATUS_CONTAINMENT_REPORTED: (
                f"{admin.get_full_name()} submitted investigation findings and countermeasures. "
                'Indicators were scoped, controls updated, and validation evidence returned to Tier 1.'
            ),
            Ticket.STATUS_PENDING_MANAGER: (
                'Tier 1 verified the countermeasures against fresh telemetry and routed the Critical/Emergency '
                'case to the SOC Manager with sign-off evidence.'
            ),
            Ticket.STATUS_APPROVED: (
                'Final verification completed. Evidence, containment effectiveness, system-owner confirmation, '
                'and follow-up ownership were reviewed before closure.'
            ),
            Ticket.STATUS_CLOSED_EVENT: (
                f"Activity classified as Event and closed. {scenario['summary']}; available evidence showed "
                'authorized or unsuccessful activity with no containment requirement.'
            ),
        }
        return notes[status]

    @staticmethod
    def _create_log(ticket, status, author, note, created_at):
        log = TicketLog.objects.create(
            ticket=ticket,
            note=note,
            status_at_time=status,
            author=author,
        )
        TicketLog.objects.filter(pk=log.pk).update(created_at=created_at, updated_at=created_at)
        return log

    def _create_generic_subtasks(self, ticket, index, t1, admin, last_time):
        specs = [
            (TicketSubtask.TYPE_INVESTIGATION, 'Collect and correlate supporting logs'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'Apply containment controls and validate'),
        ]
        for offset, (kind, title) in enumerate(specs):
            if offset == 1 and index % 2:
                continue
            if ticket.status == Ticket.STATUS_APPROVED:
                sub_status = TicketSubtask.STATUS_DONE
                result = 'Completed and validated; evidence is recorded in the parent ticket.'
            elif ticket.status == Ticket.STATUS_CONTAINMENT_REPORTED:
                sub_status = TicketSubtask.STATUS_DONE if offset == 0 else TicketSubtask.STATUS_IN_PROGRESS
                result = 'Evidence collected and initial scope documented.' if offset == 0 else ''
            else:
                sub_status = TicketSubtask.STATUS_IN_PROGRESS if offset == 0 else TicketSubtask.STATUS_OPEN
                result = ''
            subtask = TicketSubtask.objects.create(
                ticket=ticket,
                subtask_type=kind,
                title=title,
                description=(
                    'Track this work separately so the analyst, administrator, and system owner can '
                    'see the responsible person and current result without losing the main case timeline.'
                ),
                status=sub_status,
                assigned_to=admin,
                result_notes=result,
                created_by=t1,
            )
            created = ticket.created_at + timedelta(hours=offset + 2)
            TicketSubtask.objects.filter(pk=subtask.pk).update(
                created_at=created,
                updated_at=max(created, last_time - timedelta(minutes=30)),
            )

    def _create_wazuh_alerts(self, users, tickets):
        t1_users = [users[name] for name in (
            'demo.t1.somchai', 'demo.t1.narisa', 'demo.t1.kittipong', 'demo.t1.waranya',
        )]
        status_plan = (
            [WazuhAlert.TRIAGE_PENDING] * 10
            + [WazuhAlert.TRIAGE_TRIAGING] * 6
            + [WazuhAlert.TRIAGE_TRUE_POSITIVE] * 12
            + [WazuhAlert.TRIAGE_FALSE_POSITIVE] * 8
        )
        linkable = [ticket for ticket in tickets if ticket.is_incident]
        link_index = 0
        alerts = []
        for index, triage_status in enumerate(status_plan, start=1):
            analyst = t1_users[index % len(t1_users)]
            timestamp = self.now - timedelta(days=(index * 5) % 21, hours=index % 11)
            is_claimed = triage_status == WazuhAlert.TRIAGE_TRIAGING
            is_triaged = triage_status in (
                WazuhAlert.TRIAGE_TRUE_POSITIVE,
                WazuhAlert.TRIAGE_FALSE_POSITIVE,
            )
            alert = WazuhAlert.objects.create(
                opensearch_id=f'{self.WAZUH_PREFIX}{index:03d}',
                alert_id=f'production.demo.{index:04d}',
                timestamp=timestamp,
                agent_id=f'{index:03d}',
                agent_name=f'DEMO-PROD-ENDPOINT-{index:02d}',
                agent_ip=f'10.60.{index // 20}.{20 + index}',
                rule_id=str(5700 + index),
                rule_level=[10, 11, 12, 13, 14, 15][index % 6],
                rule_description=self.SCENARIOS[index % len(self.SCENARIOS)]['summary'],
                rule_groups=['production-demo', 'endpoint', 'soc-monitoring'],
                mitre_techniques=['T1059.001'] if index % 2 else ['T1078'],
                mitre_tactics=['Execution'] if index % 2 else ['Initial Access'],
                mitre_ids=['T1059.001'] if index % 2 else ['T1078'],
                raw_data={
                    'source': 'three-week production simulation',
                    'correlation_id': f'DEMO-CORR-{index:04d}',
                    'event_count': 12 + index * 3,
                },
                decoder_name='json',
                triage_status=triage_status,
                triaged_by=analyst if is_triaged else None,
                triaged_at=timestamp + timedelta(minutes=18 + index) if is_triaged else None,
                triage_note=(
                    'Reviewed against host and network context; linked to the corresponding case.'
                    if is_triaged else ''
                ),
                incident_category=(
                    WazuhAlert.CATEGORY_MALWARE if is_triaged else None
                ),
                claimed_by=analyst if is_claimed else None,
                claimed_at=timestamp + timedelta(minutes=8) if is_claimed else None,
            )
            ingested_at = timestamp + timedelta(minutes=2)
            WazuhAlert.objects.filter(pk=alert.pk).update(ingested_at=ingested_at)
            if triage_status == WazuhAlert.TRIAGE_TRUE_POSITIVE and link_index < len(linkable):
                ticket = linkable[link_index]
                if ticket.wazuh_alert_id is None:
                    # Stamp analyst response time exactly as the live
                    # create_ticket path does. In production the ticket is
                    # raised at the triage moment, so the faithful value is
                    # triaged_at - ingested_at. We deliberately do NOT use the
                    # ticket's created_at: the demo pairs alerts and tickets
                    # without aligning their timelines, so created_at -
                    # ingested_at would be meaningless (often negative).
                    Ticket.objects.filter(pk=ticket.pk).update(
                        wazuh_alert=alert,
                        alert_conversion_duration=alert.triaged_at - ingested_at,
                    )
                    ticket.wazuh_alert_id = alert.pk
                link_index += 1
            alerts.append(alert)
        return alerts

    def _create_manual_triage(self, users, tickets):
        t1_users = [users[name] for name in (
            'demo.t1.somchai', 'demo.t1.narisa', 'demo.t1.kittipong', 'demo.t1.waranya',
        )]
        sources = [
            TriageRecord.SOURCE_EMAIL,
            TriageRecord.SOURCE_PHONE,
            TriageRecord.SOURCE_USER_REPORT,
            TriageRecord.SOURCE_EXTERNAL,
        ]
        incident_tickets = [ticket for ticket in tickets if ticket.is_incident][12:18]
        records = []
        for index in range(1, 19):
            analyst = t1_users[index % len(t1_users)]
            created = self.now - timedelta(days=(index * 4) % 21, hours=index % 8)
            if index <= 6:
                decision = ''
                claimed_by = analyst if index % 2 == 0 else None
                ticket = None
            elif index <= 12:
                decision = TriageRecord.DECISION_FP
                claimed_by = None
                ticket = None
            else:
                decision = TriageRecord.DECISION_TP
                claimed_by = None
                ticket = incident_tickets[index - 13] if index - 13 < len(incident_tickets) else None
            record = TriageRecord.objects.create(
                source=sources[index % len(sources)],
                source_reference=f'{self.DEMO_PREFIX}MANUAL-{index:03d}',
                analyst=analyst,
                alert_description=(
                    f'Manual report #{index:02d}: user or external party reported suspicious '
                    'authentication, email, endpoint, or network activity for SOC review.'
                ),
                source_ip=f'198.51.100.{30 + index}',
                decision=decision,
                notes=(
                    'Intake details validated with the reporter; evidence and contact information recorded.'
                    if decision else 'Awaiting Tier 1 claim and initial evidence review.'
                ),
                claimed_by=claimed_by,
                claimed_at=created + timedelta(minutes=12) if claimed_by else None,
                ticket=ticket,
            )
            TriageRecord.objects.filter(pk=record.pk).update(created_at=created)
            records.append(record)
        return records
