from collections import Counter
from datetime import datetime, time, timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.incidents.management import seed_actors
from apps.incidents.models import (
    Ticket,
    TicketAttachment,
    TicketLog,
    TicketSubtask,
    TriageRecord,
)
from apps.wazuh_ingest.models import WazuhAlert


class Command(BaseCommand):
    help = 'Reset and seed a realistic 30-day dashboard mockup dataset.'

    REFERENCE_PREFIX = 'MOCK-SOC-'

    ACTIVE_STATUS_PLAN = (
        [Ticket.STATUS_NEW] * 2
        + [Ticket.STATUS_ESCALATED_T2] * 3
        + [Ticket.STATUS_T1_REVIEW] * 3
        + [Ticket.STATUS_AWAITING_CONTAINMENT] * 4
        + [Ticket.STATUS_CONTAINMENT_REPORTED] * 3
        + [Ticket.STATUS_PENDING_MANAGER] * 3
    )

    SEVERITY_PLAN = (
        ['Critical'] * 6
        + ['High'] * 6
        + ['Critical'] * 5
        + ['High'] * 4
        + ['Medium'] * 2
        + ['Low']
    )

    SCENARIOS = [
        {
            'device': 'FIN-ERP-APP-{n:02d}',
            'summary': 'Suspicious service-account use followed by bulk invoice export',
            'detailed': 'User Intrusion',
            'detail2': 'Data Exfiltration',
            'source': 'SIEM',
            'phase': 'Exfiltration',
            'asset_type': 'Server',
            'destination': '203.0.113.54',
            'ioc': [
                'Account svc_finance_etl queried 48,200 invoice rows outside the approved window.',
                'Outbound TLS session to 203.0.113.54 transferred 710 MB in 9 minutes.',
                'Database audit: SELECT on vendor_bank_account and payment_batch tables.',
            ],
            'action': [
                'Disable the service account, revoke active sessions, and rotate vault secrets.',
                'Confirm export scope with Finance Operations and preserve database audit logs.',
                'Block destination infrastructure at proxy, DNS, and firewall controls.',
            ],
            'containment': [
                'Service account disabled and all dependent credentials rotated.',
                'Proxy/firewall blocks deployed and validated against fresh flow logs.',
                'Finance owner confirmed no payment record modification after reconciliation.',
            ],
        },
        {
            'device': 'HR-LAPTOP-{n:02d}',
            'summary': 'Encoded PowerShell launched from a payroll-themed attachment',
            'detailed': 'Malicious Logic',
            'detail2': 'Suspicious PowerShell',
            'source': 'SIEM',
            'phase': 'Execution',
            'asset_type': 'Computer',
            'destination': '198.51.100.44',
            'ioc': [
                'Parent process WINWORD.EXE spawned powershell.exe -enc with hidden window.',
                'SHA256 8e9b1f7d9c1a4f2b86c1f2d9179d03b49a7b1ad2c0ff9a4c4c6fd31e6b700a12.',
                'EDR telemetry shows download cradle to 198.51.100.44 over HTTPS.',
            ],
            'action': [
                'Isolate the endpoint, collect memory and PowerShell operational logs.',
                'Search for matching hash, command line, and parent process across endpoints.',
                'Reset the affected user password after confirming token revocation.',
            ],
            'containment': [
                'Endpoint isolated, malicious script block hash blocked in EDR.',
                'User password reset and refresh tokens revoked.',
                'Enterprise hunt found no other hosts with the encoded command line.',
            ],
        },
        {
            'device': 'CRM-PORTAL-{n:02d}',
            'summary': 'Impossible travel sign-in against a privileged CRM account',
            'detailed': 'User Intrusion',
            'detail2': 'Impossible Travel',
            'source': 'SIEM',
            'phase': 'Initial Access',
            'asset_type': 'Server',
            'destination': '198.51.100.91',
            'ioc': [
                'Successful sign-ins from Bangkok and Frankfurt separated by 14 minutes.',
                'User agent changed from managed Edge profile to unknown Chromium build.',
                'Conditional access reported unfamiliar ASN and no compliant device claim.',
            ],
            'action': [
                'Revoke sessions, require MFA re-registration, and review CRM audit export.',
                'Validate whether the CRM account accessed customer records or admin screens.',
                'Check identity logs for password-spray or token replay around the same period.',
            ],
            'containment': [
                'Sessions revoked and MFA reset under helpdesk identity proofing.',
                'CRM audit reviewed; no admin action or bulk export after the suspicious login.',
                'Identity team added temporary geo-risk rule for the affected account group.',
            ],
        },
        {
            'device': 'EDGE-FW-{n:02d}',
            'summary': 'Sustained internet scan against exposed administration endpoints',
            'detailed': 'Reconnaissance',
            'detail2': 'Admin Panel Attempt',
            'source': 'TI',
            'phase': 'Reconnaissance',
            'asset_type': 'Network Device',
            'destination': '192.0.2.80',
            'ioc': [
                '1,840 requests across /admin, /backup, /.env, and /wp-login.php paths.',
                'Source IPs rotate through an ASN tagged as mass scanning infrastructure.',
                'WAF blocked 97 percent of requests; no authenticated session observed.',
            ],
            'action': [
                'Confirm WAF and firewall rules blocked all administrative probes.',
                'Review access logs for successful authentication or sensitive file response.',
                'Add offending IP range to temporary block list if business impact is nil.',
            ],
            'containment': [
                'WAF logs confirmed only 403/404 responses and no sensitive content exposure.',
                'Temporary block deployed for the scanning range and monitored for recurrence.',
                'External attack surface review confirmed admin paths remain restricted.',
            ],
        },
        {
            'device': 'BACKUP-SERVER-{n:02d}',
            'summary': 'Ransomware-like file rename activity on backup staging volume',
            'detailed': 'Malicious Logic',
            'detail2': 'Ransomware Behavior',
            'source': 'SIEM',
            'phase': 'Impact',
            'asset_type': 'Server',
            'destination': '203.0.113.77',
            'ioc': [
                'Rapid rename pattern added .locked-test extension to 620 files.',
                'Process tree shows unsigned updater_tmp.exe launched by compromised admin shell.',
                'No encryption completed; backup snapshot retained clean restore point.',
            ],
            'action': [
                'Isolate backup staging host and preserve process, file, and EDR telemetry.',
                'Disable the admin account, rotate privileged credentials, and validate backups.',
                'Hunt for updater_tmp.exe and extension pattern across server estate.',
            ],
            'containment': [
                'Host isolated and malicious binary quarantined after forensic copy.',
                'Privileged account disabled; all linked credentials rotated.',
                'Backup restore test succeeded and no production share encryption observed.',
            ],
        },
        {
            'device': 'PAYMENT-API-{n:02d}',
            'summary': 'External report of object authorization weakness in payment API',
            'detailed': 'Vulnerability',
            'detail2': 'Vulnerability Found',
            'source': 'EXTERNAL',
            'phase': 'Initial Access',
            'asset_type': 'Server',
            'destination': '203.0.113.120',
            'ioc': [
                'Reporter demonstrated invoice lookup by changing a numeric object identifier.',
                'Access logs show 11 suspicious invoice-detail requests from a single IP.',
                'No write operation or payment instruction change observed.',
            ],
            'action': [
                'Disable vulnerable endpoint path or enforce object ownership checks immediately.',
                'Review payment API access logs for unauthorized invoice reads.',
                'Coordinate disclosure response and patch validation with application owner.',
            ],
            'containment': [
                'API gateway rule restricted affected path until application fix was deployed.',
                'Object ownership check patched and validated in production smoke test.',
                'Log review found limited read exposure; Privacy and Legal notified.',
            ],
        },
        {
            'device': 'VPN-GATEWAY-{n:02d}',
            'summary': 'Password-spray pattern followed by successful VPN authentication',
            'detailed': 'User Intrusion',
            'detail2': 'Brute Force',
            'source': 'SIEM',
            'phase': 'Credential Access',
            'asset_type': 'Network Device',
            'destination': '198.51.100.12',
            'ioc': [
                '243 failed logins across 81 accounts, then success for contractor.ops.',
                'Source address matches residential proxy range seen in prior credential attacks.',
                'VPN session attempted access to finance file share before disconnect.',
            ],
            'action': [
                'Terminate VPN session, reset affected account, and verify MFA status.',
                'Block source IP and query identity logs for adjacent successful logins.',
                'Check file share audit trail for read/write activity during the VPN session.',
            ],
            'containment': [
                'VPN session terminated and contractor account forced through password reset.',
                'MFA token rotated and source IP blocked at VPN gateway.',
                'File share audit showed directory listing only; no file read or write.',
            ],
        },
        {
            'device': 'DNS-RESOLVER-{n:02d}',
            'summary': 'Threat-intel match for command-and-control domain lookup',
            'detailed': 'Investigating',
            'detail2': 'TI Malicious IP',
            'source': 'TI',
            'phase': 'Command and Control',
            'asset_type': 'Server',
            'destination': '203.0.113.88',
            'ioc': [
                'Internal host requested sync-update.example.invalid every 60 seconds.',
                'Domain was newly tagged high-confidence C2 by threat intelligence feed.',
                'No successful HTTP session observed after DNS sinkhole response.',
            ],
            'action': [
                'Identify requesting host, isolate if endpoint telemetry shows malicious process.',
                'Block domain and related IP indicators at DNS, proxy, and firewall layers.',
                'Hunt for beacon interval and domain pattern across DNS logs.',
            ],
            'containment': [
                'DNS sinkhole and proxy block confirmed; no outbound connection established.',
                'Requesting host scanned clean; scheduled browser extension update caused lookup.',
                'Indicator hunt completed with no additional host matches.',
            ],
        },
        {
            'device': 'ENDPOINT-FIN-{n:02d}',
            'summary': 'EDR malware alert for credential dumping tool blocked on execution',
            'detailed': 'Malicious Logic',
            'detail2': 'Malware EDR',
            'source': 'SIEM',
            'phase': 'Credential Access',
            'asset_type': 'Computer',
            'destination': '203.0.113.61',
            'ioc': [
                'EDR blocked process with LSASS memory access attempt.',
                'SHA256 4fc4a3e8d7df9a83e8267be9f3204f2f322ae710d9ed9c82d21f0aab849d441b.',
                'User downloaded archive from newly registered file-sharing domain.',
            ],
            'action': [
                'Isolate endpoint, collect suspicious archive, and review browser download history.',
                'Reset user credentials and validate no privileged token was exposed.',
                'Search for hash and archive name across endpoint telemetry.',
            ],
            'containment': [
                'EDR quarantine confirmed before credential access completed.',
                'User credentials reset and browser profile cleaned.',
                'Hash hunt returned no second host and endpoint released after full scan.',
            ],
        },
        {
            'device': 'CLOUD-IAM-{n:02d}',
            'summary': 'New privileged cloud key created outside change window',
            'detailed': 'Root Intrusion',
            'detail2': 'Privilege Escalation',
            'source': 'ADMIN',
            'phase': 'Privilege Escalation',
            'asset_type': 'Server',
            'destination': '192.0.2.150',
            'ioc': [
                'Access key created for cloud-admin-breakglass without approved change ticket.',
                'API calls enumerated S3 buckets and IAM policies within six minutes.',
                'Source IP does not match corporate VPN or automation runner ranges.',
            ],
            'action': [
                'Disable the new key, rotate breakglass credential, and review CloudTrail events.',
                'Validate no storage object was read or policy was modified.',
                'Confirm whether activity maps to emergency maintenance or compromise.',
            ],
            'containment': [
                'Unauthorized key disabled and breakglass password/key material rotated.',
                'CloudTrail review found enumeration only; no policy or bucket modification.',
                'Privileged-access workflow updated with additional alerting on key creation.',
            ],
        },
    ]

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete this command\'s previous mockup rows before seeding.',
        )
        parser.add_argument(
            '--apply',
            action='store_true',
            help='Persist the reset and mockup seed. Without this, only print the plan.',
        )

    def handle(self, *args, **options):
        self.now = timezone.now().replace(second=0, microsecond=0)
        self.tz = timezone.get_current_timezone()
        self.ticket_sequences = {}
        plan = self._build_plan()

        # Resolve the real role-holders up front so a dry run also reports who
        # the data would be attributed to (and fails early on a missing role).
        users = seed_actors.resolve()
        seed_actors.require(users, 'T1', 'T2', 'MANAGER', 'ADMIN')

        if not options['apply']:
            self._print_plan(plan, users, mode='DRY RUN')
            self.stdout.write('No database changes written. Re-run with --reset --apply to persist.')
            return
        if not options['reset']:
            raise CommandError('This seed mutates existing data. Use --reset --apply.')

        with transaction.atomic():
            self._clear_existing_data()
            tickets = []
            alerts = []
            triage_records = []
            for spec in plan:
                ticket, alert, triage = self._create_ticket(spec, users)
                tickets.append(ticket)
                if alert:
                    alerts.append(alert)
                if triage:
                    triage_records.append(triage)

        self._print_plan(plan, users, mode='APPLY')
        self.stdout.write(self.style.SUCCESS('Dashboard mockup dataset is ready.'))
        self.stdout.write(
            str({
                'tickets': len(tickets),
                'active': sum(t.status not in Ticket.TERMINAL_STATUSES for t in tickets),
                'closed': sum(t.status in Ticket.TERMINAL_STATUSES for t in tickets),
                'users_created': 0,
                'wazuh_alerts': len(alerts),
                'manual_triage_records': len(triage_records),
            })
        )
        self.stdout.write(
            'No user accounts were created or modified - testers sign in with '
            'their own credentials.'
        )

    def _print_plan(self, plan, users, mode):
        status_counts = Counter(spec['status'] for spec in plan)
        severity_counts = Counter(spec['severity'] for spec in plan)
        daily_counts = Counter(spec['opened'].date() for spec in plan)
        active_count = sum(
            spec['status'] not in Ticket.TERMINAL_STATUSES for spec in plan)
        self.stdout.write(f'Dashboard mockup seed ({mode})')
        self.stdout.write(f'Days: {len(daily_counts)}')
        self.stdout.write(f'Tickets: {len(plan)} ({active_count} active)')
        self.stdout.write(
            f'Daily range: {min(daily_counts.values())}-{max(daily_counts.values())}')
        self.stdout.write(f'Status distribution: {dict(status_counts)}')
        self.stdout.write(f'Severity distribution: {dict(severity_counts)}')
        self.stdout.write('Attributing to existing accounts (discovered by role):')
        self.stdout.write(seed_actors.summary(users, ['T1', 'T2', 'MANAGER', 'ADMIN']))

    def _clear_existing_data(self):
        """Remove only the rows THIS command created.

        It used to delete every ticket and then every non-superuser account —
        which on a shared box (UAT runs entirely on real staff logins) wiped
        real users and real tester data. Scope is now the MOCK-SOC- reference
        prefix, and user accounts are never touched by any seeder.
        """
        mine = Ticket.objects.filter(
            reference_id__startswith=self.REFERENCE_PREFIX)
        # Alerts carry no prefix of their own, so reach them through the tickets
        # that own them before those rows disappear (wazuh_alert is SET_NULL, so
        # deleting tickets first would strand them).
        alert_ids = list(
            mine.exclude(wazuh_alert__isnull=True)
            .values_list('wazuh_alert_id', flat=True)
        )
        TicketAttachment.objects.filter(ticket__in=mine).delete()
        TicketSubtask.objects.filter(ticket__in=mine).delete()
        TicketLog.objects.filter(ticket__in=mine).delete()
        TriageRecord.objects.filter(
            source_reference__startswith=self.REFERENCE_PREFIX).delete()
        mine.delete()
        WazuhAlert.objects.filter(pk__in=alert_ids).delete()
        # IngestWatermark is global ingest state, not this command's row — the
        # old version wiped it, which reset unrelated Wazuh ingestion.

    def _build_plan(self):
        today = timezone.localtime(self.now).date()
        start = today - timedelta(days=29)
        slots = []
        for day_offset in range(30):
            day = start + timedelta(days=day_offset)
            count = self._daily_count(day)
            for sequence in range(count):
                slots.append({
                    'day': day,
                    'opened': self._opened_at(day, sequence, count),
                    'sequence': sequence,
                })

        active_start = len(slots) - len(self.ACTIVE_STATUS_PLAN)
        plan = []
        for index, slot in enumerate(slots):
            scenario = self.SCENARIOS[index % len(self.SCENARIOS)]
            active_position = index - active_start
            if active_position >= 0:
                status = self.ACTIVE_STATUS_PLAN[active_position]
                is_active = True
            else:
                status = (
                    Ticket.STATUS_CLOSED_EVENT
                    if index % 5 == 0 else Ticket.STATUS_APPROVED
                )
                is_active = False
            severity = self._severity_for(index, status)
            classification = (
                Ticket.CLASSIFICATION_EVENT
                if status == Ticket.STATUS_CLOSED_EVENT else Ticket.CLASSIFICATION_INCIDENT
            )
            plan.append({
                **slot,
                'index': index + 1,
                'scenario': scenario,
                'status': status,
                'severity': severity,
                'classification': classification,
                'active': is_active,
            })
        return plan

    @staticmethod
    def _daily_count(day):
        if day.weekday() == 5:
            return 3
        if day.weekday() == 6:
            return 4
        return [6, 7, 8, 6, 7][day.weekday()]

    def _opened_at(self, day, sequence, count):
        hour = 8 + int(sequence * 8 / max(count, 1))
        minute = (17 + sequence * 11) % 60
        opened = timezone.make_aware(
            datetime.combine(day, time(hour, minute)), self.tz)
        latest_allowed = self.now - timedelta(minutes=15 + sequence * 7)
        if opened > latest_allowed:
            opened = latest_allowed
        return opened.replace(second=0, microsecond=0)

    def _severity_for(self, index, status):
        if status == Ticket.STATUS_PENDING_MANAGER:
            return 'Critical'
        return self.SEVERITY_PLAN[index % len(self.SEVERITY_PLAN)]

    def _create_ticket(self, spec, users):
        scenario = spec['scenario']
        opened = spec['opened']
        severity = spec['severity']
        status = spec['status']
        classification = spec['classification']
        t1 = self._pick_user(users, 'T1', spec['index'])
        t2 = self._pick_user(users, 'T2', spec['index'])
        manager = seed_actors.first(users, 'MANAGER')
        admin = seed_actors.first(users, 'ADMIN')
        current_owner = self._current_owner(status, t1, t2)
        incident_time = opened - self._triage_delay(severity, spec['index'])
        terminal_time = self._terminal_time(opened, severity, status, spec['index'])
        ola_deadline = self._ola_deadline(spec, incident_time, opened, terminal_time)
        path = self._status_path(status, classification, severity)
        timeline = self._timeline(opened, terminal_time, path, spec['active'])
        source_ref = f'{self.REFERENCE_PREFIX}{spec["index"]:04d}'

        alert = None
        triage = None
        if scenario['source'] == 'SIEM':
            alert = self._create_wazuh_alert(spec, scenario, incident_time, opened, t1)

        ticket = Ticket.objects.create(
            ticket_id=self._next_ticket_id(opened),
            severity=severity,
            incident_datetime=incident_time,
            reference_id=source_ref,
            device_name=scenario['device'].format(n=spec['index']),
            issue_description=self._issue_description(spec),
            ip_address=self._asset_ip(spec['index']),
            mac_address=self._mac(spec['index']),
            asset_type=scenario['asset_type'],
            spread_to_others=severity == 'Critical' or spec['index'] % 7 == 0,
            destination_ip=scenario['destination'],
            ioc_details='\n'.join(f'- {line}' for line in scenario['ioc']),
            mitre_phase=scenario['phase'],
            action_required='\n'.join(f'{i + 1}. {line}' for i, line in enumerate(scenario['action'])),
            action_precautions=self._precautions(spec),
            remediation_summary=self._remediation_summary(spec),
            containment_report=self._containment_report(spec),
            status=status,
            classification=classification,
            escalated_to_t2_at=timeline.get(Ticket.STATUS_ESCALATED_T2),
            # PENDING_MANAGER is reachable only via the emergency flag now.
            is_emergency=(severity == 'Critical' and spec['index'] % 9 == 0)
                         or status == Ticket.STATUS_PENDING_MANAGER,
            assigned_to=current_owner,
            assigned_admin=admin if self._has_admin(status, classification) else None,
            verified_by=t2 if timeline.get(Ticket.STATUS_PENDING_MANAGER) or (
                status == Ticket.STATUS_APPROVED and classification == Ticket.CLASSIFICATION_INCIDENT
            ) else None,
            verified_at=self._verified_at(timeline, status, classification),
            approved_by=self._approved_by(status, severity, manager, t2, spec['index']),
            approved_at=terminal_time if status == Ticket.STATUS_APPROVED else None,
            update_notes=self._update_notes(spec),
            ola_contain_deadline=ola_deadline,
            issue_type=scenario['source'],
            detailed_issue=scenario['detailed'],
            detailed_issue2=scenario['detail2'],
            created_by=t1,
            wazuh_alert=alert,
            alert_conversion_duration=(opened - (incident_time + timedelta(minutes=2))) if alert else None,
        )
        latest_status_time = max(timeline.values()) if timeline else opened
        Ticket.objects.filter(pk=ticket.pk).update(
            created_at=opened,
            updated_at=latest_status_time,
            status_changed_at=latest_status_time,
        )
        ticket.refresh_from_db()

        self._create_logs(ticket, spec, path, timeline, t1, t2, admin, manager)
        self._create_subtasks(ticket, spec, t1, admin, timeline)

        if scenario['source'] != 'SIEM':
            triage = self._create_triage_record(spec, scenario, opened, incident_time, t1, t2, ticket)

        return ticket, alert, triage

    @staticmethod
    def _pick_user(users, key, index):
        """Round-robin a real role-holder so authorship spreads across the team."""
        pool = users[key]
        return pool[index % len(pool)]

    @staticmethod
    def _current_owner(status, t1, t2):
        if status == Ticket.STATUS_ESCALATED_T2:
            return t2
        return t1

    @staticmethod
    def _triage_delay(severity, index):
        if severity == 'Critical':
            return timedelta(minutes=8 + (index % 18))
        if severity == 'High':
            return timedelta(minutes=24 + (index % 30))
        if severity == 'Medium':
            return timedelta(minutes=45 + (index % 40))
        return timedelta(minutes=65 + (index % 45))

    @staticmethod
    def _terminal_time(opened, severity, status, index):
        if status not in Ticket.TERMINAL_STATUSES:
            return None
        if status == Ticket.STATUS_CLOSED_EVENT:
            return opened + timedelta(minutes=45 + (index % 65))
        if severity == 'Critical':
            return opened + timedelta(hours=2, minutes=15 + (index % 65))
        if severity == 'High':
            return opened + timedelta(hours=5 + (index % 5), minutes=15)
        if severity == 'Medium':
            return opened + timedelta(hours=9 + (index % 6), minutes=20)
        return opened + timedelta(hours=14 + (index % 5), minutes=30)

    def _ola_deadline(self, spec, incident_time, opened, terminal_time):
        if spec['active']:
            offsets = [
                timedelta(minutes=45), timedelta(hours=2), timedelta(hours=3, minutes=20),
                timedelta(hours=6), timedelta(hours=8), timedelta(hours=12),
            ]
            return self.now + offsets[spec['index'] % len(offsets)]
        if spec['severity'] == 'Critical':
            return incident_time + timedelta(hours=4)
        margin = timedelta(hours=2 + (spec['index'] % 5))
        return max(opened + timedelta(hours=8), terminal_time + margin)

    @staticmethod
    def _status_path(status, classification, severity):
        if status == Ticket.STATUS_NEW:
            return [Ticket.STATUS_NEW]
        path = [Ticket.STATUS_NEW]
        escalated = severity in ('Critical', 'High') or status in (
            Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW)
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
            if severity == 'Critical':
                path.append(Ticket.STATUS_PENDING_MANAGER)
            path.append(Ticket.STATUS_APPROVED)
        return path

    def _timeline(self, opened, terminal_time, path, is_active):
        if len(path) == 1:
            return {path[0]: opened}
        if is_active:
            final_time = min(self.now - timedelta(minutes=20), opened + timedelta(hours=8))
        else:
            final_time = terminal_time
        span = max(final_time - opened, timedelta(minutes=10 * len(path)))
        step = span / max(len(path) - 1, 1)
        return {
            status: (opened + step * idx).replace(second=0, microsecond=0)
            for idx, status in enumerate(path)
        }

    def _create_wazuh_alert(self, spec, scenario, incident_time, opened, analyst):
        status = (
            WazuhAlert.TRIAGE_FALSE_POSITIVE
            if spec['classification'] == Ticket.CLASSIFICATION_EVENT
            else WazuhAlert.TRIAGE_TRUE_POSITIVE
        )
        alert = WazuhAlert.objects.create(
            opensearch_id=f'mock-dashboard-alert-{spec["index"]:04d}',
            alert_id=f'mock.rule.{spec["index"]:04d}',
            timestamp=incident_time,
            agent_id=f'{1000 + spec["index"]}',
            agent_name=scenario['device'].format(n=spec['index']),
            agent_ip=self._asset_ip(spec['index']),
            rule_id=str(570000 + spec['index']),
            rule_level={'Critical': 15, 'High': 12, 'Medium': 8, 'Low': 5}[spec['severity']],
            rule_description=scenario['summary'],
            rule_groups=['dashboard-mockup', scenario['detailed'].lower().replace(' ', '-')],
            mitre_techniques=['T1059', 'T1078'] if scenario['phase'] == 'Execution' else ['T1078'],
            mitre_tactics=[scenario['phase']],
            mitre_ids=['T1059', 'T1078'],
            raw_data={
                'mockup': True,
                'reference': f'{self.REFERENCE_PREFIX}{spec["index"]:04d}',
                'ioc_count': len(scenario['ioc']),
            },
            decoder_name='json',
            triage_status=status,
            triaged_by=analyst,
            triaged_at=opened,
            triage_note=(
                'Validated against endpoint, identity, and network telemetry; '
                'ticket opened with evidence package and recommended containment.'
            ),
            incident_category=self._alert_category(scenario),
            claimed_by=analyst,
            claimed_at=incident_time + timedelta(minutes=3),
        )
        WazuhAlert.objects.filter(pk=alert.pk).update(
            ingested_at=incident_time + timedelta(minutes=2))
        return alert

    @staticmethod
    def _alert_category(scenario):
        mapping = {
            'Malicious Logic': WazuhAlert.CATEGORY_MALWARE,
            'User Intrusion': WazuhAlert.CATEGORY_UNAUTHORIZED_ACCESS,
            'Reconnaissance': WazuhAlert.CATEGORY_RECONNAISSANCE,
            'Vulnerability': WazuhAlert.CATEGORY_OTHER,
            'Root Intrusion': WazuhAlert.CATEGORY_UNAUTHORIZED_ACCESS,
            'Investigating': WazuhAlert.CATEGORY_OTHER,
        }
        return mapping.get(scenario['detailed'], WazuhAlert.CATEGORY_OTHER)

    def _create_triage_record(self, spec, scenario, opened, incident_time, t1, t2, ticket):
        decision = (
            TriageRecord.DECISION_FP
            if spec['classification'] == Ticket.CLASSIFICATION_EVENT
            else TriageRecord.DECISION_TP
        )
        record = TriageRecord.objects.create(
            source=scenario['source'],
            source_reference=f'{self.REFERENCE_PREFIX}TRIAGE-{spec["index"]:04d}',
            analyst=t1,
            alert_description=scenario['summary'],
            source_ip=self._source_ip(spec['index']),
            decision=decision,
            notes=(
                'Initial intake validated the report, confirmed affected asset ownership, '
                'and attached the observable evidence to the generated ticket.'
            ),
            claimed_by=t1,
            claimed_at=incident_time + timedelta(minutes=4),
            escalated_to=t2 if spec['severity'] in ('Critical', 'High') else None,
            t2_decision=decision if spec['severity'] in ('Critical', 'High') else '',
            t2_notes=(
                'Tier 2 agreed with the classification and recommended the documented scope.'
                if spec['severity'] in ('Critical', 'High') else ''
            ),
            t2_decided_at=opened - timedelta(minutes=3)
            if spec['severity'] in ('Critical', 'High') else None,
            ticket=ticket,
        )
        TriageRecord.objects.filter(pk=record.pk).update(created_at=incident_time)
        return record

    def _create_logs(self, ticket, spec, path, timeline, t1, t2, admin, manager):
        for position, status in enumerate(path):
            author = self._log_author(status, position, t1, t2, admin, manager)
            note = self._log_note(status, spec, author)
            log = TicketLog.objects.create(
                ticket=ticket,
                note=note,
                status_at_time=status,
                author=author,
            )
            stamp = timeline[status]
            TicketLog.objects.filter(pk=log.pk).update(created_at=stamp, updated_at=stamp)

    @staticmethod
    def _log_author(status, position, t1, t2, admin, manager):
        if position == 0:
            return t1
        if status in (Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_AWAITING_CONTAINMENT,
                      Ticket.STATUS_PENDING_MANAGER):
            return t1
        if status == Ticket.STATUS_T1_REVIEW:
            return t2
        if status == Ticket.STATUS_CONTAINMENT_REPORTED:
            return admin
        if status == Ticket.STATUS_APPROVED:
            return manager
        if status == Ticket.STATUS_CLOSED_EVENT:
            return t2
        return t1

    def _log_note(self, status, spec, author):
        scenario = spec['scenario']
        display = author.get_full_name() or author.username
        notes = {
            Ticket.STATUS_NEW: (
                f'{display} opened the case after correlating source telemetry. '
                f"Summary: {scenario['summary']}. Evidence includes asset, account, "
                'network indicator, severity rationale, and initial business impact.'
            ),
            Ticket.STATUS_ESCALATED_T2: (
                'Tier 1 escalated for deeper validation. Packet/session metadata, '
                'identity context, endpoint process tree, and recommended classification '
                'were included so Tier 2 could make a fast decision.'
            ),
            Ticket.STATUS_T1_REVIEW: (
                'Tier 2 completed review and returned the case to Tier 1. Feedback: '
                'classification is appropriate, scope is limited to the listed asset, '
                'and containment should focus on the documented indicators.'
            ),
            Ticket.STATUS_AWAITING_CONTAINMENT: (
                'Tier 1 assigned containment to System Admin Santi with clear actions: '
                + '; '.join(scenario['action'])
            ),
            Ticket.STATUS_CONTAINMENT_REPORTED: (
                'System Admin Santi submitted containment evidence. Completed work: '
                + '; '.join(scenario['containment'])
            ),
            Ticket.STATUS_PENDING_MANAGER: (
                'Tier 1 verified the returned evidence, confirmed no active recurrence, '
                'and routed the Critical case to SOC Manager Surapong for closure approval.'
            ),
            Ticket.STATUS_APPROVED: (
                'SOC Manager/Tier 1 closure review completed. Evidence, containment, '
                'business validation, and follow-up ownership are sufficient for closure.'
            ),
            Ticket.STATUS_CLOSED_EVENT: (
                'Tier 2 closed this as an Event after review found no confirmed compromise. '
                'Observed activity was blocked, explained, or unsuccessful; no containment required.'
            ),
        }
        return notes[status]

    def _create_subtasks(self, ticket, spec, t1, admin, timeline):
        if spec['classification'] != Ticket.CLASSIFICATION_INCIDENT:
            return
        if spec['status'] in (Ticket.STATUS_NEW, Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW):
            return
        base = timeline.get(Ticket.STATUS_AWAITING_CONTAINMENT, ticket.created_at)
        done = spec['status'] in (
            Ticket.STATUS_CONTAINMENT_REPORTED,
            Ticket.STATUS_PENDING_MANAGER,
            Ticket.STATUS_APPROVED,
        )
        sub_specs = [
            (TicketSubtask.TYPE_INVESTIGATION, 'Validate scope and collect evidence'),
            (TicketSubtask.TYPE_COUNTERMEASURE, 'Apply containment and verify telemetry'),
        ]
        for offset, (kind, title) in enumerate(sub_specs):
            subtask = TicketSubtask.objects.create(
                ticket=ticket,
                subtask_type=kind,
                title=title,
                description=(
                    'Mockup work item tracking the concrete investigation or containment '
                    'activity for this incident. Evidence is summarized in the parent ticket log.'
                ),
                status=TicketSubtask.STATUS_DONE if done else TicketSubtask.STATUS_IN_PROGRESS,
                assigned_to=admin,
                result_notes=(
                    'Completed with timestamped evidence and no unresolved blocker.'
                    if done else 'In progress; latest telemetry is being reviewed.'
                ),
                created_by=t1,
            )
            created = base + timedelta(minutes=8 + offset * 12)
            TicketSubtask.objects.filter(pk=subtask.pk).update(
                created_at=created,
                updated_at=created + timedelta(minutes=20),
            )

    def _issue_description(self, spec):
        scenario = spec['scenario']
        return (
            f"{scenario['summary']} was detected on {scenario['device'].format(n=spec['index'])}. "
            f"The case was classified as {spec['classification']} with {spec['severity']} severity "
            f"because the observable activity touched {scenario['phase']} behavior and had potential "
            'business impact if left uncontained.\n\n'
            'Initial analyst assessment:\n'
            f"- Affected service: {scenario['device'].format(n=spec['index'])}\n"
            f"- Primary threat type: {scenario['detailed']} / {scenario['detail2']}\n"
            f"- Reporting source: {scenario['source']}\n"
            '- Current hypothesis: activity is limited to the listed asset and indicators, '
            'pending verification from endpoint, identity, and network telemetry.'
        )

    def _precautions(self, spec):
        scenario = spec['scenario']
        return (
            'Preserve logs and volatile evidence before disruptive containment. Coordinate with '
            'the service owner if isolation may affect production processing. Avoid deleting '
            f"artifacts tied to {scenario['detail2']} until hashes, timestamps, and screenshots "
            'are captured in the case notes.'
        )

    def _remediation_summary(self, spec):
        if spec['status'] in (Ticket.STATUS_NEW, Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW):
            return ''
        scenario = spec['scenario']
        return (
            f"Investigation focused on {scenario['summary'].lower()}. Analysts reviewed the "
            'alert timeline, identity context, endpoint telemetry, network sessions, and asset '
            'owner input. Scope was documented in the logs, and containment actions were assigned '
            'with validation evidence required before closure.'
        )

    def _containment_report(self, spec):
        if spec['status'] in (
            Ticket.STATUS_NEW,
            Ticket.STATUS_ESCALATED_T2,
            Ticket.STATUS_T1_REVIEW,
            Ticket.STATUS_AWAITING_CONTAINMENT,
        ):
            return ''
        scenario = spec['scenario']
        return 'Containment evidence:\n' + '\n'.join(
            f'- {line}' for line in scenario['containment'])

    @staticmethod
    def _has_admin(status, classification):
        return (
            classification == Ticket.CLASSIFICATION_INCIDENT
            and status not in (Ticket.STATUS_NEW, Ticket.STATUS_ESCALATED_T2, Ticket.STATUS_T1_REVIEW)
        )

    @staticmethod
    def _verified_at(timeline, status, classification):
        if classification != Ticket.CLASSIFICATION_INCIDENT:
            return None
        return timeline.get(Ticket.STATUS_PENDING_MANAGER) or (
            timeline.get(Ticket.STATUS_APPROVED) if status == Ticket.STATUS_APPROVED else None)

    @staticmethod
    def _approved_by(status, severity, manager, t2, index):
        if status != Ticket.STATUS_APPROVED:
            return None
        # Only emergency tickets carry the manager's final sign-off; Tier 2
        # closes everything else. Mirror the is_emergency seeding rule.
        was_emergency = severity == 'Critical' and index % 9 == 0
        return manager if was_emergency else t2

    @staticmethod
    def _update_notes(spec):
        if spec['active']:
            return 'Mockup active case: work is in progress and still within OLA.'
        if spec['status'] == Ticket.STATUS_CLOSED_EVENT:
            return 'Mockup event closure: reviewed and closed without containment.'
        return 'Mockup incident closure: containment verified and case closed within target.'

    @staticmethod
    def _asset_ip(index):
        return f'10.{20 + index % 20}.{1 + (index // 40)}.{20 + index % 200}'

    @staticmethod
    def _source_ip(index):
        return f'198.51.100.{10 + index % 180}'

    @staticmethod
    def _mac(index):
        return (
            f'02:42:{index % 255:02X}:{(index * 3) % 255:02X}:'
            f'{(index * 7) % 255:02X}:{(index * 11) % 255:02X}'
        )

    def _next_ticket_id(self, opened):
        prefix = Ticket.ticket_id_prefix(opened)
        self.ticket_sequences[prefix] = self.ticket_sequences.get(prefix, 0) + 1
        return f'{prefix}{self.ticket_sequences[prefix]:04d}'
