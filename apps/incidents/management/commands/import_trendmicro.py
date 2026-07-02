"""
Import historical SOC cases from the TrendMicro Workbench tracker CSV
(the reviewed/categorized export of the team's Google Sheet).

Usage:
    manage.py import_trendmicro <csv_path> [--dry-run] [--create-missing-users]

Behaviour and mapping decisions:
  - One Ticket per TrendMicro incident ID (รหัส Incident). Rows sharing an
    incident ID are merged: the most complete row becomes the Ticket, the
    rest are preserved verbatim as TicketLog entries.
  - reference_id carries the TrendMicro incident ID — this both marks the
    ticket as imported and makes re-runs idempotent (existing IDs are
    skipped).
  - Timestamps: Created Date → incident_datetime (and backdates created_at),
    วันที่รับเคส → acknowledged_at, Thai-calendar report ref (ปปกก... ลว.) →
    report_issued_at, *หยุดการเคลื่อนไหว in หมายเหตุ → closed_at. Missing
    close times stay NULL — "not captured" is reported, never invented.
  - Validation TP/FP → classification INCIDENT/EVENT. Sheet status maps to
    the workflow: เสร็จเรียบร้อย → APPROVED (Incident) / CLOSED_EVENT
    (Event); ส่งรายงาน → AWAITING_CONTAINMENT; everything else → NEW.
  - ip_address is unknown for tracker cases and stays NULL (field allows it
    as of migration 0031).
"""
import csv
import re
from datetime import datetime

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketLog

THAI_MONTHS = {
    'ม.ค': 1, 'ก.พ': 2, 'มี.ค': 3, 'เม.ย': 4, 'พ.ค': 5, 'มิ.ย': 6,
    'ก.ค': 7, 'ส.ค': 8, 'ก.ย': 9, 'ต.ค': 10, 'พ.ย': 11, 'ธ.ค': 12,
}

# Sheet status → (workflow status, rank used to pick the primary row of a
# duplicate group). Terminal split by classification happens in map_status.
STATUS_RANK = {
    'เสร็จเรียบร้อย': 4,
    'ส่งรายงาน': 3,
    'กำลังเขียนสรุป': 2,
    'กำลังวิเคราะห์': 2,
    'อยู่ระหว่างการจ่ายงาน': 1,
}

# Reviewed sheet category → (detailed_issue, detailed_issue2). The sheet only
# records the parent category, so the child falls to that parent's "Other".
CATEGORY_MAP = {
    'Training':             ('Training', 'Training Other'),
    'Unsuccessful Attempt': ('Unsuccessful Attempt', 'Unsuccessful Other'),
    'Reconnaissance':       ('Reconnaissance', 'Recon Other'),
    'Non-Compliance':       ('Non-Compliance', 'Compliance Other'),
    'Malicious Logic':      ('Malicious Logic', 'Malicious Other'),
    'User Intrusion':       ('User Intrusion', 'User Level Other'),
    'Root Intrusion':       ('Root Intrusion', 'Root Level Other'),
    'DoS':                  ('DoS', 'DoS Other'),
    'Investigating':        ('Investigating', 'Investigating Other'),
    'Explained Anomaly':    ('Explained Anomaly', 'Explained Other'),
    'SIEM Other':           ('SIEM Other', 'SIEM Other Detail'),
}


def parse_created(value):
    """'10/4/2026, 11:14:00' (day-first) → aware datetime, or None."""
    value = (value or '').strip()
    if not value:
        return None
    for fmt in ('%d/%m/%Y, %H:%M:%S', '%d/%m/%Y %H:%M:%S', '%d/%m/%Y'):
        try:
            return timezone.make_aware(datetime.strptime(value, fmt))
        except ValueError:
            continue
    return None


def parse_ack(value):
    """'10/4/2026' → aware datetime at start of day, or None."""
    value = (value or '').strip()
    if not value:
        return None
    try:
        return timezone.make_aware(datetime.strptime(value, '%d/%m/%Y'))
    except ValueError:
        return None


def parse_thai_report_date(text):
    """'ปปกก./45  ลว.14 พ.ค. 69' → aware datetime (Buddhist year), or None."""
    text = (text or '').strip()
    if not text:
        return None
    day_m = re.search(r'ลว\s*\.?\s*/?\s*(\d{1,2})', text)
    if not day_m:
        return None
    day = int(day_m.group(1))
    month = next((v for k, v in THAI_MONTHS.items() if k in text), None)
    nums = re.findall(r'\d+', text)
    if month is None or not nums:
        return None
    year_raw = int(nums[-1])
    if year_raw < 100:            # e.g. 69 → พ.ศ. 2569
        year = year_raw + 2500 - 543
    elif year_raw > 2400:         # already a Buddhist year
        year = year_raw - 543
    else:
        year = year_raw
    try:
        return timezone.make_aware(datetime(year, month, day, 12, 0))
    except ValueError:
        return None


def parse_stopped_at(remark):
    """'*หยุดการเคลื่อนไหว 2026-05-19 14:18:11' in หมายเหตุ → aware dt, or None."""
    m = re.search(
        r'หยุดการเคลื่อนไหว\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})',
        remark or '',
    )
    if not m:
        return None
    return timezone.make_aware(
        datetime.strptime(f'{m.group(1)} {m.group(2)}', '%Y-%m-%d %H:%M:%S')
    )


def completeness(row):
    return sum(1 for v in row.values() if (v or '').strip())


class Command(BaseCommand):
    help = 'Import historical cases from the reviewed TrendMicro tracker CSV.'

    def add_arguments(self, parser):
        parser.add_argument('csv_path')
        parser.add_argument('--dry-run', action='store_true',
                            help='Parse and validate everything, then roll back.')
        parser.add_argument('--create-missing-users', action='store_true',
                            help='Create placeholder SOC T1 accounts for '
                                 'assignees with no matching username.')

    # ------------------------------------------------------------------ #
    def handle(self, *args, **opts):
        try:
            with open(opts['csv_path'], encoding='utf-8-sig', newline='') as f:
                rows = [r for r in csv.DictReader(f)
                        if (r.get('no') or '').strip()]
        except OSError as exc:
            raise CommandError(f'Cannot read CSV: {exc}')
        if not rows:
            raise CommandError('No data rows found in CSV.')

        # Group duplicate rows by incident ID; most complete row wins.
        groups = {}
        for row in rows:
            iid = (row.get('รหัส Incident') or '').strip()
            if not iid:
                continue
            groups.setdefault(iid, []).append(row)
        for iid, grp in groups.items():
            grp.sort(key=lambda r: (
                STATUS_RANK.get((r.get('Status') or '').strip(), 0),
                completeness(r),
            ), reverse=True)

        # Import in chronological order so ticket_id sequences follow time.
        ordered = sorted(
            groups.items(),
            key=lambda kv: parse_created(kv[1][0].get('Created Date'))
            or timezone.now(),
        )

        self.users_created, self.ticket_seq = [], {}
        created, skipped, warnings = [], [], []

        with transaction.atomic():
            for iid, grp in ordered:
                if Ticket.objects.filter(reference_id=iid).exists():
                    skipped.append(iid)
                    continue
                ticket = self._import_group(iid, grp, opts, warnings)
                created.append((ticket.ticket_id, iid, ticket.status))

            if opts['dry_run']:
                transaction.set_rollback(True)

        # ── Report ────────────────────────────────────────────────────── #
        tag = 'DRY RUN — rolled back' if opts['dry_run'] else 'imported'
        self.stdout.write(self.style.SUCCESS(
            f'{len(created)} tickets {tag}, {len(skipped)} skipped '
            f'(already imported), {len(self.users_created)} users created.'
        ))
        if self.users_created:
            self.stdout.write('Placeholder users: '
                              + ', '.join(self.users_created))
        for w in warnings:
            self.stdout.write(self.style.WARNING(w))

    # ------------------------------------------------------------------ #
    def _get_user(self, name, opts, warnings):
        name = name.strip()
        if not name:
            return None
        username = name.lower()
        user = User.objects.filter(username__iexact=username).first()
        if user:
            return user
        if not opts['create_missing_users']:
            warnings.append(f'No user "{username}" — assignee left empty '
                            f'(use --create-missing-users).')
            return None
        user = User.objects.create(username=username, first_name=name)
        user.set_unusable_password()
        user.save(update_fields=['password'])
        UserProfile.objects.create(
            user=user, department='SOC', phone='-',
            role=UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1,
            note='Placeholder account created by import_trendmicro — '
                 'merge/rename to the analyst\'s real account.',
        )
        self.users_created.append(username)
        return user

    def _next_ticket_id(self, when):
        prefix = f'{when.year % 100:02d}{when.month:02d}'
        if prefix not in self.ticket_seq:
            seqs = [
                int(t[4:]) for t in Ticket.objects.filter(
                    ticket_id__startswith=prefix
                ).values_list('ticket_id', flat=True)
                if t[4:].isdigit()
            ]
            self.ticket_seq[prefix] = max(seqs, default=0)
        self.ticket_seq[prefix] += 1
        return f'{prefix}{self.ticket_seq[prefix]:02d}'

    # ------------------------------------------------------------------ #
    def _import_group(self, iid, grp, opts, warnings):
        row = grp[0]
        get = lambda key: (row.get(key) or '').strip()

        incident_dt = parse_created(get('Created Date'))
        if incident_dt is None:
            warnings.append(f'{iid}: unparseable Created Date '
                            f'"{get("Created Date")}" — using now().')
            incident_dt = timezone.now()
        ack_dt = parse_ack(get('วันที่รับเคส'))
        # The tracker records the ack as a bare date (midnight). A same-day
        # pickup would land BEFORE the alert's timestamp and yield a negative
        # time-to-ack, so clamp it to the alert time. Multi-day gaps keep the
        # midnight boundary — day granularity is all the tracker captured.
        if ack_dt and ack_dt < incident_dt:
            ack_dt = incident_dt
        report_dt = parse_thai_report_date(get('วันที่ออกรายงาน'))
        closed_dt = parse_stopped_at(get('หมายเหตุ'))

        validation = get('Validation Result').upper()
        classification = {
            'TP': Ticket.CLASSIFICATION_INCIDENT,
            'FP': Ticket.CLASSIFICATION_EVENT,
        }.get(validation, '')

        sheet_status = get('Status')
        if sheet_status == 'เสร็จเรียบร้อย':
            status = (Ticket.STATUS_CLOSED_EVENT
                      if classification == Ticket.CLASSIFICATION_EVENT
                      else Ticket.STATUS_APPROVED)
        elif sheet_status == 'ส่งรายงาน':
            status = Ticket.STATUS_AWAITING_CONTAINMENT
        else:
            status = Ticket.STATUS_NEW

        detailed_issue, detailed_issue2 = CATEGORY_MAP.get(
            get('Category'), ('Investigating', 'Investigating Other'))
        if get('Category') and get('Category') not in CATEGORY_MAP:
            warnings.append(f'{iid}: unknown category "{get("Category")}" '
                            f'— defaulted to Investigating.')

        assignees = [n for n in re.split(r'[,/]', get('ผู้รับผิดชอบ'))
                     if n.strip()]
        primary_user = (self._get_user(assignees[0], opts, warnings)
                        if assignees else None)

        detail = get('Detail')
        has_detail = detail and not detail.startswith('Unable to retrieve')
        description = get('Case Note')
        if has_detail:
            description = (f'{description}\n\n[TrendMicro Detail] {detail}'
                           if description else f'[TrendMicro Detail] {detail}')
        if not description:
            description = '(ไม่มีรายละเอียดในระบบติดตามเดิม — imported)'

        notes = [f'นำเข้าจาก TrendMicro tracker (แถว {get("no")})']
        if get('รหัส INC'):
            notes.append(f'รหัส INC: {get("รหัส INC")}')
        if len(assignees) > 1:
            notes.append('ผู้รับผิดชอบร่วม: ' + ', '.join(assignees[1:]))
        if get('หมายเหตุ'):
            notes.append(f'หมายเหตุ: {get("หมายเหตุ")}')

        try:
            score = int(float(get('Current Score')))
        except ValueError:
            score = None

        severity = get('Severity') if get('Severity') in dict(
            Ticket.SEVERITY_CHOICES) else 'Unknown'

        ticket = Ticket(
            ticket_id=self._next_ticket_id(incident_dt),
            reference_id=iid,
            severity=severity,
            incident_datetime=incident_dt,
            device_name=(get('Case Key') or 'ไม่ระบุ (TrendMicro import)')[:100],
            issue_description=description,
            ip_address=None,
            status=status,
            classification=classification,
            is_emergency=get('Critical Level') == 'Emergency',
            issue_type='SIEM',
            detailed_issue=detailed_issue,
            detailed_issue2=detailed_issue2,
            assigned_to=primary_user,
            created_by=primary_user,
            update_notes='\n'.join(notes),
            containment_report=get('วันที่ออกรายงาน'),
            alert_score=score,
            acknowledged_at=ack_dt,
            report_issued_at=report_dt,
            closed_at=closed_dt,
            approved_at=(closed_dt
                         if status == Ticket.STATUS_APPROVED else None),
        )
        ticket.save()

        # Backdate the auto_now_add/auto_now clocks: the ticket was "raised"
        # when the analyst took the case, not on import day.
        raised_at = ack_dt or incident_dt
        state_at = closed_dt or report_dt or raised_at
        Ticket.objects.filter(pk=ticket.pk).update(
            created_at=raised_at, status_changed_at=state_at,
            updated_at=state_at,
        )

        TicketLog.objects.create(
            ticket=ticket, status_at_time=status, author=None,
            note=f'นำเข้าข้อมูลย้อนหลังจาก TrendMicro tracker — '
                 f'incident {iid}, แถว {get("no")}',
        )
        # Preserve merged duplicate rows verbatim as log entries.
        for extra in grp[1:]:
            eget = lambda key: (extra.get(key) or '').strip()
            parts = [f'แถวซ้ำ {eget("no")} (สถานะ: {eget("Status") or "-"}'
                     f', ผู้รับผิดชอบ: {eget("ผู้รับผิดชอบ") or "-"})']
            if eget('Case Note'):
                parts.append(f'Case Note: {eget("Case Note")}')
            if eget('หมายเหตุ'):
                parts.append(f'หมายเหตุ: {eget("หมายเหตุ")}')
            TicketLog.objects.create(
                ticket=ticket, status_at_time=status, author=None,
                note='รวมแถวซ้ำจาก tracker — ' + ' | '.join(parts),
            )
        return ticket
