"""Stage the two CEO-demo tickets.

Re-runnable: every run deletes and rebuilds both tickets, so a botched
run-through can be reset with one command right before the room fills up.

    py manage.py seed_ceo_demo            # create / reset both tickets
    py manage.py seed_ceo_demo --remove   # delete them again afterwards

DEMO-CEO-001 — the LIVE case, left at AWAITING_CONTAINMENT with a realistic
prior history (T1 raised it -> routed to manager -> manager assigned an admin)
so the demo only walks the last three steps:

    admin contains -> T2 verifies -> manager approves

DEMO-CEO-002 — the CLOSED case: a fully worked Critical + emergency incident
carried the whole way to APPROVED, including a Tier 2 escalation and one
"not contained, do it again" rejection loop. Every narrative field is filled,
so it is the ticket to open when showing the report export or answering
"what does a finished case actually look like?".

Both walk the real state machine; timestamps are rewritten afterwards so the
history reads as a case worked over hours rather than in one instant.
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.incidents.models import Ticket, TicketLog, TicketSubtask

REFERENCE_ACTIVE = 'DEMO-CEO-001'
REFERENCE_CLOSED = 'DEMO-CEO-002'


class Command(BaseCommand):
    help = 'Create/reset the two pre-staged tickets used for the CEO demo.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--remove', action='store_true',
            help='Delete both demo tickets and exit.',
        )

    # ── helpers ──────────────────────────────────────────────────────── #

    def _pick(self, role_desc, **filters):
        user = User.objects.filter(**filters).order_by('username').first()
        if not user:
            raise CommandError(
                f'No {role_desc} user found ({filters}). '
                f'Create one before seeding the demo.'
            )
        return user

    @staticmethod
    def _retime_logs(ticket, base, offsets):
        """Rewrite the auto-stamped log times onto a realistic timeline."""
        logs = list(TicketLog.objects.filter(ticket=ticket).order_by('id'))
        for log, mins in zip(logs, offsets):
            TicketLog.objects.filter(pk=log.pk).update(
                created_at=base + timedelta(minutes=mins),
                updated_at=base + timedelta(minutes=mins),
            )
        return logs

    # ── entrypoint ───────────────────────────────────────────────────── #

    @transaction.atomic
    def handle(self, *args, **options):
        existing = Ticket.objects.filter(
            reference_id__in=[REFERENCE_ACTIVE, REFERENCE_CLOSED])

        if options['remove']:
            n, _ = existing.delete()
            self.stdout.write(self.style.SUCCESS(
                f'Removed demo tickets ({n} rows).'))
            return

        if existing.exists():
            existing.delete()
            self.stdout.write('Existing demo tickets removed; rebuilding.')

        t1 = self._pick('Tier 1 SOC', profile__role='SOC_STAFF', profile__tier='T1')
        t2 = self._pick('Tier 2 SOC', profile__role='SOC_STAFF', profile__tier='T2')
        manager = self._pick('SOC manager', profile__role='SOC_MANAGER')
        admin = self._pick('system admin', profile__role='SYSTEM_ADMIN')

        active = self._build_active_case(t1, t2, manager, admin)
        closed = self._build_closed_case(t1, t2, manager, admin)

        self._report(active, closed, t1, t2, manager, admin)

    # ── DEMO-CEO-001 — the live case ─────────────────────────────────── #

    def _build_active_case(self, t1, t2, manager, admin):
        now = timezone.now()
        # Raised 25 min ago: the Critical triage OLA (30 min) is still green and
        # visibly ticking, and the 4h containment clock runs live during the demo.
        detected = now - timedelta(minutes=25)

        ticket = Ticket(
            reference_id=REFERENCE_ACTIVE,
            incident_name='พบพฤติกรรมเตรียมเข้ารหัสไฟล์ (Ransomware) บนเซิร์ฟเวอร์ไฟล์ฝ่ายการเงิน',
            severity='Critical',
            ncsa_severity='CRITICAL',
            classification='INCIDENT',
            t1_route='ADMIN',
            issue_type='SIEM',
            detailed_issue='Malicious Logic',
            incident_datetime=detected,
            log_source='Wazuh / OpenSearch (rule 100213 — เปลี่ยนชื่อไฟล์จำนวนมาก)',
            device_name='NT-FS-FIN01',
            ip_address='10.0.188.41',
            mac_address='00:1B:44:11:3A:B7',
            asset_type='Server',
            operating_system='Windows Server 2019 Standard',
            asset_owner='ฝ่ายการเงิน — งานบริการร่วม',
            issue_description=(
                'Wazuh ตรวจพบเหตุการณ์เปลี่ยนชื่อไฟล์จำนวนมากบนเซิร์ฟเวอร์ไฟล์ของ'
                'ฝ่ายการเงิน NT-FS-FIN01 (10.0.188.41) โดยมีการเปลี่ยนชื่อไฟล์ '
                '1,240 ไฟล์ เป็นนามสกุล .lockbit ภายใน 90 วินาที ซึ่งเกิดขึ้นทันที'
                'หลังจากมีการเรียกใช้ vssadmin.exe เพื่อลบ Volume Shadow Copy '
                'ทั้งหมด\n\n'
                'รูปแบบดังกล่าวตรงกับพฤติกรรมการเตรียมการก่อนเข้ารหัสไฟล์ '
                '(pre-encryption staging) มากกว่าการเข้ารหัสที่ดำเนินการเสร็จสิ้น'
                'แล้ว จึงต้องเร่งควบคุมสถานการณ์ก่อนที่จะแพร่กระจายไปยังเครื่องอื่น'
            ),
            spread_to_others=True,
            destination_ip='185.220.101.47',
            ioc_details=(
                'SHA256 8f4e2a1c9b7d3e5f6a0c8b2d4e6f1a3c5b7d9e0f2a4c6b8d0e2f4a6c8b0d2e4f\n'
                'C2 185.220.101.47:443 (TOR exit node — พบครั้งแรก 14 ก.ค. 2569)\n'
                'คำสั่งที่พบ: vssadmin.exe delete shadows /all /quiet\n'
                'ไฟล์ที่ถูกวาง: C:\\Users\\Public\\svc_update.exe'
            ),
            mitre_phase='Impact,Defense Evasion',
            action_required=(
                '1. ตัดการเชื่อมต่อเครือข่ายของเครื่อง NT-FS-FIN01 '
                '(shutdown พอร์ตบนสวิตช์)\n'
                '2. บล็อกปลายทาง 185.220.101.47 ที่ไฟร์วอลล์ขอบเขตเครือข่าย\n'
                '3. เก็บหลักฐาน memory และ disk image ก่อนรีบูตเครื่อง\n'
                '4. ตรวจสอบความสมบูรณ์ของข้อมูลสำรองของ FIN share ก่อนกู้คืน'
            ),
            action_precautions=(
                'ห้ามรีบูตหรือปิดเครื่องเด็ดขาด — ข้อมูลใน memory จำเป็นต่อการจัดทำ '
                'forensic timeline ให้ใช้วิธีตัดการเชื่อมต่อที่สวิตช์แทน'
            ),
            alert_score=88,
            is_emergency=True,
            status=Ticket.STATUS_NEW,
            created_by=t1,
            assigned_to=t1,
        )
        ticket.save()

        # created_at is auto_now_add, so it has to be corrected after save().
        Ticket.objects.filter(pk=ticket.pk).update(created_at=detected)
        ticket.refresh_from_db()

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

        offsets = [2, 9, 18]
        self._retime_logs(ticket, detected, offsets)
        Ticket.objects.filter(pk=ticket.pk).update(
            status_changed_at=detected + timedelta(minutes=offsets[-1]),
            report_issued_at=detected + timedelta(minutes=offsets[-1]),
        )
        ticket.refresh_from_db()
        return ticket

    # ── DEMO-CEO-002 — the closed, fully worked case ─────────────────── #

    def _build_closed_case(self, t1, t2, manager, admin):
        now = timezone.now()
        # Detected 5 days ago and closed the same day, inside the 4h Critical
        # containment target — this case is the "we did it right" exhibit.
        detected = now - timedelta(days=5)

        action_required = (
            '1. เพิกถอน session VPN ทั้งหมดของบัญชี svc-hr-admin และบังคับรีเซ็ตรหัสผ่าน\n'
            '2. บล็อกปลายทาง 45.155.205.233 ที่ไฟร์วอลล์ และตรวจสอบ log ย้อนหลัง 30 วัน\n'
            '3. แยกเครื่อง NT-APP-HR03 ออกจากเครือข่าย และเก็บ memory image\n'
            '4. ปิดช่องโหว่ CVE-2026-21893 บน VPN gateway (patch + reboot นอกเวลาทำการ)\n'
            '5. บังคับเปิดใช้ MFA กับบัญชีสิทธิ์สูงทุกบัญชีที่เข้าผ่าน VPN'
        )

        ticket = Ticket(
            reference_id=REFERENCE_CLOSED,
            incident_name=(
                'บัญชีผู้ดูแลระบบถูกยึดผ่านช่องโหว่ VPN '
                'และมีความพยายามส่งข้อมูลบุคลากรออกนอกองค์กร'
            ),
            severity='Critical',
            ncsa_severity='CRITICAL',
            classification='INCIDENT',
            t1_route='ADMIN',
            issue_type='SIEM',
            detailed_issue='Root Intrusion',
            detailed_issue2='Data Exfiltration',
            incident_datetime=detected,
            log_source=(
                'Wazuh / OpenSearch (rule 100455 — ผู้ใช้สิทธิ์สูงเข้าระบบนอกเวลาทำการ) '
                'ร่วมกับ log ของ FortiGate VPN'
            ),
            device_name='NT-APP-HR03',
            ip_address='10.0.188.63',
            mac_address='00:1B:44:11:9C:2E',
            asset_type='Server',
            operating_system='Windows Server 2022 Standard',
            asset_owner='ฝ่ายทรัพยากรบุคคล — งานสารสนเทศบุคลากร',
            issue_description=(
                'เวลา 02:14 น. Wazuh แจ้งเตือนการเข้าสู่ระบบสำเร็จของบัญชีสิทธิ์สูง '
                'svc-hr-admin ผ่าน VPN จากหมายเลขไอพีต่างประเทศ (185.243.115.28, '
                'ประเทศเนเธอร์แลนด์) ซึ่งไม่เคยปรากฏในประวัติการใช้งานของบัญชีนี้ '
                'มาก่อน และเกิดขึ้นนอกเวลาทำการ\n\n'
                'จากการตรวจสอบพบว่าผู้โจมตีใช้ช่องโหว่ CVE-2026-21893 บน VPN '
                'gateway เพื่อข้ามการยืนยันตัวตน จากนั้นเข้าถึงเซิร์ฟเวอร์ '
                'NT-APP-HR03 (10.0.188.63) ซึ่งเก็บข้อมูลบุคลากร แล้วรวบรวมไฟล์ '
                'จำนวน 412 ไฟล์ (ประมาณ 2.3 GB) ไปไว้ที่ C:\\Windows\\Temp\\a\\ '
                'ก่อนพยายามอัปโหลดออกไปยัง 45.155.205.233 ผ่าน HTTPS\n\n'
                'การอัปโหลดถูกไฟร์วอลล์บล็อกไว้ได้ก่อน โดยยืนยันจาก log ว่ามีข้อมูล'
                'ออกไปจริงเพียง 18 MB ซึ่งเป็นไฟล์ทดสอบขนาดเล็กที่ผู้โจมตีใช้ทดสอบ'
                'เส้นทาง ไม่ใช่ฐานข้อมูลบุคลากร'
            ),
            spread_to_others=True,
            destination_ip='45.155.205.233',
            ioc_details=(
                'IP ต้นทางการเข้าถึง: 185.243.115.28 (NL, VPN provider)\n'
                'IP ปลายทางการส่งข้อมูล: 45.155.205.233:443\n'
                'บัญชีที่ถูกใช้: svc-hr-admin\n'
                'ช่องโหว่ที่ถูกใช้: CVE-2026-21893 (VPN gateway auth bypass)\n'
                'SHA256 5c1d0f8a3b6e29d47f0a8c2b5e9d1f4a7c3b6e0d2f5a8c1b4e7d0a3f6c9b2e5d\n'
                'เครื่องมือที่พบ: rclone.exe (เปลี่ยนชื่อเป็น winupd.exe)\n'
                'ที่พักไฟล์: C:\\Windows\\Temp\\a\\ (412 ไฟล์ ~2.3 GB)'
            ),
            mitre_phase='Initial Access,Credential Access,Collection,Exfiltration',
            action_required=action_required,
            action_precautions=(
                'ห้ามลบไฟล์ใน C:\\Windows\\Temp\\a\\ ก่อนเก็บหลักฐานให้ครบ — '
                'เป็นหลักฐานยืนยันขอบเขตข้อมูลที่ถูกเข้าถึง และจำเป็นต่อการรายงาน '
                'สกมช. ให้ประสานฝ่ายทรัพยากรบุคคลก่อนแจ้งเจ้าของข้อมูลทุกกรณี'
            ),
            containment_report=(
                'ดำเนินมาตรการควบคุมตามลำดับดังนี้\n\n'
                '1. เพิกถอน session VPN ทั้งหมดของบัญชี svc-hr-admin เวลา 02:41 น. '
                'และบังคับรีเซ็ตรหัสผ่าน พร้อมปิดการใช้งานบัญชีชั่วคราว\n'
                '2. บล็อก 45.155.205.233 และ 185.243.115.28 ที่ไฟร์วอลล์ขอบเขต '
                'เวลา 02:47 น. ยืนยันว่าไม่มีทราฟฟิกออกเพิ่มเติมหลังเวลาดังกล่าว\n'
                '3. แยกเครื่อง NT-APP-HR03 ออกจากเครือข่ายด้วยการ shutdown พอร์ต '
                'Gi1/0/22 บนสวิตช์ และเก็บ memory image ขนาด 32 GB ไว้ที่ '
                'เครื่องเก็บหลักฐานก่อนดำเนินการใดๆ กับเครื่อง\n'
                '4. ติดตั้งแพตช์ปิดช่องโหว่ CVE-2026-21893 บน VPN gateway '
                'ในช่วง maintenance window เวลา 03:30–04:00 น. และรีบูตเรียบร้อย\n'
                '5. บังคับเปิด MFA กับบัญชีสิทธิ์สูงทุกบัญชีที่เข้าผ่าน VPN '
                'รวม 24 บัญชี ยืนยันการเปิดใช้งานครบทุกบัญชีเวลา 05:10 น.'
            ),
            remediation_summary=(
                'ผลการตรวจสอบ\n\n'
                'ช่องทางเข้า: ผู้โจมตีใช้ช่องโหว่ CVE-2026-21893 บน VPN gateway '
                'ซึ่งยังไม่ได้ติดตั้งแพตช์ที่ออกเมื่อ 28 มิ.ย. 2569 เพื่อข้ามการ'
                'ยืนยันตัวตน แล้วใช้บัญชี svc-hr-admin ที่ไม่ได้เปิด MFA\n\n'
                'ขอบเขตผลกระทบ: จำกัดอยู่ที่เครื่อง NT-APP-HR03 เพียงเครื่องเดียว '
                'ตรวจสอบ log การเข้าถึงย้อนหลัง 30 วันแล้วไม่พบการเข้าถึงเครื่องอื่น '
                'และไม่พบการสร้างบัญชีใหม่หรือกลไกคงอยู่ (persistence) ในระบบ\n\n'
                'ข้อมูลที่รั่วไหลจริง: 18 MB เป็นไฟล์ทดสอบที่ผู้โจมตีสร้างขึ้นเอง '
                'ไม่ใช่ข้อมูลบุคลากร ยืนยันจาก log ของไฟร์วอลล์และการเทียบ hash '
                'ของไฟล์ที่ถูกรวบรวมไว้ ฐานข้อมูลบุคลากร 2.3 GB ถูกรวบรวมไว้แล้ว '
                'แต่ยังไม่ถูกส่งออกสำเร็จ\n\n'
                'สาเหตุเชิงระบบ: กระบวนการติดตั้งแพตช์ของอุปกรณ์ขอบเครือข่ายไม่มี '
                'SLA กำกับ ทำให้แพตช์ที่ออกมาแล้ว 17 วันยังไม่ถูกติดตั้ง และนโยบาย '
                'MFA ครอบคลุมเฉพาะบัญชีผู้ใช้ทั่วไป ไม่ครอบคลุมบัญชี service account'
            ),
            actions_taken_summary=(
                'เพิกถอน session และรีเซ็ตรหัสผ่านบัญชีที่ถูกยึด · '
                'บล็อก IOC ที่ไฟร์วอลล์ · แยกเครื่องออกจากเครือข่ายและเก็บหลักฐาน · '
                'ติดตั้งแพตช์ปิดช่องโหว่ VPN gateway · บังคับเปิด MFA บัญชีสิทธิ์สูง 24 บัญชี · '
                'ควบคุมสถานการณ์ได้ภายใน 3 ชั่วโมง 26 นาที (กรอบ OLA 4 ชั่วโมง)'
            ),
            next_steps_summary=(
                '1. กำหนด SLA การติดตั้งแพตช์สำหรับอุปกรณ์ขอบเครือข่ายภายใน 7 วัน '
                'สำหรับช่องโหว่ระดับ Critical (เจ้าภาพ: ฝ่ายโครงสร้างพื้นฐาน)\n'
                '2. ขยายนโยบาย MFA ให้ครอบคลุม service account ทุกบัญชี '
                'ภายในไตรมาสถัดไป\n'
                '3. เพิ่ม detection rule สำหรับการเข้าถึงของบัญชีสิทธิ์สูงจาก IP '
                'ต่างประเทศนอกเวลาทำการ (ดำเนินการแล้ว — rule 100455 ปรับปรุง)\n'
                '4. ทบทวนสิทธิ์ของ service account บนเซิร์ฟเวอร์ที่เก็บข้อมูลส่วนบุคคล\n'
                '5. รายงาน สกมช. ตามแบบฟอร์มภายในกรอบเวลาที่กำหนด (ดำเนินการแล้ว)'
            ),
            update_notes=(
                'ปิดเคสโดยความเห็นชอบของผู้จัดการ SOC — ควบคุมสถานการณ์ได้ภายใน'
                'กรอบ OLA และไม่พบข้อมูลบุคลากรรั่วไหลออกนอกองค์กร'
            ),
            alert_score=96,
            is_emergency=True,
            status=Ticket.STATUS_NEW,
            created_by=t1,
            assigned_to=t1,
        )
        ticket.save()
        Ticket.objects.filter(pk=ticket.pk).update(
            created_at=detected + timedelta(minutes=4))
        ticket.refresh_from_db()

        ticket.assigned_admin = admin
        ticket.save()

        # Walk the longest legal path: escalation to Tier 2, return to Tier 1,
        # manager triage, containment, one rejection loop, then approval.
        steps = [
            (Ticket.STATUS_ESCALATED_T2, t1,
             'บัญชีสิทธิ์สูงเข้าระบบจาก IP ต่างประเทศนอกเวลาทำการ '
             'ไม่แน่ใจว่าเป็นการใช้งานจริงของเจ้าของบัญชีหรือไม่ ขอส่ง Tier 2 ตรวจสอบ'),
            (Ticket.STATUS_T1_REVIEW, t2,
             'ตรวจสอบแล้วยืนยันเป็น Incident จริง — พบการใช้ช่องโหว่ CVE-2026-21893 '
             'ข้ามการยืนยันตัวตน และพบการรวบรวมไฟล์เตรียมส่งออก ส่งกลับ Tier 1 '
             'เพื่อดำเนินการตามกระบวนการ'),
            (Ticket.STATUS_PENDING_MGR_TRIAGE, t1,
             'รับกลับจาก Tier 2 ยืนยันเป็น Incident ระดับ Critical และติดธง Emergency '
             'เนื่องจากเกี่ยวข้องกับข้อมูลส่วนบุคคล ขอส่งผู้จัดการมอบหมายผู้ดูแลระบบ'),
            (Ticket.STATUS_AWAITING_CONTAINMENT, manager,
             f'รับทราบ — มอบหมายให้ {admin.get_full_name() or admin.username} '
             f'ดำเนินการเพิกถอน session, บล็อก IOC และแยกเครื่องทันที '
             f'พร้อมแจ้งฝ่ายทรัพยากรบุคคลให้รับทราบ'),
            (Ticket.STATUS_CONTAINMENT_REPORTED, admin,
             'ดำเนินการเพิกถอน session, รีเซ็ตรหัสผ่าน, บล็อก IOC และแยกเครื่อง'
             'เรียบร้อยแล้ว'),
            (Ticket.STATUS_AWAITING_CONTAINMENT, t2,
             'ยังไม่ถือว่าควบคุมได้ครบ — ช่องโหว่ CVE-2026-21893 บน VPN gateway '
             'ยังไม่ได้ติดตั้งแพตช์ ผู้โจมตีสามารถกลับเข้ามาด้วยวิธีเดิมได้ '
             'ขอให้ดำเนินการปิดช่องโหว่และบังคับ MFA ก่อนส่งตรวจอีกครั้ง'),
            (Ticket.STATUS_CONTAINMENT_REPORTED, admin,
             'ติดตั้งแพตช์ปิดช่องโหว่บน VPN gateway และบังคับเปิด MFA กับบัญชี'
             'สิทธิ์สูง 24 บัญชีเรียบร้อยแล้ว ยืนยันไม่มีทราฟฟิกออกเพิ่มเติม'),
            (Ticket.STATUS_PENDING_MANAGER, t2,
             'ตรวจสอบแล้วยืนยันว่าควบคุมสถานการณ์ได้ครบถ้วน ช่องโหว่ถูกปิด '
             'MFA บังคับใช้แล้ว และไม่พบกลไกคงอยู่ในระบบ ส่งผู้จัดการพิจารณาอนุมัติ'),
            (Ticket.STATUS_APPROVED, manager,
             'อนุมัติปิดเคส — ควบคุมได้ภายในกรอบ OLA และไม่พบข้อมูลบุคลากรรั่วไหล '
             'ให้ติดตามข้อเสนอแนะเชิงระบบต่อในวาระประชุมประจำเดือน'),
        ]
        for status, user, note in steps:
            ticket.transition_to(status, user, note=note)
            ticket.refresh_from_db()

        # Tick every checklist item — the admin worked through all of them.
        items, _ = Ticket.parse_checklist_items(action_required)
        ticket.containment_checklist = [
            {'text': text, 'done': True} for text in items
        ]
        ticket.acknowledged_at = detected + timedelta(minutes=6)
        ticket.owner_contacted_at = detected + timedelta(minutes=52)
        ticket.save()

        # Minutes from detection for: created, then each of the 9 transitions.
        offsets = [4, 11, 29, 38, 47, 96, 112, 158, 181, 206]
        self._retime_logs(ticket, detected, offsets[1:])
        Ticket.objects.filter(pk=ticket.pk).update(
            escalated_to_t2_at=detected + timedelta(minutes=offsets[1]),
            report_issued_at=detected + timedelta(minutes=offsets[4]),
            verified_at=detected + timedelta(minutes=offsets[8]),
            approved_at=detected + timedelta(minutes=offsets[9]),
            closed_at=detected + timedelta(minutes=offsets[9]),
            status_changed_at=detected + timedelta(minutes=offsets[9]),
        )
        ticket.refresh_from_db()
        self._add_subtasks(ticket, t1, t2, admin, detected)
        return ticket

    def _add_subtasks(self, ticket, t1, t2, admin, base):
        rows = [
            ('INVESTIGATION', 'ตรวจสอบ log การเข้าถึง VPN ย้อนหลัง 30 วัน', t2,
             'ตรวจสอบ log ของ FortiGate VPN ย้อนหลัง 30 วัน เทียบกับบัญชีสิทธิ์สูง'
             'ทั้ง 24 บัญชี',
             'ไม่พบการเข้าถึงจาก IP ต่างประเทศรายการอื่น นอกเหนือจากเหตุการณ์นี้ '
             'บัญชีอื่นไม่ได้รับผลกระทบ', 33),
            ('COUNTERMEASURE', 'เพิกถอน session และรีเซ็ตรหัสผ่าน svc-hr-admin', admin,
             'เพิกถอน session VPN ทั้งหมด บังคับรีเซ็ตรหัสผ่าน และปิดบัญชีชั่วคราว'
             'จนกว่าจะยืนยันความปลอดภัย',
             'ดำเนินการเสร็จเวลา 02:41 น. ยืนยันว่าไม่มี session ค้างอยู่ในระบบ', 62),
            ('INVESTIGATION', 'ยืนยันปริมาณข้อมูลที่ถูกส่งออกจริง', t2,
             'เทียบ log ไฟร์วอลล์กับรายการไฟล์ที่ถูกรวบรวมไว้ใน C:\\Windows\\Temp\\a\\ '
             'เพื่อระบุขอบเขตข้อมูลที่รั่วไหล',
             'ออกไปจริง 18 MB เป็นไฟล์ทดสอบที่ผู้โจมตีสร้างเอง ฐานข้อมูลบุคลากร '
             '2.3 GB ไม่ถูกส่งออก ยืนยันด้วยการเทียบ hash', 141),
            ('COUNTERMEASURE', 'ปิดช่องโหว่ CVE-2026-21893 และบังคับ MFA', admin,
             'ติดตั้งแพตช์บน VPN gateway ในช่วง maintenance window และขยายนโยบาย '
             'MFA ให้ครอบคลุมบัญชีสิทธิ์สูง',
             'ติดตั้งแพตช์และรีบูตเสร็จเวลา 04:00 น. บังคับ MFA ครบ 24 บัญชี '
             'เวลา 05:10 น.', 155),
        ]
        for kind, title, assignee, desc, result, mins in rows:
            st = TicketSubtask.objects.create(
                ticket=ticket, subtask_type=kind, title=title,
                description=desc, status='DONE', assigned_to=assignee,
                result_notes=result, created_by=t1,
            )
            TicketSubtask.objects.filter(pk=st.pk).update(
                created_at=base + timedelta(minutes=mins),
                updated_at=base + timedelta(minutes=mins + 20),
            )

    # ── output ───────────────────────────────────────────────────────── #

    def _report(self, active, closed, t1, t2, manager, admin):
        # Console output stays pure ASCII on purpose: a Thai-locale Windows
        # console is cp874, and any character outside it raises
        # UnicodeEncodeError — which, inside @transaction.atomic, would roll the
        # whole seed back at the last line. The ticket content is Thai; this
        # operator summary is not.
        w = self.stdout.write
        w(self.style.SUCCESS('\nCEO demo tickets staged.\n'))

        w(self.style.MIGRATE_HEADING('  LIVE case — walk this one on stage'))
        w(f'    Ticket      : {active.ticket_id}  ({active.reference_id})')
        w(f'    Status      : {active.status}')
        w(f'    Severity    : {active.severity} (emergency={active.is_emergency})')
        w(f'    Raised by   : {t1.username} (T1)')
        w(f'    Assigned to : {admin.username} (system admin)')
        w(f'    Contain OLA : {timezone.localtime(active.ola_contain_deadline):%d %b %H:%M}')
        w(f'    Needs mgr   : {active.requires_manager_verification}')

        w(self.style.MIGRATE_HEADING('\n  CLOSED case — open this one for the report export'))
        w(f'    Ticket      : {closed.ticket_id}  ({closed.reference_id})')
        w(f'    Status      : {closed.status}')
        w(f'    Severity    : {closed.severity} (emergency={closed.is_emergency})')
        w(f'    History     : {TicketLog.objects.filter(ticket=closed).count()} entries '
          f'(incl. Tier 2 escalation + 1 rejection loop)')
        w(f'    Subtasks    : {TicketSubtask.objects.filter(ticket=closed).count()} (all DONE)')
        w(f'    Verified by : {closed.verified_by} | Approved by: {closed.approved_by}')
        contained_in = closed.closed_at - closed.incident_datetime
        hrs, rem = divmod(int(contained_in.total_seconds()), 3600)
        w(f'    Closed in   : {hrs}h {rem // 60}m (OLA target 4h — met)')

        w('\n  Demo path for the LIVE case:')
        w(f'    1. {admin.username:12} -> submit containment report')
        w(f'    2. {t2.username:12} -> verify contained -> send to manager')
        w(f'    3. {manager.username:12} -> approve -> closed')
        w('')
