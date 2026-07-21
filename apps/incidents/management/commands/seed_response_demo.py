"""
apps/incidents/management/commands/seed_response_demo.py

Seeds dummy Response-Team data so a Forensic Analyst (and Red Team Manager) has a
populated "My Requests" queue to test on the UAT VM: tickets carrying response
requests (Forensics / RCA, VA / Pentest, Infrastructure Security) in a mix of
statuses — fresh, in-progress, completed-with-report, and one that demonstrates
the approval gate (an open request holding an emergency ticket out of closure).

Login accounts: this command gives ``uat_forensic`` and ``uat_redteam`` a REAL
(usable) password so testers can actually log in — unlike ``seed_uat_states``,
which creates them for attribution only. Default password ``Uat#2026`` (UAT
convention); override with --password.

Every ticket is tagged ``[RESPONSE-DEMO]`` in issue_description so --flush removes
exactly what this command created and nothing a live tester makes.

Usage:
    python manage.py seed_response_demo                  # ensure accounts + seed
    python manage.py seed_response_demo --flush          # wipe demo rows, re-seed
    python manage.py seed_response_demo --password S3cret # set login password
    python manage.py seed_response_demo --flush --no-seed # wipe only
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketAttachment, TicketLog, TicketSubtask

MARKER = "[RESPONSE-DEMO]"  # appended to issue_description so --flush is precise
S = Ticket
ST = TicketSubtask

# Attribution / login accounts this command ensures. The two response-team roles
# get a usable password (they must log in); the SOC-side authors are attribution
# only (unusable password — testers use their own named accounts).
_LOGIN_USERS = [
    dict(username="uat_forensic", role=UserProfile.ROLE_FORENSIC,
         first="Anucha", last="Forensic", dept="Digital Forensics", phone="0810000006"),
    dict(username="uat_redteam", role=UserProfile.ROLE_REDTEAM_MANAGER,
         first="Kittipong", last="RedTeam", dept="Offensive Security", phone="0810000007"),
]
_AUTHOR_USERS = [
    dict(key="T1", username="uat_t1", role=UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T1,
         first="Kawin", last="T1", dept="SOC", phone="0810000001"),
    dict(key="MANAGER", username="uat_manager", role=UserProfile.ROLE_SOC_MANAGER, tier="",
         first="Somchai", last="Manager", dept="SOC", phone="0810000003"),
    dict(key="ADMIN", username="uat_sysadmin", role=UserProfile.ROLE_SYSTEM_ADMIN, tier="",
         first="Nattapong", last="Admin", dept="IT", phone="0810000004"),
    dict(key="T2", username="uat_t2", role=UserProfile.ROLE_SOC_STAFF, tier=UserProfile.TIER_T2,
         first="Pimchan", last="T2", dept="SOC", phone="0810000002"),
]

# Each scenario: parent-ticket status + the response request riding on it. The
# ticket fields are pinned so the stage is internally consistent (an admin lane
# has an assigned admin; a CONTAINMENT_REPORTED ticket has a report; the gate
# demo is emergency + Tier-2-verified so it truly sits at PENDING_MANAGER).
#   who:        'FORENSIC' or 'REDTEAM'
#   req_type:   TicketSubtask type
#   req_status: subtask status
SCENARIOS = [
    dict(who="FORENSIC", req_type=ST.TYPE_FORENSIC_RCA, req_status=ST.STATUS_OPEN,
         status=S.STATUS_AWAITING_CONTAINMENT, emergency=False,
         device="WIN-SRV-07", severity="High",
         desc="Suspected data exfiltration via DNS tunneling.",
         req_title="เก็บ memory image + timeline ของเครื่องต้องสงสัย",
         req_desc="ขอ RCA: ดักจับ RAM, สร้าง timeline การเข้าถึง, ระบุ root cause.",
         req_notes="", report=False),
    dict(who="FORENSIC", req_type=ST.TYPE_FORENSIC_RCA, req_status=ST.STATUS_IN_PROGRESS,
         status=S.STATUS_CONTAINMENT_REPORTED, emergency=False,
         device="MAIL-GW-02", severity="High",
         desc="Ransomware note discovered on the file server.",
         req_title="วิเคราะห์ตัวอย่างมัลแวร์และหา patient-zero",
         req_desc="ขอ forensic บนไฟล์เซิร์ฟเวอร์ที่ถูกเข้ารหัส.",
         req_notes="กำลังวิเคราะห์ — พบ persistence ผ่าน scheduled task, กำลังหา entry point.",
         report=False),
    dict(who="FORENSIC", req_type=ST.TYPE_FORENSIC_RCA, req_status=ST.STATUS_OPEN,
         status=S.STATUS_PENDING_MANAGER, emergency=True,
         device="DC-PRIMARY", severity="Critical",
         desc="Phishing compromise of an executive mailbox (emergency).",
         req_title="RCA ด่วน: การเข้าถึงบัญชีผู้บริหาร",
         req_desc="Emergency — ต้องได้ root cause ก่อนปิดเคส (gate demo).",
         req_notes="", report=False),
    dict(who="FORENSIC", req_type=ST.TYPE_FORENSIC_RCA, req_status=ST.STATUS_DONE,
         status=S.STATUS_CONTAINMENT_REPORTED, emergency=False,
         device="DB-PROD-01", severity="Medium",
         desc="Malware beaconing to a known C2 endpoint.",
         req_title="RCA เครื่องที่ beacon ออก C2",
         req_desc="วิเคราะห์และสรุปผลพร้อมแนบรายงาน.",
         req_notes="Root cause: มาโครใน .xlsm ที่เปิดจากอีเมล → dropper. "
                   "ไม่มี lateral movement. แนบรายงานฉบับเต็มแล้ว.",
         report=True),
    dict(who="REDTEAM", req_type=ST.TYPE_VA_PT, req_status=ST.STATUS_OPEN,
         status=S.STATUS_AWAITING_CONTAINMENT, emergency=False,
         device="VPN-GW-01", severity="High",
         desc="Post-breach: external attack surface needs validation.",
         req_title="Re-scan ช่องโหว่และ pentest ระบบที่ถูกโจมตี",
         req_desc="VA/PT ยืนยันว่าช่องโหว่ถูกปิดแล้ว.",
         req_notes="", report=False),
    dict(who="REDTEAM", req_type=ST.TYPE_INFRA_SEC, req_status=ST.STATUS_IN_PROGRESS,
         status=S.STATUS_CONTAINMENT_REPORTED, emergency=False,
         device="FIREWALL-CORE", severity="Medium",
         desc="Firewall ruleset review requested after the incident.",
         req_title="ตรวจ ruleset ไฟร์วอลล์หลังเหตุการณ์",
         req_desc="Infra Security review ของ core firewall.",
         req_notes="กำลังทบทวน — พบ any-any rule ตกค้าง 2 รายการ, รอยืนยันกับเจ้าของระบบ.",
         report=False),
]


class Command(BaseCommand):
    help = "Seed dummy Response-Team (Forensic / Red Team) data for UAT."

    def add_arguments(self, parser):
        parser.add_argument("--password", default="Uat#2026",
                            help="Login password for uat_forensic / uat_redteam (default: Uat#2026)")
        parser.add_argument("--flush", action="store_true",
                            help="Delete previous RESPONSE-DEMO rows before seeding")
        parser.add_argument("--no-seed", action="store_true",
                            help="With --flush: wipe only, do not re-seed")

    def handle(self, *args, **options):
        if options["flush"]:
            _, per_model = Ticket.objects.filter(
                issue_description__contains=MARKER,
            ).delete()
            n_tickets = per_model.get("incidents.Ticket", 0)
            self.stdout.write(self.style.WARNING(
                f"Flushed {n_tickets} RESPONSE-DEMO ticket(s) "
                "(their requests + attachments cascade)."
            ))
            if options["no_seed"]:
                return

        password = options["password"]
        users = self._ensure_users(password)
        now = timezone.now()

        created = 0
        for sc in SCENARIOS:
            try:
                self._create_scenario(sc, users, now)
                created += 1
            except Exception as exc:  # keep going; report the offender
                self.stderr.write(self.style.ERROR(f"  {sc['req_title']} failed: {exc}"))

        forensic_open = sum(
            1 for sc in SCENARIOS
            if sc["who"] == "FORENSIC" and sc["req_status"] != ST.STATUS_DONE
        )
        forensic_done = sum(1 for sc in SCENARIOS if sc["who"] == "FORENSIC") - forensic_open
        # Console output stays ASCII-only: UAT VM consoles vary (cp874/cp1252)
        # and choke on Thai or arrows. The Thai lives in the DB (UTF-8), not here.
        self.stdout.write(self.style.SUCCESS(
            f"Seeded {created} response-team demo ticket(s)."
        ))
        self.stdout.write(
            f"  Forensic Analyst queue : {forensic_open} open + {forensic_done} done"
        )
        self.stdout.write(self.style.SUCCESS(
            "\nLogin (UAT):\n"
            f"  Forensic Analyst : username uat_forensic / password {password}\n"
            f"  Red Team Manager : username uat_redteam  / password {password}\n"
            "Then open the 'Response' item in the sidebar to see the queue."
        ))

    # ── users ────────────────────────────────────────────────────────────── #

    def _ensure_users(self, password):
        result = {}
        # Response-team logins get a usable password.
        for c in _LOGIN_USERS:
            user, _ = User.objects.get_or_create(
                username=c["username"],
                defaults=dict(first_name=c["first"], last_name=c["last"],
                              email=f"{c['username']}@uat.local", is_active=True),
            )
            user.email = user.email or f"{c['username']}@uat.local"
            user.set_password(password)
            user.save()
            UserProfile.objects.update_or_create(
                user=user,
                defaults=dict(role=c["role"], tier="",
                              department=c["dept"], phone=c["phone"]),
            )
            result[c["role"]] = user
        # SOC-side authors — attribution only, unusable password.
        for c in _AUTHOR_USERS:
            user, was_created = User.objects.get_or_create(
                username=c["username"],
                defaults=dict(first_name=c["first"], last_name=c["last"],
                              email=f"{c['username']}@uat.local", is_active=True),
            )
            if was_created:
                user.set_unusable_password()
                user.save()
            UserProfile.objects.get_or_create(
                user=user,
                defaults=dict(role=c["role"], tier=c["tier"],
                              department=c["dept"], phone=c["phone"]),
            )
            result[c["key"]] = user
        return result

    # ── data ─────────────────────────────────────────────────────────────── #

    def _create_scenario(self, sc, users, now):
        t1, t2 = users["T1"], users["T2"]
        admin = users["ADMIN"]
        responder = (users[UserProfile.ROLE_FORENSIC] if sc["who"] == "FORENSIC"
                     else users[UserProfile.ROLE_REDTEAM_MANAGER])

        inc_time = now - timedelta(hours=8)
        contained = sc["status"] in (S.STATUS_CONTAINMENT_REPORTED, S.STATUS_PENDING_MANAGER)
        verified = sc["status"] == S.STATUS_PENDING_MANAGER  # Tier-2 signed off already

        ticket = Ticket.objects.create(
            status            = sc["status"],
            classification    = S.CLASSIFICATION_INCIDENT,
            t1_route          = S.T1_ROUTE_ADMIN,
            severity          = sc["severity"],
            is_emergency      = sc["emergency"],
            ip_address        = "10.20.30.40",
            device_name       = sc["device"],
            issue_description = f'{sc["desc"]} {MARKER} {sc["status"]}',
            issue_type        = "SIEM",
            created_by        = t1,
            assigned_to       = t1,
            assigned_admin    = admin,
            containment_report= "ดำเนินการกักกันเบื้องต้นแล้ว (demo)." if contained else "",
            verified_by       = t2 if verified else None,
            verified_at       = inc_time + timedelta(hours=2) if verified else None,
            escalated_to_t2_at= inc_time + timedelta(minutes=30),
            incident_datetime = inc_time,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=inc_time)

        TicketLog.objects.create(
            ticket=ticket, author=t1,
            note=f"RESPONSE-DEMO: placed directly in {sc['status']}",
            status_at_time=sc["status"],
        )

        subtask = TicketSubtask.objects.create(
            ticket=ticket,
            subtask_type=sc["req_type"],
            title=sc["req_title"],
            description=sc["req_desc"],
            status=sc["req_status"],
            assigned_to=responder,
            created_by=users["MANAGER"],
            result_notes=sc["req_notes"],
        )

        if sc["report"]:
            self._attach_report(ticket, subtask, responder)
        return ticket

    def _attach_report(self, ticket, subtask, responder):
        """A small text 'report' so the responder's deliverable + the hardened
        download path have something real to exercise. Non-fatal on storage
        errors so a misconfigured MEDIA_ROOT can't break the whole seed."""
        try:
            att = TicketAttachment(
                ticket=ticket, subtask=subtask, uploaded_by=responder,
                original_name="forensic_rca_report.txt",
                description="Forensic RCA report (demo deliverable)",
            )
            att.file.save(
                "forensic_rca_report.txt",
                ContentFile(
                    "FORENSIC RCA REPORT (DEMO)\n"
                    "==========================\n"
                    f"Ticket: {ticket.ticket_id}\n"
                    "Root cause: macro-enabled .xlsm dropper opened from email.\n"
                    "Scope: single host; no lateral movement observed.\n"
                    "Recommendation: block macro execution from internet-sourced files.\n"
                    .encode("utf-8")
                ),
                save=True,
            )
        except Exception as exc:
            self.stderr.write(self.style.WARNING(
                f"  (report attachment skipped for {ticket.ticket_id}: {exc})"
            ))
