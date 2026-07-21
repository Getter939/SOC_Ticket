"""
apps/incidents/management/commands/seed_response_demo.py

Seeds dummy Response-Team data so the Forensic Analyst (and Red Team Manager, if
one exists) has a populated "My Requests" queue to exercise during UAT: tickets
carrying response requests in a mix of statuses — fresh, in-progress,
completed-with-report, and one that demonstrates the approval gate (an open
request holding an emergency ticket out of closure).

IT NEVER CREATES OR MODIFIES USER ACCOUNTS. The actors are discovered from the
real database by ROLE, so the command attributes data to whoever actually holds
each role on this environment. In particular it never touches passwords — the
UAT VM runs on real staff accounts.

Prerequisite: the roles must already be assigned in Django admin. If a required
role has no active user the command stops and names it, rather than inventing an
account. Red-team scenarios are skipped (with a notice) when no Red Team Manager
exists; assign that role and re-run to include them.

Every ticket is tagged ``[RESPONSE-DEMO]`` in issue_description so --flush removes
exactly what this command created and nothing a live tester makes.

Usage:
    python manage.py seed_response_demo --dry-run   # show which accounts it would use
    python manage.py seed_response_demo             # seed
    python manage.py seed_response_demo --flush     # wipe demo rows, re-seed
    python manage.py seed_response_demo --flush --no-seed   # wipe only
"""

from datetime import timedelta
from itertools import cycle

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.accounts.models import UserProfile
from apps.incidents.models import Ticket, TicketAttachment, TicketLog, TicketSubtask

MARKER = "[RESPONSE-DEMO]"  # appended to issue_description so --flush is precise
S = Ticket
ST = TicketSubtask

# Each scenario: parent-ticket status + the response request riding on it. Ticket
# fields are pinned so the stage is internally consistent (an admin lane has an
# assigned admin; a CONTAINMENT_REPORTED ticket has a report; the gate demo is
# emergency + Tier-2-verified so it genuinely sits at PENDING_MANAGER).
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
         req_desc="Emergency — ต้องได้ root cause ก่อนปิดเคส (approval-gate demo).",
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
    # Red-team scenarios are seeded only when a Red Team Manager exists.
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
    help = ("Seed dummy Response-Team (Forensic / Red Team) data for UAT, "
            "attributed to the real accounts holding each role.")

    def add_arguments(self, parser):
        parser.add_argument("--flush", action="store_true",
                            help="Delete previous RESPONSE-DEMO rows before seeding")
        parser.add_argument("--no-seed", action="store_true",
                            help="With --flush: wipe only, do not re-seed")
        parser.add_argument("--dry-run", action="store_true",
                            help="Show which accounts would be used, write nothing")

    def handle(self, *args, **options):
        actors = self._resolve_actors()

        if options["dry_run"]:
            self._report_actors(actors)
            runnable = [sc for sc in SCENARIOS if self._responders(sc, actors)]
            self.stdout.write("\nWould seed:")
            for sc in runnable:
                self.stdout.write(
                    f"  [{sc['req_status']:<11}] {sc['req_type']:<13} on a "
                    f"{sc['status']} ticket"
                )
            skipped = len(SCENARIOS) - len(runnable)
            if skipped:
                self.stdout.write(self.style.WARNING(
                    f"  ({skipped} red-team scenario(s) skipped - no Red Team Manager)"
                ))
            self.stdout.write(self.style.SUCCESS("\nDry run - nothing written."))
            return

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

        self._report_actors(actors)

        now = timezone.now()
        # Spread ticket authorship across the real Tier-1 analysts so the audit
        # trail and workload heatmap don't all point at one person.
        creators = cycle(actors["T1"])
        created = skipped = 0
        for sc in SCENARIOS:
            responders = self._responders(sc, actors)
            if not responders:
                skipped += 1
                continue
            try:
                self._create_scenario(sc, actors, responders[0], next(creators), now)
                created += 1
            except Exception as exc:  # keep going; report the offender
                self.stderr.write(self.style.ERROR(f"  {sc['req_title']} failed: {exc}"))

        self.stdout.write(self.style.SUCCESS(
            f"\nSeeded {created} response-team demo ticket(s)."
        ))
        if skipped:
            self.stdout.write(self.style.WARNING(
                f"Skipped {skipped} red-team scenario(s): no active user holds the "
                "Red Team Manager role. Assign it in admin and re-run to add them."
            ))
        self.stdout.write(
            "\nThe Forensic Analyst can now sign in with their OWN existing "
            "credentials\n(no passwords were created or changed) and will land on "
            "the Response queue."
        )

    # ── actors ───────────────────────────────────────────────────────────── #

    def _responders(self, scenario, actors):
        """Users eligible to receive this scenario's request (may be empty)."""
        return actors["FORENSIC"] if scenario["who"] == "FORENSIC" else actors["REDTEAM"]

    def _resolve_actors(self):
        """Find the real accounts by role. Never creates anything."""
        def by_role(role, tier=None):
            qs = User.objects.filter(is_active=True, profile__role=role)
            if tier is not None:
                qs = qs.filter(profile__tier=tier)
            return list(qs.select_related("profile").order_by("username"))

        forensic = by_role(UserProfile.ROLE_FORENSIC)
        redteam = by_role(UserProfile.ROLE_REDTEAM_MANAGER)
        managers = by_role(UserProfile.ROLE_SOC_MANAGER)
        admins = by_role(UserProfile.ROLE_SYSTEM_ADMIN)
        staff = by_role(UserProfile.ROLE_SOC_STAFF)
        # Prefer the correct tier; fall back to any SOC staff so a environment
        # without a tier split still seeds rather than failing.
        t1 = by_role(UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T1) or staff
        t2 = by_role(UserProfile.ROLE_SOC_STAFF, UserProfile.TIER_T2) or staff

        missing = []
        if not forensic:
            missing.append("Forensic Analyst (role FORENSIC)")
        if not managers:
            missing.append("SOC Manager (role SOC_MANAGER)")
        if not admins:
            missing.append("System Admin (role SYSTEM_ADMIN)")
        if not staff:
            missing.append("SOC Staff (role SOC_STAFF)")
        if missing:
            raise CommandError(
                "Cannot seed - no active user holds these role(s):\n  - "
                + "\n  - ".join(missing)
                + "\n\nAssign them in Django admin (Accounts > User profiles), "
                  "then re-run.\nThis command never creates accounts."
            )

        return dict(FORENSIC=forensic, REDTEAM=redteam,
                    MANAGER=managers, ADMIN=admins, T1=t1, T2=t2)

    def _report_actors(self, actors):
        """Print the chosen accounts by username only (no names/emails)."""
        def names(users):
            return ", ".join(u.username for u in users) if users else "(none)"

        self.stdout.write("Using these existing accounts (discovered by role):")
        self.stdout.write(f"  Forensic Analyst : {names(actors['FORENSIC'])}")
        self.stdout.write(f"  Red Team Manager : {names(actors['REDTEAM'])}")
        self.stdout.write(f"  SOC Manager      : {names(actors['MANAGER'][:1])}")
        self.stdout.write(f"  System Admin     : {names(actors['ADMIN'][:1])}")
        self.stdout.write(f"  Tier 1 (authors) : {names(actors['T1'])}")
        self.stdout.write(f"  Tier 2 (verify)  : {names(actors['T2'][:1])}")

    # ── data ─────────────────────────────────────────────────────────────── #

    def _create_scenario(self, sc, actors, responder, creator, now):
        t2 = actors["T2"][0]
        admin = actors["ADMIN"][0]
        manager = actors["MANAGER"][0]

        inc_time = now - timedelta(hours=8)
        contained = sc["status"] in (S.STATUS_CONTAINMENT_REPORTED, S.STATUS_PENDING_MANAGER)
        verified = sc["status"] == S.STATUS_PENDING_MANAGER  # Tier 2 already signed off

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
            created_by        = creator,
            assigned_to       = creator,
            assigned_admin    = admin,
            containment_report= "ดำเนินการกักกันเบื้องต้นแล้ว (demo)." if contained else "",
            verified_by       = t2 if verified else None,
            verified_at       = inc_time + timedelta(hours=2) if verified else None,
            escalated_to_t2_at= inc_time + timedelta(minutes=30),
            incident_datetime = inc_time,
        )
        Ticket.objects.filter(pk=ticket.pk).update(created_at=inc_time)

        TicketLog.objects.create(
            ticket=ticket, author=creator,
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
            created_by=manager,
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
