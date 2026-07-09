"""
apps/incidents/management/commands/seed_data.py

Populates the database with synthetic SOC ticket data for dashboard testing.
Safe to run multiple times (idempotent). All seeded rows are tagged with the
'seed_' username prefix so --flush can cleanly remove them.

Usage:
    python manage.py seed_data                      # 100 tickets, 30 days
    python manage.py seed_data --tickets 200 --days 90
    python manage.py seed_data --flush              # wipe seed data, then re-seed
    python manage.py seed_data --flush --tickets 0  # wipe only, no re-seed
"""

import random
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.incidents.models import Ticket, TicketLog
from apps.accounts.models import UserProfile

SEED_PREFIX = "seed_"

STATUS_POOL = [
    "NEW", "ESCALATED_T2", "T1_REVIEW", "AWAITING_CONTAINMENT",
    "CONTAINMENT_REPORTED", "PENDING_MANAGER", "APPROVED", "CLOSED_EVENT",
]
STATUS_WEIGHTS = [20, 10, 10, 10, 10, 10, 15, 15]

# Statuses that imply Tier 2 has already verified (verified_by populated).
PAST_T2_SIGNOFF = {"PENDING_MANAGER", "APPROVED"}
# Statuses that have manager final sign-off (approved_by populated).
MANAGER_APPROVED = {"APPROVED"}
# Statuses that are part of the incident-handling flow (classification=INCIDENT).
INCIDENT_FLOW = {
    "T1_REVIEW", "AWAITING_CONTAINMENT", "CONTAINMENT_REPORTED",
    "PENDING_MANAGER", "APPROVED",
}
# Statuses where an admin is actively assigned for containment.
ADMIN_ASSIGNED = {"AWAITING_CONTAINMENT", "CONTAINMENT_REPORTED"}

# Approximate lifecycle path to reach each status — used to generate TicketLog
# audit entries. CLOSED_EVENT is the Event fast-path (skips containment).
LIFECYCLE_PATHS = {
    "NEW":                  ["NEW"],
    "ESCALATED_T2":         ["NEW", "ESCALATED_T2"],
    "T1_REVIEW":            ["NEW", "ESCALATED_T2", "T1_REVIEW"],
    "AWAITING_CONTAINMENT": ["NEW", "ESCALATED_T2", "T1_REVIEW", "AWAITING_CONTAINMENT"],
    "CONTAINMENT_REPORTED": ["NEW", "ESCALATED_T2", "T1_REVIEW",
                             "AWAITING_CONTAINMENT", "CONTAINMENT_REPORTED"],
    "PENDING_MANAGER":      ["NEW", "ESCALATED_T2", "T1_REVIEW", "AWAITING_CONTAINMENT",
                             "CONTAINMENT_REPORTED", "PENDING_MANAGER"],
    "APPROVED":             ["NEW", "ESCALATED_T2", "T1_REVIEW", "AWAITING_CONTAINMENT",
                             "CONTAINMENT_REPORTED", "PENDING_MANAGER", "APPROVED"],
    "CLOSED_EVENT":         ["NEW", "ESCALATED_T2", "T1_REVIEW", "CLOSED_EVENT"],
}

# ── Valid choice strings read from apps/incidents/models.py ───────────────────
ISSUE_TYPE_POOL     = ["SIEM", "ADMIN", "TI", "EMAIL", "PHONE", "USER_REPORT", "EXTERNAL", "OTHER"]
DETAILED_ISSUE_POOL = [
    "Investigating", "Reconnaissance", "Malicious Logic", "User Intrusion",
    "Root Intrusion", "DoS", "Non-Compliance", "Unsuccessful Attempt",
    "Explained Anomaly", "Training",
]
DETAILED_ISSUE2_POOL = [
    "Investigating Other", "Port Scanning", "Malware EDR", "C2 Server",
    "Ransomware Behavior", "Failed Login", "SSH Failed", "Privilege Escalation",
    "Impossible Travel", "DDoS",
]


class Command(BaseCommand):
    help = "Seed the database with synthetic SOC ticket data for dashboard testing."

    def add_arguments(self, parser):
        parser.add_argument("--tickets", type=int, default=100,
                            help="Number of tickets to create (default: 100)")
        parser.add_argument("--days", type=int, default=30,
                            help="Spread tickets over this many past days (default: 30)")
        parser.add_argument("--flush", action="store_true",
                            help="Delete all previous seed data before seeding")

    def handle(self, *args, **options):
        n_tickets = options["tickets"]
        n_days    = options["days"]

        if options["flush"]:
            deleted, _ = Ticket.objects.filter(
                created_by__username__startswith=SEED_PREFIX
            ).delete()
            User.objects.filter(username__startswith=SEED_PREFIX).delete()
            self.stdout.write(self.style.WARNING(
                f"Flushed {deleted} seed ticket(s) and their logs/users."
            ))

        if n_tickets == 0:
            return

        now      = timezone.now()
        start_dt = now - timedelta(days=n_days)

        users = self._ensure_users()
        self.stdout.write("Seed users ready: " + ", ".join(users.keys()))

        created = 0
        for i in range(n_tickets):
            try:
                self._create_ticket(users, start_dt, now)
                created += 1
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f"  Ticket #{i + 1} failed: {exc}"))

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {created}/{n_tickets} tickets across the last {n_days} day(s)."
        ))

    def _ensure_users(self):
        configs = [
            dict(key="SOC_STAFF_T1",  username="seed_t1",       role="SOC_STAFF",    tier="T1",
                 first="Kawin",     last="Analyst",  dept="SOC Network",       phone="0800000001"),
            dict(key="SOC_STAFF_T2",  username="seed_t2",       role="SOC_STAFF",    tier="T2",
                 first="Pimchan",   last="Analyst",  dept="SOC Network",       phone="0800000002"),
            dict(key="SOC_MANAGER",   username="seed_manager",  role="SOC_MANAGER",  tier="",
                 first="Somchai",   last="Manager",  dept="SOC Management",    phone="0800000003"),
            dict(key="SYSTEM_ADMIN",  username="seed_sysadmin", role="SYSTEM_ADMIN", tier="",
                 first="Nattapong", last="Admin",    dept="IT Infrastructure", phone="0800000004"),
            dict(key="SYSTEM_OWNER",  username="seed_sysowner", role="SYSTEM_OWNER", tier="",
                 first="Waraporn",  last="Owner",    dept="Business Unit",     phone="0800000005"),
        ]
        result = {}
        for c in configs:
            user, was_created = User.objects.get_or_create(
                username=c["username"],
                defaults=dict(
                    first_name=c["first"], last_name=c["last"],
                    email=f"{c['username']}@nt.seed.local", is_active=True,
                ),
            )
            if was_created:
                user.set_unusable_password()
                user.save()
            UserProfile.objects.get_or_create(
                user=user,
                defaults=dict(
                    role=c["role"], tier=c["tier"],
                    department=c["dept"], phone=c["phone"],
                ),
            )
            result[c["key"]] = user
        return result

    def _create_ticket(self, users, start_dt, now):
        t1      = users["SOC_STAFF_T1"]
        t2      = users["SOC_STAFF_T2"]
        manager = users["SOC_MANAGER"]
        admin   = users["SYSTEM_ADMIN"]
        owner   = users["SYSTEM_OWNER"]

        status = random.choices(STATUS_POOL, weights=STATUS_WEIGHTS, k=1)[0]

        # Keep classification consistent with the lifecycle stage:
        #   CLOSED_EVENT  → EVENT, incident-flow states → INCIDENT,
        #   NEW/ESCALATED_T2 → still being triaged (may be unclassified).
        if status == "CLOSED_EVENT":
            classification = "EVENT"
        elif status in INCIDENT_FLOW:
            classification = "INCIDENT"
        else:
            classification = random.choices(
                ["INCIDENT", "EVENT", ""], weights=[40, 30, 30], k=1
            )[0]

        severity = random.choices(
            ["Critical", "High", "Medium", "Low", "Unknown"],
            weights=[10, 35, 30, 20, 5], k=1,
        )[0]
        is_emergency = random.random() < 0.10
        # PENDING_MANAGER is reachable only via the emergency flag now.
        if status == "PENDING_MANAGER":
            is_emergency = True
        opener       = random.choice([t1, t2])

        offset_s = random.randint(0, int((now - start_dt).total_seconds()))
        inc_time = start_dt + timedelta(seconds=offset_s)

        escalated_to_t2_at = (
            inc_time + timedelta(minutes=random.randint(5, 60))
            if status != "NEW" else None
        )

        verified_by = verified_at = None
        if status in PAST_T2_SIGNOFF:
            verified_by = t2
            verified_at = inc_time + timedelta(hours=random.uniform(1, 6))

        approved_by = approved_at = None
        if status in MANAGER_APPROVED:
            # Non-emergency cases are closed by Tier 2; only emergencies
            # carry the SOC manager's final sign-off.
            approved_by = manager if is_emergency else t2
            approved_at = inc_time + timedelta(hours=random.uniform(6, 24))

        def rand_ip():
            return (f"{random.randint(10, 192)}.{random.randint(0, 255)}"
                    f".{random.randint(0, 255)}.{random.randint(1, 254)}")

        device = random.choice([
            "WIN-SRV-01", "WIN-SRV-02", "LIN-WEB-03", "LIN-WEB-04",
            "FIREWALL-CORE", "DC-PRIMARY", "DC-SECONDARY", "MAIL-GW-02",
            "DB-PROD-01", "JUMPBOX-01", "AP-FLOOR-3", "VPN-GW-01",
            "RADIUS-SRV", "PROXY-01", "SWITCH-DIST-01",
        ])
        description = random.choice([
            "Suspicious outbound connection detected on host.",
            "Multiple failed login attempts from external IP.",
            "Malware signature found in downloaded file.",
            "Unusual privilege escalation event observed.",
            "Potential data exfiltration via DNS tunneling.",
            "Ransomware-like file modification pattern detected.",
            "Lateral movement attempt from compromised account.",
            "Port scan originating from internal subnet.",
            "Brute-force attack targeting RDP service.",
            "Unauthorized access attempt on critical file share.",
            "Suspicious PowerShell execution detected by EDR.",
            "Anomalous login from an unfamiliar country.",
        ])

        issue_type      = random.choice(ISSUE_TYPE_POOL)
        detailed_issue  = random.choice(DETAILED_ISSUE_POOL)
        detailed_issue2 = random.choice(DETAILED_ISSUE2_POOL)

        # Create via ORM — save() auto-mints ticket_id and ola_deadline.
        # Do NOT call transition_to(); it enforces role checks and would reject
        # most direct state assignments.
        ticket = Ticket.objects.create(
            status             = status,
            classification     = classification,
            severity           = severity,
            is_emergency       = is_emergency,
            ip_address         = rand_ip(),
            device_name        = device,
            issue_description  = description,
            issue_type         = issue_type,
            detailed_issue     = detailed_issue,
            detailed_issue2    = detailed_issue2,
            created_by         = opener,
            assigned_to        = random.choice([t1, t2, None, None]),
            assigned_admin     = admin if status in ADMIN_ASSIGNED else None,
            system_owner       = owner if random.random() < 0.5 else None,
            verified_by        = verified_by,
            verified_at        = verified_at,
            approved_by        = approved_by,
            approved_at        = approved_at,
            escalated_to_t2_at = escalated_to_t2_at,
            incident_datetime  = inc_time,
        )

        # created_at is auto_now_add=True, so it can't be passed to create().
        # Backdate it with a queryset update (skips save()/signals).
        Ticket.objects.filter(pk=ticket.pk).update(created_at=inc_time)

        self._create_logs(ticket, inc_time, status, opener)
        return ticket

    def _create_logs(self, ticket, inc_time, final_status, author):
        path     = LIFECYCLE_PATHS.get(final_status, ["NEW"])
        log_time = inc_time
        for state in path:
            # TicketLog: text field is `note`; `status_at_time` is required.
            log = TicketLog.objects.create(
                ticket         = ticket,
                author         = author,
                note           = f"Status set to {state}",
                status_at_time = state,
            )
            # created_at is auto_now_add=True — backdate the same way.
            TicketLog.objects.filter(pk=log.pk).update(created_at=log_time)
            log_time += timedelta(minutes=random.randint(10, 180))
