"""
apps/incidents/management/commands/seed_uat_states.py

Seeds ONE representative ticket in every live state of the current FSM, so a
UAT tester (or a dashboard) never faces an empty queue. Unlike ``seed_data``
(random weighted mix for volume), this command is DETERMINISTIC and covers all
12 statuses — including the four newer ones the volume seeder predates:
PENDING_MGR_TRIAGE, AWAITING_OWNER, OWNER_REMEDIATED, PENDING_T2_REVIEW.

Tickets are attributed to the REAL accounts holding each role (discovered via
apps.incidents.management.seed_actors) — this command never creates, modifies
or deletes a user. Every row carries the 'UAT-STATE' marker in
issue_description, so --flush removes exactly what this command created and
nothing a live tester makes during the session.

The owner-lane states (AWAITING_OWNER / OWNER_REMEDIATED) still seed when no
System Owner role is assigned; they simply carry a null system_owner.

Usage:
    python manage.py seed_uat_states                 # 1 ticket per state (12)
    python manage.py seed_uat_states --per-state 3   # 3 per state (36)
    python manage.py seed_uat_states --flush         # wipe UAT-STATE rows, re-seed
    python manage.py seed_uat_states --flush --per-state 0   # wipe only
"""

import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.incidents.management import seed_actors
from apps.incidents.models import Ticket, TicketLog

MARKER = "[UAT-STATE]"  # appended to issue_description so --flush is precise

S = Ticket  # shorthand for status/route/classification constants

# One recipe per live status. Each recipe pins the fields that MUST be
# consistent with the lifecycle stage so dashboards, OLA buckets and the
# manager-queue badge all render truthfully.
#   classification: '' unclassified, 'INCIDENT', or 'EVENT'
#   route:          t1_route once a handling lane is chosen
#   admin/owner:    whether an assigned_admin / system_owner is attached
#   t2_signed:      verified_by populated (Tier 2 has verified containment)
#   mgr_approved:   approved_by populated (final sign-off)
#   emergency:      forces is_emergency (PENDING_MANAGER is emergency-only)
RECIPES = [
    # status,                     classification,  route,          admin, owner, t2_signed, mgr_approved, emergency
    (S.STATUS_NEW,                "",              "",             False, False, False, False, False),
    (S.STATUS_ESCALATED_T2,      "",              "",             False, False, False, False, False),
    (S.STATUS_T1_REVIEW,         S.CLASSIFICATION_INCIDENT, "",   False, False, False, False, False),
    (S.STATUS_PENDING_MGR_TRIAGE, S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_ADMIN, False, False, False, False, False),
    (S.STATUS_AWAITING_CONTAINMENT, S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_ADMIN, True, False, False, False, False),
    (S.STATUS_CONTAINMENT_REPORTED, S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_ADMIN, True, False, False, False, False),
    (S.STATUS_AWAITING_OWNER,    S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_OWNER, False, True, False, False, False),
    (S.STATUS_OWNER_REMEDIATED,  S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_OWNER, False, True, False, False, False),
    (S.STATUS_PENDING_T2_REVIEW, S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_OWNER, False, True, False, False, False),
    (S.STATUS_PENDING_MANAGER,   S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_ADMIN, True, False, True, False, True),
    (S.STATUS_APPROVED,          S.CLASSIFICATION_INCIDENT, S.T1_ROUTE_ADMIN, True, False, True, True, False),
    (S.STATUS_CLOSED_EVENT,      S.CLASSIFICATION_EVENT, "",       False, False, False, False, False),
]

DEVICES = ["WIN-SRV-01", "LIN-WEB-03", "DC-PRIMARY", "MAIL-GW-02",
           "DB-PROD-01", "VPN-GW-01", "PROXY-01", "FIREWALL-CORE"]
DESCRIPTIONS = [
    "Suspicious outbound connection detected on host.",
    "Multiple failed login attempts from external IP.",
    "Malware signature found in downloaded file.",
    "Potential data exfiltration via DNS tunneling.",
    "Brute-force attack targeting RDP service.",
    "Anomalous login from an unfamiliar country.",
]


class Command(BaseCommand):
    help = "Seed one representative ticket in every FSM state for UAT."

    def add_arguments(self, parser):
        parser.add_argument("--per-state", type=int, default=1,
                            help="Tickets to create per status (default: 1)")
        parser.add_argument("--flush", action="store_true",
                            help="Delete previous UAT-STATE seed rows before seeding")

    def handle(self, *args, **options):
        per_state = options["per_state"]

        if options["flush"]:
            _, per_model = Ticket.objects.filter(
                issue_description__contains=MARKER,
            ).delete()
            self.stdout.write(self.style.WARNING(
                f"Flushed {per_model.get('incidents.Ticket', 0)} UAT-STATE "
                "ticket(s) (logs cascade). No user accounts were touched."
            ))

        if per_state <= 0:
            return

        users = seed_actors.resolve()
        seed_actors.require(users, "T1", "T2", "MANAGER", "ADMIN")
        self.stdout.write("Attributing to existing accounts (discovered by role):")
        self.stdout.write(seed_actors.summary(
            users, ["T1", "T2", "MANAGER", "ADMIN", "OWNER"]))

        now = timezone.now()
        created = 0
        for recipe in RECIPES:
            for _ in range(per_state):
                try:
                    self._create_ticket(users, recipe, now)
                    created += 1
                except Exception as exc:
                    self.stderr.write(self.style.ERROR(
                        f"  {recipe[0]} failed: {exc}"
                    ))

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {created} ticket(s) across {len(RECIPES)} states "
            f"({per_state} per state)."
        ))

    def _create_ticket(self, users, recipe, now):
        (status, classification, route, want_admin, want_owner,
         t2_signed, mgr_approved, emergency) = recipe

        # Pick a different real person per ticket so the audit trail and the
        # analyst workload heatmap spread across the team.
        t1, t2 = random.choice(users["T1"]), random.choice(users["T2"])
        manager = random.choice(users["MANAGER"])
        admin = random.choice(users["ADMIN"])
        # Optional: stays None when nobody holds the System Owner role, so the
        # owner-lane states still seed (with a null owner) rather than break.
        owner = random.choice(users["OWNER"]) if users["OWNER"] else None

        # Backdate so OLA buckets and "time in state" are realistic.
        inc_time = now - timedelta(hours=random.uniform(2, 72))

        severity = random.choice(["Critical", "High", "Medium", "Low"])
        if emergency:
            severity = "Critical"

        escalated_at = (inc_time + timedelta(minutes=random.randint(5, 60))
                        if status != S.STATUS_NEW else None)

        verified_by = verified_at = None
        if t2_signed:
            verified_by = t2
            verified_at = inc_time + timedelta(hours=random.uniform(1, 6))

        approved_by = approved_at = None
        if mgr_approved:
            approved_by = manager if emergency else t2
            approved_at = inc_time + timedelta(hours=random.uniform(6, 24))

        ip = (f"{random.randint(10, 200)}.{random.randint(0, 255)}"
              f".{random.randint(0, 255)}.{random.randint(1, 254)}")
        description = f"{random.choice(DESCRIPTIONS)} {MARKER} {status}"

        ticket = Ticket.objects.create(
            status             = status,
            classification     = classification,
            t1_route           = route,
            severity           = severity,
            is_emergency       = emergency,
            ip_address         = ip,
            device_name        = random.choice(DEVICES),
            issue_description  = description,
            issue_type         = "SIEM",
            created_by         = t1,
            assigned_to        = t1,
            assigned_admin     = admin if want_admin else None,
            system_owner       = owner if want_owner else None,
            verified_by        = verified_by,
            verified_at        = verified_at,
            approved_by        = approved_by,
            approved_at        = approved_at,
            escalated_to_t2_at = escalated_at,
            incident_datetime  = inc_time,
        )
        # created_at is auto_now_add — backdate via queryset update (no save()).
        Ticket.objects.filter(pk=ticket.pk).update(created_at=inc_time)

        TicketLog.objects.create(
            ticket=ticket, author=t1,
            note=f"UAT seed: placed directly in {status}",
            status_at_time=status,
        )
        return ticket
