import re
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.utils import timezone

from .. import ola
from ..ip_addresses import IP_ADDRESSES_HELP, validate_ip_addresses
from .choices import (
    SOURCE_SIEM, SOURCE_CHOICES,
)
from .project import ProjectIncident

class TicketQuerySet(models.QuerySet):
    def visible_to(self, user):
        """
        Return the subset of tickets the given user is allowed to see.

        Rules (single authoritative place — never bypass this):
          - SOC staff / SOC manager       → all tickets
          - System admin                  → only tickets where assigned_admin == user
          - Forensic Analyst              → all tickets, READ-ONLY (see below)
          - Red Team Manager              → only tickets carrying a RESPONSE
                                            request OF THEIR OWN TYPE assigned
                                            to them
          - No profile / unknown role     → empty queryset (safest default)
        """
        if user.is_superuser:
            return self
        profile = getattr(user, 'profile', None)
        if profile is None:
            return self.none()
        if profile.is_soc:
            return self
        if profile.is_system_admin:
            return self.filter(assigned_admin=user)
        if profile.is_system_owner:
            return self.filter(system_owner=user)
        # The Forensic Analyst reads the whole case load — correlating an
        # indicator across incidents is the job, and that is impossible through
        # a keyhole of only the cases assigned to them.
        #
        # This grants READING only, and deliberately needs no extra guard: every
        # write gate is an independent ROLE test that excludes Forensic, not a
        # "can you see it" test — can_edit_ticket (ends at is_soc),
        # holds_ticket_court (no Forensic branch, so no attachment upload),
        # user_can_drive (tier1-creator/tier2/manager only),
        # can_restore_ticket_attachment (is_soc_manager) and
        # can_access_ticket_report (is_soc). Their single write path is
        # unchanged: the deliverable on a response request assigned to them
        # (can_upload_subtask_result), which is keyed to the SUBTASK.
        if profile.is_forensic:
            return self
        # Red Team Manager gets response-only access: a ticket is visible
        # solely because it carries a RESPONSE-type request assigned to them —
        # never because they were handed an ordinary Investigation/Countermeasure
        # subtask. distinct() guards against duplicates when several are assigned.
        #
        # types_for_role() rather than RESPONSE_TYPES: the request must also be
        # one their role actually receives. Assignment alone is not enough,
        # because assignment is only validated in TicketSubtask.clean() — a row
        # written by a seed, a data migration, or objects.create() can hand a
        # Red Team Manager a FORENSIC_RCA request, and that must not become a
        # key to the ticket. Read-time enforcement is what closes that path.
        if profile.is_response_team:
            return self.filter(
                subtasks__assigned_to=user,
                subtasks__subtask_type__in=TicketSubtask.types_for_role(profile.role),
            ).distinct()
        return self.none()

    def with_severity_rank(self):
        """Annotate ``sev_rank`` from ``Ticket.SEVERITY_RANK`` for severity ordering.

        ``severity`` is a CharField, so ordering on it directly is alphabetical —
        Critical, High, **Low, Medium**, Unknown — which ranks Low above Medium.
        Order on ``-sev_rank`` instead to get Critical first and Unknown last.
        """
        return self.annotate(sev_rank=models.Case(
            *[models.When(severity=slug, then=models.Value(rank))
              for slug, rank in Ticket.SEVERITY_RANK.items()],
            default=models.Value(0),
            output_field=models.IntegerField(),
        ))


class Ticket(models.Model):
    objects = TicketQuerySet.as_manager()

    # ------------------------------------------------------------------ #
    # Status choices — redesigned SOC workflow                            #
    # ------------------------------------------------------------------ #
    STATUS_NEW                  = 'NEW'
    STATUS_ESCALATED_T2         = 'ESCALATED_T2'
    STATUS_T1_REVIEW            = 'T1_REVIEW'
    # ── SOC Manager pre-containment review (blocking) ────────────────── #
    # Every Incident passes through the SOC Manager before it reaches a
    # handling lane. The manager flags Emergency (yes/no) and forwards; they
    # cannot divert the case — the lane is fixed by Tier 1's ``t1_route``
    # (ADMIN → AWAITING_CONTAINMENT, OWNER → AWAITING_OWNER). See the
    # deterministic t1_route guard in can_transition_to / transition_to.
    STATUS_PENDING_MGR_TRIAGE   = 'PENDING_MGR_TRIAGE'
    STATUS_AWAITING_CONTAINMENT = 'AWAITING_CONTAINMENT'
    STATUS_CONTAINMENT_REPORTED = 'CONTAINMENT_REPORTED'
    # ── Direct-to-Owner fast path (any severity) ─────────────────────── #
    # A T1 handling route that skips the System Admin entirely: the analyst
    # contacts the asset owner directly (e.g. by phone) and the owner remediates
    # it themselves — no admin ticket, no containment email. The case is still
    # tracked (AWAITING_OWNER) and always passes mandatory Tier 2 verification
    # (AWAITING_OWNER → PENDING_T2_REVIEW); emergency tickets additionally
    # pass the SOC manager (PENDING_T2_REVIEW → PENDING_MANAGER). See the
    # deterministic emergency split in can_transition_to / transition_to.
    STATUS_AWAITING_OWNER       = 'AWAITING_OWNER'
    # LEGACY — nothing transitions INTO this any more. Tier 1 used to stop here
    # to record the owner's report before forwarding, which cost two clicks for
    # one act. Retained so tickets already in this status can still finish; see
    # ALLOWED_TRANSITIONS. Do not add a new edge into it.
    STATUS_OWNER_REMEDIATED     = 'OWNER_REMEDIATED'
    STATUS_PENDING_T2_REVIEW    = 'PENDING_T2_REVIEW'
    STATUS_PENDING_MANAGER      = 'PENDING_MANAGER'
    # Counter-measure gate: when Tier 2 downgrades an escalated Incident to an
    # Event, the SOC Manager verifies that call before the case closes, so a
    # ticket cannot be quietly disposed of by reclassifying it. Confirming an
    # Event that Tier 1 already classified as one does NOT come through here.
    STATUS_PENDING_MGR_EVENT_REVIEW = 'PENDING_MGR_EVENT_REVIEW'
    # Watch-and-wait: Tier 2 decided the case is not yet an Event or an Incident
    # and parked it under Tier 1 for a fixed monitoring window (see
    # MONITORING_DURATION_DAYS). If something happens Tier 1 issues it as an
    # Incident; if the window closes quietly Tier 1 concludes it an Event. A case
    # can be monitored at most once (has_been_monitored).
    STATUS_MONITORING           = 'MONITORING'
    STATUS_APPROVED             = 'APPROVED'
    STATUS_CLOSED_EVENT         = 'CLOSED_EVENT'
    STATUS_CANCELLED            = 'CANCELLED'

    # Fixed monitoring window. Not analyst-configurable on purpose: 30 days is
    # the absolute watch duration, with no extension and no second round.
    MONITORING_DURATION_DAYS = 30

    STATUS_CHOICES = [
        (STATUS_NEW,                  'กำลังจัดเตรียม (ยังไม่ส่ง)'),
        (STATUS_ESCALATED_T2,         'ส่งต่อให้ Tier 2'),
        (STATUS_MONITORING,           'กำลังเฝ้าระวัง (Monitoring)'),
        (STATUS_T1_REVIEW,            'รอ Tier 1 ทบทวน'),
        (STATUS_PENDING_MGR_TRIAGE,   'รอผู้จัดการ SOC ตรวจ (ก่อนมอบหมาย)'),
        (STATUS_AWAITING_CONTAINMENT, 'รอการจัดการจากผู้ดูแลระบบ'),
        (STATUS_CONTAINMENT_REPORTED, 'รายงานการควบคุมแล้ว'),
        (STATUS_AWAITING_OWNER,       'รอเจ้าของระบบดำเนินการเอง'),
        (STATUS_OWNER_REMEDIATED,     'เจ้าของแจ้งแก้ไขแล้ว — รอ SOC ตรวจ'),
        (STATUS_PENDING_T2_REVIEW,    'รอ Tier 2 ตรวจสอบ'),
        (STATUS_PENDING_MANAGER,      'รอผู้จัดการตรวจสอบ'),
        (STATUS_PENDING_MGR_EVENT_REVIEW, 'รอผู้จัดการตรวจสอบการปิดแบบ Event'),
        (STATUS_APPROVED,             'อนุมัติแล้ว'),
        (STATUS_CLOSED_EVENT,         'ปิด (Event)'),
        (STATUS_CANCELLED,            'ยกเลิกแล้ว'),
    ]

    # States where no further action is possible
    RESOLVED_STATUSES = frozenset({STATUS_APPROVED, STATUS_CLOSED_EVENT})
    TERMINAL_STATUSES = RESOLVED_STATUSES | {STATUS_CANCELLED}

    # ------------------------------------------------------------------ #
    # Status pill colors — SINGLE SOURCE OF TRUTH                          #
    #                                                                     #
    # Every status color-coded surface (dashboard + executive pills,      #
    # the ticket-list badge, and the Tier-2 queue stage badges) reads     #
    # from this map via `status_pill_css`, so a status always renders the #
    # same color everywhere. Each entry is (background, text-color).       #
    #                                                                     #
    # Ordering follows the workflow and "whose court the ball is in":     #
    # SOC intake/review (blue/cyan/purple) → blocked on an external actor #
    # (orange = admin, pink = owner) → work reported / verifying (teal    #
    # pair) → awaiting sign-off (steel = T2, amber = manager) → terminal  #
    # (green = approved, gray = closed event).                            #
    #                                                                     #
    # Red (#dc3545) is deliberately RESERVED for danger signals —         #
    # Critical severity, Emergency, and OLA breach — and is never used    #
    # as a status color, so those alarms stay unambiguous.                #
    # ------------------------------------------------------------------ #
    STATUS_PILL_COLORS = {
        STATUS_NEW:                  ('#0d6efd', '#ffffff'),  # blue — open, awaiting triage
        STATUS_ESCALATED_T2:         ('#6f42c1', '#ffffff'),  # purple — up to Tier 2
        STATUS_MONITORING:           ('#4c6ef5', '#ffffff'),  # indigo — watch-and-wait under Tier 1
        STATUS_T1_REVIEW:            ('#0dcaf0', '#212529'),  # cyan — back to Tier 1
        STATUS_PENDING_MGR_TRIAGE:   ('#d4a017', '#212529'),  # goldenrod — SOC Manager pre-containment review
        STATUS_AWAITING_CONTAINMENT: ('#fd7e14', '#ffffff'),  # orange — blocked on System Admin
        STATUS_CONTAINMENT_REPORTED: ('#20c997', '#212529'),  # teal — admin reported, verifying
        STATUS_AWAITING_OWNER:       ('#d63384', '#ffffff'),  # pink — blocked on System Owner
        STATUS_OWNER_REMEDIATED:     ('#0d9488', '#ffffff'),  # deep teal — owner reported, verifying
        STATUS_PENDING_T2_REVIEW:    ('#3d5a80', '#ffffff'),  # steel — awaiting Tier 2 sign-off
        STATUS_PENDING_MANAGER:      ('#ffc107', '#212529'),  # amber — awaiting manager sign-off
        STATUS_PENDING_MGR_EVENT_REVIEW: ('#b5651d', '#ffffff'),  # burnt orange — manager verifying an Event downgrade
        STATUS_APPROVED:             ('#198754', '#ffffff'),  # green — resolved / approved
        STATUS_CLOSED_EVENT:         ('#6c757d', '#ffffff'),  # gray — closed as event
        STATUS_CANCELLED:            ('#495057', '#ffffff'),
    }

    @property
    def status_pill_css(self):
        """Inline ``background``/``color`` for this ticket's status pill.

        Shared by all status color-coded surfaces so a status looks the
        same everywhere. Unknown statuses fall back to neutral gray.
        """
        bg, fg = self.STATUS_PILL_COLORS.get(self.status, ('#6c757d', '#ffffff'))
        return f'background:{bg};color:{fg};'

    @property
    def status_color(self):
        """Base hex for this ticket's status — for dot/stripe accents."""
        return self.STATUS_PILL_COLORS.get(self.status, ('#6c757d', '#ffffff'))[0]

    @property
    def status_pill_soft_css(self):
        """Soft (tinted) status style for dense tables.

        A lighter 'material' than the solid severity badge — a 10% tint of
        the status hue with a darkened, readable ink — so a status column
        never reads as another severity column. Same hue as
        :attr:`status_pill_css`, just a quieter treatment.
        """
        bg = self.status_color
        return f'background:{bg}1a;color:{self._mix_hex(bg, 0.55)};border:1px solid {bg}33;'

    @staticmethod
    def _mix_hex(hex_color, factor):
        """Darken ``#rrggbb`` toward black by ``factor`` (0-1). Returns hex."""
        h = hex_color.lstrip('#')
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        return '#{:02x}{:02x}{:02x}'.format(*(int(c * factor) for c in (r, g, b)))

    # ------------------------------------------------------------------ #
    # Event / Incident classification (replaces the old TP/FP disposition) #
    #   INCIDENT — actionable case that proceeds to containment (was TP)   #
    #   EVENT    — benign case that gets closed (was FP)                   #
    # Set by Tier 1 in the create flow; may be revised by Tier 2 on an     #
    # escalated ticket. Every ticket carries an explicit value.            #
    # ------------------------------------------------------------------ #
    CLASSIFICATION_INCIDENT = 'INCIDENT'
    CLASSIFICATION_EVENT    = 'EVENT'

    CLASSIFICATION_CHOICES = [
        (CLASSIFICATION_INCIDENT, 'Incident (เหตุการณ์จริง)'),
        (CLASSIFICATION_EVENT,    'Event (ไม่เป็นภัย)'),
    ]

    # ------------------------------------------------------------------ #
    # Tier-1 handling route for an Incident — chosen by Tier 1, then      #
    # remembered so the SOC Manager pre-containment review can forward    #
    # the ticket to the predetermined lane without being able to change   #
    # it. ADMIN → AWAITING_CONTAINMENT, OWNER → AWAITING_OWNER.           #
    # Blank until Tier 1 commits an Incident to PENDING_MGR_TRIAGE.        #
    # ------------------------------------------------------------------ #
    T1_ROUTE_ADMIN = 'ADMIN'
    T1_ROUTE_OWNER = 'OWNER'

    T1_ROUTE_CHOICES = [
        (T1_ROUTE_ADMIN, 'มอบหมายผู้ดูแลระบบ (System Admin)'),
        (T1_ROUTE_OWNER, 'ให้เจ้าของระบบแก้ไขเอง (Direct-to-Owner)'),
    ]

    # ------------------------------------------------------------------ #
    # State-machine: legal transitions                                    #
    # ------------------------------------------------------------------ #
    ALLOWED_TRANSITIONS = {
        STATUS_NEW: [
            STATUS_PENDING_MGR_TRIAGE,     # Incident → SOC Manager pre-containment review
            STATUS_ESCALATED_T2,           # Event or Incident → escalate to Tier 2
        ],
        STATUS_ESCALATED_T2: [
            STATUS_T1_REVIEW,              # Incident → T2 returns to Tier 1
            # Event that Tier 1 already classified → T2 confirms & closes.
            STATUS_CLOSED_EVENT,
            # Event that T2 downgraded from Incident → SOC Manager verifies.
            STATUS_PENDING_MGR_EVENT_REVIEW,
            # Not yet Event or Incident → Tier 2 parks it under Tier 1 to watch
            # (once only — gated on has_been_monitored).
            STATUS_MONITORING,
        ],
        # ── Watch-and-wait (Tier 1 court, fixed window) ──────────────────── #
        STATUS_MONITORING: [
            STATUS_PENDING_MGR_TRIAGE,     # something happened → issue as Incident
            STATUS_ESCALATED_T2,           # window closed quietly → conclude Event (T2 confirms close)
        ],
        STATUS_PENDING_MGR_EVENT_REVIEW: [
            STATUS_CLOSED_EVENT,           # manager agrees it is benign → close
            STATUS_ESCALATED_T2,           # manager disagrees → back to Tier 2 as Incident
        ],
        STATUS_T1_REVIEW: [
            STATUS_PENDING_MGR_TRIAGE,     # T1 reviews → SOC Manager pre-containment review
        ],
        # ── SOC Manager pre-containment review (blocking, Incident-only) ─ #
        STATUS_PENDING_MGR_TRIAGE: [
            STATUS_T1_REVIEW,            # manager returns an incomplete case to its creator
            STATUS_AWAITING_CONTAINMENT,   # manager forwards → admin lane (t1_route=ADMIN)
            STATUS_AWAITING_OWNER,         # manager forwards → owner lane (t1_route=OWNER)
        ],
        STATUS_AWAITING_CONTAINMENT: [
            STATUS_CONTAINMENT_REPORTED,   # admin submits report → Tier 2 verifies
            STATUS_PENDING_MGR_TRIAGE,     # ↩ manager step-back (see STEP_BACK_EDGES)
        ],
        STATUS_CONTAINMENT_REPORTED: [
            STATUS_AWAITING_CONTAINMENT,   # T2: not contained → back to admin (loop)
            STATUS_PENDING_MANAGER,        # T2 verified + emergency → SOC Manager
            STATUS_APPROVED,               # T2 verified + not emergency → close
            STATUS_CLOSED_EVENT,           # T2 reclassifies as Event → close (no manager)
        ],
        # ── Direct-to-Owner path ─────────────────────────────────────── #
        STATUS_AWAITING_OWNER: [
            # One action: Tier 1 attaches whatever the owner sent, records what
            # they reported in the transition note, and hands to Tier 2. This
            # used to stop at OWNER_REMEDIATED first — two clicks by the same
            # person for one act, the first of which existed mainly to unlock
            # Tier 1's own upload permission.
            STATUS_PENDING_T2_REVIEW,
            STATUS_PENDING_MGR_TRIAGE,     # ↩ manager step-back (see STEP_BACK_EDGES)
        ],
        # LEGACY — no edge leads here any more (AWAITING_OWNER now goes straight
        # to PENDING_T2_REVIEW). Kept reachable-OUT so tickets already sitting
        # in this status can still finish; do not wire a new edge back into it.
        STATUS_OWNER_REMEDIATED: [
            STATUS_PENDING_T2_REVIEW,      # always → Tier 2 verifies (mandatory)
            STATUS_AWAITING_OWNER,         # ↩ manager step-back (see STEP_BACK_EDGES)
        ],
        STATUS_PENDING_T2_REVIEW: [
            STATUS_APPROVED,               # T2 verified + not emergency → close
            STATUS_PENDING_MANAGER,        # T2 verified + emergency → SOC Manager
            STATUS_AWAITING_OWNER,         # Tier 2 rejects → back to owner
            STATUS_CLOSED_EVENT,           # T2 reclassifies as Event → close (no manager)
        ],
        STATUS_PENDING_MANAGER: [
            STATUS_APPROVED,               # manager verifies → close
            # ↩ manager step-back to the lane Tier 1 fixed (see STEP_BACK_EDGES);
            # the t1_route gate below allows exactly one of these per ticket.
            STATUS_CONTAINMENT_REPORTED,   # admin lane  (t1_route=ADMIN)
            STATUS_PENDING_T2_REVIEW,      # owner lane  (t1_route=OWNER)
        ],
        STATUS_APPROVED:     [],
        STATUS_CLOSED_EVENT: [],
        STATUS_CANCELLED:    [],
    }

    # ------------------------------------------------------------------ #
    # Permission map: (from, to) → required permission token             #
    #   TIER1_CREATOR — profile.is_tier1 AND user == created_by           #
    #   TIER2         — profile.is_tier2                                   #
    #   ASSIGNED_ADMIN— user == assigned_admin                            #
    #   MANAGER       — profile.is_soc_manager                            #
    #   MANAGER_STEP_BACK — is_soc_manager, on a backward STEP_BACK_EDGE   #
    # ------------------------------------------------------------------ #
    TRANSITION_PERMISSIONS = {
        (STATUS_NEW,                  STATUS_PENDING_MGR_TRIAGE):   'TIER1_CREATOR',
        (STATUS_NEW,                  STATUS_ESCALATED_T2):         'TIER1_CREATOR',
        (STATUS_ESCALATED_T2,         STATUS_T1_REVIEW):           'TIER2',
        (STATUS_ESCALATED_T2,         STATUS_CLOSED_EVENT):        'TIER2',
        (STATUS_ESCALATED_T2,         STATUS_PENDING_MGR_EVENT_REVIEW): 'TIER2',
        # Tier 2 parks the case under Tier 1 to watch (verifies a Tier 1
        # monitoring proposal, or decides it themselves).
        (STATUS_ESCALATED_T2,         STATUS_MONITORING):          'TIER2',
        # Watch window resolves — the owning Tier 1 concludes it. Incident goes
        # to SOC Manager triage; Event goes back to Tier 2 to confirm the close.
        (STATUS_MONITORING,           STATUS_PENDING_MGR_TRIAGE):   'TIER1_CREATOR',
        (STATUS_MONITORING,           STATUS_ESCALATED_T2):         'TIER1_CREATOR',
        (STATUS_PENDING_MGR_EVENT_REVIEW, STATUS_CLOSED_EVENT):    'MANAGER',
        (STATUS_PENDING_MGR_EVENT_REVIEW, STATUS_ESCALATED_T2):    'MANAGER',
        (STATUS_T1_REVIEW,            STATUS_PENDING_MGR_TRIAGE):   'TIER1_CREATOR',
        (STATUS_PENDING_MGR_TRIAGE,   STATUS_T1_REVIEW):            'MANAGER',
        # SOC Manager pre-containment review forwards to the fixed lane.
        (STATUS_PENDING_MGR_TRIAGE,   STATUS_AWAITING_CONTAINMENT): 'MANAGER',
        (STATUS_PENDING_MGR_TRIAGE,   STATUS_AWAITING_OWNER):       'MANAGER',
        (STATUS_AWAITING_CONTAINMENT, STATUS_CONTAINMENT_REPORTED): 'ASSIGNED_ADMIN',
        # Containment verification is Tier 2's job (any Tier 2, not the creator).
        (STATUS_CONTAINMENT_REPORTED, STATUS_AWAITING_CONTAINMENT): 'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_PENDING_MANAGER):      'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_APPROVED):             'TIER2',
        (STATUS_CONTAINMENT_REPORTED, STATUS_CLOSED_EVENT):         'TIER2',
        # Direct-to-Owner path. Tier 1 is the owner's proxy — owners are
        # contacted out of band and hold no transition rights of their own —
        # so this edge is clerical: record what the owner reported, hand it
        # over. Adequacy is judged once, by Tier 2, below.
        (STATUS_AWAITING_OWNER,       STATUS_PENDING_T2_REVIEW):    'TIER1_CREATOR',
        # Legacy: only in-flight OWNER_REMEDIATED tickets still use this.
        (STATUS_OWNER_REMEDIATED,     STATUS_PENDING_T2_REVIEW):    'TIER1_CREATOR',
        (STATUS_PENDING_T2_REVIEW,    STATUS_APPROVED):             'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_PENDING_MANAGER):      'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_AWAITING_OWNER):       'TIER2',
        (STATUS_PENDING_T2_REVIEW,    STATUS_CLOSED_EVENT):         'TIER2',
        (STATUS_PENDING_MANAGER,      STATUS_APPROVED):             'MANAGER',
        # ↩ Manager step-back edges (see STEP_BACK_EDGES / step_back()).
        (STATUS_AWAITING_CONTAINMENT, STATUS_PENDING_MGR_TRIAGE):   'MANAGER_STEP_BACK',
        (STATUS_AWAITING_OWNER,       STATUS_PENDING_MGR_TRIAGE):   'MANAGER_STEP_BACK',
        (STATUS_OWNER_REMEDIATED,     STATUS_AWAITING_OWNER):       'MANAGER_STEP_BACK',
        (STATUS_PENDING_MANAGER,      STATUS_CONTAINMENT_REPORTED): 'MANAGER_STEP_BACK',
        (STATUS_PENDING_MANAGER,      STATUS_PENDING_T2_REVIEW):    'MANAGER_STEP_BACK',
    }

    # Backward "step-back" edges a SOC Manager can drive to correct a mis-route.
    # They live in ALLOWED_TRANSITIONS so step_back() runs through transition_to()
    # and inherits every invariant it maintains (status_changed_at, Tier 2 claim
    # clearing, the audit log) instead of a parallel hand-rolled write that has
    # to remember them all a second time. They are NOT part of the forward flow:
    #   • the detail-page action builders skip them (step_back has its own UI);
    #   • can_transition_to/transition_to gate the PENDING_MANAGER pair on t1_route
    #     so a ticket only steps back into the lane Tier 1 fixed;
    #   • the lifecycle-doc sync test excludes them from the forward table.
    # step_back_target() resolves which single edge applies to a given ticket.
    STEP_BACK_EDGES = frozenset({
        (STATUS_AWAITING_CONTAINMENT, STATUS_PENDING_MGR_TRIAGE),
        (STATUS_AWAITING_OWNER,       STATUS_PENDING_MGR_TRIAGE),
        (STATUS_OWNER_REMEDIATED,     STATUS_AWAITING_OWNER),
        (STATUS_PENDING_MANAGER,      STATUS_CONTAINMENT_REPORTED),
        (STATUS_PENDING_MANAGER,      STATUS_PENDING_T2_REVIEW),
    })

    # Monitoring edges are driven by their own dedicated controls (the Tier 2
    # "Monitor" button and the Tier 1 conclude-monitoring buttons), NOT the
    # generic status dropdown / Tier 2 decision list — the conclude edges also
    # set the classification their gate requires, which the generic path cannot.
    # The detail-page action builders skip these, exactly like STEP_BACK_EDGES.
    MONITORING_EDGES = frozenset({
        (STATUS_ESCALATED_T2, STATUS_MONITORING),       # Tier 2 starts the watch
        (STATUS_MONITORING,   STATUS_PENDING_MGR_TRIAGE),  # Tier 1 concludes → Incident
        (STATUS_MONITORING,   STATUS_ESCALATED_T2),        # Tier 1 concludes → Event
    })

    # Statuses on the Tier 1 side of the lifecycle that are gated to the
    # ticket's original creator (same analyst who opened it). Used both by
    # transition_to and the same-status note guard.
    CREATOR_REVIEW_STATUSES = frozenset({
        STATUS_T1_REVIEW,
        # A monitored case is the opening analyst's to watch and conclude.
        STATUS_MONITORING,
        # Direct-to-Owner tracking sits with the opening analyst too. (The
        # CONTAINMENT_REPORTED and PENDING_T2_REVIEW queues are deliberately NOT
        # here — they are Tier 2 verification queues, so a non-creator Tier 2
        # must be able to act on and annotate them.)
        STATUS_AWAITING_OWNER, STATUS_OWNER_REMEDIATED,
    })

    # Statuses where the ball is in the OPENING ANALYST's court — the Tier 1
    # "My Queue". T1_REVIEW is the big one: Tier 2 returned the case and only
    # the creator may act (CREATOR_REVIEW_STATUSES), so it must surface
    # somewhere the creator actually looks. The dashboard's analyst heatmap
    # derives its own-court columns from this same tuple.
    TIER1_QUEUE_STATUSES = (
        STATUS_NEW, STATUS_T1_REVIEW, STATUS_MONITORING,
        STATUS_AWAITING_OWNER, STATUS_OWNER_REMEDIATED,
    )

    # Statuses that sit in the Tier 2 work queue: escalation triage plus the
    # two verification stages (admin containment / owner remediation).
    TIER2_QUEUE_STATUSES = (
        STATUS_ESCALATED_T2, STATUS_CONTAINMENT_REPORTED, STATUS_PENDING_T2_REVIEW,
    )

    # Statuses that sit in the SOC Manager work queue: the pre-containment
    # review (flag Emergency + forward) and the post-verification approval.
    MANAGER_QUEUE_STATUSES = (
        STATUS_PENDING_MGR_TRIAGE, STATUS_PENDING_MANAGER,
        STATUS_PENDING_MGR_EVENT_REVIEW,
    )

    # Edges that dispose of a benign Event — require classification == EVENT.
    # Tier 2 confirming an Event that Tier 1 already classified closes directly.
    # An Event that Tier 2 downgraded from an escalated Incident goes through
    # the SOC Manager first (STATUS_PENDING_MGR_EVENT_REVIEW) — see the gate in
    # can_transition_to / transition_to. The two mid-containment edges still let
    # Tier 2 reclassify an in-flight Incident and close it without the manager,
    # even when the emergency flag is set.
    EVENT_CLOSE_TRANSITIONS = frozenset({
        (STATUS_ESCALATED_T2,         STATUS_CLOSED_EVENT),
        (STATUS_ESCALATED_T2,         STATUS_PENDING_MGR_EVENT_REVIEW),
        (STATUS_PENDING_MGR_EVENT_REVIEW, STATUS_CLOSED_EVENT),
        (STATUS_CONTAINMENT_REPORTED, STATUS_CLOSED_EVENT),
        (STATUS_PENDING_T2_REVIEW,    STATUS_CLOSED_EVENT),
    })

    # Edges that commit to handling an Incident — require classification == INCIDENT.
    # (NEW→ESCALATED_T2 is deliberately NOT here: an escalation carries either
    # classification to Tier 2, which then decides Event-close or Incident.)
    INCIDENT_TRANSITIONS = frozenset({
        (STATUS_NEW,          STATUS_PENDING_MGR_TRIAGE),
        (STATUS_ESCALATED_T2, STATUS_T1_REVIEW),
        # Monitoring turned up something → Tier 1 commits it as an Incident.
        (STATUS_MONITORING,   STATUS_PENDING_MGR_TRIAGE),
    })

    # ------------------------------------------------------------------ #
    # Other choice sets                                                   #
    # ------------------------------------------------------------------ #
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High',     'High'),
        ('Medium',   'Medium'),
        ('Low',      'Low'),
        # Unknown = analyst cannot yet classify severity. It is unclassified,
        # NOT low-risk, so it sits below Low only for queue ordering. Severity
        # never routes to the manager — only the emergency flag does.
        # Human-assigned only (not Wazuh ingest).
        ('Unknown',  'Unknown'),
    ]

    # Ordered severity ranks for queue ordering. Unknown ranks 0 (lowest) so it
    # sorts last. Severities not in this map (e.g. blank) also rank 0.
    SEVERITY_RANK = {'Unknown': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

    # NCSA (สกมช.) statutory threat-severity level — the 3-tier classification
    # required on the official incident report, distinct from the SIEM-derived
    # ``severity`` above. Optional: the analyst may not be able to assign it at
    # intake. See the NCSA Act B.E. 2562 threat-level definitions.
    NCSA_SEVERITY_CRITICAL   = 'CRITICAL'
    NCSA_SEVERITY_SEVERE     = 'SEVERE'
    NCSA_SEVERITY_NON_SEVERE = 'NON_SEVERE'
    NCSA_SEVERITY_CHOICES = [
        (NCSA_SEVERITY_CRITICAL,   'วิกฤต (Critical)'),
        (NCSA_SEVERITY_SEVERE,     'ร้ายแรง (Severe)'),
        (NCSA_SEVERITY_NON_SEVERE, 'ไม่ร้ายแรง (Non-Severe)'),
    ]

    ASSET_TYPE_CHOICES = [
        ('Computer',       'คอมพิวเตอร์'),
        ('Server',         'เซิร์ฟเวอร์'),
        ('Network Device', 'Network Device'),
    ]

    DETAILED_ISSUE_CHOICES = [
        ('Training', 'เหตุการณ์จำลอง และ การฝึกจู่โจม ของหน่วยงานเอง (Training and Exercises)'),
        ('Unsuccessful Attempt', 'การพยายามเข้าถึงระบบที่ไม่สำเร็จ (Unsuccessful Activity Attempt)'),
        ('Reconnaissance', 'การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี (Reconnaissance)'),
        ('Non-Compliance', 'การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด (Non-Compliance Activity)'),
        ('Malicious Logic', 'การบุกรุกโดยการใช้มัลแวร์ (Malicious Logic)'),
        ('User Intrusion', 'การบุกรุกในระดับผู้ใช้งาน (User Level Intrusion)'),
        ('Root Intrusion', 'การบุกรุกในระดับผู้ควบคุมระบบ (Root Level Intrusion)'),
        ('DoS', 'การบุกรุกที่ทำให้ไม่สามารถเข้าไปใช้บริการได้ (Denial of Service)'),
        ('Investigating', 'เหตุการณ์ที่อยู่ระหว่างการวิเคราะห์สอบสวน (Investigating)'),
        ('Explained Anomaly', 'เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วว่าไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม (Explained Anomaly)'),
        ('SIEM Other', 'อื่นๆ (SIEM Other)'),
        ('Admin Unsuccessful', '(Admin) การพยายามเข้าถึงระบบที่ไม่สำเร็จ (Unsuccessful Activity Attempt)'),
        ('Admin Reconnaissance', '(Admin) การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี (Reconnaissance)'),
        ('Admin Non-Compliance', '(Admin) การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด (Non-Compliance Activity)'),
        ('Admin Malicious Logic', '(Admin) การบุกรุกโดยการใช้มัลแวร์ (Malicious Logic)'),
        ('Admin User Intrusion', '(Admin) การบุกรุกในระดับผู้ใช้งาน (User Level Intrusion)'),
        ('Admin Root Intrusion', '(Admin) การบุกรุกในระดับผู้ควบคุมระบบ (Root Level Intrusion)'),
        ('Admin DoS', '(Admin) การบุกรุกที่ทำให้ไม่สามารถเข้าไปใช้บริการได้ (Denial of Service)'),
        ('Admin Explained Anomaly', '(Admin) เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วว่าไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม (Explained Anomaly)'),
        ('TI IOC', 'แจ้งเตือน IOC (Indicators of Compromise)'),
        ('TI Other', 'อื่นๆ (TI Other)'),
        ('Data Leak', 'พบข้อมูลรั่วไหล'),
        ('Vulnerability', 'พบช่องโหว่ของอุปกรณ์หรือระบบงาน'),
        ('Attack Attempt', 'พบความพยายามในการไปโจมตีผู้อื่น'),
        ('External Other', 'อื่นๆ (External Other)'),
    ]

    RAW_DETAILED_ISSUES = [
        ('Simulated Phishing', 'พบการยิง simulated phishing campaign จากทีม security'),
        ('Brute Force', 'Red Team ทำการ brute force test กับระบบ'),
        ('Internal Scan', 'การสแกนช่องโหว่จากเครื่องมือภายใน เช่น Nexus / OpenVAS'),
        ('Whitelisted Log', 'Log แสดง activity จาก IP ภายในที่ถูก whitelist เป็น "test range"'),
        ('Training Other', 'Other (Training and Exercises)'),
        ('Failed Login', 'Login ล้มเหลวหลายครั้ง (failed login) จากบัญชีเดียวกัน'),
        ('Admin Panel Attempt', 'การพยายามเข้าถึง URL/admin panel และได้ 403/401'),
        ('Firewall Block', 'Firewall block การเชื่อมต่อจาก IP ที่ต้องสงสัย'),
        ('SSH Failed', 'SSH login failed หลายครั้ง (brute force attempt)'),
        ('Unsuccessful Other', 'Other (Unsuccessful Activity Attempt)'),
        ('Port Scanning', 'Port scanning จาก IP ภายนอก (เช่น scan port 22, 80, 443)'),
        ('DNS Enumeration', 'DNS enumeration (query domain ย่อยจำนวนมาก)'),
        ('Web Scanning', 'Web scanning เช่น /admin, /backup, /test'),
        ('User Enumeration', 'User enumeration เช่น ลอง login ด้วย username หลายๆ แบบ'),
        ('Recon Other', 'Other (Reconnaissance)'),
        ('USB Policy', 'User ใช้ USB storage ทั้งที่ policy ห้าม'),
        ('Unauthorized Software', 'ติดตั้ง software ที่ไม่ได้รับอนุญาต'),
        ('Antivirus Off', 'ปิด antivirus / endpoint protection'),
        ('Weak Password', 'ใช้ password ที่ไม่ตรง policy (เช่น ไม่มี complexity)'),
        ('Compliance Other', 'Other (Non-Compliance Activity)'),
        ('Malware EDR', 'ตรวจพบ malware จาก EDR (เช่น Trojan, ransomware)'),
        ('C2 Server', 'มีการเรียก command & control (C2) server'),
        ('Ransomware Behavior', 'ไฟล์ถูก encrypt จำนวนมาก (ransomware behavior)'),
        ('Suspicious PowerShell', 'PowerShell execution ที่ suspicious (encoded command)'),
        ('Malicious Other', 'Other (Malicious Logic)'),
        ('Impossible Travel', 'Login สำเร็จจาก location แปลก (Impossible travel)'),
        ('Abnormal Account', 'มีการใช้บัญชี user รับคำสั่งผิดปกติ'),
        ('Data Exfiltration', 'Access ไฟล์สำคัญจำนวนมากในเวลาสั้น (data exfiltration)'),
        ('Spam Account', 'Email account ถูกใช้ส่ง spam/phishing'),
        ('User Level Other', 'Other (User Level Intrusion)'),
        ('Privilege Escalation', 'มีการใช้ sudo / privilege escalation สำเร็จ'),
        ('Unauthorized Admin', 'สร้าง admin account ใหม่โดยไม่ได้รับอนุญาต'),
        ('System Config Change', 'แก้ไข system binaries หรือ config สำคัญ'),
        ('Log Service Off', 'ปิด log / security service'),
        ('Root Level Other', 'Other (Root Level Intrusion)'),
        ('HTTP Flood', 'Traffic เข้ามาจำนวนมากผิดปกติ (HTTP flood)'),
        ('SYN Flood', 'SYN flood attack'),
        ('Server Spike', 'CPU / Memory server พุ่งสูงผิดปกติ'),
        ('DDoS', 'มี request ซ้ำๆ จำนวนมากจากหลาย IP (DDoS)'),
        ('DoS Other', 'Other (Denial of Service)'),
        ('Unconfirmed Login', 'SIEM alert ว่า "suspicious login" แต่ยังไม่ confirm'),
        ('Anomaly Correlation', 'พบ anomaly แต่ยังต้อง correlation เพิ่ม'),
        ('SOC Escalate', 'Event ถูก escalate ไป SOC analyst'),
        ('Log Gathering', 'กำลังรวบรวม log จากหลายแหล่ง (Firewall, endpoint, AD)'),
        ('Investigating Other', 'Other (Investigating)'),
        ('VPN Login', 'User login จากต่างประเทศ แต่จริงๆ คือ VPN ของบริษัท'),
        ('Deploy Traffic', 'Traffic สูงเพราะมีการ deploy ระบบ / backup'),
        ('Vulnerability Scanner', 'Scan มาจาก vulnerability scanner ภายใน'),
        ('Admin Maintenance', 'Admin ทำงาน maintenance นอกเวลาปกติ'),
        ('Explained Other', 'Other (Explained Anomaly)'),
        ('SIEM Other Detail', 'อื่นๆ (SIEM Other)'),
        ('Admin Failed Login', '(Admin) Login ล้มเหลวหลายครั้ง (failed login) จากบัญชีเดียวกัน'),
        ('Admin Panel Block', '(Admin) การพยายามเข้าถึง URL/admin panel และได้ 403/401'),
        ('TI IOC Detail', '(TI) แจ้งเตือน IOC (Indicators of Compromise)'),
        ('TI Malicious IP', '(TI) พบการติดต่อกับ IP อันตราย (Malicious IP Communication)'),
        ('Data Leak Detail', '(External) พบข้อมูลรั่วไหล'),
        ('Vulnerability Found', '(External) พบช่องโหว่ของอุปกรณ์หรือระบบงาน'),
        ('Attack Attempt Detail', '(External) พบความพยายามในการไปโจมตีผู้อื่น'),
        ('External Other Detail', '(External) อื่นๆ (External Other)'),
    ]

    DETAILED_ISSUE_CHOICES2 = sorted(RAW_DETAILED_ISSUES, key=lambda x: x[1])

    # ── Threat-type hierarchy: detailed_issue → detailed_issue2 ──────── #
    # The 10 "clean" threat categories and their specific sub-types. Only
    # these are offered on the forms; the source-flavoured legacy categories
    # in DETAILED_ISSUE_CHOICES (SIEM Other, Admin *, TI *, External *) are
    # kept solely so existing tickets still display, and are hidden from new
    # selection. Single source of truth for the form choices, the create-form
    # parent auto-fill, and the JS cascade in _detailed_issue_cascade.html.
    DETAILED_ISSUE_HIERARCHY = {
        'Training':             ['Simulated Phishing', 'Brute Force', 'Internal Scan', 'Whitelisted Log', 'Training Other'],
        'Unsuccessful Attempt': ['Failed Login', 'Admin Panel Attempt', 'Firewall Block', 'SSH Failed', 'Unsuccessful Other'],
        'Reconnaissance':       ['Port Scanning', 'DNS Enumeration', 'Web Scanning', 'User Enumeration', 'Recon Other'],
        'Non-Compliance':       ['USB Policy', 'Unauthorized Software', 'Antivirus Off', 'Weak Password', 'Compliance Other'],
        'Malicious Logic':      ['Malware EDR', 'C2 Server', 'Ransomware Behavior', 'Suspicious PowerShell', 'Malicious Other'],
        'User Intrusion':       ['Impossible Travel', 'Abnormal Account', 'Data Exfiltration', 'Spam Account', 'User Level Other'],
        'Root Intrusion':       ['Privilege Escalation', 'Unauthorized Admin', 'System Config Change', 'Log Service Off', 'Root Level Other'],
        'DoS':                  ['HTTP Flood', 'SYN Flood', 'Server Spike', 'DDoS', 'DoS Other'],
        'Investigating':        ['Unconfirmed Login', 'Anomaly Correlation', 'SOC Escalate', 'Log Gathering', 'Investigating Other'],
        'Explained Anomaly':    ['VPN Login', 'Deploy Traffic', 'Vulnerability Scanner', 'Admin Maintenance', 'Explained Other'],
    }

    @classmethod
    def detailed_issue_form_choices(cls):
        """(code, label) for the clean threat categories offered on forms."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES)
        return [(p, labels.get(p, p)) for p in cls.DETAILED_ISSUE_HIERARCHY]

    @classmethod
    def detailed_issue2_form_choices(cls):
        """(code, label) for every specific sub-type under a clean category."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES2)
        return [(c, labels.get(c, c))
                for children in cls.DETAILED_ISSUE_HIERARCHY.values()
                for c in children]

    @classmethod
    def parent_of_detailed_issue2(cls, child):
        """The detailed_issue category a given detailed_issue2 belongs to."""
        for parent, children in cls.DETAILED_ISSUE_HIERARCHY.items():
            if child in children:
                return parent
        return None

    @classmethod
    def detailed_issue_cascade(cls):
        """{parent: [[child_code, child_label], …]} consumed by the JS cascade."""
        labels = dict(cls.DETAILED_ISSUE_CHOICES2)
        return {p: [[c, labels.get(c, c)] for c in children]
                for p, children in cls.DETAILED_ISSUE_HIERARCHY.items()}

    # ------------------------------------------------------------------ #
    # Fields                                                              #
    # ------------------------------------------------------------------ #
    ticket_id = models.CharField(max_length=20, unique=True, editable=False, blank=True)

    # ── Section 1: General Information ──────────────────────────────── #
    # Short human-readable name for the case (ชื่อ incident/event on the NCSA
    # report). Optional — the structured fields below carry the real detail;
    # this is a one-line handle for lists, exports and the report header.
    incident_name = models.CharField(
        max_length=255, blank=True, default='',
        verbose_name='ชื่อเหตุการณ์ (Incident/Event Name)',
    )
    severity = models.CharField(
        max_length=10, choices=SEVERITY_CHOICES, default='High',
        verbose_name='ระดับความรุนแรง',
    )
    # NCSA (สกมช.) statutory severity level — reported alongside the SIEM
    # ``severity``. Blank until an analyst assigns it.
    ncsa_severity = models.CharField(
        max_length=20, choices=NCSA_SEVERITY_CHOICES, blank=True, default='',
        verbose_name='ระดับความรุนแรงตาม สกมช.',
    )
    incident_datetime = models.DateTimeField(
        null=True, blank=True,
        verbose_name='วันและเวลาที่ตรวจพบเหตุการณ์',
    )
    # When the incident actually happened, as distinct from when SOC detected it
    # (``incident_datetime``). For a Wazuh case the two coincide — the alert's
    # OpenSearch timestamp is the event time — so the form pre-fills this from the
    # alert. Other sources (TrendMicro, Trellix, user report) carry no reliable
    # occurrence time, so Tier 1 fills it, or copies the detection time when the
    # true moment is unknown. Nullable: legacy tickets and non-form paths leave it
    # blank, and the report simply drops the row when it is empty.
    event_occurred_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='วันและเวลาที่เกิดเหตุการณ์',
    )
    # When the affected party was told about the incident — report row 1.4.
    # Tier 2 records it while verifying containment (either lane); it is required
    # to move the case forward, but not to send it back. Nullable for legacy
    # tickets and cases that never reach that step.
    affected_notified_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='วันที่ เวลา ที่แจ้งเหตุผู้ที่ได้รับผลกระทบ',
    )
    reference_id = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='Reference',
    )
    # Free-text name of the log source the alert came from (แหล่งข้อมูล on the
    # NCSA report) — e.g. "Palo Alto Firewall", "Windows Security Event Log".
    # Distinct from issue_type (the coarse reporting channel). Required at the
    # form level, not the DB, so non-form creation paths (Wazuh ingest, seeders)
    # are unaffected.
    log_source = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='แหล่งข้อมูล (Log Source)',
    )

    # ── Case Bundling (Project Incident) ─────────────────────────────── #
    # When one incident affects several systems it is fanned out into one
    # ticket per system, all pointing at the same ProjectIncident. Members
    # keep their own status/OLA; the bundle is the grouping + rollup unit.
    project_incident = models.ForeignKey(
        ProjectIncident, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='member_tickets', verbose_name='Project Incident (Case Bundle)',
    )
    bundle_suffix = models.CharField(
        max_length=4, blank=True, default='',
        verbose_name='ลำดับในกลุ่ม (A, B, C …)',
    )

    # ── Section 3: Description ───────────────────────────────────────── #
    device_name = models.CharField(max_length=100, verbose_name='ระบบ / บริการ (System/Service)')
    # Short summary shown as report row 1.12; the full write-up lives in
    # issue_description (report Section 2). Optional — report 1.12 falls back to
    # issue_description when this is blank, so existing tickets are unaffected.
    event_summary = models.TextField(
        blank=True, default='', verbose_name='สรุปเหตุการณ์',
    )
    issue_description = models.TextField(verbose_name='รายละเอียดเหตุการณ์')
    # Per-system note captured on the Project Incident form — one entry per
    # affected system. Distinct from issue_description, which stays the shared
    # incident summary copied onto every bundle member.
    system_detail = models.TextField(
        blank=True, default='', verbose_name='รายละเอียดเฉพาะระบบ',
    )

    # ── Section 4: Scope / Affected Asset ───────────────────────────── #
    # null=True with blank=False: forms still require an IP, but tickets
    # imported from the pre-system TrendMicro tracker have none to give.
    ip_address = models.TextField(
        null=True, verbose_name='IP Addresses ของทรัพย์สิน',
        validators=[validate_ip_addresses], help_text=IP_ADDRESSES_HELP,
    )
    mac_address = models.CharField(
        max_length=50, blank=True, default='',
        verbose_name='MAC Address',
    )
    asset_type = models.CharField(
        max_length=20, choices=ASSET_TYPE_CHOICES, blank=True, default='',
        verbose_name='ประเภทของทรัพย์สิน',
    )
    operating_system = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='ระบบปฏิบัติการ (Operating System)',
    )
    # Free-text owning unit/department of the affected asset (หน่วยงานเจ้าของ
    # ทรัพย์สิน on the report). Deliberately NOT the system_owner FK — this is a
    # descriptive label typed by the analyst, independent of whether that unit
    # has a registered System Owner account in the system.
    asset_owner = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='หน่วยงานเจ้าของทรัพย์สิน',
    )
    # Name of the individual who owns/looks after the asset (ชื่อเจ้าของทรัพย์สิน
    # on the report). Free text on purpose: this identifies an employee for the
    # report and for follow-up, and that person is not expected to hold an
    # account here — so it is neither the ``system_owner`` FK nor tied to one.
    asset_owner_name = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='ชื่อเจ้าของทรัพย์สิน',
    )
    spread_to_others = models.BooleanField(
        null=True, blank=True,
        verbose_name='มีการกระจายไปยังจุดอื่น',
    )

    # ── Section 5: IoC ──────────────────────────────────────────────── #
    # Structured indicators live in the related TicketIOC table (multi-valued,
    # per category). The fields below are legacy: destination_ip and ioc_details
    # predate that table and are preserved read-only for historical tickets; the
    # 0067 data migration lifts what it can from them into TicketIOC rows.
    destination_ip = models.CharField(
        max_length=100, blank=True, default='',
        verbose_name='IP Address ปลายทางที่น่าสงสัย',
    )
    ioc_details = models.TextField(
        blank=True, default='',
        verbose_name='Indicators of Compromise (IoC)',
    )
    # Its own field rather than a line inside ioc_details, because the NT
    # incident-report form gives the account its own row in section 4. Kept out
    # of the structured TicketIOC table (and therefore the IOC Database) on
    # purpose — it identifies the compromised account for the report, not a
    # shareable indicator — but it is still reachable from global search.
    ioc_user = models.CharField(
        max_length=150, blank=True, default='',
        verbose_name='บัญชีผู้ใช้ที่เกี่ยวข้อง (User)',
        help_text='บัญชีผู้ใช้ที่ผู้โจมตีใช้ในการโจมตี เช่น administrator หรือ DOMAIN\\svc_backup',
    )
    # The command(s) the attacker ran — one per line. Like ioc_user, its own
    # field (report section 4's 'คำสั่ง' row) rather than a TicketIOC category, so
    # it never enters the IOC Database; still covered by global search.
    ioc_command = models.TextField(
        blank=True, default='',
        verbose_name='คำสั่ง (Command)',
        help_text='คำสั่งที่ผู้โจมตีสั่งรัน — หนึ่งบรรทัดต่อหนึ่งคำสั่ง',
    )

    # ── Section 6: MITRE ATT&CK ─────────────────────────────────────── #
    MITRE_TACTIC_CHOICES = [
        ('Reconnaissance',       'Reconnaissance'),
        ('Resource Development', 'Resource Development'),
        ('Initial Access',       'Initial Access'),
        ('Execution',            'Execution'),
        ('Persistence',          'Persistence'),
        ('Privilege Escalation', 'Privilege Escalation'),
        ('Stealth',              'Stealth'),
        ('Defense Impairment',   'Defense Impairment'),
        ('Credential Access',    'Credential Access'),
        ('Discovery',            'Discovery'),
        ('Lateral Movement',     'Lateral Movement'),
        ('Collection',           'Collection'),
        ('Command and Control',  'Command and Control'),
        ('Exfiltration',         'Exfiltration'),
        ('Impact',               'Impact'),
    ]
    # An incident can span several ATT&CK tactics, so this stores a
    # comma-separated list of MITRE_TACTIC_CHOICES values (set via the multi-select
    # form field). Read it through ``mitre_tactic_list`` / ``mitre_tactic_labels``
    # rather than parsing the raw string.
    mitre_tactics = models.CharField(
        max_length=500, blank=True, default='',
        verbose_name='MITRE ATT&CK Tactics (ยุทธวิธีการโจมตี)',
    )

    # ── Section 7: Recommended Actions ──────────────────────────────── #
    action_required = models.TextField(
        blank=True, default='',
        verbose_name='สิ่งที่ต้องดำเนินการ',
    )
    action_precautions = models.TextField(
        blank=True, default='',
        verbose_name='ข้อควรระวังในการดำเนินการ',
    )
    # Per-item done-state for the สิ่งที่ต้องดำเนินการ checklist the assigned
    # System Admin ticks while containing the incident. A non-mandatory aid:
    # [{"text": "<item line>", "done": true|false}, ...]. Restored by text match
    # across the Tier 2 rejection loop; see ``containment_checklist_display``.
    containment_checklist = models.JSONField(default=list, blank=True)

    # Report-only prose: lets analysts polish the official document wording
    # without overloading lifecycle logs or containment fields.
    actions_taken_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปเรื่องที่ดำเนินการแล้ว',
    )
    next_steps_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปการดำเนินการลำดับถัดไป',
    )

    # ── Section 9: Remediation ──────────────────────────────────────── #
    remediation_summary = models.TextField(
        blank=True, default='',
        verbose_name='สรุปผลการดำเนินการแก้ไข',
    )
    # Report section 8's fixed remediation checklist (REMEDIATION_CHECKLIST in
    # report_content). Stores the ticked item KEYS, not their labels, so
    # rewording an item never loses its tick. Ticked by Tier 2 while verifying
    # that the System Admin / System Owner has contained the incident.
    remediation_checklist = models.JSONField(default=list, blank=True)
    # The section-8 checklist's free-text "อื่นๆ ระบุ" line.
    remediation_other = models.TextField(
        blank=True, default='',
        verbose_name='สรุปผลการดำเนินการแก้ไข — อื่นๆ',
    )

    status = models.CharField(
        max_length=30, choices=STATUS_CHOICES, default=STATUS_NEW,
    )
    classification = models.CharField(
        max_length=20, choices=CLASSIFICATION_CHOICES, blank=True, default='',
        verbose_name='การจัดประเภท (Event/Incident)',
    )
    # The handling lane Tier 1 chose for an Incident (ADMIN / OWNER). Set when
    # Tier 1 routes a ticket into PENDING_MGR_TRIAGE; read by the SOC Manager
    # forward step to send the ticket to its fixed lane. Blank for Events and
    # for tickets still awaiting a route decision.
    t1_route = models.CharField(
        max_length=10, choices=T1_ROUTE_CHOICES, blank=True, default='',
        verbose_name='เส้นทางที่ Tier 1 เลือก (Admin/Owner)',
    )
    containment_report = models.TextField(
        blank=True, default='',
        verbose_name='รายงานการควบคุม',
    )

    # Set to True the first time a ticket enters ESCALATED_T2 and never cleared
    # — the authoritative record of "this ticket was escalated to Tier 2 at some
    # point", used to gate the Tier 1 emergency-flag permission.
    escalated_to_t2_at = models.DateTimeField(
        null=True, blank=True, verbose_name='เวลาที่ส่งต่อ Tier 2 ครั้งแรก',
    )

    # ── Monitoring (watch-and-wait) ─────────────────────────────────────── #
    # When Tier 2 parks a case in STATUS_MONITORING, monitor_until is stamped
    # now + MONITORING_DURATION_DAYS. Expiry is read on the fly (monitor_until vs
    # now) — there is no scheduler; the countdown just turns overdue in the UI.
    monitor_until = models.DateTimeField(
        null=True, blank=True, verbose_name='เฝ้าระวังจนถึง',
    )
    # Set True the first (and only) time a ticket enters MONITORING and never
    # cleared — gates re-monitoring so 30 days is the absolute watch duration.
    has_been_monitored = models.BooleanField(
        default=False, verbose_name='เคยถูกเฝ้าระวังแล้ว',
    )
    # Tier 1's recommendation, set when the opening analyst escalates from NEW
    # proposing monitoring. Purely advisory to Tier 2 (only Tier 2 can grant it);
    # cleared once the case leaves the Tier 2 review either way.
    monitoring_proposed = models.BooleanField(
        default=False, verbose_name='Tier 1 แนะนำให้เฝ้าระวัง',
    )

    # Emergency marker — the operational flag that feeds
    # requires_manager_verification (closure routing). The SOC Manager makes an
    # explicit Normal/Emergency assessment at the pre-containment review
    # (PENDING_MGR_TRIAGE) via assess_emergency_initial, and may reassess it at
    # any later active stage via reassess_emergency (auditable, reason required,
    # forbidden after closure). No other role may change it.
    is_emergency = models.BooleanField(
        default=False, verbose_name='เหตุฉุกเฉิน (Emergency)',
    )
    # Who made the INITIAL Normal/Emergency assessment, and when. Stamped once
    # at the pre-containment review even when the verdict is Normal, so there is
    # positive evidence the decision was made rather than a checkbox left blank.
    # Write-once: later changes are reassessments, recorded in the timeline.
    emergency_decided_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='emergency_assessed_tickets',
        verbose_name='ผู้ประเมินสถานะฉุกเฉิน (ครั้งแรก)',
    )
    emergency_decided_at = models.DateTimeField(
        null=True, blank=True, verbose_name='เวลาประเมินสถานะฉุกเฉิน (ครั้งแรก)',
    )

    # ── System Owner ─────────────────────────────────────────────────── #
    # FK to the registered System Owner user account.  Their email and
    # department are read from their User / UserProfile at notification time.
    #
    # DORMANT (2026-07-07): the NCSA-report form redesign dropped the System
    # Owner picker from every user-facing form in favour of the free-text
    # ``asset_owner`` unit label. New tickets created via the forms therefore
    # leave this null, so the owner-notification emails
    # (notify_system_owner_created / notify_system_owner_closed) and the System
    # Owner dashboard visibility (TicketQuerySet.visible_to → system_owner) no
    # longer fire for them. The field/wiring are kept intact for legacy tickets
    # and admin use; re-introduce a picker (or map asset_owner → a recipient)
    # to reactivate owner notifications.
    system_owner = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='owned_tickets',
        verbose_name='เจ้าของระบบ / หน่วยงาน',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Timestamp of the last *status change* (set on creation, then updated by
    # transition_to whenever the status actually changes). Unlike updated_at
    # (auto_now — bumps on any save, incl. note edits / emergency toggles),
    # this tracks only lifecycle transitions, so it answers "when did this
    # ticket last move state?".
    status_changed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่อัปเดตสถานะ',
    )

    # Classification the ticket carried when it landed on Tier 2's desk.
    # Re-stamped on every entry to ESCALATED_T2 (a rejected Event review sends
    # the ticket back, so this is not write-once). Lets the Event-close gate
    # tell a Tier 2 DOWNGRADE (Incident → Event, needs the manager) apart from
    # Tier 2 merely confirming what Tier 1 had already called an Event.
    classification_at_escalation = models.CharField(
        max_length=20, choices=CLASSIFICATION_CHOICES, blank=True, default='',
        verbose_name='ประเภทตอนส่งต่อให้ Tier 2',
    )

    # ── Tier 2 queue claim (in-progress work tracking) ───────────────── #
    # Mirrors WazuhAlert.claimed_by/claimed_at on the Tier 1 triage queue: a
    # Tier 2 analyst takes a ticket out of the shared queue before acting on
    # it, so two analysts can't review the same case at once. Cleared on every
    # transition (see transition_to) because the Tier 2 queue spans three
    # stages and a claim only covers the stage it was made in — otherwise a
    # ticket would stay locked to whoever touched it first all the way through.
    t2_claimed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='t2_claimed_tickets', verbose_name='Tier 2 ผู้รับเรื่อง',
    )
    t2_claimed_at = models.DateTimeField(null=True, blank=True)

    # ── Lifecycle timestamps (dashboard metrics) ─────────────────────── #
    # acknowledged_at — when an analyst picked the case up (วันที่รับเคส).
    #   Backfilled by the TrendMicro import; for tickets born in this system
    #   creation is the ack, so queries coalesce to created_at.
    # report_issued_at — first hand-off to the system admin (วันที่ออกรายงาน).
    #   Stamped by transition_to on first entry to AWAITING_CONTAINMENT.
    # closed_at — terminal close on EITHER path. approved_at only covers
    #   APPROVED; CLOSED_EVENT tickets would otherwise have no close time.
    acknowledged_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่รับเคส',
    )
    report_issued_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ออกรายงาน',
    )
    # ── Direct-to-Owner path bookkeeping ─────────────────────────────── #
    # owner_contacted_at — first entry to AWAITING_OWNER (analogous to
    #   report_issued_at on the admin path); the point the owner was told to fix
    #   it themselves. Write-once, set by transition_to.
    # direct_owner_remediation — permanent marker that this ticket was handled by
    #   the asset owner directly (no System Admin ticket / email), for dashboard
    #   segmentation and reporting. Set by transition_to on AWAITING_OWNER.
    owner_contacted_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ติดต่อเจ้าของระบบ',
    )
    direct_owner_remediation = models.BooleanField(
        default=False, verbose_name='ให้เจ้าของระบบแก้ไขเอง (ไม่ผ่านผู้ดูแลระบบ)',
    )
    closed_at = models.DateTimeField(
        null=True, blank=True, verbose_name='วันที่ปิดเคส',
    )
    # Raw detection score from the source alert (TrendMicro Workbench 0–100).
    alert_score = models.PositiveSmallIntegerField(
        null=True, blank=True, verbose_name='คะแนน Alert (TrendMicro)',
    )

    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assigned_tickets',
    )
    assigned_admin = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='admin_tickets',
        verbose_name='ผู้ดูแลระบบที่รับผิดชอบ',
    )
    verified_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='verified_tickets',
        verbose_name='ผู้ตรวจสอบ',
    )
    verified_at = models.DateTimeField(null=True, blank=True, verbose_name='วันที่ตรวจสอบ')
    approved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='approved_tickets',
        verbose_name='ผู้อนุมัติ',
    )
    approved_at = models.DateTimeField(null=True, blank=True, verbose_name='วันที่อนุมัติ')

    # Report export metadata. These are audit fields for the latest generated
    # report artifact (report_format says whether that artifact was DOCX or
    # PDF), not the canonical ticket content itself.
    report_template_version = models.CharField(max_length=20, blank=True, default='')
    report_format = models.CharField(max_length=8, blank=True, default='')
    report_generated_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='generated_ticket_reports',
    )
    report_generated_at = models.DateTimeField(null=True, blank=True)
    report_ticket_updated_at = models.DateTimeField(null=True, blank=True)
    report_sha256 = models.CharField(max_length=64, blank=True, default='')

    update_notes = models.TextField(blank=True, null=True, verbose_name='บันทึกการติดตามงาน')
    ola_triage_deadline = models.DateTimeField(
        null=True, blank=True, verbose_name='OLA Triage Deadline')
    ola_contain_deadline = models.DateTimeField(
        null=True, blank=True, verbose_name='OLA Contain Deadline')
    # Reporting channel the incident arrived through. Shares SOURCE_CHOICES
    # with TriageRecord.source so a manual-triage record maps straight onto the
    # ticket it creates.
    issue_type = models.CharField(
        max_length=50, choices=SOURCE_CHOICES, default=SOURCE_SIEM,
        verbose_name='Source',
    )
    detailed_issue = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES, default='Investigating',
        verbose_name='ประเภทภัยคุกคาม (Detailed Issue)',
    )
    detailed_issue2 = models.CharField(
        max_length=255, choices=DETAILED_ISSUE_CHOICES2, default='Investigating Other',
        verbose_name='เรื่องที่แจ้ง',
    )
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        verbose_name='ผู้เปิดงาน',
    )

    # ── Source Wazuh alert (optional) ────────────────────────────────── #
    wazuh_alert = models.OneToOneField(
        'wazuh_ingest.WazuhAlert', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket', verbose_name='Wazuh Alert',
    )

    # Analyst response time: how long from the source alert becoming actionable
    # (wazuh_alert.ingested_at) until this ticket was raised (created_at).
    # Stamped once at creation and never recomputed, so it survives the alert
    # row being nulled (wazuh_alert is on_delete=SET_NULL). Null for tickets
    # created manually with no source alert — those have no conversion time.
    alert_conversion_duration = models.DurationField(
        null=True, blank=True,
        verbose_name='เวลาตอบสนอง (Alert พร้อมรับ → เปิด Ticket)',
        help_text='created_at − wazuh_alert.ingested_at, stamped once at creation.',
    )

    # OLA policy per severity: (triage_target, contain_target).
    #   triage  = time to raise/send the ticket (measured from incident time).
    #   contain = time to resolve; None = notification-only (no resolve deadline).
    # Unknown mirrors Critical. This dict is the single place to change the OLA
    # policy values.
    OLA_TARGETS = {
        'Critical': (timedelta(minutes=30), timedelta(hours=4)),
        'High':     (timedelta(hours=2),    timedelta(hours=24)),
        'Medium':   (timedelta(hours=24),   None),
        'Low':      (timedelta(hours=24),   None),
        'Unknown':  (timedelta(minutes=30), timedelta(hours=4)),
    }

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def is_event(self):
        """Benign Event (was False Positive) — the close-without-action path."""
        return self.classification == self.CLASSIFICATION_EVENT

    @property
    def is_incident(self):
        """Actionable Incident (was True Positive) — proceeds to containment."""
        return self.classification == self.CLASSIFICATION_INCIDENT

    # Lines like "1) ...", "1. ...", "- ..." or "• ..." are checklist items;
    # anything else (the หมายเหตุ coordination note, free prose) is trailing text.
    _CHECKLIST_ITEM_RE = re.compile(r'^\s*(?:\d+[.)]|[-•])\s+\S')

    @classmethod
    def parse_checklist_items(cls, text):
        """Split action_required text into (item_lines, trailing_lines)."""
        items, trailing = [], []
        for line in (text or '').splitlines():
            if cls._CHECKLIST_ITEM_RE.match(line):
                items.append(line.strip())
            elif line.strip():
                trailing.append(line.rstrip())
        return items, trailing

    def containment_checklist_display(self):
        """Checklist for the *current* action_required with done-states restored.

        Returns ``(items, trailing)`` where items is ``[{'text', 'done'}]`` and
        trailing is the non-item text. Done-states are matched by item text
        against the saved ``containment_checklist`` so a Tier 2 rejection keeps
        prior ticks (an item whose wording changed comes back unticked).
        """
        saved = {
            entry.get('text'): bool(entry.get('done'))
            for entry in (self.containment_checklist or [])
        }
        item_lines, trailing_lines = self.parse_checklist_items(self.action_required)
        items = [{'text': line, 'done': saved.get(line, False)} for line in item_lines]
        return items, '\n'.join(trailing_lines)

    @property
    def mitre_tactic_list(self):
        """MITRE ATT&CK tactic names recorded on this ticket (multi-select)."""
        return [p for p in self.mitre_tactics.split(',') if p]

    @property
    def mitre_tactic_labels(self):
        """Human labels for the recorded MITRE ATT&CK tactics."""
        labels = dict(self.MITRE_TACTIC_CHOICES)
        return [labels.get(p, p) for p in self.mitre_tactic_list]

    @property
    def was_escalated_to_t2(self):
        """True if this ticket was escalated to Tier 2 at any point in its life."""
        return self.escalated_to_t2_at is not None

    @property
    def is_bundled(self):
        """Part of a multi-system Project Incident (case bundle)."""
        return self.project_incident_id is not None

    @property
    def bundle_ref(self):
        """Trackable id within a bundle, e.g. 'PI-260706-01-C'. '' if unbundled."""
        if self.project_incident_id and self.bundle_suffix:
            return f'{self.project_incident.project_code}-{self.bundle_suffix}'
        return ''

    @property
    def display_id(self):
        """The stable public Ticket Reference, regardless of bundle membership."""
        return self.ticket_id

    @property
    def requires_manager_verification(self):
        """Single rule deciding whether a verified ticket must additionally be
        approved by the SOC manager before it can close.

        True only when the emergency flag is set. Severity alone never routes
        to the manager — Tier 2 verification is the standard closing gate.
        """
        return self.is_emergency

    @property
    def is_ola_triage_breached(self):
        """
        Triage OLA: was the ticket raised later than its triage/send deadline?
        Fixed at issue time (created_at), not a live countdown against now().
        """
        if self.ola_triage_deadline and self.created_at:
            return self.created_at > self.ola_triage_deadline
        return False

    # Backwards-compatible alias — "OLA breached" has always meant the
    # raise-in-time (triage) breach that templates highlight.
    @property
    def is_ola_breached(self):
        return self.is_ola_triage_breached

    @property
    def ola_badge(self):
        """Live contain-OLA pill for the queue tables (incidents/_ola_badge.html).

        Deliberately the CONTAIN deadline, matching what the lists sort and
        filter on — is_ola_breached is the historical "was it raised in time"
        fact and would contradict the ordering if shown here.
        """
        return ola.badge_for(
            self.ola_contain_deadline,
            done=self.status in self.TERMINAL_STATUSES,
        )

    @property
    def monitoring_badge(self):
        """Live watch-window pill for the queue tables and ticket detail.

        None unless the ticket is currently being monitored. ``level`` drives the
        colour (mapped in incidents/_monitoring_badge.html): green while there is
        comfortable time left, amber on the final day, red once the window has
        closed and the case is waiting on Tier 1 to conclude it. Read on the fly
        against now() — there is no scheduler, so an overdue window just shows as
        overdue until the owning analyst acts.
        """
        if self.status != self.STATUS_MONITORING or self.monitor_until is None:
            return None
        now = timezone.now()
        delta = self.monitor_until - now
        secs = abs(delta).total_seconds()
        days, hours = int(secs // 86400), int((secs % 86400) // 3600)
        amount = (f'{days} วัน' if days >= 1
                  else f'{hours} ชั่วโมง' if hours >= 1
                  else 'ไม่ถึงชั่วโมง')
        if delta.total_seconds() <= 0:
            level, label = 'overdue', f'ครบกำหนดเฝ้าระวัง — เกิน {amount}'
        elif delta <= timedelta(days=1):
            level, label = 'final', f'เฝ้าระวัง — เหลือ {amount}'
        else:
            level, label = 'active', f'เฝ้าระวัง — เหลือ {amount}'
        return {
            'level': level,
            'overdue': delta.total_seconds() <= 0,
            'label': label,
            'deadline': self.monitor_until,
        }

    @property
    def is_monitoring_expired(self):
        """A monitored case whose watch window has closed — waiting on Tier 1."""
        return (
            self.status == self.STATUS_MONITORING
            and self.monitor_until is not None
            and timezone.now() >= self.monitor_until
        )

    @property
    def is_ola_contain_breached(self):
        """
        Contain OLA: an active ticket now past its contain/resolve deadline
        (live vs now()). False when there is no contain deadline (Medium/Low
        are notification-only) or the ticket is already terminal.
        """
        if self.ola_contain_deadline and self.status not in self.TERMINAL_STATUSES:
            return timezone.now() > self.ola_contain_deadline
        return False

    @property
    def ola_remaining(self):
        """Triage margin left at the moment the ticket was issued (fixed, not live)."""
        if self.ola_triage_deadline and self.created_at:
            return self.ola_triage_deadline - self.created_at
        return None

    @property
    def is_ola_urgent(self):
        """Triaged within OLA, but with less than 1 hour of margin to spare."""
        remaining = self.ola_remaining
        if remaining is None:
            return False
        return timedelta() < remaining <= timedelta(hours=1)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            # Queue/list filters and the executive dashboard filter on status,
            # often together with severity; the composite also serves status-only
            # queries via its leftmost prefix.
            models.Index(fields=['status', 'severity'], name='ix_ticket_status_severity'),
            # List ordering (-created_at) and date-range dashboard windows.
            models.Index(fields=['created_at'], name='ix_ticket_created_at'),
            # Closed-date reporting / filtering.
            models.Index(fields=['closed_at'], name='ix_ticket_closed_at'),
            # OLA-pressure bucketing (apps/incidents/ola.py) only ever touches
            # OPEN tickets, so a PARTIAL index keeps it small and hot. The
            # condition mirrors TERMINAL_STATUSES (literals — Meta can't see the
            # class constants at definition time).
            models.Index(
                fields=['ola_contain_deadline'],
                condition=~models.Q(status__in=['APPROVED', 'CLOSED_EVENT', 'CANCELLED']),
                name='ix_ticket_open_contain_ola',
            ),
        ]

    def __str__(self):
        return f'{self.ticket_id} - {self.device_name}'

    # ------------------------------------------------------------------ #
    # Save                                                                #
    # ------------------------------------------------------------------ #

    # How many times to regenerate ticket_id when a concurrent insert wins the
    # unique-constraint race before giving up.
    _ID_MAX_RETRIES = 5

    @staticmethod
    def ticket_id_prefix(when):
        """Return the monthly public-reference prefix for ``when``."""
        return f'SOC-{when.year:04d}{when.month:02d}-'

    def _assign_ticket_id(self):
        """Compute the next monthly Ticket Reference: SOC-YYYYMM-NNNN.

        This read-then-write is racy on its own; ``save()`` retries after a
        unique-constraint collision to close the window against committed rows.
        """
        now = timezone.now()
        prefix = self.ticket_id_prefix(now)
        last = (
            Ticket.objects.filter(ticket_id__startswith=prefix)
            .order_by('-ticket_id')
            .first()
        )
        if last:
            try:
                seq = int(last.ticket_id.rsplit('-', 1)[1]) + 1
            except (ValueError, IndexError):
                seq = 1
        else:
            seq = 1

        self.ticket_id = f'{prefix}{seq:04d}'
        while Ticket.objects.filter(ticket_id=self.ticket_id).exists():
            seq += 1
            self.ticket_id = f'{prefix}{seq:04d}'

    def save(self, *args, **kwargs):
        # Serialize ordinary saves with cancellation, including stale ModelForms.
        with transaction.atomic():
            if self.pk:
                current_status = Ticket.objects.select_for_update().filter(pk=self.pk).values_list('status', flat=True).first()
                if current_status == self.STATUS_CANCELLED:
                    raise ValidationError('รายการนี้ยกเลิกแล้ว ไม่สามารถแก้ไขได้')
            if self.status == self.STATUS_CANCELLED:
                raise ValidationError('กรุณาใช้ขั้นตอนอนุมัติยกเลิกรายการ')
            result = self._save_ticket(*args, **kwargs)
            fields = kwargs.get('update_fields')
            if self.status in self.RESOLVED_STATUSES and (fields is None or 'status' in fields):
                self.cancellation_requests.filter(status='PENDING').update(
                    status='SUPERSEDED', decided_at=timezone.now(),
                    decision_note='รายการปิดตามกระบวนการปกติแล้ว',
                )
            return result

    def _save_ticket(self, *args, **kwargs):
        if not self.pk:
            # OLA clocks start when the alert/incident occurred, not when the
            # ticket is filed — fall back to now() if T1 left it blank. Targets
            # are per-severity (OLA_TARGETS); Medium/Low have no contain target.
            base_time = self.incident_datetime or timezone.now()
            triage_target, contain_target = self.OLA_TARGETS.get(
                self.severity, self.OLA_TARGETS['Unknown'])
            if not self.ola_triage_deadline and triage_target is not None:
                self.ola_triage_deadline = base_time + triage_target
            if not self.ola_contain_deadline and contain_target is not None:
                self.ola_contain_deadline = base_time + contain_target

        if not self.pk and not self.status_changed_at:
            # A brand-new ticket enters its initial status now; seed the
            # status-change clock so the field is never null going forward.
            self.status_changed_at = timezone.now()

        # Already-id'd rows (updates, or an explicit id) save straight through.
        if self.ticket_id and self.ticket_id.strip():
            super().save(*args, **kwargs)
            return

        # New ticket needing a generated id: the per-month sequence is a
        # read-then-write, so two concurrent inserts can compute the same NN and
        # one then violates the unique id. Retry with a freshly recomputed id;
        # each attempt runs in a savepoint so the failed INSERT doesn't poison
        # the caller's surrounding transaction (see ProjectIncident.save).
        for attempt in range(self._ID_MAX_RETRIES):
            self._assign_ticket_id()
            try:
                with transaction.atomic():
                    super().save(*args, **kwargs)
                return
            except IntegrityError:
                if attempt == self._ID_MAX_RETRIES - 1:
                    raise

    # ------------------------------------------------------------------ #
    # State machine                                                       #
    # ------------------------------------------------------------------ #

    @property
    def has_open_response_requests(self):
        """True if any response-team request (VA/PT, InfraSec, Forensics) on this
        ticket is not yet DONE.

        Gates final approval: an Incident cannot be APPROVED while response work
        is outstanding (see can_transition_to / transition_to). Event-close
        (CLOSED_EVENT) is deliberately NOT gated — a reclassified false alarm
        closes and any open requests simply outlive it.
        """
        return (
            self.subtasks
            .filter(subtask_type__in=TicketSubtask.RESPONSE_TYPES)
            .exclude(status__in=TicketSubtask.TERMINAL_STATUSES)
            .exists()
        )

    @property
    def is_t2_event_downgrade(self):
        """True when the ticket reached Tier 2 as an Incident and is now an Event.

        This is the case the manager verification gate exists for: Tier 2
        changed the call. A ticket that arrived already classified as an Event
        is not a downgrade — Tier 2 confirming it closes directly.

        Tickets escalated before this field existed have a blank
        classification_at_escalation and are treated as NOT downgrades, so old
        cases keep closing the way they always did.
        """
        return (
            self.is_event
            and self.classification_at_escalation == self.CLASSIFICATION_INCIDENT
        )

    def can_transition_to(self, new_status):
        """Return True if new_status is a legal next state for this ticket,
        honoring the Event/Incident classification gate and the manager-routing
        rule but ignoring per-user permissions.
        """
        edge = (self.status, new_status)
        if new_status not in self.ALLOWED_TRANSITIONS.get(self.status, []):
            return False
        # Response-team gate: any path into APPROVED is blocked while a response
        # request is still open. CLOSED_EVENT is intentionally exempt.
        if new_status == self.STATUS_APPROVED and self.has_open_response_requests:
            return False
        if edge in self.EVENT_CLOSE_TRANSITIONS and not self.is_event:
            return False
        if edge in self.INCIDENT_TRANSITIONS and not self.is_incident:
            return False
        # A case may be monitored at most once — 30 days is the absolute watch.
        # Bundle members are excluded: a Project Incident is a confirmed
        # multi-system incident, so its members are never "not yet classified".
        # (Bundle-level monitoring is a separate design, deferred.)
        if new_status == self.STATUS_MONITORING and (
            self.has_been_monitored or self.project_incident_id
        ):
            return False
        if (
            self.project_incident_id
            and self.status == self.STATUS_PENDING_MGR_TRIAGE
            and self.project_incident.emergency_decided_at is None
        ):
            return False
        # SOC Manager forward at the pre-containment review: the manager can only
        # send the ticket to the lane Tier 1 already chose (t1_route), never the
        # other one. This keeps the case "on the way either way" — the manager
        # flags Emergency but cannot divert it.
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_CONTAINMENT)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            return False
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_OWNER)
                and self.t1_route != self.T1_ROUTE_OWNER):
            return False
        # Manager step-back from PENDING_MANAGER returns the ticket to the lane
        # Tier 1 fixed (mirrors the forward PENDING_MGR_TRIAGE gate): the admin
        # lane steps back to CONTAINMENT_REPORTED, the owner lane to
        # PENDING_T2_REVIEW — never across lanes.
        if (edge == (self.STATUS_PENDING_MANAGER, self.STATUS_CONTAINMENT_REPORTED)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            return False
        if (edge == (self.STATUS_PENDING_MANAGER, self.STATUS_PENDING_T2_REVIEW)
                and self.t1_route != self.T1_ROUTE_OWNER):
            return False
        # Emergency split at Tier 2 verification (both lanes): an emergency
        # ticket must additionally pass the SOC manager; a non-emergency ticket
        # is closed by Tier 2 directly and never reaches the manager.
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            return False
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            return False
        # Event-downgrade split at Tier 2: a ticket Tier 2 downgraded from
        # Incident to Event must pass the SOC Manager; one that was already an
        # Event on arrival is confirmed and closed by Tier 2 directly.
        if (edge == (self.STATUS_ESCALATED_T2, self.STATUS_CLOSED_EVENT)
                and self.is_t2_event_downgrade):
            return False
        if (edge == (self.STATUS_ESCALATED_T2, self.STATUS_PENDING_MGR_EVENT_REVIEW)
                and not self.is_t2_event_downgrade):
            return False
        return True

    def t2_claim_blocks(self, user):
        """Whether the Tier 2 queue claim stops ``user`` acting on this ticket.

        Only applies while the ticket sits in the Tier 2 queue, and only to
        Tier 2 analysts — the claim is queue discipline between peers, not a
        lock against the manager, the admin or the owner, who reach these
        statuses by their own paths. Superusers always bypass.

        Only a claim held by *someone else* blocks. An unclaimed ticket stays
        actionable, because Tier 2 also works straight from the ticket detail
        page, which has no claim button — requiring a queue round-trip there
        would block legitimate work rather than prevent collisions. The queue
        UI still leads with Claim; this is the guarantee underneath it.
        """
        if user.is_superuser:
            return False
        if self.status not in self.TIER2_QUEUE_STATUSES:
            return False
        if self.t2_claimed_by_id is None:
            return False
        profile = getattr(user, 'profile', None)
        if profile is None or not profile.is_tier2:
            return False
        return self.t2_claimed_by_id != user.pk

    def creator_analyst_can_act(self, user):
        """Return whether ``user`` is this ticket's Tier 1/Tier 2 creator.

        Tier 2 is temporarily allowed to open cases and therefore must receive
        the same creator rights as Tier 1 on preparation, returned-review,
        monitoring, editing, and evidence surfaces.
        """
        from ..actor_access import is_creator_analyst
        return is_creator_analyst(self, user)

    @staticmethod
    def _person_label(user):
        return (user.get_full_name() or user.username) if user else None

    @property
    def court_holder_label(self):
        """Who this ticket is currently waiting on, for display.

        The readable counterpart to policies.holds_ticket_court: that answers
        "is it me?", this answers "then who?". Names the individual where the
        workflow gates on one (the creator, the assigned admin, the owner, a
        Tier 2 who has claimed it) and falls back to the role otherwise, since
        an unclaimed Tier 2 or manager queue really is the whole role's court.
        Returns None for terminal tickets — nobody is waiting on a closed case.
        """
        if self.status in self.TERMINAL_STATUSES:
            return None
        if self.status in (
            self.STATUS_NEW, self.STATUS_T1_REVIEW, self.STATUS_OWNER_REMEDIATED,
            self.STATUS_MONITORING,
        ):
            who = self._person_label(self.created_by)
            return f'Tier 1 ผู้เปิดเคส ({who})' if who else 'Tier 1 ผู้เปิดเคส'
        if self.status in self.TIER2_QUEUE_STATUSES:
            who = self._person_label(self.t2_claimed_by)
            return f'Tier 2 ({who})' if who else 'Tier 2'
        if self.status in self.MANAGER_QUEUE_STATUSES:
            return 'ผู้จัดการ SOC'
        if self.status == self.STATUS_AWAITING_CONTAINMENT:
            who = self._person_label(self.assigned_admin)
            return f'System Admin ({who})' if who else 'System Admin'
        if self.status == self.STATUS_AWAITING_OWNER:
            who = self._person_label(self.system_owner)
            return f'หน่วยงานเจ้าของระบบ ({who})' if who else 'หน่วยงานเจ้าของระบบ'
        return None

    def cancellation_action(self, *, actor, action, **kwargs):
        """Authoritative, audited cancellation entry point for every caller."""
        from ..cancellation import perform_cancellation
        return perform_cancellation(ticket=self, actor=actor, action=action, **kwargs)

    def transition_to(self, new_status, user, note=''):
        with transaction.atomic():
            current = Ticket.objects.select_for_update().get(pk=self.pk)
            if current.status != self.status or current.status == self.STATUS_CANCELLED:
                raise ValidationError('สถานะรายการเปลี่ยนแล้ว กรุณาโหลดหน้าใหม่')
            self._transition_to(new_status, user, note)

    def _transition_to(self, new_status, user, note=''):
        status_map = dict(self.STATUS_CHOICES)

        # ── 1. Validate new_status is a known code ────────────────────── #
        if new_status not in status_map:
            raise ValidationError(f"'{new_status}' ไม่ใช่สถานะที่ถูกต้อง")

        # ── 2. Same-status = note-only update (SOC only; creator-gated) ─ #
        if new_status == self.status:
            profile = getattr(user, 'profile', None)
            if not user.is_superuser and (profile is None or not profile.is_soc):
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC เท่านั้นที่สามารถเพิ่มบันทึกได้'
                )
            if (
                not user.is_superuser
                and self.status in self.CREATOR_REVIEW_STATUSES
                and not self.creator_analyst_can_act(user)
            ):
                raise ValidationError(
                    'เฉพาะผู้เปิด Ticket นี้เท่านั้นที่สามารถตรวจสอบ/เพิ่มบันทึกในขั้นตอนนี้ได้'
                )
            self.save()
            TicketLog.objects.create(
                ticket=self, note=note, status_at_time=self.status, author=user,
            )
            return

        # ── 3. Check legal transition ─────────────────────────────────── #
        if new_status not in self.ALLOWED_TRANSITIONS.get(self.status, []):
            raise ValidationError(
                f"ไม่สามารถเปลี่ยนสถานะจาก "
                f"'{status_map.get(self.status, self.status)}' "
                f"เป็น '{status_map.get(new_status, new_status)}' ได้"
            )

        # ── 3b. Tier 2 queue claim ────────────────────────────────────── #
        if self.t2_claim_blocks(user):
            raise ValidationError(
                'Ticket นี้ถูกเจ้าหน้าที่ Tier 2 คนอื่นรับไปดำเนินการแล้ว'
            )

        prev_status = self.status
        edge = (prev_status, new_status)

        # ── 4. Event/Incident classification gate ─────────────────────── #
        if edge in self.EVENT_CLOSE_TRANSITIONS and not self.is_event:
            raise ValidationError(
                'ต้องจัดประเภทเป็น Event ก่อนจึงจะปิดแบบ Event ได้'
            )
        if edge in self.INCIDENT_TRANSITIONS and not self.is_incident:
            raise ValidationError(
                'ต้องจัดประเภทเป็น Incident ก่อนจึงจะส่งต่อ/ดำเนินการได้'
            )
        # A case may be monitored at most once, and never a Project Incident
        # member (a bundle is a confirmed incident — see can_transition_to).
        if new_status == self.STATUS_MONITORING and self.has_been_monitored:
            raise ValidationError(
                'เคสนี้เคยถูกเฝ้าระวังแล้ว — ไม่สามารถเฝ้าระวังซ้ำได้'
            )
        if new_status == self.STATUS_MONITORING and self.project_incident_id:
            raise ValidationError(
                'Ticket ในกลุ่ม Project Incident ไม่รองรับการเฝ้าระวัง'
            )

        # ── 5. Manager-routing gate (deterministic, view-proof) ───────── #
        # A Project Incident is assessed and forwarded once at group level.
        # No member may be forwarded independently before that Project Review
        # has recorded its Normal/Emergency verdict.
        if (
            self.project_incident_id
            and self.status == self.STATUS_PENDING_MGR_TRIAGE
            and self.project_incident.emergency_decided_at is None
        ):
            raise ValidationError(
                'Member Ticket ของ Project Incident ต้องผ่าน Project Review ก่อนส่งต่อ'
            )

        # 5a. SOC Manager forward honors Tier 1's fixed lane (t1_route): the
        # manager reviews and forwards, but cannot swap Admin ↔ Owner.
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_CONTAINMENT)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "เจ้าของระบบ" — ส่งให้ผู้ดูแลระบบไม่ได้'
            )
        if (edge == (self.STATUS_PENDING_MGR_TRIAGE, self.STATUS_AWAITING_OWNER)
                and self.t1_route != self.T1_ROUTE_OWNER):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "ผู้ดูแลระบบ" — ส่งให้เจ้าของระบบไม่ได้'
            )
        # 5a′. Manager step-back honours the same fixed lane in reverse: a
        # PENDING_MANAGER ticket steps back only into the lane Tier 1 chose.
        if (edge == (self.STATUS_PENDING_MANAGER, self.STATUS_CONTAINMENT_REPORTED)
                and self.t1_route != self.T1_ROUTE_ADMIN):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "เจ้าของระบบ" — ย้อนกลับไปยังผู้ดูแลระบบไม่ได้'
            )
        if (edge == (self.STATUS_PENDING_MANAGER, self.STATUS_PENDING_T2_REVIEW)
                and self.t1_route != self.T1_ROUTE_OWNER):
            raise ValidationError(
                'Ticket นี้ถูกกำหนดเส้นทางเป็น "ผู้ดูแลระบบ" — ย้อนกลับไปยัง Tier 2 (เจ้าของระบบ) ไม่ได้'
            )
        # 5b. Emergency tickets must pass the SOC manager after Tier 2 verifies;
        # non-emergency tickets are closed by Tier 2 and never reach the manager.
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            raise ValidationError(
                'Ticket ฉุกเฉินต้องผ่านการตรวจสอบจากผู้จัดการ SOC ก่อนปิด'
            )
        if (edge == (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ไม่จำเป็นต้องส่งให้ผู้จัดการ — Tier 2 ปิดได้ทันที'
            )
        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_APPROVED)
                and self.requires_manager_verification):
            raise ValidationError(
                'Ticket ฉุกเฉินต้องผ่านการตรวจสอบจากผู้จัดการ SOC ก่อนปิด'
            )
        # 5c. Event-downgrade gate: Tier 2 cannot close an escalation it just
        # downgraded from Incident to Event — the SOC Manager verifies that call
        # first. Confirming an Event Tier 1 already classified is untouched.
        if (edge == (self.STATUS_ESCALATED_T2, self.STATUS_CLOSED_EVENT)
                and self.is_t2_event_downgrade):
            raise ValidationError(
                'Ticket นี้ถูกปรับจาก Incident เป็น Event โดย Tier 2 — '
                'ต้องส่งให้ผู้จัดการ SOC ตรวจสอบก่อนปิด'
            )
        if (edge == (self.STATUS_ESCALATED_T2, self.STATUS_PENDING_MGR_EVENT_REVIEW)
                and not self.is_t2_event_downgrade):
            raise ValidationError(
                'Ticket นี้เป็น Event อยู่แล้วตั้งแต่ Tier 1 — Tier 2 ปิดได้ทันที'
            )

        if (edge == (self.STATUS_PENDING_T2_REVIEW, self.STATUS_PENDING_MANAGER)
                and not self.requires_manager_verification):
            raise ValidationError(
                'Ticket นี้ไม่จำเป็นต้องส่งให้ผู้จัดการ — Tier 2 ปิดได้ทันที'
            )

        # 5c. Response-team gate: no path may close an Incident (→ APPROVED)
        # while a response request (Forensic Analyst / Red Team Manager) is still
        # open. This covers the manager approval AND the Tier-2 direct-close
        # paths, so a non-emergency incident with pending forensics cannot slip
        # closed. CLOSED_EVENT is exempt (a reclassified false alarm still closes).
        if new_status == self.STATUS_APPROVED and self.has_open_response_requests:
            raise ValidationError(
                'ยังมีคำขอทีมตอบสนอง (Forensic Analyst / Red Team Manager) '
                'ที่ยังไม่เสร็จสิ้น — ต้องดำเนินการให้ครบก่อนจึงจะปิด Ticket (อนุมัติ) ได้'
            )

        # ── 6. Check permission ───────────────────────────────────────── #
        required_perm = self.TRANSITION_PERMISSIONS.get(edge)
        profile = getattr(user, 'profile', None)

        if user.is_superuser:
            pass
        elif required_perm == 'TIER1_CREATOR':
            if not self.creator_analyst_can_act(user):
                raise ValidationError(
                    'เฉพาะนักวิเคราะห์ผู้เปิด Ticket นี้เท่านั้นที่สามารถดำเนินการต่อได้'
                )
        elif required_perm == 'TIER2':
            if profile is None or not profile.is_tier2:
                raise ValidationError(
                    'เฉพาะเจ้าหน้าที่ SOC Tier 2 เท่านั้นที่สามารถดำเนินการนี้ได้'
                )
        elif required_perm == 'MANAGER':
            if profile is None or not profile.is_soc_manager:
                raise ValidationError(
                    'เฉพาะผู้จัดการ SOC เท่านั้นที่สามารถอนุมัติได้'
                )
        elif required_perm == 'MANAGER_STEP_BACK':
            if not self._is_emergency_manager(user):
                raise ValidationError(
                    'เฉพาะผู้จัดการ SOC เท่านั้นที่ย้อนขั้นตอนได้'
                )
        elif required_perm == 'ASSIGNED_ADMIN':
            if self.assigned_admin_id is None or user.pk != self.assigned_admin_id:
                raise ValidationError(
                    'เฉพาะผู้ดูแลระบบที่รับผิดชอบ Ticket นี้เท่านั้น'
                    'ที่สามารถส่งรายงานการควบคุมได้'
                )

        # ── 7. Apply transition ───────────────────────────────────────── #
        self.status = new_status
        now = timezone.now()

        # Record when the status actually changed. We only reach here for a real
        # transition (the same-status note-only path returns at step 2), so this
        # field tracks lifecycle moves exactly — never note edits or emergency
        # toggles, which both keep the status unchanged.
        self.status_changed_at = now

        # The Tier 2 claim covers one stage only. Clearing it on every move
        # means a ticket re-entering the queue at a later stage is up for grabs
        # again rather than staying locked to whoever handled the last stage.
        self.t2_claimed_by = None
        self.t2_claimed_at = None

        # Stamp the first-ever escalation to Tier 2 (never cleared afterwards).
        if new_status == self.STATUS_ESCALATED_T2 and self.escalated_to_t2_at is None:
            self.escalated_to_t2_at = now

        # Record what Tier 2 was handed, so a later Event-close can tell a
        # downgrade from a confirmation. A manager rejecting an Event review
        # sends the ticket back as an Incident, and this re-stamps to match.
        if new_status == self.STATUS_ESCALATED_T2:
            if edge == (self.STATUS_PENDING_MGR_EVENT_REVIEW, self.STATUS_ESCALATED_T2):
                # Manager overruled the downgrade: it is an Incident again, and
                # Tier 2 has to handle it rather than re-propose the same close.
                self.classification = self.CLASSIFICATION_INCIDENT
            self.classification_at_escalation = self.classification

        # First hand-off to the system admin = the containment report going
        # out (write-once, mirrors the tracker's วันที่ออกรายงาน).
        if (new_status == self.STATUS_AWAITING_CONTAINMENT
                and self.report_issued_at is None):
            self.report_issued_at = now

        # Direct-to-Owner: mark the case as owner-handled and stamp the first
        # owner contact (write-once). The flag is a permanent record of "this
        # ticket took the owner path", used for dashboard segmentation.
        if new_status == self.STATUS_AWAITING_OWNER:
            self.direct_owner_remediation = True
            if self.owner_contacted_at is None:
                self.owner_contacted_at = now

        # Entering the watch window: stamp the fixed 30-day deadline, mark the
        # ticket monitored (one-way — blocks a second round via the gate above),
        # and reset classification to undetermined, since monitoring means "not
        # Event or Incident yet". The owning Tier 1 sets it again on the way out.
        if new_status == self.STATUS_MONITORING:
            self.monitor_until = now + timedelta(days=self.MONITORING_DURATION_DAYS)
            self.has_been_monitored = True
            self.classification = ''

        # Tier 1's monitoring recommendation is consumed the moment the case
        # leaves the Tier 2 review — never let a stale flag linger.
        if prev_status == self.STATUS_ESCALATED_T2:
            self.monitoring_proposed = False

        # Terminal close on either path — approved_at alone misses CLOSED_EVENT.
        if new_status in self.TERMINAL_STATUSES and self.closed_at is None:
            self.closed_at = now

        # Tier 2 verification sign-off (write-once): set when Tier 2 confirms
        # the containment/remediation was effective and moves the case forward
        # — whether it closes directly or routes to the SOC manager.
        if (
            prev_status in (self.STATUS_CONTAINMENT_REPORTED, self.STATUS_PENDING_T2_REVIEW)
            and new_status in (self.STATUS_PENDING_MANAGER, self.STATUS_APPROVED)
            and self.verified_by_id is None
        ):
            self.verified_by = user
            self.verified_at = now

        # Final approval sign-off (write-once).
        if new_status == self.STATUS_APPROVED and self.approved_by_id is None:
            self.approved_by = user
            self.approved_at = now

        self.save()
        TicketLog.objects.create(
            ticket=self, note=note, status_at_time=new_status, author=user,
        )

    # ------------------------------------------------------------------ #
    # Emergency flag                                                      #
    # ------------------------------------------------------------------ #

    def _is_emergency_manager(self, user):
        """SOC Manager (or superuser) — the only role that may set is_emergency."""
        if user.is_superuser:
            return True
        profile = getattr(user, 'profile', None)
        return profile is not None and profile.is_soc_manager

    def assess_emergency_initial(self, value, user):
        """Record the SOC Manager's INITIAL Normal/Emergency assessment.

        Called from the pre-containment review (PENDING_MGR_TRIAGE) forward
        action. Sets ``is_emergency`` and stamps ``emergency_decided_by/at``
        write-once — even when the verdict is Normal, so there is a positive
        record the decision was made. The forward action's own review note (and
        the transition log) carry the reasoning; this method writes no separate
        log. Permission is enforced by the forward action's manager gate.
        """
        if not self._is_emergency_manager(user):
            raise ValidationError(
                'คุณไม่มีสิทธิ์ประเมินสถานะฉุกเฉินของ Ticket นี้'
            )
        self.is_emergency = bool(value)
        if self.emergency_decided_by_id is None:
            self.emergency_decided_by = user
            self.emergency_decided_at = timezone.now()
        # Persisted by the caller's transition_to() save; kept in-memory here so
        # the two writes share one atomic block.

    def can_reassess_emergency(self, user):
        """Who may reassess ``is_emergency`` AFTER the initial review.

        SOC Manager only (superuser always may), and only while the ticket is
        active and past the pre-containment review — at PENDING_MGR_TRIAGE the
        initial assessment is the control, and terminal tickets are frozen
        (reassessment forbidden after APPROVED / CLOSED_EVENT). A MONITORING case
        is not yet classified (neither Event nor Incident), so an emergency
        verdict is premature there too — the manager assesses it at
        PENDING_MGR_TRIAGE if the watch concludes as an Incident.
        """
        if self.status in self.TERMINAL_STATUSES:
            return False
        if self.status == self.STATUS_PENDING_MGR_TRIAGE:
            return False
        if self.status == self.STATUS_MONITORING:
            return False
        if self.project_incident_id:
            return False
        return self._is_emergency_manager(user)

    def reassess_emergency(self, value, user, reason):
        """Change ``is_emergency`` after the initial review — auditable.

        Requires a written reason and records old value, new value, actor,
        timestamp and reason in the ticket timeline (TicketLog). Forbidden on
        terminal tickets and at PENDING_MGR_TRIAGE (see can_reassess_emergency).
        A no-change reassessment is rejected so the audit trail stays meaningful.
        """
        value = bool(value)
        if not self._is_emergency_manager(user):
            raise ValidationError(
                'คุณไม่มีสิทธิ์เปลี่ยนสถานะฉุกเฉินของ Ticket นี้'
            )
        if self.project_incident_id:
            raise ValidationError(
                'Member Ticket ของ Project Incident ต้องประเมิน Emergency ใหม่จากหน้า Project Incident'
            )
        if not self.can_reassess_emergency(user):
            raise ValidationError(
                'ไม่สามารถประเมินสถานะฉุกเฉินใหม่ได้ในขั้นตอนนี้ '
                '(ปิดเคสแล้ว อยู่ระหว่างเฝ้าระวัง หรืออยู่ในขั้นตรวจก่อนมอบหมาย)'
            )
        reason = (reason or '').strip()
        if not reason:
            raise ValidationError('กรุณาระบุเหตุผลในการประเมินสถานะฉุกเฉินใหม่')
        if value == self.is_emergency:
            raise ValidationError('สถานะฉุกเฉินเป็นค่านี้อยู่แล้ว')
        old = self.is_emergency
        self.is_emergency = value
        self.save(update_fields=['is_emergency', 'updated_at'])
        action = 'ตั้งเป็น' if value else 'ยกเลิก'
        audit = (
            f'🚨 ประเมินสถานะฉุกเฉินใหม่: {action} Emergency '
            f'({old} → {value}) — เหตุผล: {reason}'
        )
        TicketLog.objects.create(
            ticket=self, note=audit, status_at_time=self.status, author=user,
        )

    # ── Manager step-back ────────────────────────────────────────────── #
    # Some forward decisions had no way back at all. The worst was the SOC
    # Manager's own forward at PENDING_MGR_TRIAGE: once sent to a lane, nobody
    # could pull it back, and the emergency verdict was stamped write-once in
    # the same transaction. Approval at PENDING_MANAGER was likewise
    # approve-or-nothing, with no way to ask for more work.
    #
    # Closure is deliberately absent: APPROVED and CLOSED_EVENT stay terminal,
    # so a closed case is still final.
    STEP_BACK_TARGETS = {
        STATUS_AWAITING_CONTAINMENT: STATUS_PENDING_MGR_TRIAGE,
        STATUS_AWAITING_OWNER:       STATUS_PENDING_MGR_TRIAGE,
        # Tier 1 records the owner's report but no longer judges it, so it has
        # no self-service undo for a mis-recorded one. Without this the only
        # way out is to push it to Tier 2 and ask them to bounce it — spending
        # the reviewer's queue on a typo.
        STATUS_OWNER_REMEDIATED:     STATUS_AWAITING_OWNER,
    }

    def step_back_target(self):
        """Where a manager step-back would send this ticket, or None.

        PENDING_MANAGER is resolved from the lane Tier 1 chose, because the
        ticket arrives there from either the admin lane (CONTAINMENT_REPORTED)
        or the owner lane (PENDING_T2_REVIEW) and the two must not be confused.
        """
        if self.status == self.STATUS_PENDING_MANAGER:
            return (
                self.STATUS_CONTAINMENT_REPORTED
                if self.t1_route == self.T1_ROUTE_ADMIN
                else self.STATUS_PENDING_T2_REVIEW
            )
        return self.STEP_BACK_TARGETS.get(self.status)

    def can_step_back(self, user):
        """SOC Manager only, never out of a terminal state.

        Bundle members are allowed. Step-back is a per-system correction, not a
        group decision: after Project Review each member runs its own lane with
        its own admin/owner and OLA clock. A member still awaiting that review
        is excluded for free — PENDING_MGR_TRIAGE has no STEP_BACK_TARGETS
        entry, so step_back_target() is None above.
        """
        if self.status in self.TERMINAL_STATUSES:
            return False
        if self.step_back_target() is None:
            return False
        return self._is_emergency_manager(user)

    def step_back(self, user, reason):
        """Return the ticket one step, with a written reason. Auditable.

        A thin wrapper over transition_to(): the backward edges live in
        ALLOWED_TRANSITIONS (see STEP_BACK_EDGES) under the MANAGER_STEP_BACK
        permission token, so the actual move — status write, status_changed_at,
        Tier 2 claim clearing, the audit log — is the same single code path every
        forward transition uses, not a parallel copy that has to remember each
        invariant again. The write-once stamps (verified_by, approved_by,
        emergency_decided_by …) are untouched because no step-back target is one
        of the statuses transition_to() stamps them on, so stepping back never
        rewrites who decided what.

        The guards here run first so the manager sees a step-back-specific
        message (terminal case, no target, missing reason) rather than the
        generic transition_to() errors.
        """
        if not self._is_emergency_manager(user):
            raise ValidationError('เฉพาะผู้จัดการ SOC เท่านั้นที่ย้อนขั้นตอนได้')
        if self.status in self.TERMINAL_STATUSES:
            raise ValidationError(
                'เคสที่ปิดแล้วไม่สามารถย้อนขั้นตอนได้ — ต้องเปิดเคสใหม่'
            )
        target = self.step_back_target()
        if target is None:
            raise ValidationError('ขั้นตอนนี้ไม่รองรับการย้อนกลับ')
        reason = (reason or '').strip()
        if not reason:
            raise ValidationError('กรุณาระบุเหตุผลในการย้อนขั้นตอน')

        labels = dict(self.STATUS_CHOICES)
        note = (f'↩ ย้อนขั้นตอนโดยผู้จัดการ SOC: '
                f'{labels.get(self.status, self.status)} → '
                f'{labels.get(target, target)} — เหตุผล: {reason}')
        self.transition_to(target, user, note)
        return target


# Late imports to avoid circular dependency at class-definition time.
from .logs import TicketLog  # noqa: E402
from .subtask import TicketSubtask  # noqa: E402
