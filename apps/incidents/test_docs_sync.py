"""Guardrail: keep the lifecycle documentation in sync with the state machine.

The workflow docs drifted badly once (the retired ``OWNER_REMEDIATED`` two-step
lived on in the lifecycle doc, both handovers, and the user guide long after the
code moved to a direct ``AWAITING_OWNER -> PENDING_T2_REVIEW`` edge). These tests
fail the build if the *authoritative* lifecycle document
(``docs/architecture/ticket-lifecycle-states.md``) stops matching
``Ticket.STATUS_CHOICES`` / ``Ticket.ALLOWED_TRANSITIONS`` — so the same drift
cannot silently return.

Scope on purpose: only the one doc that declares itself the authoritative
current-workflow reference is checked. Prose docs are downstream of it.
"""
import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from apps.incidents.models import Ticket

# docs/ sits next to the Django project package; BASE_DIR is the repo root.
DOC_PATH = Path(settings.BASE_DIR) / "docs" / "architecture" / "ticket-lifecycle-states.md"

ALL_CODES = [code for code, _label in Ticket.STATUS_CHOICES]


def _codes_in(text):
    """Status codes that appear as whole tokens in ``text``."""
    return {c for c in ALL_CODES if re.search(rf"\b{re.escape(c)}\b", text)}


def _forward_targets(frm):
    """ALLOWED_TRANSITIONS targets for ``frm`` minus the backward step-back edges.

    The authoritative lifecycle doc describes the *forward* flow; manager
    step-back edges (STEP_BACK_EDGES) are a correction mechanism documented
    separately, so the graph-shape and transition-table checks below reason over
    the forward edges only — otherwise every step-back edge would demand a row in
    the forward transition table and distort the '12 active + 1 legacy' framing.
    """
    return [
        target
        for target in Ticket.ALLOWED_TRANSITIONS.get(frm, [])
        if (frm, target) not in Ticket.STEP_BACK_EDGES
    ]


class LifecycleDocIsPresent(SimpleTestCase):
    def test_authoritative_doc_exists(self):
        self.assertTrue(
            DOC_PATH.is_file(),
            f"authoritative lifecycle doc missing at {DOC_PATH}",
        )


class LifecycleDocMatchesStateMachine(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.doc = DOC_PATH.read_text(encoding="utf-8")

    def test_every_status_code_is_documented(self):
        """A status added to the code but not the doc fails here."""
        missing = [c for c in ALL_CODES if not re.search(rf"\b{re.escape(c)}\b", self.doc)]
        self.assertEqual(
            missing, [],
            f"status codes in STATUS_CHOICES but absent from {DOC_PATH.name}: {missing}",
        )

    def test_owner_remediated_is_the_sole_legacy_state(self):
        """OWNER_REMEDIATED must stay reachable-out but never reachable-in.

        This is the exact invariant the docs violated. If a future change wires
        an edge back into it (or another state loses all inbound edges), the doc
        framing of "12 active + 1 legacy" is wrong and this fails.
        """
        forward = {code: _forward_targets(code) for code in Ticket.ALLOWED_TRANSITIONS}
        inbound = {
            target
            for targets in forward.values()
            for target in targets
        }
        legacy = {
            code
            for code, targets in forward.items()
            # reachable-out but not reachable-in, excluding NEW (the initial
            # state, which is legitimately never a transition target)
            if targets and code not in inbound and code != Ticket.STATUS_NEW
        }
        self.assertEqual(
            legacy, {Ticket.STATUS_OWNER_REMEDIATED},
            "expected OWNER_REMEDIATED to be the only reachable-out / not-reachable-in "
            f"state, got {legacy}",
        )

    def test_doc_marks_owner_remediated_legacy(self):
        """The doc must label OWNER_REMEDIATED 'legacy' near at least one mention."""
        code = Ticket.STATUS_OWNER_REMEDIATED
        self.assertIn(code, self.doc)
        window = 200
        labelled = any(
            "legacy" in self.doc[max(0, m.start() - window): m.end() + window].lower()
            for m in re.finditer(re.escape(code), self.doc)
        )
        self.assertTrue(
            labelled,
            "OWNER_REMEDIATED is documented but not labelled 'legacy' near any mention",
        )

    def test_transition_table_matches_allowed_transitions(self):
        """Every non-terminal state's documented targets == its code targets.

        Parses the "Transition reference" markdown table: for each row whose
        first cell names exactly one status code (the FROM), the set of status
        codes in the second cell (the TO) must equal ALLOWED_TRANSITIONS[FROM].
        Catches a missing edge (drift) or a documented edge the code dropped.
        """
        # Scope to the one authoritative "Transition reference" table — the doc
        # has other explanatory tables (e.g. "Event close | Manager?") whose
        # first cell also names a status and would corrupt the parse.
        start = self.doc.find("## Transition reference")
        self.assertNotEqual(start, -1, "‘## Transition reference’ section not found")
        end = self.doc.find("**Terminal states:**", start)
        if end == -1:
            end = len(self.doc)
        section = self.doc[start:end]

        documented = {}
        for line in section.splitlines():
            if not line.lstrip().startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 2:
                continue
            from_codes = _codes_in(cells[0])
            if len(from_codes) != 1:
                continue  # header, separator, or prose row — not a FROM row
            (frm,) = tuple(from_codes)
            documented[frm] = _codes_in(cells[1])

        for frm in Ticket.ALLOWED_TRANSITIONS:
            expected = set(_forward_targets(frm))
            if not expected:
                continue  # terminal state — no forward row expected
            self.assertIn(
                frm, documented,
                f"transition table has no row for {frm}",
            )
            self.assertEqual(
                documented[frm], expected,
                f"{frm}: doc lists targets {sorted(documented[frm])} but "
                f"ALLOWED_TRANSITIONS says {sorted(expected)}",
            )
