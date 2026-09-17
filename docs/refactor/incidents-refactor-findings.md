# `incidents` app — scan & refactor findings

_Scan date: 2026-09-17. Scope: `apps/incidents` only. All changes below are
behavior-preserving; the full suite (844 incidents + 326 cross-app tests) stays
green apart from one pre-existing, unrelated failure (see §5)._

## 1. Why this was done

`apps/incidents` is the core of the SOC ticketing system and had outgrown two
files:

| File | Before | After |
|------|-------:|------:|
| `models.py` | **3,649 lines**, 30+ model classes (`Ticket` alone ≈2,000) | split into a `models/` package (11 modules, largest `ticket.py` = 2,076) |
| `views.py` | **2,659 lines**, 49 top-level view/helpers | split into a `views/` package (10 modules, largest `tickets.py` = 775) |

The app was already partly decomposed (`selectors.py`, `policies.py`,
`ticket_workflow.py`, …), so these two monoliths were the last big targets.

## 2. Structural split (behavior-preserving)

Both modules became packages whose `__init__.py` re-exports every public **and
private** name, so all import sites keep working unchanged:

- `from .models import X`, `from apps.incidents.models import X` — 69 sites, untouched.
- `from . import views`, `from apps.incidents.views import X` (incl. private
  helpers the tests import by name, e.g. `_transition_actions`) — untouched.

Module boundaries:

- **models/**: `choices`, `project`, `ticket` (the `Ticket` god-class kept intact
  by decision, with `TicketQuerySet` co-located), `alerts`, `logs`, `triage`,
  `subtask`, `notification_template`, `attachments`, `ioc`, `rca`.
- **views/**: `_helpers` (shared privates), `tickets`, `projects`, `attachments`,
  `reports`, `history`, `triage`, `search`, `response`, `dashboard`.

### Correctness safeguards verified
- `makemigrations --check --dry-run` → **no changes** (schema byte-identical).
- Package-relative imports rewritten one level deeper (`from .ola` →
  `from ..ola`, etc.).
- Circular refs resolved with idiomatic late/bottom imports:
  `models/ticket.py` bottom-imports `TicketLog`/`TicketSubtask`;
  `models/project.py` bottom-imports `Ticket`.
- `logger` pinned to the literal name `'apps.incidents.views'` across all view
  submodules (was `__name__`), preserving log-record source.

### Test patch-paths that had to follow moved symbols
Structural moves change where `mock.patch(...)` must target a module-level
constant/function (a re-exported copy is a different binding than the read-site).
Updated to point at the new module (behavior asserted is unchanged):
- `apps.incidents.models.MAX_ATTACHMENT_SIZE` / `…MAX_ATTACHMENT_BATCH_SIZE`
  → `apps.incidents.models.attachments.*` (tests.py, test_ticket_edit_evidence.py)
- `apps.incidents.views.generate_ticket_report`
  → `apps.incidents.views.reports.generate_ticket_report` (tests.py)

(`requests.get` and `timezone.now` patches keep working — those target shared
module objects, not moved value bindings.)

## 3. Dead code

- **1,133 unused imports** removed (`ruff --select F401 --fix`). Most were an
  artifact of the split's deliberately-broad module headers; the rest pre-existed.
- **0 dead private functions**: a full scan of all 112 private top-level
  functions in the app found none referenced only at their definition. The app
  carries no removable dead helpers. (Note: some public helpers such as
  `ti_import_upload_path` are intentionally retained for historical-migration
  references and must not be removed.)
- No obvious logic duplication surfaced during the split — attachment limits,
  status validation and queryset visibility are already centralized in
  `selectors.py` / `policies.py` / `ticket_workflow.py`.

## 4. Lint ratchet (fixes only — global config unchanged)

Broad scan (`F401,F811,F841,C4,SIM,UP,E711,E712`) after the split:

| Rule | Action |
|------|--------|
| F401 unused-import (1,133) | fixed |
| F811 redefinition (2), C420, UP012 | fixed (autofix) |
| C402 generator→dict-comp (`views/tickets.py`) | fixed |
| UP028 `yield`→`yield from` (`reports.py`) | fixed |
| F841 dead `project = None` (`views/projects.py`) | fixed |
| **Skipped (clarity):** SIM102/103 guard/nested-if collapses in `models/ticket.py` & `case_creation.py` — the explicit forms carry per-branch comments | left as-is |
| **Skipped (style):** ~15 C408 `dict(**kwargs)`→literal (mostly seed commands & tests), UP031 `%`-format & SIM117 nested-`with` in tests | left as-is per the repo's stated no-style-churn policy (`pyproject.toml`) |

The repo's default ruff config (`E9,F63,F7,F82`) passes clean on `apps/incidents`.
`pyproject.toml`'s `select` was **not** widened (decision: apply fixes only).

## 5. Pre-existing bug found — now fixed

`TemplateMarkupRegressionTest.test_no_template_comment_spans_multiple_lines` was
failing on a **multi-line `{# #}` comment at
`templates/incidents/report_preview.html:188`**. This is a real rendering bug:
Django strips `{# #}` line-by-line, so a comment whose closing `#}` is on a later
line is not a comment at all and renders to the page as literal text. Confirmed
failing identically on a clean `HEAD` worktree (predates this refactor).

**Fixed** by converting the note to `{% comment %}…{% endcomment %}`. The
incidents suite is now fully green (844/844).

## 6. Verification summary

- `manage.py check` — clean.
- `makemigrations --check --dry-run` — no changes.
- `apps.incidents` — 844 tests, only the §5 pre-existing failure.
- `apps.dashboard apps.accounts apps.wazuh_ingest apps.reporting` — 326 tests, all pass.
- `ruff check apps/incidents` (repo config) — clean.
