# Codex Handoff — RCA Report, Phase 3 (Forensic Analyst UI)

> Purpose: hand the Root Cause Analysis (RCA) report feature to Codex to build **Phase 3**
> (the analyst-facing UI). Phases 1–2 (data model, service layer, DOCX draft generator, and the
> house-styled template) are done. **Do not implement Phase 3 from this document without reading
> the referenced code first.**
>
> **Fact convention:** lines marked **[V]** are verified against the repo at the state described in
> "Current state" below. Lines marked **[A]** are assumptions/recommendations to confirm. Line
> numbers drift with edits — trust the **symbol names**, treat `~Lnnn` as a hint.

---

## 1. Project goal and architecture

**[V]** This is a Django SOC incident-ticketing system (`Getter939/SOC_Ticket`). Thai-language UI.
Key apps: `apps/incidents` (tickets, subtasks, reports, IOC database), `apps/accounts`
(roles/`UserProfile`), `apps/wazuh_ingest` (alert ingest), `apps/dashboard`, `apps/reporting`.
Config in `config/settings.py` (Postgres; `TIME_ZONE = 'Asia/Bangkok'`, `USE_TZ = True`); dev
runserver uses `config.settings_local` (see `.claude/launch.json`).

**[V]** A **Ticket** moves through a state machine (`Ticket.STATUS_*`, `ALLOWED_TRANSITIONS`,
`transition_to`). Roles are on `apps/accounts/models.py::UserProfile` (`ROLE_SOC_STAFF`,
`ROLE_SOC_MANAGER`, `ROLE_SYSTEM_ADMIN`, `ROLE_SYSTEM_OWNER`, `ROLE_FORENSIC`,
`ROLE_REDTEAM_MANAGER`). See `CONTEXT.md` and `AGENTS.md` for domain terms and agent conventions.

**The RCA feature (this project):** A SOC Manager spawns a **`FORENSIC_RCA` response request**
(`apps/incidents/models.py::TicketSubtask`, one of `TicketSubtask.RESPONSE_TYPES`) on an Incident
ticket. It routes to the **Forensic Analyst** (`ROLE_FORENSIC`). Historically the analyst's only
deliverable was a free-text `TicketSubtask.result_notes` + one attached file. This feature lets the
analyst capture the RCA as **structured data** and generate a **prefilled DOCX draft** they finish
in Word and upload back to the request.

**Reports architecture (reused):** `apps/incidents/reports.py` renders the Incident/Event reports
from a Django-free layout spec in `apps/incidents/report_content.py`, filling a committed `.docx`
template via `{{placeholder}}` substitution (`_replace_placeholders`, which **raises `ValueError` on
any leftover `{{...}}`**). RCA mirrors this: layout in `apps/incidents/rca_content.py`, service in
`apps/incidents/rca.py`, template `apps/incidents/report_templates/rca_report_template_v1.docx`.

**Report numbering:** `reports.py::_report_ticket_id(ticket, kind=None)` → `SOC-INC-YYYYMM-NNNN` /
`SOC-EVE-...` from classification, or `SOC-<KIND>-YYYYMM-NNNN` for `kind in {'RCA','VAPT','HARD'}`
(reuses the parent ticket's number). RCA calls it with `kind='RCA'`.

---

## 2. What Phases 1 and 2 accomplished

### Phase 1 — data model + service + policies (COMMITTED in `4123007`) **[V]**
- **Models** (`apps/incidents/models.py`): `RCAReport` (OneToOne → `TicketSubtask`, Section-1
  fields + `draft_*` provenance + `has_stale_draft` property), `RCAAsset`, `RCATimelineEntry`,
  `RCARootCause`, `RCARecommendation` (M2M `root_causes`), `RCAIndicator` (per-category, `excluded`,
  `source`, `pushed_ioc`). Also `AnalystIOC.source_subtask` FK. Migration
  `apps/incidents/migrations/0076_rca_report.py` (**depends on `0075_report_batch3_fields`**;
  accounts head is `0012`).
- **Service** (`apps/incidents/rca.py`): `get_or_create_rca`, `initial_section1` (ticket prefill),
  `refresh_section1_from_ticket`, `start_request` (OPEN→IN_PROGRESS), `record_edit` (stamps
  `updated_*`, audits, starts request), `pull_ticket_iocs`, `classify_ioc_push`, `push_iocs`
  (reuses `ti_platform.create_manual_iocs(..., source_subtask=)`), `import_timeline_csv`,
  `timeline_csv_template`, `case_number`.
- **Policies** (`apps/incidents/policies.py`): `can_view_rca(subtask, user)`,
  `can_edit_rca(subtask, user)`, `can_push_rca_iocs(subtask, user)`.
- **Audit** (`apps/incidents/history.py`): `record_rca_change(subtask, section_label, summary, user)`.
- **Tests**: `apps/incidents/test_rca.py`.

### Phase 2 — DOCX draft generator + house-style template (UNCOMMITTED working tree) **[V]**
- **Restyled** `apps/incidents/report_templates/rca_report_template_v1.docx` (and its builder
  `scripts/build_rca_report_template_v1.py`) to the **NT house style**, matching
  `report_template_v2` (Incident) and `event_report_template_v1` (Event): NT logo header, GOLD
  title banner + Thai subtitle, `SECTION_YELLOW` section bands, `LABEL_GRAY` label column + table
  headers, TH Sarabun New 16pt, Letter 8.5×11, 6.6" content width, muted footer with PAGE/NUMPAGES.
  Palette + helpers are imported from `scripts/build_report_template_v2.py`. Deleted the now-unused
  `assets/tlp_amber.png`.
- **Generic repeat-row expander** (`apps/incidents/reports.py`): `_expand_docx_repeat_rows(doc,
  prefix, rows)` + `_fill_docx_row(row, values)` — clones a table's single prototype row (the row
  carrying `{{prefix_*}}`) once per item; blanks placeholders when there are no rows.
- **Generator** (`apps/incidents/rca.py`): `generate_rca_draft(rca, user)` → `(filename, bytes)`.
  Fills Section 1 (`_section1_context`, checkboxes via `reports._chk`), expands the assets/timeline/
  root-cause/IOC/recommendation tables (`_repeat_rows`), derives `RC-n` codes from order and cites
  them in recommendations, records `draft_*` on the `RCAReport` **only** (never `Ticket.report_*`).
  Filename: `report_SOC-RCA-YYYYMM-NNNN_rca-v1.docx`.
- **Tests**: added draft/template tests to `apps/incidents/test_rca.py` (37 total, all pass).

**Not built yet:** any UI. There are **no** RCA views, URLs, forms, or templates. The
`can_view_rca` / `can_edit_rca` / `can_push_rca_iocs` policies and the whole service layer have **no
callers outside tests**.

---

## 3. Current state: branch, commits, uncommitted changes

- **[V] Branch:** `main`. Remote repo: `Getter939/SOC_Ticket`.
- **[V] Relevant commits:**
  - `4123007` "15/9 RCA Report Model + Manager temporary function" — Phase 1 RCA (models/migration
    0076/`rca.py`/`rca_content.py`/policies/history/`ti_platform` change/tests) **plus two unrelated
    features in the same commit**: the report-number scheme (`reports.py`, `tests.py`,
    `report_preview.html`) and the acting-tier SOC-Manager feature (`apps/accounts/*`, `views.py`).
  - `f6a6fe3` "14/9 Bundled Alerts Fix", `7e091e4` "11/9 Ticket form/detail UI fix".
- **[V] Uncommitted working tree** (`git status`):
  - **Phase 2 RCA (this session):** `apps/incidents/rca.py`, `apps/incidents/reports.py`,
    `apps/incidents/test_rca.py`, `scripts/build_rca_report_template_v1.py`,
    `apps/incidents/report_templates/rca_report_template_v1.docx` (rebuilt), and deletion of
    `apps/incidents/report_templates/assets/tlp_amber.png`.
  - **NOT part of RCA — do not conflate:** `apps/incidents/tests.py` (+47: three
    `ActingTierManagerCreateTest` flow tests) and `CHANGELOG.md` (v1.5.3 entry covering both the
    acting-tier feature and RCA groundwork). These belong to the acting-tier feature.
- **[V] Constraint:** the repo owner commits themselves — **do not `git commit` or `git push`**
  unless asked. Leave changes uncommitted. If you do commit, keep RCA changes separate from the
  acting-tier `tests.py`/`CHANGELOG.md` changes.

---

## 4. Important files and their roles

| Path | Role | State |
|---|---|---|
| `apps/incidents/models.py` | `RCAReport`, `RCAAsset`, `RCATimelineEntry`, `RCARootCause`, `RCARecommendation`, `RCAIndicator`; `TicketSubtask` (`TYPE_FORENSIC_RCA`, `RESPONSE_TYPES`, `TERMINAL_STATUSES`, `status`); `Ticket` (`STATUS_*`, `TERMINAL_STATUSES`, `STATUS_CLOSED_EVENT`); `AnalystIOC.source_subtask` | committed |
| `apps/incidents/rca.py` | RCA service — read the module docstring; all Phase-3 backend calls live here | rca.py modified (Phase 2) |
| `apps/incidents/rca_content.py` | Django-free layout spec: `RCA_SECTION1_ROWS`, per-table `RCA_*_COLUMNS`, `RCA_REPEAT_TABLES`/`RCA_REPEAT_PREFIXES`, `RCA_TEMPLATE_VERSION`, guidance | committed |
| `apps/incidents/reports.py` | `_expand_docx_repeat_rows`, `_fill_docx_row`, `_replace_placeholders`, `_report_ticket_id`, `_chk`, `_iter_docx_tables` | modified (Phase 2) |
| `apps/incidents/policies.py` | `can_view_rca`, `can_edit_rca`, `can_push_rca_iocs`, `can_upload_subtask_result`, `can_access_ticket_report`, `is_soc`, `is_soc_manager` | committed |
| `apps/incidents/history.py` | `record_rca_change`, `record_subtask_status_change`, `record_subtask_change` | committed |
| `apps/incidents/ti_platform.py` | `create_manual_iocs(entries, user, source_subtask=None)`, `_is_duplicate`, `can_manage_inventory`, `build_ioc_database` | committed |
| `apps/incidents/views.py` | `update_subtask` (~L2150), `create_response_request` (~L2103), `response_request_queue` (~L2220), `ticket_detail` (context incl. `can_request_response` ~L1079, `is_terminal` ~L983), `ticket_report_docx/pdf/preview` (~L1456–1506) | to extend |
| `apps/incidents/urls.py` | route table; RCA routes to be added near the report/subtask routes (L29–45) | to extend |
| `apps/incidents/selectors.py` | `get_ticket_detail_read_model` — prefetches subtasks/attachments/field_changes for the detail page | to extend (surface RCA summary) |
| `templates/incidents/ticket_detail.html` | `#tasks` section (~L336); the per-subtask responder update form + its `{% if not is_terminal %}` gates (~L448, L451); `result_file` input (~L457) | to extend |
| `templates/incidents/response_request_queue.html` | Forensic "Response Requests" queue; row → `ticket_detail#tasks` (~L54, L62) | optional link target |
| `templates/incidents/_structured_ioc_fields.html`, `templates/incidents/project_incident_form.html` | **Precedents for add-row inline JS with `nonce="{{ request.csp_nonce }}"`** | reference |
| `apps/incidents/report_templates/rca_report_template_v1.docx` | the filled template | modified (Phase 2) |
| `scripts/build_rca_report_template_v1.py` | rebuilds that .docx | modified (Phase 2) |
| `apps/incidents/test_rca.py` | RCA tests (service, policies, CSV, IOC, template, draft) | modified (Phase 2) |

---

## 5. Technical decisions, constraints, rejected approaches

### Decisions (all **[V]** confirmed with the product owner during Phases 1–2)
- **Authoring model:** structured data in-system → **DOCX draft** → analyst finishes narrative in
  Word → uploads final to the request. Regenerating a draft does **not** carry Word edits back.
- **Structured (in-system):** Section 1, Section 4 assets, Section 5 timeline, Section 6.2 root
  causes, Section 7 IOC tables, Section 8 recommendations.
- **Word-only (guidance text in the draft, never in-system):** Section 2 exec summary, Section 3
  diagrams, Section 5/8 intros, Section 6.1 causal narrative, Section 7.2 file behavior.
- **Timeline input:** manual rows **and** CSV/TSV import via the system template
  (`rca.timeline_csv_template()`, columns in `rca.TIMELINE_CSV_COLUMNS`).
- **IOCs:** pull ticket IOCs into the report; push new ones to the IOC Database via an **explicit
  button with a preview** (`classify_ioc_push` → confirm → `push_iocs`); per-indicator `excluded`
  flag; only `hash/ip/domain/url/file_path` are pushable — **email & account stay report-only**.
- **Root-cause "type":** free text (`RCARootCause.category`).
- **Approval:** none. The Forensic Analyst marks the `FORENSIC_RCA` request DONE; the final upload
  is **optional**.
- **Access:** anyone who can see the ticket may view the RCA and download the draft
  (`can_view_rca`); edit = assignee / SOC Manager / superuser while the request is open
  (`can_edit_rca`).
- **CLOSED_EVENT:** the analyst may keep editing/closing the request after the parent Event closes
  (`can_edit_rca` already allows `STATUS_CLOSED_EVENT`); `APPROVED`/`CANCELLED` parents freeze it.
- **First edit** moves the request OPEN→IN_PROGRESS (`rca.record_edit`→`start_request`).
- **Draft provenance** lives on `RCAReport.draft_*`, **never** on `Ticket.report_*` (single-slot).

### Constraints **[V]**
- **CSP nonce:** `settings_local` enforces a nonce-based CSP; inline `<script>` **must** carry
  `nonce="{{ request.csp_nonce }}"` or it is silently blocked. Copy the pattern from
  `_structured_ioc_fields.html` / `project_incident_form.html`.
- `_replace_placeholders` raises on any unresolved `{{...}}`; do not introduce placeholders the
  generator won't fill.
- Ruff is the linter/formatter (`pyproject.toml`, `line-length = 100`).
- Tests subclass `apps.accounts.testing.MFATestCase` (aliased `as TestCase`), not Django's.
- No autonomous commits; `.ps1` scripts must stay pure ASCII (prod is Windows).

### Rejected / out of scope **[V]**
- Editing narrative sections in-system; PDF output; an approval/sign-off step; auto-pushing IOCs on
  DONE; email/account categories in the IOC Database; RC-type as an enum; RCA spanning a
  `ProjectIncident` bundle; the dark ODT palette for the template (replaced with house style);
  VA-PT / Hardening / Threat-Hunt report generators (separate future work).

---

## 6. Phase 3 requirements and acceptance criteria

**Goal:** a Forensic Analyst can, from a `FORENSIC_RCA` request, open an RCA **workspace**, enter
all structured data, import a timeline CSV, pull/push IOCs, generate/download the DOCX draft, upload
the finished report, and mark the request DONE — entirely in the app.

### Requirements
R1. **Entry point** on `ticket_detail.html` `#tasks`: for a `FORENSIC_RCA` subtask, a link/button to
its RCA workspace + a one-line summary (case no., row counts, last-draft by/at, stale flag). Add a
link from `response_request_queue.html`.
R2. **Workspace page** `templates/incidents/rca_workspace.html` + view: Section 1 form; inline
formsets for assets (S4), timeline (S5), root causes (S6.2), recommendations (S8, with a root-cause
multi-select); Section 7 indicators grouped by table with the `excluded` checkbox. **Each section
saves independently** (a bad field in one must not lose a long timeline in another). Read-only render
when `can_edit_rca` is false. Add-row JS carries the CSP nonce.
R3. **Section-1 "refresh from ticket"** action → `rca.refresh_section1_from_ticket`.
R4. **Timeline CSV**: a download-template link (`rca.timeline_csv_template`) and an import form
(`rca.import_timeline_csv`), surfacing per-row errors from its `ValidationError`.
R5. **IOC pull** (`rca.pull_ticket_iocs`) and **IOC push** (GET preview via
`rca.classify_ioc_push`, POST confirm via `rca.push_iocs`), gated by `can_push_rca_iocs`.
R6. **Draft download** (POST) via `rca.generate_rca_draft`, returning a `FileResponse`
(`content_type` = the DOCX type used in `reports.REPORT_CONTENT_TYPE`), gated by `can_view_rca`.
R7. **Stale-draft notice** using `RCAReport.has_stale_draft`.
R8. **Final-report upload label:** add a `result_file_desc` text input to the responder update form
in `ticket_detail.html` (the view **already reads** `request.POST.get('result_file_desc')` at
`views.py` ~L2207) so the uploaded final can be labelled e.g. "รายงาน RCA ฉบับสมบูรณ์".
R9. **CLOSED_EVENT edit fix:** allow updating/closing a response request whose parent is
`STATUS_CLOSED_EVENT` (see §8 bug). Keep `APPROVED`/`CANCELLED` frozen.

### Acceptance criteria (make these tests in `apps/incidents/test_rca.py` / `test_ui_smoke.py`)
- AC1: The assignee (Forensic) GETs the workspace (200) and sees prefilled Section 1; a non-assignee
  who can see the ticket gets a **read-only** workspace; an unrelated System Admin (not assigned)
  is refused (mirror `can_view_rca`).
- AC2: Posting each section persists only that section and creates a `TicketFieldChange` with
  `field_name='rca'` (via `record_edit`); the first such save flips the request to IN_PROGRESS.
- AC3: Importing the template CSV adds the rows; a malformed CSV imports **nothing** and reports the
  bad line(s).
- AC4: The IOC push preview lists created/duplicate/excluded/unsupported buckets; confirming creates
  `AnalystIOC` rows with `source_subtask` set and never pushes email/account; re-push is idempotent.
- AC5: Draft download returns a `.docx` named `report_SOC-RCA-YYYYMM-NNNN_rca-v1.docx`, with no
  leftover `{{`, and does **not** modify `Ticket.report_*`.
- AC6: On a `STATUS_CLOSED_EVENT` parent, the assignee can still save the RCA and mark the request
  DONE; on `APPROVED`/`CANCELLED` they cannot.
- AC7: Every new inline `<script>` includes `request.csp_nonce`.
- AC8: `ruff check` clean on changed files; full `apps.incidents` suite green except the known
  pre-existing failure (§10).

---

## 7. Implementation plan (dependency order)

1. **Forms** (`apps/incidents/forms.py`): `RCASection1Form` (ModelForm on `RCAReport` — the
   Section-1 fields; render `forensic_types` as multiple checkboxes matching
   `RCAReport.FORENSIC_TYPE_CHOICES`); `modelformset_factory`/`inlineformset_factory` for `RCAAsset`,
   `RCATimelineEntry`, `RCARootCause`, `RCARecommendation` (recommendation form exposes the
   `root_causes` M2M scoped to this RCA's root causes), and `RCAIndicator`. Reuse field labels from
   the models. Validate via each model's `clean()` (e.g. `RCAIndicator.clean` normalizes values).
2. **View helpers**: a small `_load_rca_for(request, subtask_id)` that fetches the subtask, checks
   `can_view_rca`, and calls `rca.get_or_create_rca` (create only when `can_edit_rca`). Centralize
   the read-only vs editable decision with `policies.can_edit_rca` / `can_push_rca_iocs`.
3. **Views** (`apps/incidents/views.py`): `rca_workspace` (GET render; POST per-section save keyed by
   a `section` field), `rca_section1_refresh`, `rca_timeline_import`, `rca_timeline_template`
   (returns the CSV with a UTF-8 BOM so Excel shows Thai), `rca_iocs_pull`, `rca_iocs_push` (GET
   preview + POST confirm), `rca_draft` (POST → `FileResponse`). Wrap edits so a failed section
   re-renders with errors without touching others. Every mutating view: re-check `can_edit_rca` (or
   `can_push_rca_iocs`) and call `rca.record_edit` where appropriate (the service already does for
   CSV/pull/push; section saves should call it too).
4. **URLs** (`apps/incidents/urls.py`, near L41–45): `rca/<int:subtask_id>/` (workspace),
   `rca/<int:subtask_id>/section1/refresh/`, `.../timeline/import/`, `.../timeline/template.csv`,
   `.../iocs/pull/`, `.../iocs/push/`, `.../draft.docx`.
5. **Template** `templates/incidents/rca_workspace.html`: extend the project's base template; one
   `<form>` per section (POST to the workspace with a hidden `section`); inline formsets with add-row
   JS (nonce!); the IOC push preview screen; the stale-draft banner; a read-only variant.
6. **Detail-page integration** (`templates/incidents/ticket_detail.html` + `selectors.py` +
   `ticket_detail` context): the R1 button + summary on the `FORENSIC_RCA` row; the R8
   `result_file_desc` input.
7. **CLOSED_EVENT fix** (R9): relax the terminal guard in `views.update_subtask` (~L2160) and the
   two `{% if not is_terminal %}` gates in `ticket_detail.html` (~L448, L451) to permit
   `STATUS_CLOSED_EVENT` while still refusing `APPROVED`/`CANCELLED`. Prefer a single helper (e.g.
   `Ticket.TERMINAL_STATUSES - {STATUS_CLOSED_EVENT}` or a policy predicate) so the view, the two
   template gates, and `can_edit_rca` agree. Add a regression test that a non-RCA response request
   is also updatable on CLOSED_EVENT (this is a general response-team behavior, not RCA-only).
8. **Tests** (`test_rca.py`, `test_ui_smoke.py`): the AC1–AC8 cases. Use `_user`, `_ticket`,
   `_rca_request`, `_bkk` already in `test_rca.py`; `force_login` + `Client` for view tests.
9. **Docs** (final, optional this phase): `CONTEXT.md` glossary entry; Forensic role manual under
   `docs/user-guides/manuals`; a CHANGELOG entry (separate from the acting-tier one already present).

---

## 8. Known bugs, risks, assumptions, unresolved questions

### Bugs / must-fix
- **[V] CLOSED_EVENT block (R9).** `views.update_subtask` refuses when
  `ticket.status in Ticket.TERMINAL_STATUSES`, and `Ticket.TERMINAL_STATUSES` **includes**
  `STATUS_CLOSED_EVENT`; the `ticket_detail.html` update form is likewise hidden by `is_terminal`.
  This contradicts `policies.can_edit_rca`, which deliberately allows `CLOSED_EVENT`. Until fixed, a
  Forensic Analyst cannot finish an RCA on a closed Event even though the policy permits it. Confirm
  `STATUS_CLOSED_EVENT` ∈ `TERMINAL_STATUSES` in `models.py` before editing.

### Risks
- **[V] Placeholder integrity:** `_replace_placeholders` raises on leftover `{{...}}`. If Phase 3
  changes `rca_content.py` columns/keys, keep the template builder, the generator's `_repeat_rows`
  keys, and the content spec in lockstep (guarded by `test_template_carries_exactly_the_content_spec`
  and `test_forensic_types_match_the_model`).
- **[V] CSP:** inline JS without the nonce silently fails — easy to miss in review.
- **[A] Concurrency / large timelines:** per-section saves + all-or-nothing CSV import mitigate lost
  work; consider optimistic handling if two people edit one RCA (low likelihood — usually one FA).
- **[A] Formsets vs. free-text ordering:** the `order` fields drive rendering and `RC-n` codes;
  ensure the UI writes stable `order` values.

### Assumptions to confirm **[A]**
- The workspace is a standalone page (not an expander inside `ticket_detail`), reachable from the
  `#tasks` row. (Plan assumed a page.)
- All seven `RCAIndicator` categories (incl. email/account) are editable in the workspace even
  though email/account are report-only for the IOC Database.
- Draft download is offered to any `can_view_rca` user (read-only viewers included).
- Thai UI copy throughout, consistent with existing templates.

### Unresolved questions for the owner
- Should the "Response Requests" queue show an RCA-specific status/progress column, or is the
  ticket-detail summary enough?
- Should generating a draft auto-set the request to IN_PROGRESS if still OPEN (currently only
  data edits do)?

---

## 9. Commands (Windows dev box)

Python is the venv interpreter; there is no global `python` on PATH.

```powershell
# From repo root C:\Users\NT\Documents\SOC_Ticket
.\venv\Scripts\python.exe manage.py migrate                    # apply migrations incl. 0076 (do this first)
.\venv\Scripts\python.exe manage.py makemigrations incidents   # after any model change
.\venv\Scripts\python.exe scripts\build_rca_report_template_v1.py   # rebuild the RCA .docx template

# Tests
.\venv\Scripts\python.exe manage.py test apps.incidents.test_rca --keepdb --noinput
.\venv\Scripts\python.exe manage.py test apps.incidents --keepdb --noinput
# If unrelated tests fail on a --keepdb run, re-run once WITHOUT --keepdb (ThreatGuidance seed-wipe trap).

# Lint / format (ruff, line-length 100)
.\venv\Scripts\python.exe -m ruff check apps/incidents
.\venv\Scripts\python.exe -m ruff format apps/incidents

# Run the app (dev)
.\venv\Scripts\python.exe manage.py runserver 8088 --settings=config.settings_local
```

**[A]** `ruff` is configured in `pyproject.toml` but not verified as installed in the venv; if
`python -m ruff` is missing, install per the repo's dependency process before relying on it.

**Rendering a DOCX for visual review** (LibreOffice is at
`C:\Program Files\LibreOffice\program\soffice.exe`): convert to PDF, then split per page with
`pypdf` and convert each 1-page PDF to PNG — Writer's direct PNG export only emits page 1, and the
PDF→PNG step garbles Thai glyph shaping (the `.docx` itself is correct). Use a throwaway
`-env:UserInstallation=` profile dir.

---

## 10. Current test status

**[V]** `apps.incidents.test_rca` — **37 passed**. Full `apps.incidents` — **789 passed, 1 failed**.

**Expected failure (pre-existing, NOT caused by this work):**
`apps.incidents.tests.AttachmentWorkflowPermissionTest.test_detail_page_shows_attachment_accountability_metadata`
("Couldn't find 'Uploaded by'"). Confirmed failing on clean `HEAD` in earlier sessions. Treat as
baseline; do not let it block Phase 3, but do not "fix" it unprompted.

---

## 11. Recommended first task for Codex

**Start with R9 (the CLOSED_EVENT fix) — it is the smallest, is a genuine bug, unblocks the whole
RCA-on-closed-Event path, and touches code you must understand before building the workspace.**

1. In `apps/incidents/models.py`, confirm `Ticket.STATUS_CLOSED_EVENT ∈ Ticket.TERMINAL_STATUSES`
   and note `STATUS_APPROVED` / `STATUS_CANCELLED`.
2. Introduce one predicate for "response requests are frozen" — either a `policies` helper or reuse
   `can_edit_rca`'s rule (`status in TERMINAL_STATUSES and status != STATUS_CLOSED_EVENT`).
3. Apply it in `views.update_subtask` (~L2160) and the two `{% if not is_terminal %}` gates around
   the responder update form in `templates/incidents/ticket_detail.html` (~L448, L451). Keep the
   ticket-content terminal freeze elsewhere untouched.
4. Add tests to `apps/incidents/test_rca.py` (RCA request editable/closable on CLOSED_EVENT, frozen
   on APPROVED/CANCELLED) and one to the response-team suite (a plain response request is also
   updatable on CLOSED_EVENT).
5. Run `apps.incidents.test_rca` and the response-team tests; confirm only the §10 baseline failure
   remains.

Then proceed through §7 in order (Forms → Views → URLs → Template → Detail integration → Tests),
building the workspace against the existing `apps/incidents/rca.py` service — which already provides
every backend operation Phase 3 needs. Read `apps/incidents/rca.py` and `apps/incidents/rca_content.py`
in full before writing the UI.
