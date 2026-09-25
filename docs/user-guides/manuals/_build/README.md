# Role manual build scripts

Generators for the per-role Thai user manuals (`../user-manual-*.th.docx`).
Each manual is a Word `.docx` built with [docx-js](https://docx.js.org/).

## Layout

- `common.js` — shared design system (TH Sarabun New, navy/blue palette, callouts,
  screenshot placeholders, styled tables) and the `buildManual()` assembler
  (cover, dynamic TOC, running header/footer). Edit this to restyle **all** manuals.
- `build-tier1.js` — the Tier 1 manual (self-contained: it predates `common.js` and
  carries its own copy of the helpers). The other scripts `require('./common')`.
- `build-tier2.js`, `build-manager.js`, `build-admin.js`, `build-owner.js`,
  `build-exec.js`, `build-response-teams.js` (Forensic + Red Team Manager) — one
  script per persona; content only.

`build-response-teams.js` builds **two** manuals from one shared body, forked on
**two independent flags**:

- `readsAllTickets` — the Forensic Analyst reads every ticket (read-only, v1.3.1) and
  owns the IOC Database section; the Red Team Manager sees only tickets carrying a
  request assigned to them.
- `ownsRcaRequests` — the Forensic Analyst hands in Forensics / RCA requests with a
  report number (prefilled `SOC-RCA-YYYYMM-NNNN`, editable), an optional **หมายเหตุ**
  and **no file**, because the RCA report is written outside the system. The Red
  Team Manager instead enters a report number (guided by `VA-YYYY-NNNN`,
  `PT-YYYY-NNNN`, or `BL-YYYY-NNNN`), optional notes, and no file. Each
  Red Team account is designated for one function in admin. The manual also notes that the legacy intra-SOC subtask
  form is gone. The report number is **mandatory for every response type**. This flag
  was `hasRcaWorkspace` until the RCA workspace was retired (CHANGELOG [Unreleased]);
  the workspace section and its glossary rows are gone.

Both personas share the **การทำงานกับคำขอ** intro and the **รับงาน** subsection. Both are
written around the **"งานของคุณ" card** (`templates/incidents/_my_response_request.html`),
which sits at the top of the ticket page's action column. The card carries a
รับงาน → ดำเนินการ → ส่งงาน tracker, the รับงาน button and an always-open completion
form with **ส่งงาน · เสร็จสิ้น** and **บันทึกไว้ก่อน**. The assignee's own row in the
request list only links up to the card. **Do not send responders to อัปเดตงาน**: only
the SOC Manager still uses that inline form, so it belongs in the manager manual alone.

These were a single flag until the v1.7.1 pass. Keep them separate: "reads all tickets"
and "owns RCA" are different facts that could diverge again.

Its section numbers are counted (`SH()`), not hardcoded, so a role-specific section
renumbers the rest automatically — which is why large new sections should land here
first. Because it builds two manuals in one process it calls `resetFigures()` per body
— without it the second manual's first figure is numbered `3-2`.

## Build

```bash
npm install docx          # only dependency; not vendored here
node build-tier1.js        # writes ../user-manual-soc-analyst-tier1.th.docx
node build-tier2.js        # ...etc
```

## Screenshots

Every figure is a dashed placeholder box carrying a hidden `SHOT: <id>` tag
(e.g. `SHOT: T1-wazuh-triage`). Those ids are the capture checklist for the
images-later pass — the full current list is at the end of this file. To drop real
images in, embed them via `ImageRun` in place of the `shot()` placeholder (see
`shot()` in `common.js`), then rebuild.

## Notes

- Cover version string and date default in `common.js` (`buildManual`, cover block)
  and are inline in `build-tier1.js`. Individual manuals can override the common
  defaults in their `buildManual()` config (the SOC Manager manual passes its own
  `version` / `updatedTh`). All manuals are now `v1.7.8` / 25 Sep 2026, manual
  edition **1.5** — the edition number is hardcoded in both `common.js` and
  `build-tier1.js`, so bump it in both. Before the v1.7.1 pass the two had drifted
  apart (1.1 vs 1.2); if you ever see them disagree again, that is the cause.
- **List filter bar + sortable headers (v1.7.8).** Every list page shares one
  filter bar (search on Enter, selects apply on change, removable chips, a
  results bar with count and sort presets) and server-side sortable headers.
  The explanation lives once in `common.js` `listControls()`: each manual adds its
  own H2, its role-specific page rows (`pages`) and its own `shot()`.
  `build-tier1.js` carries an inline copy — keep the two in step. Things the text
  deliberately states, because users will ask: the Tier 2 Queue has **no emergency
  filter** (so an emergency can't be hidden); History's date range counts from the
  **opening** date (วันที่แจ้ง), not the close date; the Manager Queue has no date
  range; the System Owner's open list is full and paged (it stopped at 10).
- **Bulk PDF export (Unreleased).** Active Tickets and History have a
  "ส่งออก PDF (N)" menu (ZIP, max 100) for the **SOC Manager and Tier 2 only**
  (`policies.can_bulk_export_ticket_reports`). It is described by
  `bulkExportParagraphs()` in `common.js`, switched on with
  `listControls({ canExport: true })` in tier2 and manager. **Tier 1 does not get
  it** (Tier 1 keeps the one-report export on the ticket page), and neither do
  admin or the response teams.
- Content is written against
  [`docs/architecture/ticket-lifecycle-states.md`](../../../architecture/ticket-lifecycle-states.md),
  which is the authority for the state machine. When a release changes the workflow,
  diff that file first, then the manuals — the 2026-09-10 audit found the Tier 1
  manual still teaching "an Event closes the ticket immediately", two months after
  that stopped being true. `STATUS_CHOICES` is now **15 statuses**, and `NEW` is
  labelled *กำลังจัดเตรียม (ยังไม่ส่ง)* — it is a draft state, not "just opened".
- **The Thai Patch trap (v1.7.1).** Every sidebar label was renamed to Thai in tag
  `v1.7.1` (commit `bc8226b`). `templates/base.html` (the `<nav id="sidebar">` block)
  is the source of truth for menu strings, and `menuTag()` no longer carries English.
  Before shipping a manual change, run the stale-menu guard from *Verification* below —
  it must come back empty. Note also that a **nav label is not always the page heading**:
  *คิวงาน Tier 1* opens a page titled *คิวงานของฉัน*, *คิวงานผู้จัดการ* opens
  *รายการรอตรวจโดยผู้จัดการ SOC*, *คำขอตอบสนองเหตุการณ์* opens *งานตอบสนอง*, and
  *เคสที่กำลังดำเนินการอยู่* opens *Ticket ที่กำลังดำเนินการ*. Quote whichever one the
  sentence is actually pointing at.
- **Role visibility — do not document a page into the wrong manual.**
  `ฐานข้อมูล IOC` is **Forensic Analyst + superuser only** (everyone else gets a 403),
  so it belongs to `build-response-teams.js` alone. `ค้นหา IOC` is visible to everyone
  **except** Executive and System Owner. The **ticket editor** requires SOC membership
  (`can_edit_ticket`), so it goes in tier1/tier2/manager only — *not* System Admin.
  A System Owner sees exactly one menu item; an Executive sees exactly one.
- **Section numbers are hardcoded in 7 of the 8 scripts** — they live inside the heading
  string (`H1("5. …")`, `H2("5.7 …")`), so inserting a section means rewriting every
  later heading by hand, plus any `(ดู 5.x)` cross-references in the status table and
  FAQ. `build-response-teams.js` is the exception: it counts with `SH()` and renumbers
  itself, which is why the big RCA section went there first. Figure numbers always
  self-heal (`shot()` counts per section), so an inserted figure needs no edits
  downstream — but the section argument must match the H1 it sits under.
- `CHANGELOG.md` stops at **v1.7.0**. Three shipped tags have no entry — v1.6.1, v1.6.2
  and **v1.7.1 (the Thai Patch)** — so the manuals' cover version is deliberately ahead
  of the changelog until someone writes those entries. Do not "correct" the cover back
  to v1.7.0.
- **Feature coverage, v1.6.0 – v1.7.1** (which script owns what):
  | Feature | Script(s) |
  | --- | --- |
  | RCA workspace retired → รับงาน + mandatory report number (Unreleased) | `build-response-teams.js` (รับงาน shared; RCA vs VAPT/HARD wording via `ownsRcaRequests`); manager §5.2 tip + §5.12 |
  | "งานของคุณ" card for the responder (Unreleased) | `build-response-teams.js` การทำงานกับคำขอ / รับงาน / ส่งงาน, state table, FAQ; manager §5.2 tip + §5.12 |
  | Notified-date gate `affected_notified_at` (v1.7.0) | `build-tier2.js` §5.5; owner note; manager FAQ |
  | Ticket draft mode / *บันทึกไว้จัดเตรียม* (v1.7.0) | `build-tier1.js` §5.3.2; owner email table |
  | Ticket editor (v1.7.0) | tier1 §5.9, tier2 §5.9, manager §5.8 |
  | IOC Search | tier1 §5.10, tier2 §5.10, manager §5.9, admin §5.5, response-teams |
  | Response-request rename + legacy subtask form removed (v1.7.0) | manager §5.2, `build-response-teams.js` |
  | Project Incident add-member (v1.5.4) | tier1 §5.11, manager §5.10 |
  | Acting-tier access (v1.5.3) | manager §5.11 |
  | Alert bundle may close as Event (v1.5.2) | tier1 §5.1, tier2 §5.2.2 |
  | Central evidence + preview (v1.7.0) | tier1 §5.7.1, admin §5.4, tier2 §5.7 |
  | Redesigned **SOC** dashboard (v1.7.0) | manager §4.1 — see the caveat below |
  | Executive dashboard, as-built | `build-exec.js` §5 |
  | List filter bar + sortable headers (v1.7.8) | tier1 §4.1 (+ §5.1 Wazuh triage, §5.10, FAQ), tier2 §4.1 (+ §5.1 tip, §5.10, FAQ), manager §4.2 (+ §5.9, §5.12 tip, FAQ), admin §4.1 (+ §5.5, FAQ), owner §4 + §4.1 + FAQ, response-teams หน้าจอของคุณ subsection + IOC Database section |
- **Two changelog claims that do not match the code** — both already handled in the text,
  do not "fix" them back:
  1. v1.7.0's *"redesigned SOC executive dashboard"* actually landed in
     `templates/dashboard/dashboard.html` (the **SOC** dashboard, which Executives never
     see). `executive.html` only got Thai labels in v1.7.1. The redesign is therefore
     documented in the **manager** manual, not the executive one.
  2. The RCA report has **no upload** anywhere. The workspace is retired; a Forensics /
     RCA request's update form takes a report number and an optional note, no file. The
     finished report is handed to the SOC Manager as a physical document and the system
     keeps no copy.
- **Ticket cancellation (v1.5.0)** is covered — the SOC Manager decision flow in
  `build-manager.js`, and the request path in `build-tier1.js` / `build-tier2.js` /
  `build-admin.js` / `build-owner.js`. Also covered in v1.5.0: in-browser attachment
  preview and the Section 8 remediation checklist (tier2/admin/owner).
- The table of contents is a live Word field: it populates when the `.docx` is
  opened/updated in Word, and shows blank in a raw headless PDF export.

## Verification

Run these after any content change. The first two catch the mistakes that are easiest
to make and hardest to spot in a 40-page Word file.

```bash
# 1. Build all eight (build-response-teams.js prints two lines)
for f in tier1 tier2 manager admin owner exec response-teams; do node build-$f.js; done

# 2. Stale-menu guard — must return nothing but deliberate English glosses.
#    The one known-good hit is the "งานตอบสนอง (Response Requests)" figure caption,
#    which mirrors that page's actual browser title.
grep -n 'My Queue\|SOC Dashboard\|Tier 2 Queue\|Manager Review\|Active Tickets\|Ticket History\|Response Requests\|My Tickets\|Wazuh Alert Triage\|Admin Panel\|Executive Dashboard\|Work Queues\|Intake & Triage\|My Systems\|System Settings' build-*.js common.js

# 3. Cover version guard — v1.5.0 must survive only as "(เพิ่ม v1.5.0)" feature tags
grep -n 'เวอร์ชันระบบ\|ปรับปรุงล่าสุด\|คู่มือฉบับที่' common.js build-tier1.js
```

Then check, per manual:

- **Heading numbering** is monotonic (`H1 "N."`, `H2 "N.M"`, `H3 "N.M.K"`) with no gaps
  or repeats. This is what catches a botched renumber after an insert.
- **Every `step("X")` appears in that script's `stepRefs`** (or `numberedRefs()` in
  `build-tier1.js`), or the numbering silently vanishes. `build-response-teams.js` has
  **two** `buildManual()` calls — shared-body steps must be declared in both.
- **`shot()` section arguments** match the H1 the figure sits under; in
  `build-response-teams.js` every `shot()` passes `sec`, never a literal.
- **SHOT ids are unique** within each output manual.
- **Open each `.docx` in Word**, Ctrl+A then F9 to populate the TOC field, then confirm
  the TOC matches the headings, figure captions run `รูปที่ 5-1, 5-2 …` with no gaps, and
  the Red Team manual's first figure is `3-1` (if it is `3-2`, `resetFigures()` was lost).

## Screenshot capture checklist

Figures are still dashed placeholders. Current `SHOT:` ids, by manual:

| Manual | SHOT ids |
| --- | --- |
| Tier 1 | `T1-login`, `T1-sidebar`, `T1-list-filter-bar`, `T1-wazuh-triage`, `T1-manual-intake`, `T1-create-form`, `T1-ioc-fields`, `T1-draft-buttons`, `T1-draft-tab`, `T1-ticket-detail`, `T1-ticket-edit-form`, `T1-edit-history`, `T1-ioc-search`, `T1-project-add-member` |
| Tier 2 | `T2-login`, `T2-queue`, `T2-list-filter-bar`, `T2-escalation-review`, `T2-bundle-event-confirm`, `T2-monitoring-conclude`, `T2-containment-review`, `T2-owner-review`, `T2-notified-date`, `T2-ticket-edit`, `T2-ioc-search` |
| SOC Manager | `MGR-login`, `MGR-sidebar`, `MGR-dashboard`, `MGR-list-filter-bar`, `MGR-triage`, `MGR-response-request`, `MGR-approve`, `MGR-step-back`, `MGR-cancel-decision`, `MGR-ticket-edit`, `MGR-ioc-search`, `MGR-project-add-member`, `MGR-acting-tier-banner`, `MGR-rca-report-number` |
| System Admin | `ADM-login`, `ADM-active-tickets`, `ADM-containment-form`, `ADM-ioc-search` |
| System Owner | `OWN-login`, `OWN-my-tickets` |
| Executive | `EXE-login`, `EXE-dashboard`, `EXE-filter-bar`, `EXE-situation-panel`, `EXE-kpi-cards`, `EXE-pipeline-chart`, `EXE-ticket-table` |
| Forensic Analyst | `FOR-login`, `FOR-queue`, `FOR-list-filter-bar`, `FOR-my-request`, `FOR-my-request-submit`, `FOR-ioc-database`, `FOR-ioc-manual-add` |
| Red Team Manager | `RED-login`, `RED-queue`, `RED-list-filter-bar`, `RED-my-request`, `RED-my-request-submit` |

**New and pending after the "งานของคุณ" card:**

- `FOR-my-request` / `RED-my-request`: the card on a request that is still **เปิด**. It
  shows the tracker at step 1, the brief, the requester, the dates and the green รับงาน
  button.
- `FOR-my-request-submit`: the card on a Forensics / RCA request that is
  **กำลังดำเนินการ**, showing the report number and หมายเหตุ fields without a file input.
  The old `RED-my-request-submit` screenshot showed a retired file field and is no
  longer included in the Red Team manual until a current screenshot is captured.
- Take both on a desktop viewport so the card sits in the right rail beside the case.

These replace `FOR-accept`, `RED-accept`, `FOR-update` and `RED-update`. Those four were
never captured, and the list-row อัปเดตงาน form they showed is no longer the
responder's path.

`MGR-rca-report-number` is also still pending, from the RCA-workspace retirement.
Dropped ids, which need no capture: `FOR-rca-start`, `FOR-rca-stepper`,
`FOR-rca-timeline-import`, `FOR-rca-ioc-promote`, `FOR-rca-draft`, `FOR-rca-handover`,
`FOR-keepalive-modal` and `MGR-rca-open`. `FOR-queue` and `RED-queue` gained the
เลขที่รายงาน column and the รับงาน button.

**Re-capture these even though their ids did not change** — the v1.7.1 Thai Patch changed
what is on screen: `T1-sidebar`, `T1-wazuh-triage`, `T1-create-form`, `T2-queue`,
`MGR-sidebar`, `MGR-response-request`, `ADM-active-tickets`, `OWN-my-tickets`,
`EXE-dashboard`, `FOR-queue`, `RED-queue`.

**Re-capture after v1.7.8** — the list filter bar and sortable headers changed these
screens: `T1-wazuh-triage`, `T1-ioc-search`, `T2-queue`, `T2-ioc-search`,
`MGR-ioc-search`, `ADM-active-tickets`, `ADM-ioc-search`, `OWN-my-tickets` (now a
full paged list with its own bar), `FOR-queue`, `RED-queue` and `FOR-ioc-database`.
New ids to capture: `T1-list-filter-bar`, `T2-list-filter-bar`, `MGR-list-filter-bar`,
`FOR-list-filter-bar`, `RED-list-filter-bar` — take each with a filter set, so the
chips, the outlined control and an active column caret all show.
