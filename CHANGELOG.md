# Changelog

All notable changes to the SOC Ticket system. A version is the annotated git tag
deployed to the Windows production VM — see
[docs/operations/deploy-and-release.windows.md](docs/operations/deploy-and-release.windows.md).
Format loosely follows [Keep a Changelog](https://keepachangelog.com); dates are
release (tag) dates.

## [Unreleased]

### Fixed
- **Ticket forms now handle idle-session expiry before submit.** The default
  timeout is 30 minutes. Active form work keeps the session alive; a two-minute
  warning lets the user extend it. On expiry the page saves a draft and redirects
  to login, then restores the form after sign-in. A final session check before
  submit avoids losing work to an expired POST.
- **Admin-edited email templates can no longer break a workflow action.** A
  stray `{` / `}` or attribute access in a Notification Template raised past the
  fallback and returned a 500 *after* the ticket had already moved. The sender now
  falls back to the built-in text for every formatting error, and the admin form
  refuses a template it could not format.
- **Email subjects are always one line.** A multi-line field in a subject made
  Django refuse the whole email.
- **Closure email to the System Owner shows the approval time in Thai time**, not
  UTC (it was 7 hours off). Attachments beyond 15 MB per email are listed in the
  body instead of making the send fail.
- **DOCX export no longer fails on ticket text.** Text containing `{{…}}` (e.g. a
  captured template-injection payload) was re-scanned as a placeholder and either
  failed the export or pulled in another field; control characters pasted from
  logs made python-docx refuse the file. Placeholders are now filled in one pass
  over the template only, and XML-invalid characters are stripped.
- **Report preview's "hide empty / show signatures" checkboxes apply on change
  again.** Their script lacked the CSP nonce, so the browser blocked it.
- **Ticket history's default month is the Thai-time month.** Tickets opened
  00:00–06:59 on the 1st were missing, and before 07:00 on the 1st the page showed
  the previous month.
- **Malformed ids and dates return a normal response instead of a 500** — ticket
  history dates, `triage_id` / `wazuh_alert` on the create forms, and `alert_id` /
  `ticket_id` on the Wazuh triage and Tier 2 queue actions.
- **Wazuh ingest re-reads a 10-minute window behind the watermark**
  (`WAZUH_INGEST_OVERLAP_MINUTES`), so an alert indexed late with an older
  `@timestamp` is no longer skipped forever. Already-stored alerts are skipped with
  one query per page instead of one per alert.
- **A workflow action no longer silently overwrites a newer save.** If the ticket
  (or a response request) was saved by someone else after the page loaded, the
  action is refused with "reload and try again" instead of rolling their change
  back. Claims, "seen" stamps and report-export metadata written in the meantime
  are preserved.
- **IOC Database pages in the database.** The page used to load every indicator
  from both sources into memory on each view, merge and filter them in Python,
  and then show 30. PostgreSQL now merges (two non-overlapping halves joined with
  `UNION ALL`), filters, sorts and returns only the requested page; the query count
  no longer grows with the database. Results are identical except that the last
  tie-break (value) follows the database collation.
- **Five dashboard tests updated** for the server-side sorted/paginated case
  table shipped in v1.7.6 — CI was red on `main`.

### Security
- **Password-reset per-IP throttle uses the rightmost `X-Forwarded-For` hop.** It
  took the leftmost, which the client controls behind IIS ARR, so the limit could
  be reset on every request.
- **CSP `script-src` names the two exact jsDelivr files** (Bootstrap, Chart.js)
  instead of the whole host, which serves every npm package.
- **PDF export fetches no external resources.** The renderer's resolver now
  accepts only inline `data:` URIs (the report uses nothing else), closing an
  SSRF / local-file read path.
- **Project Incident page checks visibility before running any POST action**, and
  lists deleted shared evidence only to the users who can restore it.
- **Every seed command refuses to write on a server that has not opted in**
  (`DEBUG`, or `ALLOW_SEED_COMMANDS=True` in `.env`): `seed_all`, `seed_data`,
  `seed_uat_states`, `seed_ceo_demo`, `seed_dashboard_mockup`,
  `seed_ola_demo_buckets`. They write demo data credited to real staff, `seed_all`
  deletes accounts matched by common nicknames together with their tickets, and
  `seed_ola_demo_buckets --apply` rewrote the OLA deadline of every real open case.
  Dry runs and previews always work.

## [v1.7.6] — 2026-09-24

### Added
- **"งานของคุณ" card for the response-team assignee.** A Forensic Analyst or Red
  Team Manager used to open a ticket, find *ยังไม่มีขั้นตอนที่ต้องดำเนินการสำหรับบทบาทของคุณ*
  in the action column, and have to scroll past every section to reach their
  request at the bottom. Their own request is now pinned at the top of the action
  column: beside the case on desktop, first on mobile. The card has a
  รับงาน → ดำเนินการ → ส่งงาน step tracker, the manager's brief, and the รับงาน
  button, then the completion form, open rather than collapsed. Every type asks for
  the report number (required, with a browser check) and optional notes. VA/PT and
  InfraSec also offer an optional file. **ส่งงาน · เสร็จสิ้น** asks for confirmation;
  **บันทึกไว้ก่อน** saves without closing. Once done, the card shows the delivered
  report number. The queue's *เปิดคำขอ*, the new-request email, and old RCA links
  now open this card (`#my-request`). The SOC Managers' completion email still opens
  the request list. In the request list, the assignee's own row is highlighted and
  links to the card instead of repeating the form.
- **รับงาน (accept) button** for every response request (Forensics / RCA, VA/PT,
  InfraSec). It appears on the request panel and in the *งานตอบสนอง* queue. One
  click by the assignee moves the request from เปิด to กำลังดำเนินการ, so the SOC
  Manager can see it has been picked up.
- **Ticket page sections are visually distinct.** Every section card has its own
  accent rule, an icon badge and a tinted header band, so the long page no longer
  reads as one continuous white column.
- **Wazuh data freshness on the SOC dashboard.** The header now shows when the
  Wazuh ingest last completed a successful poll and how old the newest Wazuh event
  is, next to the dashboard's own refresh time. The ingest watermark only moves when
  newer alerts arrive, so it couldn't tell a quiet period from a stalled job. The new
  `IngestWatermark.last_successful_poll_at` is stamped on every error-free poll,
  including polls that find nothing. Until the migration has run and one poll has
  succeeded, the header says *ไม่มีประวัติการดึงสำเร็จ*.
- **New dashboard columns and card.**
  - A **Unassigned Active / ยังไม่มอบหมาย** stat card.
  - The active-case table has new **อายุเคส** (case age), **อยู่สถานะนี้** (time in
    current status), **OLA ควบคุม** and **ชื่อเคส** columns, replacing **ประเภท**.
  - The analyst workload rows show a **T2 claimed** badge.
  - Each workload row's breakdown lists the waiting statuses (รอผู้จัดการ SOC,
    รอผู้ดูแลระบบ, …) separately from the analyst's own work.

### Changed
- **Forensic Analyst's work is simpler: the RCA report is no longer written in the
  system.** The RCA workspace (Section 1 prefill, assets, timeline + CSV import, root
  causes, IOC pull/push, recommendations, DOCX draft) is retired. The analyst now
  finds the request in *งานตอบสนอง*, clicks **รับงาน**, writes the report outside
  the system, and hands it in with the report number on the "งานของคุณ" card.
  - Marking **any** response request **เสร็จสิ้น** now **requires the number of
    the report delivered**: Forensics / RCA and the Red Team's VA/PT and InfraSec.
    The field is prefilled with the case's number for that report kind
    (`SOC-RCA-…`, `SOC-VAPT-…`, `SOC-HARD-…` YYYYMM-NNNN) and can be edited. Notes
    are optional. An RCA request accepts no file, because that report is the
    physical document the SOC Manager collects. VA/PT and InfraSec keep their
    optional result file. The number is audited in the history, shown on the request
    and in the queue, and included in the completion email to SOC Managers (new
    `{report_number}` placeholder; add it to any completion template customised in
    admin).
  - Old `/incidents/rca/<id>/` links from emails already sent open the request on
    its ticket.
  - The RCA tables and any data already in them are **kept** (no migration drops
    them). Only the screens are gone.
- **Only the assignee or a SOC Manager can close a response request.** Before,
  any SOC member could set a request to เสร็จสิ้น from the ticket's request list.
  Closing a request unblocks the parent Incident's approval, so changing a request's
  status or report number is now limited to the assignee, a SOC Manager, or a
  superuser (`policies.can_change_subtask_status`). Other SOC members get a
  notes-only form. A crafted POST that tries to change the status or number is
  refused in full, with nothing saved. The retired Investigation / Countermeasure
  notes keep their old rule.
- **The dashboard's "สัปดาห์นี้" range is the current calendar week.** The week
  filter already selected cases opened since Monday, but the volume chart plotted a
  rolling 7 days, so the two disagreed. The chart now runs Monday to today (1–7 daily
  buckets) and is titled *Daily Case Volume (สัปดาห์นี้)*. The today, week and month
  cut-offs now use Bangkok local time instead of UTC, so early-morning cases no
  longer land in the wrong day.
- **The dashboard's active-case table sorts and pages on the server.** It used to
  send every active case to the browser and sort it there. It now sends 25 per page,
  numbered page links, and sortable headers that keep the sort and page in the URL.
  So an auto-refresh or a shared link keeps the same view, and the page stays light
  as the queue grows.
- **Role manuals updated.** The Forensic Analyst and Red Team Manager manuals are
  rewritten around the "งานของคุณ" card and the mandatory report number. The SOC
  Manager, Tier 1 and Tier 2 manuals now say that only the assignee or the SOC
  Manager can close a response request. All affected `.docx` files are rebuilt.
- **Docs:** the Wazuh ingest code comments and the reporting-layer runbook now match
  the actual schedule and data. Vulnerability alerts are never stored, the default
  minimum level is 10, and the ingest runs every minute while `refresh_reporting` runs
  nightly.

### Removed
- **`seed_response_demo` management command** (and its tests). Its demo data had
  finished RCA requests with an attached file and no report number, which the
  system no longer allows. For UAT, the SOC Manager now sends real requests.
  `seed_all` no longer runs it, but still clears leftover `[RESPONSE-DEMO]`
  tickets with `--purge-only`.

### Fixed
- **The งานตอบสนอง menu badge counted cancelled requests.** For a Forensic
  Analyst or Red Team Manager, it left out only finished (เสร็จสิ้น) requests, so
  a request the SOC Manager had cancelled stayed in the count indefinitely and
  disagreed with the queue page. It now counts only เปิด and กำลังดำเนินการ.

> Migrations: `incidents/0087` adds `TicketSubtask.report_number` (empty default,
> additive). `wazuh_ingest/0009` adds `IngestWatermark.last_successful_poll_at` and
> backfills it from the watermark's last update, so the dashboard has a starting
> value. Both are safe on live data; the backfill is not reversed on rollback.

## [v1.7.5] — 2026-09-23

### Added
- **Every ticket list now leads with what the case is called (ชื่อเรื่อง).** The
  four ticket tables — *Ticket ที่กำลังดำเนินการ*, *รายการรอตรวจโดยผู้จัดการ SOC*,
  *คิวงาน Tier 2* and *ประวัติ Ticket* — used to identify a case by its host
  (*ระบบ / บริการ*) or by its threat sub-category; none of them showed the name an
  analyst had actually given it. They now share one **ชื่อเรื่อง** column, and the
  host drops to the small secondary line beneath it. The ticket detail page reads
  name-first for the same reason.
  - The column prints the new `Ticket.display_name`: the analyst's **ชื่อเรื่อง**
    (`incident_name`) when there is one, otherwise the **หมวดหมู่ย่อย** label. That
    fallback is why no row is ever blank — `incident_name` is still optional, and
    most existing tickets have none.
  - *Ticket ที่กำลังดำเนินการ* is now searchable by ชื่อเรื่อง, and gained a
    **ความรุนแรง** sort option (ranked Critical → Unknown, not alphabetically).

### Changed
- **Two field labels renamed.** *เรื่องที่แจ้ง* → **หมวดหมู่ย่อย**
  (`detailed_issue2`, the threat sub-category dropdown) and *ชื่อเหตุการณ์* →
  **ชื่อเรื่อง** (`incident_name`), on the create form, the Project Incident form,
  the ticket editor and the Tier 2 review card. Label-only: no field changed
  meaning, and the incident/event report keeps its own row wording
  (*1.5 ชื่อ incident/event*, *1.4 ชื่อ Event*) untouched.
- **One visual language across the four ticket tables.** *คิวงาน Tier 2* used to
  flood an emergency row in solid red while the other lists drew a quiet accent
  stripe; it now uses the same stripe and the same outlined **ฉุกเฉิน** flag.
  Relative times read alike, *ประวัติ Ticket* gained the exact-timestamp tooltip
  the other pages already had, and the Project Incident pill reads *Project · …*
  everywhere. The shared table styling and the Event/Incident and Project pills
  moved into `base.html` and two partials, so the next change lands once instead
  of three times.
- **The Tier 2 queue (คิวงาน Tier 2) moved from `/wazuh/escalation_queue/` to
  `/incidents/tier2-queue/`.** It had lived in `apps/wazuh_ingest` since June 2026,
  when escalation was still an alert-level concept; the page has queried nothing but
  tickets since 2026-07-23. Views are now `apps/incidents/views/tier2_queue.py` and the
  template `templates/incidents/tier2_queue.html`. Nothing changes for analysts: the
  page, its filters and the sidebar link are identical, and the old URL redirects
  permanently (query string preserved) so existing bookmarks still work.

### Fixed
- **"ล้างตัวกรองทั้งหมด" on the manager queue no longer navigates off it.** Both
  the clear-filters link and the filtered empty state pointed at
  *Ticket ที่กำลังดำเนินการ*, so a SOC Manager clearing a filter silently left
  their own queue.
- **The Tier 2 queue now reads tickets through `Ticket.objects.visible_to()`**
  like every other list, instead of querying the table directly. No one's view
  changes — the page is already gated to Tier 2, who see every ticket either way
  — it just removes the one list that bypassed the single authoritative
  visibility rule.

> Migrations `incidents/0085` and `incidents/0086` are `AlterField` on
> `detailed_issue2` / `incident_name` carrying **nothing but the new
> `verbose_name`** — no column, constraint or data change, and reversible.
> `device_name` is untouched, so the DOCX/PDF reports are byte-for-byte
> unaffected.

## [v1.7.4] — 2026-09-22

### Added
- **Analyst-chosen importance (ระดับความสำคัญ) on the ticket.** A new mandatory
  three-way pill field (**ปกติทั่วไป / สำคัญ / สำคัญมาก**) in the *Asset & Evidence*
  section of the create form, next to ประเภทของทรัพย์สิน, and required on the
  ticket-edit and Tier 2 review/decision cards and on the Project Incident (bundle)
  form (the pick is shared by every member ticket). It replaces the old **derived**
  importance row on the report — previously Event → ปกติทั่วไป, Incident → สำคัญ,
  computed from the classification. The analyst now sets it directly.
  - The report's importance row (Incident **1.7** / Event **1.6**) prints
    `Ticket.report_importance`: the manager's **emergency flag still forces
    สำคัญมาก** (it overrides the pick); otherwise the analyst's choice; and a
    ticket with **no stored value falls back to the old derived rule**, so every
    report created before this change ticks exactly the same box as before — it is
    never left blank. A legacy ticket only takes on an explicit value once it is
    edited or reviewed, when the field becomes mandatory.
  - Shown on the ticket detail page and the RCA case panel, tracked in
    field-change history (*ระดับความสำคัญ*), and used to prefill the RCA report's
    importance (removing the duplicated derivation there).

- **"Tier 2 แก้ไข" tab in My Queue** — a passive list of the tickets you opened
  whose content a Tier 2 analyst has changed since you last looked (the lane
  choice included), plus a banner on the ticket. Opening the ticket clears it; it
  is not counted in the sidebar badge.

### Changed
- **Tier 2 now routes a confirmed Incident straight to the SOC Manager — the
  "รอ Tier 1 ทบทวน" (`T1_REVIEW`) step is gone.** Tier 2's review is a single
  decision: *Event* → close or monitor; *Incident* → choose the handling lane
  (System Admin + who, or Owner) → SOC Manager review. Cases no longer wait on
  Tier 1 after escalation. The lane is now required on every hand-off to the
  manager, so a case can never arrive with nothing to forward to (the conclude-
  monitoring → Incident form carries the same lane picker).
- **SOC Manager "return for completion" goes back to whoever routed the case** —
  Tier 2 if it was ever escalated, otherwise the creator's preparation (they fix it
  and press *Submit* again; no repeat owner email, and direct self-cancel is no
  longer offered on a reviewed ticket). The button says which.

> Migration `incidents/0084` adds `Ticket.importance` (nullable/blank; the field
> is optional at the DB level so existing rows stay valid and read through the
> `report_importance` fallback — the forms are what make it mandatory). AddField
> only; reversible.
>
> Migration `incidents/0083` adds `first_submitted_at` / `t2_changed_at` /
> `creator_seen_at` and moves any ticket still in `T1_REVIEW` back to Tier 2
> (`ESCALATED_T2`) with a log note — one-way; old log rows keep the code and
> render as "ส่งกลับ Tier 1 (legacy)".

## [v1.7.3] — 2026-09-22

### Added
- **Monitoring re-anchored to the Event classification, fully Tier‑2‑owned.**
  Monitoring is no longer a *"decide later"* state entered before Event/Incident is
  chosen — it is now a **watch phase of an Event**. Tier 2 starts it only as an
  Event decision (the classification stays **Event**, no longer blanked on entry),
  so an **Incident can never be monitored and any Event can**. **Only Tier 2**
  concludes the watch: close the Event directly (→ `CLOSED_EVENT`) or, if the watch
  turned up something, pick the handling lane and raise it to an Incident
  (→ `PENDING_MGR_TRIAGE`). The case still sits in the opening analyst's My Queue
  for visibility during the 30 days; the fixed 30‑day window, the once‑per‑case
  latch (`has_been_monitored`), and on‑read expiry are unchanged. The old
  `MONITORING → ESCALATED_T2` "confirm the close" bounce is removed — Tier 2 closes
  in one step. This supersedes the 2026‑09‑18 Event‑downgrade‑via‑Monitoring gate
  (a monitored case is now always an Event, so that bypass no longer applies).

- **สรุปเหตุการณ์ — a short summary distinct from the full write-up.** Report row
  **1.14 รายละเอียด** used to reprint Section 2 verbatim because there was no
  separate summary field. Tickets and Project Incidents now carry an optional
  `event_summary`, and the row falls back to the full description when it is
  blank, so nothing changes for a ticket that does not use it.

### Changed
- **Thai text in the exported DOCX now honours the intended sizes.**
  `python-docx` writes only `w:sz`, so Word fell back to its stock 11pt
  complex-script default for Thai even inside a 16pt body or a 22pt title; the
  builders now write `w:szCs` alongside it (the `Normal` style included, which
  evidence captions inherit). The v2 report template was rebuilt, and the report
  preview keeps the whole appendix — heading, intro, clause and table — together
  on a fresh page.

### Removed
- **Tier 1's "recommend monitoring" control.** The advisory `propose_monitoring`
  checkbox (create form and submit‑preparation card) and its backing
  `Ticket.monitoring_proposed` field are gone — deciding to monitor is entirely
  Tier 2's, so the recommendation no longer exists.

> Migration `incidents/0081` adds the optional `Ticket.event_summary` (AddField
> only; reversible).
>
> Migration `incidents/0082` drops `monitoring_proposed` (reversible; the field was
> advisory‑only and carried no operational data). Rollback follows the deploy
> runbook's §4a (previous‑tag checkout).

## [v1.7.2] — 2026-09-18

_Also tagged `v1.7.1.1` — the two tags point at the same commit._

### Changed
- **Documentation brought up to the shipped system.** A new end-to-end workflow
  reference (`docs/architecture/soc-end-to-end-workflow.md` plus a 12-page
  drawio), a refreshed `ticket-lifecycle-states.md`, and all eight Thai role
  manuals rebuilt from their `_build` sources — the v1.7.1 Thai patch had renamed
  almost every menu the manuals quoted.
- The **Executive** role now sees the same navigation section as SOC roles
  (`base.html`); it was excluded by an `is_soc`-only condition.

## [v1.7.1] — 2026-09-17

### Changed
- **The interface is Thai throughout.** Remaining English UI strings across the
  templates, the Django admin, model `verbose_name`s and choice labels were
  translated, keeping established English terms (Event, Incident, Ticket, OLA,
  Tier 1/2, SIEM, IOC) as they were. Display-label changes only — no field, value
  or behaviour changed.

> Migrations `accounts/0013`, `incidents/0080` and `wazuh_ingest/0008` are
> `AlterField`s carrying nothing but new `verbose_name`/`choices` labels — no
> column or data change, and reversible.

## [v1.7.0] — 2026-09-17

### Added
- **Notification time on the incident report (Section 1.4).** Tier 2 now records
  *"วันที่ เวลา ที่แจ้งเหตุผู้ที่ได้รับผลกระทบ"* while verifying containment — a
  date-time field styled like the detection time, on both the containment-review
  and owner-fix-review cards. It is mandatory before a case can be approved or
  routed to the SOC Manager, optional when the case is sent back, and validated
  against the detection and occurrence times. The value appears on the ticket
  detail page, in field-change history, and on the ticket edit form, and is added
  as row **1.4** of the incident report — the following rows renumber to 1.5–1.19.
  (The Event report is unchanged.)
- **Redesigned SOC executive dashboard** with reworked layout and polished
  charts.

### Changed
- **Action-flow adjustments and centralized evidence handling.** Attachment /
  evidence handling was reworked across ticket create, edit, and detail, project
  incidents, the report preview, and the workflow action panel, alongside
  workflow/status refinements.
- **Internal restructure of the incidents app.** `models.py` and `views.py` were
  split into packages; behavior-preserving.

### Removed
- **Legacy intra-SOC subtask form retired.** The manual Investigation /
  Countermeasure subtask create path was removed and the ticket-detail section
  reframed as *"คำขอทีมตอบสนอง"*, co-locating the response-request spawn form. The
  two enum values are kept for historical rows only — no schema change, no data
  loss.

> Migrations `incidents/0078` (status-choices alter) and `incidents/0079` (add
> nullable `affected_notified_at`) are both additive and reversible — rollback
> follows the deploy runbook's §4a (previous-tag checkout).

## [v1.6.0] — 2026-09-16

### Added
- **Forensic RCA workspace.** Forensics/RCA response requests now open a
  dedicated, section-based workspace for general incident data, affected
  assets, timeline evidence, root causes, indicators, linked recommendations,
  Word-draft generation, final notes, report upload, and Mark Done. Each section
  saves independently, records RCA audit history, and becomes read-only after
  completion. Timeline imports accept UTF-8/Thai Windows CSV or TSV files with
  an all-or-nothing limit of 30 data rows per file, while IOC promotion keeps
  its existing preview-and-confirm workflow.
- **Guided RCA analyst handoff.** Opening an RCA request now shows a read-only
  Ticket context panel before the analyst explicitly starts the report; starting
  pre-fills the workspace and moves the request to In Progress. Ticket rows and
  both response-request notification emails link directly to the workspace, and
  active editors receive an idle-expiry countdown with authenticated keep-alive
  protection for long-running analysis.

### Changed
- **Response-request completion after Event closure.** Assigned response-team
  members and SOC Managers can finish VA/PT, Infrastructure Security, and
  Forensics/RCA requests after the parent Ticket is closed as an Event. Approved
  Incidents and cancelled Tickets remain frozen. RCA draft generation is limited
  to the assigned analyst, SOC Manager, and superuser.

## [v1.5.4] — 2026-09-15

Adds late-discovered systems to active Project Incidents and advances the
Forensic RCA report groundwork from a data model to a generated Word draft.

### Added
- **Add affected systems to an active Project Incident.** The Project Incident
  creator or an SOC Manager can use the new plus-button form on the project page
  to create another Member Ticket with the existing system-detail and decision
  fields. Event members go to Tier 2; Incident members added after Project Review
  inherit its current Normal/Emergency assessment and enter their selected Admin
  or Direct-to-Owner lane immediately. The operation preserves the project
  creator as the Ticket owner, assigns the next member suffix, copies shared
  incident facts and structured IOCs, retains the original incident time for OLA,
  and records both project- and ticket-level audit history. Finished projects are
  frozen and cannot receive another member.
- **Forensic RCA DOCX draft generation (backend).** RCA data can now populate a
  versioned Word draft with the case number, general facts, severity and forensic
  checkboxes, affected assets, timeline, root causes, indicators and linked
  recommendations. Generation records the author, time, template version and
  SHA-256 digest on the RCA report. The in-app RCA workspace/editor is not part
  of this release.

### Changed
- **RCA Word template.** Rebuilt the draft template around repeatable table rows
  so each stored asset, timeline entry, root cause, IOC and recommendation gets
  its own formatted row while empty sections remain usable as a Word form.

## [v1.5.3] — 2026-09-15

### Added
- **Temporary Tier 1/2 access for a SOC Manager.** A superadmin can grant a SOC
  Manager temporary Tier 1 **and** Tier 2 privileges — opening cases, triage
  intake, driving their own cases, and Tier 2 verification — from the Django
  admin user list, and revoke it just as easily. While granted, the manager sees
  the Tier 1/2 navigation and a banner marking the elevated mode; every other
  role boundary (System Admin containment, System Owner remediation) stays in
  place. Only a superuser can grant or revoke it — a manager cannot elevate
  themselves.

### Changed
- **Forensic RCA report groundwork (internal).** Adds the Root Cause Analysis
  data model, generator and Word-draft template that back a Forensic Analyst's
  `FORENSIC_RCA` response request. The report is captured as structured data and
  rendered into a DOCX draft the analyst finishes in Word. Backend only in this
  release — not yet surfaced in the app.

## [v1.5.2] — 2026-09-14

### Changed
- **Alert Bundles may be classified as Event.** A bundle of related Wazuh alerts
  was previously forced to open as an Incident. It can now be saved as an Event:
  every bundled alert is recorded as a false positive and the ticket goes to
  Tier 2 to confirm before closing — one ticket for a burst of related false
  positives instead of one per alert.

## [v1.5.1] — 2026-09-11

### Changed
- **Ticket detail and form UI.** Reworked the ticket detail page, made the
  workflow action controls responsive, improved evidence (attachment/alert)
  navigation, and refined the ticket and Project Incident forms.

### Fixed
- Recover an in-progress ticket form after a failed submit so typed input and
  staged evidence are not lost.

## [v1.5.0] — 2026-09-11

Reworks the Incident/Event report toward the NT paper form, adds **in-browser
attachment preview** and a **Tier 2 remediation checklist**, and ships **ticket
cancellation** with an SOC-Manager decision flow.

### Added
- **Ticket cancellation.** A mistaken or duplicate ticket can end as `CANCELLED`
  without classifying it as an Event or certifying remediation. The Tier 1 creator
  may cancel only while the ticket is still `NEW`; after handoff the current actor
  **requests** cancellation and the **SOC Manager** approves, rejects, or cancels
  directly. Requests and decisions are separately audited, and a pending request
  does not pause the OLA clock or move the workflow stage (ADR 0005).
- **In-browser attachment preview.** A "ดูตัวอย่าง" link opens image and
  text/log/CSV attachments in a new tab with no download. Images are re-encoded
  through Pillow (the raw upload is never served — no stored-XSS from a spoofed
  file), text is decoded (utf-8 / cp874) and shown escaped, and CSV/TSV render as a
  table. Other types (Office, archives, pcaps) keep the forced download only.
- **Section 8 remediation checklist.** A fixed 15-item checklist plus an "อื่นๆ
  ระบุ" line, ticked by Tier 2 while verifying containment (System Admin lane at
  `CONTAINMENT_REPORTED`, System Owner lane at `PENDING_T2_REVIEW`). Stored per
  ticket and written to change history, so unlike the old static list every tick is
  attributable (ADR 0006). Findings / Countermeasure are retained.
- **Event occurrence time.** A new `เวลาที่เกิดเหตุ` field on the report and ticket
  forms, distinct from the detection time; a Wazuh alert pre-fills it, and a button
  copies the detection time when the true moment is unknown.
- **User + Command indicators.** Report section 4 gains a **File Name** row and a
  **คำสั่ง (Command)** field; "User" and "Command" live in the ticket form's IOC
  section, are searchable, and are deliberately kept out of the IOC Database.
- **Report signature toggle.** The preview and the DOCX/PDF exports can show or hide
  the sign-off block; the default is **hidden**.

### Changed
- **Incident report Section 1 rework** — occurrence/detection split, checkbox and
  row re-ordering, an added `รายละเอียด` row, the Reference ID folded into the
  แหล่งข้อมูล row, and a containment-executor view of the current status. Body text
  is now **16pt** with tighter cells (Incident report only; the Event one-pager is
  unchanged).
- **Ticket-detail workflow UI refactor + Manager Decision UI.** The action controls
  are extracted into focused partials, and the SOC Manager's cancellation decision
  is surfaced inline alongside the other stage actions.
- **Report Section 5 no longer lists attachment file names** — screenshots embed
  with the analyst's description as caption; the MITRE line stays.
- Ticket form: **Source → Log Source → Reference ID** order, a Log-Source hint that
  changes with the source, and the **MAC Address input removed** (the stored field
  and its read-only display are kept).

### Fixed
- Section 8 checklist keys are stored in a **canonical order**, so re-saving the
  same selection is byte-identical and never fabricates a field-history entry.
- The report's "อื่นๆ ระบุ" box now **ticks (☑) when it has text**.
- The attachment-preview view narrows its exception handling, so a real
  storage/programming failure surfaces as a logged 500 rather than a misleading 404.

### Database
- `incidents.0073`–`0075`, `reporting.0005` — all additive (new tables / nullable or
  defaulted columns). To roll back to v1.4.0, run `migrate incidents 0072` and
  `migrate reporting 0004` first.

### Docs
- ADR **0005** (ticket cancellation) and **0006** (Section 8 checklist supersedes
  the 2026-08-06 UAT removal). Lifecycle, workflow-change-log and engineering
  handover, the end-user guide, and the role manuals (`.docx`) updated.

## [v1.4.0] — 2026-09-09

Takes Wazuh **vulnerability-detector alerts out of the triage queue entirely**
and makes the queue table workable at a glance.

The production queue held 849 alerts, of which **771 (91%) were vulnerability
scan output** — 188 CVEs on two kernel packages across five hosts, every one at
`rule_level` 13 and every one past its 4-hour triage OLA. One problem ("patch
two kernels") was being presented as 771 pieces of work, at 25 rows to a page,
burying the 78 real detections beneath it. Vulnerability management belongs in
Wazuh, which has its own dashboard for it.

### Added
- **`purge_vulnerability_alerts`** management command — one-off cleanup for the
  vulnerability alerts stored before ingestion started dropping them. Supports
  `--dry-run` and `--batch-size`; refuses to delete any alert linked to a
  ticket, alert link, or bundle, because `Ticket.wazuh_alert` is `SET_NULL` and
  `TicketAlertLink.alert` cascades.
- **`WazuhAlert.kind`** (`DETECTION` / `VULNERABILITY`), classified at ingest
  from the Wazuh rule group. Migration `0007` backfills existing rows.
- **Agent IP column** on the triage queue. The field was already ingested and
  already searchable — it was simply never displayed.
- **Click-to-sort column headers** on the triage queue (time, agent, agent IP,
  level, rule, status, owner). Rows with no IP or no owner sort last in either
  direction: an absent value is missing information and must not take the top
  of the first screen.
- **Rows-per-page selector** (25 / 50 / 100), replacing a hardcoded 25.

### Changed
- **Vulnerability-detector alerts are no longer ingested.** Excluded in the
  OpenSearch query so they are never transferred, and dropped again in
  `store_alert_hits` — two gates, because the query filter depends on
  `rule.groups` being mapped as a keyword field, and a silent failure there is
  the exact accumulation this release exists to end.
- The triage queue and its sidebar badge are scoped to `kind=DETECTION`, so a
  vulnerability alert reaching the database by any other route still cannot
  flood triage. `claim_alert` rejects them outright.

## [v1.3.1] — 2026-09-09

### Changed
- **The Forensic Analyst now reads every ticket.** Correlating an indicator
  across incidents was impossible through the previous keyhole of "only cases
  with a response request assigned to me". Access is **read-only**: every write
  gate is an independent role test that excludes them (edit, attachment upload,
  attachment restore, status transitions, report export), so wider reading grants
  no new action. Their one write path is unchanged — the deliverable on a
  response request assigned to them. The Red Team Manager keeps response-only
  visibility.

## [v1.3.0] — 2026-09-09

Adds the **IOC Database** — a single place where indicators from tickets and the
Forensic Analyst's own research are collected, reviewed against MISP and tracked
— and lets a ticket record **multiple IP addresses**.

### Added
- **IOC Database** (sidebar; Forensic Analyst / superuser only). Unifies IOCs
  from **two sources** — indicators entered on tickets by T1/T2, and indicators
  the FA found externally and **types in by hand** — keyed by *(category, value)*
  so the same indicator from both sources is one row showing Source
  `Ticket` / `Manual` / both. Each indicator carries the FA's annotation: a
  two-state **Checked / Not Checked** review flag ("reviewed against MISP") and a
  free-text **Note**, both editable on **any** row including ticket-sourced ones.
  Manual entry adds several IOCs at once (a row per indicator, mixed categories),
  generates its own `MAN-####` reference, hides **File name** unless the category
  is Hash, never adds a value that already exists anywhere, and **restores** a
  previously removed record if its value is typed again. Manual rows can be
  edited in place or soft-removed. Filter toolbar (search / status / source /
  category) plus click-to-sort column headers.
- **Structured IOCs on tickets.** Ticket creation, Project Incident creation,
  Tier 2 review and ticket edit gain an **Indicators of Compromise** section with
  six multi-valued fields — File Name, Hash (SHA-256), Domain, IP Address, URL,
  File Path — each with a "＋ add" button. Values are validated and normalised per
  category (defanged input, case, IDNA and IPv6 all handled). They feed ticket
  search, the change history (one IOC-set audit entry per edit) and the incident
  report, which gains dedicated **Domain** and **URL** rows in section 4.
- **Multiple IP addresses per ticket.** `ip_address` accepts a list (comma,
  semicolon or newline separated), normalised and de-duplicated on save.

### Changed
- **IOC Search** keeps its ticket and triage results and now also matches a
  ticket by its structured IOC values, so a hash or defanged IP finds the cases
  it appeared on.
- The free-text *IoC อื่น ๆ* box is gone from the ticket forms; existing text is
  preserved read-only on tickets that have it.

### Database
- `incidents.0066`–`0072`. `0067` **backfills** structured IOC rows from existing
  tickets' `destination_ip` / `ioc_details` (both columns are left intact).
  Rolling back to v1.2.3 requires `migrate incidents 0065` first, which drops the
  IOC tables and everything entered in the IOC Database — restore from the
  pre-deploy backup instead if that data matters.

### Docs
- `docs/ti-platform-inventory.md` rewritten for the IOC Database.

## [v1.2.3] — 2026-09-07

Adds the **Monitoring (กำลังเฝ้าระวัง)** watch-and-wait state for cases that are
not yet an Event or an Incident, with its guards, dashboard coverage, and docs.

### Added
- **Monitoring status (`กำลังเฝ้าระวัง`).** When a case escalated to Tier 2 cannot
  yet be classified, Tier 2 can park it under a fixed **30-day watch** and return
  it to the opening Tier 1. Tier 1 may **recommend** monitoring at ticket creation
  (advisory — only Tier 2 grants it). It resolves to **Incident** (something
  happened → SOC-Manager triage) or **Event** (window closed quietly → Tier 2
  confirms the close). Expiry is a countdown badge (green → amber → red) computed
  on read, so no scheduler is required. Surfaced in a dedicated
  "กำลังเฝ้าระวัง" tab in Tier 1's My Queue, and counted across the executive
  and analyst-workload dashboards (14-state FSM).

### Changed
- The **My Queue nav badge** now counts only actionable work — a still-counting-
  down monitoring case (passive) no longer inflates it, while an expired watch
  (which Tier 1 must conclude) still does.

### Guards
- A case can be monitored **at most once**; **Project Incident (bundle) members**
  cannot be monitored; and the **emergency flag cannot be reassessed while
  monitoring** (the case is not yet classified).

### Database
- `incidents.0065` — `monitor_until`, `has_been_monitored`, `monitoring_proposed`
  (all additive: nullable or defaulted). Reversible; to roll back to v1.2.2 run
  `migrate incidents 0064` first.

### Docs
- End-user guide, the Tier 1 / Tier 2 / SOC Manager role manuals (`.docx`), and
  the Notion technical documentation updated for the 14-state FSM.

## [v1.2.2] — 2026-09-04

Two-factor authentication ships but is switched **off** pending a UX review, on
top of the v1.2.1 Project Incident fixes and a ticket-draft preservation fix.

### Changed
- **Two-factor authentication is now switchable** via the `MFA_ENABLED` setting
  (default `True`). Production runs with `MFA_ENABLED=False` for now — login is
  password-only, with no enrolment or verification step. Authentication and
  per-view access control are unaffected. Enrolled devices and recovery codes
  are left intact, so re-enabling (`MFA_ENABLED=True` plus a valid
  `MFA_ENCRYPTION_KEYS` key) restores 2FA unchanged.

### Fixed
- **Ticket draft no longer lost on an expired session.** The saved-in-browser
  draft is cleared only after a genuine save, so a POST rejected by a login
  redirect or CSRF 403 keeps everything the analyst had typed.
- Carries the **Project Incident form** fixes from v1.2.1 (see below).

### Database
- `accounts.0010`, `accounts.0011` — authenticator-device / MFA-audit / recovery-
  code tables (the 2FA feature). Reversible; to roll back to v1.2.0 run
  `migrate accounts 0009` first. The tables sit unused while `MFA_ENABLED=False`.

### Docs
- Documentation refresh — README status taxonomy, ADR renumbering, workflow and
  lifecycle docs, and a docs-sync test.

## [v1.2.1] — 2026-09-04

Project Incident form hotfix, cherry-picked onto v1.2.0. No breaking changes and
no database migrations.

### Fixed
- Removed the **System Owner user-picker dropdown** from the Project Incident
  form — owners are contacted directly, off-system. The Direct-to-Owner route
  itself is unchanged.
- The per-system **"ลบ" (remove) button** now removes the row and re-indexes the
  formset instead of only dimming it, while enforcing the 2-system minimum.
- Fixed a **500 on the Project Incident detail page** when a member used the
  owner route but had no owner user assigned.

## [v1.2.0] — 2026-09-01

Report forms + workflow docs. No breaking changes.

### Added
- **Event report form** — a pale-blue NT Event report (DOCX / PDF / on-screen
  preview), parallel to the existing Incident report.

### Changed
- Removed the `Template <ver> | จัดทำเมื่อ <time>` meta line from every report
  output (preview, PDF, and both DOCX templates).

### Docs
- **Role-based workflow guide** — interactive, bilingual (TH/EN), one workflow
  diagram per role plus an overview; offline-capable single HTML file.
- Dev & release cycle playbook + Windows deploy/rollback runbook.
- Minor wording fixes.

### Database
- `incidents.0064` — rename `mitre_phase` → `tactics` (reversible; to roll back
  to v1.1.0 run `migrate incidents 0063` first).

## [v1.1.0] — 2026-08-31

Production go-live on the self-signed HTTPS bridge, backup & DR, CI/CD, and a
behavior-preserving codebase refactor.

### Production & DR
- **Phase 3 — Backup & DR.** Nightly GPG-encrypted archives (pg_dump + media +
  row-count manifest) with SHA-256; read-only off-host share + hourly pull to the
  spare; a timed **restore drill** against a throwaway verify instance with the
  production locale asserted (UTF8 / Thai_Thailand.874). Weekly/daily scheduled
  tasks all green.
- **Phase 4 — Streaming standby.** PostgreSQL streaming standby (port 5433) from
  the primary; app stack pre-staged on the spare (service Manual/stopped) so the
  1–3 h RTO is real.
- **Phase 5 — Go-live enablement.** HTTPS live via a self-signed IP bridge
  (`https://10.1.220.118`) — TLS + HTTP→HTTPS redirect + secure session/CSRF
  cookies; **authenticated SMTP backup alerting** (SOC-Archive-Check emails the
  SOC on a stale archive / broken pull / full disk / non-streaming standby).
- **Phase 6 — Live-data enablement.** Wazuh ingest pointed at production
  (per-minute), nightly reporting refresh + detection capture, 90-day retention
  scheduled.

### CI/CD (Phase 7)
- **GitHub Actions** on Postgres 18 + Python 3.14 — Ruff correctness rules,
  migration-drift check, the full test suite, and an 85 % coverage floor, on
  every push and PR.
- Windows deploy/rollback runbook (SemVer tags, backup-first, `/healthz` +
  `APP_VERSION` verify).

### Refactor — Codebase Health Check (behavior-preserving, 8 phases)
- Extracted the oversized `views.py` into focused service modules — `policies`,
  `selectors`, `ticket_workflow`, `case_creation`, `project_workflow`,
  `ticket_evidence`, `ticket_updates`, `subtask_creation` — each with its own test
  suite. `views.py` shrank by well over a thousand lines and coverage rose.

### Added / Changed
- **Dark mode** toggle across the app.
- **UX/UI overhaul + font update** across the ticket, queue, dashboard, and badge
  templates.
- **Project Incident — mixed member classifications** (ADR 0003): Event members
  go to Tier 2 individually; Incident members pass the group Project Review.
- **MTTR metric restored** on the Executive dashboard.
- **Wazuh alert triage UI** fixes.
- New `system_detail` ticket field (`incidents.0063`).

### Fixed
- Backup script fixes (`New-SocBackup.ps1` and the archive/restore tooling) and
  production-prep hardening of the backup chain and the Wazuh retention command.

## [v1.0.0] — 2026-08-14

First production build — the complete SOC ticketing system on the Windows
production VM (VM foundation + application readiness).

### Included
- **Workflow** — 13-state ticket lifecycle with a role-enforced state machine; 7
  roles + Tier 1/2 RBAC; Event/Incident classification, SOC Manager
  pre-containment review, emergency gate, Tier 2 verification, direct-to-owner
  lane.
- **Intake** — Wazuh/OpenSearch SIEM ingestion, manual triage intake, claim-first
  triage queues, alert bundling.
- **Handling** — containment & remediation reports, secure evidence attachments,
  investigation/countermeasure + response-team subtasks, Project Incidents (case
  bundling).
- **Visibility** — email notifications, OLA tracking, global/IOC search, audit
  trail & ticket history, executive/monitoring dashboards, System Owner portal.
- **Reporting** — Incident report generator (HTML / PDF / DOCX), reporting `mart`
  schema.
- **Production Phase 1–2** — Windows Server + native PostgreSQL 18 + Waitress
  (NSSM service) + IIS/ARR reverse proxy; Waitress pinned, `/healthz` endpoint,
  Wazuh retention command, STORAGES fix.

[v1.5.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.5.0
[v1.4.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.4.0
[v1.3.1]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.3.1
[v1.3.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.3.0
[v1.2.3]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.3
[v1.2.2]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.2
[v1.2.1]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.1
[v1.2.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.0
[v1.1.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.1.0
[v1.0.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.0.0
