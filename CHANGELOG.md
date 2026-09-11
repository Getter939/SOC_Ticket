# Changelog

All notable changes to the SOC Ticket system. A version is the annotated git tag
deployed to the Windows production VM — see
[docs/operations/deploy-and-release.windows.md](docs/operations/deploy-and-release.windows.md).
Format loosely follows [Keep a Changelog](https://keepachangelog.com); dates are
release (tag) dates.

## [Unreleased]

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
