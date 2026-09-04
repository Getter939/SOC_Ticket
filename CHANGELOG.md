# Changelog

All notable changes to the SOC Ticket system. A version is the annotated git tag
deployed to the Windows production VM — see
[docs/operations/deploy-and-release.windows.md](docs/operations/deploy-and-release.windows.md).
Format loosely follows [Keep a Changelog](https://keepachangelog.com); dates are
release (tag) dates.

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

[v1.2.2]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.2
[v1.2.1]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.1
[v1.2.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.2.0
[v1.1.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.1.0
[v1.0.0]: https://github.com/Getter939/SOC_Ticket/releases/tag/v1.0.0
