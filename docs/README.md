# Documentation Index

> **Audience:** everyone · **Status:** Current · **Last updated:** 2026-09-02
> **Conventions:** lowercase kebab-case filenames; `.th.md` marks a Thai version

Every document in this folder, by audience. Start with the row that matches who
you are.

| I am… | Start here |
|---|---|
| A developer taking over the project | [handover/engineering-handover.md](handover/engineering-handover.md) |
| New to the domain vocabulary | [../CONTEXT.md](../CONTEXT.md) — the glossary |
| Setting up a dev environment | [../README.md](../README.md) |
| Deploying to production | [operations/production-deployment.windows.md](operations/production-deployment.windows.md) |
| Cutting a release / deploying an update | [operations/deploy-and-release.windows.md](operations/deploy-and-release.windows.md) |
| Operating the reporting / analytics layer | [operations/reporting-layer-operations.md](operations/reporting-layer-operations.md) |
| A SOC analyst / manager using the app | [user-guides/end-user-guide.th.md](user-guides/end-user-guide.th.md) |
| Running a UAT session | [uat/uat-environment-setup.md](uat/uat-environment-setup.md) |
| An executive wanting the summary | [user-guides/executive-brief.th.md](user-guides/executive-brief.th.md) |
| Wondering how far the project is from done | [project-roadmap.md](project-roadmap.md) |

## Status taxonomy

Each row below carries a **Type** so you know how much to trust it as "now":

| Type | Meaning |
|---|---|
| **Current** | Describes the live system as it is now. Keep in sync with the code. |
| **As-built** | A dated record of what was actually deployed/built. Accurate for its date. |
| **Procedure** | A runbook / how-to. Follow the steps. |
| **Historical** | Superseded — an earlier generation of the system. Reference only; do not follow. |
| **Generated** | Produced by a script or tool — edit the source, not the output. |
| **Local-sensitive** 🚫 | Untracked by git (secrets, internal hosts, or live local notes). Exists on disk only. |

🚫 = git does not track this file (see **Notes** for why). 📌 = exempt from the filename conventions.

---

## handover/ — Project handover

The entry point for anyone taking over the codebase: what the system is, how the
state machine works, where the code lives, and the things not obvious from
reading the source.

| File | Type | Contents |
|---|---|---|
| [engineering-handover.md](handover/engineering-handover.md) | Current | Full technical tour (English) — the authoritative handover |
| [engineering-handover.th.md](handover/engineering-handover.th.md) | Historical | Thai translation, **pinned to commit `564a196` (23 Jul 2026)** — carries a top banner noting it lags the English on the owner-lane collapse and the Windows platform. Not in sync; use the English for current detail |

## architecture/ — How the system is designed and why

| File | Type | Contents |
|---|---|---|
| [ticket-lifecycle-states.md](architecture/ticket-lifecycle-states.md) | Current | **The authoritative current-workflow reference.** The lifecycle (12 active states + 1 legacy `OWNER_REMEDIATED`) as a mermaid diagram + transition table, organised by responsible role |
| [workflow-change-log.md](architecture/workflow-change-log.md) | Current | Dated rationale for the workflow redesign and each amendment (manager triage, response teams, Event-downgrade gate, Tier 2 claim, Tier 1 My Queue, owner two-step retirement §0.3) |
| [data-infrastructure.md](architecture/data-infrastructure.md) | Current | The whole data picture — every store, the flows between them, the four-layer model, and how backup fits (with a mermaid diagram) |
| reporting-layer-design.md 🚫 | Current | Reporting layer (Layer ③ `mart` schema) design spec — grains, metric definitions, severity normalization, phased rollout |
| reporting-layer-build.md 🚫 | As-built | As-built record of the reporting layer (Phases 1–3 built, committed, scheduled): objects, migrations, privilege model, decisions |

## adr/ — Architecture decision records 📌

One decision per file, sequentially numbered. Read these before changing the
area they cover — they record *why*, which the code cannot.

| File | Type | Decision |
|---|---|---|
| [0001](adr/0001-case-bundling-fan-out.md) | Current | A Project Incident fans out into one member Ticket per affected system, rather than one Ticket carrying many assets |
| [0002](adr/0002-ola-clock-from-incident-time.md) | Current | OLA clocks start from when the incident occurred, not when the Ticket was filed |
| [0003](adr/0003-manager-verification-gate-in-model.md) | Current | The manager-verification gate is enforced in the model, not only the view (**amended 2026-07-08**: gate condition is the Emergency flag only — severity floor removed) |
| [0004](adr/0004-mixed-project-incident-classification.md) | Current | A Project Incident allows mixed member classifications — each member Ticket is classified independently by Tier 1 |

## operations/ — Running it in production

| File | Type | Contents |
|---|---|---|
| [production-deployment.windows.md](operations/production-deployment.windows.md) | Procedure / As-built | **The build book for production.** Windows Server + native PostgreSQL + Waitress + IIS. Executed end-to-end; Stage 13 HTTPS as-built 2026-08-26 (self-signed bridge) |
| [deploy-and-release.windows.md](operations/deploy-and-release.windows.md) | Procedure | Cutting a SemVer release and deploying an update on Windows: tag after CI green → deploy → verify → roll back |
| [dev-and-release-cycle.md](operations/dev-and-release-cycle.md) | Procedure | The prescriptive day-by-day dev/release cadence — what to do now, the train calendar |
| [backup-and-standby-handbook.windows.md](operations/backup-and-standby-handbook.windows.md) | Procedure / As-built | **The backup & DR build book for this deployment.** Windows + native PostgreSQL: backups, off-host pull, restore drills (passed 2026-08-24), streaming standby, failover/DR |
| [postgresql-standby-handbook.md](operations/postgresql-standby-handbook.md) | Procedure | Generic PostgreSQL streaming-standby reference (platform-neutral) backing the Windows handbook's Phase 3 |
| [backup-and-restore.md](operations/backup-and-restore.md) ⚠️ | Partial (concepts Current, mechanism Historical) | Backup *concepts* — archive contents, the roles/grants-not-in-the-dump gap, 3-2-1 strategy. Mechanism is Docker/Linux; the concepts still apply |
| [backup-storage-decision-brief.md](operations/backup-storage-decision-brief.md) | Current | One-page brief for the CISO / data-governance decision on backup storage location & retention (mechanism live; policy still open) |
| [reporting-layer-operations.md](operations/reporting-layer-operations.md) | Procedure / Current | Running & deploying the reporting layer: `refresh_reporting`, scheduling (live 2026-08-26), readiness checklist, verification, rollback |
| [reporting-ro-setup.sql](operations/reporting-ro-setup.sql) | Procedure | One-time superuser SQL creating the read-only `reporting_ro` role for Grafana/BI (run at Phase 4; takes `-v owner=<DB_USER>` — `ticket_prod` in prod) |
| grafana-wazuh-wall.md 🚫 | Local-sensitive / Current | The "Wazuh SOC Wall" big-screen board. Reads **directly** from the Wazuh Indexer (OpenSearch), not this app's PostgreSQL |

## security/ 🚫 — Security assessments & remediation

**Local-sensitive — untracked.** Contains security findings, internal host
details, and (now-redacted) credential-rotation steps. Values are redacted;
real secrets live in the secret manager.

| File | Type | Contents |
|---|---|---|
| security/va-report-2026-07-31.md 🚫 | Local-sensitive / As-built | White-box vulnerability assessment of the app (dated 2026-07-31) — findings, severities, remediation guidance |
| security/credential-rotation-2026-07-31.md 🚫 | Local-sensitive / Procedure | Runbook to rotate the credentials called out by the VA (HIGH-01/02) against live accounts |

## user-guides/ — For people using the app

| File | Type | Contents |
|---|---|---|
| [end-user-guide.th.md](user-guides/end-user-guide.th.md) | Current | **The current end-user guide.** Thai: every state, every role, per-screen walkthroughs |
| [role-workflows.th.html](user-guides/role-workflows.th.html) | Current | Standalone Thai role-by-role workflow walkthrough (self-contained HTML) — closest to the active workflow |
| [executive-brief.th.md](user-guides/executive-brief.th.md) | Current | Thai one-pager for executives — capabilities and governance, no implementation detail |
| feature-guide.docx ⚠️ | Historical | **Prepared 19 Jun 2026 — do NOT hand to users as current.** Predates the 2026-07 redesign: shows Tier 1 verifying containment, Critical routing to the manager, multiple roles setting Emergency, Emergency editable after closure — all now false. (Carries a banner on page 1.) Use the guides above until rewritten |
| system-overview.th.docx / .th.pdf 🏛️ | Historical / Generated | Thai system **overview** (dated, high-level) — a readable introduction, not the current-workflow authority. For behaviour, see [ticket-lifecycle-states.md](architecture/ticket-lifecycle-states.md) |

## uat/ 🚫 — User acceptance testing

**All `.md` here are untracked** (`.gitignore` covers `docs/uat/*.md`).

| File | Type | Contents |
|---|---|---|
| uat-environment-setup.md 🚫 | Local-sensitive / Procedure | Getting the UAT VM seeded so every role has a login and every dashboard has data |
| uat-test-scenarios.md 🚫 | Local-sensitive / Procedure | Guided end-to-end scenarios (22 active edges + 1 legacy) then a free-play checklist |
| items-5-6-manual-test-guide.md 🚫 | Local-sensitive / Procedure | Focused manual test guide for backlog items 5–6 |
| uat-feedback-log.md 🚫 | Local-sensitive | Low-friction feedback capture — one row per observation |
| uat-vm-operations-guide.docx | Generated | UAT VM setup & operations — a **17 Jul 2026 snapshot**; its "UAT database restored" status was **re-confirmed valid 2026-09-03**. Generated by `.codex_work/build_uat_vm_guide.py` — edit the script, not the .docx |

## diagrams/ — Hand-drawn diagrams

Both are **hand-maintained** (no generator script). Update them when the model
changes, or prefer the mermaid in `ticket-lifecycle-states.md`, which is the
authority for the workflow.

| File | Type | Contents |
|---|---|---|
| database-er-diagram.svg | As-built (snapshot) | ER diagram — a **2026-07-06 snapshot**; carries a note listing later schema it omits (Project Incident, audit-history, staging, reporting mart) |
| ticket-flow-by-role.svg ⚠️ | Historical | Ticket-flow swimlanes — **stamped OUTDATED**; predates the manager pre-triage, owner lane, Tier-2 verification, and Emergency-only gate. Use `ticket-lifecycle-states.md` |

## imports/ — Notion CSV exports

| File | Type | Contents |
|---|---|---|
| [imports/README.md](imports/README.md) | — | What these exports are |
| imports/backlog-update-2026-08-13-notion-import.csv | Generated (snapshot) | Backlog / feature tracker export, 2026-08-13 |
| imports/uat-round1-items-1-6-notion-import.csv | Generated (snapshot) | UAT round 1 items 1–6 feedback export |

## archive/ — Superseded documents

| File | Type | Contents |
|---|---|---|
| [archive/README.md](archive/README.md) | — | What's archived and what replaced it |
| archive/production-deployment.md ⚠️ | Historical | Docker/nginx/gunicorn runbook. Superseded by `operations/production-deployment.windows.md` |
| archive/backup-vm-handbook.md ⚠️ | Historical | Linux/Docker off-host backup VM build. Superseded by `operations/backup-and-standby-handbook.windows.md` |

## agents/ — AI coding-agent configuration 📌

Not product documentation. These files configure how the engineering skills in
`.agents/skills/` interact with this repo.

| File | Type | Contents |
|---|---|---|
| [domain.md](agents/domain.md) | Current | Declares the single-context layout (one `CONTEXT.md` + `docs/adr/`) |
| [issue-tracker.md](agents/issue-tracker.md) | Current | Issues live in GitHub `Getter939/SOC_Ticket`, driven via `gh` |
| [triage-labels.md](agents/triage-labels.md) | Current | Maps the five canonical triage roles to this repo's label strings |

---

## Notes

**📌 `adr/` and `agents/` are exempt from the filename conventions.** Their paths
and filenames are hardcoded in the agent skills under `.agents/skills/` and in
the root `AGENTS.md`, so they keep their existing names. ADRs additionally
follow a prescribed format (`NNNN-slug.md`, often a single paragraph) defined in
`.agents/skills/domain-modeling/ADR-FORMAT.md` — do not impose the house header
block on them.

**🚫 marks files that git does not track.** `.gitignore` **no longer** uses a
blanket `*.md` rule — Markdown is tracked by default. It now *selectively* ignores
only files known to hold local credentials, internal host details, security
findings, or live UAT notes: `PROJECT_STATUS.md`, `docs/security/`,
`docs/uat/*.md`, `docs/operations/grafana-wazuh-wall.md`, and the two reporting
`docs/architecture/reporting-layer-*.md` files. Those exist on disk but are
untracked — do not conclude from `git log` alone that they are missing.

**Paths changed on 2026-07-21, and again on 2026-09-02** (superseded docs moved
to `archive/`, Notion CSVs to `imports/`). Older commit messages and Notion pages
still reference the old locations. See §7 of
[handover/engineering-handover.md](handover/engineering-handover.md) for the
earlier old→new mapping.

**Source of truth.** For *behaviour*, the code wins — specifically
`apps/incidents/models.py` (`STATUS_CHOICES`, `ALLOWED_TRANSITIONS`) and
`apps/accounts/models.py` (`ROLE_CHOICES`). For *terminology*,
[../CONTEXT.md](../CONTEXT.md) wins. Prose docs are downstream of both.
