# SOC Ticketing System — Handover Document

_Last updated: 2026-07-02 (repo at commit `682de3f`, "1/7 OLA Policy updated")_
_ฉบับภาษาไทย: [HANDOVER.th.md](HANDOVER.th.md)_

This document is the entry point for anyone taking over this project. It covers
what the system is, how it works, where the important code lives, how to run
and deploy it, and the things that are **not** obvious from reading the code.

Companion documents (read in this order):

| Document | What it covers |
|---|---|
| [README.md](../README.md) | Local dev setup, test-data seeding, offline Wazuh fixtures |
| [WORKFLOW_REDESIGN.md](../WORKFLOW_REDESIGN.md) | Full rationale for the 2026-06-19 ticket workflow redesign |
| [DEPLOY.md](../DEPLOY.md) | Production deployment (Docker, nginx, gunicorn) — **see caveat in §7** |
| `SOC_Ticketing_System_Feature_Guide.docx` | End-user feature guide (screenshots, per-role walkthroughs) |
| Notion: "SOC Ticketing System — Technical Documentation" | Full technical reference, rewritten 2026-06-29 to match current state |

---

## 1. What this is and why

A Django-based **SOC (Security Operations Centre) ticketing and incident
management platform** for an internal Thai SOC team. It manages the full
lifecycle of security incidents: alert ingestion from Wazuh/OpenSearch, triage,
ticket creation, escalation, containment by system administrators, analyst
verification, manager approval, and OLA (Operational Level Agreement)
deadline tracking — plus a KPI dashboard.

- A previous iteration lives at `C:\Users\NT\Documents\soc-crm`; this repo is
  the current, active version.
- UI labels are a mix of Thai and English (verbose_names on models are Thai).
- Runs on an internal LAN over HTTP by default; HTTPS hardening flags exist
  but are opt-in via `.env` (see §7).

**Key design decisions and their rationale:**

- **Two separate assignment fields** — `assigned_to` (SOC analyst working the
  ticket) and `assigned_admin` (system administrator doing containment) are
  deliberately separate roles on a ticket. Do **not** merge them.
- **Classification is authoritative, never derived** — `classification`
  (`INCIDENT` / `EVENT`, formerly TP/FP) is set explicitly by Tier 1 at
  creation (Tier 2 may revise it on escalated tickets). It gates which state
  transitions are legal.
- **Tier carries permission weight** (since the 2026-06-19 redesign) — T1/T2
  on SOC staff is not just a seniority label. Only Tier 1 creates tickets and
  drives the T1 side of the workflow; Tier 2 only handles escalated tickets
  and can never assign admins or create tickets. See WORKFLOW_REDESIGN.md for
  the full reasoning.
- **OLA breach semantics differ by deadline** — the *triage* breach is a fixed
  historical fact ("was the ticket raised in time?"), while the *contain*
  breach is a live countdown on active tickets. See §4.
- **Attachments are evidence** — they are only served through an
  authenticated, authorization-checked download view. This closed a real
  stored-XSS / unauthenticated-download hole. See §8.

## 2. Tech stack

| Component | Version / detail |
|---|---|
| Python / Django | Django 6.0.5 (see `requirements.txt` for exact pins) |
| Database | PostgreSQL 16 (`psycopg2-binary`) |
| Config | `python-decouple` reading `.env` (template: `.env.example`) |
| Static files | WhiteNoise |
| Prod server | gunicorn behind nginx, via `docker-compose.prod.yml` |
| Excel export | openpyxl (`export_tickets_excel` in incidents views) |
| Alert source | Wazuh alerts via the OpenSearch REST API (`requests`) |

Migration heads at time of writing: `incidents 0030`, `wazuh_ingest 0005`,
`accounts 0003`.

## 3. Feature summary

### 3.1 Ticket lifecycle (state machine)

Eight states, defined in `apps/incidents/models.py` and enforced by
`Ticket.transition_to`:

```
NEW ─(classify EVENT)────────────────────────────► CLOSED_EVENT (terminal)
 │
 └(classify INCIDENT)
    ├── T1 assigns admin ──► AWAITING_CONTAINMENT ──► CONTAINMENT_REPORTED
    │                              ▲                        │ (admin submits report)
    │                              │ (T1: not contained)    │
    │                              └────────────────────────┤
    └── T1 escalates ──► ESCALATED_T2                       │ (T1: contained)
              │                                             ▼
              ├─(T2: EVENT)──► CLOSED_EVENT       PENDING_MANAGER ──► APPROVED (terminal)
              └─(T2: INCIDENT)──► T1_REVIEW              (or straight to APPROVED if no
                       │                                  manager verification required)
                       └──► AWAITING_CONTAINMENT
```

Rules that are easy to get wrong:

- **T2 can only return tickets to T1 (`T1_REVIEW`) or close events.** T2 never
  assigns admins and never creates tickets.
- The **rejection loop**: if T1 judges containment insufficient,
  `CONTAINMENT_REPORTED → AWAITING_CONTAINMENT` and the assigned admin is
  re-notified.
- **Manager routing**: `requires_manager_verification` is true when severity ≥
  the floor (default `Critical`, overridable via `settings.SOC_SEVERITY_FLOOR`)
  **or** the ticket is flagged emergency. Only such tickets pass through
  `PENDING_MANAGER`; others go straight to `APPROVED` when T1 confirms
  containment.
- Permission tokens (`TIER1_CREATOR`, `TIER2`, `ASSIGNED_ADMIN`, `MANAGER`) are
  declared per-transition in `TRANSITION_PERMISSIONS`; `transition_to` also
  enforces the classification gate and the manager-routing gate.
- Old states `UNDER_REVIEW` / `VERIFIED` / `CLOSED_FP` were removed by
  migration 0018 (remapped to `CONTAINMENT_REPORTED` / `PENDING_MANAGER` /
  `CLOSED_EVENT`). If you see them in old docs or the git history, translate.

### 3.2 Roles (`apps/accounts/models.py` — `UserProfile`)

| Role | Capabilities |
|---|---|
| **SOC Staff, Tier 1** | Creates tickets (manual triage or from Wazuh alerts), classifies, assigns admins, escalates to T2, verifies containment. The only role that creates tickets. |
| **SOC Staff, Tier 2** | Works `ESCALATED_T2` tickets only: revise classification, return to T1, or close as event. |
| **SOC Manager** | Verifies `PENDING_MANAGER` tickets → `APPROVED`. |
| **System Admin** | Sees only tickets where they are `assigned_admin`. Writes `containment_report` (countermeasure) and `remediation_summary` (findings), returns the ticket to T1. Never sets classification. |
| **System Owner** | Notified when tickets open/close on systems they own; has a read-oriented "My Tickets" dashboard at `/incidents/my-tickets/`. |

Visibility is centralized in `TicketQuerySet.visible_to(user)`: SOC roles see
all tickets, system admins see only their assigned tickets, users without a
profile see nothing. **Always check `getattr(user, 'profile', None)` before
role checks** — superusers created via `createsuperuser` have no profile.

### 3.3 Emergency flag

`is_emergency` can be toggled at **any** stage, including terminal states, by
any role **except** Tier 1 — T1 may only set it if the ticket was previously
escalated to T2 (`was_escalated_to_t2`, derived from the write-once
`escalated_to_t2_at` timestamp). Every toggle writes a `TicketLog`. Emergency
forces manager verification.

### 3.4 OLA policy (reworked 2026-07-01 — the most recent change)

Terminology: this system says **OLA**, not SLA (renamed in migrations
0028–0030). Two deadlines per ticket, both computed at creation from
`incident_datetime` (fallback: now), per severity via `Ticket.OLA_TARGETS`:

| Severity | Triage (raise ticket within) | Contain (resolve within) |
|---|---|---|
| Critical | 30 min | 4 h |
| High | 2 h | 24 h |
| Medium | 24 h | — (notification-only) |
| Low | 24 h | — (notification-only) |
| Unknown | mirrors Critical | mirrors Critical |

- **Triage OLA** (`is_ola_triage_breached`, alias `is_ola_breached`): a
  **fixed fact** — was `created_at` later than the triage deadline? Evaluated
  at issue time, never changes afterwards.
- **Contain OLA** (`is_ola_contain_breached`): a **live countdown** — an
  active (non-terminal) ticket past its contain deadline. Medium/Low have no
  contain deadline and can never contain-breach.
- `apps/incidents/ola.py` is the **single source of truth** for bucketing the
  active queue by contain-deadline pressure (Overdue / Due ≤1h / Due 1–4h /
  On-track). The dashboard chart and the ticket-list OLA filter both use it —
  change policy there, both surfaces follow.
- **Separate from all of the above**: `WazuhAlert` has its own flat 4-hour
  *alert triage* OLA (`WazuhAlert.OLA_HOURS`) running live from
  `alert.timestamp` until the alert is triaged.

### 3.5 Wazuh alert ingestion & triage (`apps/wazuh_ingest`)

- `python manage.py ingest_wazuh_alerts` pulls alerts from the OpenSearch REST
  API (`wazuh-alerts-*/_search`, HTTP Basic auth, config in `.env`). An ingest
  watermark prevents re-pulling; OpenSearch document IDs dedupe.
- `--fixture` mode loads bundled demo alerts with no network access (see
  README) — this is how you demo/test without reaching the cluster.
- Triage (claim / create ticket / release) is **Tier-1-only**. Releasing an
  alert **requires a reason** (`release_reason`). The alert-level
  `escalation_queue` is vestigial — escalation now happens at ticket level.
- There is **no scheduler in the repo** for ingestion — if production ingests
  periodically, that's an external cron/scheduled task on the host. Verify
  with the operator.

### 3.6 Notifications (`apps/incidents/notifications.py`)

- Email via SMTP (config in `.env`); `SITE_URL` builds absolute links.
- `notify_containment_required` fires whenever a ticket reaches
  `AWAITING_CONTAINMENT` (initial assignment **and** every rejection loop).
- System owners are notified on open/close of tickets for their systems.
- New-user credential emails and admin-panel actions to resend usernames /
  reset passwords (Thai-labelled actions in the Users admin).
- Failures are **non-fatal by design**: a failed email shows a warning but
  never rolls back the transition.

### 3.7 Dashboard (`apps/dashboard`)

KPI/chart home page (`/`): case status pipeline, categories, OLA-pressure
buckets, and a ticket table with a "Status Updated" column driven by
`status_changed_at` (a dedicated field re-stamped **only** on real status
transitions — notes and emergency toggles bump `updated_at` but not this).
Charts are fed via `json_script` (no `|safe` on user data — keep it that way).

### 3.8 Other features

- Ticket attachments (25 MB cap, download-only serving — see §8), subtasks,
  ticket logs/history with edit, Excel export, global search, IP lookup,
  manual triage records (`TriageRecord.source` shares choices with
  `Ticket.source`).

## 4. Codebase guide

```
config/                 settings.py, urls.py, middleware.py (CSP)
apps/
  incidents/            ★ THE core app — start here
    models.py           Ticket + state machine + OLA fields + logs/attachments/subtasks (61 KB)
    views.py            all ticket/triage views (48 KB)
    notifications.py    every email the system sends
    ola.py              OLA bucketing single source of truth
    forms.py            ticket/triage/attachment forms (incl. upload size cap)
    management/commands/seed_data.py            synthetic tickets for dev
    management/commands/seed_dashboard_mockup.py demo/screenshot dataset
    management/commands/seed_ola_demo_buckets.py OLA-chart demo dataset
  accounts/             UserProfile (role, tier), admin actions for credentials
  dashboard/            KPI views + tests
  wazuh_ingest/         WazuhAlert model, OpenSearch ingest, triage views
  customers/, projects/ ⚠ DEAD CODE — not in INSTALLED_APPS, no URLs (leftovers
                        from the old soc-crm version). Ignore or delete.
templates/              Django templates (base.html + per-app dirs)
```

**Reading order for a new developer:**

1. `apps/incidents/models.py` — the `Ticket` model top to bottom: statuses,
   `TRANSITION_PERMISSIONS`, `transition_to`, `OLA_TARGETS`, `save()`.
2. `WORKFLOW_REDESIGN.md` — why the state machine is shaped this way.
3. `apps/incidents/views.py` — `ticket_detail` and the transition-posting
   views; then `apps/wazuh_ingest/views.py` for the alert-to-ticket path.
4. Trace one ticket end-to-end in the UI using the seeded accounts (§5).

**Tests** are substantial and are the executable spec of the workflow:
`apps/incidents/tests.py` (71 KB) covers transitions/permissions,
`apps/dashboard/tests.py` covers KPI math, `apps/wazuh_ingest/tests.py` mocks
all HTTP. Run everything with `python manage.py test` — do this before and
after any workflow change.

## 5. Running it locally

Condensed from README.md (authoritative if they diverge):

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
copy .env.example .env                               # then fill in values
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8088
```

Needs a reachable PostgreSQL 16 (`DB_*` in `.env`). App at
`http://127.0.0.1:8088/`, admin at `/admin/`.

**Test data:**

- `python manage.py seed_data` — 100 tickets / 30 days, all statuses and
  severities, plus five role users. All seed rows carry the `seed_` username
  prefix so they can be wiped cleanly (`--flush`).
- `python manage.py ingest_wazuh_alerts --fixture [--fresh]` — offline demo
  alerts for the Wazuh triage flow.
- `test_accounts.txt` — five dev logins (shared password `Test1234!`),
  one per role. **Dev only; never create these in production.**

## 6. Deployment

Production: `docker compose -f docker-compose.prod.yml up -d --build`
(nginx → gunicorn → Django + PostgreSQL). The `web` container runs
`migrate` + `collectstatic` on every start. Full runbook in DEPLOY.md
(UFW, superuser creation, team accounts, logs).

- `docker-compose.yml` (no suffix) is **local dev only** (runserver +
  bind-mount). Never deploy it.
- No public sign-up: all accounts are created via `/admin/`.
- **Ask the outgoing owner:** where production actually runs (host/IP), who
  holds the `.env` secrets (DB password, SMTP, OpenSearch credentials), and
  what backs up the PostgreSQL volume — none of this is in the repo.

## 7. Known issues, gotchas, stale docs

1. **`apps/customers` and `apps/projects` are dead code** — present on disk
   with models/views/urls but not installed or routed. Safe to delete, but do
   it as a deliberate cleanup commit.
2. **DEPLOY.md's role table is stale**: it says tier is "a seniority label
   with no permission effect" and references `VERIFIED → APPROVED`. Both
   predate the 2026-06-19 redesign — tier **does** gate permissions and
   `VERIFIED` no longer exists. Trust WORKFLOW_REDESIGN.md and the code.
3. **CSP still allows `'unsafe-inline'`** for script/style
   (`config/middleware.py`, policy string in settings). Two inline handlers
   block going nonce-based: `ticket_detail.html` (confirm) and
   `ticket_history.html` (onchange). Planned next hardening step.
4. **No file-type/magic-byte validation on uploads** (low priority — mitigated
   by forced-download serving, §8).
5. **Alert-level `escalation_queue` is vestigial** after the redesign;
   escalation is ticket-level now.
6. **`runserver-8099.*.log` files in the repo root** are stray dev logs —
   deletable.
7. **OLA breach semantics are asymmetric** (fixed triage fact vs live contain
   countdown, §3.4) — easy to "fix" incorrectly if you assume both are live.
8. **The 0030 data migration recomputed all OLA deadlines** under the new
   per-severity policy. Historical breach stats from before 2026-07-01 reflect
   the recomputation, not what dashboards showed at the time.

## 8. Security posture (hardened 2026-06-15, VibeSec audit)

- **Attachments**: served **only** via `incidents.views.download_attachment`
  (login + `visible_to` check + forced `Content-Disposition: attachment` +
  `nosniff`). **Never re-add an open `/media/` route in `config/urls.py`** —
  that exact hole previously allowed unauthenticated downloads and stored XSS
  via uploaded `.html`/`.svg`. The dev-only media route is login-gated and
  mirrors prod behaviour.
- Upload size capped at 25 MB (`MAX_ATTACHMENT_SIZE`), enforced in the form
  **and** the create-ticket evidence loop.
- HTTPS flags (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`,
  `SECURE_SSL_REDIRECT`, HSTS, `USE_PROXY_SSL_HEADER`) are env-driven and
  default **off** so the internal-HTTP deploy works — **turn them on in any
  TLS deployment.**
- CSP via custom middleware; everything except script/style locked to
  `'self'` + `cdn.jsdelivr.net`.
- OpenSearch ingest supports TLS verification against a self-signed cluster
  cert via `OPENSEARCH_CA_BUNDLE` (recommended over `OPENSEARCH_VERIFY_SSL=False`).
- Dashboard chart data passed via `json_script`, not `|safe`.

## 9. External dependencies & contacts

| Dependency | Detail | Owner / where |
|---|---|---|
| PostgreSQL 16 | app database | _(fill in: host, backup owner)_ |
| SMTP server | all notifications | _(fill in: provider/account owner)_ |
| Wazuh / OpenSearch cluster | alert feed, HTTP Basic creds in `.env` | _(fill in: SOC infra owner)_ |
| Notion tech docs | "SOC Ticketing System — Technical Documentation" | workspace of the outgoing maintainer |
| OLA policy | who decides the per-severity targets in `OLA_TARGETS`? | _(fill in: SOC manager?)_ |

> **To the outgoing maintainer:** the italicized blanks above, plus §6's
> production questions, are the items only you can answer. Fill them in before
> handing this over.

## 10. Suggested first week

- **Day 1** — run it locally (§5), seed data, log in as each of the five test
  accounts and click around.
- **Day 2** — read `Ticket` in `models.py` + WORKFLOW_REDESIGN.md; trace one
  incident from Wazuh fixture alert → triage → ticket → containment →
  approval, as the appropriate user at each step.
- **Day 3** — run the full test suite; skim `incidents/tests.py` to see the
  workflow rules as executable spec.
- **Day 4** — review the dashboard views + `ola.py`; understand the OLA
  buckets and `status_changed_at`.
- **Day 5** — review DEPLOY.md against the real production host with the
  outgoing maintainer; confirm secrets, backups, and the ingest schedule.
