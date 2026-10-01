# Reporting mart: groundwork now, dashboard uses later

> **Audience:** developers · **Status:** Part A built and rolled out to PROD 2026-10-01 (ops doc §3G) · Part B design only · **Last updated:** 2026-10-01
>
> Companion to [reporting-layer-design.md](reporting-layer-design.md) and [../operations/reporting-layer-operations.md](../operations/reporting-layer-operations.md).

## Context
Nothing on either dashboard reads the reporting mart (`mart` schema in `ticketdata`, app `apps/reporting`) yet. `refresh_reporting` runs nightly on PROD (`SOC-Refresh-Reporting`, 00:20). Most of the mart can be rebuilt from history at any time. Three things can't, and they need doing before the mart is used:

1. **Alert funnel history is about to start disappearing.** `mart.agg_alert_daily` is a materialized view over `mart.fact_alert`, which is a view over `wazuh_ingest_wazuhalert`. `purge_wazuh_alerts` (daily 04:00, `WAZUH_RETENTION_DAYS`=90) deletes raw alerts with `timestamp < now − 90d`. It skips alerts linked to a ticket, a link or a project, and alerts in PENDING or TRIAGING. The next MV refresh then silently drops those alerts from past days: FP counts, triage-OLA counts.
2. **A failed or missed night is silent.** The job prints `errors: [...]` to `C:\SOCTicket\logs\reporting.log` and exits 0. Snapshot and detection history for that night is lost for good.
3. **The nightly snapshot misses things that can't be rebuilt**: who holds each open case (there is no assignee history anywhere), the unassigned and emergency counts, the oldest open age, and the response-request backlog. The last two were already in the design doc §5.3 and never built.

Part A was built on 2026-10-01: migration `reporting 0006`, `apps/reporting/alerts.py`, the `check_reporting_freshness` command, and new steps in `refresh_reporting`. Two choices differ from the first draft: the first run backfills every day still present automatically (no flag), and the watchdog checks the always-written `snapshot_kpi_daily` row rather than `snapshot_queue_daily`, which has no rows on a night with an empty queue. Part B is design only; no dashboard changes are in scope yet.

**Deadline check (first thing, on PROD):** run `SELECT min(timestamp) FROM wazuh_ingest_wazuhalert;` and `manage.py purge_wazuh_alerts --dry-run`. The first real loss is on min(timestamp) + 90 days. If the dry run already shows deletable rows, A1 ships first and on its own.

---

## Part A: implement beforehand (all additive, in `apps/reporting`)

### A1. Keep alert funnel history (`mart.hist_alert_daily`)
- **New managed model `HistAlertDaily`** in `apps/reporting/models.py`, `db_table = 'mart"."hist_alert_daily'`:
  - grain (day, severity_band), unique constraint;
  - the same 8 counts as the MV (`ingested_count` … `triage_ola_met`), copied from the SQL in migration `0003`;
  - `captured_at`.
- **New step 1b in `refresh_reporting.py`**, after the MV refresh: upsert from `mart.agg_alert_daily` into the history table (`bulk_create(update_conflicts=True)`, as in the detection step), **only for days ≥ today − (WAZUH_RETENTION_DAYS − 2)**.
  - Older days are frozen: never overwritten, never deleted. A day that's half-purged can't lower its own stored counts.
  - Recent days keep updating while analysts triage late.
- **Backfill:** the first run copies every day still present, which should be all of them, per the deadline check.
- **Consumers read `hist_alert_daily`, never the MV.** Add a comment on the MV saying so.
- **Tests** (`apps/reporting/tests.py`, next to `FactAlertFunnelTests`):
  - the upsert is idempotent;
  - a recent day updates when triage changes;
  - a frozen day keeps its counts after its source alerts are deleted.

### A2. Make failures loud
- **`refresh_reporting`:**
  - If `result['errors']` is non-empty after all steps, email the error list with `django.core.mail.send_mail` to a new `.env` setting, `REPORTING_ALERT_EMAILS` (comma list; empty means log only). SMTP is already configured (`EMAIL_HOST` etc. in `config/settings.py`).
  - Then `raise CommandError(...)`, so the exit code is non-zero and Task Scheduler's "Last Run Result" shows the failure.
  - A failure to send the email is logged; it must not hide the original errors.
  - The steps stay isolated: one failing still doesn't stop the others.
- **Watchdog for "the job never ran":** a new command, `check_reporting_freshness`, scheduled daily at 07:00 as `SOC-Check-Reporting`. It emails the same list and exits non-zero if:
  - there's no `snapshot_queue_daily` row for today;
  - `max(agg_detection_daily.day)` is older than yesterday;
  - `max(hist_alert_daily.day)` is older than yesterday while alerts from yesterday exist.
- **Tests:**
  - an error sends one email and exits non-zero;
  - a clean run sends none;
  - the watchdog flags a missing snapshot.

  Use the `mail.outbox` pattern already used by the other email tests.

### A3. Snapshot what can't be rebuilt
Add new tables, and leave `snapshot_queue_daily`'s grain alone so existing rows and meaning are unchanged. Write them in step 2 with the same delete-then-insert per date and one `transaction.atomic()`.
- **`SnapshotKpiDaily`**, one row per day:
  - `unassigned_open`;
  - `emergency_open_tickets`, plus `emergency_open_incidents` computed with `apps.dashboard.views._incident_count` semantics (a bundle counts once; move that helper somewhere shared rather than importing from views);
  - `oldest_open_hours`;
  - `response_open`, `response_aged_7d`.
- **`SnapshotWorkloadDaily`**, grain (date × kind × user_id × status × severity) → `open_count`:
  - `kind` is `assigned` (`Ticket.assigned_to`, null meaning unassigned) or `t2_claimed` (`t2_claimed_by`), matching what the Analyst Workload heatmap counts;
  - store `username` as text too, so a deleted user's history survives.
- **`SnapshotResponseDaily`**, grain (date × subtask_type × status × aged_7d × hc_ticket) → `open_count`:
  - "open" uses the same rule as the Executive dashboard's `active_response_q`: status OPEN or IN_PROGRESS and the ticket not closed;
  - "aged" means `created_at` more than 7 days ago.
- **Put the snapshot logic in `apps/reporting/snapshot.py`** beside `compute_snapshot_rows`, reusing `Ticket.TERMINAL_STATUSES`, `TicketSubtask.RESPONSE_TYPES` and the `ola` helpers.
- **Tests:**
  - each table is idempotent on a same-day re-run;
  - closed tickets are excluded;
  - an unassigned case goes to `user_id NULL`;
  - a bundle counts as one emergency incident.
- **Privacy note:** the workload table is per person. If `reporting_ro` is ever created, decide whether to grant it that table.

### A4. Docs, deploy, checks
- **Update:**
  - `docs/operations/reporting-layer-operations.md`: new steps, `REPORTING_ALERT_EMAILS`, the `SOC-Check-Reporting` task, the frozen-window rule;
  - `docs/architecture/reporting-layer-design.md` §5 catalog;
  - `CHANGELOG.md`.
- **Deploy order:**
  1. `migrate reporting`;
  2. set `REPORTING_ALERT_EMAILS`;
  3. run `refresh_reporting` once by hand and expect `errors: []`, with `hist_alert_daily` rows equal to MV rows;
  4. create the `SOC-Check-Reporting` task;
  5. test the alert once by running with a deliberately bad Indexer URL.
- **At the next restore drill,** confirm the backup includes the `mart` schema (`pg_restore -l <archive> | findstr mart`).

### Verification (Part A)
- `venv/Scripts/python.exe manage.py test apps.reporting apps.dashboard --noinput` passes.
- Local dry run on dev data:
  1. Run `refresh_reporting` twice: same row counts both times, no duplicates.
  2. Delete an old triaged alert and refresh again: its frozen day is unchanged.
  3. Break the Indexer URL: one email in the console backend and exit code 1.

---

## Part B: what mart data could go on the dashboards (design, not built)

**Rules for any mart-fed number:**
- **Label it as nightly data:** captions say "ข้อมูล ณ 00:20 · อัปเดต <date>", never "LIVE".
- **Stale:** past 36 hours, show it grey with "ข้อมูลไม่อัปเดต" rather than silently old.
- **History start:** show when history begins ("เริ่มเก็บ <date>") instead of plotting zeros.
- **Filters:** snapshots follow the status and severity filters but not the opened-date range (they store neither the opened date nor the date filter), and the caption says so.
- **LIVE cells:** never mix a mart number into a LIVE cell without its own caption.
- **New metrics:** every item below is new on its page, so each needs sign-off. That especially applies to the Executive page, whose brief said "no new metrics".
- **Declined:** the full "Queue Trend" panel was declined on 30 Sep 2026. The SOC items below are compact alternatives, not a re-proposal.

### SOC Dashboard (daily operations, trends for the manager)
| # | Placement | Shows | Source | Needs |
|---|---|---|---|---|
| S1 | Containment Runway header | 30-night line of overdue cases + "↑9 จาก 7 คืนก่อน" | `snapshot_queue_daily` (ola_bucket = overdue) | already captured |
| S2 | Analyst Workload expanded row | that analyst's 30-night open-case line | `snapshot_workload_daily` | A3 |
| S3 | New compact card by the Wazuh freshness header: "Wazuh Triage · 7 วัน" | alerts ingested → triaged → true positive → became a Ticket; triage-OLA met %; FP rate | `hist_alert_daily` | A1 |
| S4 | Daily Case Volume panel | alert volume per day (by rule level) as a faint series behind case volume: detection vs work | `agg_detection_daily` | already captured |
| S5 | Pipeline or Active Cases area | weekly containment-OLA compliance % (closed within deadline ÷ applicable) | `agg_ticket_daily` | MTTR/OLA definitions agreed |

### Executive Dashboard (posture over months)
| # | Placement | Shows | Source | Needs |
|---|---|---|---|---|
| E1 | KPI strip captions (Emergency, OLA overdue) | "30 วันก่อน: 52", a posture comparison, no chart | `snapshot_kpi_daily` / `snapshot_queue_daily` | A3 |
| E2 | Function card mini-bars | per-function backlog now vs 30 days ago ("PenTest 7 · 30 วันก่อน 3") | `snapshot_response_daily` | A3 |
| E3 | New KPI or card: "ปิดทันกำหนดควบคุม" | monthly containment-OLA compliance %, incident-level | `agg_ticket_daily` / `fact_ticket` | agreed definitions |
| E4 | Small card: "สัญญาณเตือน → งานจริง" | this month: alerts → true positives → Tickets (noise vs real work) | `hist_alert_daily` | A1 |
| E5 | MTTR cell | monthly trend of MTTR measured from detection time, with "% วัดจากเวลา SIEM" | `fact_ticket.time_to_resolve` | MTTR reconciled first |

**Prerequisite for S5, E3 and E5:** reconcile the dashboards' `_mttr_stats` and closure-time logic (`apps/dashboard/views.py`) with `fact_ticket` (`detected_at` coalesce, `contain_ola_met`), so each metric has one definition.

**Suggested first picks once Part A has run a few weeks:** S1 and E1. They are captions and sparklines on panels that already exist and answer "getting better or worse?". After those, S3 (it gives the alert funnel history from A1 a purpose).
