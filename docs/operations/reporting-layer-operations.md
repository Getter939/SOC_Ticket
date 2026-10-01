# Reporting Layer — Operations & Production Readiness

> **Audience:** operators, deployers · **Status:** Current — **live on PROD; scheduling executed 2026-08-26** · **Last updated:** 2026-10-01

How to run, deploy, and operate the reporting layer (Layer ③, the `mart` schema).
For the *design* see [../architecture/reporting-layer-design.md](../architecture/reporting-layer-design.md);
for the *as-built* record see [../architecture/reporting-layer-build.md](../architecture/reporting-layer-build.md).

---

> **✅ As-built — executed on PROD 2026-08-26.** The §3 cutover has been run:
> `ingest_wazuh_alerts` runs **per-minute** (`SOC-Ingest-Wazuh`, SYSTEM, IgnoreNew)
> against the production Indexer `10.1.220.32:9200`, and `refresh_reporting` runs
> **nightly** (`SOC-Refresh-Reporting`, 00:20) — MV refresh + queue snapshot +
> Indexer detection capture, all `errors: []` (first run `detection_rows: 31`).
> Retention is scheduled (`SOC-Purge-Wazuh`, daily 04:00, 90-day window; deletes
> nothing until data ages). **Interim security note:** the Indexer link runs
> `OPENSEARCH_VERIFY_SSL=False` (encrypted but unauthenticated) because the Wazuh
> root CA isn't on the VM yet — swap to `OPENSEARCH_CA_BUNDLE=C:\SOCTicket\certs\opensearch-ca.pem`
> + `OPENSEARCH_VERIFY_SSL=True` once the admin provides `root-ca.pem`. CSV
> historical import and Grafana/`reporting_ro` (§3.D) were intentionally deferred.

> **🆕 2026-10-01 — history that can't be rebuilt + loud failures (migration
> `reporting 0006`).** Alert-funnel history is now stored in `mart.hist_alert_daily`
> before the 90-day purge removes raw alerts; three more nightly snapshots record
> the KPI figures, who holds each open case, and the response-request backlog; a
> failed run emails `REPORTING_ALERT_EMAILS` and exits non-zero, and a 07:00
> watchdog (`check_reporting_freshness`) catches a night that never ran. **Rollout
> on PROD: §3G.** Background and the dashboard ideas that build on it:
> [../architecture/reporting-layer-next-steps.md](../architecture/reporting-layer-next-steps.md).

## 1. What it is, in one paragraph

A `mart` schema inside the `ticketdata` database holding pre-computed, read-only
facts and aggregates over tickets and Wazuh alerts, plus a daily queue snapshot
and a detection-volume capture from the Wazuh Indexer. Everything is refreshed by
one command, `refresh_reporting`. It is **purely additive** — no operational
table is touched — and fully reversible (`migrate reporting zero`).

---

## 2. The one command: `refresh_reporting`

```
python manage.py refresh_reporting [flags]
```

Runs isolated steps (one failing never aborts the others; it prints a result
dict and logs errors):

1. **REFRESH** the materialized views `mart.agg_ticket_daily` and
   `mart.agg_alert_daily`.
   - **1b. Alert-funnel history** — copy `agg_alert_daily` into
     `mart.hist_alert_daily` (upsert). Only days newer than
     `WAZUH_RETENTION_DAYS − 2` are updated; **older days are frozen** and never
     touched again, because `purge_wazuh_alerts` has started deleting their raw
     alerts and a recompute would only shrink them. The very first run (empty
     table) copies every day still present. Skipped if the view failed to refresh.
2. **Snapshots** — write tonight's point-in-time rows, *as of the run*, in one
   transaction. Idempotent: a same-day re-run replaces that day's rows.
   - `mart.snapshot_queue_daily` — the open queue by status, severity, age and
     OLA pressure.
   - `mart.snapshot_kpi_daily` — one row: open, unassigned, open emergency
     (Tickets and incidents — a Project Incident counts once), oldest open case
     (hours), open response requests and how many are over 7 days old. Written
     every night even when the queue is empty, so it doubles as the "the job ran"
     marker the watchdog checks.
   - `mart.snapshot_workload_daily` — open cases per holder: `assigned` (the
     assignee; NULL user = unassigned) and `t2_claimed` (the Tier 2 claimant).
     **Per-person data** — think before granting it to `reporting_ro`.
   - `mart.snapshot_response_daily` — open response requests by function,
     status, over-7-days and High/Critical parent ticket.
3. **Detection** — capture per-(day × rule_level) alert volume from the Wazuh
   Indexer into `mart.agg_detection_daily` (upsert).

**If any step reports an error** the command emails `REPORTING_ALERT_EMAILS`
(`.env`, comma-separated; empty = log only) and **exits non-zero**, so the
task's *Last Run Result* in Task Scheduler shows the failure. A night it fails to
capture cannot be captured later.

| Flag | Effect |
|---|---|
| *(none)* | all three steps, using `REFRESH … CONCURRENTLY` |
| `--no-concurrently` | plain (locking) REFRESH — for running inside an outer transaction |
| `--skip-snapshot` | skip step 2 |
| `--skip-detection` | skip step 3 (e.g. when the Indexer is unreachable) |
| `--detection-days N` | days of Indexer history to (re)capture per run (default 2) |

Expected healthy output:
`{'mv_refreshed': ['mart.agg_ticket_daily', 'mart.agg_alert_daily'], 'alert_history_rows': N, 'snapshot_rows': N, 'detection_rows': N, 'errors': []}`

### The watchdog: `check_reporting_freshness`
`refresh_reporting` can't report a night it never started (server down, task
disabled, expired service-account password). `check_reporting_freshness` runs a
few hours later and checks that the night's work is in the mart:
- a `snapshot_kpi_daily` row for today;
- a `hist_alert_daily` row for yesterday, if any alert arrived yesterday;
- `agg_detection_daily` up to yesterday, when `OPENSEARCH_HOST` is set (a day
  with no alerts at all would also trip this — rare at rule level ≥ 10).

Any gap is emailed to `REPORTING_ALERT_EMAILS` and the command exits non-zero.

**Run ordering:** schedule `ingest_wazuh_alerts` **before** `refresh_reporting`.
The alert funnel (`fact_alert` / `agg_alert_daily`) reflects only alerts already
pulled into the in-app `wazuh_ingest_wazuhalert` table, so refresh should follow
ingest. (Step 3 detection capture reads the Indexer directly and is independent.)

---

## 3. What to do once production is ready  ← the cutover checklist

At go-live, on the **Windows** production VM (Windows Server + native PostgreSQL 18
+ Waitress + IIS — see [production-deployment.windows.md](production-deployment.windows.md)).
Do these in order:

### A. Deploy the code — the schema follows automatically
`manage.py migrate` (runbook Stage 6) already applies these. To apply just the
reporting migrations, or to verify, on the VM:
```powershell
$py = 'C:\SOCTicket\app\venv\Scripts\python.exe'
& $py manage.py migrate reporting     # creates the mart schema + objects (additive, reversible)
& $py manage.py refresh_reporting --skip-detection --skip-snapshot
# expect: errors: []   ·   spot-check: SELECT count(*) FROM mart.fact_ticket;  == ticket count
```

### B. Confirm the severity map
In Django admin → **Severity mappings** (`mart.dim_severity_map`). The seeded
Wazuh bands (14–999 Critical / 12–13 High / 7–11 Medium / 0–6 Low) match the
legacy Grafana thresholds. Tune the cut-points if the SOC reports severity
differently, and add rows for any other source (e.g. TrendMicro `alert_score`
0–100). Editing here needs **no deploy** — native scores are preserved and
unmapped scores fall back to `Unknown`.

### C. Schedule the nightly refresh — this is when history starts accruing
Production is **Windows** → use **Windows Task Scheduler** (task prefix `SOC-*`,
matching the runbook), not cron. The OS timezone is `SE Asia Standard Time`
(runbook Stage 1.3), so tasks fire on Bangkok local time. `ingest_wazuh_alerts`
runs **continuously** (per-minute) so the queue stays live; `refresh_reporting`
runs **nightly**, after midnight, once the day's alerts are already ingested.
Register once (as the app service account):
```powershell
$py  = 'C:\SOCTicket\app\venv\Scripts\python.exe'
$app = 'C:\SOCTicket\app'
schtasks /create /tn "SOC-Ingest-Wazuh"      /sc minute /mo 1 /ru "NT_DOMAIN\svc_socticket" `
  /tr "cmd /c cd /d $app && `"$py`" manage.py ingest_wazuh_alerts >> C:\SOCTicket\logs\ingest.log 2>&1"
schtasks /create /tn "SOC-Refresh-Reporting" /sc daily /st 00:20 /ru "NT_DOMAIN\svc_socticket" `
  /tr "cmd /c cd /d $app && `"$py`" manage.py refresh_reporting   >> C:\SOCTicket\logs\reporting.log 2>&1"
```
(The as-built note above records `SOC-Ingest-Wazuh` running as SYSTEM with the
`IgnoreNew` multiple-instances policy so a slow run never overlaps its successor.)
**Start this at go-live, not before** — in UAT the snapshot only captures seed
data, and its history is unrecoverable, so day one of real operations is the day
to begin. (Fits the runbook's handoff to handbook Phase 5, alongside the Wazuh
ingestion and 90-day cleanup tasks.)

### D. (Only if wiring Grafana / external BI) create the read role
Run [reporting-ro-setup.sql](reporting-ro-setup.sql) once as a superuser
(`postgres`) — the app `ticket` role cannot create roles. Then point Grafana at
**`reporting_ro`** — never `ticket`, `soc`, or `postgres`. It can read the `mart`
schema only. Not needed for the in-app dashboard, which reads via the ORM.

### E. Confirm Indexer TLS for detection capture
In `.env`, set `OPENSEARCH_VERIFY_SSL=True` and point `OPENSEARCH_CA_BUNDLE` at
the trusted Wazuh CA (a PEM file on the VM). If the CA can't be verified, the
detection step fails **non-fatally** — it logs an error and the ticket/snapshot
steps still complete. Wazuh ingestion stays off until go-live (handbook Phase 5),
so this only matters once the Indexer is wired.

### F. Backups — already covered by the Windows backup handbook
The `mart` objects live in `ticketdata`, which the Windows backup
(`scripts/backup/windows/New-SocBackup.ps1`) already dumps. Materialized-view
*contents* are in the dump but derived — a restore plus one `refresh_reporting`
rebuilds them. The non-recomputable reporting data — the four `snapshot_*_daily`
tables, `hist_alert_daily`, `agg_detection_daily` and any `dim_severity_map`
edits — are ordinary tables, captured by the backup. At the next restore drill,
confirm with `pg_restore -l <archive> | findstr mart`. See
[backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md).
(Roles/grants aren't in a `pg_dump` archive, so an *archive* restore recreates
`reporting_ro` from [reporting-ro-setup.sql](reporting-ro-setup.sql); a
*streaming-standby* failover replicates roles and needs nothing.)

### G. 2026-10-01 additions — roll out in this order
Elevated PowerShell on the PROD VM. Pick a time away from the 00:20 refresh and
the 04:00 purge. Read each step's output before the next.
```powershell
Set-Location C:\SOCTicket\app
$py = 'C:\SOCTicket\app\venv\Scripts\python.exe'
```
1. **Deadline check (read-only).** First loss = oldest alert + retention days.
   ```powershell
   & $py manage.py shell -c "from datetime import timedelta; from django.db.models import Min; from apps.wazuh_ingest.models import WazuhAlert; from apps.wazuh_ingest.management.commands.purge_wazuh_alerts import DEFAULT_RETENTION_DAYS as d; m = WazuhAlert.objects.aggregate(m=Min('timestamp'))['m']; print('oldest alert:', m, '| retention days:', d, '| first loss on:', m and (m + timedelta(days=d)).date())"
   & $py manage.py purge_wazuh_alerts --dry-run
   ```
   If the dry run would delete anything, the purge has started: finish steps 2–4
   before the next 04:00.
2. **Deploy the release** — [deploy-and-release.windows.md](deploy-and-release.windows.md)
   §3 (backup → tag → pip → `migrate` → collectstatic → restart → verify). Its
   `migrate` applies `reporting 0006` (four new mart tables, additive). Confirm:
   `& $py manage.py showmigrations reporting` shows `[X] 0006_history_and_extra_snapshots`.
3. **Alert recipients.** Add `REPORTING_ALERT_EMAILS=<addr>[,<addr>]` to `.env`
   (plain ASCII, no BOM). The commands read `.env` on every run; restart
   `SOCTicketWaitress` only to keep the web app's settings in step. Prove mail
   reaches the inbox:
   ```powershell
   & $py manage.py shell -c "from django.conf import settings; from django.core.mail import send_mail; print(settings.REPORTING_ALERT_EMAILS, settings.EMAIL_BACKEND); send_mail('[SOC reporting] test', 'Test from PROD.', None, settings.REPORTING_ALERT_EMAILS)"
   ```
   If `EMAIL_BACKEND` is the console backend, nothing is actually sent — alerts
   would only be logged.
4. **One manual run, then check it.**
   ```powershell
   & $py manage.py refresh_reporting
   & $py manage.py shell -c "from django.utils import timezone; from apps.reporting.models import AggAlertDaily, HistAlertDaily, SnapshotKpiDaily; print('view', AggAlertDaily.objects.count(), 'history', HistAlertDaily.objects.count()); print(SnapshotKpiDaily.objects.filter(snapshot_date=timezone.localdate()).values().first())"
   ```
   Want `'errors': []`, `history == view`, and `open_tickets` equal to the SOC
   dashboard's Total Active Cases with no filters.
5. **The 07:00 watchdog task — same run-as account as `SOC-Refresh-Reporting`.**
   Don't use `schtasks /ru` without `/rp` (handbook §1: it creates a "run only
   when logged on" task that never runs for a service account).
   ```powershell
   $ref = Get-ScheduledTask -TaskName 'SOC-Refresh-Reporting'
   $ref.Principal | Format-List UserId, LogonType, RunLevel
   $action   = New-ScheduledTaskAction -Execute 'cmd.exe' -WorkingDirectory 'C:\SOCTicket\app' `
                 -Argument '/c ""C:\SOCTicket\app\venv\Scripts\python.exe" manage.py check_reporting_freshness >> C:\SOCTicket\logs\reporting.log 2>&1"'
   $trigger  = New-ScheduledTaskTrigger -Daily -At 07:00
   $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
   # LogonType ServiceAccount (e.g. SYSTEM):
   Register-ScheduledTask -TaskName 'SOC-Check-Reporting' -Action $action -Trigger $trigger -Settings $settings -Principal $ref.Principal
   # LogonType Password (a domain service account) — instead of the line above:
   #   $cred = Get-Credential $ref.Principal.UserId
   #   Register-ScheduledTask -TaskName 'SOC-Check-Reporting' -Action $action -Trigger $trigger -Settings $settings -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel $ref.Principal.RunLevel
   Start-ScheduledTask -TaskName 'SOC-Check-Reporting'
   Start-Sleep -Seconds 30
   Get-ScheduledTaskInfo -TaskName 'SOC-Check-Reporting' | Format-List LastRunTime, LastTaskResult
   Get-Content C:\SOCTicket\logs\reporting.log -Tail 5
   ```
   Want `LastTaskResult 0` and "reporting mart is fresh". `1` means it found a
   problem and emailed it — read the log tail. `267011` means it never started
   (account rights or logon type, handbook §1).

To undo: `migrate reporting 0005` (drops the new tables **and their data** — take a
backup first) and `Unregister-ScheduledTask -TaskName SOC-Check-Reporting`.

---

## 4. Pre-launch judgement call — detection history only

Detection capture reads the live Indexer (real data, **~3-month retention**) even
in UAT. If production launch is expected **within ~3 months**, do nothing now —
starting capture at launch still gets the trailing window. If launch is **further
out and pre-launch detection-volume history is wanted**, start
`refresh_reporting --skip-snapshot` on a schedule now to preserve it (accepting it
lives on the un-backed-up UAT box until prod). The snapshot and ticket aggregates
have no such urgency — they recompute from the operational tables any time.

---

## 5. Verifying it works

```sql
-- fact views mirror their sources 1:1
SELECT (SELECT count(*) FROM incidents_ticket)          AS tickets,
       (SELECT count(*) FROM mart.fact_ticket)          AS fact_ticket;
SELECT (SELECT count(*) FROM wazuh_ingest_wazuhalert)   AS alerts,
       (SELECT count(*) FROM mart.fact_alert)           AS fact_alert;

-- aggregates cross-check against the fact views
SELECT sum(closed_count) FROM mart.agg_ticket_daily;    -- == closed tickets with a local close date
SELECT sum(ingested_count) FROM mart.agg_alert_daily;   -- == fact_alert rows with a local alert date

-- snapshot present for today
SELECT snapshot_date, sum(open_count) FROM mart.snapshot_queue_daily GROUP BY 1;

-- tonight's KPI row agrees with the live queue
SELECT * FROM mart.snapshot_kpi_daily ORDER BY snapshot_date DESC LIMIT 1;
SELECT count(*) FROM incidents_ticket
 WHERE status NOT IN ('APPROVED', 'CLOSED_EVENT', 'CANCELLED');   -- == open_tickets

-- alert history covers every day the view still has (more, once the purge runs)
SELECT (SELECT count(*) FROM mart.agg_alert_daily)  AS view_rows,
       (SELECT count(*) FROM mart.hist_alert_daily) AS history_rows;
```

---

## 6. Rollback

```
python manage.py migrate reporting zero
```
Drops the entire `mart` schema (`DROP SCHEMA … CASCADE` in the reverse of
migration 0001). No operational table is affected. Re-apply with
`migrate reporting`.

To undo only the 2026-10-01 additions: `migrate reporting 0005`. That **drops the
history and snapshot tables with their data**, which can't be rebuilt — take a
backup first. Also delete the `SOC-Check-Reporting` task.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `REFRESH … CONCURRENTLY cannot run inside a transaction` | You wrapped the command in an atomic block; use `--no-concurrently`. Normal command runs are autocommit and unaffected. |
| Detection step error, other steps OK | Indexer unreachable or TLS/CA mismatch (see §3E). Non-fatal — fix connectivity; `--skip-detection` to silence meanwhile. |
| Alert funnel looks empty/stale | `ingest_wazuh_alerts` hasn't run, or ran after refresh. Fix the schedule order (§2). |
| A metric reads `Unknown` band unexpectedly | The alert's `rule_level` isn't covered by any `dim_severity_map` row for its source — add/adjust a range (§3B). |
| Email "refresh_reporting failed" | Read the listed errors; the other steps still ran. Fix the cause and re-run `refresh_reporting` the same day — a same-day re-run is safe. A night not re-run before midnight is lost for the snapshots. |
| Email "nightly reporting data is missing" | The 00:20 task didn't run or didn't finish: check `SOC-Refresh-Reporting`'s *Last Run Result* and `C:\SOCTicket\logs\reporting.log`. Run `refresh_reporting` by hand to capture today. |
| No email arrives at all | `REPORTING_ALERT_EMAILS` is empty (look for "Reporting alert not emailed" in the log) or SMTP is failing (the run still exits non-zero). |
| `hist_alert_daily` has fewer days than expected | It was introduced 2026-10-01; days purged before its first run are gone. Days already in it never shrink. |
| Daily counts land on the wrong day | All bucketing is Asia/Bangkok; confirm the scheduled run and any manual SQL use local dates. |

---

## 8. Related
- [../architecture/reporting-layer-design.md](../architecture/reporting-layer-design.md) — design spec.
- [../architecture/reporting-layer-build.md](../architecture/reporting-layer-build.md) — as-built record.
- [reporting-ro-setup.sql](reporting-ro-setup.sql) — the read-role DBA snippet.
- [production-deployment.md](../archive/production-deployment.md) — the overall prod deploy runbook.
- [grafana-wazuh-wall.md](grafana-wazuh-wall.md) — the existing Grafana board (reads the Indexer directly; Phase 4 adds a mart-backed datasource).
