# Reporting Layer — Operations & Production Readiness

> **Audience:** operators, deployers · **Status:** Current — Phases 1–3 built, scheduling deferred to cutover · **Last updated:** 2026-07-22

How to run, deploy, and operate the reporting layer (Layer ③, the `mart` schema).
For the *design* see [../architecture/reporting-layer-design.md](../architecture/reporting-layer-design.md);
for the *as-built* record see [../architecture/reporting-layer-build.md](../architecture/reporting-layer-build.md).

---

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

Runs three isolated steps (one failing never aborts the others; it prints a
result dict and logs errors):

1. **REFRESH** the materialized views `mart.agg_ticket_daily` and
   `mart.agg_alert_daily`.
2. **Snapshot** — write today's `mart.snapshot_queue_daily` rows (the open queue,
   bucketed by age and OLA pressure, *as of the run*). Idempotent: a same-day
   re-run replaces that day's rows.
3. **Detection** — capture per-(day × rule_level) alert volume from the Wazuh
   Indexer into `mart.agg_detection_daily` (upsert).

| Flag | Effect |
|---|---|
| *(none)* | all three steps, using `REFRESH … CONCURRENTLY` |
| `--no-concurrently` | plain (locking) REFRESH — for running inside an outer transaction |
| `--skip-snapshot` | skip step 2 |
| `--skip-detection` | skip step 3 (e.g. when the Indexer is unreachable) |
| `--detection-days N` | days of Indexer history to (re)capture per run (default 2) |

Expected healthy output:
`{'mv_refreshed': ['mart.agg_ticket_daily', 'mart.agg_alert_daily'], 'snapshot_rows': N, 'detection_rows': N, 'errors': []}`

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
(runbook Stage 1.3), so tasks fire on Bangkok local time. Run
`ingest_wazuh_alerts` **first**, then `refresh_reporting`, at a consistent early
time. Register once (as the app service account):
```powershell
$py  = 'C:\SOCTicket\app\venv\Scripts\python.exe'
$app = 'C:\SOCTicket\app'
schtasks /create /tn "SOC-Ingest-Wazuh"      /sc daily /st 00:15 /ru "NT_DOMAIN\svc_socticket" `
  /tr "cmd /c cd /d $app && `"$py`" manage.py ingest_wazuh_alerts >> C:\SOCTicket\logs\ingest.log 2>&1"
schtasks /create /tn "SOC-Refresh-Reporting" /sc daily /st 00:20 /ru "NT_DOMAIN\svc_socticket" `
  /tr "cmd /c cd /d $app && `"$py`" manage.py refresh_reporting   >> C:\SOCTicket\logs\reporting.log 2>&1"
```
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
rebuilds them; the only non-recomputable reporting data is `snapshot_queue_daily`
and any `dim_severity_map` edits, both captured by the backup. See
[backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md).
(Roles/grants aren't in a `pg_dump` archive, so an *archive* restore recreates
`reporting_ro` from [reporting-ro-setup.sql](reporting-ro-setup.sql); a
*streaming-standby* failover replicates roles and needs nothing.)

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
```

---

## 6. Rollback

```
python manage.py migrate reporting zero
```
Drops the entire `mart` schema (`DROP SCHEMA … CASCADE` in the reverse of
migration 0001). No operational table is affected. Re-apply with
`migrate reporting`.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `REFRESH … CONCURRENTLY cannot run inside a transaction` | You wrapped the command in an atomic block; use `--no-concurrently`. Normal command runs are autocommit and unaffected. |
| Detection step error, other steps OK | Indexer unreachable or TLS/CA mismatch (see §3E). Non-fatal — fix connectivity; `--skip-detection` to silence meanwhile. |
| Alert funnel looks empty/stale | `ingest_wazuh_alerts` hasn't run, or ran after refresh. Fix the schedule order (§2). |
| A metric reads `Unknown` band unexpectedly | The alert's `rule_level` isn't covered by any `dim_severity_map` row for its source — add/adjust a range (§3B). |
| Daily counts land on the wrong day | All bucketing is Asia/Bangkok; confirm the scheduled run and any manual SQL use local dates. |

---

## 8. Related
- [../architecture/reporting-layer-design.md](../architecture/reporting-layer-design.md) — design spec.
- [../architecture/reporting-layer-build.md](../architecture/reporting-layer-build.md) — as-built record.
- [reporting-ro-setup.sql](reporting-ro-setup.sql) — the read-role DBA snippet.
- [production-deployment.md](production-deployment.md) — the overall prod deploy runbook.
- [grafana-wazuh-wall.md](grafana-wazuh-wall.md) — the existing Grafana board (reads the Indexer directly; Phase 4 adds a mart-backed datasource).
