# Data Infrastructure — Current State

> **Audience:** developers, architects, operators · **Status:** Current (UAT / pre-launch) · **Last updated:** 2026-07-22

The whole data picture: every store, the flows between them, and how backup fits.
The system is organised as **four layers** — volume decreases and value-per-row
increases as you move up: ① detection → ② operational → ③ reporting → ④ presentation.

---

## Diagram

```mermaid
flowchart TB
    subgraph DET["① DETECTION — raw telemetry"]
        WI["Wazuh Indexer · OpenSearch :9200<br/><i>all alerts · ~3-month retention · separate system</i>"]
    end

    APP["Django app<br/>(Waitress)"]

    subgraph PGS["PostgreSQL server"]
        subgraph TD["ticketdata — system of record"]
            OP["public schema · ② OPERATIONAL<br/>tickets · logs · triage · users<br/>wazuh_ingest_wazuhalert"]
            MART["mart schema · ③ REPORTING<br/>fact_ticket · fact_alert · agg_*<br/>snapshot_queue_daily · agg_detection_daily<br/>dim_severity_map"]
        end
        SD["socdata<br/><i>dead prototype — retire (Phase 5)</i>"]
    end

    MEDIA["Media store<br/>attachments / evidence"]
    BK["Encrypted backups<br/>pg_dump + media · tiered · restore-verified"]
    CSV["wazuh-pipeline CSVs<br/><i>one-time load</i>"]

    subgraph PRES["④ PRESENTATION"]
        DASH["In-app dashboard"]
        GRAF["Grafana wall"]
    end

    WI -->|"ingest_wazuh_alerts"| OP
    WI -->|"refresh_reporting<br/>(detection capture)"| MART
    OP -->|"refresh_reporting"| MART
    APP <-->|"read / write"| OP
    APP -->|"files"| MEDIA
    MART -->|"reads"| DASH
    OP -.->|"legacy direct reads"| DASH
    WI -->|"direct (current)"| GRAF
    MART -.->|"Phase 4 · reporting_ro"| GRAF
    TD ==>|"nightly pg_dump"| BK
    MEDIA ==>|"tar"| BK
    CSV -.->|"dead"| SD

    classDef det fill:#152a38,stroke:#4a9fd4,color:#dbe4ee
    classDef op fill:#16323a,stroke:#35d1bf,color:#dbe4ee
    classDef mart fill:#2a2340,stroke:#a487e0,color:#e4dcf2
    classDef dead fill:#3a2020,stroke:#e0645f,color:#f0d5d4
    classDef cons fill:#1c3324,stroke:#57b878,color:#d8ecdd
    classDef infra fill:#1c2430,stroke:#8090a3,color:#c3ccd8
    class WI det
    class OP op
    class MART mart
    class SD,CSV dead
    class DASH,GRAF cons
    class APP,MEDIA,BK infra
```

Solid = live flow · dashed = legacy / future / dead · thick = backup.

---

## Stores

| Store | Layer | Role | Notes |
|---|---|---|---|
| **Wazuh Indexer** (OpenSearch :9200) | ① | Raw alert telemetry | Separate system, ~3-month retention. Not in the app's backup. |
| **ticketdata · `public`** | ② | System of record | Cases, logs, triage, users, in-app alert triage. The crown jewels. |
| **ticketdata · `mart`** | ③ | Reporting | Pre-computed facts/aggregates + queue snapshot + detection capture + severity map. See [reporting-layer-design.md](reporting-layer-design.md). |
| **Media store** | ② | Attachment evidence | pcaps, screenshots, reports. Backed up with the DB. |
| **socdata** | — | **Dead** | Superseded May-2026 CSV→PG→Grafana prototype. Retire in Phase 5. |
| **postgres** | — | System | Default maintenance DB, empty. |

## Flows

- **`ingest_wazuh_alerts`** — pulls rule.level ≥ 10 alerts from the Indexer into
  `wazuh_ingest_wazuhalert` (the in-app triage slice — *not* a copy of all telemetry).
- **`refresh_reporting`** — refreshes the `mart` facts/aggregates from `public`,
  writes the daily queue snapshot, and captures per-day detection volume from the
  Indexer. Run it *after* the ingest.
- **Backup** — nightly encrypted `pg_dump` of `ticketdata` + a media tar; tiered
  retention; restore-verified. See [../operations/backup-and-restore.md](../operations/backup-and-restore.md).
- **Presentation** — the in-app dashboard reads `mart` (Phase 4 repoints Grafana
  from the Indexer onto `mart` via `reporting_ro`).

---

## How backup fits the layers

Backup priority follows the **derived-vs-snapshot** line drawn for the reporting
layer — protecting the operational store plus a few non-recomputable snapshots
protects the whole picture:

| Layer | Backup status |
|---|---|
| ① Detection (Indexer) | **Out of scope** — separate system, own retention |
| ② Operational (`public` + media) | **Fully backed up** — the irreplaceable core |
| ③ Reporting (`mart`) | **In the dump, but split:** derived views/matviews *recompute* (`refresh_reporting`); only `snapshot_queue_daily`, `dim_severity_map`, `agg_detection_daily` genuinely need it |
| ④ Presentation | **Nothing to back up** — stateless |

Because the Indexer expires (~3 months), the `agg_detection_daily` capture is
what turns ephemeral telemetry into permanent, backed-up history. Full mechanism,
restore procedure, and the "recreate roles on restore" gap:
[../operations/backup-and-restore.md](../operations/backup-and-restore.md).

---

## Environment

Currently **UAT / pre-launch**. The reporting layer and all flows above run
against the dev/UAT localhost **PostgreSQL 18.x** `ticketdata` (seed data, no
backups). **Production is Windows-native** — Windows Server + native
**PostgreSQL 18** + Waitress + IIS, with GPG-encrypted PowerShell backups and a
streaming standby (not Docker; see
[../operations/production-deployment.windows.md](../operations/production-deployment.windows.md)
and [../operations/backup-and-standby-handbook.windows.md](../operations/backup-and-standby-handbook.windows.md)).
Scheduling of `ingest_wazuh_alerts` and `refresh_reporting` (Windows Task
Scheduler), plus `reporting_ro`/Grafana, are cutover tasks — see
[../operations/reporting-layer-operations.md](../operations/reporting-layer-operations.md).
