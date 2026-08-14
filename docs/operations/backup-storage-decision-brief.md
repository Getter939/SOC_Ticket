# Backup Storage & Retention — Decision Brief

> **Audience:** CISO / Information Security, Data Governance, DPO, Compliance · **Status:** Draft for review · **Last updated:** 2026-07-27
> **From:** SOC Ticketing System team · **Decision needed before:** production go-live

*A one-page brief to bring to the governance/security conversation. English draft;
a Thai (`.th.md`) version can be produced on request.*

---

## Purpose

Decide **where** the SOC ticketing system's backup data is stored, and **for how
long**, before the system goes to production. The backup mechanism is already
built; what remains are location and policy decisions that sit with governance,
compliance, and infrastructure — not engineering alone.

## Current state

- SOC ticketing system (cases, audit logs, triage, user accounts, attachment
  **evidence**) on native **PostgreSQL / Windows Server**. Contains **personal
  data** and **security-incident records** with NCSA (สกมช.) reporting fields.
- Backups are **scripted and designed** (`New-SocBackup.ps1`): **GPG public-key**
  encryption (a compromised production host cannot decrypt its own backups),
  tiered retention (hourly 2d · daily 30d · weekly 84d · monthly 365d),
  integrity-checked, with a **restore drill** (`Test-SocRestore.ps1`).
- The deployment plan already includes an **off-host archive copy** (read-only
  pull to a separate VM) and a **streaming standby** for DR
  (`backup-and-standby-handbook.windows.md`).
- Currently **UAT / pre-launch** — none of this runs against real data yet.

## What still needs deciding

The *mechanism* is built and the off-host copy + standby are designed, so this is
**not** primarily an engineering gap. What is unsettled belongs to
governance / compliance / infrastructure:

- **Where** the off-host archive and the DR standby physically live — and,
  critically, **confirmation the spare VM is on a different physical host / SAN**.
  If it is not, it is a warm tier, not DR (the deployment runbook already flags this).
- **Data residency** and **retention periods**, against Thai law and internal policy.
- **Immutability** of at least one archive tier (object-lock / WORM) so ransomware
  or an insider cannot delete backups.

## Recommendation

- **Confirm** the off-host archive destination and the DR standby host are on
  **NT-owned infrastructure inside Thailand**, on **separate physical hardware /
  SAN** from production.
- Make at least one archive tier **immutable** (object-lock / write-once).
- Keep the **GPG private key off production** (prod holds only the public key) and
  ensure the private key is safely escrowed — *a backup you can't decrypt is not a
  backup*.
- Keep the **scheduled restore drills** running after go-live.

## Decisions needed (the ask)

| # | Decision | Suggested owner |
|---|---|---|
| 1 | Off-host archive destination + DR standby host (on **separate hardware/SAN**), and budget | IT Infrastructure / Data Centre & Cloud |
| 2 | Data-residency requirement — confirm **in-Thailand** for personal / incident data | DPO / Data Governance |
| 3 | Retention periods per data class — reconcile with the statutory floor and internal schedule | Compliance / Data Governance |
| 4 | Whether NT is designated **CII**, and the applicable NCSA code of practice for DR/backup | CISO / Compliance |
| 5 | Immutability approach + key-management standard | CISO / Infrastructure |
| 6 | Confirm the prod DB VM + backup repository sit on **redundant storage (RAID / SAN)**, and the single-disk-failure behaviour (availability — separate from, and not a substitute for, backups) | IT Infrastructure |

## Regulatory context to confirm (reference, not legal advice)

- **Computer Crime Act (B.E. 2550/2560):** computer traffic/log data retained
  **≥ 90 days** (extendable by official order). The 365-day tier already clears it.
- **PDPA (B.E. 2562/2019):** appropriate security measures for personal data
  (encryption ✓, access control) and **cross-border transfer limits → keep
  backups in Thailand**.
- **Cybersecurity Act (B.E. 2562/2019) / NCSA:** CII organisations must meet
  cybersecurity codes of practice, typically including DR/backup controls.
- Likely also **NBTC** telecom rules and an internal **ISO 27001** posture.

## Cost & timing

Low effort — the backup + standby tooling exists; this is a **location + policy
decision, not a build**. No cost to decide now while in UAT. On approval of the
destination, residency, and retention, engineering points the existing scripts at
the approved target and enables immutability before go-live.

---

*Detail: [backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md) · [data-infrastructure.md](../architecture/data-infrastructure.md).*
