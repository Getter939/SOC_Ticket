# IOC Database

> **Audience:** Forensic Analyst / developers · **Status:** Current · **Last updated:** 2026-09-11 (v1.5.0)
> Feature shipped in **v1.3.0**; the Forensic Analyst reads every ticket (read-only) since **v1.3.1**.

The **IOC Database** (sidebar, Forensic Analyst / superuser only) collects IOC data
from **two sources**:

1. **Ticket IOCs** — entered by T1/T2 analysts on tickets (auto-collected).
2. **Manual IOCs** — indicators the Forensic Analyst found externally and typed in
   on this page. This is **not** the MISP/TI-platform set.

The FA reviews each indicator against **MISP** and annotates it. Rows are unified by
*(category + value)*, so a ticket-sourced IOC and a manually added one of the same
value are a single row whose **Source** reads Ticket, Manual, or both.

## Annotations: status and note

Each indicator carries an annotation stored per *(category, value)* — shared by both
sources, so it works on ticket-sourced rows too:

- **Status** — a two-state `Checked` / `Not Checked` flag ("reviewed against MISP").
  Absent = Not Checked. Ticking the checkbox saves immediately.
- **Note** — free text, shown in the **Note** column (next to Indicator) and edited
  through the pencil icon on any row.

## Adding IOCs manually

**เพิ่ม IOC เอง / Add IOC manually** toggles the entry section open (collapsed by
default). Each row is: **Category** → **IOC detail** → **File name** (appears only
when the category is Hash, and is optional) → **Note**. The **＋ Add row** button
appends another row, so one save can record several IOCs of different categories.

- The **ID is generated** (`MAN-0001`) — analysts never type it, and the prefix keeps
  it distinct from a ticket reference.
- Values are normalised per category (defanged input, case, IDNA, IPv6 all handled).
- **Duplicates are not added.** If the value already exists anywhere — on a ticket or
  as an active manual entry — it is reported back and skipped.
- If the value matches an entry that was **removed** earlier, that record is
  **restored** (keeping its original `MAN-` id) rather than duplicated.

## Editing and removing

Manual rows carry **Edit** (change category / IOC detail / file name — the annotation
follows the value) and **Remove**. Remove is a soft-delete: the row leaves the
database but is kept for audit, and a ticket-sourced twin of the same value stays.
Re-typing a removed value brings it back. Ticket IOCs cannot be edited or removed
here — they belong to their ticket.

Who did what is recorded on the records themselves (`added_by`, `removed_by` /
`removed_at`, and the annotation's `updated_by`); there is no separate history panel.

## Filtering and sorting

A GET filter toolbar (same pattern as Active Tickets): free-text search over value /
ID / note, plus **Status**, **Source** and **Category** dropdowns and a clear-all
link. Clicking any column header sorts the current page. Not-Checked rows sort first
by default — the worklist.

## Structured ticket IOCs (unchanged)

Ticket create / Project Incident / Tier 2 review / edit carry an **Indicators of
Compromise** section with six multi-valued fields (File Name, Hash, Domain, IP, URL,
File Path), each with a "＋ add" button. Stored as `TicketIOC`; they feed ticket
search, the change history, the incident report, and this database.

> **v1.5.0 — User and Command are kept out of the IOC Database.** The ticket IOC
> section also captures a **User** and a **คำสั่ง (Command)** indicator, and both
> are searchable on tickets, but they are **deliberately not** collected into the
> IOC Database (they are context, not shareable network/file indicators). A ticket
> can also record **multiple IP addresses** (v1.3.0) — a comma/semicolon/newline
> list, normalised and de-duplicated on save.

## Deployment

Apply migrations through the latest `incidents` migration. No new static files (all
JS is inline and nonce'd for the CSP). There is no CSV import, no file storage and no
seeder — test data is entered through the form. Run
`python manage.py test apps.incidents` to cover manual entry, duplicate/restore
rules, annotations on both sources, edit/remove, filters and access control.
