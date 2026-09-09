# IOC Database

The **IOC Database** (sidebar, Forensic/superuser only) is the resting point for
IOC data from **two sources**:

1. **Ticket IOCs** — entered by T1/T2 analysts on tickets (auto-collected).
2. **Analyst uploads** — evidence the Forensic Analyst found themselves,
   externally, and uploaded here. This is **not** the MISP/TI-platform set.

The FA reviews each indicator against **MISP** and sets a manual two-state
**review status: `Checked` / `Not Checked`** (a "reviewed against MISP" flag;
absent = Not Checked). Rows are unified by *(category + value)*, so a ticket IOC
and an uploaded IOC of the same value are one row with one shared status and a
**Source** of Ticket, FA, or both.

Access is restricted to **Forensic Analysts and superusers**. Ticket permissions
and the general IOC Search are unchanged.

## The page

- **Filter toolbar** (GET form, like Active Tickets): search (value / ID / note),
  **Status** (All / Not Checked / Checked), **Source** (All / Ticket / FA),
  **Category** (All + the six). Summary counts + a clear-all link.
- **Sortable table** — click any header to sort the current page (Category,
  Indicator, Status, Source, On tickets, Last activity). Not-Checked sorts first
  by default (the worklist). Each row links its ticket count to IOC Search.
- **Status** — a per-row **Checked** checkbox; ticking/unticking saves immediately
  (`IOCReviewStatus`, shared across sources).
- **Remove** — an FA-uploaded row can be soft-removed (mistaken upload); it leaves
  the view but its ticket-sourced twin (if any) stays. Ticket IOCs can't be removed.
- **Upload + import history** — append an analyst-findings file; retire/mark are gone.

## Upload format (analyst findings)

Download the CSV template from the page. Five columns, any order:

| Column | Meaning |
|--------|---------|
| `ID` | Analyst-assigned identifier. **Unique** — the dedup key. |
| `Category` | `Hash`, `IP`, `Domain`, `URL`, or `File Path`. |
| `File name` | Optional context. |
| `IOC detail` | The indicator value, validated per `Category`. |
| `Note` | Optional free text. |

UTF-8 CSV (BOM allowed) or the first XLSX worksheet. Limits: 5 MB, 25 MB expanded
XLSX, 10,000 rows; formulas/error cells rejected. EN + Thai headers/categories.
Row errors are reported together. **Re-importing an existing `ID` is skipped**
(original kept). Correct a record by removing it and re-adding under a new `ID`.

## Structured ticket IOCs (unchanged)

Ticket create / Project Incident / Tier 2 review / edit carry an **Indicators of
Compromise** section with six multi-valued fields (File Name, Hash, Domain, IP,
URL, File Path), each with a "＋ add" button. Stored as `TicketIOC`; feed ticket
search, change history, the incident report (Hash/Domain/URL/IP rows; File
Name/Path in Process/File Path), and the IOC Database.

## Deployment and validation

Install requirements (`openpyxl`), apply migrations through the latest incidents
migration. No new static files (inline nonce'd scripts). Include
`media/ti_platform/` in media backups. Load sample analyst-upload data with
`python manage.py seed_ti_sample` (imports `docs/ti-platform-sample.csv`). Run
`python manage.py test apps.incidents` — the suite covers import/dedup,
per-category validation, the two-source unified view, review-status toggle
(shared across sources), soft-remove, status/source/category filters,
FA/superuser-only access, ticket IOC persistence and report data.
