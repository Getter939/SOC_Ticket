# SOC Ticketing System

Django-based SOC (Security Operations Centre) ticketing and case-management app.

**New here?** Read [CONTEXT.md](CONTEXT.md) for the domain vocabulary, then
[docs/handover/engineering-handover.md](docs/handover/engineering-handover.md) for the full technical tour (state
machine, roles, OLA policy, deployment, known gotchas).

## Setup

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in the required values:

| Variable            | Description                                |
|---------------------|--------------------------------------------|
| `SECRET-KEY`        | Django secret key (generate a fresh one)   |
| `DEBUG`             | `True` for development, `False` for prod   |
| `DB_NAME`           | PostgreSQL database name                   |
| `DB_USER`           | PostgreSQL user                            |
| `DB_PASSWORD`       | PostgreSQL password                        |
| `DB_HOST`           | PostgreSQL host (e.g. `localhost`)         |
| `DB_PORT`           | PostgreSQL port (default `5432`)           |
| `EMAIL_HOST`        | SMTP server hostname                       |
| `EMAIL_HOST_USER`   | SMTP username / sender address             |
| `EMAIL_HOST_PASSWORD` | SMTP password                            |

### 4. Apply database migrations

```bash
python manage.py migrate
```

### 5. Create a superuser (first run only)

```bash
python manage.py createsuperuser
```

### 6. Run the development server

```bash
python manage.py runserver 0.0.0.0:8088
```

The app is then available at <http://127.0.0.1:8088/>.
Admin panel: <http://127.0.0.1:8088/admin/>

## Offline Wazuh testing

Testers whose IP address cannot reach the Wazuh/OpenSearch API can load the
bundled OpenSearch-shaped demo alerts:

```bash
python manage.py ingest_wazuh_alerts --fixture
python manage.py runserver
```

The command creates four pending alerts at rule levels 10, 12, 14, and 15.
They can be claimed and processed through **Wazuh Triage**, **Escalation
Queue**, and ticket creation exactly like API-ingested alerts.

The fixture is idempotent: running the command again skips existing alerts
using their OpenSearch IDs. Fixture mode makes no HTTP request, needs no
OpenSearch credentials, and does not advance the production ingest watermark.

To create another batch for repeat workflow testing, use `--fresh`. This keeps
production duplicate protection intact while assigning the demo alerts unique
test IDs and current timestamps:

```bash
python manage.py ingest_wazuh_alerts --fixture --fresh
python manage.py runserver
```

To test with an exported OpenSearch response instead:

```bash
python manage.py ingest_wazuh_alerts --fixture C:\path\to\opensearch-response.json
```

The JSON file may contain either a list of hit objects or a normal OpenSearch
response with alerts under `hits.hits`.

Automated Wazuh tests also require no API access because all HTTP requests are
mocked:

```bash
python manage.py test apps.wazuh_ingest
```

## Development — Seeding test data

To populate the database with synthetic ticket data for dashboard testing:

```bash
python manage.py seed_data
```

This creates 100 tickets spread over the last 30 days in a random weighted mix,
covering both `INCIDENT` and `EVENT` classifications and all severity levels.

> **Note:** `seed_data` predates the four newer states (`PENDING_MGR_TRIAGE`,
> `AWAITING_OWNER`, `OWNER_REMEDIATED`, `PENDING_T2_REVIEW`) and does not
> produce them. Use `seed_uat_states` below to get all 12 states.

**No seed user is created.** Every seeder discovers the actors by role
(`apps.incidents.management.seed_actors`) and attributes its tickets to the real
accounts holding each role — it never creates, modifies or deletes a user, and
never touches a password. Assign the roles in Django admin first; a seeder that
cannot find a required role stops and names it rather than inventing an account.

The roles a seeder looks for are SOC Staff (Tier 1 and Tier 2), SOC Manager,
System Admin, and — where relevant — System Owner, Forensic Analyst and Red Team
Manager. Optional ones degrade gracefully: with no System Owner assigned, the
owner-lane tickets still seed with an empty owner.

To regenerate everything at once and remove the legacy synthetic logins
(`uat_*`, `seed_*`, mockup names) that older versions created:

```bash
python manage.py seed_all --dry-run   # preview accounts + plan
python manage.py seed_all             # purge legacy + reseed all datasets
```

**Options**

| Flag          | Default | Description                                  |
|---------------|---------|----------------------------------------------|
| `--tickets N` | 100     | Number of tickets to generate                |
| `--days N`    | 30      | Time window (days) to spread tickets across  |
| `--flush`     | off     | Wipe existing seed data before seeding       |

**Reset and re-seed**

```bash
python manage.py seed_data --flush
```

**Wipe seed data only (no re-seed)**

```bash
python manage.py seed_data --flush --tickets 0
```

All seeded rows are tagged with the `seed_` username prefix, so seed data can
always be identified or removed cleanly without affecting real data.

### Other seed commands

| Command | What it builds |
|---------|----------------|
| `seed_uat_states` | One ticket parked in **each of the 12** lifecycle states — the fastest way to see every screen without walking the whole workflow. Deterministic, tagged with a `uat_` prefix so `--flush` removes exactly its own rows. `--per-state N` for more per state |
| `seed_response_demo` | Tickets with open and completed Response Requests, for the response-team queues and the approval gate |
| `seed_dashboard_mockup` | Demo/screenshot dataset for the main dashboard |
| `seed_ola_demo_buckets` | Dataset shaped to fill every OLA-pressure bucket |
| `seed_ceo_demo` | Executive-dashboard demo dataset |
