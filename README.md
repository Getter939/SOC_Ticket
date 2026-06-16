# SOC Ticketing System

Django-based SOC (Security Operations Centre) ticketing and case-management app.

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
