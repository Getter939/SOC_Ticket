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
python manage.py runserver
```

The app is then available at <http://127.0.0.1:8000/>.
Admin panel: <http://127.0.0.1:8000/admin/>
