# Deployment Guide — SOC Ticket (Production)

Production stack: **nginx → gunicorn → Django**, with **PostgreSQL**, run via
`docker-compose.prod.yml`. The dev-only `docker-compose.yml` (runserver +
live-reload bind mount) is unaffected — use `docker-compose.prod.yml` for the
actual deployment.

Commands below assume a Linux host with Docker and the Docker Compose plugin
installed, run from the project root (where `.env` and the compose files
live).

## 1. First-time setup

1. Make sure `.env` exists and is filled in (copy from `.env.example` if
   starting fresh on a new host — **never commit `.env`**). Key values:
   - `DEBUG=False`
   - `SECRET-KEY` — a real, unique secret
   - `DB_NAME`, `DB_USER`, `DB_PASSWORD` — used by both `db` and `web`
   - `ALLOWED_HOSTS` — comma-separated, no spaces; must include the LAN
     IP/hostname other users will browse to (see step 4 to find it)

2. Build and start the stack:

   ```bash
   docker compose -f docker-compose.prod.yml up -d --build
   ```

   On startup, the `web` container automatically runs `migrate` and
   `collectstatic` before starting gunicorn — no separate step needed for a
   normal deploy.

## 2. Run migrations manually

Migrations already run automatically on every `web` container start. To run
them on demand (e.g. without restarting the container):

```bash
docker compose -f docker-compose.prod.yml exec web python manage.py migrate
```

## 3. Create a superuser

```bash
docker compose -f docker-compose.prod.yml exec web python manage.py createsuperuser
```

## 4. Find the workstation's internal IP

```bash
ip -4 addr show | grep inet
# or
hostname -I
```

Add the result to `ALLOWED_HOSTS` in `.env` (comma-separated, no spaces),
then restart the stack (step 6) for the change to take effect.

## 5. Open port 80 on UFW

```bash
sudo ufw allow 80/tcp
sudo ufw status
```

Other users on the LAN can then reach the app at `http://<that-ip>/`.

## 6. Stop / restart the stack

```bash
# Stop (containers removed; named volumes — db data, static files — preserved)
docker compose -f docker-compose.prod.yml down

# Start again
docker compose -f docker-compose.prod.yml up -d

# Restart a single service (e.g. after an .env change)
docker compose -f docker-compose.prod.yml restart web

# Rebuild and restart after a code change
docker compose -f docker-compose.prod.yml up -d --build
```

## Logs

```bash
docker compose -f docker-compose.prod.yml logs -f web
docker compose -f docker-compose.prod.yml logs -f nginx
docker compose -f docker-compose.prod.yml logs -f db
```
