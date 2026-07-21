# Production Deployment

> **Audience:** whoever deploys and operates the app · **Status:** Current · **Last updated:** 2026-07-21
> **For local dev setup instead, see:** [../../README.md](../../README.md)

Production stack: **nginx → gunicorn → Django**, with **PostgreSQL**, run via
`docker-compose.prod.yml`. The dev-only `docker-compose.yml` (runserver +
live-reload bind mount) is unaffected — use `docker-compose.prod.yml` for the
actual deployment.

Commands below assume a Linux host with Docker and the Docker Compose plugin
installed, run from the project root (where `.env` and the compose files
live).

---

## Quick start — end to end

1. [First-time setup](#1-first-time-setup) — fill in `.env`, then
   `docker compose -f docker-compose.prod.yml up -d --build`
2. [Create a superuser](#3-create-a-superuser) — your own admin login
3. [Open port 80 on UFW](#5-open-port-80-on-ufw) so the LAN can reach the app
4. [Add user accounts for your team](#7-add-user-accounts-for-your-team) —
   log into `/admin/` and create a User + profile (role/tier) for each
   teammate
5. Send each teammate `http://<server-ip>/login/` — they log in with the
   username/password from step 4 and work tickets per their role

## Security prerequisites

Before starting the production stack, configure these values in `.env`:

- `TLS_CERT_PATH` and `TLS_KEY_PATH`: absolute host paths to the PEM full-chain
  certificate and private key. The production stack refuses to start without
  them so it cannot accidentally serve authenticated traffic over HTTP.
- `OPENSEARCH_CA_HOST_PATH`: the host path to the trusted CA PEM for a
  private/self-signed OpenSearch cluster. The compose file mounts it at the
  `OPENSEARCH_CA_BUNDLE` container path; certificate verification stays enabled.
- `BACKUP_ENCRYPTION=openssl` with a password file, or `BACKUP_ENCRYPTION=gpg`
  with a recipient. Unencrypted backups require an explicit local-test opt-in.

Open both TCP ports 80 and 443 in the host firewall. Port 80 only redirects to
HTTPS; users should access the service at `https://<server-name>/login/`.

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

## 5. Open ports 80 and 443 on UFW

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
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

## 7. Add user accounts for your team

There's no public sign-up page — every account is created by an admin
through the Django admin site (`/admin/`), logged in with the superuser
from step 3.

1. Go to `http://<server-ip>/admin/` and log in.
2. **Users → Add user** → fill in username, email, first/last name, and a
   temporary password.
3. On the same page, fill in the **User profile** section:
   - **Department** / **Phone** — free text
   - **Role** — determines what the user can see/do (see table below)
   - **Tier** — `T1`/`T2`, SOC Staff only. **Tier gates permissions**, it is
     not just a seniority label: only Tier 1 opens tickets and drives the
     Tier-1 side of the lifecycle; Tier 2 handles escalations and verification
     and can never create tickets or assign admins.
4. Click **Save**. If `EMAIL_HOST_USER`/`EMAIL_HOST_PASSWORD` are set in
   `.env`, the user is automatically emailed their username and password.

### Roles

| Role | What they can do |
|---|---|
| **SOC Staff — Tier 1** | Opens tickets (Wazuh alert, manual triage, or direct), sets classification, picks the handling route, tracks the Direct-to-Owner lane |
| **SOC Staff — Tier 2** | Works escalations and both verification queues (`CONTAINMENT_REPORTED`, `PENDING_T2_REVIEW`); closes non-emergency tickets |
| **SOC Manager** | Runs the pre-containment review (`PENDING_MGR_TRIAGE`) — the only role that may set the Emergency flag — forwards to the handling lane, spawns Response Requests, and approves emergency tickets (`PENDING_MANAGER → APPROVED`) |
| **System Admin** | Only sees tickets where they're the *assigned admin*; submits containment reports |
| **System Owner** | Notified when a ticket opens/closes for a system they own; has a dedicated "My Tickets" view (`/incidents/my-tickets/`) for those tickets |
| **Forensic Analyst** | Response-team role; sees only tickets carrying a Forensics/RCA Response Request assigned to them, worked from the "Response Requests" queue |
| **Red Team Manager** | Response-team role; receives VA/Pentest and Infrastructure Security Response Requests |

### Resending credentials / password resets

In **Users**, select one or more accounts and use the admin actions:
- **"ส่ง Email แจ้ง Username ให้ผู้ใช้งานที่เลือก"** — re-sends the username
  and login link by email
- **"รีเซ็ตรหัสผ่านและส่งเมลแจ้ง User"** — generates a new random password
  and emails it

## Logs

```bash
docker compose -f docker-compose.prod.yml logs -f web
docker compose -f docker-compose.prod.yml logs -f nginx
docker compose -f docker-compose.prod.yml logs -f db
```

---

## Related documents

- [../../README.md](../../README.md) — local development setup
- [grafana-wazuh-wall.md](grafana-wazuh-wall.md) — the separate Grafana wall-board
- [../handover/engineering-handover.md](../handover/engineering-handover.md) §6–§8 — deployment context, known issues, security posture
