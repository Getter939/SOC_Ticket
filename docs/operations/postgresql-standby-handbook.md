# PostgreSQL standby and recovery handbook

> **Applies to:** SOC Ticket's Docker Compose PostgreSQL 16 production stack  
> **Last updated:** 2026-07-27

Use the spare VM as a **warm standby**: it continually receives PostgreSQL
changes from production. If the production database fails, you promote it and
switch the Django app to use it.

Replication does **not** replace encrypted backups. It also copies accidental
deletes, bad migrations, and corruption; an independent backup is required for
point-in-time recovery.

## Design and limits

~~~mermaid
flowchart LR
  U["Users"] --> A["Production VM: nginx + Django"]
  A --> P["Production VM: PostgreSQL primary"]
  P -->|"private streaming replication"| S["Spare VM: PostgreSQL standby"]
  P -->|"encrypted backups"| B["Off-VM / offsite storage"]
  A -->|"separate media sync"| M["Spare VM: media copy"]
~~~

This protects against a database/VM failure. It does not protect against both
VMs failing, a shared host/rack failure, or an application/media failure. If
the production VM itself dies, the spare VM must also be ready to run the
application; a working database alone cannot serve users.

Use a manual promotion procedure. Do not enable automatic promotion without
proper fencing, because two writable databases can cause data loss.

Use these values consistently in the examples:

| Value | Example |
| --- | --- |
| PRIMARY_DB_IP | 10.20.30.11 |
| STANDBY_DB_IP | 10.20.30.12 |
| REPLICATION_USER | replicator |
| SLOT_NAME | soc_ticket_standby |
| APP_DIR | /srv/soc-ticket |

Before starting, write down your RPO (maximum acceptable data loss) and RTO
(maximum acceptable downtime). A sensible first target is RPO five minutes and
RTO one hour.

## Pre-flight checklist

- [ ] The VMs have stable private addresses and are on different physical
  hosts/failure domains if possible.
- [ ] Docker Engine and Docker Compose are installed on both VMs.
- [ ] Both use PostgreSQL 16. Physical replication requires the same major
  version.
- [ ] The standby has 2–3 times the database's used storage, including room for
  a base backup and retained write-ahead logs.
- [ ] The standby can reach PRIMARY_DB_IP on port 5432, and no other hosts can.
- [ ] You have copied a protected copy of the repository and production .env to
  the standby. Never commit .env.
- [ ] An encrypted backup exists and has passed the repository restore test.
- [ ] You have a maintenance window; enabling the settings restarts PostgreSQL.

## Configure the production database

In docker-compose.prod.yml, add these settings to the db service, alongside
the existing volumes entry:

~~~yaml
    ports:
      - "10.20.30.11:5432:5432"
    command:
      - postgres
      - -c
      - wal_level=replica
      - -c
      - max_wal_senders=10
      - -c
      - max_replication_slots=10
      - -c
      - wal_keep_size=2048MB
~~~

Replace the address with PRIMARY_DB_IP. This binds the port only to the private
interface; do not expose it publicly. Also allow exactly one firewall rule:

~~~bash
sudo ufw allow from STANDBY_DB_IP to any port 5432 proto tcp
sudo ufw status numbered
~~~

Apply the Compose change during the maintenance window:

~~~bash
cd APP_DIR
docker compose -f docker-compose.prod.yml up -d db
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs --tail=100 db web
~~~

Continue only after db is healthy and web has reconnected.

Create the dedicated replication role on the primary. The configured DB_USER is
the initial PostgreSQL superuser in this deployment.

~~~bash
cd APP_DIR
docker compose -f docker-compose.prod.yml exec db psql -U "$DB_USER" -d "$DB_NAME"
~~~

At the SQL prompt, replace the placeholders and use a long random password:

~~~sql
CREATE ROLE REPLICATION_USER WITH REPLICATION LOGIN PASSWORD 'replace-with-a-long-random-password';
SELECT rolname, rolreplication FROM pg_roles WHERE rolname = 'REPLICATION_USER';
\q
~~~

Store that password only on the standby in /root/.pg-replication-pass, permission
0600. Do not put it in Git, .env, a Compose file, or shell history.

Allow the login only from the standby IP. Replace the placeholders first:

~~~bash
docker compose -f docker-compose.prod.yml exec db sh -c \
  "printf '%s\n' 'host replication REPLICATION_USER STANDBY_DB_IP/32 scram-sha-256' >> \"\$PGDATA/pg_hba.conf\""
docker compose -f docker-compose.prod.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT pg_reload_conf();"
~~~

Verify the entry in the container once; do not append duplicate entries. Use
PostgreSQL TLS and a hostssl rule as a follow-up hardening task if your private
network is not already encrypted.

## Build the standby VM

Do **not** start the normal production db service on the spare VM: it creates
an independent writable database.

Create the standby data directory:

~~~bash
sudo install -d -o 999 -g 999 -m 0700 /srv/soc-ticket-standby/postgres
~~~

Create /srv/soc-ticket-standby/docker-compose.standby.yml:

~~~yaml
services:
  db:
    image: postgres:16
    restart: always
    command:
      - postgres
      - -c
      - hot_standby=on
      - -c
      - max_standby_streaming_delay=30s
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - /srv/soc-ticket-standby/postgres:/var/lib/postgresql/data
~~~

Make the password file, then initialize the replica:

~~~bash
sudo install -m 0600 /dev/null /root/.pg-replication-pass
sudoedit /root/.pg-replication-pass
sudo -i
export PGPASSWORD="$(< /root/.pg-replication-pass)"
docker run --rm \
  -e PGPASSWORD \
  -v /srv/soc-ticket-standby/postgres:/var/lib/postgresql/data \
  postgres:16 \
  pg_basebackup \
    --host=PRIMARY_DB_IP --port=5432 --username=REPLICATION_USER \
    --pgdata=/var/lib/postgresql/data --format=plain --wal-method=stream \
    --slot=SLOT_NAME --create-slot --write-recovery-conf --progress
unset PGPASSWORD
exit
~~~

The write-recovery option makes the copied data a read-only standby. The slot
retains WAL on the primary, so its disk usage must be monitored.

Start it and verify its state:

~~~bash
cd /srv/soc-ticket-standby
docker compose -f docker-compose.standby.yml up -d
docker compose -f docker-compose.standby.yml logs --tail=100 db
docker compose -f docker-compose.standby.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT pg_is_in_recovery();"
~~~

The last query must return t. If it returns f, stop and investigate.

On the primary, confirm the standby is streaming and the slot is active:

~~~bash
docker compose -f APP_DIR/docker-compose.prod.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT application_name, client_addr, state, sync_state, write_lag, flush_lag, replay_lag FROM pg_stat_replication;"
docker compose -f APP_DIR/docker-compose.prod.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT slot_name, active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal FROM pg_replication_slots;"
~~~

You need a row with state streaming, the standby address, and an active slot.

## Monitor and back up

Every day, confirm replication is running:

~~~bash
# Primary
docker compose -f APP_DIR/docker-compose.prod.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT client_addr, state, COALESCE(replay_lag::text, 'unknown') AS replay_lag FROM pg_stat_replication;"

# Standby
docker compose -f /srv/soc-ticket-standby/docker-compose.standby.yml exec db \
  psql -U "$DB_USER" -d "$DB_NAME" \
  -c "SELECT now() - pg_last_xact_replay_timestamp() AS replay_delay, pg_is_in_recovery();"
~~~

Monitor free disk space on both VMs. When a standby disconnects, the slot
retains database WAL on primary. A full primary disk stops production. Do not
drop a slot merely to regain space unless you accept rebuilding the standby.

The application media volume is not in PostgreSQL. Copy it separately at least
hourly to /srv/soc-ticket-standby/media, and also keep versioned encrypted
backups. Example from the primary:

~~~bash
WEB_ID="$(docker compose -f APP_DIR/docker-compose.prod.yml ps -q web)"
mkdir -p /srv/soc-ticket-media-export
docker cp "$WEB_ID:/app/media/." /srv/soc-ticket-media-export/
rsync -a --delete-delay /srv/soc-ticket-media-export/ backup@STANDBY_DB_IP:/srv/soc-ticket-standby/media/
~~~

The delete-delay option mirrors source deletions, therefore it is not a backup.
Test that a copied attachment opens successfully.

## Planned failover drill

Practise quarterly before relying on this system.

1. Announce maintenance and stop writes:

   ~~~bash
   cd APP_DIR
   docker compose -f docker-compose.prod.yml stop web
   ~~~

2. Confirm state streaming and replay delay within the RPO.
3. Stop the primary database:

   ~~~bash
   docker compose -f docker-compose.prod.yml stop db
   ~~~

4. Promote the standby:

   ~~~bash
   cd /srv/soc-ticket-standby
   docker compose -f docker-compose.standby.yml exec db pg_ctl promote -D /var/lib/postgresql/data
   docker compose -f docker-compose.standby.yml exec db psql -U "$DB_USER" -d "$DB_NAME" \
     -c "SELECT pg_is_in_recovery();"
   ~~~

   The final query must return f.

5. Change the application host from db to STANDBY_DB_IP and restart web. If the
   production VM is unavailable, run the complete app stack on the standby VM
   using the protected .env, certificates, OpenSearch CA, and media copy.

6. Verify a login, a new ticket, an update, and an attachment upload. Record
   actual RPO/RTO. Keep the former primary stopped, then rebuild it as a new
   standby.

## Emergency failover and rebuild

1. Stop web if it remains reachable.
2. **Fence the old primary** by powering it off or blocking its network access.
   Never promote while it might accept writes.
3. Check standby logs and last replay time.
4. Promote it with the preceding commands and confirm it is not in recovery.
5. Switch/redeploy the app, test users, tickets, and media, then communicate
   the recovery point.
6. Immediately take an encrypted backup from the promoted database.

The promoted standby is now the source of truth. Repair the old VM, then create
a fresh replica from the promoted database using a new slot name. Never copy
the old primary data back over the promoted database.

## Related repository material

- [Production deployment](production-deployment.md)
- [Backup script](../../scripts/backup/backup.sh)
- [Restore verification](../../scripts/backup/restore_verify.sh)

