"""Detect (and optionally fix) PostgreSQL id sequences that lag behind the data.

A Postgres ``AutoField`` id is filled from a *sequence* object that only advances
when something calls ``nextval()`` — i.e. a normal app INSERT. Loading rows with
their ids already set (a fixture ``loaddata``, a data-only / single-table
restore, a cross-environment copy) writes the rows but never bumps the sequence.
The counter stays parked below the real ``MAX(id)``, and the next app INSERT
collides: ``duplicate key value violates unique constraint "..._pkey"`` — a 500
that hits *writes* (closing a ticket, adding a note) while *reads* look fine.

This command compares every auto-id sequence against its table's ``MAX(id)`` and
reports any that would collide on the next insert. ``--fix`` fast-forwards the
drifted ones with Django's own ``sequence_reset_sql`` (``setval(seq, MAX(id))``),
which is idempotent and safe to run any time.

Run it as the last step of a restore/seed, or ad hoc after any bulk data load.
Read-only without ``--fix``; exits non-zero when drift is found so a scheduled
run or CI step can fail on it.
"""

from django.apps import apps as django_apps
from django.core.management.base import BaseCommand, CommandError
from django.core.management.color import no_style
from django.db import connection

_AUTO_FIELDS = frozenset({'AutoField', 'BigAutoField', 'SmallAutoField'})


class Command(BaseCommand):
    help = 'Report (and with --fix, reset) id sequences that lag behind MAX(id).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix', action='store_true',
            help='Reset drifted sequences to MAX(id). Without this, only reports.',
        )
        parser.add_argument(
            '--app', action='append', dest='app_labels', metavar='LABEL',
            help='Limit to one app label (repeatable). Default: every installed app.',
        )

    def handle(self, *args, **options):
        if connection.vendor != 'postgresql':
            self.stderr.write(self.style.WARNING(
                f'Sequence check supports PostgreSQL only; this connection is '
                f'{connection.vendor!r}. Nothing to do.'
            ))
            return

        if options['app_labels']:
            try:
                configs = [django_apps.get_app_config(l) for l in options['app_labels']]
            except LookupError as exc:
                raise CommandError(str(exc))
            models = [m for c in configs for m in c.get_models()]
        else:
            models = list(django_apps.get_models())

        drifted = []   # (table, seq, max_id, next_val, model)
        checked = 0
        with connection.cursor() as cur:
            # pg_get_serial_sequence() errors on a missing table (e.g. a model
            # whose migration has not been applied), which would abort the run —
            # so skip anything not actually in the database.
            existing = set(connection.introspection.table_names(cur))
            for model in models:
                pk = model._meta.pk
                if pk is None or pk.get_internal_type() not in _AUTO_FIELDS:
                    continue
                table, col = model._meta.db_table, pk.column
                if table not in existing:
                    continue
                cur.execute('SELECT pg_get_serial_sequence(%s, %s)', [table, col])
                seq = cur.fetchone()[0]
                if not seq:
                    continue
                checked += 1

                qtable = connection.ops.quote_name(table)
                qcol = connection.ops.quote_name(col)
                cur.execute(f'SELECT MAX({qcol}) FROM {qtable}')
                max_id = cur.fetchone()[0]
                if max_id is None:
                    continue  # empty table — nextval() from 1 is fine

                cur.execute(f'SELECT last_value, is_called FROM {seq}')
                last_value, is_called = cur.fetchone()
                next_val = last_value + 1 if is_called else last_value
                if next_val <= max_id:
                    drifted.append((table, seq, max_id, next_val, model))

        self.stdout.write(f'Checked {checked} sequence(s) across {len(models)} model(s).')

        if not drifted:
            self.stdout.write(self.style.SUCCESS('OK - every sequence is ahead of its data.'))
            return

        self.stdout.write(self.style.WARNING(f'{len(drifted)} sequence(s) behind their data:'))
        for table, _seq, max_id, next_val, _model in drifted:
            self.stdout.write(f'  {table:<40} next={next_val} <= MAX(id)={max_id}')

        if not options['fix']:
            self.stderr.write(self.style.ERROR(
                'The next INSERT into these tables will fail with a duplicate-key '
                'error. Re-run with --fix to reset them.'
            ))
            # Non-zero exit so a restore runbook / scheduled check fails on drift.
            raise SystemExit(1)

        fix_models = [d[4] for d in drifted]
        sql = connection.ops.sequence_reset_sql(no_style(), fix_models)
        with connection.cursor() as cur:
            for statement in sql:
                cur.execute(statement)
        self.stdout.write(self.style.SUCCESS(
            f'Fixed {len(drifted)} sequence(s) — reset to MAX(id).'
        ))
