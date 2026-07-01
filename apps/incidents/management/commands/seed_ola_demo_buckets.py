from collections import Counter
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.incidents import ola as ola_buckets
from apps.incidents.models import Ticket


class Command(BaseCommand):
    help = 'Spread active ticket OLA deadlines across dashboard demo buckets.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apply',
            action='store_true',
            help='Persist the OLA deadline changes. Without this, only print the plan.',
        )
        parser.add_argument(
            '--due-1h',
            type=int,
            default=4,
            help='Number of active tickets to place in the due <= 1h bucket.',
        )
        parser.add_argument(
            '--due-4h',
            type=int,
            default=6,
            help='Number of active tickets to place in the due 1-4h bucket.',
        )
        parser.add_argument(
            '--on-track',
            type=int,
            default=12,
            help='Number of active tickets to place in the on-track bucket.',
        )
        parser.add_argument(
            '--reference-prefix',
            default='',
            help='Optional reference_id prefix to limit which active tickets are updated.',
        )

    def handle(self, *args, **options):
        self._validate_options(options)
        now = timezone.now().replace(second=0, microsecond=0)
        deadlines = self._target_deadlines(now)

        tickets_qs = Ticket.objects.exclude(
            status__in=Ticket.TERMINAL_STATUSES,
        ).order_by('id')
        if options['reference_prefix']:
            tickets_qs = tickets_qs.filter(
                reference_id__startswith=options['reference_prefix'])

        tickets = list(tickets_qs)
        assignments = self._assign_buckets(
            tickets,
            due_1h_count=options['due_1h'],
            due_4h_count=options['due_4h'],
            on_track_count=options['on_track'],
        )

        mode = 'APPLY' if options['apply'] else 'DRY RUN'
        self.stdout.write(f'OLA demo bucket spread ({mode})')
        self.stdout.write(f'Active tickets selected: {len(tickets)}')
        if options['reference_prefix']:
            self.stdout.write(f'Reference prefix: {options["reference_prefix"]}')

        counts = Counter(assignments.values())
        for key, label, _ in ola_buckets.OLA_BUCKETS:
            self.stdout.write(
                f'- {label}: {counts[key]} tickets -> {deadlines[key].isoformat()}')

        if not options['apply']:
            self.stdout.write('No database changes written. Re-run with --apply to persist.')
            return

        for key in ola_buckets.BUCKET_KEYS:
            pks = [ticket.pk for ticket, bucket in assignments.items() if bucket == key]
            if pks:
                Ticket.objects.filter(pk__in=pks).update(ola_contain_deadline=deadlines[key])

        self.stdout.write(self.style.SUCCESS('OLA demo bucket spread applied.'))

    @staticmethod
    def _validate_options(options):
        for option_name in ('due_1h', 'due_4h', 'on_track'):
            if options[option_name] < 0:
                raise CommandError(f'--{option_name.replace("_", "-")} must be >= 0.')
        if ola_buckets.URGENT_HOURS <= 0:
            raise CommandError('ola.URGENT_HOURS must be greater than 0.')
        if ola_buckets.DUE_SOON_HOURS <= ola_buckets.URGENT_HOURS:
            raise CommandError(
                'ola.DUE_SOON_HOURS must be greater than ola.URGENT_HOURS.')

    @staticmethod
    def _target_deadlines(now):
        urgent = timedelta(hours=ola_buckets.URGENT_HOURS)
        due_soon = timedelta(hours=ola_buckets.DUE_SOON_HOURS)
        return {
            ola_buckets.OVERDUE: now - timedelta(minutes=30),
            ola_buckets.DUE_1H: now + urgent * 0.75,
            ola_buckets.DUE_4H: now + urgent + ((due_soon - urgent) / 2),
            ola_buckets.ON_TRACK: now + due_soon + timedelta(hours=6),
        }

    @staticmethod
    def _assign_buckets(tickets, due_1h_count, due_4h_count, on_track_count):
        assignments = {}
        remaining = list(tickets)

        for key, count in (
            (ola_buckets.DUE_1H, due_1h_count),
            (ola_buckets.DUE_4H, due_4h_count),
            (ola_buckets.ON_TRACK, on_track_count),
        ):
            selected = remaining[:count]
            remaining = remaining[count:]
            for ticket in selected:
                assignments[ticket] = key

        for ticket in remaining:
            assignments[ticket] = ola_buckets.OVERDUE
        return assignments
