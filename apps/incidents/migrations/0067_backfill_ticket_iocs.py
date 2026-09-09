"""Best-effort lift of legacy IOC text into structured TicketIOC rows.

Existing tickets carried indicators as free text in ``destination_ip`` and
``ioc_details``. This extracts the values we can identify unambiguously —
SHA-256 hashes, IPv4 addresses and http(s) URLs (defanging undone) — into
TicketIOC rows. Anything not confidently parsed stays in ``ioc_details``, which
the detail page continues to show read-only. Reverse simply drops the rows.
"""

import ipaddress
import re

from django.db import migrations

_HASH = re.compile(r'\b[0-9a-fA-F]{64}\b')
_URL = re.compile(r'https?://[^\s,;<>"\']+', re.IGNORECASE)
_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _defang(text):
    return (text or '').replace('[.]', '.').replace('(.)', '.').replace('[:]', ':') \
        .replace('hxxps', 'https').replace('hxxp', 'http')


def backfill(apps, schema_editor):
    Ticket = apps.get_model('incidents', 'Ticket')
    TicketIOC = apps.get_model('incidents', 'TicketIOC')

    rows = []
    for ticket in Ticket.objects.all().iterator():
        seen = set()
        order = {}

        def add(category, value):
            value = (value or '').strip()[:500]
            if not value or (category, value) in seen:
                return
            seen.add((category, value))
            index = order.get(category, 0)
            order[category] = index + 1
            rows.append(TicketIOC(ticket_id=ticket.id, category=category,
                                  value=value, order=index))

        destination = _defang(ticket.destination_ip)
        for candidate in _IPV4.findall(destination):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            add('ip', candidate)

        details = _defang(ticket.ioc_details)
        for value in _HASH.findall(details):
            add('hash', value.lower())
        for value in _URL.findall(details):
            add('url', value.rstrip('.,);]'))
        for candidate in _IPV4.findall(details):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            add('ip', candidate)

    if rows:
        TicketIOC.objects.bulk_create(rows, batch_size=500)


def drop(apps, schema_editor):
    apps.get_model('incidents', 'TicketIOC').objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0066_ticketioc_tiplatformimport_tiplatformioc_and_more'),
    ]

    operations = [
        migrations.RunPython(backfill, drop),
    ]
