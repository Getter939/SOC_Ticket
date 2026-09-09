"""Shared normalization for structured ticket IOCs and imported TI records.

One vocabulary of IOC categories is used on both sides — the ticket's structured
indicators and the TI Platform inventory — so a *(category, value)* pair means the
same thing wherever it appears and can be matched directly.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError

# ── Category vocabulary ──────────────────────────────────────────────────── #
# Ticket indicators use all six. The TI inventory classifies a row as one of the
# five matchable kinds (a file *name* is context there, not an indicator).
CAT_FILE_NAME = 'file_name'
CAT_HASH = 'hash'
CAT_DOMAIN = 'domain'
CAT_IP = 'ip'
CAT_URL = 'url'
CAT_FILE_PATH = 'file_path'

TICKET_CATEGORY_CHOICES = [
    (CAT_FILE_NAME, 'File Name'),
    (CAT_HASH, 'Hash (SHA-256)'),
    (CAT_DOMAIN, 'Domain'),
    (CAT_IP, 'IP Address'),
    (CAT_URL, 'URL'),
    (CAT_FILE_PATH, 'File Path'),
]
# Inventory Category — no File Name (that is a separate context column there).
INVENTORY_CATEGORY_CHOICES = [
    (CAT_HASH, 'Hash'),
    (CAT_IP, 'IP'),
    (CAT_DOMAIN, 'Domain'),
    (CAT_URL, 'URL'),
    (CAT_FILE_PATH, 'File Path'),
]


def refang(value):
    """Undo the usual analyst defanging so `1[.]2[.]3[.]4` / `hxxp://` compare."""
    value = str(value or '').strip()
    return (value
            .replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
            .replace('[:]', ':')
            .replace('hxxps', 'https').replace('hxxp', 'http')
            .replace('hXXps', 'https').replace('hXXp', 'http'))


def normalize_sha256(value):
    value = str(value or '').strip().lower()
    if value and not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValidationError('SHA-256 must contain exactly 64 hexadecimal characters.')
    return value


def normalize_ip(value):
    value = refang(value)
    if not value:
        return ''
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        raise ValidationError('Enter one valid IPv4 or IPv6 address.')


def normalize_domain(value):
    value = refang(value).lower()
    if not value:
        return ''
    value = value.rstrip('.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValidationError('Enter a valid domain name, without a URL or path.')
    labels = value.split('.')
    if (len(value) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                for p in labels) or labels[-1].isdigit()):
        raise ValidationError('Enter a valid domain name, without a URL or path.')
    return value


def normalize_url(value):
    """Refang, require an http(s) scheme + host, lower-case scheme/host, keep path."""
    value = refang(value)
    if not value:
        return ''
    parts = urlsplit(value)
    if parts.scheme not in {'http', 'https'} or not parts.netloc:
        raise ValidationError('Enter a valid URL, including http:// or https://.')
    netloc = parts.netloc.lower()
    normalized = f'{parts.scheme.lower()}://{netloc}{parts.path}'
    if parts.query:
        normalized += f'?{parts.query}'
    if parts.fragment:
        normalized += f'#{parts.fragment}'
    if len(normalized) > 500:
        raise ValidationError('URL is too long (500 characters maximum).')
    return normalized


def _strip(value):
    return str(value or '').strip()


# Category code → normalizer. File Name / File Path are free text (trimmed only).
CATEGORY_NORMALIZERS = {
    CAT_FILE_NAME: _strip,
    CAT_HASH: normalize_sha256,
    CAT_DOMAIN: normalize_domain,
    CAT_IP: normalize_ip,
    CAT_URL: normalize_url,
    CAT_FILE_PATH: _strip,
}


def normalize_for_category(category, value):
    """Normalize ``value`` for ``category``; raises ValidationError if malformed."""
    return CATEGORY_NORMALIZERS.get(category, _strip)(value)


# Field-validators kept for model fields (validate without returning a value).
def validate_sha256(value):
    normalize_sha256(value)


def validate_domain(value):
    normalize_domain(value)


def validate_url(value):
    normalize_url(value)


# Legacy alias — v1 code referenced IOC_NORMALIZERS keyed by the ticket field
# names. Retained so the data migration and any lingering import keep working.
IOC_NORMALIZERS = {
    'sha256': normalize_sha256,
    'ip_address': normalize_ip,
    'domain': normalize_domain,
    'file_name': _strip,
}
