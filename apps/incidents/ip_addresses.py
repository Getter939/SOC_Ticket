"""Validation and form input for an affected asset's IP addresses."""

import ipaddress
import re

from django import forms
from django.core.exceptions import ValidationError


IP_ADDRESSES_HELP = 'ระบุ IPv4 หรือ IPv6 ได้หลายรายการ คั่นด้วยจุลภาคหรือขึ้นบรรทัดใหม่'


def normalize_ip_addresses(value):
    """Keep a readable, ordered list while validating every address."""
    if not value:
        return value
    addresses = []
    for token in re.split(r'[,;\s]+', value.strip()):
        if not token:
            continue
        try:
            # Interface zones are local to a host and aren't asset addresses.
            if '%' in token:
                raise ValueError
            address = ipaddress.ip_address(token).compressed
        except ValueError:
            raise ValidationError(
                'Enter a valid IPv4 or IPv6 address: %(address)s.',
                code='invalid', params={'address': token},
            ) from None
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValidationError('Enter at least one IPv4 or IPv6 address.', code='invalid')
    return ', '.join(addresses)


def validate_ip_addresses(value):
    normalize_ip_addresses(value)


class IPAddressListField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label', 'IP Addresses ของทรัพย์สิน')
        kwargs.setdefault('help_text', IP_ADDRESSES_HELP)
        kwargs.setdefault('empty_value', None)
        kwargs.setdefault('widget', forms.Textarea(attrs={
            'class': 'form-control', 'rows': 2,
            'placeholder': '192.0.2.10, 192.0.2.11, 2001:db8::1',
        }))
        super().__init__(*args, **kwargs)

    def clean(self, value):
        return normalize_ip_addresses(super().clean(value))
