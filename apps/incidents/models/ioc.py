
from django.contrib.auth.models import User
from django.db import models

from ..ioc_values import INVENTORY_CATEGORY_CHOICES, TICKET_CATEGORY_CHOICES
from .ticket import Ticket


class ThreatGuidance(models.Model):
    """Standard containment guidance per threat category (admin-editable).

    Backing data for the "แทรกแนวทางมาตรฐาน" button on the create-ticket form:
    the analyst picks a threat category (``detailed_issue``) and can insert the
    category's standard สิ่งที่ต้องดำเนินการ / ข้อควรระวัง text, then edit it.
    Content lives here (not in code) so the SOC lead can revise the playbook
    wording in Django admin without a deploy. Seeded by migration 0041.
    """

    detailed_issue = models.CharField(
        max_length=50, unique=True, choices=Ticket.DETAILED_ISSUE_CHOICES,
        verbose_name='หมวดหมู่ภัยคุกคาม',
    )
    action_required = models.TextField(
        blank=True, default='',
        verbose_name='สิ่งที่ต้องดำเนินการ (มาตรฐาน)',
    )
    action_precautions = models.TextField(
        blank=True, default='',
        verbose_name='ข้อควรระวังในการดำเนินการ (มาตรฐาน)',
    )
    is_active = models.BooleanField(default=True, verbose_name='ใช้งาน')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['detailed_issue']
        verbose_name = 'แนวทางมาตรฐานตามหมวดหมู่ภัยคุกคาม'
        verbose_name_plural = 'แนวทางมาตรฐานตามหมวดหมู่ภัยคุกคาม'

    def __str__(self):
        return self.get_detailed_issue_display()


class TicketIOC(models.Model):
    """One structured indicator on a ticket. Multi-valued: a ticket may hold
    several rows of the same category (e.g. three IP addresses)."""

    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='iocs')
    category = models.CharField(max_length=20, choices=TICKET_CATEGORY_CHOICES, db_index=True)
    value = models.CharField(max_length=500)
    # Preserves the analyst's entry order within a category for stable rendering.
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['category', 'order', 'pk']

    def __str__(self):
        return f'{self.get_category_display()}: {self.value}'


# Retained only because historical migrations reference it by path; the CSV import
# it served was removed when manual entry replaced file uploads.
def ti_import_upload_path(instance, filename):
    from pathlib import Path
    from uuid import uuid4
    return f'ti_platform/{uuid4().hex}{Path(filename).suffix.lower()}'


class AnalystIOC(models.Model):
    """A single IOC the Forensic Analyst found through their own external research
    and entered by hand — NOT the MISP/TI-platform registered set. ``ext_id`` is a
    generated ``MAN-####`` reference, ``ioc_detail`` is the value, and ``file_name``
    is context for hashes (never an indicator on its own).

    The note and the reviewed-against-MISP flag are NOT here: they live on
    IOCReviewStatus, keyed by (category, value), so ticket-sourced indicators can
    carry them too.
    """

    ext_id = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=20, choices=INVENTORY_CATEGORY_CHOICES, db_index=True)
    file_name = models.CharField(max_length=255, blank=True, db_index=True)
    ioc_detail = models.CharField(max_length=500, db_index=True)
    added_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    # Soft-remove: a mistaken entry is hidden from the database but kept for audit.
    is_active = models.BooleanField(default=True)
    removed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    removed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # The Forensics / RCA request this entry was pushed from (see
    # apps.incidents.rca.push_iocs), so the IOC Database can link an entry back
    # to its case. Empty for indicators typed straight into the database.
    source_subtask = models.ForeignKey(
        'TicketSubtask', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='pushed_iocs',
    )

    class Meta:
        ordering = ['-pk']

    def __str__(self):
        return f'{self.ext_id} ({self.get_category_display()})'


class IOCReviewStatus(models.Model):
    """The Forensic Analyst's annotation for one indicator: the manual
    "reviewed against MISP" flag AND its note.

    Keyed by (category, value) so a ticket-sourced IOC and a manually added one of
    the same value share a single annotation. An absent row means Not Checked with
    no note.
    """

    category = models.CharField(max_length=20, choices=TICKET_CATEGORY_CHOICES, db_index=True)
    value = models.CharField(max_length=500)
    checked = models.BooleanField(default=False)
    note = models.TextField(blank=True, default='')
    updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('category', 'value')]
        ordering = ['-updated_at', '-pk']

    def __str__(self):
        state = 'checked' if self.checked else 'not checked'
        return f'{self.category}:{self.value} = {state}'
