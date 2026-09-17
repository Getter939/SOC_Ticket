
from django.contrib.auth.models import User
from django.db import models

from .ticket import Ticket

class TicketLog(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='logs')
    note = models.TextField(verbose_name='บันทึกรายละเอียด')
    status_at_time = models.CharField(max_length=30, verbose_name='สถานะขณะบันทึก')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    author = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_logs', verbose_name='ผู้บันทึก',
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'Log for {self.ticket.ticket_id} - {self.ticket.device_name}'

    @property
    def status_display(self):
        """Human label for the status code recorded at log time."""
        return dict(Ticket.STATUS_CHOICES).get(self.status_at_time, self.status_at_time)

    @property
    def was_edited(self):
        """Whether this timeline entry has been rewritten since it was made."""
        return self.revisions.exists()


class TicketFieldChange(models.Model):
    """One field's before/after, recorded whenever ticket content is rewritten.

    TicketLog stores prose — "sent for review", "returned to Tier 1" — which is
    enough to follow the workflow but not to answer "who changed the IP address,
    and what was it before?". Several surfaces overwrite content in place (Tier 2
    review rewrites ~25 fields, the admin's containment report is replaced when
    Tier 2 bounces it back, subtask result notes had no audit at all), so
    without this the previous values were simply gone.

    This is also what makes an edit view and a manager step-back safe to offer:
    an undo needs something to restore *from*.
    """

    ticket      = models.ForeignKey(
        Ticket, on_delete=models.CASCADE, related_name='field_changes',
    )
    # Set when the change belongs to a response-team deliverable rather than
    # the ticket's own fields.
    subtask     = models.ForeignKey(
        'TicketSubtask', on_delete=models.CASCADE, null=True, blank=True,
        related_name='field_changes',
    )
    field_name  = models.CharField(max_length=60)
    field_label = models.CharField(max_length=120)
    old_value   = models.TextField(blank=True, default='')
    new_value   = models.TextField(blank=True, default='')
    changed_by  = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_field_changes',
    )
    changed_at  = models.DateTimeField(auto_now_add=True)
    # Which surface made the change — 't2_review', 'containment', 'edit', …
    source      = models.CharField(max_length=30, blank=True, default='')

    class Meta:
        ordering = ['-changed_at', 'field_name']
        indexes = [models.Index(fields=['ticket', '-changed_at'])]

    def __str__(self):
        return f'{self.field_label} changed on {self.ticket_id}'


class TicketLogRevision(models.Model):
    """The text a timeline entry held before someone rewrote it.

    The timeline is the audit trail, and edit_log lets the original author or
    any SOC manager rewrite an entry in place. Without this, the record of an
    action — an attachment deletion, say — could be edited by the very person
    who took it, leaving no trace. Each edit banks the previous text here first,
    so a rewrite adds to the history instead of replacing it.
    """

    log           = models.ForeignKey(
        TicketLog, on_delete=models.CASCADE, related_name='revisions',
    )
    previous_note = models.TextField(verbose_name='ข้อความก่อนแก้ไข')
    edited_by     = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='ticket_log_revisions', verbose_name='ผู้แก้ไข',
    )
    edited_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-edited_at']

    def __str__(self):
        return f'Revision of log #{self.log_id} at {self.edited_at:%Y-%m-%d %H:%M}'
