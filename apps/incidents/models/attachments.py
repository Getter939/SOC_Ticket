
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models

from .ticket import Ticket

# ======================================================================= #
# File attachments                                                         #
# ======================================================================= #

# Per-file upload cap — guards against disk-exhaustion DoS from oversized
# uploads. Django has no built-in per-file size limit, so it is enforced
# explicitly in BOTH upload paths (AttachmentForm.clean_file and the
# create_ticket evidence loop). Bump if SOC evidence (pcaps, memory dumps)
# legitimately needs more headroom.
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25 MB

# Total cap across every file in one submit. Separate from the per-file cap
# because the real ceiling is the reverse proxy: nginx rejects an oversized
# body with a bare 413 *before* Django runs, which looks to the analyst like
# "my files vanished". Keep this comfortably under nginx's client_max_body_size
# (128M) so the batch is refused with a real message instead.
MAX_ATTACHMENT_BATCH_SIZE = 100 * 1024 * 1024  # 100 MB

# Extension allowlist for uploaded evidence. This is a SOC evidence store, so
# the default is deliberately broad — logs, captures, documents, images and
# archives are all legitimate evidence — but it still blocks active-web content
# (.html/.svg/.xhtml/.js …) that could be socially engineered into a stored-XSS
# vector. It is only a second line of defence: download_attachment already
# forces `Content-Disposition: attachment` + `nosniff` so nothing is rendered
# as same-origin script. Override with ATTACHMENT_ALLOWED_EXTENSIONS in .env/
# settings if a deployment needs a different set (e.g. malware-sample intake).
DEFAULT_ALLOWED_ATTACHMENT_EXTENSIONS = frozenset({
    # documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'rtf',
    # text / structured logs
    'txt', 'log', 'csv', 'tsv', 'json', 'yaml', 'yml', 'md',
    # images (screenshots) — content is magic-byte verified below
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    # archives / captures
    'zip', 'gz', 'tgz', '7z', 'rar', 'tar', 'pcap', 'pcapng', 'cap',
    # mail evidence
    'eml', 'msg',
})

# Extensions we can safely show inline on the ticket page (opened in a new tab
# by preview_attachment). Images are re-encoded through Pillow before display so
# the raw upload is never served; text/log/CSV is shown as autoescaped text.
# Everything else (Office, archives, pcaps, mail) has no preview and only offers
# the forced download.
PREVIEW_IMAGE_EXTENSIONS = frozenset({'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'})
PREVIEW_TEXT_EXTENSIONS = frozenset({
    'txt', 'log', 'csv', 'tsv', 'json', 'yaml', 'yml', 'md',
})

# Leading magic bytes for the renderable types we accept, so a spoofed
# `evil.svg` renamed to `.png` (still active content) is rejected on content,
# not just on its extension.
_ATTACHMENT_MAGIC_BYTES = {
    'png':  (b'\x89PNG\r\n\x1a\n',),
    'gif':  (b'GIF87a', b'GIF89a'),
    'jpg':  (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'bmp':  (b'BM',),
    'pdf':  (b'%PDF',),
    # WEBP is a RIFF container: bytes 0-3 'RIFF', bytes 8-11 'WEBP'.
    'webp': (b'RIFF',),
}


def _attachment_extension(name):
    """Lower-cased final extension of ``name`` (no dot), or '' if none."""
    _, _, ext = (name or '').rpartition('.')
    return ext.lower() if ext and '.' in (name or '') else ''


def validate_attachment_size(uploaded_file):
    """Raise ValidationError if an uploaded file exceeds MAX_ATTACHMENT_SIZE."""
    if uploaded_file is not None and uploaded_file.size > MAX_ATTACHMENT_SIZE:
        raise ValidationError(
            f'ไฟล์มีขนาดใหญ่เกินไป — สูงสุด {MAX_ATTACHMENT_SIZE // (1024 * 1024)} MB'
        )


def allowed_attachment_extensions():
    """Sorted list of the extensions this deployment accepts.

    Single source of truth for the picker UI: the `accept` attribute and the
    client-side pre-check are both built from this, so they can never drift
    from what validate_attachment_type actually enforces.
    """
    return sorted(getattr(
        settings, 'ATTACHMENT_ALLOWED_EXTENSIONS',
        DEFAULT_ALLOWED_ATTACHMENT_EXTENSIONS,
    ))


def validate_attachment_type(uploaded_file):
    """Reject disallowed file types by extension, and verify content magic bytes
    for the renderable types (images / PDF) to catch spoofed content.

    Defence-in-depth: uploads are always served as forced downloads with
    ``nosniff`` (see download_attachment), so this guards against social
    engineering and accidental active-content uploads rather than direct code
    execution.
    """
    if uploaded_file is None:
        return

    allowed = allowed_attachment_extensions()
    ext = _attachment_extension(uploaded_file.name)
    if not ext:
        raise ValidationError('ไฟล์ต้องมีนามสกุล (extension) ที่ชัดเจน')
    if ext not in allowed:
        raise ValidationError(
            f'ชนิดไฟล์ ".{ext}" ไม่ได้รับอนุญาต — '
            f'รองรับเฉพาะเอกสาร รูปภาพ log และไฟล์หลักฐานทั่วไป'
        )

    signatures = _ATTACHMENT_MAGIC_BYTES.get(ext)
    if signatures:
        pos = uploaded_file.tell() if hasattr(uploaded_file, 'tell') else 0
        try:
            uploaded_file.seek(0)
            header = uploaded_file.read(16)
        finally:
            uploaded_file.seek(pos)
        if not any(header.startswith(sig) for sig in signatures):
            raise ValidationError(
                f'เนื้อหาของไฟล์ไม่ตรงกับชนิด ".{ext}" ที่ระบุ — '
                f'ไฟล์อาจถูกปลอมนามสกุล'
            )


def validate_attachment(uploaded_file):
    """Run every attachment guard (size + type/content). Single entry point for
    both upload paths so they can never drift apart."""
    validate_attachment_size(uploaded_file)
    validate_attachment_type(uploaded_file)


def validate_attachment_batch(uploaded_files):
    """Reject a set of uploads whose combined size exceeds MAX_ATTACHMENT_BATCH_SIZE.

    validate_attachment only sees one file at a time, but the batch total is the
    real ceiling: nginx rejects an oversized request body with a bare 413 before
    Django runs, which looks to the analyst like the files silently vanished.
    stage_uploads (create flow) already enforces this per file as it accumulates;
    this is the shared guard for the ticket-detail path (AttachmentForm), which
    otherwise had only the bypassable client-side check.
    """
    total = sum(f.size for f in uploaded_files if f is not None)
    if total > MAX_ATTACHMENT_BATCH_SIZE:
        limit_mb = MAX_ATTACHMENT_BATCH_SIZE // (1024 * 1024)
        raise ValidationError(
            f'ไฟล์แนบรวมกันเกิน {limit_mb} MB — กรุณาลบบางไฟล์ออกแล้วลองใหม่'
        )


def preview_kind_for(original_name):
    """'image', 'text', or '' — how (if at all) a file with this name can be
    shown inline without a download. Shared by TicketAttachment and
    ProjectIncidentAttachment so both offer the same inline preview."""
    ext = _attachment_extension(original_name)
    if ext in PREVIEW_IMAGE_EXTENSIONS:
        return 'image'
    if ext in PREVIEW_TEXT_EXTENSIONS:
        return 'text'
    return ''


def attachment_upload_path(instance, filename):
    return f'ticket_attachments/{instance.ticket.ticket_id}/{filename}'


class TicketAttachmentQuerySet(models.QuerySet):
    def active(self):
        return self.filter(deleted_at__isnull=True)


class TicketAttachmentManager(models.Manager.from_queryset(TicketAttachmentQuerySet)):
    """Default manager: operational views never expose removed evidence."""

    def get_queryset(self):
        return super().get_queryset().active()


class TicketAttachment(models.Model):
    """File attached to a ticket — evidence, reports, screenshots, etc."""

    objects = TicketAttachmentManager()
    all_objects = models.Manager()

    ticket       = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='attachments')
    # Optional link to the response-team request this file is a deliverable for
    # (e.g. a forensics report or VA scan output). NULL for ordinary ticket-level
    # evidence. Served through the same hardened download_attachment path; the
    # ticket FK stays authoritative for visibility, so a NULL subtask is fine.
    subtask      = models.ForeignKey(
        'TicketSubtask', on_delete=models.CASCADE, null=True, blank=True,
        related_name='attachments', verbose_name='งานย่อยที่เกี่ยวข้อง',
    )
    file         = models.FileField(upload_to=attachment_upload_path)
    original_name = models.CharField(max_length=255)
    description  = models.CharField(max_length=255, blank=True, default='')
    uploaded_by  = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='uploaded_attachments',
    )
    uploaded_at  = models.DateTimeField(auto_now_add=True)
    deleted_by   = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='deleted_attachments',
    )
    deleted_at   = models.DateTimeField(null=True, blank=True)
    # Why the evidence was removed. Mandatory at the view layer rather than the
    # model, so historical rows deleted before this field existed stay valid.
    deleted_reason = models.CharField(max_length=255, blank=True, default='')

    class Meta:
        ordering = ['uploaded_at']

    def __str__(self):
        return f'{self.original_name} → {self.ticket.ticket_id}'

    @property
    def preview_kind(self):
        """'image', 'text', or '' — how (if at all) this file can be shown inline
        without a download. Drives the 'ดูตัวอย่าง' link and preview_attachment."""
        return preview_kind_for(self.original_name)


def staged_attachment_upload_path(instance, filename):
    return f'staged_attachments/{instance.token}/{filename}'


class StagedAttachment(models.Model):
    """Evidence held between a failed submit and the retry.

    A browser cannot repopulate an <input type="file"> after a page load, so
    when the create form comes back with a validation error the bytes the
    analyst already uploaded would be lost. Uploads are therefore written here
    *before* the form is validated, then adopted onto a TicketAttachment (or
    ProjectIncidentAttachment) once the case is actually created.

    This is scratch data, not evidence of record: nothing here has a ticket
    yet, and abandoned rows are removed by `purge_staged_attachments`.
    """

    # Random per-form token, round-tripped through a hidden field. Always
    # queried together with uploaded_by — see staging.staged_for().
    token         = models.CharField(max_length=32, db_index=True)
    file          = models.FileField(upload_to=staged_attachment_upload_path)
    original_name = models.CharField(max_length=255)
    uploaded_by   = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='staged_attachments',
    )
    created_at    = models.DateTimeField(auto_now_add=True)
    # Set when the analyst removes the chip. The row and its bytes are kept so
    # a misclick can be undone; purge_staged_attachments clears them on its
    # normal schedule. Discarded rows are hidden from the picker and are never
    # adopted onto a ticket.
    discarded_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'{self.original_name} (staged {self.token[:8]})'
