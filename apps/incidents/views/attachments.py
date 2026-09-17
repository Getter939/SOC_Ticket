import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from ..forms import (
    AttachmentForm,
)
from ..models import (
    Ticket,
    TicketAttachment,
)
from ..staging import (
    discard_staged, restore_staged,
)
from ..reports import (
    PREVIEW_IMAGE_ERRORS,
    build_attachment_preview_image,
)
from ..policies import (
    can_delete_ticket_attachment as _can_delete_ticket_attachment,
    can_restore_ticket_attachment as _can_restore_ticket_attachment,
    can_upload_ticket_attachment as _can_upload_ticket_attachment,
)
from ..ticket_evidence import (
    add_ticket_attachments,
    delete_ticket_attachment,
    restore_ticket_attachment,
)

logger = logging.getLogger('apps.incidents.views')



# ── Attachment views ─────────────────────────────────────────────────── #

@login_required
def upload_attachment(request, pk):
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    if not _can_upload_ticket_attachment(ticket, request.user):
        messages.error(request, 'You cannot upload attachments while this ticket is in its current status.')
        return redirect('ticket_detail', pk=pk)
    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES)
        if form.is_valid():
            description = form.cleaned_data.get('description', '')
            uploads = form.cleaned_data['file']
            try:
                result = add_ticket_attachments(
                    ticket=ticket,
                    actor=request.user,
                    uploads=uploads,
                    description=description,
                )
            except ValidationError as exc:
                messages.error(request, ' '.join(exc.messages))
                return redirect('ticket_detail', pk=pk)
            if len(result.attachments) == 1:
                messages.success(
                    request,
                    f'อัพโหลด "{result.attachments[0].original_name}" เรียบร้อยแล้ว',
                )
            else:
                messages.success(request, f'อัพโหลด {len(result.attachments)} ไฟล์เรียบร้อยแล้ว')
        else:
            # Name the offending file — "check your file again" is useless when
            # several were selected and only one was rejected.
            detail = '; '.join(
                msg for errors in form.errors.values() for msg in errors
            )
            messages.error(
                request,
                f'ไม่สามารถอัพโหลดไฟล์ได้ — {detail}' if detail
                else 'ไม่สามารถอัพโหลดไฟล์ได้ — กรุณาตรวจสอบไฟล์อีกครั้ง',
            )
    return redirect('ticket_detail', pk=pk)


@login_required
@require_POST
def discard_staged_attachment(request, pk):
    """Remove one file from an in-progress case form.

    Scoped to the uploader inside discard_staged; a 404 here means the row is
    gone or was never theirs. Answers 204 so the picker can grey the chip out
    without a page reload. The file is retained so restore_staged_attachment
    can undo this.
    """
    if not discard_staged(request.user, pk):
        raise Http404
    return HttpResponse(status=204)


@login_required
@require_POST
def restore_staged_attachment(request, pk):
    """Undo a discard while the case form is still open."""
    if not restore_staged(request.user, pk):
        raise Http404
    return HttpResponse(status=204)


@login_required
@require_POST
def delete_attachment(request, attachment_id):
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    if not _can_delete_ticket_attachment(ticket, att, request.user):
        # A refused attempt used to be a silent redirect, so probing left no
        # trace at all. It goes to the application log rather than TicketLog:
        # anyone who can see a ticket could otherwise flood its timeline.
        logger.warning(
            'Refused attachment delete: user=%s attachment=%s ticket=%s status=%s',
            request.user.pk, att.pk, ticket.ticket_id, ticket.status,
        )
        messages.error(
            request,
            'คุณไม่มีสิทธิ์ลบไฟล์นี้ หรือเคสถูกปิดแล้ว — หลักฐานของเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('ticket_detail', pk=ticket.pk)

    reason = (request.POST.get('reason') or '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการลบไฟล์')
        return redirect('ticket_detail', pk=ticket.pk)

    try:
        delete_ticket_attachment(attachment=att, actor=request.user, reason=reason)
    except ValidationError as exc:
        messages.error(request, ' '.join(exc.messages))
        return redirect('ticket_detail', pk=ticket.pk)
    messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว — ผู้จัดการ SOC สามารถกู้คืนได้')
    return redirect('ticket_detail', pk=ticket.pk)


@login_required
@require_POST
def restore_attachment(request, attachment_id):
    """Bring back evidence removed by mistake. SOC Manager / superuser only."""
    att = get_object_or_404(
        TicketAttachment.all_objects, pk=attachment_id, deleted_at__isnull=False)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    if not _can_restore_ticket_attachment(request.user):
        logger.warning(
            'Refused attachment restore: user=%s attachment=%s ticket=%s',
            request.user.pk, att.pk, ticket.ticket_id,
        )
        messages.error(request, 'กู้คืนไฟล์ได้เฉพาะผู้จัดการ SOC เท่านั้น')
        return redirect('ticket_detail', pk=ticket.pk)

    restore_ticket_attachment(attachment=att, actor=request.user)
    messages.success(request, f'กู้คืน "{att.original_name}" เรียบร้อยแล้ว')
    return redirect('ticket_detail', pk=ticket.pk)


@login_required
def download_attachment(request, attachment_id):
    """Serve a ticket attachment to authorized users only.

    Attachments are incident evidence and must never be a security hole:

      • Authorization — the requester must be able to see the parent ticket
        (same rule as ``ticket_detail`` via ``visible_to``). This closes both
        unauthenticated access and cross-role IDOR on the raw file path.
      • Forced download — ``Content-Disposition: attachment`` plus
        ``X-Content-Type-Options: nosniff`` means an uploaded ``.html`` or
        ``.svg`` is downloaded, never rendered as same-origin script. Without
        this a user could upload ``<svg onload=…>`` and land stored XSS on
        whoever opens the file.
    """
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    # 404 (not 403) if the user can't see the parent ticket — no enumeration.
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    response = FileResponse(
        att.file.open('rb'),
        as_attachment=True,
        filename=att.original_name,
    )
    response['X-Content-Type-Options'] = 'nosniff'
    return response


# Cap on how much of a text/log/CSV file the inline preview reads. Enough to read
# the file, small enough not to freeze the browser on a multi-hundred-MB log.
_PREVIEW_TEXT_MAX_BYTES = 1024 * 1024        # 1 MB
_PREVIEW_CSV_MAX_ROWS = 500
# Thai Windows logs are commonly cp874; try the Unicode forms first.
_PREVIEW_TEXT_ENCODINGS = ('utf-8-sig', 'cp874')


@login_required
def preview_attachment(request, attachment_id):
    """Render one attachment inline (own tab) so users can read it without
    downloading. Same authorization as download_attachment; only image and
    text/log/CSV files preview — anything else 404s (its button is not shown).

    Images are re-encoded through Pillow into a ``data:`` URI, so the raw upload
    is never served to the browser (no stored-XSS via a spoofed SVG/HTML). Text
    is decoded defensively and rendered autoescaped, so it displays as text, not
    markup. This is why it is safe to render inline where download_attachment
    deliberately forces a download.
    """
    att = get_object_or_404(TicketAttachment, pk=attachment_id)
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=att.ticket_id)

    kind = att.preview_kind
    if not kind:
        raise Http404('ไฟล์ชนิดนี้ไม่รองรับการแสดงตัวอย่าง')

    ctx = {'attachment': att, 'ticket': att.ticket, 'kind': kind}

    if kind == 'image':
        try:
            image = build_attachment_preview_image(att)
        except PREVIEW_IMAGE_ERRORS:
            # A corrupt / oversized / non-image file — 404 it. Anything else
            # (storage, bug) propagates to a logged 500 rather than hiding here.
            logger.warning('Inline preview failed for attachment %s', att.pk, exc_info=True)
            raise Http404('ไม่สามารถแสดงตัวอย่างไฟล์รูปภาพนี้ได้')
        ctx['image_data_uri'] = image.data_uri
        return render(request, 'incidents/attachment_preview.html', ctx)

    # text / log / csv
    with att.file.open('rb') as fh:
        raw = fh.read(_PREVIEW_TEXT_MAX_BYTES + 1)
    ctx['truncated'] = len(raw) > _PREVIEW_TEXT_MAX_BYTES
    raw = raw[:_PREVIEW_TEXT_MAX_BYTES]
    text = None
    for encoding in _PREVIEW_TEXT_ENCODINGS:
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = raw.decode('latin-1', errors='replace')

    ext = att.original_name.rpartition('.')[2].lower()
    if ext in ('csv', 'tsv'):
        rows = _preview_csv_rows(text, delimiter='\t' if ext == 'tsv' else ',')
        if rows is not None:
            ctx['csv_rows'] = rows
            ctx['csv_truncated'] = len(rows) >= _PREVIEW_CSV_MAX_ROWS
            return render(request, 'incidents/attachment_preview.html', ctx)
    ctx['text'] = text
    return render(request, 'incidents/attachment_preview.html', ctx)


def _preview_csv_rows(text, delimiter):
    """Parse text into at most _PREVIEW_CSV_MAX_ROWS rows for a table preview, or
    None if it does not parse as delimited data (fall back to plain text)."""
    import csv
    import io
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        rows = []
        for row in reader:
            rows.append(row)
            if len(rows) >= _PREVIEW_CSV_MAX_ROWS:
                break
        return rows or None
    except csv.Error:
        return None
