"""Staging for evidence uploaded on the case-creation forms.

A browser will not repopulate an ``<input type="file">`` across a page load —
that is a hard security rule, not a bug we can work around client-side. So when
``create_ticket`` re-renders with a validation error, any file the analyst
attached is gone unless the server kept it.

The flow is:

    POST → stage_uploads()   writes every valid file to StagedAttachment
         → form.is_valid()?
             no  → re-render, staged_for() lists what is being held
             yes → adopt_staged() moves the files onto the real attachment
                   rows and clears the staging table

Validation is deliberately *not* re-implemented here: every file goes through
``validate_attachment`` (models.py), the same entry point the ticket-detail
upload path uses, so the two can never drift apart.
"""

import secrets
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import (
    MAX_ATTACHMENT_BATCH_SIZE,
    ProjectIncidentAttachment,
    StagedAttachment,
    TicketAttachment,
    validate_attachment,
)

# Guards against a client that ignores the picker's own count check. Kept below
# Django's DATA_UPLOAD_MAX_NUMBER_FILES (100) so we fail with a readable message
# rather than a bare 400 from the upload handler.
MAX_ATTACHMENT_COUNT = 50


def new_token():
    """Fresh staging token. 32 hex chars — matches StagedAttachment.token."""
    return secrets.token_hex(16)


def _clean_token(value):
    """Accept a token only if it looks like one we minted.

    The token is attacker-supplied (a hidden form field), and it reaches a
    filesystem path via staged_attachment_upload_path. Restricting it to hex
    keeps path traversal impossible by construction.
    """
    value = (value or '').strip()
    if len(value) == 32 and all(c in '0123456789abcdef' for c in value):
        return value
    return None


def staged_for(user, token):
    """Files currently held under ``token`` for ``user``.

    Scoped on uploaded_by as well as token: the token travels in a hidden field
    and in the case-mode switch query string, so on its own it is not a secret
    worth trusting. Without the user filter a guessed token would let one
    analyst adopt another's evidence.
    """
    token = _clean_token(token)
    if not token:
        return StagedAttachment.objects.none()
    return StagedAttachment.objects.filter(token=token, uploaded_by=user)


def staged_total_size(user, token):
    """Bytes already staged under ``token``."""
    return sum(f.file.size for f in staged_for(user, token))


def stage_uploads(request, field_name='evidence_files'):
    """Persist ``request.FILES[field_name]`` before the form is validated.

    Returns ``(token, errors)``. ``errors`` is a list of human-readable
    messages naming the offending file — a rejected upload is always reported,
    never silently dropped, because a silently missing piece of evidence is
    worse than a noisy form.

    The token is reused across retries so a resubmit accumulates onto the same
    staging set instead of orphaning the previous one.
    """
    token = _clean_token(request.POST.get('evidence_token')) or new_token()
    uploads = request.FILES.getlist(field_name)
    errors = []

    if not uploads:
        return token, errors

    existing = staged_for(request.user, token)
    running_total = staged_total_size(request.user, token)
    running_count = existing.count()

    for upload in uploads:
        if running_count >= MAX_ATTACHMENT_COUNT:
            errors.append(
                f'แนบไฟล์ได้สูงสุด {MAX_ATTACHMENT_COUNT} ไฟล์ต่อหนึ่งเคส — '
                f'"{upload.name}" และไฟล์ที่เหลือถูกข้ามไป'
            )
            break

        if running_total + upload.size > MAX_ATTACHMENT_BATCH_SIZE:
            limit_mb = MAX_ATTACHMENT_BATCH_SIZE // (1024 * 1024)
            errors.append(
                f'ไฟล์แนบรวมกันเกิน {limit_mb} MB — '
                f'"{upload.name}" ไม่ถูกแนบ'
            )
            continue

        try:
            validate_attachment(upload)
        except ValidationError as exc:
            errors.append(f'"{upload.name}": {exc.messages[0]}')
            continue

        StagedAttachment.objects.create(
            token=token,
            file=upload,
            original_name=upload.name,
            uploaded_by=request.user,
        )
        running_total += upload.size
        running_count += 1

    return token, errors


def _adopt_one(staged, *, ticket=None, project=None, user=None):
    """Copy one staged file onto its permanent attachment row."""
    if ticket is not None:
        attachment = TicketAttachment(
            ticket=ticket, original_name=staged.original_name,
            uploaded_by=user or staged.uploaded_by,
        )
    else:
        attachment = ProjectIncidentAttachment(
            project=project, original_name=staged.original_name,
            uploaded_by=user or staged.uploaded_by,
        )
    # Re-save through the target's own upload_to so the file lands under the
    # ticket / project directory rather than staying in the staging tree.
    staged.file.open('rb')
    try:
        attachment.file.save(staged.original_name, staged.file.file, save=False)
    finally:
        staged.file.close()
    attachment.save()
    return attachment


def adopt_staged(token, user, *, ticket=None, project=None):
    """Move every file staged under ``token`` onto ``ticket`` or ``project``.

    Call inside the creating transaction. The staging *rows* are deleted here so
    a rollback restores them along with everything else, but the underlying
    *files* are only unlinked once the transaction commits — deleting them
    inline would leave a rolled-back row pointing at a file that no longer
    exists, which is the one failure mode that actually loses evidence.
    """
    if (ticket is None) == (project is None):
        raise ValueError('adopt_staged needs exactly one of ticket/project')

    adopted, orphaned = [], []
    for staged in staged_for(user, token):
        adopted.append(
            _adopt_one(staged, ticket=ticket, project=project, user=user)
        )
        orphaned.append((staged.file.storage, staged.file.name))
        staged.delete()

    def _remove_files():
        for storage, name in orphaned:
            storage.delete(name)

    transaction.on_commit(_remove_files)
    return adopted


def discard_staged(user, pk):
    """Remove one staged file. Returns True if something was removed."""
    staged = StagedAttachment.objects.filter(pk=pk, uploaded_by=user).first()
    if staged is None:
        return False
    staged.file.delete(save=False)
    staged.delete()
    return True


def purge_expired(cutoff):
    """Delete staged rows created before ``cutoff``. Returns the count."""
    stale = StagedAttachment.objects.filter(created_at__lt=cutoff)
    removed = 0
    for staged in stale:
        staged.file.delete(save=False)
        staged.delete()
        removed += 1
    return removed


def purge_orphan_files(cutoff):
    """Remove staged files on disk that no longer have a row.

    A file is written before its row is committed, so a crash or rollback in
    between leaves one behind that ``purge_expired`` can never see. Only paths
    under the staging tree are touched, and only ones older than ``cutoff``, so
    a file being written by a request in flight is never pulled out from under
    it. Returns the number of files removed.
    """
    root = Path(settings.MEDIA_ROOT) / 'staged_attachments'
    if not root.is_dir():
        return 0

    known = set(
        StagedAttachment.objects.values_list('file', flat=True)
    )
    deadline = cutoff.timestamp()
    removed = 0

    for token_dir in root.iterdir():
        if not token_dir.is_dir():
            continue
        for path in token_dir.iterdir():
            if not path.is_file():
                continue
            relative = f'staged_attachments/{token_dir.name}/{path.name}'
            if relative in known or path.stat().st_mtime >= deadline:
                continue
            path.unlink()
            removed += 1
        # Tidy the token directory once it has nothing left in it.
        if not any(token_dir.iterdir()):
            token_dir.rmdir()

    return removed
