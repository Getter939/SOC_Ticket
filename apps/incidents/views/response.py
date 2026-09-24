import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from ..forms import (
    ResponseRequestForm,
    SubtaskUpdateForm,
)
from ..models import (
    Ticket,
    TicketSubtask, validate_attachment,
)
from ..policies import (
    can_accept_subtask as _can_accept_subtask,
    can_change_subtask_status as _can_change_subtask_status,
    can_upload_subtask_result as _can_upload_subtask_result,
    can_update_subtask as _can_update_subtask,
    response_request_updates_frozen as _response_request_updates_frozen,
)
from ..subtask_creation import (
    create_response_request as create_response_request_operation,
)
from ..ticket_updates import save_subtask_update

logger = logging.getLogger('apps.incidents.views')



# ── Subtask views (response-team requests) ─────────────────────────────── #

@login_required
@require_POST
def create_response_request(request, pk):
    """SOC Manager spawns a response-team request (VA/PT, InfraSec, Forensics).

    The type fixes the receiving role; the assignee is resolved here:
    auto-assigned when a single active role-holder exists, taken from the
    picker when several do, and blocked when none exist.
    """
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    profile = getattr(request.user, 'profile', None)
    is_manager = request.user.is_superuser or (profile is not None and profile.is_soc_manager)
    if not is_manager:
        messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่สามารถส่งคำขอทีมตอบสนองได้')
        return redirect('ticket_detail', pk=pk)
    if ticket.status in Ticket.TERMINAL_STATUSES:
        messages.error(request, 'Ticket นี้ปิดแล้ว — ส่งคำขอทีมตอบสนองไม่ได้')
        return redirect('ticket_detail', pk=pk)

    form = ResponseRequestForm(request.POST)
    if not form.is_valid():
        messages.error(request, 'ไม่สามารถส่งคำขอได้ — กรุณาตรวจสอบข้อมูล')
        return redirect('ticket_detail', pk=pk)

    try:
        result = create_response_request_operation(
            ticket=ticket,
            actor=request.user,
            response_form=form,
        )
    except ValidationError as exc:
        messages.error(request, exc.message)
        return redirect('ticket_detail', pk=pk)

    if not result.notification_sent:
        messages.warning(
            request,
            'สร้างคำขอแล้ว แต่ส่งอีเมลแจ้งผู้รับผิดชอบไม่สำเร็จ',
        )
    messages.success(
        request,
        f'ส่งคำขอ "{result.subtask.get_subtask_type_display()}" ให้ '
        f'{result.subtask.assigned_to.get_full_name() or result.subtask.assigned_to.username} '
        'เรียบร้อยแล้ว',
    )
    return redirect('ticket_detail', pk=pk)


@login_required
def update_subtask(request, subtask_id):
    subtask = get_object_or_404(TicketSubtask, pk=subtask_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=subtask.ticket_id)

    # Freeze first, permission second — the two must not be conflated, or a user
    # who simply lacks permission is wrongly told "the item is closed" whenever
    # the ticket happens to be terminal (e.g. a response request on a CLOSED_EVENT
    # ticket, which is deliberately still open for its assignee to finish).
    if _response_request_updates_frozen(subtask):
        messages.error(request, 'รายการนี้ปิดหรือยกเลิกแล้ว ไม่สามารถเพิ่มไฟล์หรืออัปเดตงานย่อยได้')
        return redirect('ticket_detail', pk=ticket.pk)
    if not _can_update_subtask(subtask, request.user):
        messages.error(request, 'คุณไม่มีสิทธิ์อัปเดตงานย่อยนี้')
        return redirect('ticket_detail', pk=ticket.pk)

    if request.method == 'POST':
        was_done = subtask.is_done
        previous_status = subtask.status
        # Result notes are freely overwritable by any SOC member and previously
        # left no audit at all, so a forensic analyst's findings could be
        # replaced silently. Capture what was there first.
        previous_notes = subtask.result_notes
        previous_report_number = subtask.report_number
        # Status and report number are gated more tightly than notes: see
        # can_change_subtask_status. Refuse the whole POST (notes and file
        # included) rather than silently saving part of it with those dropped.
        posted_number = request.POST.get('report_number')
        if not _can_change_subtask_status(subtask, request.user) and (
            request.POST.get('status', subtask.status) != subtask.status
            or (posted_number is not None and posted_number.strip() != subtask.report_number)
        ):
            messages.error(
                request,
                'เปลี่ยนสถานะหรือเลขที่รายงานของคำขอนี้ได้เฉพาะผู้รับผิดชอบคำขอ '
                'หรือผู้จัดการ SOC เท่านั้น — ไม่มีการบันทึกข้อมูล',
            )
            return redirect('ticket_detail', pk=ticket.pk)
        form = SubtaskUpdateForm(request.POST, instance=subtask)
        if form.is_valid():
            # Optional deliverable file (e.g. VA/PT scan output), linked to both
            # the subtask and its ticket so it serves through the hardened
            # download_attachment path. Gated more tightly than the notes/status
            # update above: can_update lets any SOC member edit a request, but
            # only the assignee, a SOC manager, or a superuser may put a file on
            # the ticket through this route. A Forensics / RCA request takes no
            # file at all — its report is a physical document the SOC Manager
            # collects, recorded here only by its report number.
            upload = (
                request.FILES.get('result_file') if subtask.accepts_result_file
                else None
            )
            result_upload = None
            if upload is not None:
                if not _can_upload_subtask_result(subtask, request.user):
                    messages.error(
                        request,
                        'คุณไม่มีสิทธิ์แนบไฟล์ผลการดำเนินการของคำขอนี้ '
                        '— บันทึกข้อความถูกจัดเก็บแล้ว แต่ไฟล์ไม่ถูกแนบ',
                    )
                else:
                    try:
                        validate_attachment(upload)
                        result_upload = upload
                    except ValidationError as e:
                        messages.error(request, e.message)

            try:
                subtask = save_subtask_update(
                    ticket=ticket,
                    actor=request.user,
                    update_form=form,
                    previous_status=previous_status,
                    previous_notes=previous_notes,
                    was_done=was_done,
                    previous_report_number=previous_report_number,
                    result_upload=result_upload,
                    result_description=request.POST.get('result_file_desc', '').strip(),
                ).subtask
            except ValidationError as exc:
                messages.error(request, ' '.join(exc.messages))
                return redirect('ticket_detail', pk=ticket.pk)

            messages.success(request, f'อัปเดตงานย่อย "{subtask.title}" เรียบร้อยแล้ว')
        else:
            errors = form.errors.get('report_number')
            messages.error(
                request,
                errors[0] if errors else 'ไม่สามารถอัปเดตงานย่อยได้ — กรุณาตรวจสอบข้อมูล',
            )
    return redirect('ticket_detail', pk=ticket.pk)


def _request_page_url(subtask, user):
    """Where a request link lands: the assignee's own "งานของคุณ" card at the
    top of the ticket, or the request list for everyone else."""
    anchor = 'my-request' if subtask.assigned_to_id == user.pk else 'tasks'
    return f"{reverse('ticket_detail', args=[subtask.ticket_id])}#{anchor}"


@login_required
@require_POST
def accept_subtask(request, subtask_id):
    """รับงาน — the assignee acknowledges a response request (OPEN → IN_PROGRESS).

    One click instead of picking a status in the update form, so the SOC Manager
    can see at a glance that the request was seen and started. Goes through
    save_subtask_update so the status history and status_changed_at are written
    exactly as for any other status change. Sends no email.
    """
    subtask = get_object_or_404(TicketSubtask, pk=subtask_id)
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=subtask.ticket_id)
    back = request.POST.get('next', '')
    if not url_has_allowed_host_and_scheme(
        back, allowed_hosts={request.get_host()}, require_https=request.is_secure(),
    ):
        back = f"{reverse('ticket_detail', args=[ticket.pk])}#my-request"

    # Same freeze-then-permission order as update_subtask.
    if _response_request_updates_frozen(subtask):
        messages.error(request, 'รายการนี้ปิดหรือยกเลิกแล้ว ไม่สามารถรับงานได้')
        return redirect(back)
    if not _can_accept_subtask(subtask, request.user):
        messages.error(request, 'รับงานได้เฉพาะผู้รับผิดชอบ และเฉพาะคำขอที่ยังเปิดอยู่เท่านั้น')
        return redirect(back)

    form = SubtaskUpdateForm(
        {
            'status': TicketSubtask.STATUS_IN_PROGRESS,
            'result_notes': subtask.result_notes,
            'report_number': subtask.report_number,
        },
        instance=subtask,
    )
    if not form.is_valid():  # pragma: no cover — IN_PROGRESS never fails validation
        messages.error(request, 'ไม่สามารถรับงานได้ — กรุณาลองใหม่')
        return redirect(back)
    try:
        save_subtask_update(
            ticket=ticket,
            actor=request.user,
            update_form=form,
            previous_status=TicketSubtask.STATUS_OPEN,
            previous_notes=subtask.result_notes,
            was_done=False,
            previous_report_number=subtask.report_number,
        )
    except ValidationError as exc:
        messages.error(request, ' '.join(exc.messages))
        return redirect(back)
    messages.success(request, f'รับงาน "{subtask.title}" แล้ว — สถานะ: กำลังดำเนินการ')
    return redirect(back)


@login_required
def legacy_rca_workspace(request, subtask_id):
    """The RCA workspace was retired (the report is now written outside the
    system); an old emailed link lands on the request's ticket instead."""
    subtask = get_object_or_404(
        TicketSubtask,
        pk=subtask_id,
        ticket__in=Ticket.objects.visible_to(request.user),
    )
    return redirect(_request_page_url(subtask, request.user))


@login_required
def response_request_queue(request):
    """'My Requests' — the response-team member's work queue of requests routed
    to them. Forensic Analysts see Forensics/RCA; Red Team Managers see VA/PT and
    InfraSec. SOC/superusers get an all-team overview."""
    profile = getattr(request.user, 'profile', None)
    is_response = profile is not None and profile.is_response_team
    is_overview = request.user.is_superuser or (profile is not None and profile.is_soc)
    if not (is_response or is_overview):
        messages.error(request, 'หน้านี้สำหรับทีมตอบสนองเท่านั้น')
        return redirect('ticket_list')

    requests_qs = (
        TicketSubtask.objects
        .filter(subtask_type__in=TicketSubtask.RESPONSE_TYPES)
        .select_related('ticket', 'assigned_to', 'created_by')
        .order_by('status', '-created_at')
    )
    if is_response and not is_overview:
        # Both conditions matter. assigned_to alone would surface a request of
        # another team's type that was mis-assigned by a seed, a data migration,
        # or the admin — the queue must not be the place that invariant is
        # discovered. Mirrors the same filter in TicketQuerySet.visible_to().
        requests_qs = requests_qs.filter(
            assigned_to=request.user,
            subtask_type__in=TicketSubtask.types_for_role(profile.role),
        )

    status_filter = request.GET.get('status', '').strip()
    if status_filter in dict(TicketSubtask.STATUS_CHOICES):
        requests_qs = requests_qs.filter(status=status_filter)
    else:
        status_filter = ''

    requests = list(requests_qs)
    open_count = sum(1 for s in requests if s.status not in TicketSubtask.TERMINAL_STATUSES)
    # Every request type is worked on its ticket; the RCA report itself is
    # written outside the system.
    for req in requests:
        req.work_url = _request_page_url(req, request.user)
        req.can_accept = _can_accept_subtask(req, request.user)

    return render(request, 'incidents/response_request_queue.html', {
        'requests': requests,
        'status_filter': status_filter,
        'status_choices': TicketSubtask.STATUS_CHOICES,
        'open_count': open_count,
        'is_overview': is_overview and not is_response,
    })
