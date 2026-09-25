import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db.models import Count, Q, Value
from django.db.models.functions import Lower, NullIf
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
    TicketSubtask,
)
from ..policies import (
    can_accept_subtask as _can_accept_subtask,
    can_change_subtask_status as _can_change_subtask_status,
    can_update_subtask as _can_update_subtask,
    response_request_updates_frozen as _response_request_updates_frozen,
)
from ..subtask_creation import (
    create_response_request as create_response_request_operation,
)
from ..ticket_updates import save_subtask_update
from ._helpers import (
    _by,
    _choice_label_expr,
    _choice_order_expr,
    _column_sort_headers,
    _filter_chip,
    _person_name_expr,
)

logger = logging.getLogger('apps.incidents.views')


# ── Response Requests queue: sortable columns ─────────────────────────── #
# (label, first-click sort, second-click sort, first click ascending?, th class)
# — see _helpers._column_sort_headers. ผู้รับผิดชอบ only shows in the all-team
# overview. Sorting is by what each cell shows: the type LABEL, the status in
# workflow order, people by full name; blank report numbers sort last.
RESPONSE_QUEUE_COLUMNS = (
    ('ประเภท', 'type', '-type', True, ''),
    ('หัวข้อคำขอ', 'title', '-title', True, ''),
    ('เคส', '-ticket', 'ticket', False, ''),
    ('ผู้รับผิดชอบ', 'assignee', '-assignee', True, ''),
    ('ผู้ร้องขอ', 'requester', '-requester', True, ''),
    ('วันที่', 'newest', 'oldest', False, ''),
    ('สถานะ', 'status', '-status', True, ''),
    ('เลขที่รายงาน', 'report', '-report', True, ''),
    ('', None, None, True, ''),
)
_RQ_TIE = ('-created_at', '-pk')
RESPONSE_QUEUE_SORTS = {
    # Default: open work first (workflow order), newest within each status.
    'status': (_choice_order_expr('status', TicketSubtask), *_RQ_TIE),
    '-status': (_choice_order_expr('status', TicketSubtask).desc(), *_RQ_TIE),
    'newest': _RQ_TIE,
    'oldest': ('created_at', 'pk'),
    'type': (_by(_choice_label_expr('subtask_type', TicketSubtask)), *_RQ_TIE),
    '-type': (_by(_choice_label_expr('subtask_type', TicketSubtask), descending=True), *_RQ_TIE),
    'title': (_by(Lower('title')), *_RQ_TIE),
    '-title': (_by(Lower('title'), descending=True), *_RQ_TIE),
    '-ticket': ('-ticket__ticket_id', *_RQ_TIE),
    'ticket': ('ticket__ticket_id', *_RQ_TIE),
    'assignee': (_by(_person_name_expr('assigned_to__')), *_RQ_TIE),
    '-assignee': (_by(_person_name_expr('assigned_to__'), descending=True), *_RQ_TIE),
    'requester': (_by(_person_name_expr('created_by__')), *_RQ_TIE),
    '-requester': (_by(_person_name_expr('created_by__'), descending=True), *_RQ_TIE),
    'report': (_by(NullIf('report_number', Value(''))), *_RQ_TIE),
    '-report': (_by(NullIf('report_number', Value('')), descending=True), *_RQ_TIE),
}
RESPONSE_QUEUE_SORT_OPTIONS = (
    ('status', 'สถานะ (งานค้างก่อน)'),
    ('newest', 'ใหม่สุดก่อน'),
    ('oldest', 'เก่าสุดก่อน'),
)



# ── Subtask views (response-team requests) ─────────────────────────────── #

@login_required
@require_POST
def create_response_request(request, pk):
    """SOC Manager spawns one or more response-team requests.

    Each selected type becomes a separate request. Its assignee is chosen from
    the eligible accounts or auto-assigned when exactly one is eligible.
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
        errors = ' '.join(
            str(error)
            for field_errors in form.errors.values()
            for error in field_errors
        )
        messages.error(request, f'ไม่สามารถส่งคำขอได้ — {errors or "กรุณาตรวจสอบข้อมูล"}')
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
            'สร้างคำขอแล้ว แต่ส่งอีเมลแจ้งผู้รับผิดชอบบางรายไม่สำเร็จ',
        )
    if len(result.subtasks) == 1:
        subtask = result.subtask
        recipient = subtask.assigned_to.get_full_name() or subtask.assigned_to.username
        messages.success(
            request,
            f'ส่งคำขอ "{subtask.get_subtask_type_display()}" ให้ {recipient} เรียบร้อยแล้ว',
        )
    else:
        assignments = '; '.join(
            f'{subtask.get_subtask_type_display()} → '
            f'{subtask.assigned_to.get_full_name() or subtask.assigned_to.username}'
            for subtask in result.subtasks
        )
        messages.success(
            request,
            f'ส่งคำขอ {len(result.subtasks)} รายการเรียบร้อยแล้ว: {assignments}',
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
        # can_change_subtask_status. Refuse the whole POST rather than silently
        # saving only its notes.
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
            try:
                subtask = save_subtask_update(
                    ticket=ticket,
                    actor=request.user,
                    update_form=form,
                    previous_status=previous_status,
                    previous_notes=previous_notes,
                    was_done=was_done,
                    previous_report_number=previous_report_number,
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
    to them. Forensic Analysts see Forensics/RCA; Red Team Managers see their
    designated function and their own historical requests. SOC/superusers get
    an all-team overview."""
    profile = getattr(request.user, 'profile', None)
    is_response = profile is not None and profile.is_response_team
    is_overview = request.user.is_superuser or (profile is not None and profile.is_soc)
    if not (is_response or is_overview):
        messages.error(request, 'หน้านี้สำหรับทีมตอบสนองเท่านั้น')
        return redirect('ticket_list')

    scope_qs = (
        TicketSubtask.objects
        .filter(subtask_type__in=TicketSubtask.RESPONSE_TYPES)
        .select_related('ticket', 'assigned_to', 'created_by')
    )
    visible_types = TicketSubtask.RESPONSE_TYPES
    if is_response and not is_overview:
        # Both conditions matter. assigned_to alone would surface a request of
        # another team's type that was mis-assigned by a seed, a data migration,
        # or the admin — the queue must not be the place that invariant is
        # discovered. Mirrors the same filter in TicketQuerySet.visible_to().
        visible_types = TicketSubtask.types_for_profile(profile)
        scope_qs = scope_qs.filter(
            assigned_to=request.user,
            subtask_type__in=visible_types,
        )
    show_overview = is_overview and not is_response

    # Filter bar (the same one the ticket lists use): free-text search and a
    # type filter; the status pills below count what clicking them would show.
    search = request.GET.get('q', '').strip()
    type_choices = [
        (code, label) for code, label in TicketSubtask.TYPE_CHOICES if code in visible_types
    ]
    type_filter = request.GET.get('type', '').strip()
    if type_filter not in dict(type_choices):
        type_filter = ''
    requests_qs = scope_qs
    if search:
        requests_qs = requests_qs.filter(
            Q(title__icontains=search) | Q(description__icontains=search)
            | Q(ticket__ticket_id__icontains=search) | Q(report_number__icontains=search)
        )
    if type_filter:
        requests_qs = requests_qs.filter(subtask_type=type_filter)

    status_tally = dict(
        requests_qs.order_by().values_list('status').annotate(n=Count('pk')).values_list('status', 'n')
    )
    status_filter = request.GET.get('status', '').strip()
    if status_filter in dict(TicketSubtask.STATUS_CHOICES):
        requests_qs = requests_qs.filter(status=status_filter)
    else:
        status_filter = ''
    status_pills = [{'code': '', 'label': 'ทั้งหมด', 'count': sum(status_tally.values())}] + [
        {'code': code, 'label': label, 'count': status_tally.get(code, 0)}
        for code, label in TicketSubtask.STATUS_CHOICES
    ]

    sort = request.GET.get('sort', 'status').strip()
    if sort not in RESPONSE_QUEUE_SORTS:
        sort = 'status'
    requests = list(requests_qs.order_by(*RESPONSE_QUEUE_SORTS[sort]))
    # "ยังไม่เสร็จ" describes the whole queue, not the filtered slice.
    open_count = scope_qs.exclude(status__in=TicketSubtask.TERMINAL_STATUSES).count()
    # Every request type is worked on its ticket; the RCA report itself is
    # written outside the system.
    for req in requests:
        req.work_url = _request_page_url(req, request.user)
        req.can_accept = _can_accept_subtask(req, request.user)

    filter_chips = []
    if search:
        filter_chips.append(_filter_chip(request, f'ค้นหา: “{search}”', ('q',)))
    if type_filter:
        filter_chips.append(_filter_chip(
            request, f'ประเภท: {dict(type_choices)[type_filter]}', ('type',)))
    columns = [
        column for column in RESPONSE_QUEUE_COLUMNS
        if show_overview or column[1] != 'assignee'
    ]

    return render(request, 'incidents/response_request_queue.html', {
        'requests': requests,
        'status_filter': status_filter,
        'status_choices': TicketSubtask.STATUS_CHOICES,
        'status_pills': status_pills,
        'open_count': open_count,
        'is_overview': show_overview,
        'search': search,
        'type_filter': type_filter,
        'type_choices': type_choices,
        'filter_chips': filter_chips,
        'has_clearable_filters': bool(filter_chips or status_filter),
        'result_count': len(requests),
        'result_total': scope_qs.count(),
        'sort': sort,
        'sort_options': RESPONSE_QUEUE_SORT_OPTIONS,
        'sort_headers': _column_sort_headers(columns, sort),
        'sort_is_from_column': sort not in dict(RESPONSE_QUEUE_SORT_OPTIONS),
    })
