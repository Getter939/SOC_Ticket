import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, QueryDict, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from ..models import (
    Ticket,
)
from ..report_content import REMEDIATION_CHECKLIST
from ..reports import (
    build_ticket_report_render_context,
    generate_ticket_report,
    generate_ticket_report_pdf,
    stream_ticket_reports_zip,
)
from ..policies import (
    can_access_ticket_report as _can_access_ticket_report,
    can_bulk_export_ticket_reports as _can_bulk_export_ticket_reports,
)
from ._helpers import BULK_REPORT_LIMIT, _filter_open_tickets

logger = logging.getLogger('apps.incidents.views')



def _hide_empty_report_fields(params):
    return params.get('hide_empty', '1') != '0'


def _show_report_signoff(params):
    """Whether the report should print the signature block. Off by default —
    most exports circulate before sign-off, so the blank lines are noise."""
    return params.get('show_signoff', '0') == '1'


def _remediation_checklist_state(ticket):
    """The section-8 fixed checklist as [{key, label, done}], done reflecting the
    keys Tier 2 has already ticked — so the form comes back pre-checked."""
    ticked = set(ticket.remediation_checklist or [])
    return [
        {'key': key, 'label': label, 'done': key in ticked}
        for key, label in REMEDIATION_CHECKLIST
    ]


@login_required
@require_POST
def ticket_report_docx(request, pk):
    if not _can_access_ticket_report(request.user):
        raise Http404
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report(
            pk,
            generated_by=request.user,
            hide_empty=_hide_empty_report_fields(request.POST),
            show_signoff=_show_report_signoff(request.POST),
        )
    except Exception:
        logger.exception('DOCX report generation failed for ticket %s', pk)
        messages.error(request, 'ไม่สามารถสร้างรายงาน DOCX ได้ — โปรดแจ้งผู้ดูแลระบบ')
        return redirect('ticket_detail', pk=pk)
    return FileResponse(
        report.as_file(),
        as_attachment=True,
        filename=report.filename,
        content_type=report.content_type,
    )


@login_required
@require_POST
def ticket_report_pdf(request, pk):
    if not _can_access_ticket_report(request.user):
        raise Http404
    get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    try:
        report = generate_ticket_report_pdf(
            pk,
            generated_by=request.user,
            base_url=request.build_absolute_uri('/'),
            hide_empty=_hide_empty_report_fields(request.POST),
            show_signoff=_show_report_signoff(request.POST),
        )
    except Exception:
        logger.exception('PDF report generation failed for ticket %s', pk)
        messages.error(request, 'ไม่สามารถสร้างรายงาน PDF ได้ — โปรดแจ้งผู้ดูแลระบบ')
        return redirect('ticket_detail', pk=pk)
    return FileResponse(
        report.as_file(),
        as_attachment=True,
        filename=report.filename,
        content_type=report.content_type,
    )


def _bulk_reports_response(request, *, page_name, back_url, filter_open):
    """The bulk PDF export for one list page — see stream_ticket_reports_zip.

    The page posts its own querystring as `query`; `filter_open(params)` must
    rebuild that page's filtered, sorted queryset from it, so the ZIP holds
    exactly the tickets on screen (every page of them, not just the visible 25).
    SOC Manager and Tier 2 only — see policies.can_bulk_export_ticket_reports.
    """
    if not _can_bulk_export_ticket_reports(request.user):
        raise Http404
    query = request.POST.get('query', '')
    params = QueryDict(query)
    back = f'{back_url}?{query}' if query else back_url
    queryset = filter_open(params)
    count = queryset.count()
    if not count:
        messages.warning(request, 'ไม่มีเคสที่ตรงกับตัวกรองให้ส่งออก')
        return redirect(back)
    if count > BULK_REPORT_LIMIT:
        messages.warning(
            request,
            f'ส่งออกได้ครั้งละไม่เกิน {BULK_REPORT_LIMIT} เคส (ตัวกรองนี้มี {count} เคส) — '
            'กรองให้แคบลง เช่น ใช้ช่วงวันที่ที่สั้นลง',
        )
        return redirect(back)
    tickets = list(queryset.values_list('pk', 'ticket_id'))
    # Plain checkbox semantics: an unticked box posts nothing. (The single
    # export's helper reads a missing hide_empty as "on", which a checkbox can't
    # switch off.) The menu ticks hide_empty by default.
    hide_empty = request.POST.get('hide_empty') == '1'
    show_signoff = request.POST.get('show_signoff') == '1'
    logger.info(
        'Bulk PDF export by %s: %s, %d tickets, hide_empty=%s, show_signoff=%s, query=%r',
        request.user.username, page_name, len(tickets), hide_empty, show_signoff, query,
    )
    response = StreamingHttpResponse(
        stream_ticket_reports_zip(
            tickets, generated_by=request.user, base_url=request.build_absolute_uri('/'),
            hide_empty=hide_empty, show_signoff=show_signoff,
        ),
        content_type='application/zip',
    )
    stamp = timezone.localtime().strftime('%Y%m%d-%H%M')
    response['Content-Disposition'] = f'attachment; filename="reports_{page_name}_{stamp}.zip"'
    return response


@login_required
@require_POST
def ticket_list_reports_pdf(request):
    """Bulk PDF export of Active Tickets (not the Manager Queue)."""
    visible = Ticket.objects.visible_to(request.user)
    return _bulk_reports_response(
        request, page_name='active', back_url=reverse('ticket_list'),
        filter_open=lambda params: _filter_open_tickets(
            request, params, visible, date_filter=True).qs,
    )


@login_required
@require_POST
def ticket_history_reports_pdf(request):
    """Bulk PDF export of Ticket History."""
    from .history import _filter_history
    return _bulk_reports_response(
        request, page_name='history', back_url=reverse('ticket_history'),
        filter_open=lambda params: _filter_history(request, params).qs,
    )


@login_required
def ticket_report_preview(request, pk):
    if not _can_access_ticket_report(request.user):
        raise Http404
    ticket = get_object_or_404(Ticket.objects.visible_to(request.user), pk=pk)
    return render(
        request,
        'incidents/report_preview.html',
        build_ticket_report_render_context(
            ticket,
            hide_empty=_hide_empty_report_fields(request.GET),
            show_signoff=_show_report_signoff(request.GET),
        ),
    )
