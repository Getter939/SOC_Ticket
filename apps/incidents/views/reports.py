import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from ..models import (
    Ticket,
)
from ..report_content import REMEDIATION_CHECKLIST
from ..reports import (
    build_ticket_report_render_context,
    generate_ticket_report,
    generate_ticket_report_pdf,
)
from ..policies import (
    can_access_ticket_report as _can_access_ticket_report,
)

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
