"""HTTP workflow for the Forensic Analyst RCA workspace."""

from io import BytesIO

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from . import rca as rca_service
from .forms import (
    RCAAssetFormSet,
    RCAFinalSubmissionForm,
    RCAIndicatorFormSet,
    RCARecommendationFormSet,
    RCARootCauseFormSet,
    RCASection1Form,
    RCATimelineFormSet,
    RCATimelineImportForm,
    SubtaskUpdateForm,
)
from .models import RCAIndicator, RCAReport, Ticket, TicketSubtask
from .policies import (
    can_edit_rca,
    can_generate_rca_draft,
    can_push_rca_iocs,
    can_view_rca,
)
from .reports import REPORT_CONTENT_TYPE
from .selectors import get_rca_case_context
from .ticket_updates import save_subtask_update


SECTIONS = (
    ('general', 'ข้อมูลทั่วไป', '1'),
    ('assets', 'ทรัพย์สินที่ได้รับผลกระทบ', '4'),
    ('timeline', 'ลำดับเวลาเหตุการณ์', '5'),
    ('root-causes', 'Root Cause', '6.2'),
    ('iocs', 'IOC', '7'),
    ('recommendations', 'คำแนะนำ', '8'),
    ('final', 'ส่งรายงานและปิดงาน', '✓'),
)
SECTION_KEYS = frozenset(item[0] for item in SECTIONS)


def _workspace_url(subtask, section):
    return f'{reverse("rca_workspace", args=[subtask.pk])}?section={section}'


def _load_workspace(subtask_id, user):
    subtask = get_object_or_404(
        TicketSubtask.objects.select_related('ticket', 'assigned_to__profile'),
        pk=subtask_id,
        ticket__in=Ticket.objects.visible_to(user),
    )
    if not can_view_rca(subtask, user):
        raise PermissionDenied
    try:
        report = subtask.rca
    except RCAReport.DoesNotExist:
        report = None
    # An Open request is not started yet: the workspace shows a Start card and
    # creates nothing, so merely opening it (even a manager reading) does not
    # begin the work. Editors start it explicitly via rca_start. Once it is In
    # Progress or beyond, an editor auto-gets the report (covers a request moved
    # to In Progress before this UI existed).
    if (
        report is None
        and can_edit_rca(subtask, user)
        and subtask.status != TicketSubtask.STATUS_OPEN
    ):
        report, _created = rca_service.get_or_create_rca(subtask, user)
    return subtask, report


def _disable_form(form):
    for field in form.fields.values():
        field.disabled = True
    return form


def _disable_formset(formset):
    for form in formset.forms:
        _disable_form(form)
    return formset


def _ordered_formset_save(formset):
    """Save an inline formset and make its posted row order authoritative."""
    formset.save()
    order = 0
    for form in formset.forms:
        cleaned = getattr(form, 'cleaned_data', None) or {}
        if cleaned.get('DELETE') or not form.instance.pk:
            continue
        model = type(form.instance)
        if hasattr(form.instance, 'order') and form.instance.order != order:
            model.objects.filter(pk=form.instance.pk).update(order=order)
            form.instance.order = order
        order += 1


def _indicator_formsets(report, data=None):
    groups = []
    for category, label in RCAIndicator.CATEGORY_CHOICES:
        prefix = f'ioc-{category}'
        formset = RCAIndicatorFormSet(
            data=data,
            instance=report,
            prefix=prefix,
            queryset=report.indicators.filter(category=category),
            form_kwargs={'category': category},
        )
        groups.append({'category': category, 'label': label, 'formset': formset})
    return groups


def _workflow_step(subtask, report):
    """Which header stepper node is current: start → build → draft → deliver."""
    if subtask.status == TicketSubtask.STATUS_DONE:
        return 'done'
    if report is not None and report.draft_generated_at:
        return 'draft'
    if subtask.status == TicketSubtask.STATUS_IN_PROGRESS:
        return 'build'
    return 'start'


def _section_counts(report):
    if report is None:
        return {}
    return {
        'assets': report.assets.count(),
        'timeline': report.timeline.count(),
        'root-causes': report.root_causes.count(),
        'iocs': report.indicators.count(),
        'recommendations': report.recommendations.count(),
    }


def _workspace_context(
    request,
    subtask,
    report,
    active,
    *,
    bound=None,
    ioc_preview=None,
):
    editable = can_edit_rca(subtask, request.user)
    counts = _section_counts(report)
    is_open = subtask.status == TicketSubtask.STATUS_OPEN
    context = {
        'ticket': subtask.ticket,
        'subtask': subtask,
        'rca': report,
        'case': get_rca_case_context(subtask.ticket),
        'case_number': (
            rca_service.case_number(report) if report
            else rca_service.case_number_for(subtask)
        ),
        'active_section': active,
        'sections': [
            {'key': key, 'label': label, 'marker': marker, 'count': counts.get(key)}
            for key, label, marker in SECTIONS
        ],
        'can_edit': editable,
        'can_generate_draft': can_generate_rca_draft(subtask, request.user),
        'can_push_iocs': can_push_rca_iocs(subtask, request.user),
        'ioc_preview': ioc_preview,
        'timeline_max_rows': rca_service.TIMELINE_IMPORT_MAX_ROWS,
        'attachments': subtask.attachments.select_related('uploaded_by'),
        'is_open': is_open,
        'workflow_step': _workflow_step(subtask, report),
        'idle_seconds': settings.SESSION_COOKIE_AGE,
    }
    if report is None:
        # Open (not started) or a read-only viewer before the analyst starts:
        # the template shows the Start card / a waiting notice, no section forms.
        return context

    bound = bound or {}
    if active == 'general':
        form = bound.get('form') or RCASection1Form(instance=report, prefix='general')
        context['form'] = form if editable else _disable_form(form)
    elif active == 'assets':
        formset = bound.get('formset') or RCAAssetFormSet(instance=report, prefix='assets')
        context['formset'] = formset if editable else _disable_formset(formset)
    elif active == 'timeline':
        formset = bound.get('formset') or RCATimelineFormSet(instance=report, prefix='timeline')
        context['formset'] = formset if editable else _disable_formset(formset)
        context['import_form'] = bound.get('import_form') or RCATimelineImportForm()
    elif active == 'root-causes':
        formset = bound.get('formset') or RCARootCauseFormSet(
            instance=report, prefix='root-causes',
        )
        context['formset'] = formset if editable else _disable_formset(formset)
    elif active == 'iocs':
        groups = bound.get('indicator_groups') or _indicator_formsets(report)
        if not editable:
            for group in groups:
                _disable_formset(group['formset'])
        context['indicator_groups'] = groups
    elif active == 'recommendations':
        formset = bound.get('formset') or RCARecommendationFormSet(
            instance=report,
            prefix='recommendations',
            form_kwargs={'rca': report},
        )
        context['formset'] = formset if editable else _disable_formset(formset)
    elif active == 'final':
        context['final_form'] = bound.get('final_form') or RCAFinalSubmissionForm(initial={
            'result_notes': subtask.result_notes,
            'result_file_desc': 'รายงาน RCA ฉบับสมบูรณ์',
        })
    return context


def _render_workspace(request, subtask, report, active, **kwargs):
    return render(
        request,
        'incidents/rca_workspace.html',
        _workspace_context(request, subtask, report, active, **kwargs),
    )


@login_required
def rca_workspace(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    active = request.GET.get('section', 'general')
    if active not in SECTION_KEYS:
        active = 'general'
    if request.method != 'POST':
        return _render_workspace(request, subtask, report, active)
    if not can_edit_rca(subtask, request.user) or report is None:
        raise PermissionDenied

    active = request.POST.get('section', active)
    if active not in SECTION_KEYS - {'final'}:
        raise PermissionDenied

    if active == 'general':
        form = RCASection1Form(request.POST, instance=report, prefix='general')
        if form.is_valid():
            with transaction.atomic():
                form.save()
                rca_service.record_edit(
                    report, request.user, rca_service.SECTION_GENERAL, 'บันทึกข้อมูลทั่วไป',
                )
            messages.success(request, 'บันทึกข้อมูลทั่วไปแล้ว')
            return redirect(_workspace_url(subtask, 'general'))
        bound = {'form': form}
    else:
        definitions = {
            'assets': (RCAAssetFormSet, 'assets', rca_service.SECTION_ASSETS),
            'timeline': (RCATimelineFormSet, 'timeline', rca_service.SECTION_TIMELINE),
            'root-causes': (
                RCARootCauseFormSet, 'root-causes', rca_service.SECTION_ROOT_CAUSES,
            ),
            'recommendations': (
                RCARecommendationFormSet,
                'recommendations',
                rca_service.SECTION_RECOMMENDATIONS,
            ),
        }
        if active == 'iocs':
            groups = _indicator_formsets(report, request.POST)
            if all(group['formset'].is_valid() for group in groups):
                try:
                    with transaction.atomic():
                        for group in groups:
                            _ordered_formset_save(group['formset'])
                        rca_service.record_edit(
                            report,
                            request.user,
                            rca_service.SECTION_INDICATORS,
                            f'บันทึก IOC {report.indicators.count()} รายการ',
                        )
                except IntegrityError:
                    # A last-ditch guard: clean_value normalises so the formset
                    # catches most duplicates, but a concurrent save can still
                    # collide on (rca, category, value). Report it, don't 500.
                    messages.error(request, 'มี IOC ซ้ำในหมวดเดียวกัน กรุณาตรวจสอบ')
                    return _render_workspace(
                        request, subtask, report, 'iocs',
                        bound={'indicator_groups': _indicator_formsets(report)},
                    )
                messages.success(request, 'บันทึก IOC แล้ว')
                return redirect(_workspace_url(subtask, 'iocs'))
            bound = {'indicator_groups': groups}
        else:
            formset_class, prefix, audit_label = definitions[active]
            kwargs = {'form_kwargs': {'rca': report}} if active == 'recommendations' else {}
            formset = formset_class(
                request.POST, instance=report, prefix=prefix, **kwargs,
            )
            if formset.is_valid():
                with transaction.atomic():
                    _ordered_formset_save(formset)
                    count = formset.model.objects.filter(rca=report).count()
                    rca_service.record_edit(
                        report, request.user, audit_label, f'บันทึก {count} รายการ',
                    )
                messages.success(request, 'บันทึกข้อมูลในส่วนนี้แล้ว')
                return redirect(_workspace_url(subtask, active))
            bound = {'formset': formset}
    messages.error(request, 'บันทึกไม่ได้ กรุณาตรวจสอบช่องที่ระบุ')
    return _render_workspace(request, subtask, report, active, bound=bound)


@login_required
@require_POST
def rca_start(request, subtask_id):
    """The workspace's "Start RCA" button: create + prefill the report and move
    the request Open → In Progress, then land on Section 1."""
    subtask, _report = _load_workspace(subtask_id, request.user)
    if not can_edit_rca(subtask, request.user):
        raise PermissionDenied
    rca_service.start_rca(subtask, request.user)
    messages.success(request, 'เริ่มจัดทำรายงาน RCA แล้ว')
    return redirect(_workspace_url(subtask, 'general'))


@login_required
@require_POST
def rca_section1_refresh(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_edit_rca(subtask, request.user):
        raise PermissionDenied
    rca_service.refresh_section1_from_ticket(report, request.user)
    messages.success(request, 'ดึงข้อมูลทั่วไปจาก Ticket ล่าสุดแล้ว')
    return redirect(_workspace_url(subtask, 'general'))


@login_required
def rca_timeline_template(request, subtask_id):
    _subtask, _report = _load_workspace(subtask_id, request.user)
    content = '\ufeff' + rca_service.timeline_csv_template()
    response = HttpResponse(content, content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="rca_timeline_template.csv"'
    return response


@login_required
@require_POST
def rca_timeline_import(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_edit_rca(subtask, request.user):
        raise PermissionDenied
    form = RCATimelineImportForm(request.POST, request.FILES)
    if form.is_valid():
        try:
            count = rca_service.import_timeline_csv(
                report, form.cleaned_data['timeline_file'], request.user,
            )
        except ValidationError as exc:
            for error in exc.messages:
                messages.error(request, error)
        else:
            messages.success(request, f'นำเข้า Timeline {count} แถวแล้ว')
    else:
        messages.error(request, 'กรุณาเลือกไฟล์ CSV หรือ TSV')
    return redirect(_workspace_url(subtask, 'timeline'))


@login_required
@require_POST
def rca_iocs_pull(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_edit_rca(subtask, request.user):
        raise PermissionDenied
    count = rca_service.pull_ticket_iocs(report, request.user)
    if count:
        messages.success(request, f'ดึง IOC ใหม่จาก Ticket {count} รายการแล้ว')
    else:
        messages.info(request, 'ไม่มี IOC ใหม่ใน Ticket')
    return redirect(_workspace_url(subtask, 'iocs'))


@login_required
def rca_iocs_push(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_push_rca_iocs(subtask, request.user):
        raise PermissionDenied
    if request.method == 'POST':
        outcomes = rca_service.push_iocs(report, request.user)
        messages.success(
            request,
            f'ส่ง IOC แล้ว: สร้างใหม่ {outcomes["created"]}, '
            f'กู้คืน {outcomes["restored"]}, ซ้ำ {outcomes["duplicate"]}',
        )
        return redirect(_workspace_url(subtask, 'iocs'))
    return _render_workspace(
        request,
        subtask,
        report,
        'iocs',
        ioc_preview=rca_service.classify_ioc_push(report),
    )


@login_required
@require_POST
def rca_draft(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_generate_rca_draft(subtask, request.user):
        raise PermissionDenied
    filename, content = rca_service.generate_rca_draft(report, request.user)
    return FileResponse(
        BytesIO(content),
        as_attachment=True,
        filename=filename,
        content_type=REPORT_CONTENT_TYPE,
    )


@login_required
@require_POST
def rca_final_submission(request, subtask_id):
    subtask, report = _load_workspace(subtask_id, request.user)
    if report is None or not can_edit_rca(subtask, request.user):
        raise PermissionDenied
    form = RCAFinalSubmissionForm(request.POST, request.FILES)
    if not form.is_valid():
        messages.error(request, 'บันทึกส่วนส่งมอบไม่ได้ กรุณาตรวจสอบข้อมูล')
        return _render_workspace(
            request, subtask, report, 'final', bound={'final_form': form},
        )

    complete = request.POST.get('complete') == '1'
    # Snapshot BEFORE building SubtaskUpdateForm: its is_valid() runs _post_clean,
    # which writes the submitted status/notes onto this same subtask instance.
    # Reading them afterwards would report the NEW values — corrupting the audit
    # diff and, worse, making was_done look True so the completion email to SOC
    # Managers is silently skipped.
    previous_status = subtask.status
    previous_notes = subtask.result_notes
    was_done = subtask.is_done

    status = TicketSubtask.STATUS_DONE if complete else previous_status
    update_form = SubtaskUpdateForm(
        {'status': status, 'result_notes': form.cleaned_data['result_notes']},
        instance=subtask,
    )
    if not update_form.is_valid():
        messages.error(request, 'ไม่สามารถอัปเดตสถานะคำขอได้')
        return _render_workspace(
            request, subtask, report, 'final', bound={'final_form': form},
        )

    upload = form.cleaned_data.get('result_file')
    save_subtask_update(
        ticket=subtask.ticket,
        actor=request.user,
        update_form=update_form,
        previous_status=previous_status,
        previous_notes=previous_notes,
        was_done=was_done,
        result_upload=upload,
        result_description=form.cleaned_data['result_file_desc'],
    )
    if complete:
        messages.success(request, 'ส่งมอบรายงานและปิดคำขอ RCA แล้ว')
    else:
        if previous_status == TicketSubtask.STATUS_OPEN:
            rca_service.start_request(subtask, request.user)
        messages.success(request, 'บันทึกผลการดำเนินการแล้ว')
    return redirect(_workspace_url(subtask, 'final'))
