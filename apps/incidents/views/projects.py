import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.wazuh_ingest.models import WazuhAlert
from ..forms import (
    AttachmentForm, ProjectIncidentForm,
    ProjectIncidentTargetForm, ProjectIncidentTargetFormSet,
)
from ..models import (
    ProjectIncident,
    ProjectIncidentAttachment, Ticket,
    TriageRecord,
)
from ..staging import (
    staged_for, stage_uploads,
)
from .attachments import render_inline_attachment_preview
from ..report_content import GUIDANCE_COORDINATION_NOTE
from ..policies import (
    can_add_project_member as _can_add_project_member,
    can_create_ticket_from_triage as _can_create_ticket_from_triage,
    can_create_ticket_from_wazuh as _can_create_ticket_from_wazuh,
    can_delete_project_attachment as _can_delete_project_attachment,
    can_restore_ticket_attachment as _can_restore_ticket_attachment,
    can_upload_project_attachment as _can_upload_project_attachment,
)
from ..case_creation import (
    create_project_incident_from_forms,
)
from ..project_workflow import (
    MAX_PROJECT_MEMBERS, add_project_member, add_shared_attachments,
    delete_shared_attachment,
    forward_project_review,
    reassess_project_emergency,
    restore_shared_attachment,
)

logger = logging.getLogger('apps.incidents.views')

from ._helpers import (
    _active_threat_guidance,
    _case_switch_qs,
    _attachment_limits,
)


@login_required
def create_project_incident(request):
    """Fan out one multi-system incident into linked member tickets.

    Tier 1 fills the shared incident facts once and lists the affected systems;
    each system becomes a Ticket routed to its own admin (AWAITING_CONTAINMENT),
    all pointing at one ProjectIncident so they stay grouped and trackable.
    """
    profile = getattr(request.user, 'profile', None)
    # TEMP: Tier 2 allowed to open Project Incidents too (revert to is_tier1-only later).
    if not request.user.is_superuser and (
        profile is None or not (profile.is_tier1 or profile.is_tier2)
    ):
        messages.error(request, 'เฉพาะเจ้าหน้าที่ SOC Tier 1 เท่านั้นที่สามารถเปิด Project Incident ได้')
        return redirect('ticket_list')

    # Optional originating Wazuh alert — the analyst arrived here from the
    # triage queue ("Create Project Incident" on a claimed alert). It pre-fills
    # the shared fields and, on success, is linked to the whole bundle.
    source_alert = None
    alert_pk = request.POST.get('wazuh_alert') or request.GET.get('wazuh_alert')
    if alert_pk:
        source_alert = WazuhAlert.objects.filter(pk=alert_pk).first()
        if (source_alert and request.method == 'GET'
                and not _can_create_ticket_from_wazuh(source_alert, request.user)):
            messages.error(request, 'Wazuh Alert นี้ไม่ได้อยู่ในความรับผิดชอบของคุณ หรือถูกดำเนินการไปแล้ว')
            return redirect('triage_queue')

    # Or an originating manual-triage record (analyst came from Manual Triage,
    # "Create Project Incident" on a claimed record). Same idea, different queue.
    source_triage = None
    triage_pk = request.POST.get('triage_id') or request.GET.get('triage_id')
    if triage_pk:
        source_triage = TriageRecord.objects.filter(pk=triage_pk).first()
        if (source_triage and request.method == 'GET'
                and not _can_create_ticket_from_triage(source_triage, request.user)):
            messages.error(request, 'รายการ Manual Triage นี้ไม่พร้อมสำหรับการสร้าง Project Incident')
            return redirect('triage_list')

    if request.method == 'POST':
        shared_form = ProjectIncidentForm(request.POST, request.FILES, user=request.user)
        target_formset = ProjectIncidentTargetFormSet(request.POST, prefix='target')
        # Staged before validation — see create_ticket for why.
        evidence_token, staged_errors = stage_uploads(request)
        for staged_error in staged_errors:
            shared_form.add_error(None, staged_error)
        if shared_form.is_valid() and target_formset.is_valid():
            try:
                result = create_project_incident_from_forms(
                    shared_form=shared_form,
                    target_formset=target_formset,
                    actor=request.user,
                    source_alert=source_alert,
                    source_triage=source_triage,
                    evidence_token=evidence_token,
                )
            except ValidationError as exc:
                shared_form.add_error(None, exc.message)
            else:
                for warning in result.warnings:
                    messages.warning(request, warning)
                messages.success(
                    request,
                    f'สร้าง Project Incident {result.project.project_code} เรียบร้อย — '
                    f'{len(result.tickets)} Ticket ตามระบบที่ได้รับผลกระทบ',
                )
                return redirect('project_incident_detail', pk=result.project.pk)
    else:
        initial = {}
        if source_alert is not None:
            initial['title'] = (source_alert.rule_description or '')[:255]
            initial['issue_description'] = (
                request.GET.get('issue_description') or source_alert.rule_description
            )
            if source_alert.timestamp:
                initial['incident_datetime'] = timezone.localtime(
                    source_alert.timestamp
                ).strftime('%Y-%m-%dT%H:%M')
            if source_alert.alert_id:
                initial['reference_id'] = source_alert.alert_id
        elif source_triage is not None:
            initial['title'] = (source_triage.alert_description or '')[:255]
            initial['issue_description'] = source_triage.alert_description
            if source_triage.source:
                initial['issue_type'] = source_triage.source
            if source_triage.source_reference:
                initial['reference_id'] = source_triage.source_reference
        if request.GET.get('severity'):
            initial['severity'] = request.GET['severity']
        di2 = request.GET.get('detailed_issue2')
        if di2 in dict(Ticket.DETAILED_ISSUE_CHOICES2):
            initial['detailed_issue2'] = di2
            parent = Ticket.parent_of_detailed_issue2(di2)
            if parent:
                initial['detailed_issue'] = parent
        shared_form = ProjectIncidentForm(initial=initial, user=request.user)
        target_formset = ProjectIncidentTargetFormSet(prefix='target')
        evidence_token = request.GET.get('evidence_token', '')

    return render(request, 'incidents/project_incident_form.html', {
        'form': shared_form,
        'target_formset': target_formset,
        'detailed_issue_cascade': Ticket.detailed_issue_cascade(),
        'source_alert': source_alert,
        'source_triage': source_triage,
        'case_mode': 'multi',
        'case_switch_qs': _case_switch_qs(
            source_triage.pk if source_triage else None,
            source_alert.pk if source_alert else None,
            evidence_token,
        ),
        'threat_guidance': _active_threat_guidance(),
        'guidance_note': GUIDANCE_COORDINATION_NOTE,
        'evidence_token': evidence_token,
        'staged_files': staged_for(request.user, evidence_token),
        'attachment_limits': _attachment_limits(),
    })


@login_required
def project_incident_detail(request, pk):
    """Overview of a case bundle: the shared incident and its member tickets."""
    project = get_object_or_404(ProjectIncident, pk=pk)
    profile = getattr(request.user, 'profile', None)
    can_manage_project = request.user.is_superuser or (
        profile is not None and profile.is_soc_manager
    )
    can_add_project_member = _can_add_project_member(project, request.user)
    add_member_form = ProjectIncidentTargetForm(prefix='member')
    show_add_member_modal = False

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'project_mgr_forward':
            assessment = request.POST.get('emergency_assessment', '')
            note = request.POST.get('decision_note', '').strip()
            if not can_manage_project:
                messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่ดำเนินการ Project Review ได้')
            elif project.emergency_decided_at is not None:
                messages.error(request, 'Project Incident นี้ผ่าน Project Review แล้ว')
            elif assessment not in ('normal', 'emergency') or not note:
                messages.error(request, 'กรุณาเลือก Normal หรือ Emergency และกรอกบันทึกการตรวจ')
            else:
                want_emergency = assessment == 'emergency'
                try:
                    result = forward_project_review(
                        project=project,
                        actor=request.user,
                        want_emergency=want_emergency,
                        note=note,
                    )
                except ValidationError as exc:
                    messages.error(request, exc.message)
                else:
                    for warning in result.warnings:
                        messages.warning(request, warning)
                    messages.success(
                        request,
                        'Project Review เสร็จสิ้นและส่งต่อ Member Ticket ที่รอทั้งหมดแล้ว',
                    )
        elif action == 'project_reassess_emergency':
            value = request.POST.get('emergency_value', '') in ('1', 'true', 'True', 'on')
            reason = request.POST.get('emergency_reason', '').strip()
            if not can_manage_project:
                messages.error(request, 'เฉพาะผู้จัดการ SOC เท่านั้นที่ประเมิน Emergency ใหม่ได้')
            elif project.emergency_decided_at is None:
                messages.error(request, 'Project Incident ต้องผ่าน Project Review ก่อน')
            elif not reason:
                messages.error(request, 'กรุณาระบุเหตุผลในการประเมิน Emergency ใหม่')
            else:
                reassess_project_emergency(
                    project=project,
                    actor=request.user,
                    value=value,
                    reason=reason,
                )
                messages.success(request, 'อัปเดต Emergency สำหรับ Member Ticket ที่ยังดำเนินการอยู่แล้ว')
        elif action == 'add_project_member':
            add_member_form = ProjectIncidentTargetForm(request.POST, prefix='member')
            if project.all_closed:
                messages.error(request, 'ไม่สามารถเพิ่มระบบได้ เนื่องจาก Project Incident นี้ปิดครบทุก Ticket แล้ว')
            elif project.member_count >= MAX_PROJECT_MEMBERS:
                messages.error(
                    request,
                    f'Project Incident หนึ่งรายการมี Member Ticket ได้ไม่เกิน {MAX_PROJECT_MEMBERS} ระบบ',
                )
            elif not can_add_project_member:
                messages.error(request, 'เฉพาะผู้เปิด Project Incident หรือผู้จัดการ SOC เท่านั้นที่เพิ่มระบบได้')
            elif add_member_form.is_valid():
                try:
                    result = add_project_member(
                        project=project,
                        target_form=add_member_form,
                        actor=request.user,
                    )
                except ValidationError as exc:
                    add_member_form.add_error(None, exc.message)
                    show_add_member_modal = True
                else:
                    for warning in result.warnings:
                        messages.warning(request, warning)
                    ticket = result.tickets[0]
                    messages.success(
                        request,
                        f'เพิ่มระบบ {ticket.device_name} เป็น {ticket.bundle_ref} เรียบร้อย',
                    )
                    return redirect('project_incident_detail', pk=project.pk)
            else:
                show_add_member_modal = True
        if action != 'add_project_member' or not show_add_member_modal:
            return redirect('project_incident_detail', pk=project.pk)

    members = (
        project.member_tickets.visible_to(request.user)
        .select_related('assigned_admin', 'system_owner', 'project_incident')
        .order_by('bundle_suffix', 'created_at')
    )
    # A user who can see none of the members has no business on the bundle page.
    if not members and not request.user.is_superuser:
        raise Http404('ไม่พบ Project Incident')
    # Shared incident facts (NCSA severity, log source, MITRE) are copied to
    # every member at creation, so the page reads them off one "lead" member.
    # Deliberately taken from the UNSCOPED set: `members` above is filtered by
    # what the viewer may see, so using it made a System Admin who can see only
    # member C read C's values while SOC read A's — the same bundle reporting
    # different severity to different people.
    lead = project.members.first()
    # Soonest contain deadline still running, so the page that exists to
    # coordinate members shows the group's time pressure without opening each
    # ticket. Members deliberately keep independent OLA clocks.
    next_ola_member = (
        project.member_tickets
        .exclude(status__in=Ticket.TERMINAL_STATUSES)
        .filter(classification=Ticket.CLASSIFICATION_INCIDENT)
        .filter(ola_contain_deadline__isnull=False)
        .order_by('ola_contain_deadline')
        .first()
    )
    return render(request, 'incidents/project_incident_detail.html', {
        'project': project,
        'members': members,
        'lead': lead,
        'next_ola_member': next_ola_member,
        'source_triage': project.source_triages.first(),
        'project_logs': project.logs.select_related('author'),
        'can_manage_project': can_manage_project,
        'can_add_project_member': can_add_project_member,
        'add_member_form': add_member_form,
        'show_add_member_modal': show_add_member_modal,
        'project_member_limit': MAX_PROJECT_MEMBERS,
        'can_upload_project_attachment': _can_upload_project_attachment(
            project, request.user),
        'can_restore_project_attachment': _can_restore_ticket_attachment(
            request.user),
        'deleted_attachments': (
            project.attachments.model.all_objects
            .filter(project=project, deleted_at__isnull=False)
            .select_related('deleted_by')
        ),
        'pending_member_count': project.member_tickets.filter(
            status=Ticket.STATUS_PENDING_MGR_TRIAGE,
        ).count(),
    })


@login_required
def download_project_attachment(request, attachment_id):
    """Serve shared Project Incident evidence to any authorized member viewer.

    Same hardening as download_attachment: forced download plus nosniff so an
    uploaded .html/.svg can never execute same-origin, and 404 rather than 403
    so the id space isn't enumerable. The default manager is active-only, so a
    soft-deleted file 404s here exactly like a removed ticket attachment.
    """
    attachment = get_object_or_404(ProjectIncidentAttachment, pk=attachment_id)
    if not attachment.project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')
    response = FileResponse(
        attachment.file.open('rb'),
        as_attachment=True,
        filename=attachment.original_name,
    )
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@login_required
def preview_project_attachment(request, attachment_id):
    """Render one shared bundle attachment inline, in its own tab.

    Same authorization as download_project_attachment (the viewer must be able to
    see a member ticket), and the same safe rendering as preview_attachment —
    images re-encoded to a data: URI, text shown autoescaped. Only image and
    text/log/CSV files preview; anything else 404s.
    """
    attachment = get_object_or_404(ProjectIncidentAttachment, pk=attachment_id)
    if not attachment.project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')
    return render_inline_attachment_preview(
        request, attachment, extra_ctx={'project': attachment.project},
    )


@login_required
def upload_project_attachment(request, pk):
    """Add shared evidence to a bundle after it was opened.

    Mirrors upload_attachment: same AttachmentForm, so the batch multi-file
    handling and per-file validation are literally the same code path.
    """
    project = get_object_or_404(ProjectIncident, pk=pk)
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบ Project Incident')

    if not _can_upload_project_attachment(project, request.user):
        messages.error(
            request,
            'คุณไม่มีสิทธิ์แนบไฟล์ในกลุ่มนี้ หรือทุกระบบถูกปิดแล้ว',
        )
        return redirect('project_incident_detail', pk=project.pk)

    if request.method == 'POST':
        form = AttachmentForm(request.POST, request.FILES)
        if form.is_valid():
            description = form.cleaned_data.get('description', '')
            uploads = form.cleaned_data['file']
            result = add_shared_attachments(
                project=project,
                actor=request.user,
                uploads=uploads,
                description=description,
            )
            if len(result.attachments) == 1:
                messages.success(
                    request,
                    f'อัพโหลด "{result.attachments[0].original_name}" เรียบร้อยแล้ว',
                )
            else:
                messages.success(request, f'อัพโหลด {len(result.attachments)} ไฟล์เรียบร้อยแล้ว')
        else:
            detail = '; '.join(
                msg for errors in form.errors.values() for msg in errors
            )
            messages.error(
                request,
                f'ไม่สามารถอัพโหลดไฟล์ได้ — {detail}' if detail
                else 'ไม่สามารถอัพโหลดไฟล์ได้ — กรุณาตรวจสอบไฟล์อีกครั้ง',
            )
    return redirect('project_incident_detail', pk=project.pk)


@login_required
@require_POST
def delete_project_attachment(request, attachment_id):
    """Soft-delete shared bundle evidence, with a required reason."""
    att = get_object_or_404(ProjectIncidentAttachment, pk=attachment_id)
    project = att.project
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')

    if not _can_delete_project_attachment(project, att, request.user):
        # Logged, not written to the project timeline: anyone who can see the
        # bundle could otherwise flood it by probing. Same call as the ticket
        # attachment path.
        logger.warning(
            'Refused project attachment delete: user=%s attachment=%s project=%s',
            request.user.pk, att.pk, project.project_code,
        )
        messages.error(
            request,
            'คุณไม่มีสิทธิ์ลบไฟล์นี้ หรือทุกระบบในกลุ่มถูกปิดแล้ว — '
            'หลักฐานของเคสที่ปิดแล้วจะถูกล็อกไว้',
        )
        return redirect('project_incident_detail', pk=project.pk)

    reason = (request.POST.get('reason') or '').strip()
    if not reason:
        messages.error(request, 'กรุณาระบุเหตุผลในการลบไฟล์')
        return redirect('project_incident_detail', pk=project.pk)

    delete_shared_attachment(attachment=att, actor=request.user, reason=reason)
    messages.success(request, 'ลบไฟล์เรียบร้อยแล้ว — ผู้จัดการ SOC สามารถกู้คืนได้')
    return redirect('project_incident_detail', pk=project.pk)


@login_required
@require_POST
def restore_project_attachment(request, attachment_id):
    """Bring back group evidence removed by mistake. SOC Manager only.

    Not gated on all_closed, unlike deletion: refusing removal on a finished
    bundle protects the evidence set, but refusing recovery would only make a
    mistake permanent. Same reasoning as restore_attachment.
    """
    att = get_object_or_404(
        ProjectIncidentAttachment.all_objects,
        pk=attachment_id, deleted_at__isnull=False,
    )
    project = att.project
    if not project.member_tickets.visible_to(request.user).exists():
        raise Http404('ไม่พบไฟล์แนบ')

    if not _can_restore_ticket_attachment(request.user):
        logger.warning(
            'Refused project attachment restore: user=%s attachment=%s project=%s',
            request.user.pk, att.pk, project.project_code,
        )
        messages.error(request, 'กู้คืนไฟล์ได้เฉพาะผู้จัดการ SOC เท่านั้น')
        return redirect('project_incident_detail', pk=project.pk)

    restore_shared_attachment(attachment=att, actor=request.user)
    messages.success(request, 'กู้คืนไฟล์เรียบร้อยแล้ว')
    return redirect('project_incident_detail', pk=project.pk)
