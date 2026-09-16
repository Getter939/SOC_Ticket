"""Read models for incident pages.

Selectors centralize query shape and read-only decoration.  They do not mutate
workflow state and do not construct forms or HTTP responses.
"""

from django.contrib.auth.models import User
from django.db.models import Prefetch

from apps.accounts.models import UserProfile

from .models import (
    Ticket,
    TicketAttachment,
    TicketFieldChange,
    TicketLogRevision,
    TicketSubtask,
)
from .policies import (
    can_delete_ticket_attachment,
    can_edit_rca,
    can_generate_rca_draft,
    can_restore_ticket_attachment,
    can_update_subtask,
)
from .rca import case_number as rca_case_number


def get_ticket_detail_read_model(
    *,
    ticket,
    user,
    can_submit_containment,
    can_request_response,
):
    """Return query-backed context for the ticket detail page.

    The view supplies workflow permissions it already computed for POST
    handling.  This selector owns only data loading, query optimization, and
    per-record presentation flags derived from the shared policy module.
    """
    logs = ticket.logs.select_related('author').prefetch_related(
        Prefetch(
            'revisions',
            queryset=TicketLogRevision.objects.select_related('edited_by'),
        )
    )

    containment_return_log = None
    if can_submit_containment and ticket.logs.filter(
        status_at_time=Ticket.STATUS_CONTAINMENT_REPORTED,
    ).exists():
        containment_return_log = ticket.logs.filter(
            status_at_time=Ticket.STATUS_AWAITING_CONTAINMENT,
        ).select_related('author').first()

    attachments = list(
        ticket.attachments.filter(subtask__isnull=True).select_related('uploaded_by')
    )
    for attachment in attachments:
        attachment.can_delete = can_delete_ticket_attachment(ticket, attachment, user)

    # The RCA child tables are prefetched (not annotated with Count): five
    # Count(distinct=True) aggregates over a single query force a five-way JOIN
    # whose cartesian product Postgres materialises per subtask before DISTINCT
    # collapses it. Prefetching pulls the child rows only for the RCA subtasks
    # that have them, and the summary counts come from len() of the cached lists.
    subtasks = list(ticket.subtasks.select_related(
        'assigned_to', 'created_by', 'rca__draft_generated_by',
    ).prefetch_related(
        'rca__assets', 'rca__timeline', 'rca__root_causes',
        'rca__indicators', 'rca__recommendations',
        Prefetch(
            'attachments',
            queryset=TicketAttachment.objects.select_related('subtask__assigned_to'),
        ),
        Prefetch(
            'field_changes',
            queryset=TicketFieldChange.objects.filter(field_name='status')
            .select_related('changed_by').order_by('changed_at'),
        ),
    ))
    for subtask in subtasks:
        subtask.can_update = can_update_subtask(subtask, user)
        subtask.is_rca_request = subtask.subtask_type == TicketSubtask.TYPE_FORENSIC_RCA
        subtask.rca_can_start = (
            subtask.is_rca_request
            and subtask.status == TicketSubtask.STATUS_OPEN
            and can_edit_rca(subtask, user)
        )
        subtask.rca_report = getattr(subtask, 'rca', None)
        report = subtask.rca_report
        subtask.rca_case_number = rca_case_number(report) if report else ''
        subtask.rca_asset_count = len(report.assets.all()) if report else 0
        subtask.rca_timeline_count = len(report.timeline.all()) if report else 0
        subtask.rca_root_cause_count = len(report.root_causes.all()) if report else 0
        subtask.rca_indicator_count = len(report.indicators.all()) if report else 0
        subtask.rca_recommendation_count = len(report.recommendations.all()) if report else 0
        subtask.can_generate_rca_draft = can_generate_rca_draft(subtask, user)
        for attachment in subtask.attachments.all():
            attachment.can_delete = can_delete_ticket_attachment(ticket, attachment, user)

    response_routing = {}
    response_member_roles = {}
    if can_request_response:
        response_routing = TicketSubtask.response_routing()
        response_member_roles = {
            str(pk): role
            for pk, role in User.objects.filter(
                is_active=True,
                profile__role__in=(
                    UserProfile.ROLE_FORENSIC,
                    UserProfile.ROLE_REDTEAM_MANAGER,
                ),
            ).values_list('pk', 'profile__role')
        }

    can_restore_attachment = can_restore_ticket_attachment(user)
    deleted_attachments = (
        TicketAttachment.all_objects
        .filter(ticket=ticket, deleted_at__isnull=False)
        .select_related('deleted_by').order_by('-deleted_at')
        if can_restore_attachment else []
    )

    alert_links = list(ticket.alert_links.select_related('alert', 'linked_by'))

    return {
        'alert_links': alert_links,
        'logs': logs,
        'containment_return_log': containment_return_log,
        'attachments': attachments,
        'field_changes': ticket.field_changes.exclude(
            subtask__isnull=False,
            field_name='status',
        ).select_related('changed_by', 'subtask')[:50],
        'can_restore_attachment': can_restore_attachment,
        'deleted_attachments': deleted_attachments,
        'response_routing': response_routing,
        'response_member_roles': response_member_roles,
        'subtasks': subtasks,
        'open_subtask_count': sum(not subtask.is_done for subtask in subtasks),
        'evidence_count': len(attachments) + len(alert_links),
    }


def get_rca_case_context(ticket):
    """Read-only case snapshot for the RCA workspace's case panel.

    Gives the analyst the ticket's own record — description, classification,
    indicators, linked alerts and evidence — without leaving the workspace. All
    read-only; the analyst is already authorised to view it (``visible_to``).
    """
    iocs = list(ticket.iocs.all())
    ioc_groups = []
    for ioc in iocs:
        if ioc_groups and ioc_groups[-1]['category'] == ioc.category:
            ioc_groups[-1]['values'].append(ioc.value)
        else:
            ioc_groups.append({
                'category': ioc.category,
                'label': ioc.get_category_display(),
                'values': [ioc.value],
            })

    return {
        'incident_name': ticket.incident_name,
        'classification': ticket.get_classification_display() if ticket.classification else '',
        'severity': ticket.severity,
        'ncsa_severity': ticket.get_ncsa_severity_display() if ticket.ncsa_severity else '',
        'threat_category': ticket.get_detailed_issue_display() if ticket.detailed_issue else '',
        'device_name': ticket.device_name,
        'ip_address': ticket.ip_address,
        'operating_system': ticket.operating_system,
        'asset_owner': ticket.asset_owner,
        'asset_owner_name': ticket.asset_owner_name,
        'log_source': ticket.log_source,
        'reference_id': ticket.reference_id,
        'incident_datetime': ticket.incident_datetime,
        'event_occurred_at': ticket.event_occurred_at,
        'issue_description': ticket.issue_description,
        'ioc_groups': ioc_groups,
        'ioc_user': ticket.ioc_user,
        'ioc_command': ticket.ioc_command,
        'alert_links': list(
            ticket.alert_links.select_related('alert', 'linked_by')
        ),
        'attachments': list(
            ticket.attachments.filter(subtask__isnull=True).select_related('uploaded_by')
        ),
    }
