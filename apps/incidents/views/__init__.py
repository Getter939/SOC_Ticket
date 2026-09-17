"""Incident views (split from the former views.py).

Re-exports every view so ``from . import views`` (urls) and
``from apps.incidents.views import X`` keep working unchanged.
"""
from ._helpers import *  # noqa: F401,F403
from .tickets import *  # noqa: F401,F403
from .projects import *  # noqa: F401,F403
from .attachments import *  # noqa: F401,F403
from .reports import *  # noqa: F401,F403
from .history import *  # noqa: F401,F403
from .triage import *  # noqa: F401,F403
from .search import *  # noqa: F401,F403
from .response import *  # noqa: F401,F403
from .dashboard import *  # noqa: F401,F403

# Private helpers imported by name in the test-suite / other modules.
from ._helpers import (  # noqa: F401
    _transition_actions, _valid_soc_status_choices,
    _active_threat_guidance, _attachment_limits, _case_switch_qs,
    _alert_bundle_ids, _notify_containment, _render_ticket_list,
)
# Convenience re-exports of policy predicates (were aliased module globals in
# views.py; external code and tests reference them as apps.incidents.views._can_*).
from ..policies import (  # noqa: F401
    can_access_ticket_report as _can_access_ticket_report,
    can_add_project_member as _can_add_project_member,
    can_create_ticket_from_triage as _can_create_ticket_from_triage,
    can_create_ticket_from_wazuh as _can_create_ticket_from_wazuh,
    can_delete_project_attachment as _can_delete_project_attachment,
    can_delete_ticket_attachment as _can_delete_ticket_attachment,
    can_edit_ticket as _can_edit_ticket,
    can_restore_ticket_attachment as _can_restore_ticket_attachment,
    can_upload_project_attachment as _can_upload_project_attachment,
    can_upload_subtask_result as _can_upload_subtask_result,
    can_upload_ticket_attachment as _can_upload_ticket_attachment,
    can_update_subtask as _can_update_subtask,
    response_request_updates_frozen as _response_request_updates_frozen,
    holds_ticket_court as _holds_ticket_court,
    is_soc as _is_soc,
    is_soc_manager as _is_soc_manager,
    user_can_drive as _user_can_drive,
)
