"""Field-level change recording for tickets.

``TicketLog`` records what happened in prose. This records what *changed* —
field, old value, new value, who, and from which surface — so a rewritten
ticket can be reconstructed rather than merely narrated.

Usage is always the same shape: snapshot before the write, record after.

    before = snapshot(ticket)
    ...mutate and save...
    record_changes(ticket, before, user, source='t2_review')

Only fields in ``TRACKED_FIELDS`` are watched. That is deliberate: workflow
bookkeeping (status, timestamps, sign-off stamps) is already covered by
TicketLog and the write-once guards in ``Ticket.transition_to``, and mixing it
in here would bury the content edits this exists to surface.
"""

from .models import TicketFieldChange

# field name -> human label, in roughly the order the report presents them.
TRACKED_FIELDS = {
    'incident_name':         'ชื่อ incident/event',
    'incident_datetime':     'วันที่ เวลาที่ตรวจพบ',
    'classification':        'ประเภท (Event/Incident)',
    'severity':              'ระดับความรุนแรง (SIEM)',
    'ncsa_severity':         'ระดับความรุนแรง (สกมช.)',
    'issue_type':            'แหล่งที่มา',
    'detailed_issue':        'หมวดหมู่ภัยคุกคาม',
    'detailed_issue2':       'หมวดหมู่ย่อย',
    'issue_description':     'รายละเอียดเหตุการณ์',
    'device_name':           'ชื่ออุปกรณ์/ระบบ',
    'ip_address':            'IP Address',
    'mac_address':           'MAC Address',
    'asset_type':            'ประเภททรัพย์สิน',
    'operating_system':      'Operating System',
    'asset_owner':           'ส่วนงานเจ้าของทรัพย์สิน',
    'asset_owner_name':      'ชื่อเจ้าของทรัพย์สิน',
    'spread_to_others':      'มีการกระจายไปยังจุดอื่น',
    'destination_ip':        'IP Address ปลายทาง',
    'ioc_details':           'Indicators of Compromise',
    'ioc_user':              'บัญชีผู้ใช้ที่เกี่ยวข้อง',
    'log_source':            'แหล่งข้อมูล/Log',
    'mitre_phase':           'MITRE ATT&CK',
    'action_required':       'สิ่งที่ต้องดำเนินการ',
    'action_precautions':    'ข้อควรระวัง',
    'actions_taken_summary': 'เรื่องที่ดำเนินการแล้ว',
    'next_steps_summary':    'การดำเนินการลำดับถัดไป',
    'containment_report':    'รายงานการควบคุม',
    'remediation_summary':   'ผลการตรวจสอบ',
}


def _display(ticket, field, value):
    """Human-readable form of a stored value, matching what the UI shows."""
    if value is None or value == '':
        return ''
    if isinstance(value, bool):
        return 'ใช่' if value else 'ไม่ใช่'
    getter = getattr(ticket, f'get_{field}_display', None)
    if callable(getter):
        try:
            return str(getter())
        except Exception:  # choice removed from the field since it was stored
            return str(value)
    return str(value)


def snapshot(ticket, fields=None):
    """Current values of the tracked fields, to diff against after a save.

    Reads the *in-memory* object. With a ModelForm that is almost always wrong:
    ``form.is_valid()`` runs ``_post_clean()``, which writes the submitted data
    onto ``form.instance`` before you ever call ``save()``. Snapshotting after
    validation therefore compares the object with itself and finds nothing.
    Use :func:`snapshot_saved` anywhere a form is involved.
    """
    watched = fields or TRACKED_FIELDS
    return {name: getattr(ticket, name, None) for name in watched}


def snapshot_saved(ticket, fields=None):
    """Tracked values as currently stored in the database.

    Immune to the ModelForm mutation above, so it is safe to call at any point
    — before or after validation. Costs one extra query; worth it, because the
    failure mode of getting this wrong is a silently empty audit trail.
    """
    from .models import Ticket

    fresh = Ticket.objects.filter(pk=ticket.pk).first()
    if fresh is None:
        return {}
    return snapshot(fresh, fields)


def record_changes(ticket, before, user, source='', fields=None):
    """Persist a row per changed field. Returns the rows created.

    ``before`` comes from :func:`snapshot`. Values are compared raw but stored
    rendered, so a status-style choice reads as its label rather than its code.
    """
    watched = fields or TRACKED_FIELDS
    rows = []
    for name in watched:
        if name not in before:
            continue
        old = before[name]
        new = getattr(ticket, name, None)
        if old == new:
            continue
        rows.append(TicketFieldChange(
            ticket=ticket,
            field_name=name,
            field_label=TRACKED_FIELDS.get(name, name),
            old_value=_display(ticket, name, old),
            new_value=_display(ticket, name, new),
            changed_by=user,
            source=source,
        ))
    if rows:
        TicketFieldChange.objects.bulk_create(rows)
    return rows


def record_subtask_change(subtask, old_notes, new_notes, user, source='subtask'):
    """Record an overwrite of a response-team deliverable's result notes.

    Its own entry point because subtask results previously wrote **no** audit at
    all — any SOC member could silently replace a forensic analyst's findings.
    """
    if old_notes == new_notes:
        return None
    return TicketFieldChange.objects.create(
        ticket_id=subtask.ticket_id,
        subtask=subtask,
        field_name='result_notes',
        field_label=f'ผลการดำเนินการ — {subtask.title}',
        old_value=old_notes or '',
        new_value=new_notes or '',
        changed_by=user,
        source=source,
    )
