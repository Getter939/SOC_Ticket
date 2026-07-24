from django import forms
from django.contrib.auth.models import User

from apps.accounts.models import UserProfile
from apps.wazuh_ingest.models import WazuhAlert
from .models import (
    Ticket, TicketAttachment, TicketSubtask, TriageRecord,
    validate_attachment,
)


class UserChoiceField(forms.ModelChoiceField):
    """Render users by their real name while retaining their primary-key value."""

    def label_from_instance(self, user):
        return user.get_full_name() or user.username


class _DetailedIssueCascade:
    """Shared cascade behaviour for forms exposing detailed_issue/detailed_issue2.

    Restricts both selects to the clean threat hierarchy
    (Ticket.DETAILED_ISSUE_HIERARCHY) so impossible combinations can't be
    chosen, while preserving whatever (possibly legacy) value an edited
    instance already holds. Call ``_restrict_detailed_issue_fields`` from
    ``__init__`` and ``_validate_detailed_issue_pair`` from ``clean``.
    """

    @staticmethod
    def _with_current(choices, value, labels):
        """Append the instance's current value if the clean list omits it."""
        if value and value not in {code for code, _ in choices}:
            return list(choices) + [(value, labels.get(value, value))]
        return choices

    def _restrict_detailed_issue_fields(self):
        parents = Ticket.detailed_issue_form_choices()
        children = Ticket.detailed_issue2_form_choices()
        inst = getattr(self, 'instance', None)
        if inst is not None and inst.pk:
            parents = self._with_current(
                parents, inst.detailed_issue, dict(Ticket.DETAILED_ISSUE_CHOICES))
            children = self._with_current(
                children, inst.detailed_issue2, dict(Ticket.DETAILED_ISSUE_CHOICES2))
        self.fields['detailed_issue'].choices = parents
        self.fields['detailed_issue2'].choices = children

    def _validate_detailed_issue_pair(self, cleaned):
        parent = cleaned.get('detailed_issue')
        child = cleaned.get('detailed_issue2')
        valid = Ticket.DETAILED_ISSUE_HIERARCHY.get(parent)
        # Only enforce consistency within the clean taxonomy; a legacy parent
        # (not in the hierarchy) is left alone so old tickets save unchanged.
        if valid is not None and child and child not in valid:
            self.add_error(
                'detailed_issue2',
                'รายการที่เลือกไม่อยู่ในประเภทเหตุการณ์ (detailed issue) ที่เลือกไว้',
            )


def _ncsa_severity_field():
    """Mandatory single-choice NCSA severity, rendered as coloured pills like
    ``severity`` (the template iterates the radio group). A fresh instance per
    form — Field objects are mutable and must not be shared across forms."""
    return forms.ChoiceField(
        choices=Ticket.NCSA_SEVERITY_CHOICES,
        required=True,
        label='ระดับความรุนแรงตาม สกมช.',
        widget=forms.RadioSelect(attrs={'class': 'ncsa-severity-radio'}),
    )


def _mitre_phase_field():
    """Multi-select MITRE ATT&CK phases — an incident can span several phases.
    Stored on the model as a comma-separated string (see ``clean_mitre_phase``
    and ``_init_report_fields``). Fresh instance per form."""
    return forms.MultipleChoiceField(
        choices=Ticket.MITRE_PHASE_CHOICES,
        required=False,
        label='Phase การโจมตีตาม MITRE ATT&CK',
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'mitre-phase-checks'}),
    )


class NullBooleanRadioSelect(forms.RadioSelect):
    """RadioSelect rendering for a nullable boolean (tri-state ใช่ / ไม่ใช่ /
    รอตรวจสอบ). Borrows ``NullBooleanSelect``'s value<->string mapping so that
    True / False / None round-trip correctly through the radio group (a plain
    RadioSelect can't map a Python ``True`` back to the ``'true'`` option)."""
    _nb = forms.NullBooleanSelect()

    def format_value(self, value):
        return self._nb.format_value(value)

    def value_from_datadict(self, data, files, name):
        return self._nb.value_from_datadict(data, files, name)


def _spread_field():
    """Tri-state 'มีการกระจายไปยังจุดอื่น' rendered as pills (ใช่ / ไม่ใช่ /
    รอตรวจสอบ) instead of a dropdown — a checkbox can't express the null
    'not yet determined' state. Fresh instance per form."""
    return forms.NullBooleanField(
        required=False,
        label='มีการกระจายไปยังจุดอื่น',
        widget=NullBooleanRadioSelect(choices=[
            ('true',    'ใช่'),
            ('false',   'ไม่ใช่'),
            ('unknown', 'รอตรวจสอบ'),
        ]),
    )


class _ReportFields:
    """Shared helper *methods* for the NCSA-report inputs (``ncsa_severity`` +
    ``mitre_phase``).

    The two fields themselves are declared inline on each form via the factory
    helpers above — a plain mixin's ``Field`` class attributes are NOT collected
    by the form metaclass (only bases that are themselves forms contribute
    declared fields), so declaring them here would silently drop them. Methods,
    however, are inherited normally.
    """

    def _init_report_fields(self):
        """Seed the multi-select MITRE initial from the stored CSV (edit forms)."""
        inst = getattr(self, 'instance', None)
        if inst is not None and not self.is_bound and inst.mitre_phase:
            self.initial['mitre_phase'] = [
                p for p in inst.mitre_phase.split(',') if p
            ]

    def clean_mitre_phase(self):
        return ','.join(self.cleaned_data.get('mitre_phase') or [])


class TicketForm(_DetailedIssueCascade, _ReportFields, forms.ModelForm):
    # ── Tier 1 disposition (set at creation) ─────────────────────────────── #
    # The Event/Incident decision IS the disposition. Required — every ticket
    # carries an explicit value; it is never derived.
    ROUTE_ASSIGN_ADMIN = 'assign_admin'
    ROUTE_ESCALATE_T2  = 'escalate_t2'
    ROUTE_DIRECT_OWNER = 'direct_owner'
    ROUTE_CHOICES = [
        (ROUTE_ASSIGN_ADMIN, 'มอบหมายให้ผู้ดูแลระบบ (System Admin)'),
        (ROUTE_DIRECT_OWNER, 'ให้เจ้าของระบบแก้ไขเอง (ไม่ออก Ticket ถึงผู้ดูแลระบบ)'),
        (ROUTE_ESCALATE_T2,  'ส่งต่อให้ Tier 2'),
    ]

    classification = forms.ChoiceField(
        choices=Ticket.CLASSIFICATION_CHOICES,
        required=True,
        label='การจัดประเภท (Event/Incident)',
        widget=forms.RadioSelect(attrs={'class': 'classification-radio'}),
    )
    ncsa_severity = _ncsa_severity_field()
    mitre_phase = _mitre_phase_field()
    spread_to_others = _spread_field()
    t1_route = forms.ChoiceField(
        choices=ROUTE_CHOICES,
        required=False,
        label='เมื่อเป็น Incident จะดำเนินการ',
        widget=forms.RadioSelect(attrs={'class': 'route-radio'}),
    )

    wazuh_alert = forms.ModelChoiceField(
        queryset=WazuhAlert.objects.none(),
        required=False,
        label='Wazuh Alert (optional)',
        empty_label='None — manual ticket',
        widget=forms.Select(attrs={'class': 'form-select', 'id': 'id_wazuh_alert'}),
    )

    assigned_admin = UserChoiceField(
        queryset=User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_ADMIN,
            is_active=True,
        ).order_by('first_name', 'username'),
        required=False,
        label='ผู้ดูแลระบบที่รับผิดชอบ',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    class Meta:
        model = Ticket
        fields = [
            # Disposition (Event/Incident) — set by T1
            'classification',
            # Section 1
            'wazuh_alert',
            'incident_name',
            'severity',
            'ncsa_severity',
            'incident_datetime',
            'reference_id',
            'log_source',
            # Section 2
            'issue_type',
            'detailed_issue',
            'detailed_issue2',
            # Section 3
            'device_name',
            'issue_description',
            # Section 4
            'ip_address',
            'mac_address',
            'asset_type',
            'operating_system',
            'asset_owner',
            'asset_owner_name',
            'spread_to_others',
            # Section 5
            'destination_ip',
            'ioc_details',
            # Section 6
            'mitre_phase',
            # Section 7
            'action_required',
            'action_precautions',
            'actions_taken_summary',
            'next_steps_summary',
            # Assignment
            'assigned_admin',
        ]
        widgets = {
            'incident_name':      forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น Malware – Suspicious SoftEther signed file on SRV-DB-01'}),
            'severity':           forms.RadioSelect(attrs={'class': 'severity-radio'}),
            'incident_datetime':  forms.DateTimeInput(
                attrs={'class': 'form-control', 'type': 'datetime-local'},
                format='%Y-%m-%dT%H:%M',
            ),
            'reference_id':       forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น INC-2026-0001'}),
            'log_source':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น Palo Alto Firewall, Windows Security Event Log'}),
            'issue_type':         forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue':     forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue2':    forms.Select(attrs={'class': 'form-select'}),
            'device_name':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น NTHQ-WS-047 / ระบบ HR Portal'}),
            'operating_system':   forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น Windows Server 2019 / Ubuntu 22.04'}),
            'issue_description':  forms.Textarea(attrs={
                'class': 'form-control', 'rows': 5,
                'placeholder': 'สรุปรายละเอียดเหตุการณ์ที่ตรวจพบ เช่น ลักษณะเหตุการณ์ ช่องโหว่/เทคนิคที่เกี่ยวข้อง วันที่และเวลาที่เริ่มพบเหตุการณ์ แหล่งที่มาของการแจ้งเตือน และผลกระทบเบื้องต้น',
            }),
            'ip_address':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': '0.0.0.0'}),
            'mac_address':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'AA:BB:CC:DD:EE:FF'}),
            'asset_type':         forms.RadioSelect(attrs={'class': 'asset-type-radio'}),
            'asset_owner':        forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น ฝ่ายเทคโนโลยีสารสนเทศ / กองระบบงาน HR'}),
            'asset_owner_name':   forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น นายสมชาย ใจดี'}),
            'destination_ip':     forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น 79[.]124[.]59[.]146'}),
            'ioc_details':        forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'IP, Domain, Hash, หรือ IoC อื่น ๆ ที่พบ',
            }),
            'action_required':    forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'ขั้นตอน/มาตรการที่ผู้เกี่ยวข้องต้องดำเนินการเพื่อจัดการเหตุการณ์นี้',
            }),
            'action_precautions': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'ข้อควรระวังหรือผลกระทบที่อาจเกิดขึ้นระหว่างการดำเนินการ',
            }),
            'actions_taken_summary': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'สรุปสิ่งที่ SOC หรือผู้ดูแลระบบดำเนินการแล้ว เพื่อใช้ในรายงาน',
            }),
            'next_steps_summary': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'สรุปขั้นตอนถัดไปหรือการติดตามผล เพื่อใช้ในรายงาน',
            }),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        alert_qs = WazuhAlert.objects.none()
        if user is not None and user.is_authenticated:
            recent_alert_ids = list(
                WazuhAlert.objects.filter(
                    rule_level__gte=10,
                    claimed_by=user,
                    triage_status__in=[
                        WazuhAlert.TRIAGE_TRIAGING,
                        WazuhAlert.TRIAGE_ESCALATED,
                    ],
                    ticket__isnull=True,
                )
                .order_by('-timestamp')
                .values_list('pk', flat=True)[:100]
            )
            alert_qs = WazuhAlert.objects.filter(pk__in=recent_alert_ids).order_by('-timestamp')
        if self.instance and self.instance.pk and self.instance.wazuh_alert_id:
            alert_qs = alert_qs | WazuhAlert.objects.filter(pk=self.instance.wazuh_alert_id)
        self.fields['wazuh_alert'].queryset = alert_qs
        if self.instance and self.instance.pk and self.instance.incident_datetime:
            self.initial['incident_datetime'] = self.instance.incident_datetime.strftime('%Y-%m-%dT%H:%M')
        self.fields['log_source'].required = True
        # The form no longer defaults this to "now", so a blank submit is now
        # reachable. Enforce it rather than let Ticket.save() fall back silently
        # to timezone.now() as the OLA base — the label has always shown it as
        # mandatory anyway.
        self.fields['incident_datetime'].required = True
        self._restrict_detailed_issue_fields()
        self._init_report_fields()

    def clean(self):
        cleaned = super().clean()
        self._validate_detailed_issue_pair(cleaned)
        classification = cleaned.get('classification')
        route = cleaned.get('t1_route')

        if classification == Ticket.CLASSIFICATION_INCIDENT:
            # An Incident must choose a forward route at creation. Direct-to-Owner
            # is available at any severity; the mandatory review gate (Tier 2, or
            # SOC Manager when Critical/emergency) is the safeguard.
            if route not in (
                self.ROUTE_ASSIGN_ADMIN, self.ROUTE_DIRECT_OWNER, self.ROUTE_ESCALATE_T2,
            ):
                self.add_error('t1_route', 'กรุณาเลือกการดำเนินการสำหรับ Incident')
            elif route == self.ROUTE_ASSIGN_ADMIN and not cleaned.get('assigned_admin'):
                self.add_error('assigned_admin', 'กรุณาเลือกผู้ดูแลระบบที่รับผิดชอบ')
        elif classification == Ticket.CLASSIFICATION_EVENT:
            # A benign Event is closed immediately — no route, no admin.
            cleaned['t1_route'] = ''
            cleaned['assigned_admin'] = None
        return cleaned


class ProjectIncidentForm(_DetailedIssueCascade, _ReportFields, forms.ModelForm):
    """Shared, incident-level fields for a multi-system case bundle.

    Classification is implicitly Incident, so this form carries no
    classification radio — only the facts common to every affected system.
    Per-target fields, including each member's handling route, live on
    ``ProjectIncidentTargetForm``. This form is never saved
    directly; ``create_project_incident`` reads ``cleaned_data`` and copies the
    shared values onto each generated member ticket.
    """

    title = forms.CharField(
        max_length=255, required=True,
        label='หัวข้อเหตุการณ์ (Project Incident)',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'เช่น การบุกรุกผ่าน Public-Facing Application กระทบหลายระบบ',
        }),
    )
    ncsa_severity = _ncsa_severity_field()
    mitre_phase = _mitre_phase_field()
    spread_to_others = _spread_field()

    class Meta:
        model = Ticket
        fields = [
            'severity', 'ncsa_severity', 'incident_datetime', 'reference_id',
            'log_source',
            'issue_type', 'detailed_issue', 'detailed_issue2',
            'issue_description',
            'destination_ip', 'ioc_details', 'mitre_phase',
            'spread_to_others',
            'action_required', 'action_precautions',
            'actions_taken_summary', 'next_steps_summary',
        ]
        widgets = {
            'severity':           forms.RadioSelect(attrs={'class': 'severity-radio'}),
            'incident_datetime':  forms.DateTimeInput(
                attrs={'class': 'form-control', 'type': 'datetime-local'},
                format='%Y-%m-%dT%H:%M',
            ),
            'reference_id':       forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น INC-2026-0001'}),
            'log_source':         forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น Palo Alto Firewall, Windows Security Event Log'}),
            'issue_type':         forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue':     forms.Select(attrs={'class': 'form-select'}),
            'detailed_issue2':    forms.Select(attrs={'class': 'form-select'}),
            'issue_description':  forms.Textarea(attrs={
                'class': 'form-control', 'rows': 5,
                'placeholder': 'สรุปเหตุการณ์โดยรวมที่กระทบหลายระบบ — เนื้อหานี้จะถูกใช้ร่วมกันในทุก Ticket ของกลุ่ม',
            }),
            'destination_ip':     forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เช่น 79[.]124[.]59[.]146'}),
            'ioc_details':        forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'IP, Domain, Hash, หรือ IoC อื่น ๆ'}),
            'action_required':    forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'ขั้นตอน/มาตรการที่ผู้ดูแลระบบต้องดำเนินการ — ใช้ร่วมกันในทุก Ticket ของกลุ่ม',
            }),
            'action_precautions': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'ข้อควรระวัง — ใช้ร่วมกันในทุก Ticket ของกลุ่ม',
            }),
            'actions_taken_summary': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'สรุปสิ่งที่ SOC ดำเนินการแล้ว — ใช้ร่วมกันในทุก Ticket ของกลุ่ม',
            }),
            'next_steps_summary': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'สรุปขั้นตอนถัดไปหรือการติดตามผล — ใช้ร่วมกันในทุก Ticket ของกลุ่ม',
            }),
        }

    def __init__(self, *args, **kwargs):
        # ``user`` accepted for call-site symmetry with TicketForm; unused here.
        kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        # A bundle exists precisely because the incident spread across systems.
        if not self.is_bound:
            self.fields['spread_to_others'].initial = True
        self.fields['log_source'].required = True
        self._restrict_detailed_issue_fields()
        self._init_report_fields()

    def clean(self):
        cleaned = super().clean()
        self._validate_detailed_issue_pair(cleaned)
        return cleaned


class ProjectIncidentTargetForm(forms.ModelForm):
    """One affected system within a bundle — only the per-target fields.

    Each valid row becomes a member Ticket; the shared incident facts are
    copied in by the view. ``ip_address`` is optional here (a service/system
    target may have no single IP) even though single-ticket creation requires
    one.
    """

    assigned_admin = UserChoiceField(
        queryset=User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_ADMIN, is_active=True,
        ).order_by('first_name', 'username'),
        required=False, label='ผู้ดูแลระบบ', empty_label='-- เลือกผู้ดูแลระบบ --',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )
    system_owner = UserChoiceField(
        queryset=User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_OWNER, is_active=True,
        ).order_by('first_name', 'username'),
        required=False, label='เจ้าของระบบ',
        empty_label='-- เลือกเจ้าของระบบ --',
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'}),
    )
    t1_route = forms.ChoiceField(
        choices=Ticket.T1_ROUTE_CHOICES,
        required=True,
        label='เส้นทางการดำเนินการ',
        widget=forms.RadioSelect(attrs={'class': 'route-radio'}),
    )

    class Meta:
        model = Ticket
        fields = [
            'device_name', 'ip_address', 'mac_address', 'asset_type',
            'operating_system', 'asset_owner', 'asset_owner_name',
            'assigned_admin', 'system_owner',
        ]
        widgets = {
            'device_name': forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': 'เช่น ระบบ HR Portal / NTHQ-WS-047'}),
            'ip_address':  forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': '0.0.0.0'}),
            'mac_address': forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': 'AA:BB:CC:DD:EE:FF'}),
            'asset_type':  forms.Select(attrs={'class': 'form-select form-select-sm'}),
            'asset_owner': forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': 'เช่น ฝ่ายไอที'}),
            'asset_owner_name': forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': 'เช่น นายสมชาย ใจดี'}),
            'operating_system': forms.TextInput(attrs={'class': 'form-control form-control-sm', 'placeholder': 'เช่น Windows Server 2019'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # A single-ticket create requires an IP; a bundle target may be a
        # service with none, so relax it here (model already allows null).
        self.fields['ip_address'].required = False

    def clean(self):
        cleaned = super().clean()
        route = cleaned.get('t1_route')
        if route == Ticket.T1_ROUTE_ADMIN and not cleaned.get('assigned_admin'):
            self.add_error('assigned_admin', 'กรุณาเลือกผู้ดูแลระบบ')
        elif route == Ticket.T1_ROUTE_OWNER and not cleaned.get('system_owner'):
            self.add_error('system_owner', 'กรุณาเลือกเจ้าของระบบ')
        return cleaned


ProjectIncidentTargetFormSet = forms.formset_factory(
    ProjectIncidentTargetForm,
    extra=2, min_num=2, max_num=25, validate_min=True, can_delete=True,
)


class TicketReviewForm(_DetailedIssueCascade, _ReportFields, forms.ModelForm):
    """General ticket information Tier 2 may correct while reviewing."""

    ncsa_severity = _ncsa_severity_field()
    mitre_phase = _mitre_phase_field()
    spread_to_others = _spread_field()

    class Meta:
        model = Ticket
        fields = [
            'classification', 'incident_name', 'severity', 'ncsa_severity',
            'incident_datetime', 'reference_id', 'log_source',
            'issue_type', 'detailed_issue', 'detailed_issue2',
            'device_name', 'issue_description', 'ip_address', 'mac_address',
            'asset_type', 'operating_system', 'asset_owner', 'asset_owner_name',
            'spread_to_others',
            'destination_ip', 'ioc_details', 'mitre_phase', 'action_required',
            'action_precautions', 'actions_taken_summary', 'next_steps_summary',
        ]
        widgets = {
            'classification': forms.RadioSelect(),
            'incident_datetime': forms.DateTimeInput(
                attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M',
            ),
            'issue_description': forms.Textarea(attrs={'rows': 4}),
            'ioc_details': forms.Textarea(attrs={'rows': 3}),
            'action_required': forms.Textarea(attrs={'rows': 3}),
            'action_precautions': forms.Textarea(attrs={'rows': 3}),
            'actions_taken_summary': forms.Textarea(attrs={'rows': 3}),
            'next_steps_summary': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, forms.RadioSelect):
                field.widget.attrs.setdefault(
                    'class', 'form-select' if isinstance(field.widget, forms.Select) else 'form-control'
                )
        if self.instance and self.instance.incident_datetime:
            self.initial['incident_datetime'] = self.instance.incident_datetime.strftime('%Y-%m-%dT%H:%M')
        self.fields['log_source'].required = True
        self._restrict_detailed_issue_fields()
        self._init_report_fields()

    def clean(self):
        cleaned = super().clean()
        self._validate_detailed_issue_pair(cleaned)
        return cleaned


class AdminAssignmentForm(forms.ModelForm):
    assigned_admin = UserChoiceField(queryset=User.objects.none())

    class Meta:
        model = Ticket
        fields = ['assigned_admin']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigned_admin'].queryset = User.objects.filter(
            profile__role=UserProfile.ROLE_SYSTEM_ADMIN,
            is_active=True,
        ).order_by('first_name', 'username')
        self.fields['assigned_admin'].required = True
        self.fields['assigned_admin'].widget.attrs['class'] = 'form-select'


class TriageForm(forms.ModelForm):
    notes = forms.CharField(
        required=True,
        label='บันทึกเหตุผล',
        widget=forms.Textarea(attrs={
            'class': 'form-control', 'rows': 3,
            'placeholder': 'บันทึกเหตุผลประกอบการตัดสินใจ...',
        }),
    )
    class Meta:
        model = TriageRecord
        fields = [
            'source', 'source_reference', 'alert_description', 'source_ip',
            'notes',
        ]
        widgets = {
            'source': forms.Select(attrs={'class': 'form-select'}),
            'source_reference': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'เช่น Email subject, external case ID หรือหมายเลขอ้างอิง',
            }),
            'alert_description': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 4,
                'placeholder': 'อธิบายรายละเอียด Alert จากแหล่งข้อมูล — severity, affected asset, evidence...',
            }),
            'source_ip': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '0.0.0.0'}),
        }

    def __init__(self, *args, **kwargs):
        # Keep the historical call signature while the form no longer uses a
        # user to select a pre-ticket escalation recipient.
        kwargs.pop('user', None)
        super().__init__(*args, **kwargs)


# The two legacy subtask types SOC staff may spawn freely. Response-team
# request types (VA/PT, InfraSec, Forensics) are excluded here — those are
# spawned by the SOC Manager through ResponseRequestForm, which routes and
# auto-assigns them to a response-team role.
_LEGACY_SUBTASK_TYPE_CHOICES = [
    (TicketSubtask.TYPE_INVESTIGATION, 'Investigation'),
    (TicketSubtask.TYPE_COUNTERMEASURE, 'Countermeasure'),
]


# Response-team accounts must never receive an ordinary Investigation /
# Countermeasure subtask: doing so would expose the whole ticket to them via
# TicketQuerySet.visible_to. Exclude them from the legacy assignee picker so the
# response-only access model cannot be breached through the UI.
_RESPONSE_TEAM_ROLES = (UserProfile.ROLE_FORENSIC, UserProfile.ROLE_REDTEAM_MANAGER)


class SubtaskForm(forms.ModelForm):
    subtask_type = forms.ChoiceField(
        choices=_LEGACY_SUBTASK_TYPE_CHOICES,
        label='ประเภท',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    assigned_to = UserChoiceField(
        queryset=User.objects.filter(is_active=True)
        .exclude(profile__role__in=_RESPONSE_TEAM_ROLES)
        .order_by('first_name', 'username'),
        required=False,
        label='ผู้รับผิดชอบ',
        empty_label='-- ยังไม่ระบุ --',
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    class Meta:
        model = TicketSubtask
        fields = ['subtask_type', 'title', 'description', 'assigned_to']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'เช่น ตรวจสอบ log การเข้าถึง / บล็อก IP ที่ปลายทาง Firewall',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'รายละเอียดงานที่ต้องดำเนินการ...',
            }),
        }


class ResponseRequestForm(forms.ModelForm):
    """SOC Manager spawn form for a response-team request (VA/PT, InfraSec,
    Forensics). The type determines the receiving role; the assignee is
    resolved in the view (auto-assign when a single role-holder exists, picker
    when several, blocked when none)."""

    # Derived from the model's single source of truth so a future response-type
    # change (add/rename/reorder) needs editing only TicketSubtask.TYPE_CHOICES.
    RESPONSE_TYPE_CHOICES = [
        (code, label) for code, label in TicketSubtask.TYPE_CHOICES
        if code in TicketSubtask.RESPONSE_TYPES
    ]

    subtask_type = forms.ChoiceField(
        choices=RESPONSE_TYPE_CHOICES,
        label='ประเภทคำขอ',
        # Stable id so the detail-page script can filter the assignee list by the
        # chosen type (the two forms on the page would otherwise collide on the
        # Django-default id_subtask_type).
        widget=forms.Select(attrs={
            'class': 'form-select form-select-sm', 'id': 'resp-type-select',
        }),
    )
    assigned_to = UserChoiceField(
        queryset=User.objects.filter(
            is_active=True,
            profile__role__in=(
                UserProfile.ROLE_FORENSIC, UserProfile.ROLE_REDTEAM_MANAGER,
            ),
        ).order_by('first_name', 'username'),
        required=False,
        label='ผู้รับผิดชอบ (เว้นว่างเพื่อมอบหมายอัตโนมัติ)',
        empty_label='-- มอบหมายอัตโนมัติ --',
        widget=forms.Select(attrs={
            'class': 'form-select form-select-sm', 'id': 'resp-assignee-select',
        }),
    )

    class Meta:
        model = TicketSubtask
        fields = ['subtask_type', 'title', 'description', 'assigned_to']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control form-control-sm',
                'placeholder': 'เช่น เก็บ memory image / สแกนช่องโหว่ระบบที่ถูกโจมตี',
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control form-control-sm', 'rows': 2,
                'placeholder': 'ขอบเขตงานที่ต้องการให้ทีมตอบสนองดำเนินการ...',
            }),
        }


class SubtaskUpdateForm(forms.ModelForm):
    class Meta:
        model = TicketSubtask
        fields = ['status', 'result_notes']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'result_notes': forms.Textarea(attrs={
                'class': 'form-control', 'rows': 3,
                'placeholder': 'บันทึกผลการดำเนินการ...',
            }),
        }


class AttachmentForm(forms.ModelForm):
    class Meta:
        model = TicketAttachment
        fields = ['file', 'description']
        widgets = {
            'file':        forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'คำอธิบายไฟล์ (ไม่บังคับ)',
            }),
        }

    def clean_file(self):
        uploaded = self.cleaned_data.get('file')
        validate_attachment(uploaded)
        return uploaded
