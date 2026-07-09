import hashlib
import logging
import re
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote, urlparse

from django.template.loader import render_to_string
from django.utils import timezone
from docx import Document
from reportlab.lib.fonts import addMapping
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFError, TTFont
from xhtml2pdf import default as xhtml2pdf_default
from xhtml2pdf import pisa

from .models import Ticket


logger = logging.getLogger(__name__)

REPORT_TEMPLATE_VERSION = 'v1'
REPORT_TEMPLATE_NAME = f'report_template_{REPORT_TEMPLATE_VERSION}.docx'
REPORT_CONTENT_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
PDF_CONTENT_TYPE = 'application/pdf'
REPORT_TEMPLATE_PATH = Path(__file__).resolve().parent / 'report_templates' / REPORT_TEMPLATE_NAME
REPORT_PREVIEW_TEMPLATE = 'incidents/report_preview.html'
REPORT_FONT_NAME = 'ReportUnicode'
REPORT_FONT_DIR = Path(__file__).resolve().parent / 'report_templates' / 'fonts'
# TH Sarabun New is bundled under report_templates/fonts/ (see NOTICE.md) so the
# PDF renders Thai on any host. Each entry: (bold, italic, filename, reportlab
# font name) — real weights instead of faux-mapping everything to the regular.
REPORT_FONT_VARIANTS = (
    (0, 0, 'THSarabunNew.ttf', REPORT_FONT_NAME),
    (1, 0, 'THSarabunNew-Bold.ttf', f'{REPORT_FONT_NAME}-Bold'),
    (0, 1, 'THSarabunNew-Italic.ttf', f'{REPORT_FONT_NAME}-Italic'),
    (1, 1, 'THSarabunNew-BoldItalic.ttf', f'{REPORT_FONT_NAME}-BoldItalic'),
)
# Last-resort system paths, only consulted if the bundled regular face is
# missing — keeps Thai rendering alive on a host where the bundle was stripped.
REPORT_FONT_FALLBACKS = (
    Path('C:/Windows/Fonts/THSarabunNew.ttf'),
    Path('/usr/share/fonts/truetype/thai/THSarabunNew.ttf'),
    Path('/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf'),
    Path('/usr/share/fonts/truetype/thai/Garuda.ttf'),
)

APPENDIX_CATEGORIES = [
    ('Training and Exercises', 'เหตุการณ์จำลอง และ การฝึกจู่โจม ของหน่วยงาน'),
    ('Unsuccessful Activity Attempt', 'การพยายามเข้าถึงระบบที่ไม่สำเร็จ'),
    ('Reconnaissance', 'การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี'),
    ('Non-Compliance Activity', 'การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด'),
    ('Malicious Logic', 'การบุกรุกโดยการใช้มัลแวร์'),
    ('User Level Intrusion', 'การบุกรุกในระดับผู้ใช้งาน'),
    ('Root Level Intrusion', 'การบุกรุกในระดับผู้ควบคุมระบบ'),
    ('Denial of Service', 'การบุกรุกที่ทำให้ไม่สามารถเข้าใช้บริการได้'),
    ('Investigating', 'เหตุการณ์ที่อยู่ระหว่างการวิเคราะห์สอบสวน'),
    ('Explained Anomaly', 'เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม'),
]


@dataclass(frozen=True)
class GeneratedTicketReport:
    filename: str
    content: bytes
    content_type: str = REPORT_CONTENT_TYPE

    def as_file(self):
        return BytesIO(self.content)


def generate_ticket_report(ticket_id, generated_by=None):
    ticket = _load_ticket(ticket_id)
    generated_at = timezone.now()
    context = build_ticket_report_context(ticket, generated_at=generated_at)
    doc = Document(REPORT_TEMPLATE_PATH)
    _replace_placeholders(doc, context)

    output = BytesIO()
    doc.save(output)
    content = output.getvalue()
    digest = hashlib.sha256(content).hexdigest()

    _record_export_metadata(ticket, generated_by, generated_at, digest, report_format='docx')

    filename = f'report_{ticket.ticket_id}_{REPORT_TEMPLATE_VERSION}.docx'
    return GeneratedTicketReport(filename=filename, content=content)


def generate_ticket_report_pdf(ticket_id, generated_by=None, base_url=None):
    ticket = _load_ticket(ticket_id)
    generated_at = timezone.now()
    context = build_ticket_report_render_context(
        ticket,
        generated_at=generated_at,
        show_report_actions=False,
    )
    html = render_to_string(REPORT_PREVIEW_TEMPLATE, context)
    content = _render_pdf_from_html(html, base_url=base_url)
    digest = hashlib.sha256(content).hexdigest()

    _record_export_metadata(ticket, generated_by, generated_at, digest, report_format='pdf')

    filename = f'report_{ticket.ticket_id}_{REPORT_TEMPLATE_VERSION}.pdf'
    return GeneratedTicketReport(
        filename=filename,
        content=content,
        content_type=PDF_CONTENT_TYPE,
    )


def build_ticket_report_render_context(
    ticket,
    generated_at=None,
    show_report_actions=True,
    pdf_font_face_css='',
):
    report = build_ticket_report_context(ticket, generated_at=generated_at)
    return {
        'ticket': ticket,
        'report': report,
        'sections': build_ticket_report_sections(report),
        'appendix_categories': APPENDIX_CATEGORIES,
        'show_report_actions': show_report_actions,
        'pdf_font_face_css': pdf_font_face_css,
    }


def build_ticket_report_context(ticket, generated_at=None):
    generated_at = generated_at or timezone.now()
    return {
        'ticket_id': _value(ticket.display_id or ticket.ticket_id),
        'ticket_pk': _value(ticket.pk),
        'incident_datetime': _format_dt(ticket.incident_datetime),
        'incident_name': _value(ticket.incident_name),
        'classification': _value(ticket.get_classification_display()),
        'siem_severity': _value(ticket.severity),
        'ncsa_severity': _value(ticket.get_ncsa_severity_display()),
        'category': _value(ticket.get_detailed_issue_display()),
        'category_detail': _value(ticket.get_detailed_issue2_display()),
        'reporter': _user_label(ticket.created_by, include_phone=True),
        'log_source': _value(ticket.log_source),
        'source_channel': _value(ticket.get_issue_type_display()),
        'reference_id': _value(ticket.reference_id),
        'status': _value(ticket.get_status_display()),
        'actions_taken_summary': _value(ticket.actions_taken_summary),
        'next_steps_summary': _value(ticket.next_steps_summary),
        'incident_description': _value(ticket.issue_description),
        'system_name': _value(ticket.device_name),
        'asset_owner': _value(ticket.asset_owner),
        'host_name': _value(ticket.device_name),
        'ip_address': _value(ticket.ip_address),
        'mac_address': _value(ticket.mac_address),
        'operating_system': _value(ticket.operating_system),
        'asset_type': _value(ticket.get_asset_type_display()),
        'spread_to_others': _spread_label(ticket.spread_to_others),
        'destination_ip': _value(ticket.destination_ip),
        'ioc_details': _value(ticket.ioc_details),
        'evidence_files': _attachment_summary(ticket),
        'mitre_phases': _value(', '.join(ticket.mitre_phase_labels)),
        'action_required': _value(ticket.action_required),
        'action_precautions': _value(ticket.action_precautions),
        'remediation_summary': _value(ticket.remediation_summary),
        'containment_report': _value(ticket.containment_report),
        'created_by': _user_label(ticket.created_by),
        'created_at': _format_dt(ticket.created_at),
        'verified_by': _user_label(ticket.verified_by),
        'verified_at': _format_dt(ticket.verified_at),
        'approved_by': _user_label(ticket.approved_by),
        'approved_at': _format_dt(ticket.approved_at),
        'template_version': REPORT_TEMPLATE_VERSION,
        'generated_at': _format_dt(generated_at),
    }


def build_ticket_report_sections(report):
    return [
        {
            'id': 'general-info',
            'number': '1',
            'title': 'General Info',
            'subtitle': 'ข้อมูลทั่วไป',
            'layout': 'grid',
            'rows': [
                ('Incident No.', report['ticket_id'], 'Reference', report['reference_id']),
                ('Detected Date/Time', report['incident_datetime'], 'Incident/Event Name', report['incident_name']),
                ('Type', report['classification'], 'Current Status', report['status']),
                ('SIEM Severity', report['siem_severity'], 'NCSA Severity', report['ncsa_severity']),
                ('Threat Category', report['category'], 'Category Detail', report['category_detail']),
                ('Reporter', report['reporter'], 'Log Source', report['log_source']),
                ('Source Channel', report['source_channel'], 'Template', report['template_version']),
                ('Actions Taken', report['actions_taken_summary'], 'Next Steps', report['next_steps_summary']),
            ],
        },
        {
            'id': 'incident-description',
            'number': '2',
            'title': 'Incident Description',
            'subtitle': 'รายละเอียดเหตุการณ์',
            'layout': 'single',
            'rows': [('Incident Description', report['incident_description'])],
        },
        {
            'id': 'scope',
            'number': '3',
            'title': 'Scope / Affected Asset',
            'subtitle': 'ทรัพย์สินที่ได้รับผลกระทบ',
            'layout': 'grid',
            'rows': [
                ('System / Service', report['system_name'], 'Asset Owner', report['asset_owner']),
                ('Host Name', report['host_name'], 'IP Address', report['ip_address']),
                ('MAC Address', report['mac_address'], 'Operating System', report['operating_system']),
                ('Asset Type', report['asset_type'], 'Spread to Other Systems', report['spread_to_others']),
            ],
        },
        {
            'id': 'iocs',
            'number': '4',
            'title': 'IoCs / Evidence / MITRE Phases',
            'subtitle': 'Indicators of Compromise และหลักฐาน',
            'layout': 'single',
            'rows': [
                ('Destination IP', report['destination_ip']),
                ('IoC Details', report['ioc_details']),
                ('Evidence / Attachments', report['evidence_files']),
                ('MITRE ATT&CK Phases', report['mitre_phases']),
            ],
        },
        {
            'id': 'containment',
            'number': '5',
            'title': 'Containment / Precautions',
            'subtitle': 'สิ่งที่ต้องดำเนินการและข้อควรระวัง',
            'layout': 'single',
            'rows': [
                ('Containment', report['action_required']),
                ('Precautions', report['action_precautions']),
            ],
        },
        {
            'id': 'remediation',
            'number': '6',
            'title': 'Remediation / Results',
            'subtitle': 'สรุปผลการดำเนินการแก้ไข',
            'layout': 'single',
            'rows': [
                ('Investigation Findings', report['remediation_summary']),
                ('Countermeasure', report['containment_report']),
            ],
        },
        {
            'id': 'sign-off',
            'number': '7',
            'title': 'Sign-off',
            'subtitle': 'ผู้ดำเนินการ ตรวจสอบ และอนุมัติ',
            'layout': 'signoff',
            'rows': [
                ('Created by', report['created_by'], report['created_at']),
                ('Verified by', report['verified_by'], report['verified_at']),
                ('Approved by', report['approved_by'], report['approved_at']),
            ],
        },
    ]


def _record_export_metadata(ticket, generated_by, generated_at, digest, report_format):
    generated_by_id = getattr(generated_by, 'pk', None)
    Ticket.objects.filter(pk=ticket.pk).update(
        report_template_version=REPORT_TEMPLATE_VERSION,
        report_format=report_format,
        report_generated_by_id=generated_by_id,
        report_generated_at=generated_at,
        report_ticket_updated_at=ticket.updated_at,
        report_sha256=digest,
    )


def _render_pdf_from_html(html, base_url=None):
    _register_pdf_font()
    output = BytesIO()
    result = pisa.CreatePDF(
        src=html,
        dest=output,
        encoding='utf-8',
        path=base_url,
        link_callback=_resolve_pdf_resource,
    )
    if result.err:
        raise ValueError('Unable to render incident report PDF')
    return output.getvalue()


def _register_pdf_font():
    xhtml2pdf_default.DEFAULT_FONT[REPORT_FONT_NAME.lower()] = REPORT_FONT_NAME
    if REPORT_FONT_NAME in pdfmetrics.getRegisteredFontNames():
        return

    registered = {}  # (bold, italic) -> reportlab font name
    for bold, italic, filename, font_name in REPORT_FONT_VARIANTS:
        font_path = REPORT_FONT_DIR / filename
        if not font_path.exists():
            continue
        try:
            pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
        except (OSError, TTFError):
            logger.warning('Could not register bundled report font %s', font_path)
            continue
        registered[(bold, italic)] = font_name

    if (0, 0) not in registered:
        # Bundled regular face missing/unreadable — fall back to a system font
        # so Thai text still renders instead of blank boxes.
        for font_path in REPORT_FONT_FALLBACKS:
            if not font_path.exists():
                continue
            try:
                pdfmetrics.registerFont(TTFont(REPORT_FONT_NAME, str(font_path)))
            except (OSError, TTFError):
                continue
            registered[(0, 0)] = REPORT_FONT_NAME
            logger.warning(
                'Bundled report font missing; using system fallback %s', font_path,
            )
            break

    if (0, 0) not in registered:
        logger.error(
            'No Thai-capable report font found (looked in %s and system paths); '
            'PDF Thai text will render as blank boxes',
            REPORT_FONT_DIR,
        )
        return

    regular = registered[(0, 0)]
    for bold in (0, 1):
        for italic in (0, 1):
            addMapping(REPORT_FONT_NAME, bold, italic, registered.get((bold, italic), regular))


def _resolve_pdf_resource(uri, rel):
    parsed = urlparse(uri)
    if parsed.scheme == 'file':
        path = unquote(parsed.path)
        if re.match(r'^/[A-Za-z]:/', path):
            path = path[1:]
        return path
    return uri


def _load_ticket(ticket_id):
    return (
        Ticket.objects
        .select_related(
            'project_incident', 'created_by', 'created_by__profile',
            'verified_by', 'approved_by', 'assigned_admin',
        )
        .prefetch_related('attachments')
        .get(pk=ticket_id)
    )


def _replace_placeholders(doc, context):
    replacements = {f'{{{{{key}}}}}': str(value) for key, value in context.items()}
    for paragraph in _iter_paragraphs(doc):
        text = paragraph.text
        if not text or '{{' not in text:
            continue
        replaced = text
        for placeholder, value in replacements.items():
            replaced = replaced.replace(placeholder, value)
        if replaced != text:
            _set_paragraph_text(paragraph, replaced)
    remaining = sorted({
        match
        for paragraph in _iter_paragraphs(doc)
        for match in re.findall(r'\{\{[^}]+\}\}', paragraph.text)
    })
    if remaining:
        raise ValueError(f'Unresolved report template placeholders: {", ".join(remaining)}')


def _iter_paragraphs(doc):
    for paragraph in doc.paragraphs:
        yield paragraph
    for table in doc.tables:
        yield from _iter_table_paragraphs(table)
    for section in doc.sections:
        for header_footer in (section.header, section.footer):
            for paragraph in header_footer.paragraphs:
                yield paragraph
            for table in header_footer.tables:
                yield from _iter_table_paragraphs(table)


def _iter_table_paragraphs(table):
    for row in table.rows:
        for cell in row.cells:
            for paragraph in cell.paragraphs:
                yield paragraph
            for nested in cell.tables:
                yield from _iter_table_paragraphs(nested)


def _set_paragraph_text(paragraph, text):
    if paragraph.runs:
        first = paragraph.runs[0]
        first.text = text
        for run in paragraph.runs[1:]:
            run.text = ''
    else:
        paragraph.add_run(text)


def _format_dt(value):
    if not value:
        return '-'
    if timezone.is_aware(value):
        value = timezone.localtime(value)
    return value.strftime('%d/%m/%Y %H:%M')


def _value(value):
    if value is None:
        return '-'
    text = str(value).strip()
    return text or '-'


def _user_label(user, include_phone=False):
    if not user:
        return '-'
    label = user.get_full_name() or user.username
    if include_phone:
        phone = getattr(getattr(user, 'profile', None), 'phone', '')
        if phone:
            label = f'{label}, {phone}'
    return label


def _spread_label(value):
    if value is True:
        return 'ใช่'
    if value is False:
        return 'ไม่ใช่'
    return 'รอตรวจสอบ'


def _attachment_summary(ticket):
    parts = []
    for attachment in ticket.attachments.all():
        label = attachment.original_name
        if attachment.description:
            label = f'{label} - {attachment.description}'
        parts.append(label)
    return '\n'.join(parts) if parts else '-'
