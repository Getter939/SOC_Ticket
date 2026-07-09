import base64
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
from .report_content import (
    APPENDIX_CATEGORIES,
    APPENDIX_INTRO,
    FOOTER_LEFT,
    FOOTER_RIGHT,
    REMEDIATION_CHECKLIST,
)


logger = logging.getLogger(__name__)

REPORT_TEMPLATE_VERSION = 'v2'
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
# DejaVu Sans supplies the ballot-box glyphs (☐/☑) that TH Sarabun New lacks;
# used only for the checkbox marks in the PDF path.
SYMBOL_FONT_NAME = 'ReportSymbol'
SYMBOL_FONT_VARIANTS = (
    (0, 'DejaVuSans.ttf', SYMBOL_FONT_NAME),
    (1, 'DejaVuSans-Bold.ttf', f'{SYMBOL_FONT_NAME}-Bold'),
)

CHECKED = '☑'
UNCHECKED = '☐'


def _chk(flag):
    return CHECKED if flag else UNCHECKED

REPORT_LOGO_PATH = Path(__file__).resolve().parent / 'report_templates' / 'assets' / 'nt_logo.png'


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


def build_ticket_report_render_context(ticket, generated_at=None, show_report_actions=True):
    report = build_ticket_report_context(ticket, generated_at=generated_at)
    return {
        'ticket': ticket,
        'report': report,
        'sections': build_ticket_report_sections(report, ticket),
        'appendix_categories': APPENDIX_CATEGORIES,
        'appendix_intro': APPENDIX_INTRO,
        'footer_left': FOOTER_LEFT,
        'footer_right': FOOTER_RIGHT,
        'nt_logo': _logo_data_uri(),
        'show_report_actions': show_report_actions,
    }


def build_ticket_report_context(ticket, generated_at=None):
    generated_at = generated_at or timezone.now()
    asset = ticket.asset_type
    asset_known = asset in {'Computer', 'Server', 'Network Device'}
    return {
        'ticket_id': _value(ticket.display_id or ticket.ticket_id),
        'incident_datetime': _format_dt(ticket.incident_datetime),
        'incident_name': _value(ticket.incident_name),
        'category': _value(ticket.get_detailed_issue_display()),
        'reporter': _user_label(ticket.created_by, include_phone=True),
        'log_source': _value(ticket.log_source),
        'status': _value(ticket.get_status_display()),
        'actions_taken_summary': _value(ticket.actions_taken_summary),
        'next_steps_summary': _value(ticket.next_steps_summary),
        'incident_description': _value(ticket.issue_description),
        'host_ip': _host_ip(ticket),
        'system_name': _value(ticket.device_name),
        'asset_owner': _value(ticket.asset_owner),
        'host_name': _value(ticket.device_name),
        'ip_address': _value(ticket.ip_address),
        'operating_system': _value(ticket.operating_system),
        'ioc_process': _value(ticket.ioc_details),
        'ioc_command': '-',
        'ioc_hash': '-',
        'ioc_ip': _value(ticket.destination_ip),
        'evidence_log': _evidence_log(ticket),
        'action_required': _value(ticket.action_required),
        'action_precautions': _value(ticket.action_precautions),
        'remediation_summary': _value(ticket.remediation_summary),
        'containment_report': _value(ticket.containment_report),
        'signoff_admin': _signoff_name(ticket.assigned_admin),
        'signoff_approver': _signoff_name(ticket.approved_by),
        'template_version': REPORT_TEMPLATE_VERSION,
        'generated_at': _format_dt(generated_at),
        # Checkbox states (☑/☐) driven by the ticket's actual values.
        'chk_class_event': _chk(ticket.classification == Ticket.CLASSIFICATION_EVENT),
        'chk_class_incident': _chk(ticket.classification == Ticket.CLASSIFICATION_INCIDENT),
        'chk_sev_critical': _chk(ticket.severity == 'Critical'),
        'chk_sev_high': _chk(ticket.severity == 'High'),
        'chk_sev_medium': _chk(ticket.severity == 'Medium'),
        'chk_sev_low': _chk(ticket.severity == 'Low'),
        'chk_imp_high': _chk(ticket.is_emergency),
        'chk_imp_normal': _chk(not ticket.is_emergency),
        'chk_spread_yes': _chk(ticket.spread_to_others is True),
        'chk_spread_no': _chk(ticket.spread_to_others is False),
        'chk_ncsa_critical': _chk(ticket.ncsa_severity == Ticket.NCSA_SEVERITY_CRITICAL),
        'chk_ncsa_severe': _chk(ticket.ncsa_severity == Ticket.NCSA_SEVERITY_SEVERE),
        'chk_ncsa_nonsevere': _chk(ticket.ncsa_severity == Ticket.NCSA_SEVERITY_NON_SEVERE),
        'chk_asset_computer': _chk(asset == 'Computer'),
        'chk_asset_server': _chk(asset == 'Server'),
        'chk_asset_network': _chk(asset == 'Network Device'),
        'chk_asset_unknown': _chk(not asset_known),
    }


def build_ticket_report_sections(report, ticket):
    """Structured sections for the HTML/PDF preview, mirroring the v2 DOCX form.

    Row shapes consumed by report_preview.html:
      {'type': 'kv', 'label', 'value'}
      {'type': 'checks', 'label', 'options': [{'label', 'checked'}, ...]}
      {'type': 'text', 'value'}                     — full-width free-text box
      {'type': 'checklist', 'items': [str, ...]}    — static, hand-ticked
    """
    asset = ticket.asset_type
    asset_known = asset in {'Computer', 'Server', 'Network Device'}

    def kv(label, value):
        return {'type': 'kv', 'label': label, 'value': value}

    def checks(label, options):
        return {'type': 'checks', 'label': label,
                'options': [{'label': lbl, 'checked': flag} for lbl, flag in options]}

    def text(value):
        return {'type': 'text', 'value': value}

    asset_options = [
        ('Computer', asset == 'Computer'),
        ('Server', asset == 'Server'),
        ('Network Device', asset == 'Network Device'),
    ]
    spread_options = [
        ('ใช่', ticket.spread_to_others is True),
        ('ไม่ใช่', ticket.spread_to_others is False),
    ]

    return [
        {'number': '1', 'title': 'ข้อมูลทั่วไป (General Information)', 'rows': [
            kv('หมายเลข Incident', report['ticket_id']),
            kv('วันที่ เวลา ที่พบเหตุ', report['incident_datetime']),
            kv('วันที่ เวลา ที่เกิดเหตุ', report['incident_datetime']),
            kv('ชื่อ incident/event', report['incident_name']),
            checks('ประเภท: event หรือ incident', [
                ('Event', ticket.classification == Ticket.CLASSIFICATION_EVENT),
                ('Incident', ticket.classification == Ticket.CLASSIFICATION_INCIDENT)]),
            checks('ระดับความรุนแรง (อ้างอิงตามระบบ SIEM)', [
                ('Critical', ticket.severity == 'Critical'),
                ('High', ticket.severity == 'High'),
                ('Medium', ticket.severity == 'Medium'),
                ('Low', ticket.severity == 'Low')]),
            checks('ระดับความสำคัญ', [
                ('สำคัญ', not ticket.is_emergency),
                ('สำคัญมาก', ticket.is_emergency)]),
            checks('มีการกระจายไปยังจุดอื่น', spread_options),
            checks('ระดับความรุนแรง (อ้างอิงตาม สกมช.)', [
                ('วิกฤต', ticket.ncsa_severity == Ticket.NCSA_SEVERITY_CRITICAL),
                ('ร้ายแรง', ticket.ncsa_severity == Ticket.NCSA_SEVERITY_SEVERE),
                ('ไม่ร้ายแรง', ticket.ncsa_severity == Ticket.NCSA_SEVERITY_NON_SEVERE)]),
            kv('*หมวดหมู่ของภัยคุกคามทางไซเบอร์ (Category)', report['category']),
            kv('ทรัพย์สินที่ได้รับผลกระทบ', report['host_ip']),
            checks('ประเภททรัพย์สินที่ได้รับผลกระทบ', asset_options),
            kv('ส่วนงานเจ้าของหรือผู้ดูแลทรัพย์สิน', report['asset_owner']),
            kv('ระบบที่ได้รับผลกระทบ', report['system_name']),
            kv('สถานะปัจจุบัน', report['status']),
            kv('เรื่องที่ดำเนินการแล้ว', report['actions_taken_summary']),
            kv('การที่จะดำเนินการลำดับถัดไป', report['next_steps_summary']),
            kv('ผู้รายงาน', report['reporter']),
            kv('แหล่งข้อมูล', report['log_source']),
        ]},
        {'number': '2', 'title': 'รายละเอียดเหตุการณ์ (Incident Description)', 'rows': [
            text(report['incident_description'])]},
        {'number': '3', 'title': 'Scope ทรัพย์สินที่ได้รับผลกระทบ', 'rows': [
            kv('ระบบ/บริการ', report['system_name']),
            kv('หน่วยงานเจ้าของทรัพย์สิน', report['asset_owner']),
            kv('Host Name', report['host_name']),
            kv('IP Address', report['ip_address']),
            kv('Operating System', report['operating_system']),
            checks('ประเภทของทรัพย์สิน', asset_options + [('ไม่ทราบ', not asset_known)]),
            checks('มีการกระจายไปยังจุดอื่น', spread_options),
        ]},
        {'number': '4', 'title': 'Indicators of Compromise หรือหลักฐานที่พบ', 'rows': [
            kv('Process/File Path', report['ioc_process']),
            kv('คำสั่ง', report['ioc_command']),
            kv('Hash', report['ioc_hash']),
            kv('IP', report['ioc_ip']),
        ]},
        {'number': '5', 'title': 'Evidence / Log', 'rows': [text(report['evidence_log'])]},
        {'number': '6', 'title': 'สิ่งที่ต้องดำเนินการ (Containment)', 'rows': [
            text(report['action_required'])]},
        {'number': '7', 'title': 'ข้อควรระวังในการดำเนินการ', 'rows': [
            text(report['action_precautions'])]},
        {'number': '8', 'title': 'สรุปผลการดำเนินการแก้ไข', 'rows': [
            {'type': 'checklist', 'items': REMEDIATION_CHECKLIST},
            kv('ผลการตรวจสอบ / Investigation Findings', report['remediation_summary']),
            kv('มาตรการควบคุม / Countermeasure', report['containment_report']),
        ]},
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

    _register_symbol_font()


def _register_symbol_font():
    """Register DejaVu Sans for the checkbox glyphs the PDF path needs."""
    xhtml2pdf_default.DEFAULT_FONT[SYMBOL_FONT_NAME.lower()] = SYMBOL_FONT_NAME
    if SYMBOL_FONT_NAME in pdfmetrics.getRegisteredFontNames():
        return
    symbol_regular = None
    for bold, filename, font_name in SYMBOL_FONT_VARIANTS:
        font_path = REPORT_FONT_DIR / filename
        if not font_path.exists():
            continue
        try:
            pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
        except (OSError, TTFError):
            continue
        if bold == 0:
            symbol_regular = font_name
    if symbol_regular is None:
        logger.warning(
            'Checkbox symbol font (DejaVu Sans) missing in %s; PDF checkboxes '
            'may render as blank boxes', REPORT_FONT_DIR,
        )


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
    # Replace within individual runs (not whole paragraphs) so each run keeps
    # its own font — the template authors every {{placeholder}} as its own run,
    # letting checkbox glyphs (DejaVu Sans) and labels (TH Sarabun New) coexist
    # in one cell. run.text's setter turns \n into <w:br>, so multi-line values
    # keep their line breaks. A placeholder split across runs is left in place
    # and caught by the unresolved-placeholder check below.
    replacements = {f'{{{{{key}}}}}': str(value) for key, value in context.items()}
    for paragraph in _iter_paragraphs(doc):
        for run in paragraph.runs:
            text = run.text
            if '{{' not in text:
                continue
            replaced = text
            for placeholder, value in replacements.items():
                if placeholder in replaced:
                    replaced = replaced.replace(placeholder, value)
            if replaced != text:
                run.text = replaced
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


def _attachment_summary(ticket):
    parts = []
    for attachment in ticket.attachments.all():
        label = attachment.original_name
        if attachment.description:
            label = f'{label} - {attachment.description}'
        parts.append(label)
    return '\n'.join(parts) if parts else '-'


def _host_ip(ticket):
    parts = [p for p in (ticket.device_name, ticket.ip_address) if p]
    return ' / '.join(parts) if parts else '-'


def _evidence_log(ticket):
    parts = []
    attachments = _attachment_summary(ticket)
    if attachments != '-':
        parts.append(attachments)
    mitre = ', '.join(ticket.mitre_phase_labels)
    if mitre:
        parts.append(f'MITRE ATT&CK: {mitre}')
    return '\n'.join(parts) if parts else '-'


def _signoff_name(user):
    if not user:
        return '(........................................................)'
    return f'( {user.get_full_name() or user.username} )'


def _logo_data_uri():
    if not REPORT_LOGO_PATH.exists():
        return ''
    encoded = base64.b64encode(REPORT_LOGO_PATH.read_bytes()).decode('ascii')
    return f'data:image/png;base64,{encoded}'
