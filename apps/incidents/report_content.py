"""Static content shared by the incident-report DOCX builder and the HTML/PDF view.

Pure data — no Django imports — so ``scripts/build_report_template_v2.py`` can
import it without configuring Django, and ``apps.incidents.reports`` can reuse the
exact same strings. This keeps the Word template and the HTML preview from
drifting apart.
"""

FOOTER_LEFT = 'ส่วนปฏิบัติการความมั่นคงปลอดภัยไซเบอร์ (ปปกก)   โทร.0-2574-8209-10'
FOOTER_RIGHT = 'INCIDENT REPORT CONTAINMENT แบบฟอร์มรายงานเหตุการณ์ผิดปกติ'

# Global coordination note appended once when standard guidance is inserted on
# the create-ticket form. Contact numbers taken verbatim from the official NT
# incident-report form (SOC Report Template).
GUIDANCE_COORDINATION_NOTE = (
    'หมายเหตุ: สามารถประสานงานเรื่องเหตุละเมิดได้ดังนี้\n'
    'เรื่องการเฝ้าระวัง: 02-574-8209-10 (ปปกก.)\n'
    'เรื่องการส่ง log เพื่อให้ตรวจหาต้นเหตุของเหตุละเมิด: 02-574-8209-10 (ปปกก.)\n'
    'เรื่องการตรวจประเมินช่องโหว่ (VA) และการทดสอบเจาะระบบ (PT): 02-575-6883 (มปกก.)\n'
    'เรื่องขอคำแนะนำ การทำให้เซิร์ฟเวอร์แข็งแกร่ง (Hardening): 02-575-6883 (มปกก.)\n'
    'เรื่องขอคำแนะนำ Network Security และ Infrastructure Security: 02-574-8186 (วปกก.)'
)

# Section 8 used to carry a fixed 15-item remediation checklist, ticked by hand
# on the printed form. It was removed: it was static boilerplate that no ticket
# field ever drove, always rendered unticked, and section 6 already carries a
# real containment checklist whose done-state comes from `action_required`
# (Ticket.containment_checklist). Section 8 now shows only its two data rows.


# ── Table-row layout, shared by the DOCX builder and the HTML/PDF view ───── #
# Both renderers walk these lists, so a label, a row order, or a checkbox
# option order is written once. Previously each was typed into both
# apps/incidents/reports.py and scripts/build_report_template_v2.py, and had to
# be edited in lockstep — a miss only shows up as a DOCX export disagreeing with
# the PDF of the same ticket, which no test catches because the .docx is a
# hand-rebuilt binary.
#
# Row shapes:
#   ('kv',     label, context_key)
#       DOCX renders '{{context_key}}'; HTML renders report[context_key].
#   ('checks', label, [(chk_key, option_label), ...])
#       Both read the chk_* keys build_ticket_report_context already produces,
#       so the ticked state is computed in exactly one place.
#
# Section 1's rows are numbered 1.N to match the paper form. The numbers run
# sequentially over OUR row set, which is wider than the NT form's, so they
# deliberately do not correspond one-for-one with that document.

SECTION1_ROWS = [
    ('kv', '1.1 หมายเลข Incident', 'ticket_id'),
    ('kv', '1.2 วันที่ เวลา ที่พบเหตุ', 'incident_datetime'),
    ('kv', '1.3 วันที่ เวลา ที่เกิดเหตุ', 'incident_datetime'),
    ('kv', '1.4 ชื่อ incident/event', 'incident_name'),
    ('checks', '1.5 ประเภท: event หรือ incident', [
        ('chk_class_incident', 'Incident'),
        ('chk_class_event', 'Event')]),
    ('checks', '1.6 ระดับความรุนแรง (อ้างอิงตามระบบ SIEM)', [
        ('chk_sev_low', 'Low'),
        ('chk_sev_medium', 'Medium'),
        ('chk_sev_high', 'High'),
        ('chk_sev_critical', 'Critical')]),
    ('checks', '1.7 ระดับความสำคัญ', [
        ('chk_imp_normal', 'สำคัญ'),
        ('chk_imp_high', 'สำคัญมาก')]),
    ('checks', '1.8 มีการกระจายไปยังจุดอื่น', [
        ('chk_spread_yes', 'ใช่'),
        ('chk_spread_no', 'ไม่ใช่')]),
    ('checks', '1.9 ระดับความรุนแรง (อ้างอิงตาม สกมช.)', [
        ('chk_ncsa_nonsevere', 'ไม่ร้ายแรง'),
        ('chk_ncsa_severe', 'ร้ายแรง'),
        ('chk_ncsa_critical', 'วิกฤต')]),
    ('kv', '1.10 *หมวดหมู่ของภัยคุกคามทางไซเบอร์ (Category)', 'category'),
    ('kv', '1.11 ทรัพย์สินที่ได้รับผลกระทบ', 'host_ip'),
    ('checks', '1.12 ประเภททรัพย์สินที่ได้รับผลกระทบ', [
        ('chk_asset_computer', 'Computer'),
        ('chk_asset_server', 'Server'),
        ('chk_asset_network', 'Network Device')]),
    ('kv', '1.13 ส่วนงานเจ้าของหรือผู้ดูแลทรัพย์สิน', 'asset_owner'),
    ('kv', '1.14 ชื่อเจ้าของทรัพย์สิน', 'asset_owner_name'),
    ('kv', '1.15 ระบบที่ได้รับผลกระทบ', 'system_name'),
    ('kv', '1.16 สถานะปัจจุบัน', 'status'),
    ('kv', '1.17 เรื่องที่ดำเนินการแล้ว', 'actions_taken_summary'),
    ('kv', '1.18 การที่จะดำเนินการลำดับถัดไป', 'next_steps_summary'),
    ('kv', '1.19 ผู้รายงาน', 'reporter'),
    ('kv', '1.20 แหล่งข้อมูล', 'log_source'),
]

SECTION3_ROWS = [
    ('kv', 'ระบบ/บริการ', 'system_name'),
    ('kv', 'หน่วยงานเจ้าของทรัพย์สิน', 'asset_owner'),
    ('kv', 'ชื่อเจ้าของทรัพย์สิน', 'asset_owner_name'),
    ('kv', 'Host Name', 'host_name'),
    ('kv', 'IP Address', 'ip_address'),
    ('kv', 'Operating System', 'operating_system'),
    ('checks', 'ประเภทของทรัพย์สิน', [
        ('chk_asset_computer', 'Computer'),
        ('chk_asset_server', 'Server'),
        ('chk_asset_network', 'Network Device'),
        ('chk_asset_unknown', 'ไม่ทราบ')]),
    ('checks', 'มีการกระจายไปยังจุดอื่น', [
        ('chk_spread_yes', 'ใช่'),
        ('chk_spread_no', 'ไม่ใช่')]),
]

SECTION4_ROWS = [
    ('kv', 'Process/File Path', 'ioc_process'),
    ('kv', 'คำสั่ง', 'ioc_command'),
    ('kv', 'Hash', 'ioc_hash'),
    ('kv', 'IP', 'ioc_ip'),
    ('kv', 'User', 'ioc_user'),
]

# Section titles, likewise shared so the two renderers cannot drift.
SECTION_TITLES = {
    '1': 'ข้อมูลทั่วไป (General Information)',
    '2': 'รายละเอียดเหตุการณ์ (Incident Description)',
    '3': 'Scope ทรัพย์สินที่ได้รับผลกระทบ',
    '4': 'Indicators of Compromise หรือหลักฐานที่พบ',
    '5': 'Evidence / Log',
    '6': 'สิ่งที่ต้องดำเนินการ (Containment)',
    '7': 'ข้อควรระวังในการดำเนินการ',
    '8': 'สรุปผลการดำเนินการแก้ไข',
}

APPENDIX_INTRO = (
    'อ้างอิงตาม ภาคผนวก ท้ายประกาศคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ '
    'เรื่อง ลักษณะภัยคุกคามทางไซเบอร์ มาตรการป้องกัน รับมือ ประเมิน ปราบปราม '
    'และระงับภัยคุกคามทางไซเบอร์แต่ละระดับ พ.ศ. 2564'
)

# (Thai numeral, description) — the statutory cyber-threat categories (ข้อ ๑).
APPENDIX_CATEGORIES = [
    ('๐', 'เหตุการณ์จำลอง และ การฝึกจู่โจม ของหน่วยงาน (Training and Exercises)'),
    ('๑', 'การพยายามเข้าถึงระบบที่ไม่สำเร็จ (Unsuccessful Activity Attempt)'),
    ('๒', 'การพยายามบุกรุกเพื่อสำรวจข้อมูลองค์กรเพื่อโจมตี (Reconnaissance)'),
    ('๓', 'การดำเนินการที่ไม่เป็นไปตามมาตรฐานความปลอดภัยที่หน่วยงานกำหนด (Non-Compliance Activity)'),
    ('๔', 'การบุกรุกโดยการใช้มัลแวร์ (Malicious Logic)'),
    ('๕', 'การบุกรุกในระดับผู้ใช้งาน (User Level Intrusion)'),
    ('๖', 'การบุกรุกในระดับผู้ควบคุมระบบ (Root Level Intrusion)'),
    ('๗', 'การบุกรุกที่ทำให้ไม่สามารถเข้าใช้บริการได้ (Denial of Service)'),
    ('๘', 'เหตุการณ์ที่อยู่ระหว่างการวิเคราะห์สอบสวน (Investigating)'),
    ('๙', 'เหตุการณ์ผิดปกติที่ได้รับการวิเคราะห์แล้วไม่ใช่เหตุการณ์ที่เป็นภัยคุกคาม (Explained Anomaly)'),
]
