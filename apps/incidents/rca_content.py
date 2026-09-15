"""Static layout of the Root Cause Analysis report.

Django-free, like report_content: shared by the DOCX template builder
(scripts/build_rca_report_template_v1.py) and the draft generator
(apps.incidents.rca_report), so a label, a column or a placeholder is written
once and both sides stay in step.

Placeholder conventions:
  * Section 1 and the page header use ``{{rca_*}}`` keys.
  * Each repeatable table has one prototype row of ``{{<prefix>_<field>}}`` keys;
    the generator clones that row once per item (see RCA_REPEAT_PREFIXES).
"""

RCA_TEMPLATE_VERSION = 'rca-v1'

RCA_TITLE = 'ROOT CAUSE ANALYSIS REPORT'
RCA_SUBTITLE = 'รายงานผลการตรวจพิสูจน์พยานหลักฐานดิจิทัลและการวิเคราะห์ Root Cause'
RCA_CASE_LABEL = 'หมายเลขเคส (Case No.)'
RCA_HEADER_LEFT = 'ส่วนปฏิบัติการความมั่นคงปลอดภัยไซเบอร์ (ปปกก.) 0-2574-8209-10'
RCA_TLP_LABEL = 'TLP:AMBER'
RCA_FOOTER_LEFT = 'ชั้นความลับ: ปกปิด (Confidential) — ห้ามเผยแพร่นอกหน่วยงาน'

# number → (Thai title, English title)
RCA_SECTION_TITLES = {
    '1': ('ข้อมูลทั่วไป', 'General Information'),
    '2': ('บทสรุปผู้บริหาร', 'Executive Summary'),
    '3': ('ภาพรวมเหตุการณ์', 'Incident Overview'),
    '4': ('ทรัพย์สินที่ถูกบุกรุก', 'Affected Assets'),
    '5': ('ลำดับเวลาเหตุการณ์', 'Consolidated Timeline — UTC+7'),
    '6': ('การวิเคราะห์ Root Cause', 'Root Cause Analysis'),
    '7': ('ตัวบ่งชี้การถูกบุกรุกและผลวิเคราะห์ไฟล์ต้องสงสัย', 'IOC & Malware Analysis'),
    '8': ('คำแนะนำในการแก้ไขสาเหตุหลัก', 'Root Cause Remediation Recommendations'),
}
RCA_SUBSECTION_TITLES = {
    '6.1': 'ลำดับเหตุการณ์เชิงสาเหตุ (Causal Sequence of Events)',
    '6.2': 'สรุป Root Cause และปัจจัยร่วม',
    '7.1': 'รายการไฟล์ต้องสงสัยและเส้นทางบนเครื่อง',
    '7.2': 'การทำงานของไฟล์ต้องสงสัย',
    '7.3': 'IP Address',
    '7.4': 'URL / Path บนเว็บ',
    '7.5': 'Hash ของไฟล์ (SHA-256)',
    '7.6': 'บัญชีผู้ใช้',
}

# Kept in step with RCAReport.FORENSIC_TYPE_CHOICES (a test guards it).
RCA_FORENSIC_TYPES = (
    ('host_disk', 'Host / Disk Triage'),
    ('log_timeline', 'Log & Timeline Analysis'),
    ('malware', 'Malware Analysis'),
    ('memory', 'Memory Forensic'),
    ('network', 'Network Forensic'),
)

# Same row shapes as report_content: ('kv', label, key) / ('checks', label, [(key, option)]).
RCA_SECTION1_ROWS = [
    ('kv', '1.1 หมายเลขเคสการตรวจพิสูจน์', 'rca_case_no'),
    ('kv', '1.2 ชื่อเหตุการณ์', 'rca_incident_name'),
    ('kv', '1.3 วันที่/เวลา ที่เกิดเหตุครั้งแรก (ยืนยันได้)', 'rca_first_occurrence'),
    ('kv', '1.4 วันที่/เวลา ที่ตรวจพบ', 'rca_detected'),
    ('kv', '1.5 ช่วงเวลาที่ตรวจพิสูจน์ (Scope)', 'rca_scope'),
    ('checks', '1.6 ประเภทการตรวจพิสูจน์',
     [(f'rca_chk_ft_{key}', label) for key, label in RCA_FORENSIC_TYPES]),
    ('checks', '1.7 ระดับความสำคัญ', [
        ('rca_chk_imp_general', 'ปกติทั่วไป'),
        ('rca_chk_imp_important', 'สำคัญ'),
        ('rca_chk_imp_critical', 'สำคัญมาก'),
    ]),
    ('checks', '1.8 ระดับความรุนแรง (อ้างอิงตามระบบ SIEM)', [
        ('rca_chk_siem_low', 'Low'),
        ('rca_chk_siem_moderate', 'Moderate'),
        ('rca_chk_siem_high', 'High'),
        ('rca_chk_siem_critical', 'Critical'),
    ]),
    ('checks', '1.9 ระดับความรุนแรง (อ้างอิงตาม สกมช.)', [
        ('rca_chk_ncsa_non_severe', 'ไม่ร้ายแรง'),
        ('rca_chk_ncsa_severe', 'ร้ายแรง'),
        ('rca_chk_ncsa_critical', 'วิกฤต'),
    ]),
    ('kv', '1.10 *หมวดหมู่ของภัยคุกคามทางไซเบอร์', 'rca_threat_category'),
    ('kv', '1.11 ทรัพย์สินที่นำเข้าตรวจพิสูจน์', 'rca_assets_examined'),
    ('checks', '1.12 ประเภททรัพย์สิน', [
        ('rca_chk_asset_computer', 'Computer'),
        ('rca_chk_asset_server', 'Server'),
        ('rca_chk_asset_network', 'Network Device'),
        ('rca_chk_asset_unknown', 'ไม่ทราบ'),
    ]),
    ('kv', '1.13 ระบบ/บริการที่ได้รับผลกระทบ', 'rca_affected_systems'),
    ('kv', '1.14 ส่วนงานเจ้าของหรือผู้ดูแลทรัพย์สิน', 'rca_asset_owner'),
    ('kv', '1.15 ผู้ตรวจพิสูจน์', 'rca_examiner'),
    ('kv', '1.16 เลขอ้างอิงที่เกี่ยวข้อง', 'rca_related_refs'),
]

# Repeatable tables: (column header, placeholder key, width in cm). The page's
# content width is 17 cm. A key of None marks a column the analyst fills in Word.
RCA_ASSET_COLUMNS = (
    ('เครื่อง', 'as_host', 4.3),
    ('IP Address', 'as_ip', 4.2),
    ('ระบบปฏิบัติการ', 'as_detail', 8.5),
)
RCA_TIMELINE_COLUMNS = (
    ('วัน/เวลา', 'tl_when', 2.2),
    ('เครื่อง', 'tl_host', 2.8),
    ('เหตุการณ์', 'tl_event', 4.6),
    ('ไฟล์หลักฐาน', 'tl_evidence', 2.8),
    ('ตัวอย่างจากไฟล์หลักฐาน', 'tl_excerpt', 4.6),
)
RCA_ROOT_CAUSE_COLUMNS = (
    ('รหัส', 'rc_code', 1.4),
    ('ประเภท', 'rc_category', 2.1),
    ('สาเหตุ', 'rc_cause', 5.3),
    ('ไฟล์หลักฐาน / Event ID / บรรทัด', 'rc_evidence', 3.7),
    ('ตัวอย่างจากไฟล์หลักฐาน', 'rc_excerpt', 4.5),
)
RCA_FILE_PATH_COLUMNS = (
    ('Path บนเครื่อง', 'fp_value', 9.9),
    ('เครื่อง', 'fp_host', 2.2),
    ('ประเภท / หลักฐานที่พบ', 'fp_note', 4.9),
)
RCA_FILE_BEHAVIOR_COLUMNS = (
    ('ไฟล์ที่พบ', None, 4.2),
    ('การทำงานของไฟล์', None, 12.8),
)
RCA_IP_COLUMNS = (
    ('Indicator', 'ip_value', 4.2),
    ('ประเภท', 'ip_label', 2.8),
    ('บทบาทในเหตุการณ์', 'ip_note', 10.0),
)
RCA_WEB_COLUMNS = (
    ('Indicator', 'web_value', 9.0),
    ('ประเภท', 'web_label', 2.6),
    ('หมายเหตุ', 'web_note', 5.4),
)
RCA_HASH_COLUMNS = (
    ('ไฟล์ / ที่พบ', 'hash_label', 5.3),
    ('ค่า Hash (SHA-256)', 'hash_value', 11.7),
)
RCA_ACCOUNT_COLUMNS = (
    ('บัญชี', 'acct_value', 3.0),
    ('เครื่อง', 'acct_host', 3.0),
    ('หมายเหตุ', 'acct_note', 11.0),
)
RCA_RECOMMENDATION_COLUMNS = (
    ('ที่', 'rec_no', 1.2),
    ('สิ่งที่ควรดำเนินการ', 'rec_action', 15.8),
)

# Every repeatable table the generator expands, by placeholder prefix.
RCA_REPEAT_TABLES = {
    'as': RCA_ASSET_COLUMNS,
    'tl': RCA_TIMELINE_COLUMNS,
    'rc': RCA_ROOT_CAUSE_COLUMNS,
    'fp': RCA_FILE_PATH_COLUMNS,
    'ip': RCA_IP_COLUMNS,
    'web': RCA_WEB_COLUMNS,
    'hash': RCA_HASH_COLUMNS,
    'acct': RCA_ACCOUNT_COLUMNS,
    'rec': RCA_RECOMMENDATION_COLUMNS,
}
RCA_REPEAT_PREFIXES = tuple(RCA_REPEAT_TABLES)
# Evidence excerpts and hashes render smaller so long log lines still fit.
RCA_SMALL_TEXT_KEYS = frozenset({'tl_excerpt', 'rc_excerpt', 'hash_value'})

# Bracketed guidance for the sections written in Word — no placeholders, so
# the draft keeps them until the analyst replaces them.
RCA_GUIDANCE = {
    '2': '[เขียนบทสรุปผู้บริหาร: ช่วงเวลาและภาพรวมของเหตุการณ์ ระบบที่ได้รับผลกระทบ '
         'สิ่งที่พบ และสิ่งที่ตรวจสอบแล้วไม่พบ]',
    '2_primary': '[สรุปสาเหตุหลักของเหตุการณ์และเหตุผลที่ตรวจพบล่าช้า (ถ้ามี) ในหนึ่งย่อหน้า]',
    '5': '[อธิบายขอบเขตของลำดับเวลา: เครื่อง/บัญชีที่เกี่ยวข้อง แหล่งไฟล์หลักฐาน '
         'และการปรับเวลาเป็น UTC+7]',
    '6.1': '[อธิบายลำดับเหตุการณ์เชิงสาเหตุ: ช่องทางเข้า การขยายผล '
           'และเหตุผลที่การป้องกัน/ตรวจจับไม่ทำงาน]',
    '7.2': '[หมายเหตุ: วิธีการวิเคราะห์ (static / dynamic) และข้อจำกัดของหลักฐานที่มี]',
    '8': '[ลำดับการดำเนินการ เช่น เก็บพยานหลักฐานก่อนกำจัดมัลแวร์ '
         'และสร้างระบบใหม่จากซอร์สที่สะอาด]',
}
# Section 3 figure slots: (placeholder text, caption).
RCA_FIGURES = (
    ('[แทรกรูปที่ 1 — แผนผังระบบและขอบเขตผลกระทบ]', 'รูปที่ 1 — แผนผังระบบและขอบเขตผลกระทบ'),
    ('[แทรกรูปที่ 2 — แผนภาพลำดับการโจมตี]', 'รูปที่ 2 — แผนภาพลำดับการโจมตี'),
)
RCA_PRIMARY_ROOT_CAUSE_LABEL = 'Root Cause หลัก (Primary Root Cause):'
