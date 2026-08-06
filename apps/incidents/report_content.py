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
