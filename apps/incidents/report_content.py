"""Static content shared by the incident-report DOCX builder and the HTML/PDF view.

Pure data — no Django imports — so ``scripts/build_report_template_v2.py`` can
import it without configuring Django, and ``apps.incidents.reports`` can reuse the
exact same strings. This keeps the Word template and the HTML preview from
drifting apart.
"""

FOOTER_LEFT = 'ส่วนปฏิบัติการความมั่นคงปลอดภัยไซเบอร์ (ปปกก)   โทร.0-2574-8209-10'
FOOTER_RIGHT = 'INCIDENT REPORT CONTAINMENT แบบฟอร์มรายงานเหตุการณ์ผิดปกติ'

# Section 8's fixed remediation checklist — ticked by hand on the printed form.
REMEDIATION_CHECKLIST = [
    'Isolate เครื่อง – แยกเครื่องที่ได้รับผลกระทบออกจากเครือข่าย',
    'Close Service ที่ไม่จำเป็น – ปิดบริการหรือพอร์ตที่เปิดเผยและมีความเสี่ยง',
    'Block IoC – บล็อกตัวบ่งชี้การโจมตี (IP, Domain, URL, Hash)',
    'Dump memory ของเครื่อง Server',
    'รวบรวม Event Logs เพื่อส่งต่อ ปปกก.',
    'Disable/Reset Account – ปิดการใช้งานหรือรีเซ็ตรหัสผ่านบัญชีที่ได้รับผลกระทบ',
    'เปลี่ยนรหัสผ่าน',
    'Remove Malware – กำจัดมัลแวร์ออกจากระบบ',
    'ลบไฟล์ และ Path ที่ต้องสงสัย',
    'Patch Vulnerability – ติดตั้งแพตช์แก้ไขช่องโหว่ที่เกี่ยวข้อง',
    'Update Software/OS – อัปเดตซอฟต์แวร์หรือระบบปฏิบัติการให้เป็นเวอร์ชันล่าสุด',
    'Harden Configuration – ปรับแต่งการตั้งค่าความปลอดภัยของระบบให้รัดกุมมากขึ้น',
    'ตรวจสอบการทำงานของภัยคุกคามยังทำงานอยู่หรือไม่',
    'ติดตั้ง Sysmon',
    'ติดตั้ง Agent Wazuh',
]

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
