# Seed the standard containment guidance per threat category.
#
# Content approved by the SOC lead (Containment Seed Data, 2026-07-10):
# real examples generalised into reusable templates for User/Root Intrusion,
# Malicious Logic and Unsuccessful Attempt; the remaining categories follow
# the same house style. Editable afterwards in Django admin — this seed only
# fills categories that don't already have a row.
from django.db import migrations


SEED = {
    'Training': {
        'action_required': (
            '1) ยืนยันกับทีมที่รับผิดชอบว่าเป็นการฝึก/ทดสอบตามแผน\n'
            '2) ตรวจสอบขอบเขต (IP/ช่วงเวลา/ระบบเป้าหมาย) ให้ตรงที่แจ้งไว้\n'
            '3) เพิ่ม IP/บัญชีของการฝึกเข้า whitelist ชั่วคราว\n'
            '4) ปิดเคสเป็น Event เมื่อยืนยันแล้ว'
        ),
        'action_precautions': (
            '1) อย่าปิดเคสจนกว่าจะยืนยันแหล่งที่มาว่าเป็นการฝึกจริง\n'
            '2) ตรวจว่าไม่มีกิจกรรมนอกขอบเขตปะปน\n'
            '3) บันทึกผู้ยืนยัน เวลา และขอบเขต'
        ),
    },
    'Unsuccessful Attempt': {
        'action_required': (
            '1) Block IP และ URL ที่เป็นอันตราย\n'
            '2) ตรวจสอบและ Patch อุปกรณ์/ระบบที่ตกเป็นเป้าหมาย\n'
            '3) จำกัดการเข้าถึงหน้า Management เฉพาะ IP ที่ได้รับอนุญาต\n'
            '4) ตรวจบัญชีผู้ดูแลระบบว่ามีบัญชีแปลกปลอม/ถูกสร้างใหม่หรือไม่\n'
            '5) ตรวจ Log ว่ามี Request ใดสำเร็จ หรือ Config เปลี่ยนผิดปกติหรือไม่'
        ),
        'action_precautions': (
            '1) ห้ามลบ Log ก่อน Export เก็บเป็นหลักฐาน\n'
            '2) สำรอง Config ก่อนแก้ไข/Patch\n'
            '3) ตรวจ Admin, API Token, SSH Key ก่อนและหลังดำเนินการ\n'
            '4) พบ Config ผิดปกติให้เก็บหลักฐานก่อน Rollback\n'
            '5) ไม่เปิดหน้า Management ออกอินเทอร์เน็ตโดยตรง'
        ),
    },
    'Reconnaissance': {
        'action_required': (
            '1) Block IP ต้นทางที่สแกน/สำรวจ\n'
            '2) ตรวจว่าบริการ/พอร์ตที่ถูกสำรวจมีช่องโหว่หรือเปิดเผยข้อมูลเกินจำเป็น\n'
            '3) จำกัด/ปิดพอร์ตและบริการที่ไม่จำเป็นที่เปิดออกภายนอก\n'
            '4) ตั้ง Rate-limit / IPS rule ลดการสแกนซ้ำ\n'
            '5) เฝ้าระวังการยกระดับไปเป็นการโจมตีจริง'
        ),
        'action_precautions': (
            '1) เก็บ Log การสแกนไว้เป็นหลักฐานก่อนดำเนินการ\n'
            '2) อย่าเปิดเผย banner/version เกินจำเป็น\n'
            '3) เฝ้าระวังต่อเนื่อง\n'
            '4) บันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'Non-Compliance': {
        'action_required': (
            '1) ระบุการกระทำที่ฝ่าฝืน (USB ต้องห้าม, ซอฟต์แวร์ไม่ได้รับอนุญาต, ปิด Antivirus, รหัสผ่านไม่ตรง policy)\n'
            '2) ระงับ/แก้ไข (ถอนซอฟต์แวร์, เปิด Antivirus, บังคับเปลี่ยนรหัสผ่าน)\n'
            '3) แจ้งผู้ใช้/เจ้าของระบบให้ปฏิบัติตามมาตรฐาน\n'
            '4) ตรวจว่าการกระทำนั้นก่อให้เกิดช่องโหว่/การบุกรุกตามมาหรือไม่'
        ),
        'action_precautions': (
            '1) เก็บหลักฐานการฝ่าฝืน (Log/ภาพหน้าจอ) ก่อนแก้ไข\n'
            '2) ประสานเจ้าของระบบ/ต้นสังกัดก่อนดำเนินการกับผู้ใช้\n'
            '3) บันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'Malicious Logic': {
        'action_required': (
            '1) Isolate เครื่องที่ติดมัลแวร์ออกจากเครือข่ายทันที (ผ่าน EDR ก่อนตัดสายจริง)\n'
            '2) Disable/Reset บัญชีที่คาดว่าถูก compromised\n'
            '3) Block IOC ที่พบทั้งหมด (IP, URL, Domain, File Hash)\n'
            '4) ค้นหาและลบ Persistence (Scheduled Task / Registry / Service / WMI)\n'
            '5) Dump Memory และรวบรวม Event Logs (Security/System/Application) ส่งให้ มปกก. วิเคราะห์\n'
            '6) Clear เครื่อง หรือ Re-image หาก Persistence ฝังลึก\n'
            '7) ทำ Hardening และติดตั้ง Sysmon + Agent Wazuh เพื่อเฝ้าระวังต่อเนื่อง'
        ),
        'action_precautions': (
            '1) ห้ามลบไฟล์ต้องสงสัยก่อนเก็บหลักฐาน\n'
            '2) ห้าม Restart/Shutdown ก่อนเก็บ Memory และ Process\n'
            '3) ห้ามลบ/แก้ไข Log ก่อนส่งวิเคราะห์\n'
            '4) อย่าเชื่อสถานะ "Quarantine successfully" ของ AV เพียงอย่างเดียว\n'
            '5) เก็บรักษา Log (EDR, Windows Event, VPN, Proxy, Firewall) และบันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'User Intrusion': {
        'action_required': (
            '1) Isolate เครื่องที่ได้รับผลกระทบทันที\n'
            '2) Disable บัญชีผู้ใช้ที่คาดว่าถูก compromised\n'
            '3) ค้นหา Persistence (Scheduled Task / Registry / Service)\n'
            '4) ตรวจสอบและปิดช่องโหว่ที่เป็นช่องทางบุกรุก\n'
            '5) รวบรวม Log ที่เกี่ยวข้องส่งให้ มปกก.'
        ),
        'action_precautions': (
            '1) ห้ามปิดเครื่อง/ติดตั้ง OS ใหม่ก่อนเก็บหลักฐาน\n'
            '2) ห้ามลบไฟล์ที่น่าสงสัย\n'
            '3) เก็บรักษา EDR, Windows Event, VPN, Proxy, Firewall Logs\n'
            '4) บันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'Root Intrusion': {
        'action_required': (
            '1) Isolate เครื่อง/เซิร์ฟเวอร์ที่ได้รับผลกระทบทันที\n'
            '2) เปลี่ยนรหัสผ่าน Admin/Domain Admin และล้างค่า Ticket (KRBTGT) ใน AD\n'
            '3) Dump Memory หาหลักฐานและวิธีการโจมตี\n'
            '4) ค้นหา Persistence (Scheduled Task / Registry / Service / WMI Subscription)\n'
            '5) ตรวจ Domain Controller Logs หาการใช้บัญชีผิดปกติ\n'
            '6) ปิดช่องโหว่ (Apply Security Patch) ป้องกันโจมตีซ้ำ'
        ),
        'action_precautions': (
            '1) ห้ามปิดเครื่อง/Re-image ก่อนเก็บหลักฐาน\n'
            '2) ห้ามลบไฟล์/Service ที่น่าสงสัย\n'
            '3) เก็บรักษา EDR, Windows Event, PowerShell, VPN, Proxy, Firewall และ SMB/WinRM Logs\n'
            '4) บันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'DoS': {
        'action_required': (
            '1) ระบุรูปแบบการโจมตี (SYN/HTTP Flood, DDoS) และปริมาณ Traffic\n'
            '2) Block/Rate-limit IP ต้นทางที่ผิดปกติ\n'
            '3) เปิดใช้ระบบป้องกัน DDoS / ประสาน ISP หรือ Upstream เพื่อ Mitigate\n'
            '4) ปรับ Scaling/Failover รักษาความต่อเนื่องของบริการ\n'
            '5) เฝ้าระวัง Traffic และสถานะระบบต่อเนื่อง'
        ),
        'action_precautions': (
            '1) เก็บ Log/NetFlow ไว้เป็นหลักฐานก่อนดำเนินการ\n'
            '2) ระวังการ Block ที่กระทบผู้ใช้ปกติ (ตรวจ IP ปลายทางที่ใช้ร่วม เช่น CDN)\n'
            '3) ประสานผู้ให้บริการเครือข่ายเมื่อเกินขีดความสามารถ\n'
            '4) บันทึกการกระทำพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'Investigating': {
        'action_required': (
            '1) รวบรวม Log หลายแหล่ง (Firewall, Endpoint, AD, SIEM) เพื่อ Correlate\n'
            '2) เก็บรักษาหลักฐานที่เกี่ยวข้องทั้งหมด\n'
            '3) วิเคราะห์เพื่อยืนยันว่าเป็นภัยจริงหรือไม่\n'
            '4) Escalate ให้ทีมที่เกี่ยวข้องหากพบว่าเป็นเหตุจริง'
        ),
        'action_precautions': (
            '1) อย่าปิดเคสก่อนสรุปผลการวิเคราะห์\n'
            '2) เก็บหลักฐานให้ครบก่อนดำเนินการที่อาจทำให้ข้อมูลสูญหาย\n'
            '3) บันทึกสมมติฐานและผลตรวจสอบพร้อมเวลาและผู้ดำเนินการ'
        ),
    },
    'Explained Anomaly': {
        'action_required': (
            '1) บันทึกเหตุผลที่ยืนยันว่าไม่ใช่ภัย (VPN บริษัท, งาน Maintenance, Vulnerability Scanner ภายใน)\n'
            '2) ปรับจูน Rule / เพิ่ม Whitelist ลด False Positive\n'
            '3) ปิดเคสเป็น Event พร้อมแนบหลักฐาน'
        ),
        'action_precautions': (
            '1) บันทึกเหตุผลและหลักฐานที่ใช้สรุปให้ชัดเจน\n'
            '2) ทำ Whitelist/ปรับ Rule แบบย้อนกลับได้ และทบทวนเป็นระยะ\n'
            '3) ระวังการปิดเคสเร็วเกินไปโดยไม่ยืนยันแหล่งที่มา'
        ),
    },
}


def seed(apps, schema_editor):
    ThreatGuidance = apps.get_model('incidents', 'ThreatGuidance')
    for category, texts in SEED.items():
        ThreatGuidance.objects.get_or_create(
            detailed_issue=category,
            defaults={
                'action_required': texts['action_required'],
                'action_precautions': texts['action_precautions'],
            },
        )


def unseed(apps, schema_editor):
    ThreatGuidance = apps.get_model('incidents', 'ThreatGuidance')
    ThreatGuidance.objects.filter(detailed_issue__in=SEED).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0040_threatguidance'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
