from pathlib import Path
import xml.etree.ElementTree as ET
import json
import html
import re

SOURCE = Path(r'C:\Users\NT\Downloads\SOC FLOW 202609.drawio')
OUTPUT = Path(r'C:\Users\NT\Documents\SOC_Ticket\docs\architecture\SOC FLOW 202609.th.drawio')
PREVIEW = Path(r'C:\Users\NT\.codex\visualizations\2026\09\17\01a0ae7a-d114-7092-b4f3-eb9c6b3446eb\soc-workflow-review')

# Technical vocabulary, role names, enum values and field names remain English.
COMMON = {
 'Wazuh / System': 'Wazuh / ระบบ',
 'Tier 1 Analyst<br>(ticket creator)': 'Tier 1 Analyst<br>(ผู้สร้าง Ticket)',
 'System Admin<br>(assigned)': 'System Admin<br>(ผู้ได้รับมอบหมาย)',
 'System Owner<br>(no login; via Tier 1)': 'System Owner<br>(ไม่เข้าสู่ระบบ; ผ่าน Tier 1)',
 'Outcome': 'ผลลัพธ์', 'Email notifications': 'การแจ้งเตือนทาง Email',
 'yes': 'ใช่', 'no': 'ไม่ใช่', 'email': 'Email', 'details': 'รายละเอียด',
 'release': 'คืนงาน', 'create ticket': 'สร้าง Ticket', 'project incident': 'สร้าง Project Incident',
 'send now': 'ส่งทันที', 'save draft': 'บันทึกฉบับร่าง', 'approve': 'อนุมัติ',
 'reclassify as Event': 'เปลี่ยนประเภทเป็น Event', 'Emergency?': 'เป็น Emergency หรือไม่?',
 'PENDING_MANAGER<br>manager sign-off': 'PENDING_MANAGER<br>รอ SOC Manager อนุมัติ',
 '↩ step-back (reason)': '↩ ย้อนขั้นตอน (ระบุเหตุผล)',
 '⚠ System Owner: case closed<br>dormant': '⚠ System Owner: ปิดเคสแล้ว<br>ยังไม่ถูกเรียกใช้งาน',
 'PENDING_MGR_TRIAGE<br>(page 5)': 'PENDING_MGR_TRIAGE<br>(หน้า 5)',
 'ticket cancellation': 'การยกเลิก Ticket',
}
LEGEND = 'อ่านจากซ้าย → ขวา · ตามหัวลูกศรข้ามแถวบทบาท<br>ลูกศรทึบ: ขั้นตอน / การดำเนินการ &nbsp; | &nbsp; เส้นประสีแดง: ส่งกลับ / ปฏิเสธ / ยกเลิก &nbsp; | &nbsp; เส้นจุดสีน้ำเงิน: Email &nbsp; | &nbsp; เส้นจุดสีเทาไม่มีหัวลูกศร: หมายเหตุ / เงื่อนไข &nbsp; | &nbsp; เส้นกระโดดข้าม: ตัดกันแต่ไม่เชื่อมกัน'
SUPERUSER = '<b>Superuser</b> ข้ามการตรวจสอบบทบาทได้ (ทำหน้าที่แทนผู้สร้าง, Tier 2 หรือ SOC Manager; ย้อนขั้นตอน; ข้ามการจองงานของ Tier 2) แต่ยังต้องผ่านเงื่อนไขของกระบวนการ (classification, t1_route, Response Requests ที่ยังเปิดอยู่ และ Monitoring ได้ครั้งเดียว)'
PAGES = ['ภาพรวม', 'การรับเรื่อง', 'การสร้าง Ticket', 'การตรวจสอบโดย Tier 2 และ Monitoring', 'การตรวจสอบก่อน Containment โดย SOC Manager', 'เส้นทาง Admin', 'เส้นทาง Owner', 'Project Incident', 'Response Requests และ RCA', 'การยกเลิก', 'การแก้ไขโดย SOC Manager', 'ผลลัพธ์และ Email']
DATA = '''
p1-title|1 · ภาพรวมกระบวนการ SOC — Alert หรือรายงานด้วยตนเอง → ปิดเคส (v1.7.0 ตามการทำงานของระบบ)
p1-wz|Wazuh Indexer<br>Alert ประเภท DETECTION
p1-ing|ingest_wazuh_alerts<br>level ≥ 10 (ค่าเริ่มต้น) · ตัดรายการซ้ำ
p1-tq|Wazuh Triage Queue<br>จองงาน → ตัดสินผล
p1-man|รายงานด้วยตนเอง<br>Email · โทรศัพท์ · TI · ภายนอก …
p1-mq|My Queue — แท็บ Manual<br>บันทึก → จองงาน → ตัดสินผล
p1-dis|ยุติรายการรับเรื่องด้วยตนเอง<br>(ไม่สร้าง Ticket)
p1-new|แบบฟอร์ม Ticket (ผลตัดสิน + เส้นทาง)<br>· Ticket จาก Alert Bundle<br>· Ticket สมาชิกของ Project Incident
p1-drf|NEW<br>(บันทึกเป็นฉบับร่างเท่านั้น)
p1-d1|ส่งงาน:<br>ผลตัดสิน + เส้นทาง
p1-mon|MONITORING<br>(ครั้งเดียว; ไม่ใช้กับสมาชิก Project)
p1-esc|ESCALATED_T2<br>Tier 2 ตรวจสอบ
p1-ver|การตรวจยืนยันโดย Tier 2<br>CONTAINMENT_REPORTED /<br>PENDING_T2_REVIEW
p1-mer|PENDING_MGR_EVENT_REVIEW<br>(Tier 2 ลดระดับเป็น Event)
p1-pm|PENDING_MANAGER<br>(เฉพาะ Emergency)
p1-adm|เส้นทาง Admin<br>AWAITING_CONTAINMENT
p1-own|เส้นทาง Owner<br>AWAITING_OWNER
p1-prj|หน้า: 8 Project Incident · 9 Response Requests ·<br>10 การยกเลิก · 11 การแก้ไขโดย SOC Manager ·<br>12 ผลลัพธ์และ Email
p1-lg|⚠ = ระบบทำงานแตกต่าง<br>จากกระบวนการที่ตั้งใจไว้
p1-lane-CTL|การควบคุมทุกขั้นตอน
p1-can|CANCELLED<br>(จากขั้นตอนใดก็ได้ที่ยังดำเนินงานอยู่)
p1-active|Ticket ที่ยังดำเนินงานอยู่<br>กระบวนการยกเลิก · หน้า 10
p1-e3|ยุติรายการ
p1-e4|แปลงเป็น Ticket
p1-e5|แปลงเป็น Ticket
p1-e7|ส่งงานที่เตรียมไว้
p1-e9|Event / ส่งต่อ Tier 2
p1-e10|Incident: Admin หรือ Owner
p1-e11|Event (Tier 1 ระบุเป็น Event)
p1-e12|ลดระดับเป็น Event
p1-e13|ยืนยัน
p1-e14|ติดตามสถานการณ์
p1-e15|Incident + เลือกเส้นทางแล้ว
p1-e16|ไม่พบความเคลื่อนไหว → Event
p1-e17|Incident (ผ่าน T1_REVIEW)
p1-e20|ส่งรายงาน
p1-e21|Tier 1 บันทึกการแก้ไข
p1-e22|ตรวจยืนยันแล้ว · Normal
p1-e23|ตรวจยืนยันแล้ว · Emergency
p1-e25|เปลี่ยนประเภทเป็น Event
p1-e26|ยกเลิก
p2-title|2 · การรับเรื่อง — คัดกรอง Wazuh Alert และรับเรื่องด้วยตนเอง (Tier 1)
p2-ing|ingest_wazuh_alerts<br>ค่าเริ่มต้น --min-level 10 · ตัดรายการซ้ำด้วย opensearch_id<br>(กำหนดเวลาผ่าน Windows Task ตอนติดตั้งระบบ)
p2-kind|อยู่ใน Rule group ใด?
p2-vuln|vulnerability-detector<br>คัดออกขณะนำเข้า —<br>ไม่จัดเก็บในระบบ
p2-pend|Alert สถานะ PENDING<br>OLA คัดกรอง 4 ชม. นับจากเวลา Alert<br>(ยังนับเวลาขณะ TRIAGING)
p2-claim|จองงาน → TRIAGING<br>(ผู้จองสำเร็จได้เพียงคนเดียว)
p2-act|ดำเนินการกับ Alert แต่ละรายการ
p2-rel|คืนงาน (ระบุเหตุผล)<br>เฉพาะผู้จอง → PENDING
p2-bun|Alert Bundle (เลือกหลายรายการ)<br>Alert ที่ตนจองไว้ 2–25 รายการ<br>→ Ticket เดียว; รายการหลัก =<br>รายการเก่าสุดเป็นค่าเริ่มต้น
p2-ct|แบบฟอร์ม Ticket<br>กรอกคำอธิบายและ Severity ให้ล่วงหน้า<br>≥13 Crit · ≥10 High · ≥7 Med · อื่น ๆ Low<br>(แก้ไขได้)
p2-cp|แบบฟอร์ม Project Incident<br>แหล่งข้อมูลเดียว (Alert / รายการรับเรื่อง) หรือไม่มี<br>สมาชิก 2–25 รายการ
p2-sv|บันทึกแล้วหรือไม่?<br>(ส่งทันทีหรือฉบับร่าง)
p2-abort|ออกจากแบบฟอร์มโดยไม่บันทึก<br>แหล่งข้อมูลยังถูกจองอยู่;<br>OLA ของ Alert ยังนับต่อ
p2-cons|ใช้แหล่งข้อมูลแล้ว (รวมบันทึกฉบับร่าง)<br>Alert → TRUE_POSITIVE / FALSE_POSITIVE<br>รายการรับเรื่อง → TP / FP · Project: TP หากมี<br>สมาชิก Incident อย่างน้อย 1 รายการ · ไม่ซิงก์ซ้ำ
p2-go3|ดำเนินการต่อ: หน้า 3<br>(Ticket) / หน้า 8<br>(Project)
p2-rep|รายงานจากภายนอก SIEM<br>EMAIL · PHONE · TI · ADMIN ·<br>USER_REPORT · EXTERNAL · SIEM · OTHER
p2-log|บันทึกการรับเรื่องด้วยตนเอง<br>TriageRecord (ต้องระบุหมายเหตุ)<br>ไม่มี Ticket ID และ OLA
p2-mclaim|จองรายการรับเรื่อง
p2-mdec|ตัดสินผล
p2-mrel|คืนงาน (ระบุเหตุผล)<br>โดยผู้จอง
p2-mdis|ยุติรายการ (ระบุเหตุผล) โดยผู้จอง<br>→ ผลตัดสิน FP, จบรายการ
p2-mhist|แท็บ History ของผู้จบรายการ<br>(ไม่มี Ticket)
p2-note|เฉพาะ Tier 1: คิวคัดกรอง, จองงาน, คืนงาน, แปลงเป็น Ticket และรับเรื่องด้วยตนเอง<br><br>ไม่มีการแนบ Alert เข้ากับ Ticket ที่มีอยู่; ไม่มีปุ่มปิด Alert โดยตรง<br><br>สิทธิ์ข้ามการตรวจสอบของ Superuser: ดูหน้า 1
p2-e3|กลุ่มอื่น (DETECTION)
p2-e10|เลือก Alert ที่จองไว้ 2–25 รายการ
p2-e22|ไม่เข้าข่ายเป็นเคส
p3-title|3 · การสร้าง Ticket และการตัดสินผลของ Tier 1
p3-form|แบบฟอร์ม Ticket<br>จาก Alert / Bundle / รายการรับเรื่องด้วยตนเอง<br>Severity · Classification · IOCs
p3-cls|Classification ใด?
p3-rt|เส้นทางดำเนินการ<br>(Incident)
p3-evt|Event<br>บังคับเว้นเส้นทางว่าง<br>☐ เสนอ Monitoring (ข้อเสนอแนะ)
p3-adm|assign_admin<br>เลือก System Admin
p3-own|direct_owner<br>System Owner แก้ไขเอง
p3-esc|escalate_t2<br>☐ เสนอ Monitoring
p3-sub|ส่งทันทีหรือ<br>บันทึกฉบับร่าง?
p3-draft|NEW — อยู่ระหว่างเตรียมงาน<br>บันทึกแล้ว แต่ยังไม่ส่งตามเส้นทาง<br>(จดจำเส้นทางที่เลือกไว้)
p3-prep|ส่งงานที่เตรียมไว้<br>(เฉพาะผู้สร้าง)
p3-dst|ปลายทาง
p3-t2|ESCALATED_T2<br>→ หน้า 4
p3-mgr|PENDING_MGR_TRIAGE<br>t1_route = ADMIN / OWNER<br>→ หน้า 5
p3-m1|⚠ System Owner: สร้าง Ticket แล้ว<br>ยังไม่ถูกเรียกใช้งาน — ไม่มีแบบฟอร์มใดตั้งค่า<br>system_owner
p3-m2|SOC Managers:<br>รอตรวจคัดกรอง
p3-nt|ผู้สร้าง = Tier 1 Analyst ที่เปิด Ticket<br><br>การบันทึกฉบับร่างใช้แหล่งข้อมูล Alert / รายการรับเรื่องแล้ว (TP/FP) และเริ่มนับ OLA<br><br>สมาชิก SOC ทุกคนแก้ไขฉบับร่างได้; เฉพาะผู้สร้างเท่านั้นที่ส่งได้<br><br>Project Incident ไม่มีโหมดฉบับร่าง
p3-e14|Event หรือ escalate_t2
p3-e15|Admin หรือ Owner
p3-e16|เมื่อส่งงาน
p4-title|4 · การตรวจสอบงานส่งต่อโดย Tier 2, การลดระดับเป็น Event และ Monitoring
p4-in|รับมาจาก:<br>NEW (Event / ส่งต่อ Tier 2) ·<br>MONITORING → Event ·<br>SOC Manager ปฏิเสธการลดระดับ
p4-esc|ESCALATED_T2<br>บันทึก classification_at_escalation<br>ทุกครั้งที่เข้าสู่สถานะ
p4-clm|จองงานได้แต่ไม่บังคับ; ผู้จองคืนงานได้<br>(ระบุเหตุผล) หากคนอื่นจองอยู่<br>จะดำเนินการไม่ได้
p4-d|ผลตัดสินของ Tier 2
p4-mer|PENDING_MGR_EVENT_REVIEW<br>SOC Manager ตรวจยืนยันการลดระดับ
p4-md|ไม่เป็นภัยจริงหรือไม่?<br>(ต้องระบุหมายเหตุ)
p4-t1r|T1_REVIEW<br>ผู้สร้างเลือกเส้นทาง<br>(+ Admin), ต้องระบุหมายเหตุ
p4-mon|MONITORING<br>ล้าง Classification เป็นค่าว่าง<br>ช่วงติดตาม 30 วัน · ครั้งเดียวต่อเคส
p4-mo|ผู้สร้างสรุปผล<br>(ได้ทุกเวลา — ไม่ต้อง<br>รอครบกำหนด)
p4-tri|PENDING_MGR_TRIAGE<br>→ หน้า 5
p4-nt|เลือก Monitoring ได้เมื่อไม่เคยติดตามมาก่อน และไม่ใช่สมาชิก Project Incident ไม่มี Email เมื่อเริ่มติดตาม
p4-byp|✓ Monitoring ยังคงเงื่อนไขยืนยันการลดระดับ (แก้ไข 2026-09-18): Incident ที่ส่งต่อ → MONITORING<br>(ล้าง classification แต่เก็บ classification_at_escalation) → ผู้สร้างสรุป Event →<br>กลับเข้าสถานะโดยไม่บันทึกค่าทับ → ยังเป็นการลดระดับ → PENDING_MGR_EVENT_REVIEW ไม่ปิดโดยตรง
p4-nt2|ประเภทเดิมกำหนดว่าต้องผ่าน SOC Manager หรือไม่: หากบันทึกเป็น Event ตอนเข้าสถานะ → Tier 2 ปิดได้; หาก Tier 2 ลดระดับจาก Incident → SOC Manager ต้องยืนยัน
p4-e3|Event (บันทึกเป็น Event ตอนเข้าสถานะ)
p4-e4|Event (ลดระดับจาก Incident)
p4-e6|ยังตัดสินไม่ได้
p4-e8|ใช่ → ปิดเคส
p4-e9|ไม่ใช่ → ส่งกลับเป็น Incident
p4-e10|เลือกเส้นทางแล้ว
p4-e12|Incident + เส้นทาง<br>(Admin + ผู้รับผิดชอบ / Owner)
p4-e15|ไม่พบความเคลื่อนไหว → Event
p5-title|5 · การตรวจสอบก่อน Containment โดย SOC Manager (ทุก Incident)
p5-in|รับมาจาก: ส่ง NEW · T1_REVIEW ·<br>MONITORING → Incident (เลือกเส้นทางแล้ว) ·<br>สมาชิก Project · ย้อนขั้นตอน
p5-pt|PENDING_MGR_TRIAGE<br>ตรวจสอบหลักฐานและเส้นทาง
p5-ok|ข้อมูลเคสครบถ้วนหรือไม่?
p5-ret|T1_REVIEW<br>ส่งกลับพร้อมเหตุผลเป็นลายลักษณ์อักษร<br>ผู้สร้างเปลี่ยนเส้นทาง / Admin ได้
p5-as|ส่งต่อ: หมายเหตุ + ระบุ<br>Normal / Emergency ให้ชัดเจน<br>บันทึก decided_by/at ครั้งเดียว;<br>ตั้งค่าผลตัดสินใหม่เมื่อส่งต่ออีกครั้ง
p5-rt|t1_route?<br>(SOC Manager เปลี่ยนไม่ได้)
p5-adm|AWAITING_CONTAINMENT<br>→ หน้า 6
p5-own|AWAITING_OWNER<br>→ หน้า 7<br>(ไม่มี Email)
p5-m|Admin ที่ได้รับมอบหมาย:<br>แจ้งให้ดำเนินการ Containment
p5-nt|สมาชิก Project Incident: ส่งต่อ / ส่งกลับรายตัวไม่ได้จนกว่าจะผ่าน Project Review (หน้า 8)<br><br>ทุกขั้นตอนที่ยังดำเนินงานอยู่: SOC Manager เปิด Response Requests (หน้า 9) หรือยกเลิกได้ (หน้า 10)
p5-e2|ไม่ครบ — ส่งกลับ (ระบุเหตุผล)
p5-e3|ผู้สร้างส่งงานอีกครั้ง
p5-e5|ส่งต่อ
p6-title|6 · เส้นทาง Containment โดย Admin (Tier 2 ตรวจยืนยัน)
p6-wa|Admin ไม่ถูกคน? SOC Manager ย้อนขั้นตอน แล้วส่งกลับให้จัดทำข้อมูลเพิ่ม → T1_REVIEW; Tier 1 ผู้สร้างกำหนด Admin ใหม่ (หน้า 11)
p6-wk|Containment · Eradication · Recovery<br>ส่งรายงาน Containment<br>(เฉพาะ Admin ที่ได้รับมอบหมาย)
p6-d|ควบคุมเหตุได้แล้วหรือไม่?
p6-nd|วันที่แจ้ง (ต้องระบุก่อน<br>อนุมัติ / ส่งให้ SOC Manager)<br>+ รายการตรวจสอบการแก้ไข
p6-g|ไม่มี Response Request<br>ที่ค้างอยู่? (ทั้งหมดเป็น DONE<br>หรือ CANCELLED)
p6-blk|ซ่อนปุ่มปิดเคส<br>จนกว่าคำขอจะสิ้นสุดทั้งหมด<br>(หน้า 9)
p6-ok|APPROVED<br>verified_by / approved_by<br>บันทึกได้ครั้งเดียว
p6-ev|CLOSED_EVENT<br>แยกปุ่มเปลี่ยนประเภท ·<br>ไม่ต้องระบุวันที่แจ้ง · ไม่ผ่าน SOC Manager ⚠
p6-m1|Tier 2: มีการส่งรายงาน Containment<br>(สำรอง: Analyst ใน assigned_to)
p6-m2|Admin: แจ้งให้ดำเนินการ Containment<br>(พร้อมเหตุผลเมื่อส่งกลับ)
p6-e5|ไม่ใช่ → ส่งกลับ (ระบุเหตุผล)
p6-e11|Emergency (ส่งได้แม้ยังมี<br>คำขอค้างอยู่)
p6-e17|↩ ย้อนขั้นตอน (ระบุเหตุผล, ไม่มี Email)
p7-title|7 · เส้นทางตรงถึง Owner (System Owner แก้ไข; Tier 1 ผู้สร้างดำเนินการแทนในระบบ)
p7-fx|Owner ดำเนินการแก้ไข<br>(ติดต่อผ่านโทรศัพท์ / Email)
p7-rec|ผู้สร้างบันทึกรายงานของ Owner<br>(ต้องระบุหมายเหตุ; หลักฐาน<br>ไม่บังคับ และอัปโหลดแยก)
p7-leg|OWNER_REMEDIATED<br>LEGACY — เฉพาะ Ticket เก่า
p7-d|การแก้ไขผ่านหรือไม่?
p7-nd|วันที่แจ้ง (ต้องระบุก่อน<br>อนุมัติ / ส่งให้ SOC Manager)<br>+ ผลตรวจพบ / มาตรการแก้ไข
p7-g|ไม่มี Response Request<br>ที่ค้างอยู่หรือไม่?
p7-blk|ซ่อนปุ่มปิดเคส<br>จนกว่าคำขอจะสิ้นสุดทั้งหมด
p7-ev|CLOSED_EVENT<br>ไม่ผ่าน SOC Manager ⚠
p7-e4|ข้อมูลเก่า
p7-e5|↩ ย้อนขั้นตอน
p7-e7|ไม่ผ่าน → ส่งกลับ Owner<br>(ไม่มี Email)
p7-e18|↩ ย้อนขั้นตอน (ระบุเหตุผล) — เปลี่ยน<br>เส้นทางได้ผ่านการส่งกลับ →<br>T1_REVIEW เท่านั้น
p8-title|8 · Project Incident — แยก Incident เดียวเป็น Ticket สมาชิกหลายรายการ
p8-lane-LANES|เส้นทางดำเนินการ<br>(Admin / Owner)
p8-src|แหล่งข้อมูล: Alert ที่จองไว้ 1 รายการ,<br>รายการรับเรื่องด้วยตนเอง 1 รายการ หรือไม่มี
p8-pi|Project PI-YYMMDD-NN<br>(วันที่ UTC) · ข้อมูลร่วม ·<br>IOCs · หลักฐานร่วม
p8-mem|สมาชิก A, B, C …<br>2–25 รายการ ระบบละ 1 รายการ<br>(ไม่มีโหมดฉบับร่าง)
p8-r|เส้นทางของสมาชิก<br>EVENT / ADMIN / OWNER
p8-e|สมาชิก → ESCALATED_T2<br>(หน้า 4; ใช้ Monitoring ไม่ได้)
p8-pt|สมาชิก → PENDING_MGR_TRIAGE<br>(ส่ง Email ถึง SOC Managers ครั้งเดียว)
p8-rev|Project Review — ครั้งเดียว<br>(SOC Manager, ต้องระบุหมายเหตุ)<br>ตัดสิน Normal / Emergency ร่วมกัน 1 ค่า<br>ส่งต่อสมาชิก Incident ที่รออยู่ทั้งหมด
p8-ln|แต่ละสมาชิก → เส้นทางของตน<br>ตาม t1_route (หน้า 6 / 7)<br>Email ถึง Admin / Owner
p8-sb|สมาชิกถูกย้อนขั้นตอนภายหลัง<br>→ ส่งต่ออีกครั้งที่ Ticket ของตน<br>ใช้ผลตัดสินของตนเอง
p8-out|สมาชิกปิด / ยกเลิกได้<br>แยกจากกัน; Project<br>แสดงยอดรวมสถานะ
p8-add|เพิ่มสมาชิกภายหลัง<br>โดยผู้สร้าง Project หรือ SOC Manager<br>สูงสุด 25 รายการ · เพิ่มไม่ได้เมื่อ<br>สมาชิกทั้งหมดปิด / ยกเลิกแล้ว
p8-ad|ประเภท / ตรวจสอบแล้วหรือไม่?
p8-rea|ประเมิน Emergency ใหม่: เฉพาะระดับ Project<br>หลังตรวจสอบแล้ว · ระบุเหตุผล ·<br>เฉพาะสมาชิก Incident
p8-nt|Project ที่เป็น Event ทั้งหมด: ไม่มี Project Review จนกว่าจะเพิ่มสมาชิก Incident รายแรก
p8-e6|ส่งต่อทั้งหมด
p8-e8|↩ ย้อนขั้นตอน
p8-e9|ส่งต่ออีกครั้ง
p8-e12|Incident, ยังไม่ผ่านการตรวจสอบ
p8-e13|Incident, ตรวจสอบแล้ว → ใช้<br>ผลตัดสินเดิมของ Project
p9-title|9 · Response Requests (VA/PT, Infra Security, Forensic/RCA) — ดำเนินการคู่ขนานกับ Ticket
p9-op|SOC Manager เปิดคำขอ<br>ใน Ticket ที่ยังดำเนินงานอยู่ (ไม่ใช่ APPROVED /<br>CLOSED_EVENT / CANCELLED)
p9-ty|ประเภท
p9-who|มีผู้ดำรงบทบาทหรือไม่?<br>(ไม่บังคับเลือกผู้รับงาน)
p9-none|ไม่มี → เปิดคำขอไม่ได้<br>มีหลายคนแต่ไม่เลือก → ข้อผิดพลาด
p9-pick|มีคนเดียว → มอบหมายอัตโนมัติ<br>หรือมอบหมายให้คนที่เลือก
p9-ip|IN_PROGRESS<br>กด "Start RCA" หรือบันทึกการแก้ไขใด ๆ<br>(ผู้รับมอบหมาย / SOC Manager)
p9-wk|พื้นที่ทำงาน RCA: รีเฟรชส่วนที่ 1 ·<br>Timeline CSV · IOCs · ฉบับร่าง DOCX
p9-nr|⚠ VA_PT / INFRA_SEC: ไม่มีขั้นตอน Start<br>ผู้รับมอบหมายหรือ SOC Analyst คนใดก็ได้ตั้งค่า<br>OPEN / IN_PROGRESS / DONE<br>(เปิด DONE กลับมาทำต่อได้)
p9-dn|DONE<br>(RCA: ส่งฉบับสมบูรณ์<br>แล้วล็อกการแก้ไข)
p9-cx|CANCELLED<br>ผ่านการยกเลิก Ticket เท่านั้น<br>(หน้า 10)
p9-gate|ไม่มีคำขอค้างอยู่ →<br>แสดงการดำเนินการไปยัง APPROVED<br>(ไม่กีดกัน CLOSED_EVENT และ<br>PENDING_MANAGER)
p9-m1|ผู้รับมอบหมาย: มีการสร้างคำขอ
p9-m2|SOC Managers: ทุกครั้งที่เปลี่ยน<br>เข้าสู่ DONE
p9-nt|แก้ไขได้หลัง CLOSED_EVENT; ล็อกหลัง APPROVED / CANCELLED สร้างคำขอใหม่บน Ticket ที่ปิดแล้วไม่ได้
p9-e5|ไม่มีผู้รับงาน / ระบุไม่ได้ชัดเจน
p9-e6|ระบุผู้รับงานได้แล้ว
p9-e11|ส่งฉบับสมบูรณ์
p9-e15|เงื่อนไข
p10-title|10 · การยกเลิก — กระบวนการแยกที่ตรวจสอบย้อนหลังได้ จากทุกขั้นตอนที่ยังดำเนินงานอยู่
p10-lane-REQ|ผู้ขอยกเลิก<br>(SOC Manager / ผู้สร้าง /<br>ผู้รับผิดชอบขั้นตอนปัจจุบัน)
p10-act|Ticket ในขั้นตอนที่ยังดำเนินงานอยู่<br>(รวม MONITORING และสถานะเก่า)
p10-who|ใคร / ดำเนินการอะไร?
p10-blk|หาก Tier 2 คนอื่นจองงานอยู่<br>Tier 2 รายอื่นจะดำเนินการไม่ได้<br>(ไม่กีดกัน SOC Manager)
p10-dir|ยกเลิกโดยตรง — Tier 1 ผู้สร้าง<br>ที่ NEW และไม่มีงานย่อยค้างอยู่
p10-req|ขอยกเลิก: ซ้ำ (อ้างอิง Ticket ต้นฉบับ) ·<br>สร้างผิดพลาด · อื่น ๆ<br>+ คำอธิบาย
p10-pen|คำขอ PENDING<br>สูงสุด 1 คำขอ · งานและ OLA ดำเนินต่อ
p10-wd|WITHDRAWN<br>(เฉพาะผู้ขอยกเลิก)
p10-sup|SUPERSEDED — Ticket ปิดตามปกติ<br>(ไม่มี Email และผู้ตัดสิน)
p10-mdir|ยกเลิกโดยตรง — SOC Manager<br>ทุกขั้นตอนที่ยังดำเนินงานอยู่<br>เมื่อไม่มีคำขอ PENDING เท่านั้น
p10-dec|SOC Manager ตัดสิน<br>(ต้องระบุหมายเหตุ)
p10-rej|REJECTED<br>สถานะ Ticket ไม่เปลี่ยน;<br>ยื่นคำขอใหม่ได้
p10-dup|Ticket ต้นฉบับที่อ้างว่าซ้ำ<br>ยังใช้อ้างอิงและมองเห็นได้หรือไม่?
p10-err|ปฏิเสธการดำเนินการ — คำขอ<br>ยังคงเป็น PENDING
p10-sub|เลือกงานย่อยที่ยังไม่เสร็จ<br>ครบทั้งหมดหรือไม่? (รวมงานเก่า)
p10-err2|ปฏิเสธการดำเนินการ — เลือกทั้งหมด<br>หรือทำงานย่อยให้เสร็จก่อน
p10-can|CANCELLED (สิ้นสุด)<br>งานย่อย → CANCELLED · closed_at ·<br>ล้างการจองงาน · ไม่คัดกรอง Alert ซ้ำ
p10-m1|ขอยกเลิก → SOC Managers
p10-m2|ยกเลิกโดยตรง / อนุมัติ / ปฏิเสธ / ถอนคำขอ →<br>SOC Managers, ผู้ขอยกเลิก, ผู้สร้าง, Admin ที่ได้รับมอบหมาย,<br>System Owner และผู้รับมอบหมายงานย่อยทุกคน
p10-e2|Tier 1 ผู้สร้าง ที่ NEW
p10-e3|SOC Manager / ผู้สร้าง<br>/ ผู้รับผิดชอบขั้นตอน
p10-e6|ถอนคำขอ
p10-e7|ปิดเคสตามปกติ
p10-e9|ปฏิเสธ
p10-e13|ใช่ / ไม่ใช่กรณีซ้ำ
p11-title|11 · การแก้ไขโดย SOC Manager — ย้อนขั้นตอนและประเมิน Emergency ใหม่
p11-or|OWNER_REMEDIATED (สถานะเก่า)
p11-ret|ส่งกลับให้จัดทำข้อมูลเพิ่ม (ระบุเหตุผล)<br>→ T1_REVIEW: Tier 1 ผู้สร้าง<br>เปลี่ยน Admin / เส้นทาง
p11-ra|ประเมิน Emergency ใหม่<br>ระบุเหตุผลเป็นลายลักษณ์อักษร · ต้องเปลี่ยนค่า<br>บันทึกค่าเดิม → ค่าใหม่ · ไม่มี Email
p11-ok|ขั้นตอนนี้อนุญาตหรือไม่?
p11-no|ไม่อนุญาตที่ PENDING_MGR_TRIAGE,<br>MONITORING, APPROVED / CLOSED_EVENT /<br>CANCELLED และสมาชิก Project
p11-yes|อนุญาตในขั้นตอนอื่นที่ยังดำเนินงานอยู่<br>(รวม NEW, ESCALATED_T2,<br>T1_REVIEW, PENDING_MGR_EVENT_REVIEW)
p11-on|ON → การตรวจยืนยันครั้งถัดไปโดย Tier 2<br>ส่งต่อไปยัง PENDING_MANAGER
p11-off|OFF → Tier 2 ปิดได้โดยตรง;<br>Ticket ที่อยู่ PENDING_MANAGER แล้ว<br>ยังคงอยู่ที่เดิม (SOC Manager อนุมัติ)
p11-nt|ย้อนขั้นตอน: ต้องระบุเหตุผล · ผ่าน transition_to (บันทึกประวัติและล้างการจองของ Tier 2) · ไม่มี Email · คงค่าที่บันทึกครั้งเดียวไว้ · ตั้งค่า Emergency ใหม่เมื่อ SOC Manager ส่งต่อครั้งถัดไป · เคสที่ปิดแล้วไม่สามารถย้อนขั้นตอนได้
p11-e2|เพื่อเปลี่ยน Admin / เส้นทาง
p11-e10|เปิดค่า
p11-e11|ปิดค่า
p12-title|12 · ผลลัพธ์เมื่อสิ้นสุด, เงื่อนไขส่ง Email และ OLA
p12-a|APPROVED<br>verified_by/at (Tier 2 ผู้ตรวจยืนยัน)<br>approved_by/at (ผู้ปิดเคส) · closed_at<br>ทั้งหมดบันทึกได้ครั้งเดียว
p12-e|CLOSED_EVENT<br>closed_at · Response Requests<br>อาจดำเนินต่อหลังปิดเคส
p12-c|CANCELLED<br>closed_at; ไม่นับรวมใน<br>สถิติการแก้ไขและ MTTR
p12-f|ทั้ง 3 สถานะ: เปลี่ยนสถานะไม่ได้, เปลี่ยนค่า Emergency ไม่ได้ และย้อนขั้นตอนไม่ได้
p12-ola|OLA — Alert: คัดกรองภายใน 4 ชม. นับจากเวลา Alert (DETECTION จนคัดกรองเสร็จ)<br>Ticket: กำหนด Containment สำหรับ Critical 4 ชม. · High 24 ชม. · Unknown 4 ชม.; Medium / Low ไม่มีกำหนด (ซ่อนป้าย) กำหนดเวลาคัดกรองใช้กับทุก Severity ตั้งค่าครั้งเดียวเมื่อสร้าง; ซ่อนเมื่อ Ticket สิ้นสุดแล้ว
'''
BY_ID = dict(line.split('|', 1) for line in DATA.strip().splitlines())

TABLE = {
 'Email triggers (as implemented)': 'เงื่อนไขส่ง Email (ตามการทำงานของระบบ)',
 'Recipient': 'ผู้รับ', 'When': 'เมื่อใด',
 '→ PENDING_MGR_TRIAGE (create, submit, T1 route, Monitoring → Incident, project create once / Incident member add)': '→ PENDING_MGR_TRIAGE (สร้าง, ส่งงาน, Tier 1 เลือกเส้นทาง, Monitoring → Incident, สร้าง Project ครั้งเดียว / เพิ่มสมาชิก Incident)',
 'Assigned Admin': 'Admin ที่ได้รับมอบหมาย',
 '→ AWAITING_CONTAINMENT (manager forward, Project Review, send-back with reason)': '→ AWAITING_CONTAINMENT (SOC Manager ส่งต่อ, Project Review, ส่งกลับพร้อมเหตุผล)',
 'Tier 2 staff (fallback: assigned_to)': 'Tier 2 (สำรอง: assigned_to)',
 '→ CONTAINMENT_REPORTED (not on step-back)': '→ CONTAINMENT_REPORTED (ยกเว้นการย้อนขั้นตอน)',
 'Response assignee': 'ผู้รับมอบหมาย Response Request',
 'Response Request created': 'สร้าง Response Request',
 'Response Request moves into DONE (every time)': 'Response Request เปลี่ยนเป็น DONE (ทุกครั้ง)',
 'Cancellation requested': 'มีคำขอยกเลิก',
 'Managers, requester, creator, admin, owner, subtask assignees': 'SOC Managers, ผู้ขอยกเลิก, ผู้สร้าง, Admin, Owner และผู้รับมอบหมายงานย่อย',
 'Direct cancel / approve / reject / withdraw': 'ยกเลิกโดยตรง / อนุมัติ / ปฏิเสธ / ถอนคำขอ',
 '⚠ System Owner (dormant)': '⚠ System Owner (ยังไม่ถูกเรียกใช้งาน)',
 'Ticket submitted; → APPROVED / CLOSED_EVENT — system_owner is not set by any form': 'ส่ง Ticket; → APPROVED / CLOSED_EVENT — ไม่มีแบบฟอร์มใดตั้งค่า system_owner',
 '— no email —': '— ไม่มี Email —',
 'ESCALATED_T2, T1_REVIEW, AWAITING_OWNER forward (single ticket), owner reject, → PENDING_T2_REVIEW, → PENDING_MANAGER, → PENDING_MGR_EVENT_REVIEW, Monitoring start / conclude Event, step-back, emergency reassess, SUPERSEDED': 'ESCALATED_T2, T1_REVIEW, ส่งต่อไป AWAITING_OWNER (Ticket เดี่ยว), ส่งกลับ Owner, → PENDING_T2_REVIEW, → PENDING_MANAGER, → PENDING_MGR_EVENT_REVIEW, เริ่ม Monitoring / สรุปเป็น Event, ย้อนขั้นตอน, ประเมิน Emergency ใหม่, SUPERSEDED',
}

tree = ET.parse(SOURCE)
root = tree.getroot()
changed = []
unchanged = []
for i, page in enumerate(root.findall('diagram')):
    page.set('name', f'{i+1} · {PAGES[i]}')
    for node in page.iter():
        for attr in ('value', 'label', 'tooltip'):
            old = node.get(attr)
            if not old:
                continue
            ident = node.get('id', '')
            if ident.endswith('-legend'):
                new = LEGEND
            elif ident in ('p1-su', 'p11-su'):
                new = SUPERUSER
            elif ident == 'p12-mt':
                new = old
                for english, thai in TABLE.items():
                    assert english in new, english
                    new = new.replace(english, thai)
            else:
                new = BY_ID.get(ident, COMMON.get(old, old))
            if new != old:
                node.set(attr, new)
                changed.append(ident)
            else:
                unchanged.append((ident, old))

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
tree.write(OUTPUT, encoding='utf-8', xml_declaration=True)
translated = ET.parse(OUTPUT)
original = ET.parse(SOURCE)
orig_nodes = list(original.getroot().iter())
new_nodes = list(translated.getroot().iter())
assert len(orig_nodes) == len(new_nodes)
for before, after in zip(orig_nodes, new_nodes):
    assert before.tag == after.tag
    for key in set(before.attrib) | set(after.attrib):
        if key in ('value', 'label', 'tooltip') or (before.tag == 'diagram' and key == 'name'):
            continue
        assert before.get(key) == after.get(key), (before.get('id'), key)

xml = OUTPUT.read_text(encoding='utf-8')
manifest = []
for page in root.findall('diagram'):
    manifest.append([
        {'id': n.get('id'), 'text': html.unescape(re.sub(r'<[^>]*>', '', n.get('value', ''))).replace('\xa0', ' '),
         'height': float(n.find('mxGeometry').get('height', '0')),
         'width': float(n.find('mxGeometry').get('width', '0'))}
        for n in page.iter('mxCell')
        if n.get('vertex') == '1' and n.get('value') and n.find('mxGeometry') is not None
        and 'swimlane' not in n.get('style', '') and 'text;' not in n.get('style', '')
    ])
(PREVIEW / 'thai-text-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False), encoding='utf-8')
for i in range(12):
    config = html.escape(json.dumps({'xml': xml, 'page': i, 'nav': True, 'resize': True, 'toolbar': 'zoom layers pages', 'highlight': '#2563eb'}, ensure_ascii=False), quote=True)
    (PREVIEW / f'thai-{i+1}.html').write_text('<!doctype html><html><head><meta charset="utf-8"><title>SOC Flow Thai</title></head><body style="margin:16px"><div class="mxgraph" data-mxgraph="' + config + '"></div><script src="viewer-static.min.js"></script></body></html>', encoding='utf-8')
print(f'Output: {OUTPUT}\nPages: 12; translated labels: {len(changed)}; all geometry, links and non-text attributes preserved.')
print('Unchanged labels (technical terms / review list):')
for ident, value in unchanged:
    print(f'{ident}: {value}')
