# เอกสารส่งมอบงานด้านวิศวกรรม — ระบบ SOC Ticketing

> **ผู้อ่าน:** developer ที่จะรับช่วงดูแลโค้ดเบสนี้ · **สถานะ:** เป็นปัจจุบัน
> **อ้างอิงจาก:** repo ที่ commit `3967bfb` ("21/7 Codebase Audit")
> **ฉบับภาษาอังกฤษ:** [engineering-handover.md](engineering-handover.md)

เอกสารนี้เป็นจุดเริ่มต้นสำหรับผู้ที่จะรับช่วงดูแลโปรเจกต์นี้ต่อ ครอบคลุมว่าระบบนี้คืออะไร
ทำงานอย่างไร โค้ดส่วนสำคัญอยู่ที่ไหน วิธีรันและ deploy รวมถึงสิ่งที่**ไม่สามารถ**
เข้าใจได้จากการอ่านโค้ดเพียงอย่างเดียว

---

เอกสารประกอบ (แนะนำให้อ่านตามลำดับนี้):

| เอกสาร | เนื้อหา |
|---|---|
| [README.md](../../README.md) | การติดตั้งสำหรับ dev บนเครื่อง, การ seed ข้อมูลทดสอบ, Wazuh fixture แบบ offline |
| [CONTEXT.md](../../CONTEXT.md) | **อภิธานศัพท์** — ความหมายของทุกคำในระบบ (Incident vs Event, OLA, Response Request…) หากยังไม่คุ้นคำศัพท์ ให้อ่านไฟล์นี้ก่อน |
| [workflow-change-log.md](../architecture/workflow-change-log.md) | เหตุผลทั้งหมดของการออกแบบ workflow ตั๋วใหม่ รวมถึงการแก้ไขเพิ่มเติมภายหลัง |
| [ticket-lifecycle-states.md](../architecture/ticket-lifecycle-states.md) | ภาพรวม flow ปัจจุบันตั้งแต่ต้นจนจบ แยกตาม role |
| [production-deployment.md](../operations/production-deployment.md) | การ deploy production (Docker, nginx, gunicorn) |
| [adr/](../adr/) | บันทึกการตัดสินใจเชิงสถาปัตยกรรม (case bundling, จุดเริ่มนาฬิกา OLA, manager gate) |
| `../user-guides/feature-guide.docx` | คู่มือฟีเจอร์สำหรับผู้ใช้งาน (ภาพหน้าจอ, วิธีใช้งานแยกตาม role) |
| [end-user-guide.th.md](../user-guides/end-user-guide.th.md) | คู่มือผู้ใช้งานฉบับภาษาไทย |
| Notion: "SOC Ticketing System — Technical Documentation" | เอกสารอ้างอิงทางเทคนิคฉบับเต็ม |

---

## 1. ระบบนี้คืออะไร และมีไว้ทำไม

แพลตฟอร์ม **SOC (Security Operations Centre) ticketing และการจัดการ incident**
สร้างด้วย Django สำหรับทีม SOC ภายในองค์กรไทย จัดการวงจรชีวิตของ security incident
ทั้งหมด: การรับ alert จาก Wazuh/OpenSearch, การ triage, การสร้างตั๋ว, การ escalate,
การ containment โดย system administrator, การตรวจสอบยืนยันโดย analyst,
การอนุมัติโดย manager และการติดตาม deadline ตาม OLA (Operational Level
Agreement) — พร้อม dashboard แสดง KPI

- เวอร์ชันก่อนหน้าอยู่ที่ `C:\Users\NT\Documents\soc-crm` ส่วน repo นี้คือเวอร์ชัน
  ปัจจุบันที่ใช้งานจริง
- ป้ายกำกับใน UI ผสมระหว่างภาษาไทยและอังกฤษ (verbose_name บน model เป็นภาษาไทย)
- รันบน LAN ภายในผ่าน HTTP เป็นค่าเริ่มต้น มี flag สำหรับเสริมความปลอดภัย HTTPS
  แต่ต้องเปิดเองผ่าน `.env` (ดู §7)

**การตัดสินใจออกแบบที่สำคัญและเหตุผล:**

- **ฟิลด์การมอบหมายงานแยกกันสองฟิลด์** — `assigned_to` (SOC analyst
  ผู้รับผิดชอบตั๋ว) และ `assigned_admin` (system administrator ผู้ทำ containment)
  ถูกแยกกันโดยเจตนา **ห้าม**รวมเป็นฟิลด์เดียว
- **Classification เป็นค่าที่กำหนดโดยตรง ไม่ใช่ค่าที่คำนวณมา** — `classification`
  (`INCIDENT` / `EVENT` เดิมคือ TP/FP) ถูกกำหนดอย่างชัดเจนโดย Tier 1
  ตอนสร้างตั๋ว (Tier 2 แก้ไขได้เฉพาะตั๋วที่ถูก escalate มา) และเป็นตัวกำหนดว่า
  state transition ใดถูกต้องตามกติกา
- **Tier มีผลต่อสิทธิ์การใช้งาน** (ตั้งแต่การออกแบบใหม่ 2026-06-19) — T1/T2
  ของ SOC staff ไม่ใช่แค่ป้ายบอกอาวุโส เฉพาะ Tier 1 เท่านั้นที่สร้างตั๋วและดำเนินงาน
  ฝั่ง T1 ของ workflow ส่วน Tier 2 จัดการเฉพาะตั๋วที่ถูก escalate และไม่มีสิทธิ์
  มอบหมาย admin หรือสร้างตั๋วเด็ดขาด ดูเหตุผลทั้งหมดใน architecture/workflow-change-log.md
- **ความหมายของการ breach OLA ต่างกันตามชนิด deadline** — การ breach ฝั่ง
  *triage* เป็นข้อเท็จจริงในอดีตที่ตายตัว ("เปิดตั๋วทันเวลาหรือไม่") ส่วนการ breach
  ฝั่ง *contain* เป็นการนับถอยหลังแบบ real-time ของตั๋วที่ยัง active อยู่ ดู §4
- **ไฟล์แนบคือหลักฐาน (evidence)** — ให้ดาวน์โหลดได้ผ่าน view
  ที่ตรวจสอบการล็อกอินและสิทธิ์เท่านั้น การแก้ไขนี้ปิดช่องโหว่ stored-XSS /
  การดาวน์โหลดโดยไม่ล็อกอินที่เคยมีอยู่จริง ดู §8

## 2. Tech stack

| ส่วนประกอบ | เวอร์ชัน / รายละเอียด |
|---|---|
| Python / Django | Django 6.0.7 (ดูเวอร์ชันที่ pin ไว้ทั้งหมดใน `requirements.txt`) |
| ฐานข้อมูล | PostgreSQL 16 (`psycopg2-binary`) |
| Config | `python-decouple` อ่านจาก `.env` (แม่แบบ: `.env.example`) |
| Static files | WhiteNoise |
| เซิร์ฟเวอร์ production | gunicorn อยู่หลัง nginx ผ่าน `docker-compose.prod.yml` |
| Export Excel | openpyxl (`export_tickets_excel` ใน views ของ incidents) |
| แหล่งที่มาของ alert | Wazuh alerts ผ่าน OpenSearch REST API (`requests`) |
| การจำกัดการ login | `django-axes` 7.1.0 (ล็อกบัญชีเมื่อ login ผิดซ้ำ ๆ) |

Migration head ณ เวลาที่เขียน: `incidents 0046`, `wazuh_ingest 0006`,
`accounts 0006`

## 3. สรุปฟีเจอร์

### 3.1 วงจรชีวิตของตั๋ว (state machine)

มี **12 state** กำหนดไว้ใน `apps/incidents/models.py` (`STATUS_CHOICES`,
`ALLOWED_TRANSITIONS`) และบังคับใช้โดย `Ticket.transition_to`:

```
NEW
 ├─(T1 escalate; classification ใดก็ได้)──► ESCALATED_T2
 │                                            ├─(T2: EVENT)──────► CLOSED_EVENT (terminal)
 │                                            └─(T2: INCIDENT)───► T1_REVIEW
 │                                                                    │
 └─(T1 ยืนยันเป็น INCIDENT พร้อมเลือก t1_route)◄─────────────────────┘
    │
    ▼
 PENDING_MGR_TRIAGE          ← SOC Manager: ตัดสิน Emergency แล้วส่งต่อไปยัง
    │                          lane ที่ Tier 1 เลือกไว้ (เปลี่ยน lane ไม่ได้)
    ├─(t1_route = ADMIN)──► AWAITING_CONTAINMENT ──► CONTAINMENT_REPORTED
    │                             ▲   (admin ส่งรายงาน)         │
    │                             └───(T2: ยังไม่ contain)──────┤
    │                                                          │
    └─(t1_route = OWNER)──► AWAITING_OWNER ──► OWNER_REMEDIATED │
                                 ▲  (T1 บันทึกผลจากเจ้าของ)   │  │
                                 └──(ยังแก้ไม่จริง)───────────┘  │
                                 ▲                              │
                                 │        PENDING_T2_REVIEW ◄────┤ (T2 ตรวจรับ
                                 └──(T2 ตีกลับ)───┘              │  บังคับเสมอ)
                                                                 │
         คิวตรวจรับทั้งสอง ──────┬─(ตรวจผ่าน ไม่ใช่ emergency)──┴──► APPROVED (terminal)
                                  ├─(ตรวจผ่าน + emergency)──► PENDING_MANAGER ──► APPROVED
                                  └─(T2 เปลี่ยนเป็น EVENT)─────────► CLOSED_EVENT (terminal)
```

กติกาที่พลาดกันง่าย:

- **มี 2 lane การจัดการ เลือกโดย Tier 1 และล็อกไว้** `t1_route` (`ADMIN` / `OWNER`)
  ถูกเลือกตอน Tier 1 ยืนยันว่าเป็น Incident และ manager ทำได้เพียงส่งต่อไปยัง lane
  นั้น **เปลี่ยน lane ไม่ได้** — `ADMIN` คือ System Admin เข้าควบคุม ส่วน `OWNER`
  คือเจ้าของระบบแก้ไขเอง โดย Tier 1 เป็นผู้บันทึกผล
- **จุดตรวจของ manager เป็นแบบ blocking และใช้กับ Incident เท่านั้น** Incident
  ทุกใบต้องผ่าน `PENDING_MGR_TRIAGE` ก่อนงาน containment จะเริ่ม ส่วน Event
  ไม่เคยผ่านจุดนี้ — manager ไม่เกี่ยวข้องกับ Event เลย
- **สำหรับตั๋ว escalation T2 ทำได้เพียงส่งกลับให้ T1 (`T1_REVIEW`) หรือปิดเป็น event**
  T2 ไม่มีสิทธิ์มอบหมาย admin และไม่มีสิทธิ์สร้างตั๋ว แต่ T2 เป็นผู้ตรวจรับ:
  `CONTAINMENT_REPORTED` และ `PENDING_T2_REVIEW` เป็นคิวของ Tier 2
  (`TIER2_QUEUE_STATUSES`) และการตรวจรับของ lane เจ้าของระบบเป็นขั้นบังคับ ข้ามไม่ได้
- **วงจรการตีกลับ (rejection loop) มี 2 จุด**: `CONTAINMENT_REPORTED →
  AWAITING_CONTAINMENT` (Tier 2 เห็นว่า containment ยังไม่พอ และ admin
  ได้รับอีเมลแจ้งอีกครั้ง) และ `PENDING_T2_REVIEW` / `OWNER_REMEDIATED →
  AWAITING_OWNER`
- **การเปลี่ยน classification กลางทาง**: Tier 2 เปลี่ยน Incident ที่กำลังดำเนินอยู่
  ให้เป็น `EVENT` แล้วปิดได้จากคิวตรวจรับทั้งสอง (`EVENT_CLOSE_TRANSITIONS`)
  ซึ่ง**ข้าม manager แม้ตั๋วจะถูกตั้งธง emergency ไว้** เพราะ manager ไม่ยุ่งกับ Event
- **เส้นทางผ่าน manager**: `requires_manager_verification` เป็นจริง**เฉพาะเมื่อตั๋ว
  ถูกตั้งธง emergency เท่านั้น** — severity อย่างเดียวไม่ส่งถึง manager
  (ค่า `SOC_SEVERITY_FLOOR` ถูกถอดออกแล้ว) ตั๋วฉุกเฉินต้องผ่านการตรวจของ Tier 2
  ก่อนแล้วจึงเข้า `PENDING_MANAGER` ส่วนตั๋วอื่น Tier 2 ปิด (`APPROVED`) ได้เอง
- **คำขอทีมตอบสนองที่ค้างอยู่จะบล็อกการปิดงาน** หากมี response subtask ที่ยังไม่ `DONE`
  ค่า `has_open_response_requests` จะเป็นจริง และ `transition_to` จะปฏิเสธ**ทุก**
  เส้นทางที่เข้าสู่ `APPROVED` โดยปุ่มจะหายไปจาก UI แทนที่จะ error ตอน submit
  ทั้งนี้การปิดเป็น Event ได้รับการยกเว้น (ดู §3.5)
- Permission token (`TIER1_CREATOR`, `TIER2`, `ASSIGNED_ADMIN`, `MANAGER`)
  ประกาศไว้รายทรานซิชันใน `TRANSITION_PERMISSIONS` และ `transition_to`
  ยังบังคับใช้เงื่อนไข classification, เงื่อนไขเส้นทาง manager และเงื่อนไข
  response request ด้วย โดย `TIER1_CREATOR` หมายถึง **ผู้เปิดตั๋วใบนั้นเท่านั้น**
  ไม่ใช่ Tier 1 คนใดก็ได้ (ดู `CREATOR_REVIEW_STATUSES`)
- State เดิม `UNDER_REVIEW` / `VERIFIED` / `CLOSED_FP` ถูกลบไปแล้วโดย
  migration 0018 (แปลงเป็น `CONTAINMENT_REPORTED` / `PENDING_MANAGER` /
  `CLOSED_EVENT` ตามลำดับ) หากพบชื่อเหล่านี้ในเอกสารเก่าหรือ git history
  ให้แปลความหมายตามนี้

### 3.2 Role (`apps/accounts/models.py` — `UserProfile`)

มี **7 role** (`UserProfile.ROLE_CHOICES`) โดยสองรายการท้ายเพิ่มเมื่อ 2026-07-20:

| Role | ความสามารถ |
|---|---|
| **SOC Staff, Tier 1** | สร้างตั๋ว (จาก manual triage หรือจาก Wazuh alert), กำหนด classification, เลือก lane การจัดการ (`t1_route`), escalate ไป T2 และดูแล lane เจ้าของระบบ — เป็น role เดียวที่สร้างตั๋วได้ |
| **SOC Staff, Tier 2** | จัดการตั๋ว `ESCALATED_T2` (แก้ไข classification, ส่งกลับ T1, ปิดเป็น Event) **และ**คิวตรวจรับทั้งสอง — `CONTAINMENT_REPORTED` และ `PENDING_T2_REVIEW` เป็นผู้ปิดตั๋วที่ไม่ใช่ฉุกเฉินทุกใบ |
| **SOC Manager** | ตรวจก่อน containment ที่ `PENDING_MGR_TRIAGE`: ตัดสิน Emergency แล้วส่งต่อไปยัง lane ที่กำหนดไว้ เป็น role **เดียว**ที่ตั้ง `is_emergency` ได้ ออกคำขอทีมตอบสนอง และอนุมัติ `PENDING_MANAGER` → `APPROVED` |
| **System Admin** | เห็นเฉพาะตั๋วที่ตนเป็น `assigned_admin` เขียน `containment_report` (มาตรการรับมือ) และ `remediation_summary` (ผลการตรวจสอบ) แล้วส่งตั๋วเข้าคิวตรวจรับ — ไม่มีสิทธิ์กำหนด classification |
| **System Owner** | ได้รับอีเมลแจ้งเมื่อตั๋วของระบบที่ตนดูแลถูกเปิด/ปิด มีหน้า "My Tickets" สำหรับดูโดยเฉพาะที่ `/incidents/my-tickets/` |
| **Forensic Analyst** | role ฝั่งทีมตอบสนอง **ไม่ใช่**สมาชิก SOC เห็นเฉพาะตั๋วที่มีคำขอ Forensics/RCA มอบหมายให้ตน ทำงานผ่านคิว "Response Requests" (งานตอบสนอง) |
| **Red Team Manager** | role ฝั่งทีมตอบสนอง **ไม่ใช่**สมาชิก SOC รับคำขอทั้ง VA/Pentest และ Infrastructure Security |

การมองเห็นตั๋วรวมศูนย์อยู่ที่ `TicketQuerySet.visible_to(user)`: role ฝั่ง SOC
เห็นตั๋วทั้งหมด, system admin เห็นเฉพาะตั๋วที่ได้รับมอบหมาย, สอง role ฝั่งทีมตอบสนอง
เห็นเฉพาะตั๋วที่มีคำขอมอบหมายให้ตน, ผู้ใช้ที่ไม่มี profile ไม่เห็นอะไรเลย
**ต้องเช็ค `getattr(user, 'profile', None)` ก่อนเช็ค role เสมอ** —
superuser ที่สร้างผ่าน `createsuperuser` ไม่มี profile

### 3.3 ธง Emergency

`is_emergency` เป็นสิทธิ์ของ **SOC Manager เท่านั้น** (`can_set_emergency`;
superuser ตั้งได้ด้วย) ไม่มี role อื่นแตะได้ รวมถึง Tier 1 และ Tier 2
จุดตัดสินใจหลักคือการตรวจก่อน containment (`PENDING_MGR_TRIAGE`) ที่ manager
ชี้ว่าฉุกเฉินหรือไม่ก่อนส่งต่อ แต่ manager ยังแก้ไขหรือยกระดับได้ใน**ทุก** stage
ภายหลัง รวมถึง terminal state การเปิด/ปิดทุกครั้งจะบันทึก `TicketLog` ว่าใครเป็น
ผู้เปลี่ยนและเปลี่ยนจากค่าใดเป็นค่าใด และธง emergency เป็นเงื่อนไขเดียวที่บังคับให้
ต้องผ่านการตรวจสอบของ manager ก่อนปิด

> หมายเหตุเชิงประวัติ: การออกแบบเดิมเคยให้ทุก role **ยกเว้น** Tier 1 เปิด/ปิดได้
> พร้อมข้อยกเว้น `was_escalated_to_t2` กติกานั้นถูกยกเลิกแล้ว หากพบโค้ดหรือเอกสาร
> ที่ยังอ้างถึง แสดงว่าเป็นของก่อนการปรับ workflow เรื่อง manager triage

### 3.4 นโยบาย OLA (ปรับปรุงใหม่ 2026-07-01 — การเปลี่ยนแปลงล่าสุด)

คำศัพท์: ระบบนี้ใช้คำว่า **OLA** ไม่ใช่ SLA (เปลี่ยนชื่อใน migration 0028–0030)
ตั๋วแต่ละใบมี deadline สองตัว คำนวณตอนสร้างตั๋วจาก `incident_datetime`
(ถ้าว่างใช้เวลาปัจจุบัน) ตาม severity ผ่าน `Ticket.OLA_TARGETS`:

| Severity | Triage (ต้องเปิดตั๋วภายใน) | Contain (ต้องแก้ไขภายใน) |
|---|---|---|
| Critical | 30 นาที | 4 ชม. |
| High | 2 ชม. | 24 ชม. |
| Medium | 24 ชม. | — (แจ้งเตือนอย่างเดียว) |
| Low | 24 ชม. | — (แจ้งเตือนอย่างเดียว) |
| Unknown | เหมือน Critical | เหมือน Critical |

- **Triage OLA** (`is_ola_triage_breached` มี alias `is_ola_breached`):
  เป็น**ข้อเท็จจริงตายตัว** — `created_at` เลย deadline ฝั่ง triage หรือไม่
  ประเมิน ณ เวลาเปิดตั๋ว และไม่เปลี่ยนแปลงอีกหลังจากนั้น
- **Contain OLA** (`is_ola_contain_breached`): เป็นการ**นับถอยหลังแบบ real-time** —
  ตั๋วที่ยัง active (ไม่ใช่ terminal) และเลย deadline ฝั่ง contain ไปแล้ว
  Medium/Low ไม่มี contain deadline จึงไม่มีวัน breach ฝั่งนี้
- `apps/incidents/ola.py` เป็น **single source of truth** สำหรับการจัดกลุ่มคิวงาน
  ตามความเร่งด่วนของ contain deadline (Overdue / Due ≤1h / Due 1–4h /
  On-track) ทั้งกราฟใน dashboard และตัวกรอง OLA ในหน้ารายการตั๋วใช้ไฟล์นี้ร่วมกัน —
  แก้นโยบายที่นี่ที่เดียว ทั้งสองหน้าจอจะตรงกันเอง
- **แยกจากทั้งหมดข้างบน**: `WazuhAlert` มี OLA ของตัวเองสำหรับ *การ triage alert*
  แบบคงที่ 4 ชั่วโมง (`WazuhAlert.OLA_HOURS`) นับแบบ real-time จาก
  `alert.timestamp` จนกว่า alert จะถูก triage

### 3.5 คำขอทีมตอบสนอง (Response Request) — เพิ่มเมื่อ 2026-07-20

**Response Request** คือ `TicketSubtask` ชนิดพิเศษที่ SOC Manager ออกไปยังทีม
นอกศูนย์ SOC และดำเนินไป **คู่ขนาน** กับงาน containment

- `TicketSubtask.TYPE_CHOICES` มี 5 ชนิด สองชนิดแรกเป็น subtask ปกติฝั่ง SOC
  (`INVESTIGATION`, `COUNTERMEASURE`) ส่วนอีกสามชนิดใน `RESPONSE_TYPES`
  คือคำขอทีมตอบสนอง:

  | ชนิด | ส่งถึง |
  |---|---|
  | `VA_PT` (VA / Pentest) | Red Team Manager |
  | `INFRA_SEC` (Infrastructure Security) | Red Team Manager |
  | `FORENSIC_RCA` (Forensics / RCA) | Forensic Analyst |

- ระบบ **auto-assign** ให้ผู้ถือ role นั้นทันทีหากมีเพียงคนเดียว หากมีหลายคน
  manager เป็นผู้เลือก ผู้รับงานทำงานผ่านหน้า **"Response Requests"** (งานตอบสนอง)
- **เงื่อนไขการปิดงาน**: ตราบใดที่ยังมีคำขอที่ไม่ใช่สถานะ `DONE`
  `Ticket.has_open_response_requests` จะเป็นจริง และ `transition_to` จะบล็อก
  **ทุก** เส้นทางที่เข้าสู่ `APPROVED` โดยปุ่มตรวจรับจะหายไปจาก UI แทนที่จะ
  error ตอน submit ทั้งนี้ **การปิดเป็น Event ได้รับการยกเว้นโดยเจตนา**
- สถานะ subtask คือ `OPEN` / `IN_PROGRESS` / `DONE` ติดตามแยกจากสถานะของตั๋วหลัก
- มี notification template รองรับ 2 รายการ: `RESPONSE_REQUEST_CREATED`
  (ถึงผู้รับงาน) และ `RESPONSE_REQUEST_COMPLETED` (กลับถึง manager)

### 3.6 Project Incident (การรวมกลุ่มเคส)

เหตุการณ์จริงหนึ่งเรื่องที่กระทบหลายระบบจะถูกทำเป็นตั๋วหลายใบ — ใบละหนึ่งระบบ —
โดยรวมกลุ่มด้วย `ProjectIncident` และมี `bundle_suffix` กำกับสมาชิกแต่ละใบ
ดู [adr/0001-case-bundling-fan-out.md](../adr/0001-case-bundling-fan-out.md)

- การรวมกลุ่มนี้เป็น **หน่วยสำหรับสรุปรวมเท่านั้น** ไม่มี lifecycle ของตัวเอง
  ตั๋วสมาชิกแต่ละใบถูก contain ตรวจรับ และปิดอย่างอิสระบนนาฬิกา OLA ของตัวเอง
  สิ่งที่ต่างกันระหว่างใบพี่น้องมีเพียงเป้าหมาย (device / IP / เจ้าของ / admin)
- **Ticket Reference ของตั๋วไม่เปลี่ยน**เมื่อเข้าร่วม project incident
  โดย member reference เป็นส่วนเสริม ไม่ได้มาแทนที่
- การสรุปรวมบน dashboard และการ export รายงานแบบรวมกลุ่มถูกกันออกจาก phase 1
  และยัง**ไม่ได้ทำ**

### 3.7 การรับ alert จาก Wazuh และการ triage (`apps/wazuh_ingest`)

- `python manage.py ingest_wazuh_alerts` ดึง alert จาก OpenSearch REST API
  (`wazuh-alerts-*/_search`, HTTP Basic auth, ตั้งค่าใน `.env`) มี watermark
  ป้องกันการดึงซ้ำ และใช้ OpenSearch document ID กันข้อมูลซ้ำ
- โหมด `--fixture` โหลด alert ตัวอย่างที่แนบมากับ repo โดยไม่ต้องต่อเครือข่าย
  (ดู README) — ใช้สำหรับ demo/ทดสอบโดยไม่ต้องเข้าถึง cluster
- การ triage (claim / สร้างตั๋ว / release) เป็นสิทธิ์ของ **Tier 1 เท่านั้น**
  การ release alert **ต้องระบุเหตุผล** (`release_reason`) ส่วน `escalation_queue`
  ระดับ alert เป็นของตกค้าง — ปัจจุบันการ escalate ทำที่ระดับตั๋วแล้ว
- **ไม่มี scheduler ใน repo** สำหรับการ ingest — ถ้า production มีการ ingest
  เป็นรอบ ๆ แสดงว่าเป็น cron/scheduled task ภายนอกบนเครื่อง host
  ต้องยืนยันกับผู้ดูแลระบบ

### 3.8 การแจ้งเตือน (`apps/incidents/notifications.py`)

- ส่งอีเมลผ่าน SMTP (ตั้งค่าใน `.env`) โดย `SITE_URL` ใช้สร้างลิงก์แบบ absolute
- หัวข้อและเนื้อหาอีเมล **แก้ไขได้จากหน้า admin** ผ่าน `NotificationTemplate`
  โดยอ้างอิงด้วย `KEY_CHOICES` และมีคำใบ้ placeholder รายคีย์ (`PLACEHOLDERS`)
  ปัจจุบันมี 7 คีย์:

  | คีย์ | ส่งถึง |
  |---|---|
  | `CONTAINMENT_REQUIRED` | System Admin ที่ได้รับมอบหมาย |
  | `CONTAINMENT_SUBMITTED` | ฝั่ง SOC |
  | `MANAGER_TRIAGE_PENDING` | SOC Manager — มี Incident รออยู่ที่จุดตรวจก่อน containment |
  | `OWNER_CREATED` / `OWNER_CLOSED` | System Owner |
  | `RESPONSE_REQUEST_CREATED` | Forensic Analyst / Red Team Manager |
  | `RESPONSE_REQUEST_COMPLETED` | SOC Manager |

- `notify_containment_required` ทำงานทุกครั้งที่ตั๋วเข้าสู่ `AWAITING_CONTAINMENT`
  (ทั้งการมอบหมายครั้งแรก**และ**ทุกรอบของการตีกลับ)
- System owner ได้รับแจ้งเมื่อตั๋วของระบบที่ตนดูแลถูกเปิด/ปิด
- มีอีเมลแจ้ง credential ผู้ใช้ใหม่ และ action ในหน้า admin สำหรับส่ง username ซ้ำ /
  รีเซ็ตรหัสผ่าน (action ภาษาไทยในหน้า Users ของ admin)
- ความล้มเหลวของอีเมล**ไม่ทำให้งานหลักล้มเหลว** (ออกแบบไว้เช่นนั้น):
  อีเมลส่งไม่ออกจะแสดงคำเตือน แต่ไม่ rollback ทรานซิชันของตั๋ว

### 3.9 Dashboard (`apps/dashboard`)

หน้าแรก (`/`) แสดง KPI/กราฟ: pipeline สถานะเคส, หมวดหมู่, กลุ่มความเร่งด่วน OLA
และตารางตั๋วที่มีคอลัมน์ "Status Updated" ขับเคลื่อนโดย `status_changed_at`
(ฟิลด์เฉพาะที่ประทับเวลาใหม่**เฉพาะ**เมื่อมีการเปลี่ยนสถานะจริง — การเพิ่มโน้ตหรือ
เปิด/ปิดธง emergency จะอัปเดต `updated_at` แต่ไม่แตะฟิลด์นี้)
ข้อมูลกราฟส่งผ่าน `json_script` (ไม่ใช้ `|safe` กับข้อมูลผู้ใช้ — คงไว้แบบนี้ต่อไป)

### 3.10 ฟีเจอร์อื่น ๆ

- ไฟล์แนบตั๋ว (จำกัด 25 MB, ให้ดาวน์โหลดอย่างเดียว — ดู §8), subtask,
  log/ประวัติตั๋วพร้อมแก้ไขได้, export Excel, ค้นหาแบบ global, IP lookup,
  บันทึก manual triage (`TriageRecord.source` ใช้ชุดตัวเลือกร่วมกับ
  `Ticket.source`)

## 4. แนะนำโครงสร้างโค้ด

```
config/                 settings.py, urls.py, middleware.py (CSP)
apps/
  incidents/            ★ app หลักของระบบ — เริ่มอ่านที่นี่
    models.py           Ticket + state machine + OLA + log/ไฟล์แนบ/subtask/
                        ProjectIncident/NotificationTemplate (~106 KB)
    views.py            view ของตั๋ว/triage/คิวทีมตอบสนองทั้งหมด (~82 KB)
    notifications.py    อีเมลทุกฉบับที่ระบบส่ง
    ola.py              single source of truth ของการจัดกลุ่ม OLA
    forms.py            ฟอร์มตั๋ว/triage/ไฟล์แนบ (รวมการจำกัดขนาดไฟล์)
    reports.py          การสร้างรายงาน
    report_content.py   เนื้อหา/ข้อความในรายงาน
    report_templates/   เทมเพลตเลย์เอาต์รายงาน
    management/commands/
      seed_data.py               ตั๋วสังเคราะห์สำหรับ dev (ผู้ใช้ 7 role)
      seed_dashboard_mockup.py   ชุดข้อมูล demo/ภาพหน้าจอ
      seed_ola_demo_buckets.py   ชุดข้อมูล demo กราฟ OLA
      seed_response_demo.py      ชุดข้อมูล demo ทีมตอบสนอง
      seed_uat_states.py         ตั๋วหนึ่งใบต่อหนึ่งสถานะ สำหรับ UAT
      seed_ceo_demo.py           ชุดข้อมูล demo dashboard ผู้บริหาร
      import_trendmicro.py       นำเข้า CSV จาก Trend Micro
  accounts/             UserProfile (role, tier), admin action เรื่อง credential
  dashboard/            view ของ KPI + dashboard ผู้บริหาร + เทสต์
  wazuh_ingest/         model WazuhAlert, การ ingest จาก OpenSearch, view การ triage
templates/              Django template (base.html + โฟลเดอร์แยกตาม app)
```

**ลำดับการอ่านสำหรับ developer ใหม่:**

1. [CONTEXT.md](../../CONTEXT.md) — อภิธานศัพท์ ใช้เวลา 20 นาทีที่นี่
   ประหยัดเวลาเดาความหมายของคำว่า "Event", "OLA" หรือ "Response Request" ได้หลายชั่วโมง
2. `apps/incidents/models.py` — อ่าน model `Ticket` จากบนลงล่าง: สถานะต่าง ๆ,
   `ALLOWED_TRANSITIONS`, `TRANSITION_PERMISSIONS`, `transition_to`,
   `OLA_TARGETS`, `save()`
3. `architecture/workflow-change-log.md` — ทำไม state machine ถึงมีรูปร่างแบบนี้ รวมถึง
   การปรับเรื่อง manager triage และทีมตอบสนอง
4. `apps/incidents/views.py` — `ticket_detail` และ view ที่ POST ทรานซิชัน
   จากนั้น `apps/wazuh_ingest/views.py` สำหรับเส้นทาง alert-สู่-ตั๋ว
5. ไล่ตั๋วหนึ่งใบตั้งแต่ต้นจนจบใน UI ด้วยบัญชีทดสอบที่ seed ไว้ (§5)

**เทสต์**มีจำนวนมากและถือเป็นสเปกของ workflow ในรูปแบบที่รันได้:
`apps/incidents/tests.py` (~148 KB) ครอบคลุมทรานซิชัน/สิทธิ์,
`apps/dashboard/tests.py` ครอบคลุมการคำนวณ KPI, `apps/wazuh_ingest/tests.py`
mock HTTP ทั้งหมด และมีชุดเทสต์เฉพาะทางเพิ่มเติมที่
`apps/incidents/test_ui_smoke.py`, `test_lookup_search_import.py` และ
`test_dashboard_mock_seed.py` รันทั้งหมดด้วย `python manage.py test` —
ควรรันก่อนและหลังการแก้ไข workflow ทุกครั้ง

## 5. การรันบนเครื่อง

สรุปย่อจาก README.md (ยึด README เป็นหลักหากขัดแย้งกัน):

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
copy .env.example .env                               # แล้วกรอกค่าให้ครบ
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8088
```

ต้องมี PostgreSQL 16 ที่เชื่อมต่อได้ (`DB_*` ใน `.env`) แอปอยู่ที่
`http://127.0.0.1:8088/` หน้า admin ที่ `/admin/`

**ข้อมูลทดสอบ:**

- `python manage.py seed_data` — ตั๋ว 100 ใบกระจายใน 30 วันแบบสุ่มถ่วงน้ำหนัก
  ครบทุก severity พร้อมผู้ใช้ **7 role** (`seed_t1`, `seed_t2`, `seed_manager`,
  `seed_sysadmin`, `seed_sysowner`, `seed_forensic`, `seed_redteam`)
  ข้อมูล seed ทุกแถวมี prefix `seed_` ใน username จึงลบออกได้สะอาด (`--flush`)
  **คำสั่งนี้มีมาก่อน 4 สถานะใหม่ จึงไม่สร้างสถานะเหล่านั้น** ให้ใช้
  `seed_uat_states` แทน
- `python manage.py seed_uat_states` — แบบกำหนดแน่นอน: ตั๋วหนึ่งใบใน**ทุกสถานะ
  ครบทั้ง 12** ทำให้ทดสอบทุกหน้าจอและทุกปุ่มได้โดยไม่ต้องเดิน workflow ทั้งเส้น
  ใช้ prefix `uat_` (ไม่ใช่ `seed_`) การ `--flush` จึงลบเฉพาะแถวของตัวเอง
  ไม่กระทบข้อมูลที่ผู้ทดสอบสร้างระหว่างเซสชัน
- `python manage.py seed_response_demo` — ตั๋วที่มีคำขอทีมตอบสนองทั้งที่ค้างและ
  ที่เสร็จแล้ว สำหรับทดสอบคิวทีมตอบสนองและเงื่อนไขการปิดงาน
- `python manage.py ingest_wazuh_alerts --fixture [--fresh]` — alert ตัวอย่าง
  แบบ offline สำหรับทดสอบ flow การ triage ของ Wazuh
- `test_accounts.txt` — บัญชีล็อกอินสำหรับ dev หนึ่งบัญชีต่อ role
  **ใช้สำหรับ dev เท่านั้น ห้ามสร้างบัญชีเหล่านี้ใน production**

## 6. การ Deploy

Production: `docker compose -f docker-compose.prod.yml up -d --build`
(nginx → gunicorn → Django + PostgreSQL) container `web` รัน `migrate` +
`collectstatic` อัตโนมัติทุกครั้งที่ start ดูขั้นตอนเต็มใน operations/production-deployment.md
(UFW, การสร้าง superuser, บัญชีทีม, การดู log)

- `docker-compose.yml` (ไม่มี suffix) ใช้สำหรับ **dev บนเครื่องเท่านั้น**
  (runserver + bind-mount) ห้ามนำไป deploy เด็ดขาด
- ไม่มีหน้า sign-up สาธารณะ: บัญชีทั้งหมดสร้างผ่าน `/admin/`
- **ต้องถามผู้ดูแลคนเดิม:** production รันอยู่ที่ไหนจริง ๆ (host/IP),
  ใครถือ secret ใน `.env` (รหัสผ่าน DB, SMTP, credential ของ OpenSearch)
  และอะไรเป็นตัว backup ข้อมูล PostgreSQL — ทั้งหมดนี้ไม่มีอยู่ใน repo

## 7. ปัญหาที่ทราบแล้ว จุดที่ต้องระวัง และเอกสารที่ล้าสมัย

1. **เอกสารถูกย้าย 2 ครั้ง — path เดิมใน commit และ Notion ล้าสมัยแล้ว**
   ครั้งแรก `WORKFLOW_REDESIGN.md` และ `DEPLOY.md` ย้ายจาก root เข้า `docs/`
   จากนั้นเมื่อ 2026-07-21 ไฟล์ทั้งหมดใน `docs/` ถูกจัดเข้าโฟลเดอร์ตามหมวดหมู่
   **พร้อมเปลี่ยนชื่อไฟล์เป็น kebab-case** ตำแหน่งปัจจุบัน:

   | path เดิม | path ปัจจุบัน |
   |---|---|
   | `WORKFLOW_REDESIGN.md` | `docs/architecture/workflow-change-log.md` |
   | `DEPLOY.md` | `docs/operations/production-deployment.md` |
   | `docs/HANDOVER.md` / `.th.md` | `docs/handover/engineering-handover.md` / `.th.md` |
   | `docs/soc-ticket-flow.md` | `docs/architecture/ticket-lifecycle-states.md` |
   | `docs/user-guide-th.md` | `docs/user-guides/end-user-guide.th.md` |
   | `docs/ceo-brief-th.md` | `docs/user-guides/executive-brief.th.md` |
   | `docs/GRAFANA_DASHBOARD.md` | `docs/operations/grafana-wazuh-wall.md` |
   | `docs/UAT_DATA_PREP.md` | `docs/uat/uat-environment-setup.md` |
   | `docs/UAT_TEST_SCRIPT.md` | `docs/uat/uat-test-scenarios.md` |
   | `docs/UAT_FEEDBACK_LOG.md` | `docs/uat/uat-feedback-log.md` |
   | `docs/*.svg` | `docs/diagrams/` (เปลี่ยนเป็น kebab-case) |

   `docs/adr/` และ `docs/agents/` **ไม่ได้ย้าย** เพราะ path ทั้งสองถูกอ้างอิงตายตัว
   ใน agent skills ที่ `.agents/skills/` และใน `AGENTS.md` ที่ root
   ดูดัชนีฉบับเต็มที่ [docs/README.md](../README.md)
   (ส่วนตาราง role ที่ล้าสมัยในเอกสาร deployment ได้แก้ไขแล้วเมื่อ 2026-07-21)
2. **CSP ยังอนุญาต `'unsafe-inline'`** สำหรับ script/style
   (`config/middleware.py`, policy string อยู่ใน settings) inline handler
   สองจุดที่ขวางการเปลี่ยนไปใช้ nonce: `ticket_detail.html` (confirm) และ
   `ticket_history.html` (onchange) — เป็นขั้นตอน hardening ถัดไปที่วางแผนไว้
3. **ยังไม่มีการตรวจชนิดไฟล์/magic byte ของไฟล์อัปโหลด** (ความสำคัญต่ำ —
   ลดความเสี่ยงแล้วด้วยการบังคับดาวน์โหลด ดู §8)
4. **`escalation_queue` ระดับ alert เป็นของตกค้าง**หลังการออกแบบใหม่
   ปัจจุบันการ escalate ทำที่ระดับตั๋ว
5. **ไฟล์ `runserver-8099.*.log` ใน root ของ repo** เป็น log dev ที่หลงเหลือ —
   ลบทิ้งได้
6. **ความหมายของการ breach OLA ไม่สมมาตรกัน** (triage เป็นข้อเท็จจริงตายตัว
   ส่วน contain เป็นการนับถอยหลังแบบ real-time ดู §3.4) — เสี่ยงต่อการ "แก้บั๊ก"
   ผิด ๆ ถ้าเข้าใจว่าทั้งคู่เป็นแบบ real-time
7. **Data migration 0030 คำนวณ OLA deadline ทั้งหมดใหม่**ตามนโยบาย
   รายเซเวียริตี้ใหม่ สถิติการ breach ย้อนหลังก่อน 2026-07-01 จึงสะท้อน
   การคำนวณใหม่ ไม่ใช่สิ่งที่ dashboard เคยแสดง ณ เวลานั้น

## 8. สถานะด้านความปลอดภัย (hardening 2026-06-15 จากการ audit ด้วย VibeSec)

- **ไฟล์แนบ**: ให้บริการผ่าน `incidents.views.download_attachment` **เท่านั้น**
  (ต้องล็อกอิน + เช็ค `visible_to` + บังคับ `Content-Disposition: attachment` +
  `nosniff`) **ห้ามเพิ่ม route `/media/` แบบเปิดกลับเข้าไปใน `config/urls.py`
  เด็ดขาด** — ช่องโหว่นี้เคยเปิดให้ดาวน์โหลดโดยไม่ล็อกอินและเกิด stored XSS
  ผ่านไฟล์ `.html`/`.svg` ที่อัปโหลดมาแล้ว route media เฉพาะ dev
  มีการล็อกอินป้องกันและทำงานเหมือน production
- ขนาดไฟล์อัปโหลดจำกัด 25 MB (`MAX_ATTACHMENT_SIZE`) บังคับใช้ทั้งในฟอร์ม
  **และ**ใน loop รับหลักฐานตอนสร้างตั๋ว
- Flag HTTPS (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`,
  `SECURE_SSL_REDIRECT`, HSTS, `USE_PROXY_SSL_HEADER`) ควบคุมผ่าน env
  และค่าเริ่มต้น**ปิด**เพื่อให้ deploy แบบ HTTP ภายในใช้งานได้ —
  **ต้องเปิดเมื่อ deploy หลัง TLS ทุกครั้ง**
- CSP ผ่าน middleware ที่เขียนเอง ทุกอย่างล็อกไว้ที่ `'self'` +
  `cdn.jsdelivr.net` ยกเว้น script/style
- การ ingest จาก OpenSearch รองรับการตรวจสอบ TLS กับ cert แบบ self-signed
  ของ cluster ผ่าน `OPENSEARCH_CA_BUNDLE` (แนะนำมากกว่าการตั้ง
  `OPENSEARCH_VERIFY_SSL=False`)
- ข้อมูลกราฟ dashboard ส่งผ่าน `json_script` ไม่ใช่ `|safe`

## 9. Dependency ภายนอกและผู้ติดต่อ

| Dependency | รายละเอียด | เจ้าของ / อยู่ที่ไหน |
|---|---|---|
| PostgreSQL 16 | ฐานข้อมูลของแอป | _(กรอก: host, ผู้ดูแล backup)_ |
| เซิร์ฟเวอร์ SMTP | การแจ้งเตือนทั้งหมด | _(กรอก: ผู้ให้บริการ/เจ้าของบัญชี)_ |
| Cluster Wazuh / OpenSearch | แหล่ง alert, credential แบบ HTTP Basic ใน `.env` | _(กรอก: เจ้าของ SOC infra)_ |
| เอกสารเทคนิคใน Notion | "SOC Ticketing System — Technical Documentation" | workspace ของผู้ดูแลคนเดิม |
| นโยบาย OLA | ใครเป็นผู้กำหนดเป้าหมายรายเซเวียริตี้ใน `OLA_TARGETS`? | _(กรอก: SOC manager?)_ |

> **ถึงผู้ดูแลคนเดิม:** ช่องว่างตัวเอียงด้านบน รวมถึงคำถามเรื่อง production ใน §6
> คือสิ่งที่มีแต่คุณเท่านั้นที่ตอบได้ กรุณากรอกให้ครบก่อนส่งมอบงาน

## 10. แผนสัปดาห์แรกที่แนะนำ

- **วันที่ 1** — อ่าน [CONTEXT.md](../../CONTEXT.md) เพื่อจับคำศัพท์ก่อน จากนั้น
  รันบนเครื่องตัวเอง (§5), `seed_data` + `seed_uat_states`, แล้วล็อกอินด้วยบัญชี
  ทดสอบทั้ง **7 role** แล้วลองคลิกสำรวจ
- **วันที่ 2** — อ่าน `Ticket` ใน `models.py` + architecture/workflow-change-log.md;
  ไล่ incident หนึ่งเคสตั้งแต่ Wazuh fixture alert → triage →
  **จุดตรวจของ manager ก่อน containment** → containment → การตรวจรับของ Tier 2 →
  อนุมัติ โดยสวมบทบาทผู้ใช้ที่ถูกต้องในแต่ละขั้น จากนั้นทำซ้ำอีกรอบด้วย lane
  Direct-to-Owner
- **วันที่ 3** — รันชุดเทสต์ทั้งหมด; อ่านผ่าน ๆ `incidents/tests.py`
  เพื่อดูกติกา workflow ในรูปแบบสเปกที่รันได้
- **วันที่ 4** — ทบทวน view ของ dashboard + `ola.py`; ทำความเข้าใจกลุ่ม OLA
  และ `status_changed_at`
- **วันที่ 5** — ตรวจ operations/production-deployment.md เทียบกับเครื่อง production จริงร่วมกับ
  ผู้ดูแลคนเดิม; ยืนยันเรื่อง secret, backup และตารางเวลาการ ingest
