# ระบบ SOC Ticketing — เอกสารส่งมอบงาน (Handover Document)

_อัปเดตล่าสุด: 2026-07-02 (repo ที่ commit `682de3f`, "1/7 OLA Policy updated")_
_English version: [HANDOVER.md](HANDOVER.md)_

เอกสารนี้เป็นจุดเริ่มต้นสำหรับผู้ที่จะรับช่วงดูแลโปรเจกต์นี้ต่อ ครอบคลุมว่าระบบนี้คืออะไร
ทำงานอย่างไร โค้ดส่วนสำคัญอยู่ที่ไหน วิธีรันและ deploy รวมถึงสิ่งที่**ไม่สามารถ**
เข้าใจได้จากการอ่านโค้ดเพียงอย่างเดียว

เอกสารประกอบ (แนะนำให้อ่านตามลำดับนี้):

| เอกสาร | เนื้อหา |
|---|---|
| [README.md](../README.md) | การติดตั้งสำหรับ dev บนเครื่อง, การ seed ข้อมูลทดสอบ, Wazuh fixture แบบ offline |
| [WORKFLOW_REDESIGN.md](../WORKFLOW_REDESIGN.md) | เหตุผลทั้งหมดของการออกแบบ workflow ตั๋วใหม่เมื่อ 2026-06-19 |
| [DEPLOY.md](../DEPLOY.md) | การ deploy production (Docker, nginx, gunicorn) — **ดูข้อควรระวังใน §7** |
| `SOC_Ticketing_System_Feature_Guide.docx` | คู่มือฟีเจอร์สำหรับผู้ใช้งาน (ภาพหน้าจอ, วิธีใช้งานแยกตาม role) |
| Notion: "SOC Ticketing System — Technical Documentation" | เอกสารอ้างอิงทางเทคนิคฉบับเต็ม เขียนใหม่เมื่อ 2026-06-29 ให้ตรงกับสถานะปัจจุบัน |

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
  มอบหมาย admin หรือสร้างตั๋วเด็ดขาด ดูเหตุผลทั้งหมดใน WORKFLOW_REDESIGN.md
- **ความหมายของการ breach OLA ต่างกันตามชนิด deadline** — การ breach ฝั่ง
  *triage* เป็นข้อเท็จจริงในอดีตที่ตายตัว ("เปิดตั๋วทันเวลาหรือไม่") ส่วนการ breach
  ฝั่ง *contain* เป็นการนับถอยหลังแบบ real-time ของตั๋วที่ยัง active อยู่ ดู §4
- **ไฟล์แนบคือหลักฐาน (evidence)** — ให้ดาวน์โหลดได้ผ่าน view
  ที่ตรวจสอบการล็อกอินและสิทธิ์เท่านั้น การแก้ไขนี้ปิดช่องโหว่ stored-XSS /
  การดาวน์โหลดโดยไม่ล็อกอินที่เคยมีอยู่จริง ดู §8

## 2. Tech stack

| ส่วนประกอบ | เวอร์ชัน / รายละเอียด |
|---|---|
| Python / Django | Django 6.0.5 (ดูเวอร์ชันที่ pin ไว้ทั้งหมดใน `requirements.txt`) |
| ฐานข้อมูล | PostgreSQL 16 (`psycopg2-binary`) |
| Config | `python-decouple` อ่านจาก `.env` (แม่แบบ: `.env.example`) |
| Static files | WhiteNoise |
| เซิร์ฟเวอร์ production | gunicorn อยู่หลัง nginx ผ่าน `docker-compose.prod.yml` |
| Export Excel | openpyxl (`export_tickets_excel` ใน views ของ incidents) |
| แหล่งที่มาของ alert | Wazuh alerts ผ่าน OpenSearch REST API (`requests`) |

Migration head ณ เวลาที่เขียน: `incidents 0030`, `wazuh_ingest 0005`,
`accounts 0003`

## 3. สรุปฟีเจอร์

### 3.1 วงจรชีวิตของตั๋ว (state machine)

มี 8 state กำหนดไว้ใน `apps/incidents/models.py` และบังคับใช้โดย
`Ticket.transition_to`:

```
NEW ─(classify EVENT)────────────────────────────► CLOSED_EVENT (terminal)
 │
 └(classify INCIDENT)
    ├── T1 มอบหมาย admin ──► AWAITING_CONTAINMENT ──► CONTAINMENT_REPORTED
    │                              ▲                        │ (admin ส่งรายงาน)
    │                              │ (T1: ยังไม่ contain)    │
    │                              └────────────────────────┤
    └── T1 escalate ──► ESCALATED_T2                        │ (T1: contain แล้ว)
              │                                             ▼
              ├─(T2: EVENT)──► CLOSED_EVENT       PENDING_MANAGER ──► APPROVED (หรือข้ามไป
              └─(T2: INCIDENT)──► T1_REVIEW              APPROVED เลย ถ้าไม่ต้องผ่าน
                       │                                  การตรวจสอบของ manager)
                       └──► AWAITING_CONTAINMENT
```

กติกาที่พลาดกันง่าย:

- **T2 ทำได้เพียงส่งตั๋วกลับให้ T1 (`T1_REVIEW`) หรือปิดเป็น event เท่านั้น**
  T2 ไม่มีสิทธิ์มอบหมาย admin และไม่มีสิทธิ์สร้างตั๋ว
- **วงจรการตีกลับ (rejection loop)**: ถ้า T1 พิจารณาว่าการ containment ยังไม่เพียงพอ
  จะเปลี่ยน `CONTAINMENT_REPORTED → AWAITING_CONTAINMENT` และ admin
  ที่ได้รับมอบหมายจะได้รับอีเมลแจ้งอีกครั้ง
- **เส้นทางผ่าน manager**: `requires_manager_verification` เป็นจริงเมื่อ severity ≥
  เกณฑ์ขั้นต่ำ (ค่าเริ่มต้น `Critical` เปลี่ยนได้ผ่าน `settings.SOC_SEVERITY_FLOOR`)
  **หรือ**ตั๋วถูกตั้งธง emergency เฉพาะตั๋วแบบนี้เท่านั้นที่จะผ่าน `PENDING_MANAGER`
  ตั๋วอื่นไป `APPROVED` ทันทีเมื่อ T1 ยืนยันว่า contain แล้ว
- Permission token (`TIER1_CREATOR`, `TIER2`, `ASSIGNED_ADMIN`, `MANAGER`)
  ประกาศไว้รายทรานซิชันใน `TRANSITION_PERMISSIONS` และ `transition_to`
  ยังบังคับใช้เงื่อนไข classification และเงื่อนไขเส้นทาง manager ด้วย
- State เดิม `UNDER_REVIEW` / `VERIFIED` / `CLOSED_FP` ถูกลบไปแล้วโดย
  migration 0018 (แปลงเป็น `CONTAINMENT_REPORTED` / `PENDING_MANAGER` /
  `CLOSED_EVENT` ตามลำดับ) หากพบชื่อเหล่านี้ในเอกสารเก่าหรือ git history
  ให้แปลความหมายตามนี้

### 3.2 Role (`apps/accounts/models.py` — `UserProfile`)

| Role | ความสามารถ |
|---|---|
| **SOC Staff, Tier 1** | สร้างตั๋ว (จาก manual triage หรือจาก Wazuh alert), กำหนด classification, มอบหมาย admin, escalate ไป T2, ตรวจสอบยืนยันการ containment — เป็น role เดียวที่สร้างตั๋วได้ |
| **SOC Staff, Tier 2** | จัดการเฉพาะตั๋ว `ESCALATED_T2`: แก้ไข classification, ส่งกลับ T1, หรือปิดเป็น event |
| **SOC Manager** | ตรวจสอบยืนยันตั๋ว `PENDING_MANAGER` → `APPROVED` |
| **System Admin** | เห็นเฉพาะตั๋วที่ตนเป็น `assigned_admin` เขียน `containment_report` (มาตรการรับมือ) และ `remediation_summary` (ผลการตรวจสอบ) แล้วส่งตั๋วกลับให้ T1 — ไม่มีสิทธิ์กำหนด classification |
| **System Owner** | ได้รับอีเมลแจ้งเมื่อตั๋วของระบบที่ตนดูแลถูกเปิด/ปิด มีหน้า "My Tickets" สำหรับดูโดยเฉพาะที่ `/incidents/my-tickets/` |

การมองเห็นตั๋วรวมศูนย์อยู่ที่ `TicketQuerySet.visible_to(user)`: role ฝั่ง SOC
เห็นตั๋วทั้งหมด, system admin เห็นเฉพาะตั๋วที่ได้รับมอบหมาย, ผู้ใช้ที่ไม่มี profile
ไม่เห็นอะไรเลย **ต้องเช็ค `getattr(user, 'profile', None)` ก่อนเช็ค role เสมอ** —
superuser ที่สร้างผ่าน `createsuperuser` ไม่มี profile

### 3.3 ธง Emergency

`is_emergency` เปิด/ปิดได้**ทุก** stage รวมถึง terminal state โดยทุก role
**ยกเว้น** Tier 1 — T1 จะตั้งได้ก็ต่อเมื่อตั๋วเคยถูก escalate ไป T2 มาก่อน
(`was_escalated_to_t2` ซึ่งคำนวณจาก timestamp `escalated_to_t2_at`
ที่เขียนครั้งเดียวไม่ลบทิ้ง) การเปิด/ปิดทุกครั้งจะบันทึก `TicketLog`
และธง emergency บังคับให้ต้องผ่านการตรวจสอบของ manager

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

### 3.5 การรับ alert จาก Wazuh และการ triage (`apps/wazuh_ingest`)

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

### 3.6 การแจ้งเตือน (`apps/incidents/notifications.py`)

- ส่งอีเมลผ่าน SMTP (ตั้งค่าใน `.env`) โดย `SITE_URL` ใช้สร้างลิงก์แบบ absolute
- `notify_containment_required` ทำงานทุกครั้งที่ตั๋วเข้าสู่ `AWAITING_CONTAINMENT`
  (ทั้งการมอบหมายครั้งแรก**และ**ทุกรอบของการตีกลับ)
- System owner ได้รับแจ้งเมื่อตั๋วของระบบที่ตนดูแลถูกเปิด/ปิด
- มีอีเมลแจ้ง credential ผู้ใช้ใหม่ และ action ในหน้า admin สำหรับส่ง username ซ้ำ /
  รีเซ็ตรหัสผ่าน (action ภาษาไทยในหน้า Users ของ admin)
- ความล้มเหลวของอีเมล**ไม่ทำให้งานหลักล้มเหลว** (ออกแบบไว้เช่นนั้น):
  อีเมลส่งไม่ออกจะแสดงคำเตือน แต่ไม่ rollback ทรานซิชันของตั๋ว

### 3.7 Dashboard (`apps/dashboard`)

หน้าแรก (`/`) แสดง KPI/กราฟ: pipeline สถานะเคส, หมวดหมู่, กลุ่มความเร่งด่วน OLA
และตารางตั๋วที่มีคอลัมน์ "Status Updated" ขับเคลื่อนโดย `status_changed_at`
(ฟิลด์เฉพาะที่ประทับเวลาใหม่**เฉพาะ**เมื่อมีการเปลี่ยนสถานะจริง — การเพิ่มโน้ตหรือ
เปิด/ปิดธง emergency จะอัปเดต `updated_at` แต่ไม่แตะฟิลด์นี้)
ข้อมูลกราฟส่งผ่าน `json_script` (ไม่ใช้ `|safe` กับข้อมูลผู้ใช้ — คงไว้แบบนี้ต่อไป)

### 3.8 ฟีเจอร์อื่น ๆ

- ไฟล์แนบตั๋ว (จำกัด 25 MB, ให้ดาวน์โหลดอย่างเดียว — ดู §8), subtask,
  log/ประวัติตั๋วพร้อมแก้ไขได้, export Excel, ค้นหาแบบ global, IP lookup,
  บันทึก manual triage (`TriageRecord.source` ใช้ชุดตัวเลือกร่วมกับ
  `Ticket.source`)

## 4. แนะนำโครงสร้างโค้ด

```
config/                 settings.py, urls.py, middleware.py (CSP)
apps/
  incidents/            ★ app หลักของระบบ — เริ่มอ่านที่นี่
    models.py           Ticket + state machine + ฟิลด์ OLA + log/ไฟล์แนบ/subtask (61 KB)
    views.py            view ของตั๋ว/triage ทั้งหมด (48 KB)
    notifications.py    อีเมลทุกฉบับที่ระบบส่ง
    ola.py              single source of truth ของการจัดกลุ่ม OLA
    forms.py            ฟอร์มตั๋ว/triage/ไฟล์แนบ (รวมการจำกัดขนาดไฟล์)
    management/commands/seed_data.py            ตั๋วสังเคราะห์สำหรับ dev
    management/commands/seed_dashboard_mockup.py ชุดข้อมูล demo/ภาพหน้าจอ
    management/commands/seed_ola_demo_buckets.py ชุดข้อมูล demo กราฟ OLA
  accounts/             UserProfile (role, tier), admin action เรื่อง credential
  dashboard/            view ของ KPI + เทสต์
  wazuh_ingest/         model WazuhAlert, การ ingest จาก OpenSearch, view การ triage
  customers/, projects/ ⚠ โค้ดตาย (DEAD CODE) — ไม่อยู่ใน INSTALLED_APPS ไม่มี URL
                        (ของเหลือจากเวอร์ชัน soc-crm เดิม) ข้ามไปหรือลบทิ้งได้
templates/              Django template (base.html + โฟลเดอร์แยกตาม app)
```

**ลำดับการอ่านสำหรับ developer ใหม่:**

1. `apps/incidents/models.py` — อ่าน model `Ticket` จากบนลงล่าง: สถานะต่าง ๆ,
   `TRANSITION_PERMISSIONS`, `transition_to`, `OLA_TARGETS`, `save()`
2. `WORKFLOW_REDESIGN.md` — ทำไม state machine ถึงมีรูปร่างแบบนี้
3. `apps/incidents/views.py` — `ticket_detail` และ view ที่ POST ทรานซิชัน
   จากนั้น `apps/wazuh_ingest/views.py` สำหรับเส้นทาง alert-สู่-ตั๋ว
4. ไล่ตั๋วหนึ่งใบตั้งแต่ต้นจนจบใน UI ด้วยบัญชีทดสอบที่ seed ไว้ (§5)

**เทสต์**มีจำนวนมากและถือเป็นสเปกของ workflow ในรูปแบบที่รันได้:
`apps/incidents/tests.py` (71 KB) ครอบคลุมทรานซิชัน/สิทธิ์,
`apps/dashboard/tests.py` ครอบคลุมการคำนวณ KPI, `apps/wazuh_ingest/tests.py`
mock HTTP ทั้งหมด รันทั้งหมดด้วย `python manage.py test` — ควรรันก่อนและหลัง
การแก้ไข workflow ทุกครั้ง

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

- `python manage.py seed_data` — ตั๋ว 100 ใบกระจายใน 30 วัน ครบทุกสถานะและ
  severity พร้อมผู้ใช้ 5 role ข้อมูล seed ทุกแถวมี prefix `seed_` ใน username
  จึงลบออกได้สะอาด (`--flush`)
- `python manage.py ingest_wazuh_alerts --fixture [--fresh]` — alert ตัวอย่าง
  แบบ offline สำหรับทดสอบ flow การ triage ของ Wazuh
- `test_accounts.txt` — บัญชีล็อกอินสำหรับ dev 5 บัญชี (รหัสผ่านร่วม `Test1234!`)
  หนึ่งบัญชีต่อ role **ใช้สำหรับ dev เท่านั้น ห้ามสร้างบัญชีเหล่านี้ใน production**

## 6. การ Deploy

Production: `docker compose -f docker-compose.prod.yml up -d --build`
(nginx → gunicorn → Django + PostgreSQL) container `web` รัน `migrate` +
`collectstatic` อัตโนมัติทุกครั้งที่ start ดูขั้นตอนเต็มใน DEPLOY.md
(UFW, การสร้าง superuser, บัญชีทีม, การดู log)

- `docker-compose.yml` (ไม่มี suffix) ใช้สำหรับ **dev บนเครื่องเท่านั้น**
  (runserver + bind-mount) ห้ามนำไป deploy เด็ดขาด
- ไม่มีหน้า sign-up สาธารณะ: บัญชีทั้งหมดสร้างผ่าน `/admin/`
- **ต้องถามผู้ดูแลคนเดิม:** production รันอยู่ที่ไหนจริง ๆ (host/IP),
  ใครถือ secret ใน `.env` (รหัสผ่าน DB, SMTP, credential ของ OpenSearch)
  และอะไรเป็นตัว backup ข้อมูล PostgreSQL — ทั้งหมดนี้ไม่มีอยู่ใน repo

## 7. ปัญหาที่ทราบแล้ว จุดที่ต้องระวัง และเอกสารที่ล้าสมัย

1. **`apps/customers` และ `apps/projects` เป็นโค้ดตาย** — มีไฟล์
   models/views/urls อยู่บนดิสก์ แต่ไม่ได้ติดตั้งและไม่มี URL เชื่อมต่อ
   ลบได้อย่างปลอดภัย แต่ควรทำเป็น commit เก็บกวาดแยกต่างหากโดยตั้งใจ
2. **ตาราง role ใน DEPLOY.md ล้าสมัย**: ระบุว่า tier เป็น "ป้ายบอกอาวุโส
   ที่ไม่มีผลต่อสิทธิ์" และอ้างถึง `VERIFIED → APPROVED` ทั้งสองอย่าง
   เป็นข้อมูลก่อนการออกแบบใหม่ 2026-06-19 — ปัจจุบัน tier **มีผล**ต่อสิทธิ์
   และ state `VERIFIED` ไม่มีอยู่แล้ว ให้ยึด WORKFLOW_REDESIGN.md และโค้ดเป็นหลัก
3. **CSP ยังอนุญาต `'unsafe-inline'`** สำหรับ script/style
   (`config/middleware.py`, policy string อยู่ใน settings) inline handler
   สองจุดที่ขวางการเปลี่ยนไปใช้ nonce: `ticket_detail.html` (confirm) และ
   `ticket_history.html` (onchange) — เป็นขั้นตอน hardening ถัดไปที่วางแผนไว้
4. **ยังไม่มีการตรวจชนิดไฟล์/magic byte ของไฟล์อัปโหลด** (ความสำคัญต่ำ —
   ลดความเสี่ยงแล้วด้วยการบังคับดาวน์โหลด ดู §8)
5. **`escalation_queue` ระดับ alert เป็นของตกค้าง**หลังการออกแบบใหม่
   ปัจจุบันการ escalate ทำที่ระดับตั๋ว
6. **ไฟล์ `runserver-8099.*.log` ใน root ของ repo** เป็น log dev ที่หลงเหลือ —
   ลบทิ้งได้
7. **ความหมายของการ breach OLA ไม่สมมาตรกัน** (triage เป็นข้อเท็จจริงตายตัว
   ส่วน contain เป็นการนับถอยหลังแบบ real-time ดู §3.4) — เสี่ยงต่อการ "แก้บั๊ก"
   ผิด ๆ ถ้าเข้าใจว่าทั้งคู่เป็นแบบ real-time
8. **Data migration 0030 คำนวณ OLA deadline ทั้งหมดใหม่**ตามนโยบาย
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

- **วันที่ 1** — รันบนเครื่องตัวเอง (§5), seed ข้อมูล, ล็อกอินด้วยบัญชีทดสอบ
  ทั้ง 5 บัญชีแล้วลองคลิกสำรวจ
- **วันที่ 2** — อ่าน `Ticket` ใน `models.py` + WORKFLOW_REDESIGN.md;
  ไล่ incident หนึ่งเคสตั้งแต่ Wazuh fixture alert → triage → ตั๋ว → containment →
  อนุมัติ โดยสวมบทบาทผู้ใช้ที่ถูกต้องในแต่ละขั้น
- **วันที่ 3** — รันชุดเทสต์ทั้งหมด; อ่านผ่าน ๆ `incidents/tests.py`
  เพื่อดูกติกา workflow ในรูปแบบสเปกที่รันได้
- **วันที่ 4** — ทบทวน view ของ dashboard + `ola.py`; ทำความเข้าใจกลุ่ม OLA
  และ `status_changed_at`
- **วันที่ 5** — ตรวจ DEPLOY.md เทียบกับเครื่อง production จริงร่วมกับ
  ผู้ดูแลคนเดิม; ยืนยันเรื่อง secret, backup และตารางเวลาการ ingest
