// Tier 1 user manual (Thai) — reference sample
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  TableOfContents, Header, Footer, PageNumber, ImageRun, LevelFormat,
  PageBreak, VerticalAlign,
} = require("docx");

// ── Palette (matches the app) ──
const NAVY = "1A1A2E", BLUE = "245EA8", RED = "E63946",
      INK = "1F2D3D", MUTED = "6C7888", HAIR = "E1E6ED",
      WHITE = "FFFFFF", SUBTLE = "F7F8FA";
const FONT = "TH Sarabun New";
const MONO = "Consolas";

const OUT = "C:/Users/NT/Documents/SOC_Ticket/docs/user-guides/manuals/user-manual-soc-analyst-tier1.th.docx";
const LOGO = "C:/Users/NT/Documents/SOC_Ticket/static/Image/S25542658.jpg";

// ── Run / paragraph helpers ──
function r(text, o = {}) {
  const opts = { text, size: o.size || 32 };
  if (o.bold) opts.bold = true;
  if (o.italics) opts.italics = true;
  if (o.color) opts.color = o.color;
  if (o.mono) opts.font = MONO;
  if (o.super) opts.superScript = true;
  return new TextRun(opts);
}
function P(arg, o = {}) {
  const kids = typeof arg === "string" ? [r(arg, o)] : arg;
  return new Paragraph({ spacing: { after: o.after != null ? o.after : 120 }, alignment: o.align, children: kids });
}
function H1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] }); }
function H2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] }); }
function H3(text) { return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] }); }
function bullet(arg) {
  const kids = typeof arg === "string" ? [r(arg)] : arg;
  return new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60 }, children: kids });
}
function step(ref, arg) {
  const kids = typeof arg === "string" ? [r(arg)] : arg;
  return new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 80 }, children: kids });
}

// ── Callout box ──
function callout(kind, lines) {
  const map = {
    warn: { color: RED, bg: "FDECEE", label: "ข้อควรระวัง" },
    tip:  { color: BLUE, bg: "EAF1FB", label: "เคล็ดลับ" },
    note: { color: MUTED, bg: "F1F3F6", label: "สิ่งที่ต้องจำ" },
  };
  const c = map[kind];
  const body = [new Paragraph({ spacing: { after: 60 }, children: [r(c.label, { bold: true, color: c.color, size: 30 })] })];
  lines.forEach((ln, i) => {
    const kids = typeof ln === "string" ? [r(ln)] : ln;
    body.push(new Paragraph({ spacing: { after: i === lines.length - 1 ? 0 : 60 }, children: kids }));
  });
  return new Table({
    width: { size: 9600, type: WidthType.DXA },
    columnWidths: [9600],
    borders: {
      top: { style: BorderStyle.SINGLE, size: 2, color: c.bg },
      bottom: { style: BorderStyle.SINGLE, size: 2, color: c.bg },
      right: { style: BorderStyle.SINGLE, size: 2, color: c.bg },
      left: { style: BorderStyle.SINGLE, size: 28, color: c.color },
    },
    rows: [new TableRow({ children: [new TableCell({
      width: { size: 9600, type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: c.bg, color: "auto" },
      margins: { top: 140, bottom: 140, left: 200, right: 200 },
      children: body,
    })] })],
  });
}

// ── Screenshot placeholder ──
const FIGSEC = {};
function shot(caption, shotId, section) {
  FIGSEC[section] = (FIGSEC[section] || 0) + 1;
  const figNo = section + "-" + FIGSEC[section];
  const box = new Table({
    width: { size: 9600, type: WidthType.DXA },
    columnWidths: [9600],
    borders: {
      top: { style: BorderStyle.DASHED, size: 6, color: "9DB4D4" },
      bottom: { style: BorderStyle.DASHED, size: 6, color: "9DB4D4" },
      left: { style: BorderStyle.DASHED, size: 6, color: "9DB4D4" },
      right: { style: BorderStyle.DASHED, size: 6, color: "9DB4D4" },
    },
    rows: [new TableRow({ children: [new TableCell({
      width: { size: 9600, type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: SUBTLE, color: "auto" },
      margins: { top: 520, bottom: 520, left: 200, right: 200 },
      verticalAlign: VerticalAlign.CENTER,
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
          children: [r("[ ตำแหน่งภาพหน้าจอ ]", { bold: true, color: MUTED, size: 30 })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
          children: [r(caption, { color: INK })] }),
        new Paragraph({ alignment: AlignmentType.CENTER,
          children: [r("SHOT: " + shotId, { mono: true, color: "9AA6B4", size: 24 })] }),
      ],
    })] })],
  });
  const cap = new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 160 },
    children: [r("รูปที่ " + figNo + "  ", { bold: true, color: BLUE, size: 28 }), r(caption, { italics: true, color: MUTED, size: 28 })] });
  return [box, cap];
}

// ── Data table (styled) ──
function dataTable(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const border = { style: BorderStyle.SINGLE, size: 2, color: HAIR };
  const headRow = new TableRow({
    tableHeader: true,
    cantSplit: true,
    children: headers.map((h, i) => new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: NAVY, color: "auto" },
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      children: [new Paragraph({ children: [r(h, { bold: true, color: WHITE, size: 28 })] })],
    })),
  });
  const bodyRows = rows.map((cells, ri) => new TableRow({
    cantSplit: true,
    children: cells.map((cell, i) => {
      const kids = Array.isArray(cell) ? cell : [r(cell, { size: 28 })];
      return new TableCell({
        width: { size: widths[i], type: WidthType.DXA },
        shading: { type: ShadingType.CLEAR, fill: ri % 2 ? SUBTLE : WHITE, color: "auto" },
        margins: { top: 70, bottom: 70, left: 120, right: 120 },
        children: [new Paragraph({ spacing: { after: 0 }, children: kids })],
      });
    }),
  }));
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    borders: { top: border, bottom: border, left: border, right: border,
      insideHorizontal: border, insideVertical: border },
    rows: [headRow, ...bodyRows],
  });
}

function spacer(h) { return new Paragraph({ spacing: { after: h || 120 }, children: [] }); }
// Status name over its code, code on its own line (Word-safe break)
function stateName(th, code) {
  return [r(th, { bold: true, size: 28 }),
          new TextRun({ text: code, break: 1, font: MONO, size: 24, color: MUTED })];
}
function menuTag(t) { return r(t, { bold: true, color: BLUE }); }   // English UI label
function ui(t) { return r(t, { bold: true, color: INK }); }          // Thai UI label / button

// ═══════════════════════════ COVER ═══════════════════════════
const logoData = fs.readFileSync(LOGO);
const cover = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 900, after: 200 },
    children: [new ImageRun({ type: "jpg", data: logoData, transformation: { width: 232, height: 232 } })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
    children: [r("คู่มือการใช้งานระบบ", { color: MUTED, size: 34 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 },
    children: [r("SOC Support System", { bold: true, color: NAVY, size: 56 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 320 },
    children: [r("ระบบบริหารจัดการเหตุการณ์ความปลอดภัย", { color: INK, size: 34 })] }),
];
// Role band (full-width navy table cell)
cover.push(new Table({
  width: { size: 9600, type: WidthType.DXA }, columnWidths: [9600],
  borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } },
  rows: [new TableRow({ children: [new TableCell({
    width: { size: 9600, type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: NAVY, color: "auto" },
    margins: { top: 200, bottom: 200, left: 200, right: 200 },
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
        children: [r("คู่มือสำหรับบทบาท", { color: "AEB8CC", size: 30 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 },
        children: [r("นักวิเคราะห์ SOC ระดับ 1", { bold: true, color: WHITE, size: 46 })] }),
      new Paragraph({ alignment: AlignmentType.CENTER,
        children: [r("SOC Analyst — Tier 1", { color: "D7DEEC", size: 32 })] }),
    ],
  })] })],
}));
cover.push(spacer(360));
cover.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
  children: [r("เวอร์ชันระบบ v1.1.0", { color: INK, size: 28 }), r("   ·   ", { color: HAIR, size: 28 }),
             r("ปรับปรุงล่าสุด 3 กันยายน 2026", { color: INK, size: 28 })] }));
cover.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
  children: [r("คู่มือฉบับที่ 1.0 (ตัวอย่าง)", { color: MUTED, size: 28 })] }));
cover.push(spacer(700));
cover.push(new Paragraph({ alignment: AlignmentType.CENTER,
  children: [r("เอกสารใช้ภายในองค์กร — บริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน)", { italics: true, color: MUTED, size: 26 })] }));
cover.push(new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════════════ TOC ═══════════════════════════
const toc = [
  new Paragraph({ spacing: { after: 160 }, children: [r("สารบัญ", { bold: true, color: NAVY, size: 40 })] }),
  new TableOfContents("สารบัญ", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ═══════════════════════════ BODY ═══════════════════════════
const body = [];
const push = (...x) => x.forEach((e) => body.push(e));

// 1. About
push(H1("1. เกี่ยวกับคู่มือฉบับนี้"));
push(P([r("คู่มือฉบับนี้จัดทำขึ้นสำหรับ "), r("นักวิเคราะห์ SOC ระดับ 1 (Tier 1)", { bold: true }),
  r(" โดยเฉพาะ อธิบายทุกหน้าจอและทุกงานที่คุณต้องใช้ในการทำงานประจำวัน ตั้งแต่การเข้าสู่ระบบ การคัดแยกการแจ้งเตือน การเปิดตั๋วงาน ไปจนถึงการดำเนินการต่อเมื่อเรื่องถูกส่งกลับมาถึงคุณ")]));
push(H2("ผู้อ่านและขอบเขต"));
push(bullet([r("ผู้อ่าน: ", { bold: true }), r("นักวิเคราะห์ SOC ระดับ 1 ผู้เป็นด่านแรกในการรับและคัดแยกเหตุการณ์")]));
push(bullet([r("ขอบเขต: ", { bold: true }), r("เฉพาะงานและสิทธิ์ของบทบาท Tier 1 — งานของบทบาทอื่นมีคู่มือแยกเล่ม")]));
push(H2("สัญลักษณ์ที่ใช้ในคู่มือ"));
push(callout("warn", ["กล่องสีแดง — เรื่องที่ต้องระวังเป็นพิเศษ หากพลาดอาจกระทบเส้นทางของตั๋วงาน"]));
push(spacer(80));
push(callout("tip", ["กล่องสีน้ำเงิน — เคล็ดลับหรือคำแนะนำที่ช่วยให้ทำงานได้เร็วและถูกต้องขึ้น"]));
push(spacer(80));
push(callout("note", ["กล่องสีเทา — ข้อเท็จจริงสำคัญของระบบที่ควรจำ"]));
push(spacer(120));
push(callout("note", [
  [r("ในคู่มือฉบับตัวอย่างนี้ ตำแหน่งภาพหน้าจอทั้งหมดยังเป็น ", {}), r("กรอบว่าง (placeholder)", { bold: true }), r(" ระบบจะเติมภาพจริงในขั้นตอนถัดไป", {})],
  [r("ชื่อเมนูภาษาอังกฤษ เช่น ", {}), menuTag("My Queue"), r(" คือข้อความที่ปรากฏจริงบนหน้าจอ ส่วนคำอธิบายภาษาไทยอยู่ในวงเล็บ", {})],
]));

// 2. Role at a glance
push(H1("2. บทบาทของคุณโดยย่อ"));
push(P("นักวิเคราะห์ระดับ 1 เป็นด่านแรกและเป็น “เจ้าของ” ตั๋วงานตลอดสายงานฝั่งต้นทาง หน้าที่หลักของคุณคือรับการแจ้งเตือน คัดแยก เปิดตั๋วงาน และจัดประเภทเหตุการณ์ว่าเป็น Event หรือ Incident แล้วเลือกเส้นทางที่เหมาะสม"));
push(H2("สิ่งที่คุณทำได้ และทำไม่ได้"));
push(dataTable(
  ["สิ่งที่คุณทำได้ (Tier 1)", "สิ่งที่คุณทำไม่ได้"],
  [
    ["เปิดตั๋วงานใหม่ และจัดประเภท Event / Incident", "ตรวจรับงานควบคุมและปิดงาน (เป็นหน้าที่ของ Tier 2)"],
    ["คัดแยก Alert จาก Wazuh และรายการรับแจ้งด้วยตนเอง", "มอบหมายผู้ดูแลระบบด้วยตนเองหลังส่งต่อให้ Tier 2"],
    ["เลือกเส้นทาง: มอบผู้ดูแลระบบ หรือส่งต่อ Tier 2", "ตั้ง/ยกเลิกแฟล็กฉุกเฉิน (เฉพาะผู้จัดการ SOC)"],
    ["บันทึกผลการแก้ไขของเจ้าของระบบแล้วส่งให้ Tier 2", "อนุมัติปิดงานขั้นสุดท้าย (Tier 2 หรือผู้จัดการ SOC)"],
  ],
  [4800, 4800],
));
push(spacer(140));
push(callout("warn", [
  [r("ตั๋วงานหนึ่งใบผูกกับ ", {}), r("ผู้เปิดตั๋ว", { bold: true }), r(" เท่านั้น — งานฝั่ง Tier 1 ของตั๋วใบนั้น (เช่น การดำเนินการต่อเมื่อ Tier 2 ส่งกลับ) ทำได้โดยผู้เปิดตั๋วคนเดิมเสมอ เพื่อนร่วมทีม Tier 1 คนอื่นจะดำเนินการแทนในตั๋วของคุณไม่ได้", {})],
]));

// 3. Login
push(H1("3. การเข้าสู่ระบบ"));
push(step("s3", [r("เปิดเว็บเบราว์เซอร์ แล้วไปยังที่อยู่ของระบบที่ผู้ดูแลระบบแจ้งให้คุณทราบ")]));
push(step("s3", [r("กรอก "), ui("ชื่อผู้ใช้ (Username)"), r(" และ "), ui("รหัสผ่าน (Password)"), r(" ที่ได้รับ")]));
push(step("s3", [r("กดปุ่มเข้าสู่ระบบ ระบบจะพาคุณเข้าสู่ "), menuTag("SOC Dashboard"), r(" โดยอัตโนมัติ")]));
push(...shot("หน้าเข้าสู่ระบบ แสดงช่องชื่อผู้ใช้ รหัสผ่าน และปุ่มเข้าสู่ระบบ", "T1-login", 3));
push(callout("note", [
  "บัญชีทุกบัญชีสร้างและกำหนดบทบาทโดยผู้ดูแลระบบ SOC คุณสมัครใช้งานเองไม่ได้ หากลืมรหัสผ่านให้ติดต่อทีม SOC",
  [r("ระบบล็อกบัญชีชั่วคราวเมื่อกรอกรหัสผ่านผิดหลายครั้งติดกัน ", {}), r("(ค่าเริ่มต้น 5 ครั้ง)", { bold: true }), r(" เพื่อความปลอดภัย หากถูกล็อกให้ติดต่อผู้ดูแลระบบ", {})],
]));

// 4. Screens & menus
push(H1("4. หน้าจอและเมนูของคุณ"));
push(P([r("หลังเข้าสู่ระบบ คุณจะเห็นแถบเมนูด้านซ้ายมือ ระบบแสดงเฉพาะเมนูที่บทบาทของคุณมีสิทธิ์ใช้งาน สำหรับ Tier 1 เมนูจะจัดเป็น 3 กลุ่มหลักดังนี้")]));
push(dataTable(
  ["กลุ่ม / เมนู", "หน้าที่"],
  [
    [[menuTag("Overview › SOC Dashboard")], "ภาพรวมสถานะงานและตัวชี้วัดของทีม SOC"],
    [[menuTag("Intake & Triage › My Queue"), r(" (คิวงานของฉัน)")], "งานที่รอคุณดำเนินการ, รายการรับแจ้งด้วยตนเอง, และประวัติ"],
    [[menuTag("Intake & Triage › Wazuh Alert Triage")], "การแจ้งเตือนจากระบบตรวจจับ Wazuh ที่รอการคัดแยก"],
    [[ui("เปิดเคสใหม่")], "เปิดตั๋วงานใหม่โดยตรง (เลือกขอบเขตระบบเดียว/หลายระบบในฟอร์ม)"],
    [[menuTag("Tickets › Active Tickets")], "ตั๋วงานที่ยังไม่ปิด ทั้งหมดที่คุณมองเห็น"],
    [[menuTag("Tickets › Ticket History")], "ตั๋วงานที่ปิดแล้ว สำหรับค้นย้อนหลัง"],
    [[menuTag("Tickets › IOC Search")], "ค้นหาตัวบ่งชี้การบุกรุก (IP, ค่าแฮช ฯลฯ) ข้ามตั๋ว"],
  ],
  [4200, 5400],
));
push(...shot("แถบเมนูด้านซ้ายเมื่อเข้าสู่ระบบด้วยบทบาท Tier 1 พร้อมตัวเลขจำนวนงานค้างบนเมนู", "T1-sidebar", 4));

// 5. Core tasks
push(H1("5. งานหลักทีละขั้นตอน"));

push(H2("5.1 คัดแยก Alert จาก Wazuh"));
push(P([r("การแจ้งเตือนส่วนใหญ่มาจากระบบตรวจจับอัตโนมัติ "), r("Wazuh", { bold: true }), r(" และปรากฏที่เมนู "), menuTag("Wazuh Alert Triage")]));
push(step("s51", [r("เปิดเมนู "), menuTag("Wazuh Alert Triage"), r(" จะเห็นรายการ Alert เรียงตามความรุนแรงและ OLA")]));
push(step("s51", [r("กด "), ui("รับรายการ (Claim)"), r(" ที่ Alert ที่ต้องการ เพื่อจองว่าคุณเป็นผู้ดูแล (กันการทำซ้ำ)")]));
push(step("s51", [r("หลังรับรายการ เลือกดำเนินการอย่างใดอย่างหนึ่ง:")]));
push(bullet([ui("สร้าง Ticket"), r(" — เปิดตั๋วจาก Alert นี้ (ไปยังแบบฟอร์มในหัวข้อ 5.3)")]));
push(bullet([ui("Project Incident"), r(" — เหตุการณ์เดียวที่กระทบหลายระบบ ระบบจะสร้างตั๋วแยกตามระบบ")]));
push(bullet([ui("คืนคิว (Release)"), r(" — คืน Alert กลับเข้าคิว "), r("ต้องระบุเหตุผล", { bold: true })]));
push(...shot("หน้า Wazuh Triage แสดงรายการ Alert พร้อมปุ่มรับรายการ สร้าง Ticket และคืนคิว", "T1-wazuh-triage", 5));
push(callout("tip", [
  [r("ระบบแปลงระดับของ Alert เป็นความรุนแรงเบื้องต้นให้อัตโนมัติ (สูงมาก→Critical, สูง→High, กลาง→Medium, ที่เหลือ→Low) ", {}), r("ปรับแก้ได้", { bold: true }), r(" ก่อนบันทึก", {})],
  [r("ต้องการรวมหลาย Alert เป็นตั๋วเดียว ให้เปิด ", {}), ui("โหมดรวม Alert"), r(" แล้วเลือก Alert ที่ Claim ไว้ตั้งแต่ 2 รายการขึ้นไป", {})],
]));

push(H2("5.2 รับแจ้งด้วยตนเอง (Manual Intake)"));
push(P([r("เหตุการณ์ที่แจ้งผ่านช่องทางอื่น เช่น อีเมลหรือโทรศัพท์ จะบันทึกไว้ในเมนู "), menuTag("My Queue"), r(" แท็บ "), ui("รับแจ้งด้วยตนเอง")]));
push(step("s52", [r("ที่ "), menuTag("My Queue"), r(" กด "), ui("เพิ่มรายการรับแจ้ง"), r(" เพื่อบันทึกเรื่องที่แจ้งเข้ามา")]));
push(step("s52", [r("ที่แท็บ "), ui("รับแจ้งด้วยตนเอง"), r(" กด "), ui("รับรายการ (Claim)"), r(" ที่รายการที่ต้องการ")]));
push(step("s52", [r("สร้างเป็นตั๋วงาน หรือหากไม่ใช่เหตุการณ์ความมั่นคงปลอดภัย ให้ปิดรายการพร้อมระบุเหตุผล (ไม่ต้องเปิดตั๋วแล้วปิดทิ้ง)")]));
push(...shot("แท็บรับแจ้งด้วยตนเองใน My Queue พร้อมปุ่มรับรายการ", "T1-manual-intake", 5));

push(H2("5.3 เปิดตั๋วงานและกรอกแบบฟอร์ม"));
push(P([r("เปิดตั๋วใหม่โดยตรงได้จากเมนู "), ui("เปิดเคสใหม่"), r(" หรือมาจากขั้นตอน 5.1/5.2 ที่ด้านบนของฟอร์มเลือกขอบเขต "), r("ระบบเดียว", { bold: true }), r(" หรือ "), r("หลายระบบ (Project Incident)", { bold: true })]));
push(step("s53", [r("จัดประเภทเหตุการณ์ — เลือก "), r("Event (ไม่เป็นภัย)", { bold: true }), r(" ระบบจะปิดตั๋วทันที หรือ "), r("Incident (เหตุการณ์จริง)", { bold: true }), r(" เพื่อดำเนินการต่อ")]));
push(step("s53", [r("หากเป็น Incident เลือกเส้นทาง: "), ui("มอบหมายให้ผู้ดูแลระบบ"), r(" (เมื่อมั่นใจ) หรือ "), ui("ส่งต่อให้ Tier 2"), r(" (เมื่อยังไม่แน่ใจ)")]));
push(step("s53", [r("กรอกรายละเอียด: ความรุนแรง วันเวลาที่ตรวจพบ ระบบ/บริการ IP รายละเอียดเหตุการณ์ ฯลฯ")]));
push(step("s53", [r("แนบหลักฐาน (ถ้ามี) — แต่ละไฟล์ไม่เกิน "), r("25 MB", { bold: true })]));
push(step("s53", [r("กดบันทึก ระบบจะสร้างหมายเลขตั๋วให้อัตโนมัติ")]));
push(...shot("แบบฟอร์มเปิดตั๋วงาน แสดงตัวเลือกจัดประเภท Event/Incident และตัวเลือกเส้นทาง", "T1-create-form", 5));
push(callout("warn", [
  "การจัดประเภท Event/Incident กำหนดเส้นทางทั้งหมดของตั๋ว หากจัดเป็น Event ตั๋วจะปิดทันที — หากไม่แน่ใจ ให้เลือก Incident แล้วส่งต่อให้ Tier 2 ช่วยวินิจฉัย",
]));

push(H2("5.4 ดำเนินการต่อเมื่อ Tier 2 ส่งกลับ (T1_REVIEW)"));
push(P("เมื่อ Tier 2 ยืนยันว่าเป็นเหตุการณ์จริงและส่งกลับ ตั๋วจะกลับมาถึงคุณ (ผู้เปิดตั๋วเดิม) ที่สถานะ “รอ Tier 1 ทบทวน”"));
push(step("s54", [r("เปิดตั๋วจาก "), menuTag("My Queue"), r(" ทบทวนความเห็นของ Tier 2")]));
push(step("s54", [r("เลือกเส้นทางการจัดการ: มอบหมายผู้ดูแลระบบ หรือให้เจ้าของระบบแก้ไขเอง พร้อมบันทึกเหตุผล")]));
push(step("s54", [r("ตั๋วจะไปรอ "), r("ผู้จัดการ SOC ตรวจก่อนมอบหมาย", { bold: true }), r(" โดยอัตโนมัติ")]));

push(H2("5.5 เส้นทางให้เจ้าของระบบแก้ไขเอง (Direct-to-Owner)"));
push(P("กรณีเจ้าของระบบเป็นผู้แก้ไขเอง เมื่อเจ้าของแจ้งว่าแก้ไขแล้ว ให้บันทึกผลและส่งให้ Tier 2 ตรวจรับ"));
push(step("s55", [r("บันทึกผลการแก้ไขที่เจ้าของระบบแจ้งกลับ พร้อมแนบหลักฐานที่ได้รับ")]));
push(step("s55", [r("ส่งให้ Tier 2 ตรวจรับ — ทำใน "), r("ขั้นตอนเดียว", { bold: true }), r(" (บันทึกและส่งพร้อมกัน)")]));
push(callout("note", ["การตรวจรับของ Tier 2 บังคับทุกกรณี ข้ามไม่ได้ — Tier 1 ไม่ได้เป็นผู้ตัดสินว่าการแก้ไขเพียงพอหรือไม่"]));

push(H2("ตัวอย่างเส้นทาง Incident เต็มรูปแบบ"));
push(P("สมมติมีการแจ้งเตือนพบมัลแวร์บนเซิร์ฟเวอร์:"));
push(step("s56", [r("Tier 1", { bold: true }), r(" รับ Alert สร้างตั๋ว จัดเป็น Incident และมอบหมายผู้ดูแลระบบ")]));
push(step("s56", [r("ผู้จัดการ SOC", { bold: true }), r(" ตรวจก่อนมอบหมาย ประเมินฉุกเฉิน แล้วส่งต่อ")]));
push(step("s56", [r("ผู้ดูแลระบบ", { bold: true }), r(" เข้าควบคุม (แยกเครื่อง/ลบมัลแวร์) แล้วส่งรายงานการควบคุม")]));
push(step("s56", [r("Tier 2", { bold: true }), r(" ตรวจรับรายงาน แล้วปิดงาน (หรือส่งผู้จัดการอนุมัติหากฉุกเฉิน)")]));
push(step("s56", [r("ระบบแจ้งเจ้าของระบบทางอีเมลเมื่อปิดงาน")]));
push(...shot("หน้ารายละเอียดตั๋วงาน แสดงปุ่มการดำเนินการตามสถานะปัจจุบันและช่องบันทึกการดำเนินการ", "T1-ticket-detail", 5));
push(callout("warn", ["ทุกครั้งที่เปลี่ยนสถานะ ระบบบังคับให้กรอกบันทึกการดำเนินการเสมอ บันทึกนี้ถูกเก็บในประวัติของตั๋วเพื่อการตรวจสอบย้อนหลัง"]));

// 6. States relevant to T1
push(H1("6. สถานะที่เกี่ยวข้องกับคุณ"));
push(P("ตารางนี้สรุปเฉพาะสถานะที่ Tier 1 ต้องลงมือทำ สถานะอื่น (เช่น การควบคุมของผู้ดูแลระบบ การตรวจรับของ Tier 2) เป็นงานของบทบาทอื่น"));
push(dataTable(
  ["สถานะ", "หมายถึง", "คุณต้องทำ"],
  [
    [stateName("แจ้งเหตุใหม่", "NEW"), "ตั๋วเพิ่งถูกเปิด", "เดินหน้าต่อทันทีตามการจัดประเภทและเส้นทางที่เลือกในฟอร์ม"],
    [stateName("ส่งต่อให้ Tier 2", "ESCALATED_T2"), "คุณส่งให้ Tier 2 พิจารณา", "รอ Tier 2 — ยังไม่ต้องทำอะไร"],
    [stateName("รอ Tier 1 ทบทวน", "T1_REVIEW"), "Tier 2 ยืนยัน Incident แล้วส่งกลับ", "เลือกเส้นทางการจัดการ (ดู 5.4)"],
    [stateName("รอเจ้าของระบบ", "AWAITING_OWNER"), "เจ้าของระบบกำลังแก้ไขเอง", "ติดตาม แล้วบันทึกผล+ส่ง Tier 2 (ดู 5.5)"],
    [stateName("รอ Tier 2 ตรวจสอบ", "PENDING_T2_REVIEW"), "ส่งเข้าคิวตรวจรับของ Tier 2 แล้ว", "รอ Tier 2 — ยังไม่ต้องทำอะไร"],
  ],
  [2600, 3400, 3600],
));

// 7. Emails
push(H1("7. การแจ้งเตือนทางอีเมล"));
push(P("ในฐานะ Tier 1 อีเมลที่คุณควรจับตาที่สุดคือเมื่อผู้ดูแลระบบส่งรายงานการควบคุมกลับมา ซึ่งเป็นสัญญาณว่าถึงคิวตรวจสอบ"));
push(dataTable(
  ["เหตุการณ์", "ผู้รับ"],
  [
    ["ผู้ดูแลระบบส่งรายงานการควบคุม", [r("นักวิเคราะห์ผู้เปิดตั๋ว ", { bold: true }), r("(คุณ)")]],
    ["เปิดตั๋วงานใหม่", "เจ้าของระบบ (หากระบุไว้)"],
    ["ปิดตั๋วงาน (อนุมัติ หรือปิด Event)", "เจ้าของระบบ (หากระบุไว้)"],
    ["ตั๋วถูกมอบหมาย/ส่งกลับให้ผู้ดูแลระบบ", "ผู้ดูแลระบบที่รับผิดชอบ"],
  ],
  [6000, 3600],
));

// 8. FAQ
push(H1("8. คำถามที่พบบ่อย"));
push(H3("ทำไมฉันตั้งแฟล็กฉุกเฉินไม่ได้?"));
push(P("แฟล็กฉุกเฉินตั้งได้เฉพาะผู้จัดการ SOC เท่านั้น หากเห็นว่าเหตุการณ์ควรเป็นฉุกเฉิน ให้แจ้งผู้จัดการผ่านบันทึกการดำเนินการ"));
push(H3("ทำไมฉันไม่เห็นปุ่มปิดงาน?"));
push(P("การตรวจรับงานควบคุมและการปิดงานเป็นหน้าที่ของ Tier 2 ไม่ใช่ Tier 1 หากไม่เห็นปุ่ม แปลว่าไม่ใช่ขั้นตอนของคุณ"));
push(H3("ทำไมเพื่อนร่วมทีม Tier 1 เปิดตั๋วของฉันต่อไม่ได้?"));
push(P("งานฝั่ง Tier 1 สงวนไว้ให้ผู้เปิดตั๋วเดิมเสมอ หากคุณไม่อยู่ ให้ประสานผู้จัดการ SOC"));
push(H3("ลืมรหัสผ่าน / บัญชีถูกล็อก ทำอย่างไร?"));
push(P("ติดต่อผู้ดูแลระบบ SOC เพื่อรีเซ็ตรหัสผ่านหรือปลดล็อกบัญชี คุณสมัคร/รีเซ็ตเองไม่ได้"));

// 9. Glossary
push(H1("9. อภิธานศัพท์"));
push(dataTable(
  ["คำ", "ความหมาย"],
  [
    [[r("ตั๋วงาน (Ticket)", { bold: true })], "บันทึกเหตุการณ์ความปลอดภัยหนึ่งเรื่อง มีหมายเลขอ้างอิงเฉพาะ"],
    [[r("Event / Incident", { bold: true })], "การจัดประเภท: Event = ไม่เป็นภัย (ปิด) · Incident = เหตุการณ์จริง (ดำเนินการต่อ)"],
    [[r("OLA", { bold: true })], "กรอบเวลามาตรฐานภายในองค์กร นับจากเวลาที่เหตุการณ์เกิดจริง (ไม่ใช่ SLA)"],
    [[r("แฟล็กฉุกเฉิน", { bold: true })], "เครื่องหมายเร่งด่วนพิเศษ ตั้งได้เฉพาะผู้จัดการ SOC บังคับให้ผ่านการอนุมัติก่อนปิด"],
    [[r("การควบคุม (Containment)", { bold: true })], "การเข้าจัดการที่ตัวระบบ/อุปกรณ์ที่ถูกโจมตี โดยผู้ดูแลระบบ"],
    [[r("คำขอทีมตอบสนอง", { bold: true })], "งานเฉพาะทางที่ผู้จัดการส่งให้ทีมนอก SOC (พิสูจน์หลักฐาน/ทดสอบเจาะระบบ)"],
  ],
  [3000, 6600],
));

// ═══════════════════════════ DOCUMENT ═══════════════════════════
function numberedRefs() {
  const refs = ["s3", "s51", "s52", "s53", "s54", "s55", "s56"];
  return refs.map((reference) => ({
    reference,
    levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.START,
      style: { run: { bold: true, color: BLUE, font: FONT }, paragraph: { indent: { left: 460, hanging: 300 } } } }],
  }));
}

const doc = new Document({
  creator: "NT SOC",
  title: "คู่มือการใช้งาน SOC Support System — Tier 1",
  styles: {
    default: {
      document: { run: { font: FONT, size: 32, color: INK }, paragraph: { spacing: { line: 320, lineRule: "auto" } } },
    },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 40, bold: true, color: NAVY },
        paragraph: { spacing: { before: 320, after: 140 }, outlineLevel: 0,
          border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: "D7DEEC", space: 6 } } } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 34, bold: true, color: BLUE },
        paragraph: { spacing: { before: 220, after: 100 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 32, bold: true, color: INK },
        paragraph: { spacing: { before: 160, after: 60 }, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.START,
        style: { run: { color: BLUE }, paragraph: { indent: { left: 460, hanging: 260 } } } }] },
      ...numberedRefs(),
    ],
  },
  sections: [
    // Cover — no header/footer
    { properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
      children: cover },
    // Body — header + footer, page numbers restart
    {
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 }, pageNumbers: { start: 1 } } },
      headers: { default: new Header({ children: [new Paragraph({
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: HAIR, space: 4 } },
        tabStops: [{ type: "right", position: 10772 }],
        children: [r("SOC Support System", { color: MUTED, size: 24 }),
          new TextRun({ text: "\tคู่มือนักวิเคราะห์ SOC ระดับ 1", font: FONT, size: 24, color: MUTED })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.CENTER,
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: HAIR, space: 4 } },
        children: [new TextRun({ text: "หน้า ", font: FONT, size: 24, color: MUTED }),
          new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 24, color: MUTED })] })] }) },
      children: [...toc, ...body],
    },
  ],
});

Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(OUT, buf); console.log("Wrote", OUT, buf.length, "bytes"); });
