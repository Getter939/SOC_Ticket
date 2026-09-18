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
function menuTag(t) { return r(t, { bold: true, color: BLUE }); }   // sidebar / menu label (Thai since v1.7.1)
function ui(t) { return r(t, { bold: true, color: INK }); }          // button / field label on screen

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
  children: [r("เวอร์ชันระบบ v1.7.1", { color: INK, size: 28 }), r("   ·   ", { color: HAIR, size: 28 }),
             r("ปรับปรุงล่าสุด 18 กันยายน 2026", { color: INK, size: 28 })] }));
cover.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
  children: [r("คู่มือฉบับที่ 1.3", { color: MUTED, size: 28 })] }));
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
  [r("ในคู่มือฉบับนี้ ตำแหน่งภาพหน้าจอทั้งหมดยังเป็น ", {}), r("กรอบว่าง (placeholder)", { bold: true }), r(" ระบบจะเติมภาพจริงในขั้นตอนถัดไป", {})],
  [r("ตัวหนาสีน้ำเงิน เช่น ", {}), menuTag("รับเรื่องและคัดกรอง › คิวงาน Tier 1"), r(" คือชื่อเมนูบนแถบด้านซ้าย — ระบบปรับเป็นภาษาไทยทั้งหมดตั้งแต่ v1.7.1 หากหน้าจอของคุณยังเป็นภาษาอังกฤษ แปลว่ายังไม่ได้อัปเดตรุ่น", {})],
  [r("ตัวหนาสีเข้ม เช่น ", {}), ui("รับรายการ (Claim)"), r(" คือชื่อปุ่ม ช่องกรอก หรือหัวข้อการ์ดบนหน้าจอ", {})],
  [r("ชื่อเมนูกับหัวข้อบนหน้าจอ ", {}), r("ไม่จำเป็นต้องตรงกัน", { bold: true }), r(" เช่น เมนู ", {}), menuTag("คิวงาน Tier 1"), r(" เปิดไปยังหน้าที่พาดหัวว่า “คิวงานของฉัน”", {})],
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
push(step("s3", [r("กดปุ่มเข้าสู่ระบบ ระบบจะพาคุณเข้าสู่ "), menuTag("แดชบอร์ด SOC"), r(" โดยอัตโนมัติ")]));
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
    [[menuTag("ภาพรวม › แดชบอร์ด SOC")], "ภาพรวมสถานะงานและตัวชี้วัดของทีม SOC"],
    [[menuTag("รับเรื่องและคัดกรอง › คิวงาน Tier 1"), r(" (คิวงานของฉัน)")], "งานที่รอคุณดำเนินการ, เคสที่กำลังเฝ้าระวัง, รายการรับแจ้งด้วยตนเอง, และประวัติ"],
    [[menuTag("รับเรื่องและคัดกรอง › คัดกรองการแจ้งเตือนจาก Wazuh")], "การแจ้งเตือนจากระบบตรวจจับ Wazuh ที่รอการคัดแยก"],
    [[ui("เปิดเคสใหม่")], "เปิดตั๋วงานใหม่โดยตรง (เลือกขอบเขตระบบเดียว/หลายระบบในฟอร์ม)"],
    [[menuTag("เคส › เคสที่กำลังดำเนินการอยู่")], "ตั๋วงานที่ยังไม่ปิด ทั้งหมดที่คุณมองเห็น"],
    [[menuTag("เคส › ประวัติเคสที่ปิดไปแล้ว")], "ตั๋วงานที่ปิดแล้ว สำหรับค้นย้อนหลัง"],
    [[menuTag("เคส › ค้นหา IOC")], "ค้นหาตัวบ่งชี้การบุกรุก (IP, ค่าแฮช ฯลฯ) ข้ามตั๋ว"],
  ],
  [4200, 5400],
));
push(...shot("แถบเมนูด้านซ้ายเมื่อเข้าสู่ระบบด้วยบทบาท Tier 1 พร้อมตัวเลขจำนวนงานค้างบนเมนู", "T1-sidebar", 4));

// 5. Core tasks
push(H1("5. งานหลักทีละขั้นตอน"));

push(H2("5.1 คัดแยก Alert จาก Wazuh"));
push(P([r("การแจ้งเตือนส่วนใหญ่มาจากระบบตรวจจับอัตโนมัติ "), r("Wazuh", { bold: true }), r(" และปรากฏที่เมนู "), menuTag("คัดกรองการแจ้งเตือนจาก Wazuh")]));
push(P([r("คิวนี้รับเฉพาะ "), r("การแจ้งเตือนจากการตรวจจับ (Detection)", { bold: true }),
  r(" เท่านั้น — การแจ้งเตือน "), r("ช่องโหว่ (Vulnerability)", { bold: true }),
  r(" ไม่ถูกดึงเข้าระบบนี้แล้ว เพราะเป็นงานบริหารจัดการช่องโหว่ที่มีหน้าจอของตัวเองใน Wazuh อยู่แล้ว")]));
push(step("s51", [r("เปิดเมนู "), menuTag("คัดกรองการแจ้งเตือนจาก Wazuh"), r(" จะเห็นรายการ Alert เรียงตามความรุนแรงและ OLA")]));
push(step("s51", [r("ปรับมุมมองได้ตามต้องการ: "), r("กดหัวคอลัมน์", { bold: true }),
  r(" ได้ทุกคอลัมน์ ยกเว้น OLA และ ดำเนินการ (เวลา, Agent, Agent IP, ระดับ, Rule, สถานะ, ผู้รับเรื่อง) เพื่อเรียงลำดับ และเลือกจำนวนแถวต่อหน้าได้ "),
  r("25 / 50 / 100", { bold: true }), r(" — แถวที่ไม่มีค่าในคอลัมน์ที่เรียง จะถูกจัดไว้ท้ายสุดเสมอ")]));
push(step("s51", [r("กด "), ui("รับรายการ (Claim)"), r(" ที่ Alert ที่ต้องการ เพื่อจองว่าคุณเป็นผู้ดูแล (กันการทำซ้ำ)")]));
push(step("s51", [r("หลังรับรายการ เลือกดำเนินการอย่างใดอย่างหนึ่ง:")]));
push(bullet([ui("สร้าง Ticket"), r(" — เปิดตั๋วจาก Alert นี้ (ไปยังแบบฟอร์มในหัวข้อ 5.3)")]));
push(bullet([ui("Project Incident"), r(" — เหตุการณ์เดียวที่กระทบหลายระบบ ระบบจะสร้างตั๋วแยกตามระบบ")]));
push(bullet([ui("คืนคิว (Release)"), r(" — คืน Alert กลับเข้าคิว "), r("ต้องระบุเหตุผล", { bold: true })]));
push(...shot("หน้า Wazuh Triage แสดงรายการ Alert พร้อมปุ่มรับรายการ สร้าง Ticket และคืนคิว", "T1-wazuh-triage", 5));
push(callout("tip", [
  [r("ระบบแปลงระดับของ Alert เป็นความรุนแรงเบื้องต้นให้อัตโนมัติ (สูงมาก→Critical, สูง→High, กลาง→Medium, ที่เหลือ→Low) ", {}), r("ปรับแก้ได้", { bold: true }), r(" ก่อนบันทึก", {})],
  [r("ต้องการรวมหลาย Alert เป็นตั๋วเดียว ให้กด ", {}), ui("รวม Alert ที่เกี่ยวข้อง"),
   r(" ที่หัวหน้าจอ แล้วเลือก Alert ที่ Claim ไว้ตั้งแต่ 2 รายการขึ้นไป จากนั้นกด ", {}),
   ui("สร้าง Ticket จาก Alert ที่เลือก"), {}],
]));
push(spacer(80));
push(callout("note", [
  [r("เพิ่ม v1.5.2: ", { bold: true }), r("ตั๋วที่สร้างจากการรวม Alert จัดเป็น ", {}), r("Event", { bold: true }),
   r(" ได้แล้ว (เดิมบังคับให้เป็น Incident เท่านั้น) เหมาะกับกรณี Alert ชุดเดียวกันเป็น False Positive ทั้งชุด — ตั๋วจะถูกส่งให้ ", {}),
   r("Tier 2 ยืนยันก่อนปิด", { bold: true }), r(" ตามปกติ ไม่ได้ปิดทันที", {})],
]));

push(H2("5.2 รับแจ้งด้วยตนเอง (Manual Intake)"));
push(P([r("เหตุการณ์ที่แจ้งผ่านช่องทางอื่น เช่น อีเมลหรือโทรศัพท์ จะบันทึกไว้ในเมนู "), menuTag("คิวงาน Tier 1"), r(" แท็บ "), ui("รับแจ้งด้วยตนเอง")]));
push(step("s52", [r("ที่ "), menuTag("คิวงาน Tier 1"), r(" กด "), ui("เพิ่มรายการรับแจ้ง"), r(" เพื่อบันทึกเรื่องที่แจ้งเข้ามา")]));
push(step("s52", [r("ที่แท็บ "), ui("รับแจ้งด้วยตนเอง"), r(" กด "), ui("รับรายการ (Claim)"), r(" ที่รายการที่ต้องการ")]));
push(step("s52", [r("สร้างเป็นตั๋วงาน หรือหากไม่ใช่เหตุการณ์ความมั่นคงปลอดภัย ให้ปิดรายการพร้อมระบุเหตุผล (ไม่ต้องเปิดตั๋วแล้วปิดทิ้ง)")]));
push(...shot("แท็บรับแจ้งด้วยตนเองใน คิวงาน Tier 1 พร้อมปุ่มรับรายการ", "T1-manual-intake", 5));

push(H2("5.3 เปิดตั๋วงานและกรอกแบบฟอร์ม"));
push(P([r("เปิดตั๋วใหม่โดยตรงได้จากเมนู "), ui("เปิดเคสใหม่"), r(" หรือมาจากขั้นตอน 5.1/5.2 ที่ด้านบนของฟอร์มเลือกขอบเขต "), r("ระบบเดียว", { bold: true }), r(" หรือ "), r("หลายระบบ (Project Incident)", { bold: true })]));
push(step("s53", [r("จัดประเภทเหตุการณ์ — เลือก "), r("Event (ไม่เป็นภัย)", { bold: true }),
  r(" ตั๋วจะถูกส่งให้ "), r("Tier 2 ยืนยันก่อนปิด", { bold: true }), r(" หรือ "), r("Incident (เหตุการณ์จริง)", { bold: true }), r(" เพื่อดำเนินการต่อ")]));
push(step("s53", [r("หากเป็น Incident เลือกเส้นทาง: "), ui("มอบหมายให้ผู้ดูแลระบบ"), r(" (เมื่อมั่นใจ), "),
  ui("ให้เจ้าของระบบแก้ไขเอง"), r(" หรือ "), ui("ส่งต่อให้ Tier 2"), r(" (เมื่อยังไม่แน่ใจ) — สองเส้นทางแรกจะไปรอ "),
  r("ผู้จัดการ SOC ตรวจก่อนมอบหมาย", { bold: true }), r(" เสมอ")]));
push(step("s53", [r("หากยังไม่ชัดว่าเป็น Event หรือ Incident และเลือกส่งให้ Tier 2 จะมีช่อง "), ui("แนะนำให้เฝ้าระวัง (Monitoring)"), r(" ให้ติ๊กได้ — เป็นเพียง "), r("คำแนะนำ", { bold: true }), r(" ผู้ตัดสินใจเฝ้าระวังจริงคือ Tier 2 (ดู 5.6)")]));
push(step("s53", [r("กรอกรายละเอียด: ความรุนแรง, "), ui("เวลาที่ตรวจพบ"), r(" และ "), ui("เวลาที่เกิดเหตุ"),
  r(" (เพิ่ม v1.5.0 — คนละค่ากัน; ถ้ามาจาก Alert ระบบเติมให้ และมีปุ่มคัดลอกเวลาที่ตรวจพบมาใช้เมื่อไม่ทราบเวลาจริง), ระบบ/บริการ, รายละเอียดเหตุการณ์ ฯลฯ — ช่อง "),
  ui("IP Address"), r(" ใส่ได้ "), r("หลายค่า", { bold: true }), r(" คั่นด้วยจุลภาค อัฒภาค หรือขึ้นบรรทัดใหม่")]));
push(callout("note", [
  [r("ปรับปรุง v1.5.0: ", { bold: true }), r("ลำดับช่องต้นฟอร์มเป็น ", {}), ui("แหล่งที่มา → แหล่ง Log → หมายเลขอ้างอิง (Reference ID)"),
   r(" และ ", {}), r("ตัดช่องกรอก MAC Address ออก", { bold: true }), r(" (ค่าที่บันทึกไว้เดิมยังแสดงแบบอ่านอย่างเดียว)", {})],
]));
push(step("s53", [r("กรอกหัวข้อ "), ui("Indicators of Compromise (IOC)"), r(" เท่าที่มี (ดูรายละเอียดในหัวข้อ 5.3.1)")]));
push(step("s53", [r("แนบหลักฐาน (ถ้ามี) — แต่ละไฟล์ไม่เกิน "), r("25 MB", { bold: true })]));
push(step("s53", [r("กดบันทึก ระบบจะสร้างหมายเลขตั๋วให้อัตโนมัติ")]));
push(...shot("แบบฟอร์มเปิดตั๋วงาน แสดงตัวเลือกจัดประเภท Event/Incident และตัวเลือกเส้นทาง", "T1-create-form", 5));
push(callout("warn", [
  "การจัดประเภท Event/Incident กำหนดเส้นทางทั้งหมดของตั๋ว — และไม่ว่าจะเลือกทางใด ตั๋วก็ไม่ปิดด้วยมือคุณเอง: Event ต้องให้ Tier 2 ยืนยันก่อนปิด ส่วน Incident ต้องผ่านผู้จัดการ SOC และการตรวจรับของ Tier 2 หากไม่แน่ใจ ให้เลือก Incident แล้วส่งต่อให้ Tier 2 ช่วยวินิจฉัย",
]));

push(H3("5.3.1 ตัวบ่งชี้การบุกรุก (Indicators of Compromise)"));
push(P([r("หัวข้อ "), ui("Indicators of Compromise (IOC)"), r(" บนแบบฟอร์มมี "), r("6 ช่อง", { bold: true }),
  r(" แยกตามประเภท และแต่ละช่องใส่ได้หลายค่า — กดปุ่ม "), ui("＋ เพิ่ม / add"),
  r(" เพื่อเพิ่มกล่องข้อความอีกกล่องต่อหนึ่งค่า และกด "), ui("×"), r(" เพื่อลบกล่องที่ไม่ใช้")]));
push(dataTable(
  ["ช่อง", "ตัวอย่างค่า"],
  [
    ["File Name", "invoice.exe"],
    ["Hash (SHA-256)", "ค่าแฮช 64 ตัวอักษร"],
    ["Domain", "malicious.example.com"],
    ["IP Address", "79[.]124[.]59[.]146"],
    ["URL", "https://bad.example.com/x"],
    ["File Path", "C:\\Users\\...\\invoice.exe"],
  ],
  [3200, 6400],
));
push(spacer(140));
push(callout("note", [
  [r("เพิ่ม v1.5.0: ", { bold: true }), r("ส่วน IOC ยังมีช่อง ", {}), ui("ผู้ใช้ (User)"), r(" และ ", {}), ui("คำสั่ง (Command)"),
   r(" ซึ่งค้นหาได้และเข้าสู่รายงานเช่นกัน แต่ ", {}), r("ไม่ถูกรวมเข้าฐานข้อมูล IOC โดยเจตนา", { bold: true }),
   r(" (เป็นบริบทของเหตุการณ์ ไม่ใช่ตัวบ่งชี้เครือข่าย/ไฟล์ที่แชร์ต่อ)", {})],
]));
push(spacer(140));
push(callout("tip", [
  [r("วางค่าที่ถูก “ถอดพิษ” (defanged) เช่น ", {}), r("79[.]124[.]59[.]146", { mono: true }), r(" หรือ ", {}), r("hxxp://", { mono: true }), r(" ได้เลย ระบบจะจัดรูปแบบให้เป็นมาตรฐานเดียวกันเอง", {})],
  [r("ค่าที่กรอกไว้จะเข้าสู่ ", {}), menuTag("ค้นหา IOC"), r(" ประวัติการแก้ไขของตั๋ว และรายงานเหตุการณ์ รวมทั้งไปปรากฏใน ", {}), menuTag("ฐานข้อมูล IOC"), r(" ให้ทีมพิสูจน์หลักฐานตรวจต่อ (หน้านั้นเปิดได้เฉพาะทีมพิสูจน์หลักฐาน คุณจึงไม่เห็นเมนูนี้) — กรอกให้ครบเท่าที่มีจึงมีประโยชน์กับทั้งกระบวนการ", {})],
]));
push(...shot("หัวข้อ Indicators of Compromise บนแบบฟอร์มตั๋ว แสดงช่องหลายค่าและปุ่มเพิ่ม", "T1-ioc-fields", 5));

push(H3("5.3.2 บันทึกไว้จัดเตรียม แล้วส่งภายหลัง (เพิ่ม v1.7.0)"));
push(P([r("ไม่จำเป็นต้องกรอกให้ครบในครั้งเดียว ที่ท้ายแบบฟอร์มมีปุ่มสองปุ่มที่ทำคนละอย่าง")]));
push(dataTable(
  ["ปุ่ม", "ระบบจะทำ"],
  [
    [[r("บันทึกไว้จัดเตรียม", { bold: true })], "ออกหมายเลขตั๋วให้ แต่ยังไม่ส่งเข้ากระบวนการ — ตั๋วอยู่สถานะ “กำลังจัดเตรียม (ยังไม่ส่ง)” และยังเป็นของคุณคนเดียว"],
    [[r("บันทึกและส่ง Ticket", { bold: true })], "บันทึกแล้วเดินตั๋วต่อทันทีตามการจัดประเภทและเส้นทางที่เลือกไว้"],
  ],
  [3200, 6400],
));
push(spacer(140));
push(P([r("ปุ่มส่งจะเปลี่ยนข้อความตามเส้นทางที่คุณเลือก เช่น "), ui("ส่งให้ Tier 2 ยืนยัน"), r(", "),
  ui("ส่งผู้จัดการ SOC (มอบหมาย System Admin)"), r(" หรือ "), ui("ส่งผู้จัดการ SOC (เจ้าของระบบแก้ไขเอง)"),
  r(" — อ่านข้อความบนปุ่มก่อนกดทุกครั้ง เพราะบอกปลายทางที่แท้จริงของตั๋ว")]));
push(...shot("ท้ายแบบฟอร์มเปิดเคส แสดงปุ่มบันทึกไว้จัดเตรียมและปุ่มบันทึกและส่ง Ticket", "T1-draft-buttons", 5));
push(P([r("ตั๋วที่จัดเตรียมไว้จะรออยู่ในเมนู "), menuTag("รับเรื่องและคัดกรอง › คิวงาน Tier 1"), r(" แท็บ "),
  ui("Ticket ของฉัน"), r(" กลับมาแก้ไขและแนบหลักฐานเพิ่มได้เรื่อย ๆ — ในระหว่างนี้หน้าแก้ไขยังให้คุณเปลี่ยน "),
  r("การจัดประเภท เส้นทาง และผู้ดูแลระบบที่รับผิดชอบ", { bold: true }), r(" ได้ ซึ่งหลังส่งแล้วจะแก้ไม่ได้อีก")]));
push(step("s53b", [r("เปิดตั๋วที่จัดเตรียมไว้จาก "), menuTag("คิวงาน Tier 1"), r(" แท็บ "), ui("Ticket ของฉัน")]));
push(step("s53b", [r("ตรวจข้อมูลและหลักฐานให้ครบ (แก้ไขผ่านปุ่ม "), ui("แก้ไขข้อมูล"), r(" ได้ ดู 5.9)")]));
push(step("s53b", [r("กด "), ui("ส่ง Ticket เข้าสู่กระบวนการ"), r(" ในการ์ด "), ui("Ticket อยู่ระหว่างจัดเตรียม"),
  r(" — หากยังไม่ชัดว่าเป็น Event หรือ Incident ติ๊ก "), ui("แนะนำให้ Tier 2 พิจารณาเฝ้าระวัง"), r(" ไปพร้อมกันได้")]));
push(...shot("แท็บ Ticket ของฉันในคิวงาน Tier 1 แสดงตั๋วที่อยู่ระหว่างจัดเตรียม", "T1-draft-tab", 5));
push(callout("warn", [
  [r("ตั๋วที่ยังจัดเตรียมอยู่ ", {}), r("ไม่มีใครเห็นและไม่มีอีเมลแจ้งใคร", { bold: true }),
   r(" — เจ้าของระบบยังไม่ได้รับแจ้ง และไม่มีบทบาทใดเริ่มงานต่อ หากเหตุการณ์เร่งด่วน อย่าทิ้งไว้เป็นฉบับจัดเตรียม ให้ส่งเข้ากระบวนการทันที", {})],
]));

push(H2("5.4 ดำเนินการต่อเมื่อ Tier 2 ส่งกลับ (T1_REVIEW)"));
push(P("เมื่อ Tier 2 ยืนยันว่าเป็นเหตุการณ์จริงและส่งกลับ ตั๋วจะกลับมาถึงคุณ (ผู้เปิดตั๋วเดิม) ที่สถานะ “รอ Tier 1 ทบทวน”"));
push(step("s54", [r("เปิดตั๋วจาก "), menuTag("คิวงาน Tier 1"), r(" ทบทวนความเห็นของ Tier 2")]));
push(step("s54", [r("เลือกเส้นทางการจัดการ: มอบหมายผู้ดูแลระบบ หรือให้เจ้าของระบบแก้ไขเอง พร้อมบันทึกเหตุผล")]));
push(step("s54", [r("ตั๋วจะไปรอ "), r("ผู้จัดการ SOC ตรวจก่อนมอบหมาย", { bold: true }), r(" โดยอัตโนมัติ")]));

push(H2("5.5 เส้นทางให้เจ้าของระบบแก้ไขเอง (Direct-to-Owner)"));
push(P("กรณีเจ้าของระบบเป็นผู้แก้ไขเอง เมื่อเจ้าของแจ้งว่าแก้ไขแล้ว ให้บันทึกผลและส่งให้ Tier 2 ตรวจรับ"));
push(step("s55", [r("บันทึกผลการแก้ไขที่เจ้าของระบบแจ้งกลับ พร้อมแนบหลักฐานที่ได้รับ")]));
push(step("s55", [r("ส่งให้ Tier 2 ตรวจรับ — ทำใน "), r("ขั้นตอนเดียว", { bold: true }), r(" (บันทึกและส่งพร้อมกัน)")]));
push(callout("note", ["การตรวจรับของ Tier 2 บังคับทุกกรณี ข้ามไม่ได้ — Tier 1 ไม่ได้เป็นผู้ตัดสินว่าการแก้ไขเพียงพอหรือไม่"]));

push(H2("5.6 ดำเนินการต่อเมื่อเคสอยู่ในการเฝ้าระวัง (Monitoring)"));
push(P([r("เมื่อ Tier 2 เห็นว่าเคสยังไม่ชัดว่าเป็น Event หรือ Incident เขาจะกด “เฝ้าระวัง 30 วัน” เคสจะกลับมาอยู่กับคุณ (ผู้เปิดตั๋ว) ที่สถานะ "), r("กำลังเฝ้าระวัง", { bold: true }), r(" และปรากฏในแท็บ "), ui("กำลังเฝ้าระวัง"), r(" ของ "), menuTag("คิวงาน Tier 1"), r(" พร้อมตัวนับถอยหลัง (เขียว → เหลืองเมื่อใกล้ครบ → แดงเมื่อครบกำหนด)")]));
push(P("ระหว่างนี้เพียงเฝ้าติดตาม ไม่ต้องทำอะไรจนกว่าจะครบกำหนดหรือมีเหตุเกิดขึ้น จากนั้นเปิดตั๋วแล้วสรุปผลด้วยการ์ด “สรุปผลการเฝ้าระวัง”:"));
push(step("s56b", [r("มีเหตุการณ์เกิดขึ้นระหว่างเฝ้าระวัง → กด "), ui("มีเหตุการณ์ → ออกเป็น Incident"), r(" (ส่งผู้จัดการ SOC ตรวจก่อนมอบหมาย)")]));
push(step("s56b", [r("ครบกำหนด 30 วันและไม่มีเหตุ → กด "), ui("ครบกำหนด/ไม่มีเหตุ → สรุปเป็น Event"), r(" (ส่ง Tier 2 ยืนยันปิด)")]));
push(...shot("การ์ดสรุปผลการเฝ้าระวังบนหน้ารายละเอียดตั๋ว พร้อมปุ่มออกเป็น Incident และสรุปเป็น Event", "T1-monitoring-conclude", 5));
push(callout("note", ["เฝ้าระวังได้ครั้งเดียวต่อเคส (30 วันคือกำหนดสูงสุด ขยายไม่ได้) และระหว่างเฝ้าระวังยังตั้งแฟล็กฉุกเฉินไม่ได้ เพราะเคสยังไม่ถูกจัดประเภท"]));

push(H2("ตัวอย่างเส้นทาง Incident เต็มรูปแบบ"));
push(P("สมมติมีการแจ้งเตือนพบมัลแวร์บนเซิร์ฟเวอร์:"));
push(step("s56", [r("Tier 1", { bold: true }), r(" รับ Alert สร้างตั๋ว จัดเป็น Incident และมอบหมายผู้ดูแลระบบ")]));
push(step("s56", [r("ผู้จัดการ SOC", { bold: true }), r(" ตรวจก่อนมอบหมาย ประเมินฉุกเฉิน แล้วส่งต่อ")]));
push(step("s56", [r("ผู้ดูแลระบบ", { bold: true }), r(" เข้าควบคุม (แยกเครื่อง/ลบมัลแวร์) แล้วส่งรายงานการควบคุม")]));
push(step("s56", [r("Tier 2", { bold: true }), r(" ตรวจรับรายงาน แล้วปิดงาน (หรือส่งผู้จัดการอนุมัติหากฉุกเฉิน)")]));
push(step("s56", [r("ระบบแจ้งเจ้าของระบบทางอีเมลเมื่อปิดงาน")]));
push(...shot("หน้ารายละเอียดตั๋วงาน แสดงปุ่มการดำเนินการตามสถานะปัจจุบันและช่องบันทึกการดำเนินการ", "T1-ticket-detail", 5));
push(callout("warn", ["ทุกครั้งที่เปลี่ยนสถานะ ระบบบังคับให้กรอกบันทึกการดำเนินการเสมอ บันทึกนี้ถูกเก็บในประวัติของตั๋วเพื่อการตรวจสอบย้อนหลัง"]));

push(H2("5.7 ดูตัวอย่างไฟล์แนบ และหลักฐานส่วนกลาง (ปรับปรุง v1.7.0)"));
push(P([r("ไฟล์แนบที่เป็น "), r("รูปภาพ", { bold: true }), r(" และ "), r("ข้อความ/log/CSV", { bold: true }),
  r(" มีลิงก์ "), ui("ดูตัวอย่าง"), r(" ให้เปิดดูในแท็บใหม่ได้ทันทีโดยไม่ต้องดาวน์โหลด — รูปภาพถูกแปลงใหม่เพื่อความปลอดภัย, ข้อความแสดงแบบ escape, และ CSV/TSV แสดงเป็นตาราง ไฟล์ประเภทอื่น (เอกสาร Office, ไฟล์บีบอัด, pcap) ยังเป็นการดาวน์โหลดเท่านั้น และทุกกรณีผ่านการตรวจสิทธิ์ก่อน")]));
push(H3("5.7.1 หลักฐานเฉพาะตั๋ว กับหลักฐานส่วนกลาง (เพิ่ม v1.7.0)"));
push(P([r("เมื่อเหตุการณ์เดียวกระทบหลายระบบ (Project Incident) หลักฐานถูกเก็บ "),
  r("แยกเป็นสองที่", { bold: true }), r(" และไม่ปะปนกัน:")]));
push(dataTable(
  ["เก็บที่ไหน", "ใช้กับอะไร"],
  [
    [[r("หลักฐานเฉพาะ Ticket", { bold: true })], "ไฟล์ที่เกี่ยวกับระบบนั้นระบบเดียว — แนบในหน้าตั๋วหรือหน้าแก้ไขตั๋ว ไม่ไปปรากฏในตั๋วใบอื่น"],
    [[r("หลักฐานส่วนกลาง", { bold: true })], "ไฟล์ที่เป็นของเหตุการณ์ทั้งกลุ่ม — แนบในหน้า Project Incident หัวข้อ “หลักฐานส่วนกลาง” ไม่ถูกคัดลอกลงตั๋วแต่ละใบ"],
  ],
  [3200, 6400],
));
push(spacer(140));
push(callout("tip", [
  [r("หน้าดูตัวอย่างรองรับทั้งสองแบบแล้ว เมื่อเปิดดูหลักฐานส่วนกลางจะมีปุ่ม ", {}), ui("กลับไปหน้ากลุ่ม"),
   r(" พากลับไปยัง Project Incident ต้นเรื่อง", {})],
  [r("ในหน้าแก้ไขตั๋วที่อยู่ในกลุ่ม ระบบจะเตือนไว้ให้ด้วยว่าหากไฟล์เป็นหลักฐานร่วมของเหตุการณ์ ควรไปแนบที่ ", {}),
   r("หลักฐานส่วนกลาง", { bold: true }), r(" แทน", {})],
]));
push(spacer(80));
push(callout("note", [
  [r("ปรับปรุง v1.7.0: ", { bold: true }), r("ถ้าการบันทึกไม่ผ่าน (เช่น กรอกข้อมูลไม่ครบ) ", {}),
   r("ไฟล์ที่เลือกไว้แล้วจะไม่หาย", { bold: true }), r(" ระบบเก็บไว้ให้เป็นป้ายสีเขียวใต้หัวข้อ ", {}),
   ui("ไฟล์ที่ระบบเก็บไว้ให้แล้ว"), r(" — เลือกเพิ่มต่อได้เลย ไม่ต้องเลือกใหม่ทั้งชุด และมีปุ่ม ", {}),
   ui("เลิกทำ"), r(" หากเผลอเอาออก", {})],
]));

push(H2("5.8 การยกเลิกตั๋วงาน (เพิ่ม v1.5.0)"));
push(P([r("ตั๋วที่ "), r("ซ้ำ", { bold: true }), r(" หรือ "), r("เปิดผิด", { bold: true }),
  r(" สามารถจบด้วยสถานะ "), stateName("ยกเลิกแล้ว", "CANCELLED"), r(" ได้โดยไม่ต้องจัดเป็น Event หรือรับรองการแก้ไข")]));
push(step("s58", [r("ขณะสถานะยังเป็น "), r("กำลังจัดเตรียม (ยังไม่ส่ง)", { bold: true }), r(" เท่านั้น คุณ (ผู้เปิดตั๋ว) กด "),
  ui("ยกเลิกตั๋ว"), r(" ได้เอง โดยเลือกเหตุผลและกรอกคำอธิบาย")]));
push(step("s58", [r("หลังตั๋วเดินหน้าไปแล้ว คุณทำได้เพียง "), ui("ยื่นคำขอยกเลิก"),
  r(" — ผู้จัดการ SOC เป็นผู้อนุมัติ/ปฏิเสธ (เพราะฟอร์มเปิดเคสจะเดินตั๋วต่อทันทีเมื่อบันทึก ตั๋วส่วนใหญ่จึงต้องผ่านการอนุมัติของผู้จัดการ)")]));
push(callout("note", ["เหตุผลมีให้เลือก: รายการซ้ำ / สร้างรายการผิด / เหตุผลอื่น พร้อมคำอธิบายบังคับ (กรณีซ้ำต้องอ้างอิงตั๋วอื่น) คำขอที่ค้างอยู่ไม่หยุดนาฬิกา OLA และไม่เลื่อนสถานะ ผู้ยื่นถอนคำขอเองได้ ตั๋วที่ยกเลิกแล้วไม่ถูกนับในสถิติการปิดงานสำเร็จและ MTTR"]));

push(H2("5.9 แก้ไขข้อมูลเคสหลังบันทึก (เพิ่ม v1.7.0)"));
push(P([r("พิมพ์ IP ผิด ได้ข้อมูลเพิ่มจากผู้ดูแลระบบ หรือต้องเติม IOC ที่เพิ่งพบ — ไม่ต้องเปิดตั๋วใหม่ ให้กดปุ่ม "),
  ui("แก้ไขข้อมูล"), r(" บนหน้ารายละเอียดตั๋ว ระบบจะพาไปหน้า "), r("แก้ไขข้อมูลเคส #<เลขตั๋ว>", { bold: true })]));
push(P("หน้านี้มีสามการ์ด:"));
push(bullet([ui("ข้อมูลเคส"), r(" — ทุกช่องของแบบฟอร์มเดิม รวมถึงหัวข้อ "), ui("Indicators of Compromise (IOC)"), r(" ที่เพิ่ม/ลบค่าได้")]));
push(bullet([r("หลักฐานเฉพาะ Ticket — แนบไฟล์เพิ่มได้ ไฟล์เดิมยังอยู่ครบ ไม่ถูกแทนที่")]));
push(bullet([ui("เหตุผลในการแก้ไข"), r(" — "), r("บังคับกรอก", { bold: true, color: "E63946" }), r(" เช่น “พิมพ์ IP ผิด” หรือ “ได้รับข้อมูลเพิ่มเติมจากผู้ดูแลระบบ”")]));
push(step("s59", [r("กด "), ui("แก้ไขข้อมูล"), r(" บนหน้ารายละเอียดตั๋ว")]));
push(step("s59", [r("แก้เฉพาะช่องที่ต้องแก้ แล้วกรอก "), ui("ระบุเหตุผล"), r(" ให้ชัดเจน")]));
push(step("s59", [r("กด "), ui("บันทึกการแก้ไข"), r(" ระบบจะสรุปให้ว่าแก้ไปกี่รายการ")]));
push(...shot("หน้าแก้ไขข้อมูลเคส แสดงการ์ดข้อมูลเคส หลักฐาน และช่องเหตุผลที่บังคับกรอก", "T1-ticket-edit-form", 5));
push(P([r("ทุกช่องที่เปลี่ยนถูกบันทึกเป็นคู่ "), r("ค่าเดิม → ค่าใหม่", { bold: true }),
  r(" พร้อมชื่อผู้แก้และเวลา ดูย้อนหลังได้ที่หน้ารายละเอียดตั๋ว หัวข้อ "), ui("ประวัติการแก้ไขข้อมูล")]));
push(...shot("หัวข้อประวัติการแก้ไขข้อมูลบนหน้ารายละเอียดตั๋ว แสดงค่าเดิมและค่าใหม่", "T1-edit-history", 5));
push(callout("warn", [
  [r("หน้านี้แก้ได้เฉพาะ ", {}), r("เนื้อหาของเคส", { bold: true }),
   r(" เท่านั้น — ไม่เปลี่ยนสถานะ ไม่เปลี่ยนเส้นทางการมอบหมาย และไม่แตะลายเซ็นผู้ตรวจ (Verified) หรือผู้อนุมัติ หากต้องการย้อนขั้นตอน ต้องให้ผู้จัดการ SOC เป็นผู้ทำ", {})],
  [r("หากตั๋วกำลังรอบทบาทอื่นดำเนินการ จะมีแถบสีเหลืองเตือนว่า “เคสนี้กำลังรอ … ดำเนินการ” — ", {}),
   r("เป็นคำเตือน ไม่ใช่การห้าม", { bold: true }),
   r(" คุณยังแก้ได้ แต่ควรแจ้งผู้รับผิดชอบหลังบันทึก เพราะเขาอาจกำลังทำงานอยู่บนข้อมูลชุดเดิม", {})],
]));
push(spacer(80));
push(callout("note", [
  [r("ข้อจำกัดที่ควรรู้: เคสที่ ", {}), r("ยกเลิกแล้ว", { bold: true }), r(" แก้ไม่ได้เลยไม่ว่าใคร ส่วนเคสที่ ", {}),
   r("ปิดไปแล้ว", { bold: true }), r(" (อนุมัติ / ปิด Event) แก้ได้เฉพาะผู้ดูแลระบบสูงสุดเท่านั้น", {})],
  [r("สิทธิ์ ", {}), r("แนบไฟล์", { bold: true }), r(" แยกจากสิทธิ์แก้ข้อมูล — บางสถานะคุณแก้ข้อความได้แต่แนบไฟล์ไม่ได้ ระบบจะขึ้นข้อความอธิบายแทนช่องแนบไฟล์", {})],
]));

push(H2("5.10 ค้นหา IOC — ค้นอะไรได้บ้าง"));
push(P([r("เมนู "), menuTag("เคส › ค้นหา IOC"), r(" (หัวข้อหน้าจอ: ค้นหา IOC / Ticket) ตอบคำถามเดียว คือ "),
  r("“ค่านี้เคยโผล่ในเคสไหนมาก่อนหรือไม่”", { bold: true }),
  r(" ใช้ก่อนเปิดตั๋วใหม่เพื่อดูว่าเป็นเหตุการณ์ซ้ำหรือเป็นชุดเดียวกับเคสเก่า")]));
push(P("ผลลัพธ์แสดงเป็นสองการ์ดที่แยกหน้ากัน:"));
push(dataTable(
  ["การ์ด", "ค้นจากอะไร"],
  [
    [[r("เคส", { bold: true })], "เลข Ticket, ชื่อระบบ, IP ต้นทาง/ปลายทาง, รายละเอียดเหตุการณ์, MITRE, หมายเลขอ้างอิง, บัญชีผู้ใช้/คำสั่ง และค่าตัวบ่งชี้ทั้ง 6 ประเภทที่กรอกไว้"],
    [[r("บันทึกการคัดกรอง", { bold: true })], "ประวัติการคัดแยก Alert — แหล่งที่มา, IP ต้นทาง, รายละเอียด Alert และบันทึกของผู้คัดแยก"],
  ],
  [3000, 6600],
));
push(spacer(140));
push(callout("tip", [
  [r("วางค่าที่ถอดพิษไว้ เช่น ", {}), r("79[.]124[.]59[.]146", { mono: true }), r(" หรือ ", {}), r("hxxp://", { mono: true }),
   r(" ค้นได้เลย ระบบเทียบให้ทั้งรูปแบบปกติและรูปแบบถอดพิษ", {})],
  [r("ค้นบางส่วนได้ ไม่ต้องพิมพ์เต็ม เช่น พิมพ์เฉพาะต้น IP เพื่อดูทั้งวงเครือข่าย หรือพิมพ์เลขตั๋วบางส่วน", {})],
]));
push(...shot("หน้าค้นหา IOC แสดงผลการค้นหาแยกเป็นการ์ดเคสและการ์ดบันทึกการคัดกรอง", "T1-ioc-search", 5));
push(callout("note", [
  "หน้านี้ค้นจากตั๋วและประวัติการคัดกรองเท่านั้น ไม่ได้ค้นจากฐานข้อมูล IOC (หน้าของทีมพิสูจน์หลักฐาน) และแสดงเฉพาะเคสที่บทบาทของคุณมีสิทธิ์เห็น",
]));

push(H2("5.11 เพิ่มระบบที่ได้รับผลกระทบเข้ากลุ่ม Project Incident (เพิ่ม v1.5.4)"));
push(P([r("เมื่อเปิด Project Incident ไปแล้วแล้วพบว่ามีระบบอื่นถูกกระทบด้วย ไม่ต้องเปิดกลุ่มใหม่ — ที่หน้า Project Incident หัวข้อ "),
  r("Ticket ตามระบบที่ได้รับผลกระทบ", { bold: true }), r(" กดปุ่ม "), ui("เพิ่มระบบที่ได้รับผลกระทบ")]));
push(step("s511", [r("กรอก "), ui("ระบบ / บริการ"), r(" และเลือก "), ui("การตัดสินใจและเส้นทาง"),
  r(" ของระบบนั้น (Event หรือ Incident พร้อมเส้นทาง) — แต่ละระบบเลือกต่างกันได้")]));
push(step("s511", [r("กรอกรายละเอียดเฉพาะระบบเท่าที่มี: IP, ประเภททรัพย์สิน, ระบบปฏิบัติการ, หน่วยงานและชื่อเจ้าของทรัพย์สิน")]));
push(step("s511", [r("กด "), ui("สร้าง Member Ticket"), r(" ระบบจะออกตั๋วใบใหม่ในกลุ่มเดิมให้")]));
push(...shot("แบบฟอร์มเพิ่มระบบที่ได้รับผลกระทบบนหน้า Project Incident", "T1-project-add-member", 5));
push(callout("note", [
  [r("ระบบคัดลอก ", {}), r("ข้อเท็จจริงของเหตุการณ์และตัวบ่งชี้ (IOC)", { bold: true }),
   r(" จากตั๋วใบแรกมาให้อัตโนมัติ และคง ", {}), r("เวลาที่เกิดเหตุเดิม", { bold: true }),
   r(" ไว้ นาฬิกา OLA ของตั๋วใหม่จึงนับจากเวลาเกิดเหตุจริง ไม่ใช่เวลาที่คุณเพิ่งกดเพิ่ม", {})],
  [r("ถ้ากลุ่มผ่าน Project Review ไปแล้ว ตั๋วใหม่ประเภท Incident จะ ", {}),
   r("รับผลการประเมินฉุกเฉินของกลุ่มมาใช้", { bold: true }), r(" และเข้าเลนที่คุณเลือกทันที ไม่ต้องรอผู้จัดการตรวจซ้ำ", {})],
]));
push(spacer(80));
push(callout("warn", [
  "เพิ่มได้เฉพาะผู้เปิด Project Incident หรือผู้จัดการ SOC และเพิ่มได้ไม่เกิน 25 ระบบต่อหนึ่งกลุ่ม — เมื่อทุกตั๋วในกลุ่มปิดหมดแล้ว กลุ่มจะถูกตรึง เพิ่มระบบอีกไม่ได้",
]));

// 6. States relevant to T1
push(H1("6. สถานะที่เกี่ยวข้องกับคุณ"));
push(P("ตารางนี้สรุปเฉพาะสถานะที่ Tier 1 ต้องลงมือทำ สถานะอื่น (เช่น การควบคุมของผู้ดูแลระบบ การตรวจรับของ Tier 2) เป็นงานของบทบาทอื่น"));
push(dataTable(
  ["สถานะ", "หมายถึง", "คุณต้องทำ"],
  [
    [stateName("กำลังจัดเตรียม (ยังไม่ส่ง)", "NEW"), "ตั๋วถูกบันทึกไว้แล้วแต่ยังไม่ส่งเข้ากระบวนการ", [r("เติมข้อมูล/หลักฐานให้ครบ แล้วกด ", {}), r("ส่ง Ticket เข้าสู่กระบวนการ", { bold: true }), r(" (ดู 5.3.2)", {})]],
    [stateName("ส่งต่อให้ Tier 2", "ESCALATED_T2"), "คุณส่งให้ Tier 2 พิจารณา", "รอ Tier 2 — ยังไม่ต้องทำอะไร"],
    [stateName("กำลังเฝ้าระวัง", "MONITORING"), "Tier 2 ให้เฝ้าระวัง 30 วัน (ยังไม่ชี้ขาด)", "เฝ้าติดตาม เมื่อครบกำหนด/มีเหตุ สรุปเป็น Event หรือ Incident (ดู 5.6)"],
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
push(H3("แก้ไขข้อมูลเคสหลังบันทึกไปแล้วได้ไหม?"));
push(P("ได้ ตราบใดที่เคสยังไม่ปิดหรือยกเลิก — กดปุ่ม “แก้ไขข้อมูล” บนหน้ารายละเอียดตั๋ว และต้องระบุเหตุผลทุกครั้ง ระบบบันทึกไว้ว่าใครแก้ช่องใด จากค่าอะไรเป็นอะไร (ดู 5.9)"));
push(H3("ค้นว่า IP หรือค่าแฮชนี้เคยเจอในเคสไหนมาก่อน ทำอย่างไร?"));
push(P("ใช้เมนู “เคส › ค้นหา IOC” ค้นข้ามตั๋วและข้ามประวัติการคัดกรองได้ในที่เดียว (ดู 5.10)"));
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
  const refs = ["s3", "s51", "s52", "s53", "s53b", "s54", "s55", "s56", "s56b", "s58", "s59", "s511"];
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
