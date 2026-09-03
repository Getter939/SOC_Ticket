// Shared design system + assembly for the SOC role manuals (Thai)
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  TableOfContents, Header, Footer, PageNumber, ImageRun, LevelFormat,
  PageBreak, VerticalAlign,
} = require("docx");

const NAVY = "1A1A2E", BLUE = "245EA8", RED = "E63946",
      INK = "1F2D3D", MUTED = "6C7888", HAIR = "E1E6ED",
      WHITE = "FFFFFF", SUBTLE = "F7F8FA";
const FONT = "TH Sarabun New";
const MONO = "Consolas";
const LOGO = "C:/Users/NT/Documents/SOC_Ticket/static/Image/S25542658.jpg";

function r(text, o = {}) {
  const opts = { text, size: o.size || 32 };
  if (o.bold) opts.bold = true;
  if (o.italics) opts.italics = true;
  if (o.color) opts.color = o.color;
  if (o.mono) opts.font = MONO;
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
function spacer(h) { return new Paragraph({ spacing: { after: h || 120 }, children: [] }); }
function stateName(th, code) {
  return [r(th, { bold: true, size: 28 }),
          new TextRun({ text: code, break: 1, font: MONO, size: 24, color: MUTED })];
}
function menuTag(t) { return r(t, { bold: true, color: BLUE }); }
function ui(t) { return r(t, { bold: true, color: INK }); }

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
    width: { size: 9600, type: WidthType.DXA }, columnWidths: [9600],
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

const FIGSEC = {};
function shot(caption, shotId, section) {
  FIGSEC[section] = (FIGSEC[section] || 0) + 1;
  const figNo = section + "-" + FIGSEC[section];
  const box = new Table({
    width: { size: 9600, type: WidthType.DXA }, columnWidths: [9600],
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
    width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    borders: { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border },
    rows: [headRow, ...bodyRows],
  });
}

// ── Assemble & write a manual ──
function buildManual(cfg) {
  // cfg: { outPath, roleBandTh, roleEn, headerRight, subtitleTh, body, stepRefs }
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
    new Table({
      width: { size: 9600, type: WidthType.DXA }, columnWidths: [9600],
      borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } },
      rows: [new TableRow({ children: [new TableCell({
        width: { size: 9600, type: WidthType.DXA },
        shading: { type: ShadingType.CLEAR, fill: NAVY, color: "auto" },
        margins: { top: 200, bottom: 200, left: 200, right: 200 },
        children: [
          new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [r("คู่มือสำหรับบทบาท", { color: "AEB8CC", size: 30 })] }),
          new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 }, children: [r(cfg.roleBandTh, { bold: true, color: WHITE, size: 46 })] }),
          new Paragraph({ alignment: AlignmentType.CENTER, children: [r(cfg.roleEn, { color: "D7DEEC", size: 32 })] }),
        ],
      })] })],
    }),
    spacer(360),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
      children: [r("เวอร์ชันระบบ v1.1.0", { color: INK, size: 28 }), r("   ·   ", { color: HAIR, size: 28 }), r("ปรับปรุงล่าสุด 3 กันยายน 2026", { color: INK, size: 28 })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 },
      children: [r("คู่มือฉบับที่ 1.0", { color: MUTED, size: 28 })] }),
    spacer(700),
    new Paragraph({ alignment: AlignmentType.CENTER,
      children: [r("เอกสารใช้ภายในองค์กร — บริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน)", { italics: true, color: MUTED, size: 26 })] }),
    new Paragraph({ children: [new PageBreak()] }),
  ];

  const toc = [
    new Paragraph({ spacing: { after: 160 }, children: [r("สารบัญ", { bold: true, color: NAVY, size: 40 })] }),
    new TableOfContents("สารบัญ", { hyperlink: true, headingStyleRange: "1-2" }),
    new Paragraph({ children: [new PageBreak()] }),
  ];

  const stepConfig = (cfg.stepRefs || []).map((reference) => ({
    reference,
    levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.START,
      style: { run: { bold: true, color: BLUE, font: FONT }, paragraph: { indent: { left: 460, hanging: 300 } } } }],
  }));

  const doc = new Document({
    creator: "NT SOC",
    title: "คู่มือการใช้งาน SOC Support System — " + cfg.roleBandTh,
    styles: {
      default: { document: { run: { font: FONT, size: 32, color: INK }, paragraph: { spacing: { line: 320, lineRule: "auto" } } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 40, bold: true, color: NAVY },
          paragraph: { spacing: { before: 320, after: 140 }, outlineLevel: 0, border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: "D7DEEC", space: 6 } } } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 34, bold: true, color: BLUE }, paragraph: { spacing: { before: 220, after: 100 }, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 32, bold: true, color: INK }, paragraph: { spacing: { before: 160, after: 60 }, outlineLevel: 2 } },
      ],
    },
    numbering: {
      config: [
        { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.START,
          style: { run: { color: BLUE }, paragraph: { indent: { left: 460, hanging: 260 } } } }] },
        ...stepConfig,
      ],
    },
    sections: [
      { properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } }, children: cover },
      {
        properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 }, pageNumbers: { start: 1 } } },
        headers: { default: new Header({ children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: HAIR, space: 4 } },
          tabStops: [{ type: "right", position: 10772 }],
          children: [r("SOC Support System", { color: MUTED, size: 24 }),
            new TextRun({ text: "\t" + cfg.headerRight, font: FONT, size: 24, color: MUTED })] })] }) },
        footers: { default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: HAIR, space: 4 } },
          children: [new TextRun({ text: "หน้า ", font: FONT, size: 24, color: MUTED }),
            new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 24, color: MUTED })] })] }) },
        children: [...toc, ...cfg.body],
      },
    ],
  });

  return Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(cfg.outPath, buf); console.log("Wrote", cfg.outPath, buf.length); });
}

module.exports = { r, P, H1, H2, H3, bullet, step, spacer, stateName, menuTag, ui, callout, shot, dataTable, buildManual,
  colors: { NAVY, BLUE, RED, INK, MUTED } };
