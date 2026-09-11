const { r, P, H1, H2, H3, bullet, step, spacer, stateName, menuTag, ui, callout, shot, resetFigures, dataTable, buildManual } = require("./common");

// Shared body for a response-team role. `who` = short id used in SHOT ids.
//
// The two personas are NOT interchangeable on visibility: since v1.3.1 the
// Forensic Analyst reads every ticket (read-only) so indicators can be
// correlated across incidents, while the Red Team Manager still sees only the
// tickets carrying a request assigned to them. `readsAllTickets` forks that
// text — and gives the Forensic Analyst the IOC Database section, which is
// their page alone. Section numbers are counted, not hardcoded, so an
// role-specific section does not renumber the rest by hand.
function responseTeamBody({ roleTh, intro, requestTable, who, readsAllTickets }) {
  resetFigures();   // two manuals are built in one process — see common.js
  const body = [];
  const push = (...x) => x.forEach((e) => body.push(e));
  let sec = 0;
  const SH = (t) => { sec += 1; return H1(sec + ". " + t); };

  push(SH("เกี่ยวกับคู่มือฉบับนี้"));
  push(P([r("คู่มือฉบับนี้จัดทำขึ้นสำหรับ "), r(roleTh, { bold: true }),
    r(" ซึ่งเป็นทีมตอบสนองนอกศูนย์ SOC รับเฉพาะ ", {}), r("คำขอทีมตอบสนอง (Response Request)", { bold: true }), r(" ที่ผู้จัดการ SOC มอบหมายให้")]));
  push(P(intro));
  push(H2("สัญลักษณ์ที่ใช้ในคู่มือ"));
  push(callout("note", ["กล่องสีเทา — ข้อเท็จจริงสำคัญที่ควรจำ"]));
  push(spacer(80));
  push(callout("tip", ["กล่องสีน้ำเงิน — เคล็ดลับหรือคำแนะนำ"]));

  push(SH("บทบาทของคุณโดยย่อ"));
  if (readsAllTickets) {
    push(P("งานของคุณดำเนิน คู่ขนาน กับงานควบคุมของทีม SOC ไม่ได้หยุดรอกัน คุณมีหน้าที่ดำเนินการตามคำขอที่ได้รับมอบหมาย แล้วอัปเดตสถานะและผลการดำเนินการกลับเข้าระบบ"));
    push(P([r("คุณ "), r("อ่านตั๋วได้ทุกใบในระบบ", { bold: true }),
      r(" เพื่อเชื่อมโยงตัวบ่งชี้และหลักฐานข้ามเหตุการณ์ได้ แต่เป็นสิทธิ์ "), r("อ่านอย่างเดียว", { bold: true }),
      r(" — ช่องทางเดียวที่คุณเขียนข้อมูลลงตั๋วได้คือผลการดำเนินการในคำขอที่มอบหมายให้คุณ และบันทึก/สถานะการตรวจสอบใน "), menuTag("IOC Database")]));
  } else {
    push(P("งานของคุณดำเนิน คู่ขนาน กับงานควบคุมของทีม SOC ไม่ได้หยุดรอกัน คุณจะเห็นเฉพาะตั๋วที่มีคำขอมอบหมายให้คุณ และมีหน้าที่ดำเนินการตามคำขอแล้วอัปเดตสถานะและผลการดำเนินการกลับเข้าระบบ"));
  }
  push(H2("ประเภทคำขอที่คุณรับผิดชอบ"));
  push(dataTable(["ประเภทคำขอ", "คำอธิบาย"], requestTable, [4200, 5400]));
  push(spacer(140));
  push(callout("warn", [
    "ตราบใดที่คำขอของคุณยังไม่เสร็จสิ้น ตั๋วต้นเรื่องจะปิด (อนุมัติ) ไม่ได้ ดังนั้นการอัปเดตสถานะให้เป็นปัจจุบันจึงสำคัญต่อการปิดงานของทั้งกระบวนการ",
  ]));

  push(SH("การเข้าสู่ระบบ"));
  push(step("s3", "เปิดเว็บเบราว์เซอร์ แล้วไปยังที่อยู่ของระบบที่ทีม SOC แจ้ง"));
  push(step("s3", [r("กรอก "), ui("ชื่อผู้ใช้ (Username)"), r(" และ "), ui("รหัสผ่าน (Password)"), r(" แล้วกดเข้าสู่ระบบ")]));
  push(...shot("หน้าเข้าสู่ระบบ", who + "-login", sec));
  push(callout("note", ["บัญชีสร้างและกำหนดบทบาทโดยผู้ดูแลระบบ SOC หากบัญชีถูกล็อก (ผิดเกิน 5 ครั้ง) ให้ติดต่อทีม SOC"]));

  push(SH("หน้าจอของคุณ"));
  push(P([r("เมนูหลักของคุณคือ "), menuTag("Work Queues › Response Requests"), r(" (หัวข้อหน้าจอ: งานตอบสนอง) ซึ่งแสดงเฉพาะคำขอที่มอบหมายให้คุณ พร้อมตัวกรองตามสถานะ")]));
  push(...shot("หน้างานตอบสนอง (Response Requests) แสดงคำขอที่มอบหมายให้คุณ", who + "-queue", sec));
  if (readsAllTickets) {
    push(P("นอกจากคิวงานของคุณแล้ว คุณยังเปิดเมนูเหล่านี้ได้ด้วย:"));
    push(bullet([menuTag("Tickets › Active Tickets / History"), r(" — อ่านตั๋วทุกใบ (อ่านอย่างเดียว: ไม่มีปุ่มแก้ไข เปลี่ยนสถานะ แนบไฟล์ หรือออกรายงาน)")]));
    push(bullet([menuTag("Tickets › IOC Database"), r(" — แหล่งรวมตัวบ่งชี้ทั้งหมด เป็นหน้าเฉพาะของบทบาทคุณ (ดูหัวข้อถัดไป)")]));
    push(bullet([menuTag("Tickets › IOC Search"), r(" — ค้นหาตัวบ่งชี้ข้ามตั๋วและข้ามคิวคัดกรอง Wazuh")]));
    push(callout("note", [
      [r("เพิ่ม v1.5.0: ", { bold: true }), r("เมื่อเปิดตั๋วเพื่ออ่านหลักฐาน ไฟล์แนบที่เป็นรูปภาพและข้อความ/log/CSV มีลิงก์ ", {}),
       ui("ดูตัวอย่าง"), r(" เปิดดูในแท็บใหม่ได้โดยไม่ต้องดาวน์โหลด (ผ่านการตรวจสิทธิ์เสมอ)", {})],
    ]));
  }

  push(SH("การทำงานกับคำขอ"));
  push(P("แต่ละคำขอผูกกับตั๋วต้นเรื่อง การดำเนินงานทั้งหมดทำในหน้ารายละเอียดตั๋ว หัวข้อ “งานย่อยและคำขอทีมตอบสนอง”"));
  push(step("s51", [r("ที่ "), menuTag("Response Requests"), r(" กด "), ui("เปิดคำขอ"), r(" เพื่อไปยังหน้ารายละเอียดตั๋ว (ส่วนงานย่อย)")]));
  push(step("s51", [r("เมื่อเริ่มลงมือ เปลี่ยนสถานะเป็น "), ui("กำลังดำเนินการ")]));
  push(step("s51", [r("กรอก "), ui("ผลการดำเนินการ"), r(" และ "), ui("แนบไฟล์ผล (ถ้ามี)"), r(" แล้วกดบันทึก")]));
  push(step("s51", [r("เมื่อเสร็จ เปลี่ยนสถานะเป็น "), ui("เสร็จสิ้น"), r(" ระบบจะแจ้งผู้จัดการ SOC โดยอัตโนมัติ")]));
  push(...shot("แบบฟอร์มอัปเดตคำขอ: สถานะ ผลการดำเนินการ และการแนบไฟล์ผล", who + "-update", sec));
  push(callout("tip", [
    [r("สถานะของคำขอมี 3 ระดับ: ", {}), r("เปิด", { bold: true }), r(" → ", {}), r("กำลังดำเนินการ", { bold: true }), r(" → ", {}), r("เสร็จสิ้น", { bold: true }), r(" แนบไฟล์ผลเพื่อให้ทีม SOC ใช้อ้างอิงประกอบการปิดงาน", {})],
  ]));

  // ── Forensic Analyst only: the IOC Database (v1.3.0) ──
  if (readsAllTickets) {
    push(SH("ฐานข้อมูล IOC (IOC Database)"));
    push(P([r("เมนู "), menuTag("Tickets › IOC Database"),
      r(" คือแหล่งรวมตัวบ่งชี้การบุกรุกของทั้งระบบ เปิดได้เฉพาะบทบาทของคุณ หน้านี้รวมตัวบ่งชี้จาก "),
      r("สองแหล่ง", { bold: true }), r(" เข้าเป็นรายการเดียวกันโดยยึด “ประเภท + ค่า” เป็นตัวจับคู่:")]));
    push(bullet([r("Source ", {}), r("Ticket", { bold: true }), r(" — ตัวบ่งชี้ที่ Tier 1 / Tier 2 กรอกไว้บนตั๋ว")]));
    push(bullet([r("Source ", {}), r("Manual", { bold: true }), r(" — ตัวบ่งชี้ที่คุณค้นพบเองจากภายนอกแล้วบันทึกเข้ามา")]));
    push(P("ถ้าค่าเดียวกันมาจากทั้งสองแหล่ง จะยังเป็นแถวเดียว แต่แสดงที่มาทั้งสอง"));

    push(H2("อ่านตารางและกรองข้อมูล"));
    push(dataTable(
      ["คอลัมน์", "ความหมาย"],
      [
        ["Category", "ประเภทตัวบ่งชี้ (File Name, Hash, Domain, IP Address, URL, File Path)"],
        ["Indicator", "ค่าของตัวบ่งชี้"],
        ["Note", "บันทึกของคุณ — กดไอคอนดินสอเพื่อแก้ไขได้ทุกแถว"],
        ["Status", [r("Checked", { bold: true }), r(" / ", {}), r("Not Checked", { bold: true }), r(" — สลับได้ทันทีเมื่อคุณตรวจค่านั้นกับ MISP แล้ว", {})]],
        ["Source", "Ticket / Manual หรือทั้งสอง"],
        ["On tickets", "จำนวนตั๋วที่พบตัวบ่งชี้นี้"],
        ["Last activity", "ความเคลื่อนไหวล่าสุดของตัวบ่งชี้"],
      ],
      [2600, 7000],
    ));
    push(spacer(140));
    push(P([r("แถบด้านบนมีตัวกรอง "), ui("ค้นหา / Search"), r(" (ค้นได้ทั้งค่า รหัส และบันทึก), "),
      ui("สถานะ / Status"), r(", "), ui("แหล่งที่มา / Source"), r(" และ "), ui("ประเภท / Category"),
      r(" — กด "), ui("กรอง"), r(" เพื่อใช้งาน และ "), r("กดหัวคอลัมน์", { bold: true }), r(" เพื่อเรียงลำดับได้ทุกคอลัมน์")]));
    push(...shot("หน้า IOC Database: แถบตัวกรอง ตารางตัวบ่งชี้ พร้อมคอลัมน์ Status และ Source", "FOR-ioc-database", sec));

    push(H2("บันทึกผลการตรวจสอบ"));
    push(P("สองช่องนี้เป็นของคุณ และแก้ไขได้ทุกแถว รวมถึงแถวที่มาจากตั๋วของทีม SOC ด้วย"));
    push(step("s6i", [r("ที่คอลัมน์ "), ui("Status"), r(" กดสลับเป็น "), ui("Checked"), r(" เมื่อคุณตรวจตัวบ่งชี้นั้นกับ MISP เรียบร้อยแล้ว")]));
    push(step("s6i", [r("ที่คอลัมน์ "), ui("Note"), r(" กดไอคอนดินสอเพื่อบันทึกสิ่งที่พบ แล้วกด "), ui("บันทึก / Save")]));

    push(H2("เพิ่มตัวบ่งชี้ที่คุณค้นพบเอง"));
    push(step("s6i", [r("กด "), ui("เพิ่ม IOC เอง / Add IOC manually"), r(" ที่ด้านบนของหน้า")]));
    push(step("s6i", [r("กรอกทีละแถว: "), ui("Category"), r(", "), ui("IOC detail"), r(" (ค่าของตัวบ่งชี้) และ "), ui("Note"),
      r(" — ช่อง "), ui("File name"), r(" จะปรากฏเฉพาะเมื่อเลือกประเภท Hash")]));
    push(step("s6i", [r("ต้องการเพิ่มหลายค่าพร้อมกัน กด "), ui("เพิ่มแถว / Add row"), r(" ได้เรื่อย ๆ ต่างประเภทกันในครั้งเดียวก็ได้")]));
    push(step("s6i", [r("กด "), ui("บันทึก / Save"), r(" ระบบจะออกรหัสอ้างอิงให้อัตโนมัติในรูปแบบ "), r("MAN-####", { mono: true })]));
    push(...shot("แบบฟอร์มเพิ่ม IOC เอง แสดงหลายแถวและช่อง File name ที่ปรากฏเมื่อเลือก Hash", "FOR-ioc-manual-add", sec));
    push(callout("note", [
      "ระบบไม่ยอมให้มีค่าซ้ำ: ถ้าค่าที่คุณกรอกมีอยู่แล้วไม่ว่าจะมาจากตั๋วหรือจากการบันทึกเอง ระบบจะไม่สร้างรายการใหม่ และถ้าค่านั้นเคยถูกลบไป การกรอกซ้ำจะกู้รายการเดิมกลับมาพร้อมบันทึกเดิม",
    ]));
    push(spacer(80));
    push(P([r("แถวที่คุณบันทึกเองแก้ไขได้ในหน้าเดียวกัน (ไอคอนดินสอ) หรือลบออกได้ (ไอคอนถังขยะ) ส่วนแถวที่มาจากตั๋วจะแก้ได้เฉพาะ "),
      ui("Status"), r(" และ "), ui("Note"), r(" เท่านั้น เพราะค่าตัวบ่งชี้เป็นของตั๋วต้นเรื่อง")]));
  }

  push(SH("สถานะของคำขอ"));
  push(dataTable(
    ["สถานะคำขอ", "หมายถึง", "คุณต้องทำ"],
    [
      [stateName("เปิด", "OPEN"), "คำขอใหม่ที่มอบหมายให้คุณ", "เริ่มดำเนินการ แล้วเปลี่ยนเป็น “กำลังดำเนินการ”"],
      [stateName("กำลังดำเนินการ", "IN_PROGRESS"), "คุณกำลังดำเนินการ", "บันทึกผลระหว่างทาง แล้วปิดท้ายด้วย “เสร็จสิ้น”"],
      [stateName("เสร็จสิ้น", "DONE"), "ดำเนินการครบแล้ว", "ไม่มี — ระบบแจ้งผู้จัดการ SOC ให้อัตโนมัติ"],
    ],
    [2600, 3400, 3600],
  ));

  push(SH("การแจ้งเตือนทางอีเมล"));
  push(dataTable(
    ["เหตุการณ์", "ผู้รับ"],
    [
      ["มีคำขอทีมตอบสนองใหม่มอบหมายให้คุณ", [r("ทีมของคุณ ", { bold: true })]],
      ["คุณทำเครื่องหมายคำขอเป็น “เสร็จสิ้น”", "ผู้จัดการ SOC ผู้ออกคำขอ"],
    ],
    [6000, 3600],
  ));

  push(SH("คำถามที่พบบ่อย"));
  if (readsAllTickets) {
    push(H3("ฉันเปิดดูตั๋วใบไหนได้บ้าง?"));
    push(P("ทุกใบ — เพื่อให้เชื่อมโยงตัวบ่งชี้ข้ามเหตุการณ์ได้ แต่เป็นการอ่านอย่างเดียวทั้งหมด"));
    push(H3("ทำไมฉันไม่เห็นปุ่มแก้ไขหรือเปลี่ยนสถานะบนตั๋ว?"));
    push(P("สิทธิ์เขียนของคุณจำกัดไว้ที่ผลการดำเนินการในคำขอของคุณ และช่อง Status/Note ใน IOC Database เท่านั้น"));
  } else {
    push(H3("ทำไมฉันเห็นตั๋วเฉพาะบางใบ?"));
    push(P("ระบบแสดงเฉพาะตั๋วที่มีคำขอมอบหมายให้คุณเท่านั้น"));
  }
  push(H3("ฉันจัดประเภทหรือปิดตั๋วต้นเรื่องได้ไหม?"));
  push(P("ไม่ได้ — คุณดำเนินการได้เฉพาะคำขอของคุณ การปิดตั๋วต้นเรื่องเป็นหน้าที่ของทีม SOC"));
  push(H3("ลืมรหัสผ่าน / บัญชีถูกล็อก?"));
  push(P("ติดต่อทีม SOC เพื่อรีเซ็ตหรือปลดล็อก"));

  push(SH("อภิธานศัพท์"));
  const glossary = [
    [[r("คำขอทีมตอบสนอง (Response Request)", { bold: true })], "งานเฉพาะทางที่ผู้จัดการ SOC ส่งให้ทีมนอก SOC ทำคู่ขนานกับงานควบคุม"],
    [[r("งานคู่ขนาน", { bold: true })], "งานที่ดำเนินไปพร้อมกับงานควบคุม ไม่หยุดรอกัน"],
    [[r("ตั๋วต้นเรื่อง (Ticket)", { bold: true })], "เหตุการณ์ที่คำขอของคุณผูกอยู่"],
  ];
  if (readsAllTickets) {
    glossary.push(
      [[r("IOC (Indicator of Compromise)", { bold: true })], "ตัวบ่งชี้การบุกรุก เช่น ค่าแฮช โดเมน IP URL ชื่อไฟล์ หรือเส้นทางไฟล์"],
      [[r("IOC Database", { bold: true })], "หน้ารวมตัวบ่งชี้จากตั๋วและจากที่คุณบันทึกเอง พร้อมสถานะการตรวจสอบและบันทึกของคุณ"],
      [[r("MAN-####", { bold: true })], "รหัสอ้างอิงที่ระบบออกให้ตัวบ่งชี้ที่บันทึกเข้ามาเอง"],
    );
  }
  push(dataTable(["คำ", "ความหมาย"], glossary, [3600, 6000]));

  return body;
}

// ── Forensic Analyst ──
buildManual({
  outPath: "C:/Users/NT/Documents/SOC_Ticket/docs/user-guides/manuals/user-manual-forensic-analyst.th.docx",
  roleBandTh: "ผู้เชี่ยวชาญพิสูจน์หลักฐาน",
  roleEn: "Forensic Analyst",
  headerRight: "คู่มือผู้เชี่ยวชาญพิสูจน์หลักฐาน",
  stepRefs: ["s3", "s51", "s6i"],
  body: responseTeamBody({
    roleTh: "ผู้เชี่ยวชาญพิสูจน์หลักฐาน (Forensic Analyst)",
    who: "FOR",
    readsAllTickets: true,
    intro: "งานของคุณเน้นการพิสูจน์หลักฐานดิจิทัลและการวิเคราะห์สาเหตุที่แท้จริง (Root Cause Analysis) ของเหตุการณ์ และเป็นผู้ดูแลฐานข้อมูลตัวบ่งชี้การบุกรุก (IOC Database) ของระบบ",
    requestTable: [
      ["Forensics / RCA", "พิสูจน์หลักฐานดิจิทัล และวิเคราะห์สาเหตุที่แท้จริงของเหตุการณ์"],
    ],
  }),
});

// ── Red Team Manager ──
buildManual({
  outPath: "C:/Users/NT/Documents/SOC_Ticket/docs/user-guides/manuals/user-manual-redteam-manager.th.docx",
  roleBandTh: "ผู้จัดการทีมทดสอบเจาะระบบ",
  roleEn: "Red Team Manager",
  headerRight: "คู่มือผู้จัดการทีมทดสอบเจาะระบบ",
  stepRefs: ["s3", "s51"],
  body: responseTeamBody({
    roleTh: "ผู้จัดการทีมทดสอบเจาะระบบ (Red Team Manager)",
    who: "RED",
    readsAllTickets: false,
    intro: "งานของคุณเน้นการตรวจสอบช่องโหว่ การทดสอบเจาะระบบ และความมั่นคงปลอดภัยของโครงสร้างพื้นฐาน",
    requestTable: [
      ["VA / Pentest", "ตรวจสอบช่องโหว่และทดสอบเจาะระบบ"],
      ["Infrastructure Security", "ตรวจสอบและเสริมความมั่นคงปลอดภัยของโครงสร้างพื้นฐาน"],
    ],
  }),
});
