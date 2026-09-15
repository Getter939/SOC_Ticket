"""Build the Root Cause Analysis (RCA) report DOCX template.

Styled to match the other NT SOC report templates (``report_template_v2`` and
``event_report_template_v1``): the NT logo in every page header, a gold title
banner with a Thai subtitle, light-yellow section bands, gray label columns,
TH Sarabun New body text, and the same gray borders and muted footer. The
palette, fonts and low-level helpers are imported from
``build_report_template_v2`` so the three templates stay in one house style; only
this report's richer structure (multi-column evidence tables) is added on top.

The document is a *template*, filled per request by ``apps.incidents.rca_report``:
  * Section 1 and the page header through ``{{placeholder}}`` substitution;
  * every repeatable table (sections 4, 5, 6.2, 7.x, 8) has a header row plus ONE
    prototype row of ``{{prefix_field}}`` placeholders, cloned once per item.
Narrative sections carry bracketed guidance text for the analyst to replace in
Word — no placeholders, so nothing is filled there.

Layout data (titles, rows, columns, guidance) lives in apps/incidents/rca_content.py.

Run from the repo root:  python scripts/build_rca_report_template_v1.py
"""
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# House style — shared with the Incident (v2) and Event templates so all three
# read as one family.
from scripts.build_report_template_v2 import (  # noqa: E402
    BODY_FONT,
    BODY_PT,
    BORDER,
    GOLD,
    LABEL_GRAY,
    LOGO_PATH,
    MUTED,
    SECTION_YELLOW,
    SYMBOL_FONT,
    TEXT,
    add_runs,
    checkbox_segments,
    clear_table_borders,
    set_cell_margins,
    set_cell_shading,
    set_run_font,
    set_table_borders,
)
from apps.incidents.rca_content import (  # noqa: E402
    RCA_ACCOUNT_COLUMNS,
    RCA_ASSET_COLUMNS,
    RCA_CASE_LABEL,
    RCA_FIGURES,
    RCA_FILE_BEHAVIOR_COLUMNS,
    RCA_FILE_PATH_COLUMNS,
    RCA_FOOTER_LEFT,
    RCA_GUIDANCE,
    RCA_HASH_COLUMNS,
    RCA_HEADER_LEFT,
    RCA_IP_COLUMNS,
    RCA_PRIMARY_ROOT_CAUSE_LABEL,
    RCA_RECOMMENDATION_COLUMNS,
    RCA_ROOT_CAUSE_COLUMNS,
    RCA_SECTION1_ROWS,
    RCA_SECTION_TITLES,
    RCA_SMALL_TEXT_KEYS,
    RCA_SUBSECTION_TITLES,
    RCA_SUBTITLE,
    RCA_TIMELINE_COLUMNS,
    RCA_TITLE,
    RCA_TLP_LABEL,
    RCA_WEB_COLUMNS,
)

TEMPLATES_DIR = BASE_DIR / 'apps' / 'incidents' / 'report_templates'
OUTPUT_PATH = TEMPLATES_DIR / 'rca_report_template_v1.docx'

# Banner heading colour, matching v2's title/section-band text.
BAND_TEXT = '1F2933'
GUIDE = '808080'          # bracketed guidance for the Word-only sections

# Letter, with v2's margins → the same 6.6" content width the other templates use.
CONTENT_IN = 6.6
TABLE_PT = 13            # dense evidence tables read a touch smaller than the 16pt body
SMALL_PT = 11           # long log excerpts / hashes


# ── low-level helpers ──────────────────────────────────────────────────── #

def _first(cell):
    paragraph = cell.paragraphs[0]
    fmt = paragraph.paragraph_format
    fmt.space_before = Pt(0)
    fmt.space_after = Pt(0)
    fmt.line_spacing = 1.0
    return paragraph


def _scale(widths):
    """Scale the content-spec column widths (cm) to the 6.6" content width."""
    total = sum(widths)
    return [value / total * CONTENT_IN for value in widths]


def _set_widths(table, widths_in, *, top_align=False):
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for index, width in enumerate(widths_in):
        table.columns[index].width = Inches(width)
    align = WD_CELL_VERTICAL_ALIGNMENT.TOP if top_align else WD_CELL_VERTICAL_ALIGNMENT.CENTER
    for row in table.rows:
        for index, width in enumerate(widths_in):
            cell = row.cells[index]
            cell.width = Inches(width)
            cell.vertical_alignment = align
            set_cell_margins(cell)


def _single_cell(doc, *, fill=None, border=False):
    table = doc.add_table(rows=1, cols=1)
    _set_widths(table, [CONTENT_IN])
    (set_table_borders if border else clear_table_borders)(table)
    cell = table.rows[0].cells[0]
    if fill:
        set_cell_shading(cell, fill)
    return cell


def _spacer(doc, points=6):
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(0)
    paragraph.paragraph_format.line_spacing = Pt(points)


def _add_field(paragraph, instruction, size, color):
    """Append a Word field (PAGE / NUMPAGES) as begin/instr/separate/result/end runs."""
    def field_run(child):
        run = paragraph.add_run()
        set_run_font(run, size=size, color=color)
        run._r.append(child)

    begin = OxmlElement('w:fldChar')
    begin.set(qn('w:fldCharType'), 'begin')
    field_run(begin)
    instr = OxmlElement('w:instrText')
    instr.set(qn('xml:space'), 'preserve')
    instr.text = f' {instruction} '
    field_run(instr)
    separate = OxmlElement('w:fldChar')
    separate.set(qn('w:fldCharType'), 'separate')
    field_run(separate)
    result = paragraph.add_run('1')
    set_run_font(result, size=size, color=color)
    end = OxmlElement('w:fldChar')
    end.set(qn('w:fldCharType'), 'end')
    field_run(end)


def _repeat_header_row(row):
    row._tr.get_or_add_trPr().append(OxmlElement('w:tblHeader'))


# ── page furniture ─────────────────────────────────────────────────────── #

def style_doc(doc):
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(0.9)
    section.right_margin = Inches(0.9)
    section.bottom_margin = Inches(0.5)
    section.left_margin = Inches(1.0)
    section.header_distance = Inches(0.4)
    section.footer_distance = Inches(0.3)

    normal = doc.styles['Normal']
    normal.font.name = BODY_FONT
    for attr in ('w:ascii', 'w:hAnsi', 'w:cs'):
        normal._element.rPr.rFonts.set(qn(attr), BODY_FONT)
    normal.font.size = Pt(BODY_PT)
    normal.font.color.rgb = RGBColor.from_string(TEXT)
    normal.paragraph_format.space_after = Pt(0)
    normal.paragraph_format.line_spacing = 1.0


def build_header(doc):
    """NT logo (right), matching v2/event, with the case number + TLP marker at
    left so the confidentiality tier travels on every page."""
    header = doc.sections[0].header
    header.is_linked_to_previous = False
    table = header.add_table(rows=1, cols=2, width=Inches(CONTENT_IN))
    clear_table_borders(table)
    _set_widths(table, [4.6, 2.0])
    left, right = table.rows[0].cells
    lp = _first(left)
    add_runs(lp, [
        (RCA_HEADER_LEFT, BODY_FONT, 9.5, MUTED, False),
        ('   ', BODY_FONT, 9.5, MUTED, False),
        ('{{rca_case_no}}', BODY_FONT, 9.5, MUTED, False),
        (f'   {RCA_TLP_LABEL}', BODY_FONT, 9.5, TEXT, True),
    ])
    rp = _first(right)
    rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    if LOGO_PATH.exists():
        rp.add_run().add_picture(str(LOGO_PATH), width=Inches(1.5))
    else:
        add_runs(rp, [('NT', BODY_FONT, 16, TEXT, True)])
    empty = header.paragraphs[0]
    empty._p.getparent().remove(empty._p)


def build_footer(doc):
    """Two-column muted footer, matching v2: confidentiality left, page x/y right."""
    footer = doc.sections[0].footer
    footer.is_linked_to_previous = False
    table = footer.add_table(rows=1, cols=2, width=Inches(CONTENT_IN))
    table.autofit = False
    clear_table_borders(table)
    left, right = table.rows[0].cells
    left.width = Inches(4.6)
    right.width = Inches(2.0)
    add_runs(_first(left), [(RCA_FOOTER_LEFT, BODY_FONT, 10, MUTED, False)])
    rp = _first(right)
    rp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    add_runs(rp, [('หน้า ', BODY_FONT, 10, MUTED, False)])
    _add_field(rp, 'PAGE', 10, MUTED)
    add_runs(rp, [(' / ', BODY_FONT, 10, MUTED, False)])
    _add_field(rp, 'NUMPAGES', 10, MUTED)
    empty = footer.paragraphs[0]
    empty._p.getparent().remove(empty._p)


# ── content blocks ─────────────────────────────────────────────────────── #

def add_title_banner(doc):
    cell = _single_cell(doc, fill=GOLD)
    set_cell_margins(cell, top=140, bottom=140)
    title = _first(cell)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_runs(title, [(RCA_TITLE, BODY_FONT, 22, BAND_TEXT, True)])
    subtitle = cell.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_after = Pt(0)
    add_runs(subtitle, [(RCA_SUBTITLE, BODY_FONT, 15, BAND_TEXT, True)])
    case = doc.add_paragraph()
    case.alignment = WD_ALIGN_PARAGRAPH.CENTER
    case.paragraph_format.space_before = Pt(4)
    add_runs(case, [
        (f'{RCA_CASE_LABEL}  ', BODY_FONT, 14, MUTED, False),
        ('{{rca_case_no}}', BODY_FONT, 15, TEXT, True),
    ])
    _spacer(doc, 6)


def add_section_band(doc, number):
    thai, english = RCA_SECTION_TITLES[number]
    cell = _single_cell(doc, fill=SECTION_YELLOW)
    set_cell_margins(cell, top=70, bottom=70)
    paragraph = _first(cell)
    paragraph.paragraph_format.keep_with_next = True
    add_runs(paragraph, [
        (f'{number}. {thai}', BODY_FONT, 17, BAND_TEXT, True),
        (f'  ({english})', BODY_FONT, 12, BAND_TEXT, False),
    ])
    _spacer(doc, 3)


def add_subheading(doc, number):
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_before = Pt(6)
    paragraph.paragraph_format.space_after = Pt(2)
    paragraph.paragraph_format.keep_with_next = True
    add_runs(paragraph, [(f'{number} {RCA_SUBSECTION_TITLES[number]}', BODY_FONT, BODY_PT, TEXT, True)])


def add_guidance_box(doc, text):
    cell = _single_cell(doc, border=True)
    set_cell_margins(cell, top=60, bottom=60)
    paragraph = _first(cell)
    run = paragraph.add_run(text)
    set_run_font(run, size=BODY_PT, color=GUIDE)
    run.italic = True
    _spacer(doc, 3)


def add_label(doc, text):
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_before = Pt(4)
    paragraph.paragraph_format.keep_with_next = True
    add_runs(paragraph, [(text, BODY_FONT, BODY_PT, TEXT, True)])


def add_section1(doc):
    """Section 1 — the same 2-column gray-label kv table as the other reports."""
    table = doc.add_table(rows=len(RCA_SECTION1_ROWS), cols=2)
    _set_widths(table, [2.3, 4.3])
    set_table_borders(table)
    for index, (kind, label, spec) in enumerate(RCA_SECTION1_ROWS):
        left, right = table.rows[index].cells
        set_cell_shading(left, LABEL_GRAY)
        add_runs(_first(left), [(label, BODY_FONT, BODY_PT, TEXT, True)])
        if kind == 'kv':
            add_runs(_first(right), [(f'{{{{{spec}}}}}', BODY_FONT, BODY_PT, TEXT, False)])
        else:
            add_runs(_first(right), checkbox_segments(spec))
    _spacer(doc, 6)


def add_repeat_table(doc, columns):
    """Header row (repeated on every page) + one prototype row of placeholders.

    Styled like v2's appendix table: a LABEL_GRAY header with bold text and the
    house gray borders. A column whose key is None stays empty for Word.
    """
    table = doc.add_table(rows=2, cols=len(columns))
    _set_widths(table, _scale([width for _title, _key, width in columns]), top_align=True)
    set_table_borders(table)
    header, prototype = table.rows
    _repeat_header_row(header)
    for index, (title, key, _width) in enumerate(columns):
        head_cell = header.cells[index]
        set_cell_shading(head_cell, LABEL_GRAY)
        head_cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        add_runs(_first(head_cell), [(title, BODY_FONT, TABLE_PT, TEXT, True)])
        if key:
            size = SMALL_PT if key in RCA_SMALL_TEXT_KEYS else TABLE_PT
            add_runs(_first(prototype.cells[index]), [(f'{{{{{key}}}}}', BODY_FONT, size, TEXT, False)])
    _spacer(doc, 6)


def add_figure_slot(doc, placeholder, caption):
    cell = _single_cell(doc, border=True)
    set_cell_margins(cell, top=560, bottom=560)
    paragraph = _first(cell)
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run(placeholder)
    set_run_font(run, size=BODY_PT, color=GUIDE)
    run.italic = True
    caption_paragraph = doc.add_paragraph()
    caption_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption_paragraph.paragraph_format.space_after = Pt(6)
    add_runs(caption_paragraph, [(caption, BODY_FONT, 13, TEXT, True)])


# ── document ───────────────────────────────────────────────────────────── #

def build(output_path=OUTPUT_PATH):
    doc = Document()
    style_doc(doc)
    build_header(doc)
    build_footer(doc)
    add_title_banner(doc)

    add_section_band(doc, '1')
    add_section1(doc)

    add_section_band(doc, '2')
    add_guidance_box(doc, RCA_GUIDANCE['2'])
    add_label(doc, RCA_PRIMARY_ROOT_CAUSE_LABEL)
    add_guidance_box(doc, RCA_GUIDANCE['2_primary'])

    add_section_band(doc, '3')
    for placeholder, caption in RCA_FIGURES:
        add_figure_slot(doc, placeholder, caption)

    add_section_band(doc, '4')
    add_repeat_table(doc, RCA_ASSET_COLUMNS)

    add_section_band(doc, '5')
    add_guidance_box(doc, RCA_GUIDANCE['5'])
    add_repeat_table(doc, RCA_TIMELINE_COLUMNS)

    add_section_band(doc, '6')
    add_subheading(doc, '6.1')
    add_guidance_box(doc, RCA_GUIDANCE['6.1'])
    add_subheading(doc, '6.2')
    add_repeat_table(doc, RCA_ROOT_CAUSE_COLUMNS)

    add_section_band(doc, '7')
    add_subheading(doc, '7.1')
    add_repeat_table(doc, RCA_FILE_PATH_COLUMNS)
    add_subheading(doc, '7.2')
    add_repeat_table(doc, RCA_FILE_BEHAVIOR_COLUMNS)
    add_guidance_box(doc, RCA_GUIDANCE['7.2'])
    add_subheading(doc, '7.3')
    add_repeat_table(doc, RCA_IP_COLUMNS)
    add_subheading(doc, '7.4')
    add_repeat_table(doc, RCA_WEB_COLUMNS)
    add_subheading(doc, '7.5')
    add_repeat_table(doc, RCA_HASH_COLUMNS)
    add_subheading(doc, '7.6')
    add_repeat_table(doc, RCA_ACCOUNT_COLUMNS)

    add_section_band(doc, '8')
    add_guidance_box(doc, RCA_GUIDANCE['8'])
    add_repeat_table(doc, RCA_RECOMMENDATION_COLUMNS)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output_path))
    print(output_path)


if __name__ == '__main__':
    build()
