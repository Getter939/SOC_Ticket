"""Guard Thai/Latin font-size parity in the shipped and rebuilt DOCX forms."""
import tempfile
from pathlib import Path
from unittest import TestCase

from docx import Document
from docx.oxml.ns import qn

from scripts import build_event_report_template_v1 as event
from scripts import build_report_template_v2 as incident


class ReportTypographyTest(TestCase):
    def assert_script_sizes_match(self, doc):
        # Word uses szCs for Thai; python-docx's font.size reads only sz.
        normal = doc.styles['Normal']._element.rPr
        self.assertIsNotNone(normal.find(qn('w:szCs')))
        self.assertEqual(
            normal.find(qn('w:szCs')).get(qn('w:val')),
            normal.find(qn('w:sz')).get(qn('w:val')),
        )
        parts = [doc.element]
        for section in doc.sections:
            parts.extend([section.header._element, section.footer._element])
        for part in parts:
            for run in part.xpath('.//w:r[w:t]'):
                text = ''.join(run.xpath('./w:t/text()'))
                with self.subTest(text=text[:60]):
                    latin = run.xpath('./w:rPr/w:sz/@w:val')
                    thai = run.xpath('./w:rPr/w:szCs/@w:val')
                    self.assertTrue(latin, 'Text must declare its intended size')
                    self.assertEqual(thai, latin)

    def test_committed_templates_use_matching_script_sizes(self):
        for builder in (incident, event):
            with self.subTest(template=builder.OUTPUT_PATH.name):
                self.assert_script_sizes_match(Document(builder.OUTPUT_PATH))

    def test_rebuilt_templates_use_matching_script_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for builder in (incident, event):
                with self.subTest(template=builder.OUTPUT_PATH.name):
                    path = Path(tmp) / builder.OUTPUT_PATH.name
                    builder.build(path)
                    self.assert_script_sizes_match(Document(path))
