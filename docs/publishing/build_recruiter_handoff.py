"""Build the personal PDF using ReportLab; requires the bundled document runtime."""

import hashlib
import json
from pathlib import Path
from xml.sax.saxutils import escape

from recruiter_handoff_content import PAGES, SOURCES
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "output/pdf/SignalBridge_Recruiter_Handoff.pdf"
QA = ROOT / "var/audit/recruiter-handoff"
NAVY = colors.HexColor("#102B43")
TEAL = colors.HexColor("#076A71")
INK = colors.HexColor("#24384B")
MUTED = colors.HexColor("#51677A")
PALE = colors.HexColor("#EFF5F8")
LINE = colors.HexColor("#D3E0E8")
GOLD = colors.HexColor("#BB892F")
WIDTH = 524


def styles():
    fonts = Path("C:/Windows/Fonts")
    for name, file in (
        ("Arial", "arial.ttf"),
        ("Arial-Bold", "arialbd.ttf"),
        ("Arial-Italic", "ariali.ttf"),
        ("Arial-BoldItalic", "arialbi.ttf"),
    ):
        pdfmetrics.registerFont(TTFont(name, str(fonts / file)))
    pdfmetrics.registerFontFamily(
        "Arial",
        normal="Arial",
        bold="Arial-Bold",
        italic="Arial-Italic",
        boldItalic="Arial-BoldItalic",
    )
    base = dict(
        fontName="Arial",
        textColor=INK,
        fontSize=10.8,
        leading=14.5,
        spaceAfter=7,
        allowWidows=0,
        allowOrphans=0,
    )
    return {
        "body": ParagraphStyle("body", **base),
        "lead": ParagraphStyle("lead", **{**base, "fontSize": 14, "leading": 20, "spaceAfter": 15}),
        "title": ParagraphStyle(
            "title",
            **{
                **base,
                "fontName": "Arial-Bold",
                "fontSize": 26,
                "leading": 31,
                "textColor": NAVY,
                "spaceAfter": 13,
            },
        ),
        "h": ParagraphStyle(
            "h",
            **{
                **base,
                "fontName": "Arial-Bold",
                "fontSize": 13,
                "leading": 17,
                "textColor": TEAL,
                "spaceBefore": 6,
                "spaceAfter": 6,
                "keepWithNext": True,
            },
        ),
        "small": ParagraphStyle(
            "small", **{**base, "fontSize": 9, "leading": 12, "textColor": MUTED}
        ),
        "source": ParagraphStyle(
            "source",
            **{**base, "fontSize": 9, "leading": 11.5, "spaceAfter": 4, "textColor": MUTED},
        ),
        "cell": ParagraphStyle(
            "cell", **{**base, "fontSize": 10, "leading": 12.8, "spaceAfter": 0}
        ),
        "th": ParagraphStyle(
            "th",
            **{
                **base,
                "fontName": "Arial-Bold",
                "fontSize": 9.5,
                "leading": 12.5,
                "textColor": colors.white,
                "spaceAfter": 0,
            },
        ),
        "metric": ParagraphStyle(
            "metric",
            fontName="Arial-Bold",
            fontSize=25,
            leading=29,
            textColor=TEAL,
            alignment=TA_CENTER,
        ),
        "metriclabel": ParagraphStyle(
            "metriclabel",
            fontName="Arial",
            fontSize=8.7,
            leading=12,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
        "quote": ParagraphStyle(
            "quote", **{**base, "fontSize": 11.3, "leading": 16, "textColor": NAVY, "spaceAfter": 0}
        ),
    }


class Pipeline(Flowable):
    def __init__(self):
        super().__init__()
        self.width = WIDTH
        self.height = 160

    def draw(self):
        c = self.canv
        boxes = [
            (0, 96, "SOURCE + OUTBOX", "Metadata / signed delivery"),
            (180, 96, "COLLECTOR", "Verify / validate / queue"),
            (360, 96, "WORKER + RULES", "R1 / R2 / R3"),
            (0, 16, "TOOL EVIDENCE", "Wazuh / ZAP / reports"),
            (180, 16, "CASES + ANALYST", "Evidence / decision / audit"),
            (360, 16, "REVIEW + RETEST", "Scoped human decisions"),
        ]
        for x, y, title, sub in boxes:
            c.setFillColor(NAVY if y == 96 else TEAL)
            c.roundRect(x, y, 164, 50, 7, fill=1, stroke=0)
            c.setFillColor(colors.white)
            c.setFont("Arial-Bold", 9.2)
            c.drawCentredString(x + 82, y + 30, title)
            c.setFont("Arial", 8.2)
            c.drawCentredString(x + 82, y + 14, sub)
        c.setStrokeColor(MUTED)
        c.setLineWidth(1.2)
        # The worker and reviewed tool evidence both feed analyst workflows.
        c.line(442, 96, 442, 81)
        c.line(442, 81, 262, 81)
        for x1, y1, x2, y2 in (
            (164, 121, 180, 121),
            (344, 121, 360, 121),
            (262, 81, 262, 66),
            (164, 41, 180, 41),
            (344, 41, 360, 41),
        ):
            c.line(x1, y1, x2, y2)
            if x1 == x2:
                c.line(x2, y2, x2 - 3, y2 + 5)
                c.line(x2, y2, x2 + 3, y2 + 5)
            else:
                direction = 1 if x2 > x1 else -1
                c.line(x2, y2, x2 - direction * 4, y2 + 3)
                c.line(x2, y2, x2 - direction * 4, y2 - 3)


class Handbook(BaseDocTemplate):
    def __init__(self, path):
        super().__init__(
            str(path),
            pagesize=(612, 792),
            leftMargin=44,
            rightMargin=44,
            topMargin=55,
            bottomMargin=43,
            title="SignalBridge - Recruiter Handoff",
            author="Prepared with AI assistance for Aman Agarwal",
            subject="Verified project scope, evidence, limitations and interview study",
        )
        frame = Frame(
            44, 43, WIDTH, 694, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0
        )
        self.addPageTemplates(PageTemplate(id="handbook", frames=frame, onPage=self.decorate))
        self.page_map = []

    def decorate(self, c, doc):
        page = doc.page
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(0, 779, 612, 13, fill=1, stroke=0)
        c.setFont("Arial-Bold", 8.2)
        c.setFillColor(TEAL)
        c.drawString(44, 753, "SIGNALBRIDGE  /  " + PAGES[min(page - 1, len(PAGES) - 1)]["section"])
        c.setStrokeColor(LINE)
        c.line(44, 33, 568, 33)
        c.setFillColor(MUTED)
        c.setFont("Arial", 8)
        c.drawString(44, 20, "PERSONAL HANDOFF  |  September 30, 2026  |  AI-assisted project")
        c.drawRightString(568, 20, f"{page:02d} / {len(PAGES):02d}")
        c.restoreState()

    def afterFlowable(self, item):
        if hasattr(item, "section_index"):
            index = item.section_index
            self.canv.bookmarkPage(f"p{index}")
            self.canv.addOutlineEntry(PAGES[index - 1]["title"], f"p{index}", 0)
            self.page_map.append({"section": index, "page": self.page})


def make_table(headers, rows, st):
    count = len(headers)
    widths = [140, 384] if count == 2 else [102, 214, 208] if count == 3 else [164, 140, 140, 80]
    cells = [[Paragraph(escape(str(v)), st["th"]) for v in headers]]
    cells += [[Paragraph(escape(str(v)), st["cell"]) for v in row] for row in rows]
    t = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PALE, colors.white]),
                ("LINEBELOW", (0, 1), (-1, -1), 0.5, LINE),
            ]
        )
    )
    return [t, Spacer(1, 12)]


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    QA.mkdir(parents=True, exist_ok=True)
    st = styles()
    story = []
    for index, page in enumerate(PAGES, 1):
        if index > 1:
            story.append(PageBreak())
        title = Paragraph(escape(page["title"]), st["title"])
        title.section_index = index
        story.append(title)
        if page.get("subtitle"):
            story.append(Paragraph(escape(page["subtitle"]), st["h"]))
        for kind, content in page["blocks"]:
            if kind in ("p", "lead", "h", "caption"):
                style = {"p": "body", "lead": "lead", "h": "h", "caption": "small"}[kind]
                story.append(Paragraph(content, st[style]))
            elif kind in ("quote", "callout"):
                cell = Paragraph(content, st["quote"] if kind == "quote" else st["body"])
                t = Table([[cell]], colWidths=[WIDTH])
                t.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), PALE),
                            ("LINEBEFORE", (0, 0), (-1, -1), 3, TEAL if kind == "quote" else GOLD),
                            ("LEFTPADDING", (0, 0), (-1, -1), 13),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                            ("TOPPADDING", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ]
                    )
                )
                story += [t, Spacer(1, 11)]
            elif kind == "table":
                story += make_table(*content, st)
            elif kind == "qa":
                q, a = content
                story.append(
                    KeepTogether([Paragraph(escape(q), st["h"]), Paragraph(escape(a), st["body"])])
                )
            elif kind == "diagram":
                story += [Pipeline(), Spacer(1, 8)]
            elif kind == "metrics":
                t = Table(
                    [
                        [Paragraph(escape(v), st["metric"]) for v, _ in content],
                        [Paragraph(escape(v), st["metriclabel"]) for _, v in content],
                    ],
                    colWidths=[WIDTH / 4] * 4,
                )
                t.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), PALE),
                            ("TOPPADDING", (0, 0), (-1, 0), 11),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 10),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ]
                    )
                )
                story += [t, Spacer(1, 12)]
            elif kind == "image":
                im = Image(str(ROOT / content))
                ratio = min(WIDTH / im.imageWidth, 190 / im.imageHeight)
                im.drawWidth, im.drawHeight = im.imageWidth * ratio, im.imageHeight * ratio
                im.hAlign = "LEFT"
                story += [im, Spacer(1, 5)]
            elif kind == "sources":
                for label, title, path in SOURCES:
                    if not (ROOT / path).is_file():
                        raise ValueError("Missing handoff source: " + path)
                    # Portable link: PDF is under output/pdf, repository remains alongside it.
                    url = "../../" + path
                    story.append(
                        Paragraph(
                            f"<b>{escape(label)} | {escape(title)}</b><br/>"
                            f'<link href="{escape(url)}" color="#076A71">{escape(path)}</link>',
                            st["source"],
                        )
                    )
            else:
                raise ValueError(kind)
    document = Handbook(OUTPUT)
    document.build(story)
    expected = [{"section": i, "page": i} for i in range(1, len(PAGES) + 1)]
    (QA / "page-map.json").write_text(json.dumps(document.page_map, indent=2), encoding="utf8")
    if document.page_map != expected or document.page != len(PAGES):
        raise ValueError(f"Layout overflow: {document.page} pages; inspect page-map.json")
    manifest = {
        "date": "2026-09-30",
        "output": OUTPUT.name,
        "pages": document.page,
        "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest(),
        "sources": {
            name: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for name, _, path in SOURCES
        },
    }
    (QA / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"pages": document.page, "pdf": str(OUTPUT), "sha256": manifest["sha256"]}))


if __name__ == "__main__":
    build()
