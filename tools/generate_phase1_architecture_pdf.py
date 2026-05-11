from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)


class ArchitectureFigure(Flowable):
    """Draw the Phase 1 architecture figure directly into the PDF."""

    def __init__(self, width: float = 7.0 * inch, height: float = 4.8 * inch) -> None:
        super().__init__()
        self.width = width
        self.height = height
        self.hAlign = "CENTER"

    def wrap(self, avail_width: float, avail_height: float) -> tuple[float, float]:
        return self.width, self.height

    def draw(self) -> None:
        c = self.canv
        x = 0
        y = 0
        w = self.width
        h = self.height

        def box(
            bx: float,
            by: float,
            bw: float,
            bh: float,
            title: str,
            subtitle: str,
            fill_color,
            title_size: int = 10,
            subtitle_size: int = 7,
            dashed: bool = False,
        ) -> None:
            c.saveState()
            if dashed:
                c.setDash(5, 3)
            c.setStrokeColor(colors.HexColor("#1f2937"))
            c.setLineWidth(1)
            c.setFillColor(fill_color)
            c.roundRect(bx, by, bw, bh, 8, stroke=1, fill=1)
            c.setFillColor(colors.HexColor("#111827"))
            c.setFont("Helvetica-Bold", title_size)
            c.drawCentredString(bx + bw / 2, by + bh - 15, title)
            c.setFont("Helvetica", subtitle_size)
            lines = subtitle.split("\n")
            line_y = by + bh - 28
            for line in lines:
                c.drawCentredString(bx + bw / 2, line_y, line)
                line_y -= 10
            c.restoreState()

        def arrow(x1: float, y1: float, x2: float, y2: float, dashed: bool = False) -> None:
            c.saveState()
            c.setStrokeColor(colors.HexColor("#374151"))
            c.setFillColor(colors.HexColor("#374151"))
            c.setLineWidth(1.5)
            if dashed:
                c.setDash(4, 3)
            c.line(x1, y1, x2, y2)
            dx = x2 - x1
            dy = y2 - y1
            if dx == 0 and dy == 0:
                c.restoreState()
                return
            mag = (dx * dx + dy * dy) ** 0.5
            ux = dx / mag
            uy = dy / mag
            ah = 8
            aw = 4
            px = -uy
            py = ux
            tip_x = x2
            tip_y = y2
            left_x = tip_x - ah * ux + aw * px
            left_y = tip_y - ah * uy + aw * py
            right_x = tip_x - ah * ux - aw * px
            right_y = tip_y - ah * uy - aw * py
            c.line(tip_x, tip_y, left_x, left_y)
            c.line(tip_x, tip_y, right_x, right_y)
            c.restoreState()

        def label(text: str, lx: float, ly: float, size: int = 8, fill=colors.HexColor("#6b7280")) -> None:
            c.saveState()
            c.setFont("Helvetica-Oblique", size)
            c.setFillColor(fill)
            c.drawString(lx, ly, text)
            c.restoreState()

        outer_margin = 8
        col_gap = 26
        box_w = (w - (outer_margin * 2) - (col_gap * 2)) / 3
        box_h = 48
        left_x = x + outer_margin
        center_x = left_x + box_w + col_gap
        right_x = center_x + box_w + col_gap
        top_y = y + h - 78
        front_y = top_y - 65
        mid_y = front_y - 65
        lift_y = mid_y - 65
        bottom_y = y + 8

        box(
            left_x,
            top_y,
            box_w,
            box_h,
            "Input Contracts",
            "Soroban WASM fixtures\nor user contracts",
            colors.HexColor("#dbeafe"),
        )
        box(
            center_x,
            top_y,
            box_w,
            box_h,
            "sordec-cli",
            "dump-facts | dump-ir | coverage\nread-only CLI surface",
            colors.HexColor("#dcfce7"),
        )
        box(
            center_x,
            front_y,
            box_w,
            box_h,
            "sordec-frontend",
            "WASM parsing\nSoroban metadata decoding",
            colors.HexColor("#fef3c7"),
        )
        box(
            left_x,
            mid_y,
            box_w,
            box_h,
            "WasmFacts",
            "imports, exports, type map\ncustom sections",
            colors.HexColor("#e0f2fe"),
        )
        box(
            right_x,
            mid_y,
            box_w,
            box_h,
            "SorobanFacts",
            "contractspecv0\ncontractmetav0 / env meta",
            colors.HexColor("#fde68a"),
        )
        box(
            center_x,
            mid_y,
            box_w,
            box_h,
            "sordec-passes",
            "lift_with_waffle\nhost-call catalog",
            colors.HexColor("#ede9fe"),
        )
        box(
            center_x,
            lift_y,
            box_w,
            box_h,
            "LiftedIr",
            "typed CFG / SSA\nfunctions, blocks, values",
            colors.HexColor("#fce7f3"),
        )
        box(
            left_x,
            bottom_y,
            box_w,
            box_h,
            "Phase 1 Outputs",
            "facts JSON | lifted IR text\ncoverage report",
            colors.HexColor("#fee2e2"),
        )
        box(
            right_x,
            bottom_y,
            box_w,
            box_h,
            "Future Phases",
            "HighIr structuring\nWAT + Rust emission",
            colors.HexColor("#f3f4f6"),
            dashed=True,
        )

        arrow(left_x + box_w, top_y + box_h / 2, center_x, top_y + box_h / 2)
        arrow(center_x + box_w / 2, top_y, center_x + box_w / 2, front_y + box_h)
        arrow(center_x, front_y + 4, left_x + box_w / 2, mid_y + box_h)
        arrow(center_x + box_w / 2, front_y, center_x + box_w / 2, mid_y + box_h)
        arrow(center_x + box_w, front_y + 4, right_x + box_w / 2, mid_y + box_h)
        arrow(left_x + box_w, mid_y + box_h / 2, center_x, mid_y + box_h / 2)
        arrow(right_x, mid_y + box_h / 2, center_x + box_w, mid_y + box_h / 2)
        arrow(center_x + box_w / 2, mid_y, center_x + box_w / 2, lift_y + box_h)
        arrow(center_x, lift_y + box_h / 2, left_x + box_w, bottom_y + box_h / 2)
        arrow(center_x + box_w, lift_y + box_h / 2, right_x, bottom_y + box_h / 2, dashed=True)

        label("implemented in Phase 1", center_x + 14, front_y + box_h + 10, size=7)
        label("typed facts", left_x + 20, mid_y + box_h + 8, size=7)
        label("typed metadata", right_x + 14, mid_y + box_h + 8, size=7)
        label("future", right_x + 48, bottom_y + box_h + 8, size=7)

        title = "Phase 1 Component Flow"
        c.setFont("Helvetica-Bold", 13)
        c.setFillColor(colors.HexColor("#111827"))
        title_width = stringWidth(title, "Helvetica-Bold", 13)
        c.drawString((w - title_width) / 2, h - 16, title)


def build_pdf(output_path: Path) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCenter",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#111827"),
        spaceAfter=14,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
        spaceAfter=16,
    )
    h1 = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#111827"),
        spaceBefore=8,
        spaceAfter=8,
    )
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=8,
    )
    bullet = ParagraphStyle(
        "Bullet",
        parent=body,
        leftIndent=14,
        bulletIndent=0,
        spaceBefore=0,
        spaceAfter=6,
    )

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.7 * inch,
        leftMargin=0.7 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Sordec Phase 1 Architecture",
        author="OpenAI Codex",
    )

    story = [
        Paragraph("Sordec Phase 1 Architecture", title_style),
        Paragraph(
            "A component-oriented view of what the repository implements today as the first phase of the Soroban reverse-engineering tool.",
            subtitle_style,
        ),
        ArchitectureFigure(),
        Spacer(1, 0.18 * inch),
        Paragraph("Phase 1 Scope", h1),
        Paragraph(
            "Phase 1 is the foundation and inspection layer of the broader decompiler project. "
            "It does not yet reconstruct source code. Instead, it turns raw Soroban WASM into typed facts, "
            "typed lifted IR, and measurable inspection outputs.",
            body,
        ),
        Paragraph(
            "The three user-visible deliverables are `dump-facts`, `dump-ir`, and `coverage`.",
            body,
        ),
        PageBreak(),
        Paragraph("Primary Components", h1),
        Paragraph(
            "<b>sordec-cli</b>: read-only command surface that executes the implemented pipeline and renders facts, IR, and coverage.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-frontend</b>: parses core WASM structure and decodes Soroban custom sections into typed metadata.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-ir</b>: defines the durable typed boundaries `WasmFacts`, `LiftedIr`, and scaffolded `HighIr`.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-passes</b>: wraps `waffle` for WASM-to-SSA/CFG lifting and ships the Soroban host-call catalog.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-common</b>: shared IDs, arenas, diagnostics, provenance, and unknown-reason tracking.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-driver</b>: future end-to-end orchestrator; in Phase 1 it intentionally stops at the wired front half.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>sordec-backend</b>: placeholder for annotated WAT and compilable Rust emission in later phases.",
            bullet,
            bulletText="•",
        ),
        Paragraph(
            "<b>samples/ and tools/</b>: reproducible real-contract corpus and verification scripts used to prove Phase 1 on real inputs.",
            bullet,
            bulletText="•",
        ),
        Paragraph("Implemented Data Flow", h1),
        Paragraph(
            "A Soroban contract enters through the CLI, is parsed by the frontend into `WasmFacts` and optional `SorobanFacts`, "
            "then lifted by `sordec-passes::lift_with_waffle` into `LiftedIr`. The CLI finally renders either JSON facts, "
            "human-readable IR, or a coverage summary.",
            body,
        ),
        Paragraph("What Is Deliberately Deferred", h1),
        Paragraph(
            "Semantic pattern recovery, control-flow structuring, `HighIr` lowering, annotated WAT emission, and recovered Rust "
            "are all later-phase work. Phase 1 exists to make those later phases possible on top of a verified typed foundation.",
            body,
        ),
    ]

    def draw_page(canvas, document) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d1d5db"))
        canvas.line(document.leftMargin, letter[1] - 0.5 * inch, letter[0] - document.rightMargin, letter[1] - 0.5 * inch)
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(document.leftMargin, 0.38 * inch, "Sordec Phase 1 Architecture")
        canvas.drawRightString(letter[0] - document.rightMargin, 0.38 * inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)


if __name__ == "__main__":
    output = Path("/Users/mobasuony/Desktop/Sordec-Phase1-Architecture.pdf")
    build_pdf(output)
    print(output)
