"""Generate portable PDF reports without HTML execution or remote font/resource loads."""

import json
import logging
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from fontTools.ttLib import TTFont
from fpdf import FPDF

from redops.core.errors import InputError
from redops.core.reviews import finding_key
from redops.reporting.document import review_by_key

FONTS = Path(__file__).resolve().parent / "fonts"
logger = logging.getLogger(__name__)


@lru_cache(maxsize=2)
def supported_characters(bold: bool) -> frozenset[int]:
    with TTFont(FONTS / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")) as font:
        return frozenset(font.getBestCmap())


def font_text(value: object, *, bold: bool = False) -> str:
    """Keep supported glyphs; represent unsupported/control characters reversibly."""
    supported = supported_characters(bold)
    return "".join(
        char
        if char == "\n" or ord(char) in supported and ord(char) >= 32
        else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


class AssessmentPDF(FPDF):
    def header(self) -> None:
        self.set_font("DejaVu", "B", 15)
        self.set_text_color(160, 45, 45)
        self.cell(0, 10, "RedOps Assessment", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(25, 38, 52)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("DejaVu", size=8)
        self.cell(0, 10, f"RedOps | Page {self.page_no()}", align="C")


def render_pdf(document: dict[str, Any]) -> bytes:
    if len(json.dumps(document).encode("utf-8")) > 2 * 1024 * 1024:
        raise InputError(
            "PDF export is limited to 2 MiB of assessment data; "
            "use JSON or HTML for larger reports."
        )
    pdf = AssessmentPDF()
    for style, filename in (("", "DejaVuSans.ttf"), ("B", "DejaVuSans-Bold.ttf")):
        pdf.add_font("DejaVu", style, FONTS / filename)
    pdf.set_text_shaping(True)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 14, 16)
    pdf.set_title("RedOps Assessment")
    pdf.set_author("RedOps")
    pdf.set_creation_date(datetime.fromisoformat(document["created_at"]))
    pdf.add_page()

    def paragraph(value: object, *, bold: bool = False) -> None:
        pdf.set_font("DejaVu", "B" if bold else "", 10)
        pdf.multi_cell(0, 5, font_text(value, bold=bold), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    paragraph(document["scope"]["engagement"], bold=True)
    paragraph(
        f"Assessment: {document['id']}\nCreated: {document['created_at']}\n"
        f"Status: {document['status']}"
    )
    for warning in document["warnings"]:
        paragraph(warning)
    paragraph(
        "Glyphs unavailable in the bundled font appear as explicit Unicode escapes. "
        "The JSON report retains original text."
    )
    counts = Counter(finding["severity"] for finding in document["findings"])
    coverage = document["coverage"]
    paragraph(
        f"{len(document['hosts'])} hosts | {coverage['services_total']} open services | "
        f"{len(document['findings'])} candidate findings\n"
        + " | ".join(
            f"{level}: {counts[level]}"
            for level in ("critical", "high", "medium", "low", "none", "unknown")
        )
    )
    paragraph(f"{coverage['services_with_supported_cpe']} services with a supported versioned CPE.")
    reviews = review_by_key(document)
    if "review_export" in document:
        export = document["review_export"]
        paragraph("Operator review annotations", bold=True)
        paragraph(
            f"Review revision: {export['revision']}\nExported: {export['exported_at']}\n"
            f"{export['interpretation']}"
        )
    paragraph("Inventory", bold=True)
    for host in document["hosts"]:
        paragraph(
            f"{host['ip']} | {host['hostname']} | OS observation: {host['os'] or 'unknown'}",
            bold=True,
        )
        if not host["services"]:
            paragraph("No open services recorded.")
        for service in host["services"]:
            paragraph(
                f"{service['port']['number']}/{service['port']['protocol']}: "
                f"{service['name']} | {service['product']} {service['version']}\n"
                f"CPE observations: {', '.join(service['cpes']) or 'none'}"
            )
    paragraph("Candidate findings and remediation", bold=True)
    if not document["findings"]:
        paragraph(
            "No candidates found in this catalog. This does not establish that services are secure."
        )
    for finding in document["findings"]:
        paragraph(
            f"{finding['vulnerability_id']} | {finding['severity'].upper()} | "
            f"{finding['host']}:{finding['port']}/{finding['protocol']}",
            bold=True,
        )
        for label, field in (
            ("CVSS", "cvss"),
            ("Status", "status"),
            ("Description", "description"),
            ("Remediation", "remediation"),
            ("Source", "source"),
        ):
            paragraph(f"{label}: {finding[field]}")
        paragraph("Matched CPEs: " + ", ".join(finding["matched_cpes"]))
        annotation = reviews.get(finding_key(document["id"], finding))
        if annotation:
            paragraph(f"Operator disposition: {annotation['disposition']}")
            review = annotation["review"]
            if review:
                paragraph(
                    f"Review {review['id']} | {review['operator']} | {review['timestamp']}\n"
                    f"{review['notes']}"
                )
            else:
                paragraph("No operator decision recorded.")
    if document.get("advisories"):
        paragraph("NVD advisory context", bold=True)
        paragraph(
            "Advisories do not confirm applicability. "
            "Finding scores retain the reviewed catalog values."
        )
        for advisory in document["advisories"]:
            paragraph(f"{advisory['cve_id']} | {advisory['status']}", bold=True)
            paragraph(advisory["description"])
            paragraph(
                f"CVSS: {advisory['cvss']} ({advisory['cvss_version']})\n"
                f"Provider: {advisory['provider']}\nRetrieved: {advisory['retrieved_at']}"
            )
    paragraph("Provenance", bold=True)
    for key, value in document["provenance"].items():
        paragraph(f"{key}: {value}")
    result = bytes(pdf.output())
    logger.info("Generated PDF with %d pages", pdf.page_no())
    return result
