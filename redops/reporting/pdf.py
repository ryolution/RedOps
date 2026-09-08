"""Generate portable PDF reports without HTML execution or remote font/resource loads."""

import json
from datetime import datetime
from typing import Any

from fpdf import FPDF

from redops.core.errors import InputError


class AssessmentPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(160, 45, 45)
        self.cell(0, 10, "RedOps Assessment", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(25, 38, 52)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", size=8)
        self.cell(0, 10, f"RedOps | Page {self.page_no()}", align="C")


def render_pdf(document: dict[str, Any]) -> bytes:
    if len(json.dumps(document).encode("utf-8")) > 2 * 1024 * 1024:
        raise InputError(
            "PDF export is limited to 2 MiB of assessment data; "
            "use JSON or HTML for larger reports."
        )
    pdf = AssessmentPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(16, 14, 16)
    pdf.set_title("RedOps Assessment")
    pdf.set_author("RedOps")
    pdf.set_creation_date(datetime.fromisoformat(document["created_at"]))
    pdf.add_page()

    def paragraph(value: object, *, bold: bool = False) -> None:
        # Core PDF fonts are portable. Unsupported Unicode is represented reversibly,
        # rather than being dropped or fetching a font over the network.
        value = str(value).encode("ascii", errors="backslashreplace").decode("ascii")
        value = "".join(char if char in "\n\t" or ord(char) >= 32 else " " for char in value)
        pdf.set_font("Helvetica", "B" if bold else "", 10)
        pdf.multi_cell(0, 5, value, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    paragraph(document["scope"]["engagement"], bold=True)
    paragraph(
        f"Assessment: {document['id']}\nCreated: {document['created_at']}\n"
        f"Status: {document['status']}"
    )
    for warning in document["warnings"]:
        paragraph(warning)
    paragraph(
        "Non-ASCII text is preserved as Unicode escapes. The JSON report retains original text."
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
    return bytes(pdf.output())
