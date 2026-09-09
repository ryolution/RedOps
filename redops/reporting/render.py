"""Self-contained output; every observed value is escaped before HTML rendering."""

import json
import logging
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from redops.core.io import atomic_write
from redops.core.reviews import finding_key
from redops.reporting.document import review_by_key
from redops.reporting.pdf import render_pdf

logger = logging.getLogger(__name__)


def render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"


def render_html(document: dict[str, Any]) -> str:
    def text(value: object) -> str:
        return escape(str(value), quote=True)

    reviews = review_by_key(document)

    def decision(item: dict[str, Any]) -> str:
        annotation = reviews.get(finding_key(document["id"], item))
        if annotation is None:
            return ""
        result = f"<p><strong>Operator disposition:</strong> {text(annotation['disposition'])}</p>"
        review = annotation["review"]
        if review:
            result += (
                f"<p>Review {review['id']} · {text(review['operator'])} · "
                f"{text(review['timestamp'])}</p><p>{text(review['notes'])}</p>"
            )
        else:
            result += "<p>No operator decision recorded.</p>"
        return result

    review_notice = ""
    if "review_export" in document:
        export = document["review_export"]
        review_notice = (
            f"<h2>Operator review annotations</h2><p>Review revision: {export['revision']} · "
            f"Exported: {text(export['exported_at'])}</p>"
            f"<p>{text(export['interpretation'])}</p>"
        )

    counts = Counter(finding["severity"] for finding in document["findings"])
    cards = "".join(
        f'<div class="card"><strong>{counts[level]}</strong><span>{level.title()}</span></div>'
        for level in ("critical", "high", "medium", "low", "none", "unknown")
    )
    inventory = "".join(
        "<tr>"
        + "".join(
            f"<td>{text(value)}</td>"
            for value in (
                host["ip"],
                host["hostname"],
                host["os"] or "unknown",
                service["port"]["number"] if service else "—",
                service["port"]["protocol"] if service else "—",
                service["name"] if service else "No open services recorded",
                service["product"] if service else "",
                service["version"] if service else "",
                ", ".join(service["cpes"]) if service else "",
            )
        )
        + "</tr>"
        for host in document["hosts"]
        for service in host["services"] or [None]
    )
    findings = (
        "".join(
            '<article class="finding">'
            f"<h3>{text(item['vulnerability_id'])} "
            f"<small>{text(item['severity'].upper())}</small></h3>"
            f"<p>{text(item['host'])} · {text(item['port'])}/{text(item['protocol'])} · "
            f"CVSS {text(item['cvss'] if item['cvss'] is not None else 'unknown')}</p>"
            f"<p>{text(item['description'])}</p>"
            f"<p><strong>Review status:</strong> {text(item['status'])}</p>"
            f"<p><strong>Remediation:</strong> {text(item['remediation'])}</p>"
            f"<p><strong>Evidence:</strong> {text(', '.join(item['matched_cpes']))}</p>"
            f"<p><strong>Source:</strong> {text(item['source'])}</p>"
            + decision(item)
            + "</article>"
            for item in document["findings"]
        )
        or "<p>No candidates were found in the supplied catalog. "
        "This does not establish that the services are secure.</p>"
    )
    warnings = "".join(f"<li>{text(value)}</li>" for value in document["warnings"])
    advisories = "".join(
        '<article class="finding">'
        f"<h3>{text(item['cve_id'])}</h3><p>{text(item['description'])}</p>"
        f"<p>Advisory status: {text(item['status'])} · CVSS {text(item['cvss'])} "
        f"({text(item['cvss_version'])})</p>"
        f"<p>Provider: {text(item['provider'])} · Retrieved: {text(item['retrieved_at'])}</p>"
        "</article>"
        for item in document.get("advisories", [])
    )
    if advisories:
        advisories = (
            "<h2>NVD advisory context</h2><p>Advisory metadata does not confirm applicability. "
            "Candidate scores above remain those supplied in the reviewed catalog.</p>" + advisories
        )
    coverage = document["coverage"]
    provenance = "<br>".join(
        f"{text(key)}: {text(value)}" for key, value in document["provenance"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>RedOps Assessment {text(document["id"])}</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif;
color: #172536; background: #edf1f5; }}
body {{ margin: 0; }} main {{ max-width: 1120px; margin: auto; padding: 2rem; }}
header {{ border-top: 5px solid #ce493f; padding: 1rem 0; }} h1 {{ font-size: 2.4rem; }}
.eyebrow {{ letter-spacing: .18em; font-size: .8rem; font-weight: 700; color: #a52f2f; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: .8rem; }}
.card, .finding {{ background: white; padding: 1.2rem;
border: 1px solid #dce2e9; border-radius: 8px; }}
.card strong {{ display: block; font-size: 2rem; }} .card span, small {{ color: #526172; }}
.finding {{ margin: 1rem 0; }} .finding p {{ overflow-wrap: anywhere; }}
.notice {{ border-left: 4px solid #ce493f; padding: .3rem 1rem; background: #fff8f1; }}
.table-scroll {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; background: white; }}
th, td {{ padding: .7rem; text-align: left; border-bottom: 1px solid #dce2e9; }}
footer {{ font-size: .8rem; overflow-wrap: anywhere; color: #526172; margin-top: 2rem; }}
@media print {{ body {{ background: white; }} main {{ padding: 0; }}
.finding {{ break-inside: avoid; }} }}
</style></head><body><main>
<header><p class="eyebrow">REDOPS / ASSESSMENT</p><h1>Inventory &amp; vulnerability evidence</h1>
<p>{text(document["scope"]["engagement"])} · {text(document["created_at"])} ·
{text(document["status"])}</p></header>
<aside class="notice"><ul>{warnings}</ul></aside>
<h2>Candidate findings</h2><div class="cards">{cards}</div>
<p>{len(document["hosts"])} hosts · {coverage["services_total"]} open services ·
{coverage["services_with_supported_cpe"]} services with a supported versioned CPE.</p>
{review_notice}
<h2>Service inventory</h2><div class="table-scroll"><table>
<thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Port</th><th>Protocol</th><th>Service</th>
<th>Product</th><th>Version</th><th>CPE observations</th></tr></thead>
<tbody>{inventory}</tbody></table></div>
<h2>Evidence and remediation</h2>{findings}{advisories}
<footer>Assessment: {text(document["id"])}<br>
{provenance}</footer>
</main></body></html>"""


def render_report(document: dict[str, Any], format_name: str) -> str | bytes:
    renderers = {"json": render_json, "html": render_html, "pdf": render_pdf}
    if format_name not in renderers:
        raise ValueError("Unsupported report format")
    return renderers[format_name](document)


def export_report(document: dict[str, Any], destination: Path, format_name: str) -> None:
    atomic_write(destination, render_report(document, format_name))
    logger.info("Assessment report exported as %s", format_name)
