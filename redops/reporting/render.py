"""Self-contained output; every observed value is escaped before HTML rendering."""

import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from redops.core.io import atomic_write


def render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"


def render_html(document: dict[str, Any]) -> str:
    def text(value: object) -> str:
        return escape(str(value), quote=True)

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
                service["port"]["number"],
                service["port"]["protocol"],
                service["name"],
                service["product"],
                service["version"],
            )
        )
        + "</tr>"
        for host in document["hosts"]
        for service in host["services"]
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
            f"<p><strong>Source:</strong> {text(item['source'])}</p></article>"
            for item in document["findings"]
        )
        or "<p>No candidates were found in the supplied catalog. "
        "This does not establish that the services are secure.</p>"
    )
    warnings = "".join(f"<li>{text(value)}</li>" for value in document["warnings"])
    coverage = document["coverage"]
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
<h2>Service inventory</h2><div class="table-scroll"><table>
<thead><tr><th>IP</th><th>Hostname</th><th>Port</th><th>Protocol</th><th>Service</th>
<th>Product</th><th>Version</th></tr></thead><tbody>{inventory}</tbody></table></div>
<h2>Evidence and remediation</h2>{findings}
<footer>Assessment: {text(document["id"])}<br>
Nmap SHA-256: {text(document["provenance"]["nmap_sha256"])}<br>
Catalog SHA-256: {text(document["provenance"]["catalog_sha256"])}<br>
Catalog updated: {text(document["provenance"]["catalog_updated_at"])}</footer>
</main></body></html>"""


def export_report(document: dict[str, Any], destination: Path, format_name: str) -> None:
    if format_name not in {"json", "html"}:
        raise ValueError("Unsupported report format")
    atomic_write(
        destination, render_json(document) if format_name == "json" else render_html(document)
    )
