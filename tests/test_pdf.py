import io

import pytest
from pypdf import PdfReader

from redops.core.errors import InputError
from redops.reporting.pdf import render_pdf
from redops.reporting.render import export_report


def test_pdf_contains_inventory_findings_and_provenance(preview):
    data = render_pdf(preview)
    assert data.startswith(b"%PDF-")
    reader = PdfReader(io.BytesIO(data))
    assert len(reader.pages) > 1
    content = "\n".join(page.extract_text() for page in reader.pages)
    for expected in ("RedOps Assessment", "192.0.2.10", "DEMO-WEB-001", "candidate_needs_review"):
        assert expected in content
    assert preview["provenance"]["catalog_sha256"] in content.replace("\n", "")


def test_pdf_preserves_supported_unicode_and_escapes_missing_glyphs(preview, caplog):
    preview["hosts"][0]["hostname"] = "démo-λ café 漢"
    preview["warnings"].append("مرحبا بالعالم")
    content = "\n".join(
        page.extract_text() for page in PdfReader(io.BytesIO(render_pdf(preview))).pages
    )
    assert "démo-λ café \\u6f22" in content
    # PDF extraction may reorder Arabic runs; every original letter remains mapped.
    assert set("مرحبا بالعالم") <= set(content)
    assert "missing" not in caplog.text.lower()


def test_pdf_export_writes_a_real_document(preview, tmp_path):
    path = tmp_path / "report.pdf"
    export_report(preview, path, "pdf")
    assert PdfReader(path).metadata.title == "RedOps Assessment"
    assert list(tmp_path.glob(".redops-*")) == []


def test_pdf_has_an_explicit_input_limit(preview):
    preview["warnings"].append("a" * (2 * 1024 * 1024))
    with pytest.raises(InputError, match="limited"):
        render_pdf(preview)
