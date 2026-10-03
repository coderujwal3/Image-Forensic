"""Unit tests for report generation (Terminal, JSON, HTML)."""

import json
from pathlib import Path
from forensic_image.core.evidence import ImageEvidence
from forensic_image.reporting.html_reporter import HTMLReporter
from forensic_image.reporting.json_reporter import JSONReporter
from forensic_image.reporting.terminal import TerminalReporter


def test_report_generation(clean_jpeg_path: Path, tmp_path: Path) -> None:
    ev = ImageEvidence(clean_jpeg_path)
    report = ev.analyze()

    # Terminal report
    term_str = TerminalReporter().render_to_string(report)
    assert "FORENSIC IMAGE INTELLIGENCE REPORT" in term_str
    assert report.manifest.evidence_id in term_str
    assert report.hashes.sha256[:16] in term_str

    # JSON report
    json_str = JSONReporter().render(report)
    loaded = json.loads(json_str)
    assert loaded["report_id"] == report.report_id
    assert loaded["hashes"]["sha256"] == report.hashes.sha256

    # HTML report
    html_str = HTMLReporter().render(report)
    assert "<!DOCTYPE html>" in html_str
    assert report.hashes.sha256 in html_str
    assert "Forensic Findings &amp; Observations" in html_str or "Forensic Findings" in html_str

    # File saving methods on report
    html_file = tmp_path / "out.html"
    json_file = tmp_path / "out.json"
    report.save_html(str(html_file))
    report.save_json(str(json_file))

    assert html_file.exists() and html_file.stat().st_size > 0
    assert json_file.exists() and json_file.stat().st_size > 0
