"""Unit tests for forensic analyzers (quantization, subsampling, recompression, tampering)."""

from pathlib import Path
from PIL import Image
from forensic_image.core.constants import ChromaSubsampling, FindingStatus, Severity
from forensic_image.core.evidence import ImageEvidence
from forensic_image.forensics.quantization import STD_LUMINANCE_50, estimate_ijg_quality, scale_ijg_table
from forensic_image.forensics.subsampling import SubsamplingAnalyzer
from forensic_image.forensics.tampering import TamperingAnalyzer


def test_ijg_quality_estimation() -> None:
    # Scale standard table to Q85 and test estimation
    q85_table = scale_ijg_table(STD_LUMINANCE_50, 85)
    est_q, mae, exact = estimate_ijg_quality(q85_table)

    assert est_q == 85
    assert mae == 0.0
    assert exact is True

    # Scale standard table to Q75
    q75_table = scale_ijg_table(STD_LUMINANCE_50, 75)
    est_q75, mae75, exact75 = estimate_ijg_quality(q75_table)

    assert est_q75 == 75
    assert mae75 == 0.0


def test_subsampling_detection(clean_jpeg_path: Path) -> None:
    ev = ImageEvidence(clean_jpeg_path)
    rep = ev.analyze()

    assert rep.subsampling.get("subsampling") in (
        ChromaSubsampling.YUV420.value,
        ChromaSubsampling.YUV422.value,
        ChromaSubsampling.YUV444.value,
    )


def test_tampering_dimension_mismatch(tmp_path: Path) -> None:
    # Create test JPEG
    p = tmp_path / "tampered_dims.jpg"
    img = Image.new("RGB", (800, 600), "green")
    img.save(p, format="JPEG")

    ev = ImageEvidence(p)
    # Simulate context where EXIF declares 4032x3024
    ctx = {
        "exif": {"exif_image_width": 4032, "exif_image_height": 3024},
        "xmp": {},
        "container_structure": None,
    }
    analyzer = TamperingAnalyzer()
    res, findings = analyzer.analyze(ev, ctx)

    assert res["dimension_mismatch"] is True
    assert any(f.category == "TAMPERING" and f.severity == Severity.HIGH for f in findings)


def test_screenshot_detection(screenshot_png_path: Path) -> None:
    ev = ImageEvidence(screenshot_png_path)
    rep = ev.analyze()

    assert rep.screenshot.get("status") in ("detected", "possible")
    assert rep.screenshot.get("matched_resolution") == "1179x2556"
    assert "iPhone" in rep.screenshot.get("matched_category", "")
