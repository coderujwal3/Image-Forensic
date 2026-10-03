"""Metadata tampering, inconsistency detection, and structural discrepancy analyzer."""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class TamperingAnalysis(BaseModel):
    """Forensic report on internal metadata discrepancies and structural tampering."""
    inconsistencies_count: int = 0
    dimension_mismatch: bool = False
    orientation_mismatch: bool = False
    editing_software_detected: bool = False
    detected_software: Optional[str] = None
    temporal_inconsistency: bool = False
    has_trailing_payload: bool = False
    discrepancies: List[str] = Field(default_factory=list)


class TamperingAnalyzer(BaseAnalyzer):
    """Identifies logical inconsistencies between headers, container metadata, and decoded image data."""

    name = "tampering"
    description = "Metadata tampering and structural inconsistency detection"
    version = "1.0.0"

    EDITING_SOFTWARE_KEYWORDS = [
        "photoshop", "gimp", "lightroom", "canva", "snapseed", "vsco", "pixlr",
        "picsart", "inshot", "affinity", "paint.net", "corel", "imagemagick",
    ]

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = TamperingAnalysis()
        findings: List[Finding] = []

        w, h = evidence.dimensions
        exif = context.get("exif", {})
        xmp = context.get("xmp", {})
        container_struct = context.get("container_structure")

        # 1. Dimension Mismatch
        exif_w = exif.get("exif_image_width")
        exif_h = exif.get("exif_image_height")
        if exif_w and exif_h and w > 0 and h > 0:
            # Check direct or transposed match
            direct_match = (w == exif_w and h == exif_h)
            transposed_match = (w == exif_h and h == exif_w)
            if not direct_match and not transposed_match:
                analysis.dimension_mismatch = True
                analysis.inconsistencies_count += 1
                disc = f"EXIF declares {exif_w}x{exif_h}, but decoded image payload is {w}x{h}."
                analysis.discrepancies.append(disc)

                findings.append(
                    Finding(
                        category="TAMPERING",
                        status=FindingStatus.DERIVED,
                        severity=Severity.HIGH,
                        title="Metadata / pixel dimension discrepancy detected",
                        description=(
                            "The declared dimensions in EXIF metadata (ExifImageWidth/Height) conflict "
                            "with the actual pixel dimensions of the image container payload. "
                            "This demonstrates the image was resized or re-encoded without updating metadata."
                        ),
                        evidence=[
                            f"EXIF dimensions: {exif_w} × {exif_h}",
                            f"Actual pixel dimensions: {w} × {h}",
                        ],
                        confidence=1.0,
                        confidence_level=ConfidenceLevel.CERTAIN,
                        limitations=["Some automated content management systems crop or scale images while retaining stale EXIF."],
                    )
                )

        # 2. Editing Software Signature
        software_field = exif.get("software") or xmp.get("creator_tool")
        if software_field:
            s_lower = software_field.lower()
            for kw in self.EDITING_SOFTWARE_KEYWORDS:
                if kw in s_lower:
                    analysis.editing_software_detected = True
                    analysis.detected_software = software_field
                    findings.append(
                        Finding(
                            category="TAMPERING",
                            status=FindingStatus.OBSERVED,
                            severity=Severity.MEDIUM,
                            title=f"Editing software signature identified: {software_field}",
                            description=(
                                f"Metadata tag explicitly records '{software_field}' as the creating or processing software, "
                                "confirming post-capture software manipulation."
                            ),
                            evidence=[f"Software tag: {software_field}"],
                        )
                    )
                    break

        # 3. Temporal Inconsistency
        dto = exif.get("date_time_original")
        dtm = exif.get("date_time") or xmp.get("modify_date")
        if dto and dtm and dto != dtm:
            analysis.temporal_inconsistency = True
            disc = f"Original capture time ({dto}) differs from modification time ({dtm})."
            analysis.discrepancies.append(disc)
            findings.append(
                Finding(
                    category="TAMPERING",
                    status=FindingStatus.DERIVED,
                    severity=Severity.INFO,
                    title="Temporal modification timeline documented in metadata",
                    description=(
                        f"Original capture timestamp ({dto}) precedes modification timestamp ({dtm}), "
                        "confirming post-acquisition re-saving or metadata modification."
                    ),
                    evidence=[
                        f"DateTimeOriginal: {dto}",
                        f"ModifyDate: {dtm}",
                    ],
                )
            )

        # 4. Trailing Payload (Steganography / Polyglot / Overlay)
        if container_struct and getattr(container_struct, "has_trailing_data", False):
            t_len = getattr(container_struct, "trailing_data_length", 0)
            t_off = getattr(container_struct, "trailing_data_offset", 0)
            analysis.has_trailing_payload = True
            analysis.inconsistencies_count += 1
            disc = f"Trailing data appended after container termination marker ({t_len} bytes at offset {t_off})."
            analysis.discrepancies.append(disc)

            findings.append(
                Finding(
                    category="FILE_STRUCTURE",
                    status=FindingStatus.OBSERVED,
                    severity=Severity.HIGH,
                    title="Trailing data detected past container end-of-file marker",
                    description=(
                        f"Detected {t_len} bytes of unparsed binary payload located strictly after the container "
                        f"termination marker (offset {t_off}). This is characteristic of steganographic embedding, "
                        "polyglot file creation, or appended archive data."
                    ),
                    evidence=[
                        f"Trailing bytes length: {t_len} bytes",
                        f"Starting offset: {t_off}",
                    ],
                    limitations=["Some camera models or transfer tools inadvertently write trailing padding bytes."],
                )
            )

        return analysis.model_dump(), findings
