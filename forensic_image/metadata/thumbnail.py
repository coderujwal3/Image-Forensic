"""Forensic embedded thumbnail extraction and discrepancy analysis."""

import io
from typing import Any, Dict, Optional, Tuple
from PIL import Image
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.hashing.perceptual import compute_phash, perceptual_similarity


class ThumbnailDetails(BaseModel):
    """Forensic report on embedded thumbnail presence, dimensions, and discrepancies."""
    is_present: bool = False
    status: FindingStatus = FindingStatus.NOT_AVAILABLE
    source_type: Optional[str] = None  # "EXIF_IFD1", "JFXX", "PHOTOSHOP_IRB"
    width: Optional[int] = None
    height: Optional[int] = None
    aspect_ratio: Optional[float] = None
    byte_size: Optional[int] = None
    format: Optional[str] = None
    visual_similarity_to_main: Optional[float] = None
    has_discrepancy: bool = False
    discrepancy_reasons: list[str] = Field(default_factory=list)


class ThumbnailForensics:
    """Extracts, hashes, and compares embedded thumbnails with the primary image."""

    def analyze(
        self,
        thumb_bytes: Optional[bytes],
        main_img: Optional[Image.Image],
        source_type: str = "EXIF_IFD1",
    ) -> Tuple[ThumbnailDetails, list[Finding]]:
        details = ThumbnailDetails()
        findings: list[Finding] = []

        if not thumb_bytes or len(thumb_bytes) < 100:
            return details, findings

        details.is_present = True
        details.status = FindingStatus.OBSERVED
        details.source_type = source_type
        details.byte_size = len(thumb_bytes)

        findings.append(
            Finding(
                category="THUMBNAIL",
                status=FindingStatus.OBSERVED,
                severity=Severity.INFO,
                title="Embedded thumbnail detected",
                description=f"An embedded thumbnail of {len(thumb_bytes)} bytes was located via {source_type}.",
                evidence=[f"Source: {source_type}", f"Size: {len(thumb_bytes)} bytes"],
            )
        )

        try:
            with Image.open(io.BytesIO(thumb_bytes)) as t_img:
                t_w, t_h = t_img.size
                details.width = t_w
                details.height = t_h
                details.format = t_img.format
                details.aspect_ratio = round(t_w / t_h, 3) if t_h > 0 else 0.0

                if main_img:
                    m_w, m_h = main_img.size
                    main_ar = round(m_w / m_h, 3) if m_h > 0 else 0.0

                    # 1. Aspect Ratio Discrepancy (e.g. Cropping)
                    ar_diff = abs(details.aspect_ratio - main_ar)
                    if ar_diff > 0.08:
                        details.has_discrepancy = True
                        reason = f"Aspect ratio mismatch: thumbnail is {details.aspect_ratio:.2f} ({t_w}x{t_h}) vs main image {main_ar:.2f} ({m_w}x{m_h})."
                        details.discrepancy_reasons.append(reason)
                        findings.append(
                            Finding(
                                category="THUMBNAIL",
                                status=FindingStatus.DERIVED,
                                severity=Severity.MEDIUM,
                                title="Thumbnail aspect ratio mismatch with main image",
                                description=(
                                    "The embedded thumbnail has a significantly different aspect ratio "
                                    "from the main image, indicating the image was likely cropped without re-generating the preview."
                                ),
                                evidence=[
                                    f"Thumbnail dimensions: {t_w}x{t_h} (AR {details.aspect_ratio:.2f})",
                                    f"Main image dimensions: {m_w}x{m_h} (AR {main_ar:.2f})",
                                ],
                                limitations=["Some camera firmware stores standard 4:3 previews even when shooting in 16:9 mode."],
                            )
                        )

                    # 2. Visual Content Discrepancy
                    try:
                        t_hash = compute_phash(t_img)
                        m_hash = compute_phash(main_img)
                        sim = perceptual_similarity(t_hash, m_hash)
                        details.visual_similarity_to_main = round(sim, 3)

                        if sim < 0.70:
                            details.has_discrepancy = True
                            reason = f"Low visual similarity ({sim:.2f}) between thumbnail and main image."
                            details.discrepancy_reasons.append(reason)
                            findings.append(
                                Finding(
                                    category="THUMBNAIL",
                                    status=FindingStatus.INFERRED,
                                    severity=Severity.HIGH,
                                    title="Thumbnail visual content divergence from main image",
                                    description=(
                                        "The embedded thumbnail exhibits low visual similarity to the primary image. "
                                        "This suggests the main image was heavily edited, censored, or replaced after thumbnail generation."
                                    ),
                                    evidence=[f"Perceptual similarity score: {sim:.2f} / 1.00"],
                                    limitations=["Heavy compression or extreme aspect ratios can depress perceptual similarity."],
                                )
                            )
                    except Exception:
                        pass
        except Exception as e:
            findings.append(
                Finding(
                    category="THUMBNAIL",
                    status=FindingStatus.UNKNOWN,
                    severity=Severity.LOW,
                    title="Embedded thumbnail unparseable",
                    description=f"Raw thumbnail bytes present but failed image decode: {str(e)}",
                )
            )

        return details, findings
