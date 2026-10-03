"""Forensic transformation, resizing, and cropping analysis."""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class TransformationAnalysis(BaseModel):
    """Forensic report on resizing, cropping, and dimension transformations."""
    actual_width: int = 0
    actual_height: int = 0
    actual_aspect_ratio: float = 0.0
    aspect_ratio_standard_name: Optional[str] = None
    is_standard_sensor_ratio: bool = False
    is_common_web_resample: bool = False
    is_downscaled_suspected: bool = False
    is_cropped_suspected: bool = False
    total_megapixels: float = 0.0


class TransformationAnalyzer(BaseAnalyzer):
    """Investigates dimension relationships, standard sensor ratios, and scaling indicators."""

    name = "transformation"
    description = "Resizing, cropping, and dimension transformation analysis"
    version = "1.0.0"

    STANDARD_RATIOS = {
        (4, 3): "4:3 (Standard Digital Camera / Tablet)",
        (3, 2): "3:2 (Standard 35mm DSLR / Mirrorless)",
        (16, 9): "16:9 (Widescreen Video / Display)",
        (1, 1): "1:1 (Square Format)",
        (16, 10): "16:10 (Desktop / Laptop Display)",
        (19.5, 9): "19.5:9 (Modern Mobile Phone Display)",
        (20, 9): "20:9 (Modern Mobile Phone Display)",
    }

    COMMON_WEB_LIMITS = {640, 720, 800, 960, 1080, 1200, 1280, 1440, 1600, 1920, 2048, 2560}

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = TransformationAnalysis()
        findings: List[Finding] = []

        w, h = evidence.dimensions
        if w == 0 or h == 0:
            return analysis.model_dump(), findings

        analysis.actual_width = w
        analysis.actual_height = h
        ar = round(max(w, h) / min(w, h), 3)
        analysis.actual_aspect_ratio = ar
        mp = round((w * h) / 1_000_000.0, 2)
        analysis.total_megapixels = mp

        # Check standard ratios
        matched_ratio = None
        for (num, den), name in self.STANDARD_RATIOS.items():
            ref_ar = round(num / den, 3)
            if abs(ar - ref_ar) <= 0.02:
                matched_ratio = name
                analysis.is_standard_sensor_ratio = (num, den) in ((4, 3), (3, 2), (1, 1), (16, 9))
                break

        analysis.aspect_ratio_standard_name = matched_ratio

        # Check common web bounding dimensions
        max_dim = max(w, h)
        if max_dim in self.COMMON_WEB_LIMITS:
            analysis.is_common_web_resample = True

        exif_data = context.get("exif", {})
        has_camera_make = bool(exif_data.get("make") or exif_data.get("model"))
        exif_w = exif_data.get("exif_image_width")
        exif_h = exif_data.get("exif_image_height")

        # 1. Resizing vs Camera Sensor
        if has_camera_make and mp < 3.5:
            # Modern cameras almost invariably shoot >= 12 MP
            analysis.is_downscaled_suspected = True
            findings.append(
                Finding(
                    category="TRANSFORMATION",
                    status=FindingStatus.DERIVED,
                    severity=Severity.LOW,
                    title="Image resolution suggests downscaling from native sensor",
                    description=(
                        f"Image resolution ({w}x{h}, {mp} MP) is significantly lower than native capture "
                        f"resolutions of modern camera models ({exif_data.get('make', '')} {exif_data.get('model', '')})."
                    ),
                    evidence=[
                        f"Pixel dimensions: {w}x{h} ({mp} MP)",
                        f"Reported camera: {exif_data.get('make', 'Unknown')} {exif_data.get('model', 'Unknown')}",
                    ],
                    limitations=["User or camera settings may configure smaller resolution capture modes."],
                )
            )

        # 2. Web Resizing Targets
        if analysis.is_common_web_resample:
            findings.append(
                Finding(
                    category="TRANSFORMATION",
                    status=FindingStatus.DERIVED,
                    severity=Severity.INFO,
                    title=f"Dimension matches standard web resizing threshold ({max_dim}px)",
                    description=(
                        f"Longest image edge is exactly {max_dim}px, which corresponds to standard CDN/web "
                        "resizing bounding box targets."
                    ),
                    evidence=[f"Longest edge: {max_dim}px"],
                )
            )

        # 3. Cropping suspicion
        if has_camera_make and not analysis.is_standard_sensor_ratio:
            analysis.is_cropped_suspected = True
            findings.append(
                Finding(
                    category="TRANSFORMATION",
                    status=FindingStatus.INFERRED,
                    severity=Severity.LOW,
                    title="Non-standard aspect ratio consistent with cropping",
                    description=(
                        f"The aspect ratio ({ar:.3f}) deviates from standard native camera sensor formats "
                        "(4:3, 3:2, 16:9). This characteristic is consistent with post-capture cropping."
                    ),
                    evidence=[
                        f"Observed aspect ratio: {ar:.3f}",
                        f"Dimensions: {w}x{h}",
                    ],
                    limitations=["Custom in-camera composition crops or panorama modes produce non-standard ratios."],
                )
            )

        return analysis.model_dump(), findings
