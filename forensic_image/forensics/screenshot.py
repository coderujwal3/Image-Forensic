"""Forensic screenshot detection and display resolution matching."""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class ScreenResolution(BaseModel):
    width: int
    height: int
    device_category: str  # "iPhone", "Android", "iPad/Tablet", "Desktop/Laptop"
    device_models: str


class ScreenshotAnalysis(BaseModel):
    """Forensic report on screenshot indicators."""
    status: str = "not_detected"  # "detected", "possible", "not_detected", "inconclusive"
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    matched_device: Optional[str] = None
    matched_category: Optional[str] = None
    matched_resolution: Optional[str] = None
    is_screen_resolution_exact: bool = False
    is_png_container: bool = False
    is_display_color_profile: bool = False
    lacks_camera_exif: bool = True
    evidence_signals: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class ScreenshotAnalyzer(BaseAnalyzer):
    """Investigates pixel dimensions, container formats, and metadata absences typical of screenshots."""

    name = "screenshot"
    description = "Screenshot indicator and native screen resolution analysis"
    version = "1.0.0"

    SCREEN_RESOLUTIONS: List[ScreenResolution] = [
        # iOS Devices
        ScreenResolution(width=1290, height=2796, device_category="iPhone", device_models="iPhone 14/15/16 Pro Max"),
        ScreenResolution(width=1179, height=2556, device_category="iPhone", device_models="iPhone 14/15/16 Pro"),
        ScreenResolution(width=1284, height=2778, device_category="iPhone", device_models="iPhone 12/13 Pro Max"),
        ScreenResolution(width=1170, height=2532, device_category="iPhone", device_models="iPhone 12/13/14"),
        ScreenResolution(width=1125, height=2436, device_category="iPhone", device_models="iPhone X/XS/11 Pro"),
        ScreenResolution(width=828, height=1792, device_category="iPhone", device_models="iPhone XR/11"),
        ScreenResolution(width=750, height=1334, device_category="iPhone", device_models="iPhone SE/7/8"),
        ScreenResolution(width=2048, height=2732, device_category="iPad/Tablet", device_models="iPad Pro 12.9-inch"),
        ScreenResolution(width=1668, height=2388, device_category="iPad/Tablet", device_models="iPad Pro 11-inch"),
        ScreenResolution(width=1640, height=2360, device_category="iPad/Tablet", device_models="iPad Air 10.9-inch"),
        # Android Flagships & Common Screens
        ScreenResolution(width=1080, height=2400, device_category="Android", device_models="Samsung Galaxy S20/S21/A-series, Pixel 6/7/8"),
        ScreenResolution(width=1080, height=2340, device_category="Android", device_models="Samsung Galaxy S22/S23/S24"),
        ScreenResolution(width=1440, height=3120, device_category="Android", device_models="Google Pixel Pro series"),
        ScreenResolution(width=1440, height=3088, device_category="Android", device_models="Samsung Galaxy Ultra series"),
        ScreenResolution(width=1080, height=2412, device_category="Android", device_models="OnePlus / Oppo / Realme series"),
        # Desktop & Laptops
        ScreenResolution(width=1920, height=1080, device_category="Desktop/Laptop", device_models="Standard Full HD 1080p"),
        ScreenResolution(width=2560, height=1440, device_category="Desktop/Laptop", device_models="QHD 1440p Monitor"),
        ScreenResolution(width=3840, height=2160, device_category="Desktop/Laptop", device_models="4K UHD Monitor"),
        ScreenResolution(width=2880, height=1800, device_category="Desktop/Laptop", device_models="MacBook Pro 15/16 Retina"),
        ScreenResolution(width=3024, height=1964, device_category="Desktop/Laptop", device_models="MacBook Pro 14 Liquid Retina XDR"),
        ScreenResolution(width=2560, height=1600, device_category="Desktop/Laptop", device_models="MacBook Air / Pro 13"),
        ScreenResolution(width=1440, height=900, device_category="Desktop/Laptop", device_models="MacBook Air standard"),
    ]

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = ScreenshotAnalysis()
        findings: List[Finding] = []

        w, h = evidence.dimensions
        if w == 0 or h == 0:
            return analysis.model_dump(), findings

        fmt = evidence.format.value
        analysis.is_png_container = (fmt == "PNG")

        exif = context.get("exif", {})
        icc = context.get("icc", {})

        # 1. Camera EXIF absence check
        has_camera = bool(exif.get("make") or exif.get("model") or exif.get("focal_length_mm") or exif.get("iso"))
        analysis.lacks_camera_exif = not has_camera

        # 2. Display Color Profile
        dev_class = icc.get("device_class")
        analysis.is_display_color_profile = (dev_class == "mntr")

        # 3. Exact screen resolution matching (both portrait and landscape)
        matched_res = None
        for res in self.SCREEN_RESOLUTIONS:
            if (w == res.width and h == res.height) or (w == res.height and h == res.width):
                matched_res = res
                break

        score = 0.0
        signals = []

        if matched_res:
            analysis.is_screen_resolution_exact = True
            analysis.matched_resolution = f"{matched_res.width}x{matched_res.height}"
            analysis.matched_category = matched_res.device_category
            analysis.matched_device = matched_res.device_models
            signals.append(f"Dimensions match exact native screen resolution: {matched_res.device_models} ({matched_res.width}x{matched_res.height})")
            score += 0.45

        if analysis.lacks_camera_exif:
            signals.append("Total absence of camera sensor capture metadata (Make, Model, Lens, ISO, Exposure)")
            score += 0.25

        if analysis.is_png_container:
            signals.append("Stored in lossless PNG container (standard OS screen capture format)")
            score += 0.20

        if analysis.is_display_color_profile:
            signals.append("ICC profile specifies Display/Monitor color space ('mntr')")
            score += 0.10

        analysis.evidence_signals = signals
        analysis.confidence = min(0.95, round(score, 2))

        if analysis.confidence >= 0.70:
            analysis.status = "detected"
            analysis.confidence_level = ConfidenceLevel.HIGH if analysis.confidence >= 0.85 else ConfidenceLevel.MEDIUM
        elif analysis.confidence >= 0.40:
            analysis.status = "possible"
            analysis.confidence_level = ConfidenceLevel.LOW
        else:
            analysis.status = "not_detected"
            analysis.confidence_level = ConfidenceLevel.LOW

        analysis.limitations = [
            "An image cropped to screen dimensions or rendered by graphics software can match screen resolutions.",
            "Stripping camera EXIF from a regular photograph will mimic metadata absence.",
            "Display resolution matching alone does not prove screenshot provenance.",
        ]

        if analysis.status in ("detected", "possible"):
            findings.append(
                Finding(
                    category="SCREENSHOT",
                    status=FindingStatus.INFERRED,
                    severity=Severity.INFO if analysis.status == "possible" else Severity.LOW,
                    title=f"Screenshot indicators {analysis.status}",
                    description=(
                        f"Structural, dimensional, and metadata characteristics are consistent with screen capture "
                        f"({analysis.matched_device or 'Unknown display device'})."
                    ),
                    evidence=signals,
                    confidence=analysis.confidence,
                    confidence_level=analysis.confidence_level,
                    limitations=analysis.limitations,
                    alternative_explanations=[
                        "An image was rendered or cropped to standard wallpaper/screen dimensions.",
                        "Camera metadata was stripped and the file was saved as PNG.",
                    ],
                )
            )

        return analysis.model_dump(), findings
