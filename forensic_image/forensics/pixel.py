"""Experimental pixel-level forensics: Error Level Analysis (ELA) and high-frequency noise variance."""

import io
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image, ImageChops, ImageEnhance
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class PixelForensicsAnalysis(BaseModel):
    """Forensic report on experimental pixel-level anomaly signals."""
    is_experimental: bool = True
    ela_mean_error: float = 0.0
    ela_max_error: int = 0
    ela_std_error: float = 0.0
    noise_variance_global: float = 0.0
    noise_variance_std: float = 0.0
    potential_localized_inconsistencies: bool = False
    disclaimer: str = (
        "EXPERIMENTAL MODULE: ELA and noise variance metrics reflect compression and gradient variations. "
        "They do NOT constitute conclusive proof of digital manipulation or forgery on their own."
    )


class PixelForensicAnalyzer(BaseAnalyzer):
    """Executes experimental Error Level Analysis (ELA) and spatial noise variance profiling."""

    name = "pixel"
    description = "Experimental pixel-level Error Level Analysis (ELA) and noise variance"
    version = "1.0.0"

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = PixelForensicsAnalysis()
        findings: List[Finding] = []

        img = evidence.image
        if img is None:
            return analysis.model_dump(), findings

        # Run ELA
        try:
            rgb_img = img.convert("RGB")
            # Save to in-memory JPEG at fixed quality 95
            buf = io.BytesIO()
            rgb_img.save(buf, format="JPEG", quality=95)
            buf.seek(0)
            recomp = Image.open(buf)

            # Compute absolute difference
            diff = ImageChops.difference(rgb_img, recomp)
            diff_arr = np.asarray(diff, dtype=np.float32)

            analysis.ela_mean_error = round(float(np.mean(diff_arr)), 3)
            analysis.ela_max_error = int(np.max(diff_arr))
            analysis.ela_std_error = round(float(np.std(diff_arr)), 3)

            # High-frequency noise variance via 3x3 Laplacian residual
            gray = np.asarray(rgb_img.convert("L"), dtype=np.float32)
            # 3x3 Laplacian filter kernel
            laplacian = (
                -4.0 * gray[1:-1, 1:-1]
                + gray[:-2, 1:-1]
                + gray[2:, 1:-1]
                + gray[1:-1, :-2]
                + gray[1:-1, 2:]
            )
            analysis.noise_variance_global = round(float(np.var(laplacian)), 3)

            # Divide into 16x16 grid patches to check local noise consistency
            h, w = laplacian.shape
            grid_h = h // 16
            grid_w = w // 16
            if grid_h >= 4 and grid_w >= 4:
                patch_vars = []
                for r in range(grid_h):
                    for c in range(grid_w):
                        patch = laplacian[r * 16 : (r + 1) * 16, c * 16 : (c + 1) * 16]
                        patch_vars.append(np.var(patch))
                analysis.noise_variance_std = round(float(np.std(patch_vars)), 3)

                # If the ratio of patch std to global mean variance is extremely high, flag for inspection
                if analysis.noise_variance_global > 0:
                    cv = analysis.noise_variance_std / analysis.noise_variance_global
                    if cv > 3.0:
                        analysis.potential_localized_inconsistencies = True

            findings.append(
                Finding(
                    category="PIXEL_FORENSICS",
                    status=FindingStatus.DERIVED,
                    severity=Severity.INFO,
                    title="Experimental Error Level Analysis (ELA) computed",
                    description=(
                        f"ELA recompression baseline computed (Mean error: {analysis.ela_mean_error}, "
                        f"Std: {analysis.ela_std_error}, Max: {analysis.ela_max_error}). Global noise variance: {analysis.noise_variance_global}."
                    ),
                    evidence=[
                        f"ELA mean error: {analysis.ela_mean_error}",
                        f"ELA max error: {analysis.ela_max_error}",
                        f"Global noise variance: {analysis.noise_variance_global}",
                    ],
                    limitations=[
                        "ELA alone CANNOT prove or disprove image manipulation.",
                        "Natural high-contrast edges and fine textures naturally display elevated ELA response.",
                        "Uniform smooth backgrounds naturally exhibit lower error levels.",
                    ],
                )
            )

        except Exception:
            pass

        return analysis.model_dump(), findings
