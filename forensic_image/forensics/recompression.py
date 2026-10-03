"""Forensic recompression and double-compression indicator analysis."""

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image
from pydantic import BaseModel, Field
from scipy.fftpack import dct

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class RecompressionAnalysis(BaseModel):
    """Forensic indicators of possible prior JPEG recompression."""
    is_recompressed_suspected: bool = False
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    dct_histogram_periodicity: float = 0.0
    benford_divergence: float = 0.0
    evidence_signals: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class RecompressionAnalyzer(BaseAnalyzer):
    """Analyzes DCT domain statistics and quantization signatures for double compression."""

    name = "recompression"
    description = "Recompression and double JPEG compression detection"
    version = "1.0.0"

    # Benford's Law standard theoretical distribution for first digits (1..9)
    BENFORD_REF = [math.log10(1.0 + 1.0 / d) for d in range(1, 10)]

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = RecompressionAnalysis()
        findings: List[Finding] = []

        # Analyze pixel DCT statistics if PIL image is accessible
        img = evidence.image
        if img is None:
            return analysis.model_dump(), findings

        # Run 8x8 block DCT coefficient analysis on luma channel
        try:
            gray = np.asarray(img.convert("L"), dtype=np.float32)
            h, w = gray.shape
            
            # Crop to multiple of 8
            h_crop = (h // 8) * 8
            w_crop = (w // 8) * 8
            if h_crop < 64 or w_crop < 64:
                return analysis.model_dump(), findings

            blocks = gray[:h_crop, :w_crop].reshape(h_crop // 8, 8, w_crop // 8, 8).swapaxes(1, 2)
            
            # Compute 2D DCT for each 8x8 block
            dct_blocks = dct(dct(blocks, axis=2, norm="ortho"), axis=3, norm="ortho")
            
            # Extract low-to-mid frequency AC coefficients (e.g. at (1,2) and (2,1))
            ac_coeffs = np.round(dct_blocks[:, :, 1, 2].flatten()).astype(int)
            ac_nonzero = ac_coeffs[ac_coeffs != 0]

            # 1. Periodicity / Peak-and-valley test (double quantization signature)
            periodicity_score = self._compute_periodicity(ac_nonzero)
            analysis.dct_histogram_periodicity = round(periodicity_score, 3)

            # 2. First-digit Benford's Law divergence
            benford_div = self._compute_benford_divergence(ac_nonzero)
            analysis.benford_divergence = round(benford_div, 4)

            # Check context from metadata and quantization
            q_analysis = context.get("quantization", {})
            est_q = q_analysis.get("estimated_quality")
            xmp_data = context.get("xmp", {})
            history_events = xmp_data.get("history", [])

            signals = []
            score = 0.0

            if periodicity_score > 0.45:
                signals.append(f"Periodic histogram modulation detected in DCT AC coefficients (score: {periodicity_score:.2f})")
                score += 0.40

            if benford_div > 0.06:
                signals.append(f"First-digit distribution deviates from logarithmic Benford model (div: {benford_div:.3f})")
                score += 0.25

            if history_events and len(history_events) > 1:
                signals.append(f"XMP documents {len(history_events)} prior editing/saving history transitions")
                score += 0.30

            analysis.evidence_signals = signals
            analysis.confidence = min(0.95, round(score, 2))

            if analysis.confidence >= 0.70:
                analysis.is_recompressed_suspected = True
                analysis.confidence_level = ConfidenceLevel.HIGH if analysis.confidence >= 0.80 else ConfidenceLevel.MEDIUM
            elif analysis.confidence >= 0.40:
                analysis.is_recompressed_suspected = True
                analysis.confidence_level = ConfidenceLevel.LOW
            else:
                analysis.confidence_level = ConfidenceLevel.INCONCLUSIVE

            analysis.limitations = [
                "The original camera capture is unavailable for direct baseline subtraction.",
                "Non-JPEG sources (e.g. synthetic graphics or screenshots) can exhibit irregular DCT distributions.",
                "Identical quality re-compression (Q1 == Q2) typically does not produce visible periodicity.",
            ]

            if analysis.is_recompressed_suspected:
                findings.append(
                    Finding(
                        category="RECOMPRESSION",
                        status=FindingStatus.INFERRED,
                        severity=Severity.MEDIUM if analysis.confidence >= 0.70 else Severity.LOW,
                        title="Characteristics consistent with prior recompression",
                        description=(
                            "Statistical and structural DCT characteristics exhibit artifacts consistent with "
                            "multiple encoding generations or post-capture recompression."
                        ),
                        evidence=signals,
                        confidence=analysis.confidence,
                        confidence_level=analysis.confidence_level,
                        limitations=analysis.limitations,
                        alternative_explanations=[
                            "Image may have been rendered from a complex scene with periodic textures.",
                            "Encoder firmware may use an aggressive non-linear psychovisual rate control.",
                        ],
                    )
                )

        except Exception:
            pass

        return analysis.model_dump(), findings

    def _compute_periodicity(self, coeffs: np.ndarray) -> float:
        """Measures periodic comb-filtering in coefficient histograms typical of double quantization."""
        if len(coeffs) < 100:
            return 0.0
        # Restrict to range [-50, 50]
        subset = coeffs[(coeffs >= -50) & (coeffs <= 50)]
        if len(subset) < 100:
            return 0.0

        hist, _ = np.histogram(subset, bins=101, range=(-50.5, 50.5))
        hist = hist.astype(float)
        # Power spectrum of histogram
        fft_mag = np.abs(np.fft.rfft(hist - np.mean(hist)))
        if len(fft_mag) < 4:
            return 0.0
        
        # Exclude DC and very low freq
        ac_fft = fft_mag[2:]
        if len(ac_fft) == 0:
            return 0.0
        peak = np.max(ac_fft)
        mean_p = np.mean(ac_fft)
        ratio = (peak / (mean_p + 1e-6))
        # Normalize into a 0.0 - 1.0 confidence range
        return float(min(1.0, max(0.0, (ratio - 2.5) / 5.0)))

    def _compute_benford_divergence(self, coeffs: np.ndarray) -> float:
        """Computes Kullback-Leibler / total variation divergence from Benford's first digit distribution."""
        abs_vals = np.abs(coeffs)
        valid = abs_vals[abs_vals >= 1]
        if len(valid) < 200:
            return 0.0

        first_digits = [int(str(v)[0]) for v in valid[:10000]]
        counts = [first_digits.count(d) for d in range(1, 10)]
        total = sum(counts)
        if total == 0:
            return 0.0

        probs = [c / total for c in counts]
        # Total variation distance: 0.5 * sum |p - q|
        tv_dist = 0.5 * sum(abs(p - q) for p, q in zip(probs, self.BENFORD_REF))
        return float(tv_dist)
