"""JPEG Quantization table analysis, quality factor estimation, and encoder benchmarking."""

import math
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer
from forensic_image.formats.jpeg import QuantizationTable


STD_LUMINANCE_50 = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99
]

STD_CHROMINANCE_50 = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99
]


def scale_ijg_table(base_table: List[int], quality: int) -> List[int]:
    """Generates standard Independent JPEG Group (IJG) table scaled to quality factor 1-100."""
    q = max(1, min(100, quality))
    scale = (5000.0 / q) if q < 50 else (200.0 - 2.0 * q)
    scaled = []
    for val in base_table:
        temp = (val * scale + 50.0) // 100.0
        clamped = max(1, min(255, int(temp)))
        scaled.append(clamped)
    return scaled


def estimate_ijg_quality(observed_table: List[int], is_chroma: bool = False) -> Tuple[int, float, bool]:
    """Estimates the closest IJG quality factor (1-100) for a given 64-element table.
    
    Returns:
        Tuple of (estimated_quality, mean_absolute_error, is_exact_match)
    """
    base = STD_CHROMINANCE_50 if is_chroma else STD_LUMINANCE_50
    best_q = 50
    min_mae = float("inf")

    for q in range(1, 101):
        candidate = scale_ijg_table(base, q)
        mae = sum(abs(o - c) for o, c in zip(observed_table, candidate)) / 64.0
        if mae < min_mae:
            min_mae = mae
            best_q = q
        if mae == 0.0:
            return q, 0.0, True

    return best_q, round(min_mae, 3), (min_mae == 0.0)


class QuantizationAnalysis(BaseModel):
    """Forensic report on JPEG quantization characteristics."""
    tables_count: int = 0
    estimated_quality: Optional[int] = None
    is_standard_ijg: bool = False
    is_custom_or_camera: bool = False
    table_qualities: Dict[int, int] = Field(default_factory=dict)
    mae_from_standard: Dict[int, float] = Field(default_factory=dict)
    all_ones: bool = False  # Quality 100 / lossless-like
    tables: Dict[int, List[int]] = Field(default_factory=dict)


class QuantizationAnalyzer(BaseAnalyzer):
    """Analyzes JPEG quantization tables to establish compression quality and encoder behavior."""

    name = "quantization"
    description = "JPEG quantization table analysis and quality estimation"
    version = "1.0.0"

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = QuantizationAnalysis()
        findings: List[Finding] = []

        jpeg_struct = context.get("jpeg_structure")
        if not jpeg_struct or not jpeg_struct.quantization_tables:
            return analysis.model_dump(), findings

        q_tables: Dict[int, QuantizationTable] = jpeg_struct.quantization_tables
        analysis.tables_count = len(q_tables)

        for tid, q_obj in q_tables.items():
            table_vals = q_obj.values_natural
            analysis.tables[tid] = table_vals
            is_chroma = (tid == 1)
            est_q, mae, exact = estimate_ijg_quality(table_vals, is_chroma=is_chroma)
            analysis.table_qualities[tid] = est_q
            analysis.mae_from_standard[tid] = mae

        # Luminance table is table 0
        if 0 in analysis.table_qualities:
            analysis.estimated_quality = analysis.table_qualities[0]
            analysis.is_standard_ijg = (analysis.mae_from_standard.get(0, 1.0) == 0.0)
            analysis.is_custom_or_camera = (analysis.mae_from_standard.get(0, 0.0) > 3.0)
            analysis.all_ones = all(v == 1 for v in analysis.tables[0])

        findings.append(
            Finding(
                category="JPEG_QUANTIZATION",
                status=FindingStatus.OBSERVED,
                severity=Severity.INFO,
                title="JPEG Quantization Tables extracted",
                description=(
                    f"Extracted {len(q_tables)} quantization table(s). Estimated IJG compression quality: "
                    f"~{analysis.estimated_quality}% (Table 0 MAE: {analysis.mae_from_standard.get(0, 0.0):.2f})."
                ),
                evidence=[
                    f"Quantization tables count: {len(q_tables)}",
                    f"Estimated quality factor: {analysis.estimated_quality}",
                    f"Standard IJG table match: {analysis.is_standard_ijg}",
                ],
                limitations=[
                    "Quality factor is an estimation based on standard IJG quantization scaling; non-standard encoders may use custom tables.",
                ],
            )
        )

        if analysis.is_custom_or_camera:
            findings.append(
                Finding(
                    category="JPEG_QUANTIZATION",
                    status=FindingStatus.DERIVED,
                    severity=Severity.LOW,
                    title="Non-standard / Camera-specific quantization table detected",
                    description=(
                        "The observed luminance quantization table deviates from standard IJG scaling curves "
                        "(MAE > 3.0). This is characteristic of camera firmware or proprietary encoder optimizations."
                    ),
                    evidence=[f"Luminance table MAE from IJG: {analysis.mae_from_standard.get(0, 0.0):.2f}"],
                    limitations=["Deviations from standard IJG tables do not alone identify the specific device model."],
                )
            )

        if analysis.estimated_quality is not None and analysis.estimated_quality < 70:
            findings.append(
                Finding(
                    category="JPEG_QUANTIZATION",
                    status=FindingStatus.DERIVED,
                    severity=Severity.LOW,
                    title="Low JPEG quality compression detected",
                    description=f"Estimated compression quality factor is low ({analysis.estimated_quality}%), typical of web optimization or messaging recompression.",
                    evidence=[f"Estimated quality: {analysis.estimated_quality}%"],
                )
            )

        return analysis.model_dump(), findings
