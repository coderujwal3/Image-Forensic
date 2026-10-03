"""Forensic chroma subsampling analyzer."""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ChromaSubsampling, FindingStatus, Severity
from forensic_image.core.findings import Finding
from forensic_image.forensics.base import BaseAnalyzer


class SubsamplingAnalysis(BaseModel):
    """Forensic report on color subsampling configuration."""
    subsampling: ChromaSubsampling = ChromaSubsampling.UNKNOWN
    is_chroma_downsampled: bool = False
    components_count: int = 0
    sampling_factors: Dict[str, str] = Field(default_factory=dict)


class SubsamplingAnalyzer(BaseAnalyzer):
    """Analyzes chroma component sampling factors from the JPEG frame header."""

    name = "subsampling"
    description = "Chroma subsampling analysis"
    version = "1.0.0"

    def analyze(self, evidence: Any, context: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Finding]]:
        analysis = SubsamplingAnalysis()
        findings: List[Finding] = []

        jpeg_struct = context.get("jpeg_structure")
        if not jpeg_struct or not jpeg_struct.frame_header:
            return analysis.model_dump(), findings

        fh = jpeg_struct.frame_header
        subsampling = fh.chroma_subsampling
        analysis.subsampling = subsampling
        analysis.components_count = fh.num_components

        for idx, comp in enumerate(fh.components):
            c_name = "Y" if idx == 0 else ("Cb" if idx == 1 else ("Cr" if idx == 2 else f"Comp_{comp.component_id}"))
            analysis.sampling_factors[c_name] = f"{comp.horizontal_sampling}x{comp.vertical_sampling}"

        analysis.is_chroma_downsampled = subsampling in (
            ChromaSubsampling.YUV420,
            ChromaSubsampling.YUV422,
            ChromaSubsampling.YUV440,
            ChromaSubsampling.YUV411,
        )

        findings.append(
            Finding(
                category="JPEG_SUBSAMPLING",
                status=FindingStatus.OBSERVED,
                severity=Severity.INFO,
                title=f"Chroma subsampling detected: {subsampling.value}",
                description=f"JPEG components configuration indicates {subsampling.value} subsampling scheme.",
                evidence=[
                    f"Components count: {fh.num_components}",
                    f"Sampling factors: {analysis.sampling_factors}",
                ],
            )
        )

        if subsampling == ChromaSubsampling.YUV444:
            findings.append(
                Finding(
                    category="JPEG_SUBSAMPLING",
                    status=FindingStatus.DERIVED,
                    severity=Severity.INFO,
                    title="High-fidelity 4:4:4 chroma configuration",
                    description=(
                        "Chroma is not downsampled (4:4:4). This is commonly observed in desktop graphics software, "
                        "high-quality exports, screenshots, or archival conversions, rather than typical smartphone capture."
                    ),
                    evidence=["Chroma channels (Cb, Cr) preserve full 1:1 spatial resolution with luma (Y)."],
                    limitations=["Some professional mirrorless cameras support 4:4:4 JPEG recording."],
                )
            )

        return analysis.model_dump(), findings
