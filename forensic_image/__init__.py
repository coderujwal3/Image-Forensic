"""Forensic Image Intelligence Library.

A professional-grade, evidence-driven digital image forensics, evidence preservation,
and provenance analysis framework.
"""

from pathlib import Path
from typing import Optional, Union

from forensic_image.core.constants import (
    ChromaSubsampling,
    ConfidenceLevel,
    FindingStatus,
    ImageFormat,
    Severity,
)
from forensic_image.core.evidence import ImageEvidence
from forensic_image.core.exceptions import (
    ChainOfCustodyError,
    CorruptEvidenceError,
    DecompressionBombError,
    ForensicError,
    MalformedSegmentError,
    SecurityThresholdError,
    UnsupportedFormatError,
    VerificationError,
)
from forensic_image.core.findings import Finding, FindingsList
from forensic_image.core.manifest import EvidenceManifest
from forensic_image.core.report import ForensicReport
from forensic_image.forensics.base import BaseAnalyzer
from forensic_image.forensics.registry import AnalyzerRegistry, default_registry
from forensic_image.hashing.cryptographic import (
    CryptographicHashes,
    compute_cryptographic_hashes,
)
from forensic_image.hashing.perceptual import (
    PerceptualHashes,
    compute_ahash,
    compute_dhash,
    compute_phash,
    compute_whash,
    hamming_distance,
    perceptual_similarity,
)
from forensic_image.version import TOOL_NAME, __version__


def analyze(
    source: Union[str, Path, bytes, bytearray],
    metadata: bool = True,
    jpeg: bool = True,
    hashes: bool = True,
    similarity: bool = True,
    quantization: bool = True,
    subsampling: bool = True,
    recompression: bool = True,
    transformation: bool = True,
    tampering: bool = True,
    screenshot: bool = True,
    pixel: bool = False,
    profiles: bool = True,
    provenance: bool = True,
    operator: str = "Forensic Analyst",
) -> ForensicReport:
    """Primary high-level API for digital image forensic analysis.
    
    Args:
        source: File path (str/Path) or raw byte buffer (bytes/bytearray).
        metadata: Parse EXIF, GPS, XMP, IPTC, and ICC metadata.
        jpeg: Perform deep JPEG container inspection and marker parsing.
        hashes: Compute MD5, SHA-1, SHA-256, SHA-512 cryptographic digests.
        similarity: Calculate perceptual visual hashes (pHash, dHash, aHash, wHash).
        quantization: Analyze DQT tables and estimate IJG quality factor.
        subsampling: Analyze chroma component sampling factors (4:2:0, 4:4:4, etc.).
        recompression: Check for double compression and DCT coefficient artifacts.
        transformation: Check for resizing, downscaling, and aspect ratio cropping.
        tampering: Detect metadata vs pixel discrepancies and container trailing bytes.
        screenshot: Check for native screen resolutions and screenshot signatures.
        pixel: Execute experimental Error Level Analysis (ELA) and noise variance.
        profiles: Compare against reference platform profiles.
        provenance: Synthesize an evidence-based timeline hypothesis.
        operator: Investigator/operator name for custody audit trail.
        
    Returns:
        Structured ForensicReport object.
    """
    evidence = ImageEvidence(source, operator=operator)
    return evidence.analyze(
        metadata=metadata,
        jpeg=jpeg,
        hashes=hashes,
        similarity=similarity,
        quantization=quantization,
        subsampling=subsampling,
        recompression=recompression,
        transformation=transformation,
        tampering=tampering,
        screenshot=screenshot,
        pixel=pixel,
        profiles=profiles,
        provenance=provenance,
        operator=operator,
    )


def verify(source: Union[str, Path, bytes, bytearray], expected_sha256: str) -> bool:
    """Verifies that the target image exactly matches the expected SHA-256 digest."""
    evidence = ImageEvidence(source)
    return evidence.verify(expected_sha256)


__all__ = [
    "TOOL_NAME",
    "__version__",
    "analyze",
    "verify",
    "ImageEvidence",
    "ForensicReport",
    "Finding",
    "FindingsList",
    "FindingStatus",
    "Severity",
    "ConfidenceLevel",
    "ImageFormat",
    "ChromaSubsampling",
    "EvidenceManifest",
    "CryptographicHashes",
    "PerceptualHashes",
    "compute_cryptographic_hashes",
    "compute_phash",
    "compute_dhash",
    "compute_ahash",
    "compute_whash",
    "hamming_distance",
    "perceptual_similarity",
    "BaseAnalyzer",
    "AnalyzerRegistry",
    "default_registry",
    "ForensicError",
    "CorruptEvidenceError",
    "SecurityThresholdError",
    "DecompressionBombError",
    "UnsupportedFormatError",
    "MalformedSegmentError",
    "VerificationError",
    "ChainOfCustodyError",
]
