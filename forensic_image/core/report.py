"""Complete structured forensic report model and serialization engine."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus, ImageFormat, Severity
from forensic_image.core.findings import Finding, FindingsList
from forensic_image.core.manifest import EvidenceManifest
from forensic_image.formats.base import ContainerStructure
from forensic_image.formats.jpeg import JPEGStructure
from forensic_image.hashing.cryptographic import CryptographicHashes
from forensic_image.hashing.perceptual import PerceptualHashes
from forensic_image.metadata.exif import EXIFData
from forensic_image.metadata.icc import ICCData
from forensic_image.metadata.iptc import IPTCData
from forensic_image.metadata.thumbnail import ThumbnailDetails
from forensic_image.metadata.xmp import XMPData
from forensic_image.profiles.matcher import ProfileMatchResult


class FileOverview(BaseModel):
    """Basic physical and container metrics of the evidence file."""
    filename: str
    size_bytes: int
    mime_type: str
    format: str
    width: int = 0
    height: int = 0
    megapixels: float = 0.0
    aspect_ratio: float = 0.0


class MetadataOverview(BaseModel):
    """Unified container for all parsed metadata domains."""
    exif: EXIFData = Field(default_factory=EXIFData)
    xmp: XMPData = Field(default_factory=XMPData)
    iptc: IPTCData = Field(default_factory=IPTCData)
    icc: ICCData = Field(default_factory=ICCData)


class ForensicReport(BaseModel):
    """The master forensic investigation report."""
    report_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    manifest: EvidenceManifest
    file: FileOverview
    hashes: CryptographicHashes
    similarity: PerceptualHashes
    metadata: MetadataOverview = Field(default_factory=MetadataOverview)
    thumbnail: ThumbnailDetails = Field(default_factory=ThumbnailDetails)
    container_structure: Optional[ContainerStructure] = None
    jpeg: Optional[JPEGStructure] = None
    findings: FindingsList = Field(default_factory=FindingsList)
    quantization: Dict[str, Any] = Field(default_factory=dict)
    subsampling: Dict[str, Any] = Field(default_factory=dict)
    recompression: Dict[str, Any] = Field(default_factory=dict)
    transformation: Dict[str, Any] = Field(default_factory=dict)
    tampering: Dict[str, Any] = Field(default_factory=dict)
    screenshot: Dict[str, Any] = Field(default_factory=dict)
    pixel: Dict[str, Any] = Field(default_factory=dict)
    profile_matches: List[ProfileMatchResult] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)

    def to_json(self, indent: int = 2) -> str:
        """Serializes report to structured JSON."""
        return self.model_dump_json(indent=indent)

    def save_json(self, target_path: str) -> None:
        """Saves report to a JSON file."""
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    def save_html(self, target_path: str, title: Optional[str] = None) -> None:
        """Generates and saves a modern interactive HTML report."""
        from forensic_image.reporting.html_reporter import HTMLReporter
        reporter = HTMLReporter()
        html_content = reporter.render(self, title=title)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def __str__(self) -> str:
        """Terminal-friendly string summary."""
        from forensic_image.reporting.terminal import TerminalReporter
        return TerminalReporter().render_to_string(self)
