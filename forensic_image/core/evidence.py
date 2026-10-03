"""Core ImageEvidence representation ensuring immutable evidence preservation."""

import io
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
from PIL import Image

from forensic_image.core.constants import FindingStatus, ImageFormat, SecurityLimits, Severity
from forensic_image.core.exceptions import (
    CorruptEvidenceError,
    DecompressionBombError,
    SecurityThresholdError,
    VerificationError,
)
from forensic_image.core.findings import Finding, FindingsList
from forensic_image.core.manifest import EvidenceManifest
from forensic_image.core.reader import SafeBinaryReader
from forensic_image.core.report import FileOverview, ForensicReport, MetadataOverview
from forensic_image.formats.base import ContainerStructure
from forensic_image.formats.detector import detect_image_format
from forensic_image.formats.jpeg import JPEGParser, JPEGStructure
from forensic_image.formats.png import PNGParser, PNGStructure
from forensic_image.formats.webp import WebPParser, WebPStructure
from forensic_image.hashing.cryptographic import (
    CryptographicHashes,
    compute_cryptographic_hashes,
)
from forensic_image.hashing.perceptual import (
    PerceptualHashes,
    compute_perceptual_hashes,
)
from forensic_image.metadata.exif import EXIFData, EXIFParser
from forensic_image.metadata.icc import ICCData, ICCParser
from forensic_image.metadata.iptc import IPTCData, IPTCParser
from forensic_image.metadata.thumbnail import ThumbnailDetails, ThumbnailForensics
from forensic_image.metadata.xmp import XMPData, XMPParser
from forensic_image.profiles.matcher import ProfileMatcher, ProfileMatchResult


# Enforce decompression bomb defense globally in Pillow
Image.MAX_IMAGE_PIXELS = SecurityLimits.MAX_TOTAL_PIXELS


class ImageEvidence:
    """Immutable forensic evidence representation of a digital image.
    
    Principles:
    1. Read original bytes once.
    2. Compute SHA-256 and cryptographic digests immediately.
    3. Never alter or mutate evidence bytes.
    4. Provide bounded, defensive readers for parser execution.
    """

    def __init__(
        self,
        source: Union[str, Path, bytes, bytearray],
        filename: Optional[str] = None,
        acquisition_source: str = "Local filesystem",
        operator: str = "Forensic Analyst",
    ) -> None:
        if isinstance(source, (str, Path)):
            path = Path(source).resolve()
            if not path.exists():
                raise FileNotFoundError(f"Evidence file not found: {path}")
            if not path.is_file():
                raise ValueError(f"Path is not a regular file: {path}")
            
            size = path.stat().st_size
            if size > SecurityLimits.MAX_FILE_SIZE_BYTES:
                raise SecurityThresholdError(
                    f"File size {size} exceeds threshold {SecurityLimits.MAX_FILE_SIZE_BYTES} bytes."
                )
            with open(path, "rb") as f:
                self._bytes: bytes = f.read()
            self._filename = filename or path.name
            self._source_path = str(path)
        elif isinstance(source, (bytes, bytearray)):
            if len(source) > SecurityLimits.MAX_FILE_SIZE_BYTES:
                raise SecurityThresholdError(
                    f"Byte size {len(source)} exceeds threshold {SecurityLimits.MAX_FILE_SIZE_BYTES} bytes."
                )
            self._bytes = bytes(source)
            self._filename = filename or f"memory_evidence_{uuid.uuid4().hex[:8]}.bin"
            self._source_path = None
        else:
            raise TypeError(f"Unsupported evidence source type: {type(source)}")

        # 1. Hashing
        self._hashes = compute_cryptographic_hashes(self._bytes)
        self._evidence_id = f"EVID-{self._hashes.sha256[:16].upper()}"

        # 2. Format Detection
        self._format, self._mime_type = detect_image_format(self._bytes)

        # 3. Evidence Manifest & Custody Tracking
        self._manifest = EvidenceManifest(
            evidence_id=self._evidence_id,
            filename=self._filename,
            acquisition_source=acquisition_source,
            hashes=self._hashes,
        )
        self._manifest.record_event(
            action="ACQUIRED",
            operator=operator,
            filename=self._filename,
            size_bytes=self._hashes.size_bytes,
            sha256=self._hashes.sha256,
        )

        # 4. Safe image decoding for dimensions and pixel forensics
        self._dimensions = (0, 0)
        self._pil_img: Optional[Image.Image] = None
        self._load_pil_safely()

    @property
    def raw_bytes(self) -> bytes:
        """Immutable copy of original evidence bytes."""
        return self._bytes

    @property
    def hashes(self) -> CryptographicHashes:
        return self._hashes

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def format(self) -> ImageFormat:
        return self._format

    @property
    def mime_type(self) -> str:
        return self._mime_type

    @property
    def dimensions(self) -> Tuple[int, int]:
        return self._dimensions

    @property
    def image(self) -> Optional[Image.Image]:
        return self._pil_img

    def get_reader(self) -> SafeBinaryReader:
        """Returns a bounds-checked SafeBinaryReader over evidence bytes."""
        return SafeBinaryReader(self._bytes)

    def verify(self, expected_sha256: str) -> bool:
        """Verifies integrity of the evidence against an expected SHA-256 hash."""
        is_valid = self._hashes.sha256.lower() == expected_sha256.strip().lower()
        if not is_valid:
            raise VerificationError(
                f"Integrity check failed! Expected SHA-256 {expected_sha256}, computed {self._hashes.sha256}."
            )
        return True

    def _load_pil_safely(self) -> None:
        try:
            bio = io.BytesIO(self._bytes)
            img = Image.open(bio)
            w, h = img.size
            if w > SecurityLimits.MAX_IMAGE_DIMENSION or h > SecurityLimits.MAX_IMAGE_DIMENSION:
                raise DecompressionBombError(
                    f"Image dimension ({w}x{h}) exceeds safe threshold {SecurityLimits.MAX_IMAGE_DIMENSION}px."
                )
            if (w * h) > SecurityLimits.MAX_TOTAL_PIXELS:
                raise DecompressionBombError(
                    f"Total pixels ({w * h}) exceeds safe threshold {SecurityLimits.MAX_TOTAL_PIXELS}."
                )
            self._dimensions = (w, h)
            self._pil_img = img
        except Exception:
            # Container might still be partially inspectable even if PIL cannot decode pixels
            pass

    def analyze(
        self,
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
        pixel: bool = False,  # Off by default (experimental)
        profiles: bool = True,
        provenance: bool = True,
        operator: str = "Forensic Analyst",
    ) -> ForensicReport:
        """Runs the digital image forensic analysis pipeline."""
        report_id = f"REP-{uuid.uuid4().hex[:12].upper()}"
        findings = FindingsList()

        w, h = self._dimensions
        ar = round(w / h, 3) if h > 0 else 0.0
        mp = round((w * h) / 1_000_000.0, 2)

        file_overview = FileOverview(
            filename=self._filename,
            size_bytes=self._hashes.size_bytes,
            mime_type=self._mime_type,
            format=self._format.value,
            width=w,
            height=h,
            megapixels=mp,
            aspect_ratio=ar,
        )

        findings.add(
            Finding(
                category="INTEGRITY",
                status=FindingStatus.DERIVED,
                severity=Severity.INFO,
                title="Cryptographic evidence identifier established",
                description=f"Evidence authenticated with SHA-256 digest: {self._hashes.sha256}",
                evidence=[
                    f"SHA-256: {self._hashes.sha256}",
                    f"MD5: {self._hashes.md5}",
                    f"Byte size: {self._hashes.size_bytes}",
                ],
            )
        )

        # 1. Similarity / Perceptual Hashes
        p_hashes = PerceptualHashes()
        if similarity and self._pil_img:
            p_hashes = compute_perceptual_hashes(self._pil_img)

        # 2. Container & Binary Parsing
        container_struct: Optional[ContainerStructure] = None
        jpeg_struct: Optional[JPEGStructure] = None
        raw_exif_bytes: Optional[bytes] = None
        raw_xmp_data: Optional[Any] = None
        raw_icc_bytes: Optional[bytes] = None
        raw_app13_bytes: Optional[bytes] = None

        if self._format == ImageFormat.JPEG and jpeg:
            j_parser = JPEGParser()
            jpeg_struct = j_parser.parse(self._bytes)
            container_struct = jpeg_struct

            # Extract metadata chunks from JPEG segments
            for seg in jpeg_struct.segments:
                if seg.name == "APP1" and seg.payload_offset and seg.payload_length:
                    payload = self._bytes[seg.payload_offset : seg.payload_offset + seg.payload_length]
                    if payload.startswith(b"Exif\x00\x00") and not raw_exif_bytes:
                        raw_exif_bytes = payload[6:]  # TIFF header starts after "Exif\0\0"
                    elif payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00") and not raw_xmp_data:
                        raw_xmp_data = payload[29:]
                elif seg.name == "APP2" and seg.payload_offset and seg.payload_length:
                    payload = self._bytes[seg.payload_offset : seg.payload_offset + seg.payload_length]
                    if payload.startswith(b"ICC_PROFILE\x00") and not raw_icc_bytes:
                        # 12-byte header: ICC_PROFILE\0 + seq(1) + count(1)
                        if len(payload) > 14:
                            raw_icc_bytes = payload[14:]
                elif seg.name == "APP13" and seg.payload_offset and seg.payload_length:
                    payload = self._bytes[seg.payload_offset : seg.payload_offset + seg.payload_length]
                    if payload.startswith(b"Photoshop 3.0\x00"):
                        raw_app13_bytes = payload

            # Record JPEG container anomalies into findings
            for anom in jpeg_struct.anomalies:
                findings.add(
                    Finding(
                        category="FILE_STRUCTURE",
                        status=FindingStatus.OBSERVED,
                        severity=Severity.HIGH if "Trailing" in anom or "Truncated" in anom else Severity.LOW,
                        title="JPEG container anomaly detected",
                        description=anom,
                        evidence=[anom],
                    )
                )

        elif self._format == ImageFormat.PNG:
            png_parser = PNGParser()
            png_struct = png_parser.parse(self._bytes)
            container_struct = png_struct
            raw_exif_bytes = png_struct.exif_raw_bytes
            raw_xmp_data = png_struct.xmp_raw_string
            raw_icc_bytes = png_struct.icc_raw_bytes

            for anom in png_struct.anomalies:
                findings.add(
                    Finding(
                        category="FILE_STRUCTURE",
                        status=FindingStatus.OBSERVED,
                        severity=Severity.HIGH if "Trailing" in anom or "CRC" in anom else Severity.LOW,
                        title="PNG container anomaly detected",
                        description=anom,
                        evidence=[anom],
                    )
                )

        elif self._format == ImageFormat.WEBP:
            webp_parser = WebPParser()
            webp_struct = webp_parser.parse(self._bytes)
            container_struct = webp_struct
            raw_exif_bytes = webp_struct.exif_raw_bytes
            raw_xmp_data = webp_struct.xmp_raw_bytes
            raw_icc_bytes = webp_struct.icc_raw_bytes

            for anom in webp_struct.anomalies:
                findings.add(
                    Finding(
                        category="FILE_STRUCTURE",
                        status=FindingStatus.OBSERVED,
                        severity=Severity.HIGH if "Trailing" in anom else Severity.LOW,
                        title="WebP container anomaly detected",
                        description=anom,
                        evidence=[anom],
                    )
                )

        # 3. Metadata Parsing
        meta_overview = MetadataOverview()
        if metadata:
            # EXIF
            if raw_exif_bytes:
                meta_overview.exif = EXIFParser().parse(raw_exif_bytes)
                findings.add(
                    Finding(
                        category="METADATA",
                        status=FindingStatus.OBSERVED,
                        severity=Severity.INFO,
                        title="EXIF metadata extracted",
                        description=(
                            f"EXIF present. Device: {meta_overview.exif.make or 'Unknown'} {meta_overview.exif.model or ''}. "
                            f"Capture timestamp: {meta_overview.exif.date_time_original or 'None'}."
                        ),
                        evidence=[
                            f"Make: {meta_overview.exif.make}",
                            f"Model: {meta_overview.exif.model}",
                            f"Software: {meta_overview.exif.software}",
                        ],
                    )
                )
                if meta_overview.exif.gps.has_coordinates:
                    findings.add(
                        Finding(
                            category="METADATA",
                            status=FindingStatus.OBSERVED,
                            severity=Severity.INFO,
                            title="GPS coordinates recovered",
                            description=(
                                f"Precise geolocation coordinates recovered: "
                                f"{meta_overview.exif.gps.latitude}, {meta_overview.exif.gps.longitude}."
                            ),
                            evidence=[
                                f"Latitude: {meta_overview.exif.gps.latitude}",
                                f"Longitude: {meta_overview.exif.gps.longitude}",
                                f"Altitude: {meta_overview.exif.gps.altitude_m}m",
                            ],
                        )
                    )
                else:
                    findings.add(
                        Finding(
                            category="METADATA",
                            status=FindingStatus.NOT_AVAILABLE,
                            severity=Severity.INFO,
                            title="No GPS metadata present",
                            description="No GPS geolocation coordinates were located in the supplied evidence.",
                            limitations=["Stripped GPS data cannot be reconstructed from pixels alone."],
                        )
                    )
            else:
                findings.add(
                    Finding(
                        category="METADATA",
                        status=FindingStatus.NOT_AVAILABLE,
                        severity=Severity.INFO,
                        title="EXIF metadata absent",
                        description="No standard EXIF metadata payload exists in the examined image container.",
                        limitations=["Stripped EXIF metadata cannot be reconstructed from pixel payload."],
                    )
                )

            # XMP
            if raw_xmp_data:
                meta_overview.xmp = XMPParser().parse(raw_xmp_data)

            # IPTC
            if raw_app13_bytes:
                meta_overview.iptc = IPTCParser().parse(raw_app13_bytes)

            # ICC
            if raw_icc_bytes:
                meta_overview.icc = ICCParser().parse(raw_icc_bytes)

        # 4. Embedded Thumbnail Analysis
        thumb_details = ThumbnailDetails()
        if meta_overview.exif.thumbnail_bytes:
            thumb_details, thumb_findings = ThumbnailForensics().analyze(
                meta_overview.exif.thumbnail_bytes,
                self._pil_img,
                source_type="EXIF_IFD1",
            )
            for tf in thumb_findings:
                findings.add(tf)

        # Context dictionary for forensic analyzers
        analyzer_context: Dict[str, Any] = {
            "jpeg_structure": jpeg_struct,
            "container_structure": container_struct,
            "exif": meta_overview.exif.model_dump(),
            "xmp": meta_overview.xmp.model_dump(),
            "iptc": meta_overview.iptc.model_dump(),
            "icc": meta_overview.icc.model_dump(),
            "thumbnail": thumb_details.model_dump(),
        }

        # 5. Specialized Forensic Analyzers
        from forensic_image.forensics.pixel import PixelForensicAnalyzer
        from forensic_image.forensics.provenance import ProvenanceAnalyzer
        from forensic_image.forensics.quantization import QuantizationAnalyzer
        from forensic_image.forensics.recompression import RecompressionAnalyzer
        from forensic_image.forensics.screenshot import ScreenshotAnalyzer
        from forensic_image.forensics.subsampling import SubsamplingAnalyzer
        from forensic_image.forensics.tampering import TamperingAnalyzer
        from forensic_image.forensics.transformation import TransformationAnalyzer

        quant_res = {}
        if quantization and jpeg_struct:
            quant_res, q_findings = QuantizationAnalyzer().analyze(self, analyzer_context)
            analyzer_context["quantization"] = quant_res
            for f in q_findings:
                findings.add(f)

        sub_res = {}
        if subsampling and jpeg_struct:
            sub_res, s_findings = SubsamplingAnalyzer().analyze(self, analyzer_context)
            analyzer_context["subsampling"] = sub_res
            for f in s_findings:
                findings.add(f)

        trans_res = {}
        if transformation:
            trans_res, t_findings = TransformationAnalyzer().analyze(self, analyzer_context)
            analyzer_context["transformation"] = trans_res
            for f in t_findings:
                findings.add(f)

        tamper_res = {}
        if tampering:
            tamper_res, m_findings = TamperingAnalyzer().analyze(self, analyzer_context)
            analyzer_context["tampering"] = tamper_res
            for f in m_findings:
                findings.add(f)

        screen_res = {}
        if screenshot:
            screen_res, sc_findings = ScreenshotAnalyzer().analyze(self, analyzer_context)
            analyzer_context["screenshot"] = screen_res
            for f in sc_findings:
                findings.add(f)

        recomp_res = {}
        if recompression:
            recomp_res, rc_findings = RecompressionAnalyzer().analyze(self, analyzer_context)
            analyzer_context["recompression"] = recomp_res
            for f in rc_findings:
                findings.add(f)

        pixel_res = {}
        if pixel:
            pixel_res, px_findings = PixelForensicAnalyzer().analyze(self, analyzer_context)
            analyzer_context["pixel"] = pixel_res
            for f in px_findings:
                findings.add(f)

        # 6. Platform Reference Profile Matching
        profile_matches: List[ProfileMatchResult] = []
        if profiles:
            matcher = ProfileMatcher()
            obs_features = {
                "format": self._format.value,
                "width": w,
                "height": h,
                "chroma_subsampling": sub_res.get("subsampling"),
                "has_exif": meta_overview.exif.is_present,
                "has_gps": meta_overview.exif.gps.has_coordinates,
                "estimated_quality": quant_res.get("estimated_quality"),
                "is_progressive": getattr(jpeg_struct, "is_progressive", False) if jpeg_struct else False,
            }
            profile_matches = matcher.evaluate(obs_features)
            top_match = profile_matches[0] if profile_matches else None
            if top_match and top_match.consistency_score >= 0.70:
                findings.add(
                    Finding(
                        category="PLATFORM_PROFILE",
                        status=FindingStatus.INFERRED,
                        severity=Severity.INFO,
                        title=f"Characteristics consistent with reference profile '{top_match.display_name}'",
                        description=top_match.interpretation,
                        evidence=top_match.matched_features,
                        confidence=top_match.consistency_score,
                        limitations=top_match.limitations,
                    )
                )

        # 7. Provenance & Timeline Hypothesis
        prov_res = {}
        if provenance:
            prov_res, pr_findings = ProvenanceAnalyzer().analyze(self, analyzer_context)
            for f in pr_findings:
                findings.add(f)

        self._manifest.record_event(
            action="ANALYZED",
            operator=operator,
            report_id=report_id,
            findings_count=findings.count,
        )

        return ForensicReport(
            report_id=report_id,
            manifest=self._manifest,
            file=file_overview,
            hashes=self._hashes,
            similarity=p_hashes,
            metadata=meta_overview,
            thumbnail=thumb_details,
            container_structure=container_struct,
            jpeg=jpeg_struct,
            findings=findings,
            quantization=quant_res,
            subsampling=sub_res,
            recompression=recomp_res,
            transformation=trans_res,
            tampering=tamper_res,
            screenshot=screen_res,
            pixel=pixel_res,
            profile_matches=profile_matches,
            provenance=prov_res,
        )
