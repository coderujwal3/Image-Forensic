"""Defensive binary parser for Google WebP (RIFF/VP8) containers."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import SecurityLimits
from forensic_image.core.reader import SafeBinaryReader
from forensic_image.formats.base import BinarySegment, ContainerStructure


class WebPChunk(BinarySegment):
    """Parsed WebP FourCC chunk."""
    fourcc: str
    padded_length: int = 0


class WebPVP8X(BaseModel):
    """VP8X Extended features header."""
    has_icc: bool = False
    has_alpha: bool = False
    has_exif: bool = False
    has_xmp: bool = False
    has_animation: bool = False
    canvas_width: int = 0
    canvas_height: int = 0


class WebPStructure(ContainerStructure):
    """Complete structural forensic analysis of a WebP container."""
    format_name: str = "WEBP"
    has_riff: bool = False
    has_webp_header: bool = False
    declared_riff_size: int = 0
    actual_file_size: int = 0
    vp8x: Optional[WebPVP8X] = None
    chunks: List[WebPChunk] = Field(default_factory=list)
    exif_raw_bytes: Optional[bytes] = None
    xmp_raw_bytes: Optional[bytes] = None
    icc_raw_bytes: Optional[bytes] = None


class WebPParser:
    """Zero-crash defensive WebP parser."""

    def parse(self, data: bytes) -> WebPStructure:
        structure = WebPStructure()
        reader = SafeBinaryReader(data)
        structure.actual_file_size = reader.size

        if reader.size < 12:
            structure.is_valid_container = False
            structure.anomalies.append("File size smaller than 12-byte WebP header.")
            return structure

        riff = reader.read(4)
        if riff != b"RIFF":
            structure.is_valid_container = False
            structure.anomalies.append(f"Invalid RIFF header: expected b'RIFF', got {riff!r}.")
            return structure
        structure.has_riff = True

        riff_size = reader.read_u32_le()
        structure.declared_riff_size = riff_size

        webp_sig = reader.read(4)
        if webp_sig != b"WEBP":
            structure.is_valid_container = False
            structure.anomalies.append(f"Invalid WebP FourCC: expected b'WEBP', got {webp_sig!r}.")
            return structure
        structure.has_webp_header = True

        expected_total = riff_size + 8
        if expected_total < reader.size:
            structure.has_trailing_data = True
            structure.trailing_data_offset = expected_total
            structure.trailing_data_length = reader.size - expected_total
            structure.anomalies.append(
                f"Trailing payload detected after WebP RIFF: {structure.trailing_data_length} bytes at offset {expected_total}."
            )
        elif expected_total > reader.size:
            structure.anomalies.append(
                f"WebP container truncated: RIFF declared {expected_total} bytes, but actual size is {reader.size}."
            )

        chunk_count = 0
        while not reader.is_eof():
            chunk_count += 1
            if chunk_count > SecurityLimits.MAX_SEGMENTS_COUNT:
                structure.anomalies.append(
                    f"Security threshold: WebP chunk count exceeded {SecurityLimits.MAX_SEGMENTS_COUNT}."
                )
                break

            chunk_offset = reader.tell()
            if reader.remaining < 8:
                if reader.remaining > 0:
                    structure.anomalies.append(f"Trailing incomplete chunk header at offset {chunk_offset}.")
                break

            fourcc_bytes = reader.read(4)
            fourcc = fourcc_bytes.decode("ascii", errors="replace")
            chunk_payload_size = reader.read_u32_le()

            padded_payload_size = chunk_payload_size + (chunk_payload_size % 2)

            if reader.remaining < chunk_payload_size:
                structure.anomalies.append(
                    f"Truncated WebP chunk {fourcc}: declared {chunk_payload_size} bytes, available {reader.remaining}."
                )
                break

            payload_offset = reader.tell()
            chunk_data = reader.read(chunk_payload_size)

            # Consume padding byte if present
            if chunk_payload_size % 2 == 1 and not reader.is_eof():
                reader.read(1)

            chunk = WebPChunk(
                name=fourcc.strip(),
                fourcc=fourcc,
                offset=chunk_offset,
                length=8 + padded_payload_size,
                payload_offset=payload_offset,
                payload_length=chunk_payload_size,
                padded_length=padded_payload_size,
            )

            if fourcc == "VP8X":
                self._parse_vp8x(chunk_data, structure, chunk)
            elif fourcc == "EXIF":
                structure.exif_raw_bytes = chunk_data
                chunk.details["size"] = len(chunk_data)
            elif fourcc == "XMP ":
                structure.xmp_raw_bytes = chunk_data
                chunk.details["size"] = len(chunk_data)
            elif fourcc == "ICCP":
                structure.icc_raw_bytes = chunk_data
                chunk.details["size"] = len(chunk_data)

            structure.chunks.append(chunk)
            structure.segments.append(chunk)

        return structure

    def _parse_vp8x(self, data: bytes, structure: WebPStructure, chunk: WebPChunk) -> None:
        if len(data) < 10:
            return
        flags = data[0]
        has_icc = bool(flags & 0x20)
        has_alpha = bool(flags & 0x10)
        has_exif = bool(flags & 0x08)
        has_xmp = bool(flags & 0x04)
        has_animation = bool(flags & 0x02)

        # 24-bit canvas dimensions (1-based: value + 1)
        width_minus_one = data[4] | (data[5] << 8) | (data[6] << 16)
        height_minus_one = data[7] | (data[8] << 8) | (data[9] << 16)
        width = width_minus_one + 1
        height = height_minus_one + 1

        vp8x = WebPVP8X(
            has_icc=has_icc,
            has_alpha=has_alpha,
            has_exif=has_exif,
            has_xmp=has_xmp,
            has_animation=has_animation,
            canvas_width=width,
            canvas_height=height,
        )
        structure.vp8x = vp8x
        chunk.details.update(vp8x.model_dump())
