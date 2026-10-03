"""Defensive binary parser for PNG containers and chunk validation."""

import zlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import SecurityLimits
from forensic_image.core.exceptions import CorruptEvidenceError
from forensic_image.core.reader import SafeBinaryReader
from forensic_image.formats.base import BinarySegment, ContainerStructure


class PNGChunk(BinarySegment):
    """Parsed PNG chunk with CRC validation status."""
    crc_declared: int = 0
    crc_computed: int = 0
    crc_valid: bool = True
    is_critical: bool = True
    is_ancillary: bool = False


class PNGIHDR(BaseModel):
    """Decoded PNG Image Header (IHDR)."""
    width: int
    height: int
    bit_depth: int
    color_type: int
    color_type_name: str
    compression_method: int
    filter_method: int
    interlace_method: int
    is_interlaced: bool


class PNGStructure(ContainerStructure):
    """Complete structural forensic analysis of a PNG file."""
    format_name: str = "PNG"
    has_valid_signature: bool = False
    has_ihdr: bool = False
    has_iend: bool = False
    ihdr: Optional[PNGIHDR] = None
    chunks: List[PNGChunk] = Field(default_factory=list)
    text_metadata: Dict[str, str] = Field(default_factory=dict)
    exif_raw_bytes: Optional[bytes] = None
    icc_raw_bytes: Optional[bytes] = None
    xmp_raw_string: Optional[str] = None
    crc_failures_count: int = 0


class PNGParser:
    """Zero-crash defensive PNG container parser."""

    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    COLOR_TYPES = {
        0: "Grayscale",
        2: "Truecolor (RGB)",
        3: "Indexed-color",
        4: "Grayscale with Alpha",
        6: "Truecolor with Alpha (RGBA)",
    }

    def parse(self, data: bytes) -> PNGStructure:
        structure = PNGStructure()
        reader = SafeBinaryReader(data)

        if reader.size < 8:
            structure.is_valid_container = False
            structure.anomalies.append("File size smaller than 8-byte PNG signature.")
            return structure

        sig = reader.read(8)
        if sig != self.PNG_SIGNATURE:
            structure.is_valid_container = False
            structure.anomalies.append(f"Invalid PNG signature: got {sig!r}.")
            return structure

        structure.has_valid_signature = True
        structure.segments.append(
            BinarySegment(
                name="SIGNATURE",
                offset=0,
                length=8,
                description="PNG 8-byte file signature",
            )
        )

        chunk_count = 0
        while not reader.is_eof():
            chunk_count += 1
            if chunk_count > SecurityLimits.MAX_SEGMENTS_COUNT:
                structure.anomalies.append(
                    f"Security threshold: chunk count exceeded {SecurityLimits.MAX_SEGMENTS_COUNT}."
                )
                break

            chunk_offset = reader.tell()
            if reader.remaining < 12:  # 4 (length) + 4 (type) + 4 (crc)
                structure.anomalies.append(
                    f"Truncated PNG: incomplete chunk header at offset {chunk_offset} ({reader.remaining} bytes left)."
                )
                break

            declared_length = reader.read_u32_be()
            chunk_type_bytes = reader.read(4)
            try:
                chunk_name = chunk_type_bytes.decode("ascii")
            except UnicodeDecodeError:
                chunk_name = f"CHUNK_{chunk_type_bytes.hex().upper()}"

            if reader.remaining < (declared_length + 4):
                structure.anomalies.append(
                    f"Truncated PNG chunk {chunk_name}: declared data {declared_length} bytes, available {reader.remaining - 4}."
                )
                break

            data_offset = reader.tell()
            chunk_data = reader.read(declared_length)
            crc_declared = reader.read_u32_be()

            # Validate CRC32
            computed_crc = zlib.crc32(chunk_type_bytes + chunk_data) & 0xFFFFFFFF
            crc_valid = (computed_crc == crc_declared)
            if not crc_valid:
                structure.crc_failures_count += 1
                structure.anomalies.append(
                    f"CRC32 mismatch in chunk {chunk_name} at offset {chunk_offset}: declared 0x{crc_declared:08X}, computed 0x{computed_crc:08X}."
                )

            is_critical = chunk_name[0].isupper()
            chunk_obj = PNGChunk(
                name=chunk_name,
                offset=chunk_offset,
                length=declared_length + 12,
                payload_offset=data_offset,
                payload_length=declared_length,
                crc_declared=crc_declared,
                crc_computed=computed_crc,
                crc_valid=crc_valid,
                is_critical=is_critical,
                is_ancillary=not is_critical,
            )

            # Specific chunk decoding
            try:
                if chunk_name == "IHDR":
                    self._parse_ihdr(chunk_data, structure, chunk_obj)
                elif chunk_name == "eXIf":
                    structure.exif_raw_bytes = chunk_data
                    chunk_obj.details["exif_bytes_len"] = len(chunk_data)
                elif chunk_name == "tEXt":
                    self._parse_text(chunk_data, structure, chunk_obj)
                elif chunk_name == "zTXt":
                    self._parse_ztxt(chunk_data, structure, chunk_obj)
                elif chunk_name == "iTXt":
                    self._parse_itxt(chunk_data, structure, chunk_obj)
                elif chunk_name == "iCCP":
                    self._parse_iccp(chunk_data, structure, chunk_obj)
                elif chunk_name == "IEND":
                    structure.has_iend = True
                    structure.chunks.append(chunk_obj)
                    structure.segments.append(chunk_obj)
                    
                    # Detect trailing bytes after IEND
                    iend_end_offset = reader.tell()
                    trailing = reader.remaining
                    if trailing > 0:
                        structure.has_trailing_data = True
                        structure.trailing_data_offset = iend_end_offset
                        structure.trailing_data_length = trailing
                        structure.anomalies.append(
                            f"Trailing payload detected after IEND: {trailing} bytes at offset {iend_end_offset}."
                        )
                    break
            except Exception as e:
                structure.anomalies.append(f"Error parsing chunk {chunk_name} at {chunk_offset}: {str(e)}")

            structure.chunks.append(chunk_obj)
            structure.segments.append(chunk_obj)

        if not structure.has_iend:
            structure.anomalies.append("Missing IEND chunk: PNG stream terminated abnormally.")

        return structure

    def _parse_ihdr(self, data: bytes, structure: PNGStructure, chunk: PNGChunk) -> None:
        if len(data) < 13:
            structure.anomalies.append(f"Invalid IHDR size: expected 13 bytes, got {len(data)}.")
            return

        reader = SafeBinaryReader(data)
        width = reader.read_u32_be()
        height = reader.read_u32_be()
        bit_depth = reader.read_u8()
        color_type = reader.read_u8()
        comp = reader.read_u8()
        filt = reader.read_u8()
        interlace = reader.read_u8()

        color_name = self.COLOR_TYPES.get(color_type, f"Unknown ({color_type})")
        ihdr = PNGIHDR(
            width=width,
            height=height,
            bit_depth=bit_depth,
            color_type=color_type,
            color_type_name=color_name,
            compression_method=comp,
            filter_method=filt,
            interlace_method=interlace,
            is_interlaced=(interlace == 1),
        )
        structure.ihdr = ihdr
        structure.has_ihdr = True
        chunk.details.update(ihdr.model_dump())

    def _parse_text(self, data: bytes, structure: PNGStructure, chunk: PNGChunk) -> None:
        null_idx = data.find(b"\x00")
        if null_idx != -1:
            key = data[:null_idx].decode("latin-1", errors="replace")
            val = data[null_idx + 1 :].decode("latin-1", errors="replace")
            structure.text_metadata[key] = val
            chunk.details["key"] = key
            chunk.details["value"] = val

    def _parse_ztxt(self, data: bytes, structure: PNGStructure, chunk: PNGChunk) -> None:
        null_idx = data.find(b"\x00")
        if null_idx != -1 and len(data) > null_idx + 2:
            key = data[:null_idx].decode("latin-1", errors="replace")
            # compression method byte is at null_idx + 1
            compressed = data[null_idx + 2 :]
            try:
                decompressed = zlib.decompress(compressed)
                val = decompressed.decode("latin-1", errors="replace")
                structure.text_metadata[key] = val
                chunk.details["key"] = key
                chunk.details["value"] = val
            except Exception:
                pass

    def _parse_itxt(self, data: bytes, structure: PNGStructure, chunk: PNGChunk) -> None:
        null_idx = data.find(b"\x00")
        if null_idx != -1 and len(data) > null_idx + 5:
            key = data[:null_idx].decode("utf-8", errors="replace")
            comp_flag = data[null_idx + 1]
            # null_idx + 2 is compression method
            # Then language tag terminated by null
            rest = data[null_idx + 3 :]
            lang_null = rest.find(b"\x00")
            if lang_null != -1:
                trans_rest = rest[lang_null + 1 :]
                trans_null = trans_rest.find(b"\x00")
                if trans_null != -1:
                    text_bytes = trans_rest[trans_null + 1 :]
                    if comp_flag == 1:
                        try:
                            text_bytes = zlib.decompress(text_bytes)
                        except Exception:
                            pass
                    val = text_bytes.decode("utf-8", errors="replace")
                    structure.text_metadata[key] = val
                    chunk.details["key"] = key
                    if key == "XML:com.adobe.xmp":
                        structure.xmp_raw_string = val

    def _parse_iccp(self, data: bytes, structure: PNGStructure, chunk: PNGChunk) -> None:
        null_idx = data.find(b"\x00")
        if null_idx != -1 and len(data) > null_idx + 2:
            prof_name = data[:null_idx].decode("latin-1", errors="replace")
            comp_data = data[null_idx + 2 :]
            try:
                raw_icc = zlib.decompress(comp_data)
                structure.icc_raw_bytes = raw_icc
                chunk.details["profile_name"] = prof_name
                chunk.details["icc_size"] = len(raw_icc)
            except Exception:
                pass
