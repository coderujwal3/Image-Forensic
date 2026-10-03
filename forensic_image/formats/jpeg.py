"""Defensive binary parser for JPEG (JFIF/EXIF) image containers."""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from forensic_image.core.constants import ChromaSubsampling, JPEGMarker, SecurityLimits
from forensic_image.core.exceptions import CorruptEvidenceError
from forensic_image.core.reader import SafeBinaryReader
from forensic_image.formats.base import BinarySegment, ContainerStructure


# Zigzag sequence for 8x8 DCT matrix reordering
ZIGZAG_ORDER = [
     0,  1,  5,  6, 14, 15, 27, 28,
     2,  4,  7, 13, 16, 26, 29, 42,
     3,  8, 12, 17, 25, 30, 41, 43,
     9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63
]


class QuantizationTable(BaseModel):
    """Parsed JPEG Quantization Table (DQT)."""
    table_id: int
    precision_bits: int  # 8 or 16
    values_zigzag: List[int]
    values_natural: List[int]  # 8x8 matrix flattened in row-major order

    @property
    def matrix_8x8(self) -> List[List[int]]:
        return [self.values_natural[i * 8 : (i + 1) * 8] for i in range(8)]


class HuffmanTable(BaseModel):
    """Parsed JPEG Huffman Table (DHT)."""
    table_class: int  # 0 = DC, 1 = AC
    table_id: int     # 0 to 3
    num_codes_by_length: List[int]  # 16 counts for lengths 1 to 16
    total_codes: int


class JPEGComponent(BaseModel):
    """Component configuration within JPEG frame (SOF)."""
    component_id: int
    horizontal_sampling: int
    vertical_sampling: int
    quantization_table_id: int


class JPEGFrameHeader(BaseModel):
    """SOF (Start of Frame) Header."""
    marker_name: str
    marker_code: int
    precision: int
    height: int
    width: int
    num_components: int
    components: List[JPEGComponent] = Field(default_factory=list)

    @property
    def chroma_subsampling(self) -> ChromaSubsampling:
        if self.num_components == 1:
            return ChromaSubsampling.GRAYSCALE
        if self.num_components >= 3:
            # Component 0 is Y, Component 1 is Cb, Component 2 is Cr
            y_comp = self.components[0]
            cb_comp = self.components[1]
            cr_comp = self.components[2]
            
            # Standard ratio relative to Y
            if y_comp.horizontal_sampling == 2 and y_comp.vertical_sampling == 2:
                if cb_comp.horizontal_sampling == 1 and cb_comp.vertical_sampling == 1:
                    return ChromaSubsampling.YUV420
            elif y_comp.horizontal_sampling == 2 and y_comp.vertical_sampling == 1:
                if cb_comp.horizontal_sampling == 1 and cb_comp.vertical_sampling == 1:
                    return ChromaSubsampling.YUV422
            elif y_comp.horizontal_sampling == 1 and y_comp.vertical_sampling == 1:
                if cb_comp.horizontal_sampling == 1 and cb_comp.vertical_sampling == 1:
                    return ChromaSubsampling.YUV444
            elif y_comp.horizontal_sampling == 1 and y_comp.vertical_sampling == 2:
                if cb_comp.horizontal_sampling == 1 and cb_comp.vertical_sampling == 1:
                    return ChromaSubsampling.YUV440
            elif y_comp.horizontal_sampling == 4 and y_comp.vertical_sampling == 1:
                return ChromaSubsampling.YUV411
        return ChromaSubsampling.UNKNOWN


class JPEGStructure(ContainerStructure):
    """Complete structural forensic analysis of a JPEG file."""
    format_name: str = "JPEG"
    has_soi: bool = False
    has_eoi: bool = False
    is_progressive: bool = False
    is_baseline: bool = True
    quantization_tables: Dict[int, QuantizationTable] = Field(default_factory=dict)
    huffman_tables: List[HuffmanTable] = Field(default_factory=list)
    frame_header: Optional[JPEGFrameHeader] = None
    restart_interval: int = 0
    comments: List[str] = Field(default_factory=list)
    entropy_coded_data_size: int = 0
    is_truncated: bool = False


class JPEGParser:
    """Zero-crash defensive JPEG parser."""

    MARKER_NAMES = {
        0xFFD8: "SOI",
        0xFFD9: "EOI",
        0xFFC0: "SOF0",
        0xFFC1: "SOF1",
        0xFFC2: "SOF2",
        0xFFC3: "SOF3",
        0xFFC4: "DHT",
        0xFFDD: "DRI",
        0xFFDA: "SOS",
        0xFFDB: "DQT",
        0xFFFE: "COM",
        0xFFE0: "APP0",
        0xFFE1: "APP1",
        0xFFE2: "APP2",
        0xFFE3: "APP3",
        0xFFE4: "APP4",
        0xFFE5: "APP5",
        0xFFE6: "APP6",
        0xFFE7: "APP7",
        0xFFE8: "APP8",
        0xFFE9: "APP9",
        0xFFEA: "APP10",
        0xFFEB: "APP11",
        0xFFEC: "APP12",
        0xFFED: "APP13",
        0xFFEE: "APP14",
        0xFFEF: "APP15",
    }

    def parse(self, data: bytes) -> JPEGStructure:
        structure = JPEGStructure()
        reader = SafeBinaryReader(data)

        if reader.size < 4:
            structure.is_valid_container = False
            structure.anomalies.append("File size smaller than minimum JPEG container (4 bytes).")
            return structure

        # Check SOI
        try:
            first_marker = reader.read_u16_be()
        except CorruptEvidenceError:
            structure.is_valid_container = False
            structure.anomalies.append("Corrupted file header: cannot read initial marker.")
            return structure

        if first_marker != JPEGMarker.SOI:
            structure.is_valid_container = False
            structure.anomalies.append(f"Invalid JPEG SOI marker: expected 0xFFD8, got 0x{first_marker:04X}.")
            return structure

        structure.has_soi = True
        structure.segments.append(
            BinarySegment(
                name="SOI",
                code=JPEGMarker.SOI,
                offset=0,
                length=2,
                description="Start of Image",
            )
        )

        segment_count = 0
        in_scan = False

        while not reader.is_eof():
            segment_count += 1
            if segment_count > SecurityLimits.MAX_SEGMENTS_COUNT:
                structure.anomalies.append(
                    f"Security threshold reached: segment count exceeded {SecurityLimits.MAX_SEGMENTS_COUNT}."
                )
                break

            current_offset = reader.tell()

            # Skip padding 0xFF bytes if any
            byte = reader.read_u8()
            if byte != 0xFF:
                # Malformed marker stream or unexpected sync byte
                continue

            # Read marker byte, skipping fill 0xFF bytes
            marker_byte = reader.read_u8()
            while marker_byte == 0xFF and not reader.is_eof():
                marker_byte = reader.read_u8()

            if marker_byte == 0x00:
                # Byte stuffing in entropy data; not a standalone marker
                continue

            marker_code = 0xFF00 | marker_byte
            marker_name = self.MARKER_NAMES.get(marker_code, f"MARKER_0x{marker_code:04X}")

            # EOI marker (End of Image)
            if marker_code == JPEGMarker.EOI:
                structure.has_eoi = True
                structure.segments.append(
                    BinarySegment(
                        name="EOI",
                        code=marker_code,
                        offset=current_offset,
                        length=2,
                        description="End of Image",
                    )
                )
                # Check for trailing data after EOI
                eoi_end_offset = reader.tell()
                remaining = reader.remaining
                if remaining > 0:
                    structure.has_trailing_data = True
                    structure.trailing_data_offset = eoi_end_offset
                    structure.trailing_data_length = remaining
                    structure.anomalies.append(
                        f"Trailing data detected after EOI: {remaining} bytes starting at offset {eoi_end_offset}."
                    )
                break

            # Standalone markers with no length payload
            if (0xFFD0 <= marker_code <= 0xFFD7) or marker_code in (0xFF01,):
                structure.segments.append(
                    BinarySegment(
                        name=marker_name,
                        code=marker_code,
                        offset=current_offset,
                        length=2,
                    )
                )
                continue

            # Markers with 16-bit length payload
            if reader.remaining < 2:
                structure.is_truncated = True
                structure.anomalies.append(f"Truncated file: missing length for marker {marker_name} at {current_offset}.")
                break

            declared_length = reader.read_u16_be()
            if declared_length < 2:
                structure.anomalies.append(
                    f"Malformed segment length {declared_length} for {marker_name} at offset {current_offset}."
                )
                break

            payload_length = declared_length - 2
            if reader.remaining < payload_length:
                structure.is_truncated = True
                structure.anomalies.append(
                    f"Truncated segment: {marker_name} declared length {declared_length}, but only {reader.remaining} bytes remain."
                )
                payload_length = reader.remaining

            payload_offset = reader.tell()
            payload = reader.read(payload_length)

            segment = BinarySegment(
                name=marker_name,
                code=marker_code,
                offset=current_offset,
                length=declared_length + 2,
                payload_offset=payload_offset,
                payload_length=payload_length,
            )

            # Specific marker parsing
            try:
                if marker_code == JPEGMarker.DQT:
                    self._parse_dqt(payload, structure, segment)
                elif marker_code == JPEGMarker.DHT:
                    self._parse_dht(payload, structure, segment)
                elif marker_code in (JPEGMarker.SOF0, JPEGMarker.SOF1, JPEGMarker.SOF2):
                    self._parse_sof(marker_code, marker_name, payload, structure, segment)
                elif marker_code == JPEGMarker.DRI:
                    if len(payload) >= 2:
                        structure.restart_interval = (payload[0] << 8) | payload[1]
                        segment.details["restart_interval"] = structure.restart_interval
                elif marker_code == JPEGMarker.COM:
                    comment = payload.decode("latin-1", errors="replace")
                    structure.comments.append(comment)
                    segment.details["comment"] = comment
                elif 0xFFE0 <= marker_code <= 0xFFEF:
                    self._annotate_app_marker(marker_code, payload, segment)
            except Exception as e:
                structure.anomalies.append(f"Error parsing segment {marker_name} at {current_offset}: {str(e)}")

            structure.segments.append(segment)

            # If SOS (Start of Scan), the entropy-coded image scan data begins
            if marker_code == JPEGMarker.SOS:
                in_scan = True
                scan_start = reader.tell()
                scan_size = self._skip_scan_data(reader)
                structure.entropy_coded_data_size += scan_size
                in_scan = False

        if not structure.has_eoi and not structure.is_truncated:
            structure.anomalies.append("Missing EOI marker: file may be truncated or improperly terminated.")

        return structure

    def _parse_dqt(self, payload: bytes, structure: JPEGStructure, segment: BinarySegment) -> None:
        reader = SafeBinaryReader(payload)
        tables_found = []
        while reader.remaining >= 65:
            info = reader.read_u8()
            precision = (info >> 4) & 0x0F  # 0 = 8-bit, 1 = 16-bit
            table_id = info & 0x0F
            precision_bits = 16 if precision == 1 else 8

            if precision == 0:
                if reader.remaining < 64:
                    break
                values_zigzag = list(reader.read(64))
            else:
                if reader.remaining < 128:
                    break
                values_zigzag = [reader.read_u16_be() for _ in range(64)]

            # Convert zigzag order back to natural 8x8 order
            natural_values = [0] * 64
            for z_idx, n_idx in enumerate(ZIGZAG_ORDER):
                natural_values[n_idx] = values_zigzag[z_idx]

            table = QuantizationTable(
                table_id=table_id,
                precision_bits=precision_bits,
                values_zigzag=values_zigzag,
                values_natural=natural_values,
            )
            structure.quantization_tables[table_id] = table
            tables_found.append({"id": table_id, "precision_bits": precision_bits})

        segment.details["tables"] = tables_found

    def _parse_dht(self, payload: bytes, structure: JPEGStructure, segment: BinarySegment) -> None:
        reader = SafeBinaryReader(payload)
        tables_found = []
        while reader.remaining >= 17:
            info = reader.read_u8()
            table_class = (info >> 4) & 0x0F  # 0 = DC, 1 = AC
            table_id = info & 0x0F
            counts = list(reader.read(16))
            total_symbols = sum(counts)
            if reader.remaining < total_symbols:
                break
            _ = reader.read(total_symbols)  # Symbols

            ht = HuffmanTable(
                table_class=table_class,
                table_id=table_id,
                num_codes_by_length=counts,
                total_codes=total_symbols,
            )
            structure.huffman_tables.append(ht)
            tables_found.append({"class": table_class, "id": table_id, "total": total_symbols})

        segment.details["huffman_tables"] = tables_found

    def _parse_sof(
        self,
        marker_code: int,
        marker_name: str,
        payload: bytes,
        structure: JPEGStructure,
        segment: BinarySegment,
    ) -> None:
        if len(payload) < 6:
            return

        precision = payload[0]
        height = (payload[1] << 8) | payload[2]
        width = (payload[3] << 8) | payload[4]
        num_components = payload[5]

        components = []
        offset = 6
        for _ in range(num_components):
            if offset + 3 > len(payload):
                break
            comp_id = payload[offset]
            sampling = payload[offset + 1]
            h_samp = (sampling >> 4) & 0x0F
            v_samp = sampling & 0x0F
            quant_id = payload[offset + 2]
            components.append(
                JPEGComponent(
                    component_id=comp_id,
                    horizontal_sampling=h_samp,
                    vertical_sampling=v_samp,
                    quantization_table_id=quant_id,
                )
            )
            offset += 3

        frame_header = JPEGFrameHeader(
            marker_name=marker_name,
            marker_code=marker_code,
            precision=precision,
            height=height,
            width=width,
            num_components=num_components,
            components=components,
        )
        structure.frame_header = frame_header

        if marker_code == JPEGMarker.SOF2:
            structure.is_progressive = True
            structure.is_baseline = False
        else:
            structure.is_progressive = False
            structure.is_baseline = (marker_code == JPEGMarker.SOF0)

        segment.details.update(
            {
                "width": width,
                "height": height,
                "precision": precision,
                "components": num_components,
                "chroma_subsampling": frame_header.chroma_subsampling.value,
                "is_progressive": structure.is_progressive,
            }
        )

    def _annotate_app_marker(self, marker_code: int, payload: bytes, segment: BinarySegment) -> None:
        if marker_code == JPEGMarker.APP0:
            if payload.startswith(b"JFIF\x00"):
                segment.description = "JFIF container header"
                segment.details["identifier"] = "JFIF"
            elif payload.startswith(b"JFXX\x00"):
                segment.description = "JFXX thumbnail extension"
                segment.details["identifier"] = "JFXX"
        elif marker_code == JPEGMarker.APP1:
            if payload.startswith(b"Exif\x00\x00"):
                segment.description = "EXIF metadata"
                segment.details["identifier"] = "Exif"
            elif payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                segment.description = "Adobe XMP metadata"
                segment.details["identifier"] = "XMP"
        elif marker_code == JPEGMarker.APP2:
            if payload.startswith(b"ICC_PROFILE\x00"):
                segment.description = "ICC Color Profile"
                segment.details["identifier"] = "ICC_PROFILE"
            elif payload.startswith(b"FPXR\x00"):
                segment.description = "FlashPix format"
        elif marker_code == JPEGMarker.APP13:
            if payload.startswith(b"Photoshop 3.0\x00"):
                segment.description = "Photoshop 3.0 IRB (IPTC / Image Resources)"
                segment.details["identifier"] = "Photoshop 3.0"
        elif marker_code == JPEGMarker.APP14:
            if payload.startswith(b"Adobe\x00"):
                segment.description = "Adobe DCT color transform encoding"
                segment.details["identifier"] = "Adobe"

    def _skip_scan_data(self, reader: SafeBinaryReader) -> int:
        """Safely scans through entropy-coded scan data until next valid non-restart marker."""
        start_pos = reader.tell()
        while not reader.is_eof():
            byte = reader.read_u8()
            if byte == 0xFF:
                if reader.is_eof():
                    break
                next_byte = reader.read_u8()
                if next_byte == 0x00:
                    # Byte stuffing (0xFF 0x00) -> continue scan
                    continue
                if 0xD0 <= next_byte <= 0xD7:
                    # Restart marker RST0-RST7 -> continue scan
                    continue
                if next_byte == 0xFF:
                    # Fill byte
                    while not reader.is_eof():
                        peek = reader.peek(1)
                        if peek == b"\xFF":
                            reader.read_u8()
                        else:
                            break
                    continue
                # Found legitimate terminating marker! Rewind 2 bytes so main loop parses it
                reader.seek(-2, whence=1)
                break
        return reader.tell() - start_pos
