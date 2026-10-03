"""Forensic ICC color profile parser and device class analyzer."""

import struct
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus
from forensic_image.core.reader import SafeBinaryReader


class ICCData(BaseModel):
    """Forensic ICC color profile characteristics."""
    is_present: bool = False
    status: FindingStatus = FindingStatus.NOT_AVAILABLE
    profile_size: int = 0
    cmm_type: Optional[str] = None
    version: Optional[str] = None
    device_class: Optional[str] = None
    device_class_name: Optional[str] = None
    color_space: Optional[str] = None
    connection_space: Optional[str] = None
    creation_date: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    description: Optional[str] = None
    tags_count: int = 0
    tag_table: List[str] = Field(default_factory=list)


class ICCParser:
    """Defensive ICC Profile Header and Tag Table parser."""

    DEVICE_CLASSES = {
        "scnr": "Input Device (Scanner / Camera)",
        "mntr": "Display Device (Monitor / Screen)",
        "prtr": "Output Device (Printer)",
        "link": "DeviceLink Profile",
        "spac": "ColorSpace Conversion Profile",
        "abst": "Abstract Profile",
        "nmcl": "Named Color Profile",
    }

    def parse(self, icc_bytes: bytes) -> ICCData:
        result = ICCData()
        if not icc_bytes or len(icc_bytes) < 128:
            return result

        reader = SafeBinaryReader(icc_bytes)
        profile_size = reader.read_u32_be()
        if profile_size > reader.size:
            profile_size = reader.size

        result.profile_size = profile_size
        cmm_type = reader.read(4).decode("ascii", errors="replace").strip()
        result.cmm_type = cmm_type if cmm_type else "None"

        # Version: byte 0 = major, byte 1 = minor (in upper 4 bits) + bugfix
        ver_bytes = reader.read(4)
        major = ver_bytes[0]
        minor = (ver_bytes[1] >> 4) & 0x0F
        bugfix = ver_bytes[1] & 0x0F
        result.version = f"{major}.{minor}.{bugfix}"

        device_class = reader.read(4).decode("ascii", errors="replace").strip().lower()
        result.device_class = device_class
        result.device_class_name = self.DEVICE_CLASSES.get(device_class, f"Unknown ({device_class})")

        color_space = reader.read(4).decode("ascii", errors="replace").strip()
        result.color_space = color_space

        conn_space = reader.read(4).decode("ascii", errors="replace").strip()
        result.connection_space = conn_space

        # Creation date (12 bytes: year(2), month(2), day(2), hour(2), min(2), sec(2))
        date_raw = reader.read(12)
        try:
            y, m, d, hh, mm, ss = struct.unpack(">6H", date_raw)
            result.creation_date = f"{y:04d}-{m:02d}-{d:02d} {hh:02d}:{mm:02d}:{ss:02d} UTC"
        except Exception:
            pass

        # Skip profile signature (4 bytes b"acsp")
        _ = reader.read(4)
        # Platform (4 bytes)
        _ = reader.read(4)
        # Flags (4 bytes)
        _ = reader.read(4)

        # Manufacturer (4 bytes)
        mfg = reader.read(4).decode("ascii", errors="replace").strip()
        result.manufacturer = mfg if mfg else None

        # Model (4 bytes)
        mdl = reader.read(4).decode("ascii", errors="replace").strip()
        result.model = mdl if mdl else None

        # Seek to tag count at offset 128
        reader.seek(128)
        if reader.remaining >= 4:
            tag_count = reader.read_u32_be()
            result.tags_count = tag_count

            # Scan tag table for 'desc' tag
            for _ in range(min(tag_count, 100)):
                if reader.remaining < 12:
                    break
                tag_sig = reader.read(4).decode("ascii", errors="replace").strip()
                tag_offset = reader.read_u32_be()
                tag_size = reader.read_u32_be()
                result.tag_table.append(tag_sig)

                if tag_sig == "desc":
                    result.description = self._parse_desc_tag(icc_bytes, tag_offset, tag_size)

        result.is_present = True
        result.status = FindingStatus.OBSERVED
        return result

    def _parse_desc_tag(self, data: bytes, offset: int, size: int) -> Optional[str]:
        if offset + size > len(data) or size < 8:
            return None
        tag_data = data[offset : offset + size]
        tag_type = tag_data[:4]

        # 'desc' format: 4 bytes type, 4 bytes reserved, 4 bytes count, ASCII string
        if tag_type == b"desc" and len(tag_data) >= 12:
            ascii_count = struct.unpack(">I", tag_data[8:12])[0]
            if 12 + ascii_count <= len(tag_data):
                desc_str = tag_data[12 : 12 + ascii_count].decode("latin-1", errors="replace")
                return desc_str.strip("\x00 ").strip()

        # 'mluc' (multi-localized Unicode string)
        if tag_type == b"mluc" and len(tag_data) >= 16:
            # tag_data: type(4), reserved(4), record_count(4), record_size(4)
            rec_count = struct.unpack(">I", tag_data[8:12])[0]
            if rec_count > 0 and len(tag_data) >= 16 + 12:
                # first record: lang(2), country(2), len(4), offset(4)
                str_len = struct.unpack(">I", tag_data[20:24])[0]
                str_off = struct.unpack(">I", tag_data[24:28])[0]
                if str_off + str_len <= len(tag_data):
                    try:
                        return tag_data[str_off : str_off + str_len].decode("utf-16-be").strip("\x00 ")
                    except Exception:
                        pass

        # 'text' format
        if tag_type == b"text" and len(tag_data) > 8:
            return tag_data[8:].decode("latin-1", errors="replace").strip("\x00 ")

        return None
