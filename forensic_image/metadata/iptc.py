"""Forensic IPTC-NAA and Photoshop Image Resource Block (8BIM) parser."""

import struct
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus
from forensic_image.core.reader import SafeBinaryReader


class IPTCData(BaseModel):
    """Structured IPTC editorial and provenance metadata."""
    is_present: bool = False
    status: FindingStatus = FindingStatus.NOT_AVAILABLE
    headline: Optional[str] = None
    caption: Optional[str] = None
    byline_creator: Optional[str] = None
    byline_title: Optional[str] = None
    copyright: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    source: Optional[str] = None
    job_id: Optional[str] = None
    raw_datasets: Dict[str, Any] = Field(default_factory=dict)


class IPTCParser:
    """Safe parser for IPTC-NAA record 2 datasets inside Photoshop 8BIM blocks."""

    DATASET_NAMES = {
        0x05: "ObjectName",
        0x19: "Keywords",
        0x50: "ByLine",
        0x55: "ByLineTitle",
        0x5A: "City",
        0x5C: "SubLocation",
        0x5F: "ProvinceState",
        0x65: "CountryName",
        0x67: "JobIdentifier",
        0x69: "Headline",
        0x74: "CopyrightNotice",
        0x78: "CaptionAbstract",
        0x7A: "WriterEditor",
    }

    def parse(self, app13_payload: bytes) -> IPTCData:
        result = IPTCData()
        if not app13_payload:
            return result

        # Must start with "Photoshop 3.0\x00"
        if not app13_payload.startswith(b"Photoshop 3.0\x00"):
            return result

        reader = SafeBinaryReader(app13_payload[14:])

        # Walk 8BIM records
        while reader.remaining >= 12:
            sig = reader.read(4)
            if sig != b"8BIM":
                # Seek next 8BIM
                idx = app13_payload.find(b"8BIM", reader.position)
                if idx == -1:
                    break
                reader.seek(idx + 4)
                continue

            res_id = reader.read_u16_be()
            # Pascal string name
            name_len = reader.read_u8()
            _ = reader.read(name_len)
            # Pad to even length (name_len + 1 must be even)
            if (name_len + 1) % 2 != 0 and not reader.is_eof():
                reader.read(1)

            if reader.remaining < 4:
                break
            res_size = reader.read_u32_be()
            if reader.remaining < res_size:
                break

            res_data = reader.read(res_size)
            # Pad to even
            if res_size % 2 != 0 and not reader.is_eof():
                reader.read(1)

            # Resource ID 0x0404 is IPTC-NAA
            if res_id == 0x0404:
                self._parse_iptc_datasets(res_data, result)

        return result

    def _parse_iptc_datasets(self, data: bytes, result: IPTCData) -> None:
        reader = SafeBinaryReader(data)
        result.is_present = True
        result.status = FindingStatus.OBSERVED

        while reader.remaining >= 5:
            marker = reader.read_u8()
            if marker != 0x1C:
                # Seek next 0x1C
                continue

            record_num = reader.read_u8()
            dataset_num = reader.read_u8()
            tag_size = reader.read_u16_be()

            if reader.remaining < tag_size:
                break

            tag_bytes = reader.read(tag_size)
            try:
                tag_str = tag_bytes.decode("utf-8").strip("\x00 ")
            except UnicodeDecodeError:
                tag_str = tag_bytes.decode("latin-1", errors="replace").strip("\x00 ")

            if record_num == 2:
                name = self.DATASET_NAMES.get(dataset_num, f"Dataset_2_{dataset_num}")
                if dataset_num == 0x19:  # Keywords
                    result.keywords.append(tag_str)
                elif dataset_num == 0x69:  # Headline
                    result.headline = tag_str
                elif dataset_num == 0x78:  # Caption
                    result.caption = tag_str
                elif dataset_num == 0x50:  # Byline
                    result.byline_creator = tag_str
                elif dataset_num == 0x55:
                    result.byline_title = tag_str
                elif dataset_num == 0x74:  # Copyright
                    result.copyright = tag_str
                elif dataset_num == 0x5A:
                    result.city = tag_str
                elif dataset_num == 0x5F:
                    result.state = tag_str
                elif dataset_num == 0x65:
                    result.country = tag_str
                elif dataset_num == 0x67:
                    result.job_id = tag_str

                result.raw_datasets[name] = tag_str
