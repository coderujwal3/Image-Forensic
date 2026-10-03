"""Forensic EXIF metadata extraction and decoding with safe TIFF IFD navigation."""

import struct
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from forensic_image.core.constants import FindingStatus
from forensic_image.core.reader import SafeBinaryReader


class GPSData(BaseModel):
    """Forensically decoded geolocation evidence."""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    altitude_ref: Optional[int] = None
    timestamp: Optional[str] = None
    processing_method: Optional[str] = None
    raw_tags: Dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.NOT_AVAILABLE

    @property
    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None


class EXIFData(BaseModel):
    """Structured EXIF forensic metadata container."""
    is_present: bool = False
    status: FindingStatus = FindingStatus.NOT_AVAILABLE
    byte_order: Optional[str] = None  # 'II' (Little Endian) or 'MM' (Big Endian)
    make: Optional[str] = None
    model: Optional[str] = None
    software: Optional[str] = None
    date_time: Optional[str] = None
    date_time_original: Optional[str] = None
    date_time_digitized: Optional[str] = None
    lens_make: Optional[str] = None
    lens_model: Optional[str] = None
    lens_serial_number: Optional[str] = None
    camera_serial_number: Optional[str] = None
    focal_length_mm: Optional[float] = None
    focal_length_35mm: Optional[float] = None
    f_number: Optional[float] = None
    exposure_time: Optional[str] = None
    iso: Optional[int] = None
    flash: Optional[int] = None
    white_balance: Optional[int] = None
    exposure_program: Optional[int] = None
    metering_mode: Optional[int] = None
    orientation: Optional[int] = None
    exif_image_width: Optional[int] = None
    exif_image_height: Optional[int] = None
    maker_note_present: bool = False
    maker_note_type: Optional[str] = None
    gps: GPSData = Field(default_factory=GPSData)
    thumbnail_offset: Optional[int] = None
    thumbnail_length: Optional[int] = None
    thumbnail_bytes: Optional[bytes] = None
    raw_tags: Dict[str, Any] = Field(default_factory=dict)


class EXIFParser:
    """Safe, zero-crash EXIF parser operating directly on TIFF IFD structures."""

    TAG_NAMES = {
        0x010E: "ImageDescription",
        0x010F: "Make",
        0x0110: "Model",
        0x0112: "Orientation",
        0x011A: "XResolution",
        0x011B: "YResolution",
        0x0128: "ResolutionUnit",
        0x0131: "Software",
        0x0132: "DateTime",
        0x013B: "Artist",
        0x8298: "Copyright",
        0x8769: "ExifIFDOffset",
        0x8825: "GPSInfoIFDOffset",
        0x829A: "ExposureTime",
        0x829D: "FNumber",
        0x8822: "ExposureProgram",
        0x8827: "ISOSpeedRatings",
        0x9000: "ExifVersion",
        0x9003: "DateTimeOriginal",
        0x9004: "DateTimeDigitized",
        0x9201: "ShutterSpeedValue",
        0x9202: "ApertureValue",
        0x9204: "ExposureBiasValue",
        0x9207: "MeteringMode",
        0x9208: "LightSource",
        0x9209: "Flash",
        0x920A: "FocalLength",
        0x927C: "MakerNote",
        0x9286: "UserComment",
        0xA001: "ColorSpace",
        0xA002: "ExifImageWidth",
        0xA003: "ExifImageHeight",
        0xA405: "FocalLengthIn35mmFilm",
        0xA431: "BodySerialNumber",
        0xA432: "LensSpecification",
        0xA433: "LensMake",
        0xA434: "LensModel",
        0xA435: "LensSerialNumber",
        0x0201: "JPEGInterchangeFormat",
        0x0202: "JPEGInterchangeFormatLength",
    }

    GPS_TAG_NAMES = {
        0x0000: "GPSVersionID",
        0x0001: "GPSLatitudeRef",
        0x0002: "GPSLatitude",
        0x0003: "GPSLongitudeRef",
        0x0004: "GPSLongitude",
        0x0005: "GPSAltitudeRef",
        0x0006: "GPSAltitude",
        0x0007: "GPSTimeStamp",
        0x001B: "GPSProcessingMethod",
        0x001D: "GPSDateStamp",
    }

    def parse(self, tiff_data: bytes) -> EXIFData:
        """Parses raw TIFF header bytes (starts at 'II*' or 'MM*')."""
        result = EXIFData()
        if len(tiff_data) < 8:
            return result

        endian_code = tiff_data[:2]
        if endian_code == b"II":
            endian = "<"
            result.byte_order = "II (Little Endian)"
        elif endian_code == b"MM":
            endian = ">"
            result.byte_order = "MM (Big Endian)"
        else:
            return result

        magic = struct.unpack(f"{endian}H", tiff_data[2:4])[0]
        if magic != 42:
            return result

        result.is_present = True
        result.status = FindingStatus.OBSERVED

        ifd0_offset = struct.unpack(f"{endian}I", tiff_data[4:8])[0]
        parsed_tags = {}

        # Parse IFD0
        ifd0_tags, next_ifd_offset = self._read_ifd(tiff_data, ifd0_offset, endian)
        parsed_tags.update(ifd0_tags)

        # Parse Exif SubIFD if present
        exif_sub_offset = ifd0_tags.get(0x8769)
        if isinstance(exif_sub_offset, int):
            sub_tags, _ = self._read_ifd(tiff_data, exif_sub_offset, endian)
            parsed_tags.update(sub_tags)

        # Parse GPS SubIFD if present
        gps_sub_offset = ifd0_tags.get(0x8825)
        gps_tags = {}
        if isinstance(gps_sub_offset, int):
            gps_tags, _ = self._read_ifd(tiff_data, gps_sub_offset, endian, is_gps=True)

        # Parse IFD1 (embedded thumbnail) if present
        if next_ifd_offset > 0 and next_ifd_offset < len(tiff_data):
            ifd1_tags, _ = self._read_ifd(tiff_data, next_ifd_offset, endian)
            thumb_offset = ifd1_tags.get(0x0201)
            thumb_len = ifd1_tags.get(0x0202)
            if isinstance(thumb_offset, int) and isinstance(thumb_len, int):
                result.thumbnail_offset = thumb_offset
                result.thumbnail_length = thumb_len
                if thumb_offset + thumb_len <= len(tiff_data):
                    result.thumbnail_bytes = tiff_data[thumb_offset : thumb_offset + thumb_len]

        # Populate structured EXIFData
        result.raw_tags = {self.TAG_NAMES.get(k, f"Tag_0x{k:04X}"): v for k, v in parsed_tags.items()}
        result.make = self._clean_str(parsed_tags.get(0x010F))
        result.model = self._clean_str(parsed_tags.get(0x0110))
        result.software = self._clean_str(parsed_tags.get(0x0131))
        result.date_time = self._clean_str(parsed_tags.get(0x0132))
        result.date_time_original = self._clean_str(parsed_tags.get(0x9003))
        result.date_time_digitized = self._clean_str(parsed_tags.get(0x9004))
        result.lens_make = self._clean_str(parsed_tags.get(0xA433))
        result.lens_model = self._clean_str(parsed_tags.get(0xA434))
        result.lens_serial_number = self._clean_str(parsed_tags.get(0xA435))
        result.camera_serial_number = self._clean_str(parsed_tags.get(0xA431))
        result.orientation = parsed_tags.get(0x0112)
        result.exif_image_width = parsed_tags.get(0xA002)
        result.exif_image_height = parsed_tags.get(0xA003)
        result.flash = parsed_tags.get(0x9209)
        result.white_balance = parsed_tags.get(0xA403)
        result.exposure_program = parsed_tags.get(0x8822)
        result.metering_mode = parsed_tags.get(0x9207)
        result.iso = parsed_tags.get(0x8827)

        # Numbers / rationals
        fl = parsed_tags.get(0x920A)
        if isinstance(fl, tuple) and len(fl) == 2 and fl[1] != 0:
            result.focal_length_mm = round(fl[0] / fl[1], 2)
        elif isinstance(fl, (int, float)):
            result.focal_length_mm = float(fl)

        fl35 = parsed_tags.get(0xA405)
        if isinstance(fl35, (int, float)):
            result.focal_length_35mm = float(fl35)

        fn = parsed_tags.get(0x829D)
        if isinstance(fn, tuple) and len(fn) == 2 and fn[1] != 0:
            result.f_number = round(fn[0] / fn[1], 2)
        elif isinstance(fn, (int, float)):
            result.f_number = float(fn)

        exp = parsed_tags.get(0x829A)
        if isinstance(exp, tuple) and len(exp) == 2 and exp[1] != 0:
            if exp[0] == 1:
                result.exposure_time = f"1/{exp[1]}"
            else:
                result.exposure_time = f"{round(exp[0] / exp[1], 5)}s"

        # Check MakerNote safely
        mn = parsed_tags.get(0x927C)
        if mn:
            result.maker_note_present = True
            result.maker_note_type = self._identify_makernote(mn, result.make)

        # GPS decoding
        if gps_tags:
            result.gps = self._decode_gps(gps_tags)

        return result

    def _read_ifd(
        self,
        data: bytes,
        offset: int,
        endian: str,
        is_gps: bool = False,
    ) -> Tuple[Dict[int, Any], int]:
        tags = {}
        if offset + 2 > len(data):
            return tags, 0

        num_entries = struct.unpack(f"{endian}H", data[offset : offset + 2])[0]
        # Sanity bound on entries
        if num_entries > 500:
            return tags, 0

        cur = offset + 2
        for _ in range(num_entries):
            if cur + 12 > len(data):
                break
            tag_id, tag_type, count, val_or_offset = struct.unpack(f"{endian}HHI4s", data[cur : cur + 12])
            cur += 12

            val = self._parse_tag_value(data, tag_type, count, val_or_offset, endian)
            if val is not None:
                tags[tag_id] = val

        next_ifd = 0
        if cur + 4 <= len(data):
            next_ifd = struct.unpack(f"{endian}I", data[cur : cur + 4])[0]

        return tags, next_ifd

    def _parse_tag_value(
        self,
        data: bytes,
        tag_type: int,
        count: int,
        val_or_offset_bytes: bytes,
        endian: str,
    ) -> Any:
        # Type sizes: 1=BYTE, 2=ASCII, 3=SHORT(2), 4=LONG(4), 5=RATIONAL(8), 7=UNDEFINED(1)
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
        unit_size = type_sizes.get(tag_type, 1)
        total_size = count * unit_size

        if total_size <= 4:
            payload = val_or_offset_bytes[:total_size]
        else:
            val_offset = struct.unpack(f"{endian}I", val_or_offset_bytes)[0]
            if val_offset + total_size > len(data):
                return None
            payload = data[val_offset : val_offset + total_size]

        if tag_type == 2:  # ASCII
            try:
                return payload.decode("latin-1").rstrip("\x00")
            except Exception:
                return None
        elif tag_type == 3:  # SHORT
            if count == 1:
                return struct.unpack(f"{endian}H", payload[:2])[0]
            return [struct.unpack(f"{endian}H", payload[i * 2 : (i + 1) * 2])[0] for i in range(count)]
        elif tag_type == 4:  # LONG
            if count == 1:
                return struct.unpack(f"{endian}I", payload[:4])[0]
            return [struct.unpack(f"{endian}I", payload[i * 4 : (i + 1) * 4])[0] for i in range(count)]
        elif tag_type == 5:  # RATIONAL
            rationals = []
            for i in range(count):
                sub = payload[i * 8 : (i + 1) * 8]
                if len(sub) == 8:
                    num, den = struct.unpack(f"{endian}II", sub)
                    rationals.append((num, den))
            return rationals[0] if count == 1 and rationals else rationals
        elif tag_type == 7:  # UNDEFINED
            return bytes(payload)
        return None

    def _decode_gps(self, gps_tags: Dict[int, Any]) -> GPSData:
        gps = GPSData()
        gps.status = FindingStatus.OBSERVED
        gps.raw_tags = {self.GPS_TAG_NAMES.get(k, f"GPS_0x{k:04X}"): v for k, v in gps_tags.items()}

        lat_ref = gps_tags.get(0x0001)
        lat_val = gps_tags.get(0x0002)
        lon_ref = gps_tags.get(0x0003)
        lon_val = gps_tags.get(0x0004)

        if lat_val and len(lat_val) == 3:
            deg = lat_val[0][0] / lat_val[0][1] if lat_val[0][1] else 0
            minute = lat_val[1][0] / lat_val[1][1] if lat_val[1][1] else 0
            sec = lat_val[2][0] / lat_val[2][1] if lat_val[2][1] else 0
            decimal_lat = deg + (minute / 60.0) + (sec / 3600.0)
            if lat_ref == "S":
                decimal_lat = -decimal_lat
            gps.latitude = round(decimal_lat, 6)

        if lon_val and len(lon_val) == 3:
            deg = lon_val[0][0] / lon_val[0][1] if lon_val[0][1] else 0
            minute = lon_val[1][0] / lon_val[1][1] if lon_val[1][1] else 0
            sec = lon_val[2][0] / lon_val[2][1] if lon_val[2][1] else 0
            decimal_lon = deg + (minute / 60.0) + (sec / 3600.0)
            if lon_ref == "W":
                decimal_lon = -decimal_lon
            gps.longitude = round(decimal_lon, 6)

        alt = gps_tags.get(0x0006)
        if alt and isinstance(alt, tuple) and alt[1] != 0:
            gps.altitude_m = round(alt[0] / alt[1], 2)
            gps.altitude_ref = gps_tags.get(0x0005)

        time_val = gps_tags.get(0x0007)
        date_val = gps_tags.get(0x001D)
        if date_val and time_val and len(time_val) == 3:
            h = int(time_val[0][0] / time_val[0][1]) if time_val[0][1] else 0
            m = int(time_val[1][0] / time_val[1][1]) if time_val[1][1] else 0
            s = int(time_val[2][0] / time_val[2][1]) if time_val[2][1] else 0
            gps.timestamp = f"{date_val} {h:02d}:{m:02d}:{s:02d} UTC"

        proc = gps_tags.get(0x001B)
        if isinstance(proc, (str, bytes)):
            if isinstance(proc, bytes):
                # May have 8-byte charset prefix (e.g. ASCII\0\0\0)
                proc = proc[8:].decode("latin-1", errors="replace") if len(proc) > 8 else proc.hex()
            gps.processing_method = proc.strip("\x00")

        return gps

    def _clean_str(self, val: Any) -> Optional[str]:
        if val is None:
            return None
        if isinstance(val, str):
            cleaned = val.strip("\x00 ").strip()
            return cleaned if cleaned else None
        return str(val)

    def _identify_makernote(self, mn: bytes, make: Optional[str]) -> str:
        if not isinstance(mn, bytes):
            return "Unknown"
        if mn.startswith(b"Nikon"):
            return "Nikon"
        if mn.startswith(b"Canon"):
            return "Canon"
        if mn.startswith(b"Apple iOS"):
            return "Apple"
        if mn.startswith(b"OLYMP"):
            return "Olympus"
        if mn.startswith(b"FUJIFILM"):
            return "Fujifilm"
        if mn.startswith(b"SONY"):
            return "Sony"
        if make:
            make_lower = make.lower()
            for brand in ("apple", "canon", "nikon", "sony", "samsung", "google", "fujifilm", "panasonic"):
                if brand in make_lower:
                    return brand.capitalize()
        return "Generic"
