"""Defensive image container magic byte identification and MIME type detection."""

from typing import Tuple
from forensic_image.core.constants import ImageFormat


def detect_image_format(data: bytes) -> Tuple[ImageFormat, str]:
    """Inspects file prefix magic bytes to identify container format defensively.
    
    Returns:
        Tuple of (ImageFormat, mime_type_str)
    """
    if len(data) < 4:
        return ImageFormat.UNKNOWN, "application/octet-stream"

    # JPEG: FF D8 FF
    if data.startswith(b"\xFF\xD8\xFF"):
        return ImageFormat.JPEG, "image/jpeg"

    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ImageFormat.PNG, "image/png"

    # WebP: RIFF ???? WEBP
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ImageFormat.WEBP, "image/webp"

    # TIFF: II*\x00 (little endian) or MM\x00* (big endian)
    if data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
        return ImageFormat.TIFF, "image/tiff"

    # GIF: GIF87a or GIF89a
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ImageFormat.GIF, "image/gif"

    # BMP: BM
    if data.startswith(b"BM"):
        return ImageFormat.BMP, "image/bmp"

    # ISO Base Media File Format (HEIF / AVIF)
    # Check for 'ftyp' at offset 4
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"avif", b"avis"):
            return ImageFormat.AVIF, "image/avif"
        if brand in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"):
            return ImageFormat.HEIF, "image/heif"

    return ImageFormat.UNKNOWN, "application/octet-stream"
