"""Unit tests for defensive container and binary marker parsers."""

from pathlib import Path
from forensic_image.formats.jpeg import JPEGParser
from forensic_image.formats.png import PNGParser
from forensic_image.formats.webp import WebPParser


def test_jpeg_parser_clean(clean_jpeg_path: Path) -> None:
    data = clean_jpeg_path.read_bytes()
    parser = JPEGParser()
    struct = parser.parse(data)

    assert struct.is_valid_container is True
    assert struct.has_soi is True
    assert struct.has_eoi is True
    assert struct.has_trailing_data is False
    assert len(struct.quantization_tables) >= 1
    assert struct.frame_header is not None
    assert struct.frame_header.width == 800
    assert struct.frame_header.height == 600


def test_jpeg_parser_trailing_payload(trailing_payload_jpeg_path: Path) -> None:
    data = trailing_payload_jpeg_path.read_bytes()
    parser = JPEGParser()
    struct = parser.parse(data)

    assert struct.is_valid_container is True
    assert struct.has_soi is True
    assert struct.has_eoi is True
    assert struct.has_trailing_data is True
    assert struct.trailing_data_length > 0
    assert struct.trailing_data_offset is not None
    assert any("Trailing data detected" in a for a in struct.anomalies)


def test_jpeg_parser_truncated() -> None:
    # Truncated midway through SOF marker
    truncated_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDB\x00\x43"
    parser = JPEGParser()
    struct = parser.parse(truncated_bytes)

    # Must not crash; records anomalies
    assert struct.has_soi is True
    assert struct.has_eoi is False
    assert struct.is_truncated is True
    assert len(struct.anomalies) > 0


def test_png_parser_clean(clean_png_path: Path) -> None:
    data = clean_png_path.read_bytes()
    parser = PNGParser()
    struct = parser.parse(data)

    assert struct.is_valid_container is True
    assert struct.has_valid_signature is True
    assert struct.has_ihdr is True
    assert struct.has_iend is True
    assert struct.ihdr.width == 800
    assert struct.ihdr.height == 600
    assert struct.crc_failures_count == 0
    assert struct.has_trailing_data is False


def test_png_parser_trailing_payload(clean_png_path: Path) -> None:
    data = clean_png_path.read_bytes() + b"SECRET_OVERLAY_BYTES_AFTER_IEND"
    parser = PNGParser()
    struct = parser.parse(data)

    assert struct.has_trailing_data is True
    assert struct.trailing_data_length == len(b"SECRET_OVERLAY_BYTES_AFTER_IEND")


def test_webp_parser_clean(clean_webp_path: Path) -> None:
    data = clean_webp_path.read_bytes()
    parser = WebPParser()
    struct = parser.parse(data)

    assert struct.is_valid_container is True
    assert struct.has_riff is True
    assert struct.has_webp_header is True
    assert len(struct.chunks) >= 1
