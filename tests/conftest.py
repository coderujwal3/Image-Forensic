"""Test fixtures and synthetic image evidence generators."""

import io
import struct
from pathlib import Path
import pytest
from PIL import Image, ImageDraw


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


def create_test_image(width: int = 400, height: int = 300, color: str = "red") -> Image.Image:
    """Creates a basic Pillow image for testing."""
    img = Image.new("RGB", (width, height), color=color)
    draw = ImageDraw.Draw(img)
    draw.rectangle([20, 20, width - 20, height - 20], outline="white", width=3)
    draw.text((30, 30), "TEST EVIDENCE", fill="white")
    return img


def build_exif_with_gps() -> bytes:
    """Builds a binary TIFF/EXIF buffer containing camera tags and GPS info."""
    endian = "<"
    buf = io.BytesIO()
    buf.write(b"II\x2a\x00\x08\x00\x00\x00")  # TIFF header: II, 42, IFD0 offset 8

    # IFD0: 5 tags
    # 0x010F: Make
    # 0x0110: Model
    # 0x0131: Software
    # 0x8769: ExifIFD pointer
    # 0x8825: GPSIFD pointer
    num_tags = 5
    buf.write(struct.pack(f"{endian}H", num_tags))

    make_str = b"Nikon Corporation\x00"
    model_str = b"NIKON D850\x00"
    soft_str = b"Ver.1.10\x00"

    # Offsets layout
    # IFD0 starts at 8, size = 2 + (5 * 12) + 4 = 66 bytes -> ends at offset 74
    # String payloads placed after IFD0
    make_off = 74
    model_off = make_off + len(make_str)
    soft_off = model_off + len(model_str)
    exif_ifd_off = soft_off + len(soft_str)
    if exif_ifd_off % 2 != 0:
        exif_ifd_off += 1

    # Exif SubIFD: 2 tags (DateTimeOriginal, ExifImageWidth)
    # size = 2 + (2 * 12) + 4 = 30 bytes
    gps_ifd_off = exif_ifd_off + 30
    if gps_ifd_off % 2 != 0:
        gps_ifd_off += 1

    # IFD0 entries
    buf.write(struct.pack(f"{endian}HHI4s", 0x010F, 2, len(make_str), struct.pack(f"{endian}I", make_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0110, 2, len(model_str), struct.pack(f"{endian}I", model_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0131, 2, len(soft_str), struct.pack(f"{endian}I", soft_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0x8769, 4, 1, struct.pack(f"{endian}I", exif_ifd_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0x8825, 4, 1, struct.pack(f"{endian}I", gps_ifd_off)))
    # Next IFD = 0
    buf.write(struct.pack(f"{endian}I", 0))

    # Write string data
    buf.write(make_str)
    buf.write(model_str)
    buf.write(soft_str)

    # Pad to exif_ifd_off
    while buf.tell() < exif_ifd_off:
        buf.write(b"\x00")

    # Exif SubIFD (at exif_ifd_off)
    dto_str = b"2026:05:14 12:30:00\x00"
    dto_off = gps_ifd_off + 80  # place after GPS IFD

    buf.write(struct.pack(f"{endian}H", 2))
    buf.write(struct.pack(f"{endian}HHI4s", 0x9003, 2, len(dto_str), struct.pack(f"{endian}I", dto_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0xA002, 4, 1, struct.pack(f"{endian}I", 4032)))
    buf.write(struct.pack(f"{endian}I", 0))

    # Pad to gps_ifd_off
    while buf.tell() < gps_ifd_off:
        buf.write(b"\x00")

    # GPS SubIFD
    # Tags: LatRef (0x0001), Lat (0x0002), LonRef (0x0003), Lon (0x0004), Alt (0x0006)
    coord_data_off = dto_off + len(dto_str)
    if coord_data_off % 2 != 0:
        coord_data_off += 1

    buf.write(struct.pack(f"{endian}H", 4))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0001, 2, 2, b"N\x00\x00\x00"))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0002, 5, 3, struct.pack(f"{endian}I", coord_data_off)))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0003, 2, 2, b"W\x00\x00\x00"))
    buf.write(struct.pack(f"{endian}HHI4s", 0x0004, 5, 3, struct.pack(f"{endian}I", coord_data_off + 24)))
    buf.write(struct.pack(f"{endian}I", 0))

    # Pad to dto_off
    while buf.tell() < dto_off:
        buf.write(b"\x00")
    buf.write(dto_str)

    # Pad to coord_data_off
    while buf.tell() < coord_data_off:
        buf.write(b"\x00")

    # Latitude: 37 deg, 46 min, 30 sec (37.775 deg)
    buf.write(struct.pack(f"{endian}6I", 37, 1, 46, 1, 30, 1))
    # Longitude: 122 deg, 25 min, 12 sec (122.42 deg)
    buf.write(struct.pack(f"{endian}6I", 122, 1, 25, 1, 12, 1))

    return buf.getvalue()


@pytest.fixture
def clean_jpeg_path(tmp_path: Path) -> Path:
    p = tmp_path / "clean_photo.jpg"
    img = create_test_image(800, 600, "navy")
    img.save(p, format="JPEG", quality=90)
    return p


@pytest.fixture
def clean_png_path(tmp_path: Path) -> Path:
    p = tmp_path / "clean_graphics.png"
    img = create_test_image(800, 600, "teal")
    img.save(p, format="PNG")
    return p


@pytest.fixture
def clean_webp_path(tmp_path: Path) -> Path:
    p = tmp_path / "clean_web.webp"
    img = create_test_image(800, 600, "purple")
    img.save(p, format="WEBP", quality=90)
    return p


@pytest.fixture
def trailing_payload_jpeg_path(clean_jpeg_path: Path, tmp_path: Path) -> Path:
    p = tmp_path / "trailing_evidence.jpg"
    with open(clean_jpeg_path, "rb") as f:
        data = f.read()
    # Append secret payload past EOI
    secret = b"HIDDEN_FORENSIC_PAYLOAD_OFFSET_PAST_EOI" * 4
    with open(p, "wb") as f:
        f.write(data + secret)
    return p


@pytest.fixture
def screenshot_png_path(tmp_path: Path) -> Path:
    p = tmp_path / "iphone15_screenshot.png"
    # Exact iPhone 14/15/16 Pro screen resolution
    img = create_test_image(1179, 2556, "black")
    img.save(p, format="PNG")
    return p
