"""Container parsers for digital image forensic structural analysis."""

from forensic_image.formats.base import BinarySegment, ContainerStructure
from forensic_image.formats.detector import detect_image_format
from forensic_image.formats.jpeg import (
    JPEGFrameHeader,
    JPEGParser,
    JPEGStructure,
    QuantizationTable,
    HuffmanTable,
)
from forensic_image.formats.png import PNGChunk, PNGIHDR, PNGParser, PNGStructure
from forensic_image.formats.webp import WebPChunk, WebPParser, WebPStructure, WebPVP8X

__all__ = [
    "BinarySegment",
    "ContainerStructure",
    "detect_image_format",
    "JPEGFrameHeader",
    "JPEGParser",
    "JPEGStructure",
    "QuantizationTable",
    "HuffmanTable",
    "PNGChunk",
    "PNGIHDR",
    "PNGParser",
    "PNGStructure",
    "WebPChunk",
    "WebPParser",
    "WebPStructure",
    "WebPVP8X",
]
