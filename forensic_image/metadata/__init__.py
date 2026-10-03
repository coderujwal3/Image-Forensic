"""Metadata analysis package for digital image forensics."""

from forensic_image.metadata.exif import EXIFData, EXIFParser, GPSData
from forensic_image.metadata.icc import ICCData, ICCParser
from forensic_image.metadata.iptc import IPTCData, IPTCParser
from forensic_image.metadata.thumbnail import ThumbnailDetails, ThumbnailForensics
from forensic_image.metadata.xmp import XMPData, XMPHistoryEvent, XMPParser

__all__ = [
    "EXIFData",
    "EXIFParser",
    "GPSData",
    "ICCData",
    "ICCParser",
    "IPTCData",
    "IPTCParser",
    "ThumbnailDetails",
    "ThumbnailForensics",
    "XMPData",
    "XMPHistoryEvent",
    "XMPParser",
]
