"""Core constants, enums, and security thresholds for digital image forensics."""

from enum import Enum


class FindingStatus(str, Enum):
    """Forensic status categorization separating direct observation from inference.
    
    Principles:
    - OBSERVED: Directly extracted from raw file bytes, container headers, or metadata.
    - DERIVED: Mathematically computed from observed data without statistical uncertainty.
    - INFERRED: Scientific deduction/hypothesis based on statistical heuristics, models, or profiles.
    - UNKNOWN: Inconclusive or ambiguous forensic evidence.
    - NOT_AVAILABLE: Expected artifact/metadata field was absent in the examined evidence.
    - NOT_CHECKED: The specific analysis module was disabled or not executed.
    """
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"


class Severity(str, Enum):
    """Forensic significance of a finding.
    
    IMPORTANT: Describes evidence anomaly significance, NOT criminal or malicious intent.
    """
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """Qualitative confidence level for forensic inferences."""
    CERTAIN = "CERTAIN"      # 1.0 (for observed / derived facts)
    HIGH = "HIGH"            # >= 0.8
    MEDIUM = "MEDIUM"        # 0.5 - 0.79
    LOW = "LOW"              # < 0.5
    INCONCLUSIVE = "INCONCLUSIVE"


class ImageFormat(str, Enum):
    """Standardized image container formats."""
    JPEG = "JPEG"
    PNG = "PNG"
    WEBP = "WEBP"
    TIFF = "TIFF"
    GIF = "GIF"
    BMP = "BMP"
    HEIF = "HEIF"
    AVIF = "AVIF"
    UNKNOWN = "UNKNOWN"


class ChromaSubsampling(str, Enum):
    """Standard chroma subsampling schemes in YCbCr color spaces."""
    YUV444 = "4:4:4"
    YUV422 = "4:2:2"
    YUV420 = "4:2:0"
    YUV440 = "4:4:0"
    YUV411 = "4:1:1"
    GRAYSCALE = "Grayscale"
    UNKNOWN = "Unknown"


class JPEGMarker:
    """Standard ITU-T T.81 / ISO/IEC 10918-1 JPEG Markers."""
    SOI = 0xFFD8   # Start of Image
    EOI = 0xFFD9   # End of Image
    SOF0 = 0xFFC0  # Baseline DCT
    SOF1 = 0xFFC1  # Extended Sequential DCT
    SOF2 = 0xFFC2  # Progressive DCT
    SOF3 = 0xFFC3  # Lossless (sequential)
    DHT = 0xFFC4   # Define Huffman Table(s)
    SOF5 = 0xFFC5  # Differential sequential DCT
    SOF6 = 0xFFC6  # Differential progressive DCT
    SOF7 = 0xFFC7  # Differential lossless (sequential)
    JPG = 0xFFC8   # Reserved for JPEG extensions
    SOF9 = 0xFFC9  # Extended sequential DCT (arithmetic)
    SOF10 = 0xFFCA # Progressive DCT (arithmetic)
    SOF11 = 0xFFCB # Lossless (arithmetic)
    SOF13 = 0xFFCD # Differential sequential DCT (arithmetic)
    SOF14 = 0xFFCE # Differential progressive DCT (arithmetic)
    SOF15 = 0xFFCF # Differential lossless (arithmetic)
    DAC = 0xFFCC   # Define Arithmetic Coding
    RST0 = 0xFFD0  # Restart Interval 0
    RST1 = 0xFFD1  # Restart Interval 1
    RST2 = 0xFFD2  # Restart Interval 2
    RST3 = 0xFFD3  # Restart Interval 3
    RST4 = 0xFFD4  # Restart Interval 4
    RST5 = 0xFFD5  # Restart Interval 5
    RST6 = 0xFFD6  # Restart Interval 6
    RST7 = 0xFFD7  # Restart Interval 7
    SOS = 0xFFDA   # Start of Scan
    DQT = 0xFFDB   # Define Quantization Table(s)
    DNL = 0xFFDC   # Define Number of Lines
    DRI = 0xFFDD   # Define Restart Interval
    DHP = 0xFFDE   # Define Hierarchical Progression
    EXP = 0xFFDF   # Expand Reference Component(s)
    APP0 = 0xFFE0  # JFIF / JFXX
    APP1 = 0xFFE1  # EXIF / XMP
    APP2 = 0xFFE2  # ICC Profile / FlashPix
    APP3 = 0xFFE3
    APP4 = 0xFFE4
    APP5 = 0xFFE5
    APP6 = 0xFFE6
    APP7 = 0xFFE7
    APP8 = 0xFFE8
    APP9 = 0xFFE9
    APP10 = 0xFFEA
    APP11 = 0xFFEB
    APP12 = 0xFFEC # Picture Info / Duck
    APP13 = 0xFFED # Photoshop IRB / IPTC
    APP14 = 0xFFEE # Adobe DCT filters
    APP15 = 0xFFEF
    COM = 0xFFFE   # Comment
    TEM = 0xFF01   # For temporary private use in arithmetic coding


class SecurityLimits:
    """Defensive thresholds against malformed files and DoS / decompression bombs."""
    MAX_FILE_SIZE_BYTES = 250 * 1024 * 1024  # 250 MB
    MAX_IMAGE_DIMENSION = 30000              # 30,000 pixels on any edge
    MAX_TOTAL_PIXELS = 100_000_000           # 100 Megapixels
    MAX_SEGMENTS_COUNT = 10000               # Prevent infinite loop in chunk/marker parsing
    MAX_METADATA_STRING_LEN = 1_000_000      # 1 MB for individual text/XML metadata payloads
    MAX_RECURSION_DEPTH = 32                 # Recursion safety
