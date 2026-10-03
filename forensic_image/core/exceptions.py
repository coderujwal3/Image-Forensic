"""Custom forensic exception hierarchy."""


class ForensicError(Exception):
    """Base class for all forensic analysis exceptions."""
    pass


class CorruptEvidenceError(ForensicError):
    """Raised when evidence file has invalid headers, unexpected EOF, or corrupted data."""
    pass


class SecurityThresholdError(ForensicError):
    """Raised when a security threshold (e.g. decompression bomb, size limit) is violated."""
    pass


class DecompressionBombError(SecurityThresholdError):
    """Raised when image declared dimensions exceed safe memory thresholds."""
    pass


class UnsupportedFormatError(ForensicError):
    """Raised when image format is unknown or not supported for deep analysis."""
    pass


class MalformedSegmentError(ForensicError):
    """Raised when a binary container segment has an impossible offset or length."""
    pass


class VerificationError(ForensicError):
    """Raised when cryptographic evidence verification fails."""
    pass


class ChainOfCustodyError(ForensicError):
    """Raised when evidence manifest or chain of custody integrity is broken."""
    pass
