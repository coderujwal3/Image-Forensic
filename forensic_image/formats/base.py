"""Base container structures and models for binary segment inspection."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BinarySegment(BaseModel):
    """Represents a discrete structural segment, chunk, or marker within a container."""
    name: str = Field(description="Segment or chunk mnemonic (e.g. APP1, DQT, IHDR, IDAT, VP8X)")
    code: Optional[int] = Field(default=None, description="Numeric marker code (e.g. 0xFFE1) if applicable")
    offset: int = Field(description="Absolute byte offset from file start")
    length: int = Field(description="Declared or computed length of segment in bytes")
    payload_offset: Optional[int] = Field(default=None, description="Offset where segment data payload starts")
    payload_length: Optional[int] = Field(default=None, description="Length of payload data excluding headers")
    description: Optional[str] = Field(default=None, description="Human-readable explanation of segment role")
    details: Dict[str, Any] = Field(default_factory=dict, description="Parsed segment-specific metadata")


class ContainerStructure(BaseModel):
    """Structural breakdown of binary container layout."""
    format_name: str
    is_valid_container: bool = True
    header_offset: int = 0
    header_length: int = 0
    segments: List[BinarySegment] = Field(default_factory=list)
    has_trailing_data: bool = False
    trailing_data_offset: Optional[int] = None
    trailing_data_length: int = 0
    anomalies: List[str] = Field(default_factory=list)

    def get_segments_by_name(self, name: str) -> List[BinarySegment]:
        return [s for s in self.segments if s.name.upper() == name.upper()]
