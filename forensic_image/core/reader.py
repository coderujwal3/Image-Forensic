"""Defensive, bounds-checked binary reader for forensic file inspection."""

import io
import struct
from typing import Optional, Union

from forensic_image.core.constants import SecurityLimits
from forensic_image.core.exceptions import CorruptEvidenceError, SecurityThresholdError


class SafeBinaryReader:
    """Zero-crash defensive binary stream reader with strict bounds enforcement."""

    __slots__ = ("_data", "_size", "_pos", "_max_bytes")

    def __init__(
        self,
        data: Union[bytes, bytearray, memoryview],
        max_bytes: int = SecurityLimits.MAX_FILE_SIZE_BYTES,
    ):
        if len(data) > max_bytes:
            raise SecurityThresholdError(
                f"Data size {len(data)} exceeds maximum allowed limit {max_bytes} bytes."
            )
        self._data = memoryview(data)
        self._size = len(self._data)
        self._pos = 0
        self._max_bytes = max_bytes

    @property
    def size(self) -> int:
        return self._size

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return max(0, self._size - self._pos)

    def is_eof(self) -> bool:
        return self._pos >= self._size

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == io.SEEK_END:
            new_pos = self._size + offset
        else:
            raise ValueError(f"Invalid whence argument: {whence}")

        if new_pos < 0 or new_pos > self._size:
            raise CorruptEvidenceError(
                f"Seek out of bounds: target {new_pos}, valid range [0, {self._size}]."
            )
        self._pos = new_pos
        return self._pos

    def read(self, n: int, allow_truncated: bool = False) -> bytes:
        if n < 0:
            raise ValueError(f"Negative read count: {n}")
        if n > self._max_bytes:
            raise SecurityThresholdError(
                f"Requested read of {n} bytes exceeds threshold {self._max_bytes}."
            )
        available = self._size - self._pos
        if n > available:
            if not allow_truncated:
                raise CorruptEvidenceError(
                    f"Unexpected EOF: requested {n} bytes at offset {self._pos}, but only {available} available."
                )
            n = available

        data = bytes(self._data[self._pos : self._pos + n])
        self._pos += n
        return data

    def peek(self, n: int) -> bytes:
        if n < 0:
            raise ValueError(f"Negative peek count: {n}")
        available = self._size - self._pos
        count = min(n, available)
        return bytes(self._data[self._pos : self._pos + count])

    def slice(self, start: int, length: int) -> bytes:
        if start < 0 or length < 0 or (start + length) > self._size:
            raise CorruptEvidenceError(
                f"Invalid slice range [{start}, {start + length}] for size {self._size}."
            )
        return bytes(self._data[start : start + length])

    def find(self, pattern: bytes, start: Optional[int] = None, end: Optional[int] = None) -> int:
        s = self._pos if start is None else start
        e = self._size if end is None else end
        if s < 0 or e > self._size or s > e:
            return -1
        # Convert memoryview window to search
        raw = self._data[s:e]
        idx = bytes(raw).find(pattern)
        if idx == -1:
            return -1
        return s + idx

    def sub_reader(self, length: int) -> "SafeBinaryReader":
        data = self.read(length)
        return SafeBinaryReader(data, max_bytes=self._max_bytes)

    # Fast struct unpackers
    def read_u8(self) -> int:
        if self._pos + 1 > self._size:
            raise CorruptEvidenceError(f"Unexpected EOF reading uint8 at {self._pos}.")
        val = self._data[self._pos]
        self._pos += 1
        return val

    def read_i8(self) -> int:
        val = self.read_u8()
        return val if val < 128 else val - 256

    def read_u16_be(self) -> int:
        raw = self.read(2)
        return struct.unpack(">H", raw)[0]

    def read_u16_le(self) -> int:
        raw = self.read(2)
        return struct.unpack("<H", raw)[0]

    def read_u32_be(self) -> int:
        raw = self.read(4)
        return struct.unpack(">I", raw)[0]

    def read_u32_le(self) -> int:
        raw = self.read(4)
        return struct.unpack("<I", raw)[0]

    def read_u64_be(self) -> int:
        raw = self.read(8)
        return struct.unpack(">Q", raw)[0]

    def read_u64_le(self) -> int:
        raw = self.read(8)
        return struct.unpack("<Q", raw)[0]
