"""Cryptographic hashing implementation for digital evidence preservation."""

import hashlib
from typing import Dict, Union
from pydantic import BaseModel, Field


class CryptographicHashes(BaseModel):
    """Cryptographic hashes establishing exact byte identity of the evidence."""
    md5: str = Field(description="128-bit MD5 digest (legacy compatibility)")
    sha1: str = Field(description="160-bit SHA-1 digest (legacy compatibility)")
    sha256: str = Field(description="256-bit SHA-256 digest (primary evidence identifier)")
    sha512: str = Field(description="512-bit SHA-512 digest (high-assurance identifier)")
    size_bytes: int = Field(description="Exact file size in bytes")

    def to_dict(self) -> Dict[str, Union[str, int]]:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "sha512": self.sha512,
            "size_bytes": self.size_bytes,
        }


def compute_cryptographic_hashes(data: Union[bytes, memoryview]) -> CryptographicHashes:
    """Computes standard forensic cryptographic hashes on immutable raw bytes.
    
    Args:
        data: Raw immutable byte sequence of the original file.
        
    Returns:
        CryptographicHashes container with MD5, SHA-1, SHA-256, SHA-512 and byte size.
    """
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()

    # Process in 64KB blocks for memory efficiency with large byte views
    chunk_size = 64 * 1024
    mv = memoryview(data)
    total_len = len(mv)

    for i in range(0, total_len, chunk_size):
        chunk = mv[i : i + chunk_size]
        h_md5.update(chunk)
        h_sha1.update(chunk)
        h_sha256.update(chunk)
        h_sha512.update(chunk)

    return CryptographicHashes(
        md5=h_md5.hexdigest(),
        sha1=h_sha1.hexdigest(),
        sha256=h_sha256.hexdigest(),
        sha512=h_sha512.hexdigest(),
        size_bytes=total_len,
    )
