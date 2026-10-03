"""Evidence integrity, manifests, and chain of custody tracking."""

import hashlib
import json
import platform
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.hashing.cryptographic import CryptographicHashes
from forensic_image.version import TOOL_NAME, __version__


class CustodyEvent(BaseModel):
    """An immutable step in the forensic processing of evidence."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    operator: str = Field(default="Forensic Analyst")
    action: str = Field(description="Action executed (e.g. ACQUIRED, HASHED, PARSED, ANALYZED, REPORT_GENERATED)")
    details: Dict[str, Any] = Field(default_factory=dict)


class EvidenceManifest(BaseModel):
    """Forensic evidence manifest documenting acquisition, hashes, and environment."""
    manifest_id: str = Field(default_factory=lambda: f"MAN-{uuid.uuid4().hex[:12].upper()}")
    evidence_id: str = Field(description="Unique identifier for the evidence item")
    filename: str = Field(description="Original file basename as received")
    acquisition_source: str = Field(default="Local filesystem", description="Origin or acquisition reference")
    acquisition_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hashes: CryptographicHashes = Field(description="Cryptographic digests of the original unaltered bytes")
    environment: Dict[str, str] = Field(
        default_factory=lambda: {
            "tool": TOOL_NAME,
            "tool_version": __version__,
            "python_version": sys.version.split()[0],
            "os_system": platform.system(),
            "os_release": platform.release(),
            "os_machine": platform.machine(),
        }
    )
    custody_chain: List[CustodyEvent] = Field(default_factory=list)
    manifest_hash: Optional[str] = Field(default=None, description="SHA-256 of manifest canonical content")

    def record_event(self, action: str, operator: str = "Forensic Analyst", **details: Any) -> None:
        self.custody_chain.append(
            CustodyEvent(
                operator=operator,
                action=action,
                details=details,
            )
        )
        self.update_manifest_hash()

    def update_manifest_hash(self) -> str:
        """Computes deterministic SHA-256 digest of manifest contents excluding manifest_hash."""
        data = self.model_dump(exclude={"manifest_hash"})
        canonical = json.dumps(data, sort_keys=True)
        h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.manifest_hash = h
        return h

    def verify_manifest(self) -> bool:
        if not self.manifest_hash:
            return False
        current_hash = self.manifest_hash
        data = self.model_dump(exclude={"manifest_hash"})
        canonical = json.dumps(data, sort_keys=True)
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return current_hash == computed
