"""Forensic findings model and container maintaining strict separation of evidence and inference."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity


class Finding(BaseModel):
    """A scientifically defensible forensic finding.
    
    Principles:
    - Evidence != Interpretation
    - Every finding explicitly categorizes its epistemic status (OBSERVED, DERIVED, INFERRED, etc.)
    - Inferences must clearly articulate supporting evidence and inherent limitations.
    """
    id: str = Field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    category: str = Field(description="Forensic domain (e.g. METADATA, JPEG, TAMPERING, SCREENSHOT)")
    status: FindingStatus = Field(description="Epistemic status: OBSERVED, DERIVED, INFERRED, UNKNOWN, NOT_AVAILABLE")
    severity: Severity = Field(default=Severity.INFO, description="Forensic significance of the observation")
    title: str = Field(description="Concise title of finding")
    description: str = Field(description="Detailed narrative explaining the observation or inference")
    evidence: List[str] = Field(default_factory=list, description="Directly observable facts supporting this finding")
    confidence: Optional[float] = Field(default=None, description="Numeric confidence if mathematically/statistically justifiable")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.CERTAIN, description="Qualitative confidence rating")
    limitations: List[str] = Field(default_factory=list, description="Forensic caveats, bounds of certainty, and missing data limitations")
    alternative_explanations: List[str] = Field(default_factory=list, description="Plausible non-anomalous reasons for the observed phenomenon")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.model_dump()


class FindingsList(BaseModel):
    """Collection of findings with forensic query and aggregation helpers."""
    items: List[Finding] = Field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.items.append(finding)

    def by_status(self, status: FindingStatus) -> List[Finding]:
        return [f for f in self.items if f.status == status]

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.items if f.severity == severity]

    def by_category(self, category: str) -> List[Finding]:
        return [f for f in self.items if f.category.lower() == category.lower()]

    @property
    def count(self) -> int:
        return len(self.items)

    @property
    def observed_count(self) -> int:
        return len(self.by_status(FindingStatus.OBSERVED))

    @property
    def derived_count(self) -> int:
        return len(self.by_status(FindingStatus.DERIVED))

    @property
    def inferred_count(self) -> int:
        return len(self.by_status(FindingStatus.INFERRED))

    def has_high_severity(self) -> bool:
        return any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in self.items)
