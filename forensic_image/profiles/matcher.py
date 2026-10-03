"""Reference profile matching framework for platform and encoder consistency analysis.

FORENSIC PRINCIPLE:
Profile matching assesses structural CONSISTENCY with known experimental profiles.
It NEVER establishes definitive source attribution or legal origin on its own.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from forensic_image.core.constants import ConfidenceLevel, FindingStatus, Severity
from forensic_image.core.findings import Finding


class ReferenceProfile(BaseModel):
    """Experimentally collected structural signature of a platform or encoder."""
    profile_id: str
    display_name: str
    category: str  # "social_media", "messaging", "camera", "editor", "screenshot"
    description: str
    format: str
    max_dimension: Optional[int] = None
    allowed_dimensions: Optional[List[List[int]]] = None
    chroma_subsampling: Optional[str] = None
    expected_exif_present: Optional[bool] = None
    expected_gps_present: Optional[bool] = None
    typical_quality_range: Optional[List[int]] = None
    is_progressive_preferred: Optional[bool] = None
    app_markers_signature: Optional[List[str]] = None
    notes: Optional[str] = None


class ProfileMatchResult(BaseModel):
    """Result of comparing evidence against a reference profile."""
    profile_id: str
    display_name: str
    category: str
    consistency_score: float = 0.0  # 0.0 to 1.0
    matched_features: List[str] = Field(default_factory=list)
    unmatched_features: List[str] = Field(default_factory=list)
    interpretation: str = ""
    limitations: List[str] = Field(default_factory=list)


class ProfileMatcher:
    """Compares observed image characteristics against a corpus of reference profiles."""

    def __init__(self, profiles_dir: Optional[Path] = None) -> None:
        self.profiles: List[ReferenceProfile] = []
        if profiles_dir is None:
            profiles_dir = Path(__file__).parent / "data"
        self._load_profiles(profiles_dir)

    def _load_profiles(self, directory: Path) -> None:
        if not directory.exists():
            return
        for file in directory.glob("*.json"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.profiles.append(ReferenceProfile(**data))
            except Exception:
                pass

    def evaluate(self, observed: Dict[str, Any]) -> List[ProfileMatchResult]:
        results: List[ProfileMatchResult] = []
        for prof in self.profiles:
            match = self._compare(prof, observed)
            results.append(match)

        # Sort by consistency score descending
        results.sort(key=lambda x: x.consistency_score, reverse=True)
        return results

    def _compare(self, profile: ReferenceProfile, obs: Dict[str, Any]) -> ProfileMatchResult:
        matched: List[str] = []
        unmatched: List[str] = []
        total_checks = 0
        passed_checks = 0

        # 1. Format check
        obs_fmt = obs.get("format", "").upper()
        if profile.format:
            total_checks += 2
            if obs_fmt == profile.format.upper():
                matched.append(f"Container format matches {profile.format}")
                passed_checks += 2
            else:
                unmatched.append(f"Format mismatch: expected {profile.format}, observed {obs_fmt}")

        # 2. Dimensions check
        obs_w = obs.get("width", 0)
        obs_h = obs.get("height", 0)
        max_edge = max(obs_w, obs_h)
        if profile.max_dimension:
            total_checks += 1
            if max_edge <= profile.max_dimension:
                matched.append(f"Max edge ({max_edge}px) is within profile limit ({profile.max_dimension}px)")
                passed_checks += 1
            else:
                unmatched.append(f"Max edge ({max_edge}px) exceeds profile limit ({profile.max_dimension}px)")

        if profile.allowed_dimensions:
            total_checks += 2
            pair_match = any((obs_w == p[0] and obs_h == p[1]) or (obs_w == p[1] and obs_h == p[0]) for p in profile.allowed_dimensions)
            if pair_match:
                matched.append(f"Exact screen resolution matched ({obs_w}x{obs_h})")
                passed_checks += 2
            else:
                unmatched.append(f"Resolution ({obs_w}x{obs_h}) does not match profile dimensions")

        # 3. Subsampling
        obs_sub = obs.get("chroma_subsampling")
        if profile.chroma_subsampling and obs_sub:
            total_checks += 1
            if obs_sub == profile.chroma_subsampling:
                matched.append(f"Chroma subsampling matches {profile.chroma_subsampling}")
                passed_checks += 1
            else:
                unmatched.append(f"Chroma subsampling differs: expected {profile.chroma_subsampling}, observed {obs_sub}")

        # 4. EXIF presence
        obs_exif = obs.get("has_exif", False)
        if profile.expected_exif_present is not None:
            total_checks += 1
            if obs_exif == profile.expected_exif_present:
                status_str = "present" if profile.expected_exif_present else "stripped/absent"
                matched.append(f"EXIF metadata status ({status_str}) matches expectation")
                passed_checks += 1
            else:
                exp_str = "present" if profile.expected_exif_present else "stripped"
                obs_str = "present" if obs_exif else "stripped"
                unmatched.append(f"EXIF expectation failed: profile expects {exp_str}, file has {obs_str}")

        # 5. GPS presence
        obs_gps = obs.get("has_gps", False)
        if profile.expected_gps_present is not None:
            total_checks += 1
            if obs_gps == profile.expected_gps_present:
                status_str = "present" if profile.expected_gps_present else "stripped"
                matched.append(f"GPS metadata status ({status_str}) matches expectation")
                passed_checks += 1
            else:
                unmatched.append("GPS metadata expectation mismatch")

        # 6. Quality range
        obs_q = obs.get("estimated_quality")
        if profile.typical_quality_range and obs_q:
            total_checks += 1
            q_min, q_max = profile.typical_quality_range
            if q_min <= obs_q <= q_max:
                matched.append(f"Estimated JPEG quality ({obs_q}%) is within expected range [{q_min}, {q_max}]%")
                passed_checks += 1
            else:
                unmatched.append(f"Quality ({obs_q}%) outside typical range [{q_min}, {q_max}]%")

        # 7. Progressive
        obs_prog = obs.get("is_progressive")
        if profile.is_progressive_preferred is not None and obs_prog is not None:
            total_checks += 1
            if obs_prog == profile.is_progressive_preferred:
                matched.append(f"Progressive encoding mode ({obs_prog}) matches profile")
                passed_checks += 1
            else:
                unmatched.append(f"Progressive mode mismatch: expected {profile.is_progressive_preferred}, got {obs_prog}")

        score = (passed_checks / total_checks) if total_checks > 0 else 0.0
        score = round(score, 3)

        return ProfileMatchResult(
            profile_id=profile.profile_id,
            display_name=profile.display_name,
            category=profile.category,
            consistency_score=score,
            matched_features=matched,
            unmatched_features=unmatched,
            interpretation=f"Observed characteristics are {round(score * 100)}% consistent with reference profile '{profile.display_name}'.",
            limitations=[
                "This comparison measures structural consistency only and does NOT constitute platform attribution.",
                "Multiple platforms share common web encoding parameters and CDN recompression libraries.",
            ],
        )
