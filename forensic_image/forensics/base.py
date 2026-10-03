"""Base interface for modular forensic analyzers."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple
from forensic_image.core.findings import Finding


class BaseAnalyzer(ABC):
    """Abstract base class for all forensic image analyzers."""

    name: str = "base_analyzer"
    description: str = "Base forensic analyzer"
    version: str = "1.0.0"

    @abstractmethod
    def analyze(
        self,
        evidence: Any,  # ImageEvidence instance
        context: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        """Executes forensic analysis on evidence.
        
        Args:
            evidence: The ImageEvidence object holding immutable bytes and container data.
            context: Shared dictionary containing outputs from previous analyzers.
            
        Returns:
            Tuple of:
            - Dict of structured domain-specific data
            - List of forensic Finding objects
        """
        pass
