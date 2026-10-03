"""Pluggable analyzer registry allowing modular and extensible forensic pipelines."""

from typing import Dict, List, Optional
from forensic_image.forensics.base import BaseAnalyzer


class AnalyzerRegistry:
    """Registry managing available and active forensic analyzer plugins."""

    def __init__(self) -> None:
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        self._enabled: Dict[str, bool] = {}

    def register(self, analyzer: BaseAnalyzer, enabled: bool = True) -> None:
        name = analyzer.name.lower()
        self._analyzers[name] = analyzer
        self._enabled[name] = enabled

    def unregister(self, name: str) -> None:
        name = name.lower()
        self._analyzers.pop(name, None)
        self._enabled.pop(name, None)

    def enable(self, name: str) -> None:
        name = name.lower()
        if name in self._analyzers:
            self._enabled[name] = True

    def disable(self, name: str) -> None:
        name = name.lower()
        if name in self._analyzers:
            self._enabled[name] = False

    def is_enabled(self, name: str) -> bool:
        return self._enabled.get(name.lower(), False)

    def get(self, name: str) -> Optional[BaseAnalyzer]:
        return self._analyzers.get(name.lower())

    def list_analyzers(self) -> List[Dict[str, str]]:
        return [
            {
                "name": name,
                "description": analyzer.description,
                "version": analyzer.version,
                "enabled": str(self._enabled.get(name, False)),
            }
            for name, analyzer in self._analyzers.items()
        ]

    def get_active_analyzers(self) -> List[BaseAnalyzer]:
        return [
            analyzer
            for name, analyzer in self._analyzers.items()
            if self._enabled.get(name, False)
        ]


# Global singleton registry
default_registry = AnalyzerRegistry()
