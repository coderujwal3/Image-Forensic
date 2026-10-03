"""JSON export engine for forensic report structures."""

import json
from typing import Any, Dict


class JSONReporter:
    """Exports forensic reports as strictly typed and canonical JSON."""

    def render(self, report: Any, indent: int = 2) -> str:
        if hasattr(report, "to_json"):
            return report.to_json(indent=indent)
        if hasattr(report, "model_dump_json"):
            return report.model_dump_json(indent=indent)
        return json.dumps(report, indent=indent, default=str)
