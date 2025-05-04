"""JSON formatter for Insect reports."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from insect.finding import Finding
from insect.reporting.formatters import BaseFormatter


class JsonEncoder(json.JSONEncoder):
    """Custom JSON encoder for Insect types."""

    def default(self, obj: Any) -> Any:
        """Handle special types during JSON encoding.

        Args:
            obj: Object to encode.

        Returns:
            JSON-serializable representation of the object.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


class JsonFormatter(BaseFormatter):
    """JSON formatter for Insect reports."""

    format_name = "json"

    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings as a JSON string.

        Args:
            findings: List of findings.
            metadata: Scan metadata.

        Returns:
            Formatted report as a JSON string.
        """
        # Convert findings to dictionaries
        findings_dicts = [finding.to_dict() for finding in findings]

        # Create the report dictionary
        report = {
            "scan_metadata": metadata,
            "findings": findings_dicts,
        }

        # Convert to JSON with custom encoder and pretty formatting
        indentation = self.config.get("reports", {}).get("json", {}).get("indent", 2)
        json_str = json.dumps(report, cls=JsonEncoder, indent=indentation)

        return json_str
