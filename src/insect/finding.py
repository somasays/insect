"""Data structure for representing security findings."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity levels for findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    """Types of findings."""

    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    MISCONFIG = "misconfig"
    SUSPICIOUS = "suspicious"
    LICENSE = "license"
    OTHER = "other"


@dataclass
class Location:
    """Location of a finding in a file."""

    path: Path
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    snippet: Optional[str] = None

    def __str__(self) -> str:
        """Get a string representation of the location."""
        result = str(self.path)
        if self.line_start is not None:
            result += f":{self.line_start}"
            if self.line_end is not None and self.line_end != self.line_start:
                result += f"-{self.line_end}"
        return result


@dataclass
class Finding:
    """Represents a security finding discovered during a scan."""

    id: str
    title: str
    description: str
    severity: Severity
    type: FindingType
    location: Location
    analyzer: str
    confidence: float = 1.0  # From 0.0 to 1.0
    created_at: datetime = field(default_factory=datetime.now)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "type": self.type.value,
            "location": {
                "path": str(self.location.path),
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
                "column_start": self.location.column_start,
                "column_end": self.location.column_end,
                "snippet": self.location.snippet,
            },
            "analyzer": self.analyzer,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "references": self.references,
            "tags": self.tags,
            "metadata": self.metadata,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create a Finding instance from a dictionary."""
        location_data = data.get("location", {})
        location = Location(
            path=Path(location_data.get("path", "")),
            line_start=location_data.get("line_start"),
            line_end=location_data.get("line_end"),
            column_start=location_data.get("column_start"),
            column_end=location_data.get("column_end"),
            snippet=location_data.get("snippet"),
        )

        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=Severity(data.get("severity", "low")),
            type=FindingType(data.get("type", "other")),
            location=location,
            analyzer=data.get("analyzer", ""),
            confidence=data.get("confidence", 1.0),
            created_at=datetime.fromisoformat(
                data.get("created_at", datetime.now().isoformat())
            ),
            references=data.get("references", []),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
            remediation=data.get("remediation"),
            cwe_id=data.get("cwe_id"),
            cvss_score=data.get("cvss_score"),
        )
