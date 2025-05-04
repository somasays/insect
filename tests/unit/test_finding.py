"""Unit tests for the Finding data structure."""

from datetime import datetime
from pathlib import Path

from insect.finding import Finding, FindingType, Location, Severity


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"


def test_finding_type_enum():
    """Test FindingType enum values."""
    assert FindingType.VULNERABILITY == "vulnerability"
    assert FindingType.SECRET == "secret"
    assert FindingType.MISCONFIG == "misconfig"
    assert FindingType.SUSPICIOUS == "suspicious"
    assert FindingType.LICENSE == "license"
    assert FindingType.OTHER == "other"


def test_location_str():
    """Test Location __str__ method."""
    # Location with only path
    loc1 = Location(path=Path("/path/to/file.py"))
    assert str(loc1) == "/path/to/file.py"
    
    # Location with path and line
    loc2 = Location(path=Path("/path/to/file.py"), line_start=10)
    assert str(loc2) == "/path/to/file.py:10"
    
    # Location with path, start and end line
    loc3 = Location(path=Path("/path/to/file.py"), line_start=10, line_end=15)
    assert str(loc3) == "/path/to/file.py:10-15"
    
    # Location with same start and end line
    loc4 = Location(path=Path("/path/to/file.py"), line_start=10, line_end=10)
    assert str(loc4) == "/path/to/file.py:10"


def test_finding_creation():
    """Test creating a Finding instance."""
    location = Location(path=Path("/path/to/file.py"), line_start=10, line_end=15)
    
    finding = Finding(
        id="INSECT-001",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=location,
        analyzer="test_analyzer",
    )
    
    assert finding.id == "INSECT-001"
    assert finding.title == "Test Finding"
    assert finding.description == "This is a test finding"
    assert finding.severity == Severity.MEDIUM
    assert finding.type == FindingType.VULNERABILITY
    assert finding.location == location
    assert finding.analyzer == "test_analyzer"
    assert finding.confidence == 1.0
    assert isinstance(finding.created_at, datetime)
    assert finding.references == []
    assert finding.tags == []
    assert finding.metadata == {}
    assert finding.remediation is None
    assert finding.cwe_id is None
    assert finding.cvss_score is None


def test_finding_to_dict():
    """Test converting a Finding to a dictionary."""
    location = Location(
        path=Path("/path/to/file.py"),
        line_start=10,
        line_end=15,
        column_start=5,
        column_end=20,
        snippet="def vulnerable_func():",
    )
    
    finding = Finding(
        id="INSECT-001",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=location,
        analyzer="test_analyzer",
        confidence=0.95,
        references=["https://example.com/vuln1"],
        tags=["python", "security"],
        metadata={"foo": "bar"},
        remediation="Fix the vulnerability",
        cwe_id="CWE-123",
        cvss_score=7.5,
    )
    
    # Temporarily set a fixed created_at for testing
    fixed_datetime = datetime(2023, 1, 1, 12, 0, 0)
    finding.created_at = fixed_datetime
    
    result = finding.to_dict()
    
    assert result["id"] == "INSECT-001"
    assert result["title"] == "Test Finding"
    assert result["description"] == "This is a test finding"
    assert result["severity"] == "medium"
    assert result["type"] == "vulnerability"
    assert result["location"]["path"] == "/path/to/file.py"
    assert result["location"]["line_start"] == 10
    assert result["location"]["line_end"] == 15
    assert result["location"]["column_start"] == 5
    assert result["location"]["column_end"] == 20
    assert result["location"]["snippet"] == "def vulnerable_func():"
    assert result["analyzer"] == "test_analyzer"
    assert result["confidence"] == 0.95
    assert result["created_at"] == "2023-01-01T12:00:00"
    assert result["references"] == ["https://example.com/vuln1"]
    assert result["tags"] == ["python", "security"]
    assert result["metadata"] == {"foo": "bar"}
    assert result["remediation"] == "Fix the vulnerability"
    assert result["cwe_id"] == "CWE-123"
    assert result["cvss_score"] == 7.5


def test_finding_from_dict():
    """Test creating a Finding from a dictionary."""
    data = {
        "id": "INSECT-001",
        "title": "Test Finding",
        "description": "This is a test finding",
        "severity": "high",
        "type": "secret",
        "location": {
            "path": "/path/to/file.py",
            "line_start": 10,
            "line_end": 15,
            "column_start": 5,
            "column_end": 20,
            "snippet": "api_key = 'SECRET'",
        },
        "analyzer": "secret_analyzer",
        "confidence": 0.8,
        "created_at": "2023-01-01T12:00:00",
        "references": ["https://example.com/secret1"],
        "tags": ["secret", "api-key"],
        "metadata": {"source": "config"},
        "remediation": "Use environment variables",
        "cwe_id": "CWE-798",
        "cvss_score": 8.2,
    }
    
    finding = Finding.from_dict(data)
    
    assert finding.id == "INSECT-001"
    assert finding.title == "Test Finding"
    assert finding.description == "This is a test finding"
    assert finding.severity == Severity.HIGH
    assert finding.type == FindingType.SECRET
    assert str(finding.location.path) == "/path/to/file.py"
    assert finding.location.line_start == 10
    assert finding.location.line_end == 15
    assert finding.location.column_start == 5
    assert finding.location.column_end == 20
    assert finding.location.snippet == "api_key = 'SECRET'"
    assert finding.analyzer == "secret_analyzer"
    assert finding.confidence == 0.8
    assert finding.created_at == datetime(2023, 1, 1, 12, 0, 0)
    assert finding.references == ["https://example.com/secret1"]
    assert finding.tags == ["secret", "api-key"]
    assert finding.metadata == {"source": "config"}
    assert finding.remediation == "Use environment variables"
    assert finding.cwe_id == "CWE-798"
    assert finding.cvss_score == 8.2 