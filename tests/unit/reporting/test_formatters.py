"""Tests for report formatters."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict
from unittest import mock

import pytest

from insect.finding import Finding, FindingType, Location, Severity
from insect.reporting import create_formatter
from insect.reporting.formatters import BaseFormatter
from insect.reporting.html_formatter import HtmlFormatter
from insect.reporting.json_formatter import JsonFormatter
from insect.reporting.text_formatter import TextFormatter


def create_test_finding() -> Finding:
    """Create a test finding for use in tests."""
    return Finding(
        id="TEST-001",
        title="Test Finding",
        description="This is a test finding for unit tests",
        severity=Severity.MEDIUM,
        type=FindingType.SUSPICIOUS,
        location=Location(
            path=Path("/path/to/test.py"),
            line_start=10,
            line_end=15,
            snippet="print('test')",
        ),
        analyzer="test_analyzer",
        confidence=0.8,
        references=["https://example.com/reference"],
        tags=["test", "unit-test"],
        remediation="Fix the test issue",
    )


def create_test_metadata() -> Dict:
    """Create test metadata for use in tests."""
    return {
        "scan_id": "test-scan-id",
        "repository": "/path/to/repo",
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": 1.23,
        "file_count": 100,
        "finding_count": 5,
        "severity_counts": {
            "critical": 1,
            "high": 1,
            "medium": 2,
            "low": 1,
        },
        "type_counts": {
            "vulnerability": 1,
            "secret": 1,
            "suspicious": 2,
            "misconfig": 1,
        },
    }


def test_create_formatter():
    """Test create_formatter factory function."""
    config = {"foo": "bar"}

    # Test valid formats
    text_formatter = create_formatter("text", config)
    assert isinstance(text_formatter, TextFormatter)
    assert text_formatter.config == config

    json_formatter = create_formatter("json", config)
    assert isinstance(json_formatter, JsonFormatter)
    assert json_formatter.config == config

    html_formatter = create_formatter("html", config)
    assert isinstance(html_formatter, HtmlFormatter)
    assert html_formatter.config == config

    # Test invalid format
    with pytest.raises(ValueError, match="Unsupported format"):
        create_formatter("invalid", config)


def test_base_formatter():
    """Test BaseFormatter."""
    config = {"foo": "bar"}
    formatter = BaseFormatter(config)
    assert formatter.config == config

    # format_findings should raise NotImplementedError
    with pytest.raises(NotImplementedError):
        formatter.format_findings([], {})


def test_text_formatter():
    """Test TextFormatter."""
    config = {}
    formatter = TextFormatter(config)
    findings = [create_test_finding()]
    metadata = create_test_metadata()

    result = formatter.format_findings(findings, metadata)
    assert isinstance(result, str)
    assert "Test Finding" in result
    assert "MEDIUM Severity Issues" in result
    assert "/path/to/test.py" in result


def test_json_formatter():
    """Test JsonFormatter."""
    config = {"reports": {"json": {"indent": 2}}}
    formatter = JsonFormatter(config)
    findings = [create_test_finding()]
    metadata = create_test_metadata()

    result = formatter.format_findings(findings, metadata)
    assert isinstance(result, str)

    # Parse the JSON to verify structure
    parsed = json.loads(result)
    assert "scan_metadata" in parsed
    assert "findings" in parsed
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["title"] == "Test Finding"
    assert parsed["findings"][0]["severity"] == "medium"


def test_html_formatter():
    """Test HtmlFormatter."""
    config = {}
    formatter = HtmlFormatter(config)
    findings = [create_test_finding()]
    metadata = create_test_metadata()

    result = formatter.format_findings(findings, metadata)
    assert isinstance(result, str)
    assert "<!DOCTYPE html>" in result
    assert "Test Finding" in result
    assert "<title>Insect Security Report</title>" in result


def test_write_report():
    """Test write_report method."""
    config = {}
    formatter = TextFormatter(config)
    findings = [create_test_finding()]
    metadata = create_test_metadata()

    # Test with no output path (returns string)
    result = formatter.write_report(findings, metadata)
    assert isinstance(result, str)

    # Test with output path (returns Path and writes file)
    with mock.patch("builtins.open", mock.mock_open()) as mock_file:
        output_path = Path("/tmp/test_report.txt")
        result = formatter.write_report(findings, metadata, output_path)
        assert result == output_path
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")
