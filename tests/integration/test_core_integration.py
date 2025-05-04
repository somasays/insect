"""Integration tests for the core orchestration module."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List, Set
from unittest.mock import MagicMock, patch, call

import pytest

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.core import (
    scan_repository,
    analyze_file,
    discover_files,
    filter_findings,
    create_scan_metadata,
)
from insect.finding import Finding, FindingType, Location, Severity


class MockAnalyzer(BaseAnalyzer):
    """Mock analyzer for testing."""

    name = "mock_analyzer"
    description = "Mock analyzer for testing"
    supported_extensions = {".py", ".js"}
    
    def __init__(self, config):
        """Initialize the mock analyzer."""
        super().__init__(config)
        self.analyzed_files = []
        
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Record the analyzed file and return mock findings."""
        print(f"MockAnalyzer.analyze_file called with {file_path}")
        self.analyzed_files.append(file_path)
        
        # Return a mock finding for Python and JS files
        if file_path.suffix in self.supported_extensions:
            finding = Finding(
                id=f"MOCK-001-{file_path.suffix}",
                title=f"Mock finding for {file_path.name}",
                description=f"This is a mock finding for testing in {file_path}",
                severity=Severity.MEDIUM,
                confidence=0.8,
                type=FindingType.SUSPICIOUS,
                location=Location(
                    path=file_path,
                    line_start=1,
                    line_end=2,
                    column_start=1,
                    column_end=10,
                ),
                analyzer=self.name,
                references=["https://example.com/mock-finding"],
                tags=["mock", "test"],
                metadata={"mock": True},
            )
            return [finding]
        return []


class MockRepoAnalyzer(BaseAnalyzer):
    """Mock repository-level analyzer for testing."""
    
    name = "mock_repo_analyzer"
    description = "Mock repository-level analyzer for testing"
    supported_extensions = {"*"}  # Indicates a repository-level analyzer
    
    def __init__(self, config):
        """Initialize the mock repository analyzer."""
        super().__init__(config)
        self.analyzed_repos = []
        
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Record the repo and return a mock finding."""
        # For repo-level analyzers, we're interested in the repo path
        print(f"MockRepoAnalyzer.analyze_file called with {file_path}")
        repo_path = file_path.parent
        self.analyzed_repos.append(repo_path)
        
        finding = Finding(
            id="MOCK-REPO-001",
            title="Mock repository finding",
            description="This is a mock repository-level finding",
            severity=Severity.HIGH,
            confidence=0.9,
            type=FindingType.SUSPICIOUS,
            location=Location(
                path=repo_path / "repo_file.txt",  # Fake file in the repo
                line_start=None,
                line_end=None,
                column_start=None,
                column_end=None,
            ),
            analyzer=self.name,
            references=["https://example.com/mock-repo-finding"],
            tags=["mock", "repo"],
            metadata={"repo_mock": True},
        )
        return [finding]


# Register mock analyzers for testing
register_analyzer(MockAnalyzer)
register_analyzer(MockRepoAnalyzer)


@pytest.fixture
def test_repo():
    """Create a temporary test repository for integration testing."""
    temp_dir = tempfile.mkdtemp()
    repo_path = Path(temp_dir) / "test_repo"
    repo_path.mkdir()
    
    # Create some test files with different extensions
    python_file = repo_path / "test.py"
    python_file.write_text("print('Hello, World!')")
    
    js_file = repo_path / "test.js"
    js_file.write_text("console.log('Hello, World!');")
    
    txt_file = repo_path / "readme.txt"
    txt_file.write_text("This is a test file.")
    
    # Create a subdirectory with additional files
    subdir = repo_path / "subdir"
    subdir.mkdir()
    subdir_py_file = subdir / "subdir_test.py"
    subdir_py_file.write_text("print('Hello from subdir!')")
    
    # Create a .git directory to simulate a git repo
    git_dir = repo_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("# Mock git config")
    
    yield repo_path
    
    # Clean up after the test
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return {
        "general": {
            "max_depth": 5,
            "include_hidden": False,
        },
        "patterns": {
            "include": ["*"],
            "exclude": ["*/.git/*"],
        },
        "analyzers": {
            "mock_analyzer": True,
            "mock_repo_analyzer": True,
        },
        "severity": {
            "min_level": "LOW",
        },
        "confidence": {
            "min_level": 0.0,
        },
        "allowlist": {
            "findings": [],
            "patterns": [],
        },
    }


@pytest.fixture
def mock_analyzers():
    """Create instances of mock analyzers and patch the analyzer registry."""
    # Mock for get_all_analyzer_classes
    with patch("insect.analysis.get_all_analyzer_classes") as mock_get_analyzers:
        mock_get_analyzers.return_value = {
            "mock_analyzer": MockAnalyzer,
            "mock_repo_analyzer": MockRepoAnalyzer,
        }
        
        # Mock for create_analyzer_instance
        with patch("insect.analysis.create_analyzer_instance") as mock_create_analyzer:
            def side_effect(name, config):
                if name == "mock_analyzer":
                    return MockAnalyzer(config)
                elif name == "mock_repo_analyzer":
                    return MockRepoAnalyzer(config)
                return None
            
            mock_create_analyzer.side_effect = side_effect
            
            yield {
                "get_all_analyzer_classes": mock_get_analyzers,
                "create_analyzer_instance": mock_create_analyzer,
            }


def test_core_integration_analyzer_calls(test_repo, mock_config, mock_analyzers):
    """Test that analyzers are properly called during repository scanning."""
    # Run scan with our mock analyzers
    findings, metadata = scan_repository(test_repo, mock_config)
    
    # We should have some findings (the mock analyzer creates them)
    assert len(findings) > 0
    
    # Look for findings from both analyzers
    has_repo_finding = any(finding.id == 'MOCK-REPO-001' for finding in findings)
    has_py_finding = any(finding.id.endswith('.py') for finding in findings)
    has_js_finding = any(finding.id.endswith('.js') for finding in findings)
    
    assert has_repo_finding, "No repository-level findings"
    assert has_py_finding, "No Python file findings"
    assert has_js_finding, "No JavaScript file findings"
    
    # Verify metadata contains expected fields
    assert "file_count" in metadata
    assert "finding_count" in metadata
    assert "enabled_analyzers" in metadata
    assert "severity_counts" in metadata


def test_core_integration_file_filtering(test_repo, mock_config, mock_analyzers):
    """Test that file filtering works correctly."""
    # Modify config to exclude Python files
    mock_config["patterns"]["exclude"].append("*.py")
    
    # Run scan with our mock analyzers
    findings, metadata = scan_repository(test_repo, mock_config)
    
    # Look for findings - should NOT have Python file findings
    has_py_finding = any(finding.id.endswith('.py') for finding in findings)
    has_js_finding = any(finding.id.endswith('.js') for finding in findings)
    
    assert not has_py_finding, "Found Python file findings despite exclude pattern"
    assert has_js_finding, "No JavaScript file findings"


def test_core_integration_finding_filtering(test_repo, mock_config, mock_analyzers):
    """Test that finding filtering works correctly."""
    # Modify config to filter out MEDIUM severity findings
    mock_config["severity"]["min_level"] = "HIGH"
    
    # Run scan with our mock analyzers
    findings, metadata = scan_repository(test_repo, mock_config)
    
    # Verify only HIGH severity findings were included
    assert all(finding.severity.value >= Severity.HIGH.value for finding in findings), \
        "All findings should be HIGH severity or higher"
    
    # Verify metadata reflects the filtering
    if "severity_counts" in metadata:
        assert metadata["severity_counts"].get("MEDIUM", 0) == 0, \
            "Should have no MEDIUM severity findings"


def test_analyze_file_function(test_repo, mock_config):
    """Test the analyze_file function directly."""
    file_path = test_repo / "test.py"
    
    # Create a mock analyzer directly (not using fixture)
    analyzer = MockAnalyzer(mock_config)
    
    # Analyze the file
    findings = analyze_file(file_path, [analyzer])
    
    # Verify analyzer was called with the file
    assert file_path in analyzer.analyzed_files, f"{file_path} not analyzed"
    
    # Verify expected findings were returned
    assert len(findings) >= 1, "Should have at least one finding"
    assert findings[0].id.startswith("MOCK-"), "Finding should be from mock analyzer"


def test_filter_findings_function(mock_config):
    """Test the filter_findings function directly."""
    # Create findings with different severities
    findings = [
        Finding(
            id="TEST-001",
            title="Low severity finding",
            description="Low finding",
            severity=Severity.LOW,
            confidence=0.5,
            type=FindingType.VULNERABILITY,
            location=None,
            analyzer="test",
        ),
        Finding(
            id="TEST-002",
            title="Medium severity finding",
            description="Medium finding",
            severity=Severity.MEDIUM,
            confidence=0.7,
            type=FindingType.SUSPICIOUS,
            location=None,
            analyzer="test",
        ),
        Finding(
            id="TEST-003",
            title="High severity finding",
            description="High finding",
            severity=Severity.HIGH,
            confidence=0.9,
            type=FindingType.SECRET,
            location=None,
            analyzer="test",
        ),
    ]
    
    # Test filtering by severity
    mock_config["severity"]["min_level"] = "MEDIUM"
    filtered = filter_findings(findings, mock_config)
    assert len(filtered) == 2
    assert filtered[0].severity == Severity.MEDIUM
    assert filtered[1].severity == Severity.HIGH
    
    # Test filtering by confidence
    mock_config["severity"]["min_level"] = "LOW"
    mock_config["confidence"]["min_level"] = 0.8
    filtered = filter_findings(findings, mock_config)
    assert len(filtered) == 1
    assert filtered[0].severity == Severity.HIGH
    
    # Test filtering using allowlist
    mock_config["confidence"]["min_level"] = 0.0
    mock_config["allowlist"]["findings"] = ["TEST-002"]
    filtered = filter_findings(findings, mock_config)
    assert len(filtered) == 2
    assert filtered[0].id == "TEST-001"
    assert filtered[1].id == "TEST-003"


def test_core_integration_error_handling(test_repo, mock_config, mock_analyzers):
    """Test error handling during scanning."""
    # Create an analyzer that raises an exception
    class ErrorAnalyzer(BaseAnalyzer):
        name = "error_analyzer"
        description = "Analyzer that raises an exception"
        supported_extensions = {".py", ".js"}
        
        def analyze_file(self, file_path):
            raise RuntimeError("Simulated analyzer error")
    
    # Register our error analyzer
    register_analyzer(ErrorAnalyzer)
    
    # Modify mock to include our error analyzer
    with patch("insect.analysis.get_all_analyzer_classes") as mock_get_analyzers:
        mock_get_analyzers.return_value = {
            "error_analyzer": ErrorAnalyzer,
            "mock_repo_analyzer": MockRepoAnalyzer,
        }
        
        with patch("insect.analysis.create_analyzer_instance") as mock_create_analyzer:
            def side_effect(name, config):
                if name == "error_analyzer":
                    return ErrorAnalyzer(config)
                elif name == "mock_repo_analyzer":
                    return MockRepoAnalyzer(config)
                return None
            
            mock_create_analyzer.side_effect = side_effect
            
            # Update config to use our error analyzer
            config_with_error = mock_config.copy()
            config_with_error["analyzers"] = {
                "error_analyzer": True,
                "mock_repo_analyzer": True,
            }
            
            # Run the scan (should not crash despite analyzer errors)
            findings, metadata = scan_repository(test_repo, config_with_error)
            
            # There should still be findings from mock_repo_analyzer
            has_repo_findings = any(finding.analyzer == "mock_repo_analyzer" for finding in findings)
            assert has_repo_findings, "Should still have repository-level findings despite errors" 