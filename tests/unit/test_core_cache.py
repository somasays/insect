"""Tests for caching in the core module."""

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from insect.core import analyze_file, scan_repository
from insect.finding import Finding, FindingType, Location, Severity
from insect.utils.cache_utils import ScanCache


@pytest.fixture
def mock_analyzer():
    """Create a mock analyzer."""
    mock_analyzer = mock.MagicMock()
    mock_analyzer.name = "mock_analyzer"
    mock_analyzer.can_analyze_file.return_value = True
    return mock_analyzer


@pytest.fixture
def sample_finding():
    """Create a sample finding."""
    return Finding(
        id="TEST-123",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=Location(
            path=Path("/test/file.py"),
            line_start=1,
            line_end=1,
        ),
        analyzer="mock_analyzer",
    )


@pytest.fixture
def mock_cache():
    """Create a mock scan cache."""
    mock_cache = mock.MagicMock(spec=ScanCache)
    mock_cache.is_file_cached.return_value = False
    mock_cache.get_cached_findings.return_value = []
    return mock_cache


def test_analyze_file_with_cache(mock_analyzer, sample_finding, mock_cache):
    """Test analyze_file with caching."""
    # Set up mocks
    mock_analyzer.analyze_file.return_value = [sample_finding]
    
    # Test the first scan (cache miss)
    with tempfile.NamedTemporaryFile(suffix=".py") as temp_file:
        file_path = Path(temp_file.name)
        
        # Call analyze_file with cache
        findings = analyze_file(file_path, [mock_analyzer], mock_cache)
        
        # Verify that the analyzer was called
        mock_analyzer.analyze_file.assert_called_once_with(file_path)
        
        # Verify that the findings were cached
        mock_cache.cache_findings.assert_called_once()
        
        # Verify that we got the expected findings
        assert len(findings) == 1
        assert findings[0] == sample_finding
        
        # Reset mocks for the next test
        mock_analyzer.analyze_file.reset_mock()
        mock_cache.is_file_cached.return_value = True
        mock_cache.get_cached_findings.return_value = [sample_finding]
        
        # Call analyze_file again (cache hit)
        findings = analyze_file(file_path, [mock_analyzer], mock_cache)
        
        # Verify that the analyzer was not called
        mock_analyzer.analyze_file.assert_not_called()
        
        # Verify that the cache was used
        mock_cache.is_file_cached.assert_called_with(file_path, "mock_analyzer")
        mock_cache.get_cached_findings.assert_called_with(file_path, "mock_analyzer")
        
        # Verify that we got the expected findings
        assert len(findings) == 1
        assert findings[0] == sample_finding


@mock.patch("insect.core.ScanCache")
@mock.patch("insect.core.create_analyzers")
@mock.patch("insect.core.discover_files")
@mock.patch("insect.core.analyze_file")
def test_scan_repository_with_cache(
    mock_analyze_file, mock_discover_files, mock_create_analyzers, mock_scan_cache_class
):
    """Test scan_repository with caching enabled."""
    # Set up mocks
    mock_scan_cache = mock.MagicMock()
    mock_scan_cache_class.return_value = mock_scan_cache
    
    mock_analyzer = mock.MagicMock()
    mock_analyzer.name = "mock_analyzer"
    mock_analyzer.supported_extensions = {".py"}
    mock_create_analyzers.return_value = [mock_analyzer]
    
    test_file = Path("/test/file.py")
    mock_discover_files.return_value = [test_file]
    
    sample_finding = Finding(
        id="TEST-123",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=Location(
            path=test_file,
            line_start=1,
            line_end=1,
        ),
        analyzer="mock_analyzer",
    )
    mock_analyze_file.return_value = [sample_finding]
    
    # Create a test repository path
    repo_path = Path("/test/repo")
    
    # Configure the test
    config = {
        "analyzers": {"mock_analyzer": True},
        "cache": {"enabled": True},
        "patterns": {"include": ["*"], "exclude": []},
        "general": {"max_depth": 10},
        "severity": {"min_level": "low"},
    }
    
    # Call scan_repository
    findings, metadata = scan_repository(repo_path, config)
    
    # Verify that the cache was initialized
    mock_scan_cache_class.assert_called_once()
    
    # Verify that analyze_file was called with the cache
    mock_analyze_file.assert_called_with(test_file, [mock_analyzer], mock_scan_cache)
    
    # Verify that the cache was saved
    mock_scan_cache.save_cache.assert_called_once()
    
    # Verify that cache stats were added to metadata
    assert "cache_stats" in metadata


@mock.patch("insect.core.ScanCache")
@mock.patch("insect.core.create_analyzers")
@mock.patch("insect.core.discover_files")
@mock.patch("insect.core.analyze_file")
def test_scan_repository_without_cache(
    mock_analyze_file, mock_discover_files, mock_create_analyzers, mock_scan_cache_class
):
    """Test scan_repository with caching disabled."""
    # Set up mocks
    mock_analyzer = mock.MagicMock()
    mock_analyzer.name = "mock_analyzer"
    mock_analyzer.supported_extensions = {".py"}
    mock_create_analyzers.return_value = [mock_analyzer]
    
    test_file = Path("/test/file.py")
    mock_discover_files.return_value = [test_file]
    
    sample_finding = Finding(
        id="TEST-123",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=Location(
            path=test_file,
            line_start=1,
            line_end=1,
        ),
        analyzer="mock_analyzer",
    )
    mock_analyze_file.return_value = [sample_finding]
    
    # Create a test repository path
    repo_path = Path("/test/repo")
    
    # Configure the test with caching disabled
    config = {
        "analyzers": {"mock_analyzer": True},
        "cache": {"enabled": False},
        "patterns": {"include": ["*"], "exclude": []},
        "general": {"max_depth": 10},
        "severity": {"min_level": "low"},
    }
    
    # Call scan_repository
    findings, metadata = scan_repository(repo_path, config)
    
    # Verify that the cache was not initialized
    mock_scan_cache_class.assert_not_called()
    
    # Verify that analyze_file was called without the cache
    mock_analyze_file.assert_called_with(test_file, [mock_analyzer], None)
    
    # Verify that cache stats were not added to metadata
    assert "cache_stats" not in metadata