"""Tests for cache_utils.py."""

import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest

from insect.finding import Finding, FindingType, Location, Severity
from insect.utils.cache_utils import ScanCache, cache_enabled, get_cache_dir


@pytest.fixture
def temp_repo_path():
    """Create a temporary repository path."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def temp_file(temp_repo_path):
    """Create a temporary file."""
    file_path = temp_repo_path / "test_file.py"
    with open(file_path, "w") as f:
        f.write("print('Hello, world!')")
    yield file_path


@pytest.fixture
def sample_finding(temp_file):
    """Create a sample finding."""
    return Finding(
        id="TEST-123",
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        type=FindingType.VULNERABILITY,
        location=Location(
            path=temp_file,
            line_start=1,
            line_end=1,
            column_start=1,
            column_end=10,
            snippet="print('Hello, world!')",
        ),
        analyzer="test_analyzer",
        confidence=0.8,
        references=["https://example.com"],
        tags=["test", "vulnerability"],
        remediation="Fix the issue",
        cwe_id="CWE-123",
        cvss_score=7.5,
    )


def test_cache_enabled():
    """Test the cache_enabled function."""
    # Test with cache enabled
    config = {"cache": {"enabled": True}}
    assert cache_enabled(config) is True

    # Test with cache disabled
    config = {"cache": {"enabled": False}}
    assert cache_enabled(config) is False

    # Test with default when not specified
    config = {}
    assert cache_enabled(config) is True


def test_get_cache_dir():
    """Test the get_cache_dir function."""
    # Test with custom directory
    config = {"cache": {"directory": "/custom/cache/dir"}}
    repo_path = Path("/repo")
    assert get_cache_dir(config, repo_path) == Path("/custom/cache/dir")

    # Test with default directory
    config = {}
    repo_path = Path("/repo")
    assert get_cache_dir(config, repo_path) == Path("/repo/.insect/cache")


def test_scan_cache_init(temp_repo_path):
    """Test ScanCache initialization."""
    # Test with default cache directory
    cache = ScanCache(temp_repo_path)
    assert cache.repo_path == temp_repo_path
    assert cache.cache_dir == temp_repo_path / ".insect" / "cache"
    assert cache.cache_file == temp_repo_path / ".insect" / "cache" / "scan_cache.json"
    assert cache.cache_dir.exists()

    # Test with custom cache directory
    custom_dir = temp_repo_path / "custom_cache"
    cache = ScanCache(temp_repo_path, custom_dir)
    assert cache.repo_path == temp_repo_path
    assert cache.cache_dir == custom_dir
    assert cache.cache_file == custom_dir / "scan_cache.json"
    assert cache.cache_dir.exists()


def test_scan_cache_save_load(temp_repo_path, temp_file):
    """Test saving and loading the cache."""
    cache = ScanCache(temp_repo_path)
    
    # Initial cache should be empty
    assert "file_hashes" in cache.cache_data
    assert len(cache.cache_data["file_hashes"]) == 0
    
    # Add an entry to the cache
    file_path_str = str(temp_file)
    cache.cache_data["file_hashes"][file_path_str] = {
        "hash": "test_hash",
        "mtime": 123456789,
        "analyzers": {
            "test_analyzer": {
                "findings": [],
                "timestamp": datetime.now().isoformat(),
            }
        }
    }
    
    # Save the cache
    cache.save_cache()
    assert cache.cache_file.exists()
    
    # Load the cache in a new instance
    new_cache = ScanCache(temp_repo_path)
    assert file_path_str in new_cache.cache_data["file_hashes"]
    assert new_cache.cache_data["file_hashes"][file_path_str]["hash"] == "test_hash"


def test_is_file_cached(temp_repo_path, temp_file):
    """Test checking if a file is cached."""
    cache = ScanCache(temp_repo_path)
    analyzer_name = "test_analyzer"
    
    # File should not be cached initially
    assert not cache.is_file_cached(temp_file, analyzer_name)
    
    # Add file to cache manually
    file_path_str = str(temp_file)
    cache.cache_data["file_hashes"][file_path_str] = {
        "hash": "test_hash",
        "mtime": os.path.getmtime(temp_file),
        "analyzers": {
            analyzer_name: {
                "findings": [],
                "timestamp": datetime.now().isoformat(),
            }
        }
    }
    
    # File should now be cached
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        assert cache.is_file_cached(temp_file, analyzer_name)
    
    # File should not be cached for a different analyzer
    assert not cache.is_file_cached(temp_file, "different_analyzer")
    
    # Test with modified file (different hash)
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="different_hash"):
        assert not cache.is_file_cached(temp_file, analyzer_name)


def test_cache_findings(temp_repo_path, temp_file, sample_finding):
    """Test caching findings for a file."""
    cache = ScanCache(temp_repo_path)
    analyzer_name = "test_analyzer"
    findings = [sample_finding]
    
    # Cache the findings
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        cache.cache_findings(temp_file, analyzer_name, findings)
    
    # Check that the findings were cached
    file_path_str = str(temp_file)
    assert file_path_str in cache.cache_data["file_hashes"]
    assert analyzer_name in cache.cache_data["file_hashes"][file_path_str]["analyzers"]
    
    cached_findings = cache.cache_data["file_hashes"][file_path_str]["analyzers"][analyzer_name]["findings"]
    assert len(cached_findings) == 1
    assert cached_findings[0]["id"] == sample_finding.id


def test_get_cached_findings(temp_repo_path, temp_file, sample_finding):
    """Test retrieving cached findings."""
    cache = ScanCache(temp_repo_path)
    analyzer_name = "test_analyzer"
    findings = [sample_finding]
    
    # Cache the findings
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        cache.cache_findings(temp_file, analyzer_name, findings)
    
    # Get the cached findings
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        cached_findings = cache.get_cached_findings(temp_file, analyzer_name)
    
    # Check that the retrieved findings match the original
    assert len(cached_findings) == 1
    assert cached_findings[0].id == sample_finding.id
    assert cached_findings[0].title == sample_finding.title
    assert cached_findings[0].severity == sample_finding.severity


def test_clean_old_entries(temp_repo_path, temp_file):
    """Test cleaning old cache entries."""
    cache = ScanCache(temp_repo_path)
    analyzer_name = "test_analyzer"
    file_path_str = str(temp_file)
    
    # Add a recent entry
    recent_time = datetime.now().isoformat()
    cache.cache_data["file_hashes"][file_path_str] = {
        "hash": "test_hash",
        "mtime": os.path.getmtime(temp_file),
        "analyzers": {
            analyzer_name: {
                "findings": [],
                "timestamp": recent_time,
            }
        }
    }
    
    # Add an old entry for a non-existent file
    old_time = (datetime.now() - timedelta(days=31)).isoformat()
    non_existent_file = str(temp_repo_path / "non_existent.py")
    cache.cache_data["file_hashes"][non_existent_file] = {
        "hash": "old_hash",
        "mtime": 123456789,
        "analyzers": {
            analyzer_name: {
                "findings": [],
                "timestamp": old_time,
            }
        }
    }
    
    # Add an old entry for an existing file
    another_analyzer = "another_analyzer"
    cache.cache_data["file_hashes"][file_path_str]["analyzers"][another_analyzer] = {
        "findings": [],
        "timestamp": old_time,
    }
    
    # Clean old entries
    removed = cache.clean_old_entries(max_age_days=30)
    
    # Should have removed 2 entries - the non-existent file and the old analyzer
    assert removed == 2
    
    # Non-existent file should be removed
    assert non_existent_file not in cache.cache_data["file_hashes"]
    
    # Old analyzer entry should be removed but recent one should remain
    assert analyzer_name in cache.cache_data["file_hashes"][file_path_str]["analyzers"]
    assert another_analyzer not in cache.cache_data["file_hashes"][file_path_str]["analyzers"]


def test_cache_stats(temp_repo_path, temp_file, sample_finding):
    """Test cache statistics tracking."""
    cache = ScanCache(temp_repo_path)
    analyzer_name = "test_analyzer"
    
    # Initial stats should be zero
    assert cache.get_cache_stats() == {
        "hits": 0,
        "misses": 0,
        "files_scanned": 0,
        "files_skipped": 0,
    }
    
    # First check should be a miss
    assert not cache.is_file_cached(temp_file, analyzer_name)
    assert cache.get_cache_stats()["misses"] == 1
    
    # Cache the findings
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        cache.cache_findings(temp_file, analyzer_name, [sample_finding])
    
    # Next check should be a hit
    with mock.patch('insect.utils.cache_utils.calculate_file_hash', return_value="test_hash"):
        assert cache.is_file_cached(temp_file, analyzer_name)
    assert cache.get_cache_stats()["hits"] == 1
    
    # Check for a different analyzer should be a miss
    assert not cache.is_file_cached(temp_file, "different_analyzer")
    assert cache.get_cache_stats()["misses"] == 2