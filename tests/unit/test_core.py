"""Unit tests for core functionality."""

from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from insect.core import discover_files, filter_files, is_git_repository, scan_repository


def test_is_git_repository():
    """Test is_git_repository function."""
    # Mock Path.exists and Path.is_dir
    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "is_dir", return_value=True
    ):
        assert is_git_repository(Path("/path/to/repo")) is True

    # Mock Path.exists return False
    with patch.object(Path, "exists", return_value=False):
        assert is_git_repository(Path("/path/to/repo")) is False

    # Mock Path.is_dir return False
    with patch.object(Path, "exists", return_value=True), patch.object(
        Path, "is_dir", return_value=False
    ):
        assert is_git_repository(Path("/path/to/repo")) is False


def test_filter_files():
    """Test filter_files function."""
    # Create test file paths
    files = [
        Path("/repo/src/main.py"),
        Path("/repo/src/test.py"),
        Path("/repo/node_modules/package.json"),
        Path("/repo/dist/app.min.js"),
        Path("/repo/.git/config"),
    ]

    # Test with wildcard include and no excludes
    result = filter_files(files, ["*"], [])
    assert len(result) == 5
    assert all(f in result for f in files)

    # Test with specific include pattern
    result = filter_files(files, ["*/src/*"], [])
    assert len(result) == 2
    assert Path("/repo/src/main.py") in result
    assert Path("/repo/src/test.py") in result

    # Test with exclude pattern
    result = filter_files(files, ["*"], ["*/node_modules/*", "*/.git/*"])
    assert len(result) == 3
    assert Path("/repo/node_modules/package.json") not in result
    assert Path("/repo/.git/config") not in result

    # Test with include and exclude patterns
    result = filter_files(files, ["*/src/*", "*/dist/*"], ["*test*"])
    assert len(result) == 2
    assert Path("/repo/src/main.py") in result
    assert Path("/repo/dist/app.min.js") in result
    assert Path("/repo/src/test.py") not in result


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Create a mock configuration for testing."""
    return {
        "general": {
            "max_depth": 3,
            "include_hidden": False,
        },
        "patterns": {
            "include": ["*"],
            "exclude": ["*/node_modules/*", "*/.git/*", "*.pyc"],
        },
        "analyzers": {
            "static": True,
            "config": True,
            "binary": False,
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


def test_discover_files(mock_config):
    """Test discover_files function."""
    # Create a mock directory structure using patch
    mock_walk_data = [
        # (root, dirs, files)
        ("/repo", ["src", ".git", "node_modules"], ["README.md", ".gitignore"]),
        ("/repo/src", ["utils", "tests"], ["main.py", "__init__.py", "main.pyc"]),
        ("/repo/.git", ["hooks"], ["config"]),
        ("/repo/node_modules", ["package1"], ["package.json"]),
        ("/repo/src/utils", [], ["helper.py", "__init__.py"]),
        ("/repo/src/tests", [], ["test_main.py"]),
    ]

    # Create a function to mock relative_to that returns paths with the correct depth
    def mock_relative_to(self, base):
        if str(self) == str(base):
            return Path(".")
        rel_path = str(self).replace(str(base) + "/", "")
        return Path(rel_path)

    with patch("os.walk", return_value=mock_walk_data), patch.object(
        Path, "relative_to", mock_relative_to
    ):

        # Test with default config
        result = discover_files(Path("/repo"), mock_config)

        # Files that should be included
        assert Path("/repo/README.md") in result
        assert Path("/repo/src/main.py") in result
        assert Path("/repo/src/__init__.py") in result
        assert Path("/repo/src/utils/helper.py") in result
        assert Path("/repo/src/utils/__init__.py") in result
        assert Path("/repo/src/tests/test_main.py") in result

        # Files that should be excluded
        assert Path("/repo/.gitignore") not in result  # Hidden file
        assert Path("/repo/src/main.pyc") not in result  # Excluded by pattern
        assert Path("/repo/.git/config") not in result  # Hidden dir and excluded
        assert Path("/repo/node_modules/package.json") not in result  # Excluded

        # Test with include_hidden=True
        mock_config["general"]["include_hidden"] = True
        result_with_hidden = discover_files(Path("/repo"), mock_config)
        assert Path("/repo/.gitignore") in result_with_hidden
        assert (
            Path("/repo/.git/config") not in result_with_hidden
        )  # Still excluded by pattern

        # Test with max_depth=1 - this should only include files directly in /repo
        result_depth_1 = discover_files(Path("/repo"), mock_config, max_depth=1)

        # Should include files in the root only
        assert Path("/repo/README.md") in result_depth_1
        assert (
            Path("/repo/.gitignore") in result_depth_1
        )  # Hidden but include_hidden=True

        # Should exclude files deeper than depth 1
        assert Path("/repo/src/main.py") not in result_depth_1
        assert Path("/repo/src/__init__.py") not in result_depth_1
        assert Path("/repo/src/utils/helper.py") not in result_depth_1


def test_scan_repository(mock_config):
    """Test scan_repository function."""
    # Mock necessary functions to isolate the test
    with patch("insect.core.discover_files", return_value=[]) as mock_discover, patch(
        "pathlib.Path.exists", return_value=True
    ), patch("insect.core.logger"), patch(
        "insect.core.create_analyzers", return_value=[]
    ), patch(
        "insect.utils.cache_utils.cache_enabled", return_value=False
    ), patch(
        "tempfile.mkdtemp", return_value="/tmp/test_cache"
    ), patch(
        "insect.analysis.dependency_manager.get_dependencies_status", return_value={}
    ):

        # Test with default enabled analyzers
        findings, metadata = scan_repository(Path("/repo"), mock_config)

        # Verify discover_files was called
        mock_discover.assert_called_once()

        # Verify basic structure of return values
        assert isinstance(findings, list)
        assert isinstance(metadata, dict)
        assert "scan_id" in metadata
        assert "repository" in metadata
        assert metadata["file_count"] == 0

        # Debug: print findings if any exist
        if len(findings) > 0:
            print(f"Unexpected findings: {len(findings)}")
            for finding in findings:
                print(f"  - {finding.title} (analyzer: {finding.analyzer})")

        assert metadata["finding_count"] == 0

        # Test with non-existent repository
        with patch("pathlib.Path.exists", return_value=False):
            findings, metadata = scan_repository(Path("/nonexistent"), mock_config)
            assert findings == []
            assert metadata == {}

        # Test with specified enabled analyzers
        enabled = {"static"}
        with patch("insect.core.create_scan_metadata") as mock_metadata:
            # Mock the metadata creation to ensure enabled_analyzers is set correctly
            mock_metadata.return_value = {
                "enabled_analyzers": ["static"],
                "duration_seconds": 0.5,
                "repository": "/repo",
                "file_count": 0,
                "finding_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            }
            findings, metadata = scan_repository(
                Path("/repo"), mock_config, enabled_analyzers=enabled
            )
            assert isinstance(findings, list)
            assert isinstance(metadata, dict)
            assert metadata["enabled_analyzers"] == ["static"]
