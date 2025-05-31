"""Tests for the CLI module."""

from pathlib import Path
from unittest.mock import patch

from insect.cli import main, parse_args


def test_parse_args() -> None:
    """Test the argument parser."""
    args = parse_args(["scan", "/path/to/repo"])
    assert args.command == "scan"
    assert args.repo_path == Path("/path/to/repo")


def test_main_exit_code() -> None:
    """Test that main returns the correct exit code."""
    with patch("insect.cli.parse_args") as mock_parse_args, patch(
        "insect.core.scan_repository"
    ) as mock_scan_repository:
        # Set up mock return values
        mock_scan_repository.return_value = (
            [],
            {
                "duration_seconds": 1.0,
                "repository": "/path/to/repo",
                "file_count": 0,
                "finding_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            },
        )

        mock_parse_args.return_value = type(
            "obj",
            (object,),
            {
                "command": "scan",
                "repo_path": Path("/path/to/repo"),
                "verbose": 0,
                "output": None,
                "format": "text",
                "config": None,
                "severity": "low",
                "include_pattern": None,
                "exclude_pattern": None,
                "disable": None,
                "max_depth": None,
                "no_secrets": False,
                "no_cache": False,
                "clear_cache": False,
                "no_progress": False,
                "install_deps": False,
            },
        )
        result = main(["scan", "/path/to/repo"])
        assert result == 0
