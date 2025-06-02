"""Tests for the CLI argument parsing."""

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from insect.cli import main, parse_args


class TestCLIArgumentParsing:
    """Test suite for CLI argument parsing."""

    def test_version_action(self, capsys):
        """Test that the version action works correctly."""
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--version"])

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "insect" in captured.out
        assert "." in captured.out  # Version number contains a dot

    def test_help_action(self, capsys):
        """Test that the help action works correctly."""
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--help"])

        assert excinfo.value.code == 0
        captured = capsys.readouterr()
        assert "insect" in captured.out
        assert "Insect - A security scanner" in captured.out

    def test_no_command(self):
        """Test that running without a command shows help and exits."""
        with pytest.raises(SystemExit) as excinfo:
            parse_args([])

        assert excinfo.value.code == 1

    def test_scan_command_required_args(self):
        """Test that the scan command requires a repo path."""
        with pytest.raises(SystemExit):
            parse_args(["scan"])

    def test_scan_command_with_repo_path(self):
        """Test that the scan command with repo path works."""
        args = parse_args(["scan", "/path/to/repo"])
        assert args.command == "scan"
        assert args.repo_path == Path("/path/to/repo")

    def test_scan_command_with_options(self):
        """Test that the scan command with options works."""
        args = parse_args(
            [
                "scan",
                "/path/to/repo",
                "--output",
                "report.json",
                "--format",
                "json",
                "--config",
                "custom_config.toml",
                "--severity",
                "high",
                "--include-pattern",
                "*.py",
                "--exclude-pattern",
                "tests/*",
                "--disable",
                "binary",
                "--max-depth",
                "5",
                "--no-secrets",
            ]
        )

        assert args.command == "scan"
        assert args.repo_path == Path("/path/to/repo")
        assert args.output == Path("report.json")
        assert args.format == "json"
        assert args.config == Path("custom_config.toml")
        assert args.severity == "high"
        assert args.include_pattern == ["*.py"]
        assert args.exclude_pattern == ["tests/*"]
        assert args.disable == ["binary"]
        assert args.max_depth == 5
        assert args.no_secrets is True

    def test_default_values(self):
        """Test that default values are set correctly."""
        args = parse_args(["scan", "/path/to/repo"])

        assert args.format == "text"
        assert args.output is None
        assert args.config is None
        assert args.severity == "low"
        assert args.sensitivity == "normal"  # New default
        assert args.include_pattern is None
        assert args.exclude_pattern is None
        assert args.disable is None
        assert args.max_depth is None
        assert args.no_secrets is False

    def test_verbosity_levels(self):
        """Test that verbosity levels are parsed correctly."""
        # Default verbosity (0)
        args = parse_args(["scan", "/path/to/repo"])
        assert args.verbose == 0

        # Info verbosity (-v)
        args = parse_args(["scan", "/path/to/repo", "-v"])
        assert args.verbose == 1

        # Debug verbosity (-vv)
        args = parse_args(["scan", "/path/to/repo", "-vv"])
        assert args.verbose == 2


class TestCLIMain:
    """Test suite for the main CLI function."""

    def test_main_scan_command(self, capsys):
        """Test that the main function handles the scan command."""
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
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                    },
                },
            )

            mock_args = argparse.Namespace(
                command="scan",
                repo_path=Path("/path/to/repo"),
                verbose=0,
                output=None,
                format="text",
                config=None,
                severity="low",
                sensitivity="normal",  # Add new parameter
                include_pattern=None,
                exclude_pattern=None,
                disable=None,
                max_depth=None,
                no_secrets=False,
                no_cache=False,
                clear_cache=False,
                no_progress=False,
                install_deps=False,
            )
            mock_parse_args.return_value = mock_args

            # Call the main function
            result = main()

            # Verify the result
            assert result == 0

            # Verify that the output contains expected messages
            captured = capsys.readouterr()
            assert "Repository to scan" in captured.out
            assert "/path/to/repo" in captured.out

    def test_main_exception_handling(self, capsys):
        """Test that the main function handles exceptions correctly."""
        with patch("insect.cli.parse_args") as mock_parse_args:
            mock_parse_args.side_effect = Exception("Test error")

            # Call the main function
            result = main()

            # Verify the result
            assert result == 1

            # Verify that the output contains the error message
            captured = capsys.readouterr()
            assert "Error" in captured.out
            assert "Test error" in captured.out
