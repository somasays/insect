"""Tests for the dependency_manager module."""

import json
import sys
from pathlib import Path
from unittest import mock

from insect.analysis.dependency_manager import (
    DEPENDENCIES,
    DependencyInfo,
    DependencyStatus,
    _is_version_sufficient,
    check_dependency,
    generate_dependency_report,
    get_dependencies_status,
    install_dependency,
    install_missing_dependencies,
)


def test_is_version_sufficient():
    """Test the _is_version_sufficient function."""
    # Test basic version comparison
    assert _is_version_sufficient("1.2.3", "1.0.0") is True
    assert _is_version_sufficient("1.0.0", "1.0.0") is True
    assert _is_version_sufficient("0.9.0", "1.0.0") is False

    # Test with different length versions
    assert _is_version_sufficient("1.2", "1.0.0") is True
    assert _is_version_sufficient("1.2.3.4", "1.2.3") is True

    # Test error handling
    assert _is_version_sufficient("invalid", "1.0.0") is True
    assert _is_version_sufficient("1.0.0", "invalid") is True
    assert _is_version_sufficient("", "") is True


def test_dependency_info():
    """Test the DependencyInfo class."""
    # Test basic initialization
    info = DependencyInfo(
        name="test",
        description="Test dependency",
        required=True,
        version_args=["--version"],
        min_version="1.0.0",
        install_instructions={"default": "pip install test"},
    )

    assert info.name == "test"
    assert info.description == "Test dependency"
    assert info.required is True
    assert info.version_args == ["--version"]
    assert info.min_version == "1.0.0"
    assert info.install_instructions == {"default": "pip install test"}

    # Test get_install_instructions with different platforms
    with mock.patch.object(sys, "platform", "linux"):
        assert info.get_install_instructions() == "pip install test"

    # Test platform-specific instructions
    info.install_instructions = {
        "linux": "apt install test",
        "darwin": "brew install test",
        "win32": "choco install test",
        "default": "pip install test",
    }

    with mock.patch.object(sys, "platform", "linux"):
        assert info.get_install_instructions() == "apt install test"

    with mock.patch.object(sys, "platform", "darwin"):
        assert info.get_install_instructions() == "brew install test"

    with mock.patch.object(sys, "platform", "win32"):
        assert info.get_install_instructions() == "choco install test"

    with mock.patch.object(sys, "platform", "unknown"):
        assert info.get_install_instructions() == "pip install test"

    # Test with no platform-specific or default instructions
    info.install_instructions = {}
    assert info.get_install_instructions().startswith("Please install test")


def test_dependencies_registry():
    """Test the DEPENDENCIES registry."""
    # Check that registry contains expected tools
    assert "bandit" in DEPENDENCIES
    assert "semgrep" in DEPENDENCIES
    assert "shellcheck" in DEPENDENCIES

    # Check properties of registry entries
    bandit = DEPENDENCIES["bandit"]
    assert isinstance(bandit, DependencyInfo)
    assert bandit.name == "bandit"
    assert bandit.required is False
    assert bandit.min_version is not None
    assert isinstance(bandit.install_instructions, dict)
    assert "default" in bandit.install_instructions


@mock.patch("shutil.which")
@mock.patch("subprocess.run")
def test_check_dependency_not_found(mock_run, mock_which):
    """Test the check_dependency function when dependency is not found."""
    # Mock dependency not found
    mock_which.return_value = None

    status, version, path = check_dependency("bandit", "test_analyzer")

    assert status == DependencyStatus.NOT_FOUND
    assert version is None
    assert path is None
    mock_which.assert_called_once_with("bandit")
    mock_run.assert_not_called()

    # Test with unknown dependency
    status, version, path = check_dependency("unknown", "test_analyzer")
    assert status == DependencyStatus.NOT_FOUND


@mock.patch("shutil.which")
@mock.patch("subprocess.run")
def test_check_dependency_available(mock_run, mock_which):
    """Test the check_dependency function when dependency is available."""
    # Mock dependency found
    mock_which.return_value = "/usr/bin/bandit"

    # Mock successful run
    mock_process = mock.MagicMock()
    mock_process.stdout = "bandit 1.7.5\n"
    mock_run.return_value = mock_process

    status, version, path = check_dependency("bandit", "test_analyzer")

    assert status == DependencyStatus.AVAILABLE
    assert version == "1.7.5"
    assert path == "/usr/bin/bandit"
    mock_which.assert_called_once_with("bandit")
    mock_run.assert_called_once()


@mock.patch("shutil.which")
@mock.patch("subprocess.run")
def test_check_dependency_version_mismatch(mock_run, mock_which):
    """Test the check_dependency function with version mismatch."""
    # Mock dependency found
    mock_which.return_value = "/usr/bin/bandit"

    # Mock successful run but with old version
    mock_process = mock.MagicMock()
    mock_process.stdout = "bandit 1.0.0\n"
    mock_run.return_value = mock_process

    # The min version for bandit is higher than 1.0.0
    status, version, path = check_dependency("bandit", "test_analyzer")

    assert status == DependencyStatus.VERSION_MISMATCH
    assert version == "1.0.0"
    assert path == "/usr/bin/bandit"


@mock.patch("shutil.which")
@mock.patch("subprocess.run")
def test_check_dependency_broken(mock_run, mock_which):
    """Test the check_dependency function when dependency is broken."""
    # Mock dependency found
    mock_which.return_value = "/usr/bin/bandit"

    # Mock failed run
    mock_run.side_effect = Exception("Command failed")

    status, version, path = check_dependency("bandit", "test_analyzer")

    assert status == DependencyStatus.BROKEN
    assert version is None
    assert path == "/usr/bin/bandit"


@mock.patch("insect.analysis.dependency_manager.check_dependency")
def test_get_dependencies_status(mock_check_dependency):
    """Test the get_dependencies_status function."""

    # Mock check_dependency to return different statuses for different dependencies
    def mock_check_side_effect(dep_name, *args):
        if dep_name == "bandit":
            return DependencyStatus.AVAILABLE, "1.7.5", "/usr/bin/bandit"
        if dep_name == "semgrep":
            return DependencyStatus.NOT_FOUND, None, None
        return DependencyStatus.BROKEN, None, "/usr/bin/shellcheck"

    mock_check_dependency.side_effect = mock_check_side_effect

    # Get dependencies status
    status = get_dependencies_status()

    # Check that all dependencies are included
    assert "bandit" in status
    assert "semgrep" in status
    assert "shellcheck" in status

    # Check specific dependency statuses
    assert status["bandit"]["status"] == "available"
    assert status["bandit"]["version"] == "1.7.5"
    assert status["bandit"]["path"] == "/usr/bin/bandit"

    assert status["semgrep"]["status"] == "not_found"
    assert status["semgrep"]["version"] == "unknown"
    assert status["semgrep"]["path"] == "not found"

    assert status["shellcheck"]["status"] == "broken"


@mock.patch("insect.analysis.dependency_manager.get_dependencies_status")
def test_generate_dependency_report_text(mock_get_dependencies_status):
    """Test the generate_dependency_report function with text format."""
    # Mock get_dependencies_status
    mock_get_dependencies_status.return_value = {
        "bandit": {
            "status": "available",
            "description": "A tool for Python security",
            "required": "False",
            "version": "1.7.5",
            "path": "/usr/bin/bandit",
            "install": "pip install bandit",
        },
        "semgrep": {
            "status": "not_found",
            "description": "A static analysis tool",
            "required": "False",
            "version": "unknown",
            "path": "not found",
            "install": "pip install semgrep",
        },
    }

    # Generate text report
    report = generate_dependency_report("text")

    # Check that the report contains expected information
    assert "Insect External Dependencies" in report
    assert "Bandit" in report
    assert "✓ Available" in report
    assert "Semgrep" in report
    assert "✗ Not Found" in report
    assert "pip install semgrep" in report

    # Check report with output path
    with mock.patch("builtins.open", mock.mock_open()) as mock_file:
        output_path = Path("deps_report.txt")
        result = generate_dependency_report("text", output_path)

        assert result is None
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")


@mock.patch("insect.analysis.dependency_manager.get_dependencies_status")
def test_generate_dependency_report_json(mock_get_dependencies_status):
    """Test the generate_dependency_report function with JSON format."""
    # Mock get_dependencies_status
    mock_deps = {
        "bandit": {
            "status": "available",
            "description": "A tool for Python security",
            "required": "False",
            "version": "1.7.5",
            "path": "/usr/bin/bandit",
            "install": "pip install bandit",
        },
        "semgrep": {
            "status": "not_found",
            "description": "A static analysis tool",
            "required": "False",
            "version": "unknown",
            "path": "not found",
            "install": "pip install semgrep",
        },
    }
    mock_get_dependencies_status.return_value = mock_deps

    # Generate JSON report
    report = generate_dependency_report("json")

    # Parse and check content
    parsed = json.loads(report)
    assert parsed == mock_deps

    # Check with output path
    with mock.patch("builtins.open", mock.mock_open()) as mock_file:
        output_path = Path("deps_report.json")
        result = generate_dependency_report("json", output_path)

        assert result is None
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")


def test_generate_dependency_report_unsupported_format():
    """Test the generate_dependency_report function with unsupported format."""
    result = generate_dependency_report("html")
    assert result is None


@mock.patch("subprocess.run")
@mock.patch("insect.analysis.dependency_manager.check_dependency")
def test_install_dependency(mock_check, mock_run):
    """Test installing a dependency."""

    # Mock successful installation
    mock_run.return_value = mock.MagicMock(returncode=0)
    mock_check.return_value = (DependencyStatus.AVAILABLE, "1.7.4", "/usr/bin/bandit")

    # Test successful installation
    success = install_dependency("bandit")
    assert success is True
    mock_run.assert_called_once()

    # Mock failed installation
    mock_run.reset_mock()
    mock_run.return_value = mock.MagicMock(returncode=1, stderr="Installation failed")

    # Test failed installation
    success = install_dependency("bandit")
    assert success is False
    mock_run.assert_called_once()

    # Test unknown dependency
    mock_run.reset_mock()
    success = install_dependency("unknown")
    assert success is False
    mock_run.assert_not_called()


@mock.patch("insect.analysis.dependency_manager.install_dependency")
@mock.patch("insect.analysis.dependency_manager.get_dependencies_status")
def test_install_missing_dependencies(mock_get_status, mock_install):
    """Test installing all missing dependencies."""

    # Setup mock to return different statuses
    mock_get_status.return_value = {
        "bandit": {"status": "available", "version": "1.7.4"},
        "semgrep": {"status": "not_found", "version": "unknown"},
        "shellcheck": {"status": "broken", "version": "unknown"},
    }

    # Setup installation success/failure
    def mock_install_side_effect(name):
        return name == "semgrep"  # Only semgrep installs successfully

    mock_install.side_effect = mock_install_side_effect

    # Install missing dependencies
    results = install_missing_dependencies()

    # Verify results
    assert results["bandit"] is True  # Already available
    assert results["semgrep"] is True  # Successfully installed
    assert results["shellcheck"] is False  # Failed to install

    # Check install calls
    assert mock_install.call_count == 2  # Only called for missing dependencies
