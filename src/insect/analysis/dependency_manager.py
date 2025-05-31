"""
Dependency management for external tools used by analyzers.

This module provides utilities for checking, verifying, and providing
installation guidance for external tools that Insect can optionally use
for enhanced security analysis.
"""

import logging
import shutil
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DependencyStatus(Enum):
    """Status of an external dependency."""

    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    VERSION_MISMATCH = "version_mismatch"
    BROKEN = "broken"


class DependencyInfo:
    """Information about an external dependency."""

    def __init__(
        self,
        name: str,
        description: str,
        required: bool = False,
        version_args: Optional[List[str]] = None,
        min_version: Optional[str] = None,
        install_instructions: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize dependency information.

        Args:
            name: Name of the executable (e.g., 'bandit', 'semgrep')
            description: Description of what the tool does
            required: Whether the tool is required (True) or optional (False)
            version_args: Command-line arguments to check the tool's version
            min_version: Minimum version required (semver format)
            install_instructions: Dict mapping platform to installation instructions
        """
        if version_args is None:
            version_args = ["--version"]
        self.name = name
        self.description = description
        self.required = required
        self.version_args = version_args
        self.min_version = min_version
        self.install_instructions = install_instructions or {}

    def get_install_instructions(self, platform: Optional[str] = None) -> str:
        """Get installation instructions for the current or specified platform.

        Args:
            platform: Platform to get instructions for. If None, uses sys.platform.

        Returns:
            Installation instructions as a string.
        """
        if platform is None:
            platform = sys.platform

        # Try to get platform-specific instructions
        if platform in self.install_instructions:
            return self.install_instructions[platform]

        # Fall back to default instructions
        if "default" in self.install_instructions:
            return self.install_instructions["default"]

        # Generic instructions if nothing else is available
        return f"Please install {self.name} to enable additional security scanning capabilities."


# Registry of external tools used by Insect
DEPENDENCIES = {
    "bandit": DependencyInfo(
        name="bandit",
        description="A tool designed to find common security issues in Python code",
        required=False,
        version_args=["--version"],
        min_version="1.7.0",
        install_instructions={
            "default": "pip install bandit",
            "darwin": "pip install bandit or brew install bandit",
            "linux": "pip install bandit or use your distribution's package manager",
            "win32": "pip install bandit",
        },
    ),
    "semgrep": DependencyInfo(
        name="semgrep",
        description="A lightweight static analysis tool for many languages",
        required=False,
        version_args=["--version"],
        min_version="0.90.0",
        install_instructions={
            "default": "pip install semgrep",
            "darwin": "pip install semgrep or brew install semgrep",
            "linux": "pip install semgrep or use your distribution's package manager",
            "win32": "pip install semgrep",
        },
    ),
    "shellcheck": DependencyInfo(
        name="shellcheck",
        description="A shell script static analysis tool",
        required=False,
        install_instructions={
            "default": "https://github.com/koalaman/shellcheck#installing",
            "darwin": "brew install shellcheck",
            "linux": "apt-get install shellcheck or use your distribution's package manager",
            "win32": "Install using Chocolatey: choco install shellcheck",
        },
    ),
    "trivy": DependencyInfo(
        name="trivy",
        description="A comprehensive vulnerability scanner for containers and other artifacts",
        required=False,
        version_args=["--version"],
        min_version="0.30.0",
        install_instructions={
            "default": "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
            "darwin": "brew install trivy",
            "linux": "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add - && echo 'deb https://aquasecurity.github.io/trivy-repo/deb generic main' | sudo tee -a /etc/apt/sources.list && sudo apt-get update && sudo apt-get install trivy",
            "win32": "choco install trivy",
        },
    ),
    "grype": DependencyInfo(
        name="grype",
        description="A vulnerability scanner for container images and filesystems",
        required=False,
        version_args=["version"],
        min_version="0.60.0",
        install_instructions={
            "default": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "darwin": "brew install grype",
            "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
            "win32": "Download from https://github.com/anchore/grype/releases",
        },
    ),
    "safety": DependencyInfo(
        name="safety",
        description="A command line tool that checks Python dependencies for known security vulnerabilities",
        required=False,
        version_args=["--version"],
        min_version="2.0.0",
        install_instructions={
            "default": "pip install safety",
            "darwin": "pip install safety",
            "linux": "pip install safety",
            "win32": "pip install safety",
        },
    ),
    "npm": DependencyInfo(
        name="npm",
        description="Node.js package manager with audit capabilities",
        required=False,
        version_args=["--version"],
        min_version="8.0.0",
        install_instructions={
            "default": "https://nodejs.org/en/download/",
            "darwin": "brew install node",
            "linux": "curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs",
            "win32": "Download from https://nodejs.org/en/download/",
        },
    ),
}


def check_dependency(
    dependency_name: str,
    analyzer_name: str,
) -> Tuple[DependencyStatus, Optional[str], Optional[str]]:
    """Check if a dependency is available and meets requirements.

    Args:
        dependency_name: Name of the dependency to check
        analyzer_name: Name of the analyzer requiring this dependency (for logging)

    Returns:
        Tuple containing:
        - DependencyStatus: Status of the dependency
        - Optional[str]: Version string if available, None otherwise
        - Optional[str]: Path to the executable if found, None otherwise
    """
    if dependency_name not in DEPENDENCIES:
        logger.warning(f"Unknown dependency: {dependency_name}")
        return DependencyStatus.NOT_FOUND, None, None

    dependency = DEPENDENCIES[dependency_name]
    tool_path = shutil.which(dependency_name)

    if not tool_path:
        if dependency.required:
            logger.warning(
                f"{dependency_name.capitalize()} is not installed or not in PATH. "
                f"This is required for {analyzer_name}."
            )
        else:
            logger.info(
                f"{dependency_name.capitalize()} is not installed or not in PATH. "
                f"Some features in {analyzer_name} will be disabled."
            )
        return DependencyStatus.NOT_FOUND, None, None

    # Basic check if tool runs and get version
    try:
        result = subprocess.run(
            [tool_path] + dependency.version_args,
            capture_output=True,
            check=False,
            text=True,
        )

        # Try to extract version from output
        version = None
        if result.stdout:
            # Simple extraction - just take the first line and the first number that looks like a version
            lines = result.stdout.strip().split("\n")
            for line in lines:
                # Look for patterns like "1.2.3" or "v1.2.3" or "version 1.2.3"
                parts = line.replace("v", " ").replace("version", " ").split()
                for part in parts:
                    if part and part[0].isdigit() and "." in part:
                        version = part
                        break
                if version:
                    break

        # Check minimum version if specified
        if (
            dependency.min_version
            and version
            and not _is_version_sufficient(version, dependency.min_version)
        ):
            logger.warning(
                f"{dependency_name.capitalize()} version {version} is lower than "
                f"the recommended minimum version {dependency.min_version}."
            )
            return DependencyStatus.VERSION_MISMATCH, version, tool_path

        logger.debug(
            f"Tool '{dependency_name}' v{version or 'unknown'} found at: {tool_path} "
            f"for {analyzer_name}"
        )
        return DependencyStatus.AVAILABLE, version, tool_path

    except Exception as e:
        logger.warning(
            f"Failed to run '{dependency_name} {' '.join(dependency.version_args)}'. "
            f"{dependency_name.capitalize()} might be broken or incorrectly configured "
            f"for {analyzer_name}. Error: {e}"
        )
        return DependencyStatus.BROKEN, None, tool_path


def get_dependencies_status() -> Dict[str, Dict[str, str]]:
    """Get the status of all registered dependencies.

    Returns:
        Dict mapping dependency names to their status information.
    """
    result = {}

    for name, dependency in DEPENDENCIES.items():
        status, version, path = check_dependency(name, "status_check")
        result[name] = {
            "status": status.value,
            "description": dependency.description,
            "required": str(dependency.required),
            "version": version or "unknown",
            "path": path or "not found",
            "install": dependency.get_install_instructions(),
        }

    return result


def _is_version_sufficient(current: str, minimum: str) -> bool:
    """Check if current version meets the minimum required version.

    Args:
        current: Current version string (e.g., "1.2.3")
        minimum: Minimum required version string (e.g., "1.0.0")

    Returns:
        True if current version is greater than or equal to minimum, False otherwise.
    """
    try:
        # Simple semver comparison - split by dots and compare each component
        current_parts = [int(x) for x in current.split(".")]
        minimum_parts = [int(x) for x in minimum.split(".")]

        # Pad with zeros if needed
        while len(current_parts) < len(minimum_parts):
            current_parts.append(0)
        while len(minimum_parts) < len(current_parts):
            minimum_parts.append(0)

        # Compare each component
        for c, m in zip(current_parts, minimum_parts):
            if c > m:
                return True
            if c < m:
                return False

        # Equal versions
        return True

    except (ValueError, IndexError, TypeError):
        # If parsing fails, assume version is sufficient
        logger.warning(f"Failed to parse version numbers: {current} vs {minimum}")
        return True


def install_dependency(dependency_name: str) -> bool:
    """Attempt to install a missing dependency.

    Args:
        dependency_name: Name of the dependency to install

    Returns:
        True if installation was successful, False otherwise
    """
    if dependency_name not in DEPENDENCIES:
        logger.warning(f"Unknown dependency: {dependency_name}")
        return False

    dependency = DEPENDENCIES[dependency_name]
    platform = sys.platform

    # Get install instructions for this platform
    if platform in dependency.install_instructions:
        install_cmd = dependency.install_instructions[platform]
    else:
        install_cmd = dependency.install_instructions.get("default", "")

    if not install_cmd:
        logger.warning(
            f"No installation instructions available for {dependency_name} on {platform}"
        )
        return False

    # If multiple installation methods are provided, use the first one (usually pip)
    if " or " in install_cmd:
        install_cmd = install_cmd.split(" or ")[0].strip()

    # Execute the installation command
    logger.info(f"Installing {dependency_name} using: {install_cmd}")
    try:
        # Split the command into parts
        cmd_parts = install_cmd.split()

        # Run the installation command
        result = subprocess.run(cmd_parts, capture_output=True, check=False, text=True)

        if result.returncode != 0:
            logger.error(f"Failed to install {dependency_name}: {result.stderr}")
            return False

        logger.info(f"Successfully installed {dependency_name}")

        # Verify installation
        status, version, path = check_dependency(
            dependency_name, "install_verification"
        )
        return status == DependencyStatus.AVAILABLE

    except Exception as e:
        logger.error(f"Error installing {dependency_name}: {e}")
        return False


def install_missing_dependencies() -> Dict[str, bool]:
    """Attempt to install all missing dependencies.

    Returns:
        Dictionary mapping dependency names to installation success (True/False)
    """
    results = {}

    dependencies = get_dependencies_status()
    for name, info in dependencies.items():
        if info["status"] != "available":
            logger.info(f"Attempting to install missing dependency: {name}")
            results[name] = install_dependency(name)
        else:
            logger.debug(f"Dependency {name} is already available")
            results[name] = True

    return results


def generate_dependency_report(
    format_type: str = "text", output_path: Optional[Path] = None
) -> Optional[str]:
    """Generate a report on the status of all dependencies.

    Args:
        format_type: Format of the report ("text", "json", or "html")
        output_path: Path to write the report to. If None, returns the report as a string.

    Returns:
        If output_path is None, the report as a string. Otherwise, None.
    """
    # TODO: Implement full report generation

    dependencies = get_dependencies_status()

    if format_type == "text":
        result = ["# Insect External Dependencies\n"]

        for name, info in dependencies.items():
            status_label = {
                "available": "✓ Available",
                "not_found": "✗ Not Found",
                "version_mismatch": "⚠ Version Mismatch",
                "broken": "✗ Broken Installation",
            }.get(info["status"], "? Unknown")

            result.append(f"## {name.capitalize()}")
            result.append(f"Status: {status_label}")
            result.append(f"Description: {info['description']}")
            result.append(f"Version: {info['version']}")
            result.append(f"Path: {info['path']}")
            if info["status"] != "available":
                result.append("\nInstallation Instructions:")
                result.append(f"  {info['install']}")
            result.append("\n")

        report = "\n".join(result)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
            return None

        return report

    if format_type == "json":
        import json

        report = json.dumps(dependencies, indent=2)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
            return None

        return report

    logger.warning(f"Unsupported report format: {format_type}")
    return None
