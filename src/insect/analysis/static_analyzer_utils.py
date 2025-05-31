"""
Utility functions for static analyzers.
"""

import logging
from typing import List, Optional, Tuple

from insect.analysis.dependency_manager import DependencyStatus, check_dependency

logger = logging.getLogger(__name__)


def get_snippet_context(
    lines: List[str], line_index: int, context: int = 3
) -> Tuple[int, int, str]:
    """Extracts a snippet with context around a given line index.

    Args:
        lines: List of lines in the file.
        line_index: 0-based index of the line where the finding occurred.
        context: Number of lines to include before and after the target line.

    Returns:
        Tuple containing start index (0-based), end index (0-based, exclusive), and the extracted snippet string.
    """
    start_idx = max(0, line_index - context)
    end_idx = min(len(lines), line_index + context + 1)
    snippet = "\n".join(lines[start_idx:end_idx])
    return (
        start_idx,
        end_idx - 1,
        snippet,
    )  # end_idx adjusted for inclusive range representation


def check_tool_availability(
    tool_name: str,
    analyzer_name: str,
    required: bool = True,  # noqa: ARG001
    version_args: Optional[List[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Check if a required external tool is available in the PATH.

    Args:
        tool_name: The name of the tool executable (e.g., 'bandit', 'semgrep').
        analyzer_name: The name of the analyzer requiring the tool (for logging).
        required: If True, log a warning if the tool is not found.
        version_args: Arguments to check the tool's version (e.g., ["--version"]).

    Returns:
        Tuple containing:
        - bool: True if the tool is found and seems operational, False otherwise.
        - str or None: Installation instructions if tool is not available, None otherwise.
    """
    # Use the new dependency manager for checking tools
    if version_args is None:
        version_args = ["--version"]
    status, version, tool_path = check_dependency(tool_name, analyzer_name)

    if status == DependencyStatus.AVAILABLE:
        return True, None

    # For backward compatibility, return the same simple boolean result plus installation instructions
    if status == DependencyStatus.NOT_FOUND:
        from insect.analysis.dependency_manager import DEPENDENCIES

        if tool_name in DEPENDENCIES:
            install_instructions = DEPENDENCIES[tool_name].get_install_instructions()
            return False, install_instructions

    if status == DependencyStatus.VERSION_MISMATCH:
        logger.warning(
            f"{tool_name.capitalize()} was found but may not function correctly. "
            f"Consider upgrading to a newer version."
        )
        # Still return True for version mismatch, as the tool may still work
        return True, None

    return False, None
