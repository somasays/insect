"""
Utility functions for static analyzers.
"""

import logging
import shutil
import subprocess
from typing import List, Tuple

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
    required: bool = True,
    version_args: List[str] = ["--version"],
) -> bool:
    """Check if a required external tool is available in the PATH.

    Args:
        tool_name: The name of the tool executable (e.g., 'bandit', 'semgrep').
        analyzer_name: The name of the analyzer requiring the tool (for logging).
        required: If True, log a warning if the tool is not found.
        version_args: Arguments to check the tool's version (e.g., ["--version"]).

    Returns:
        True if the tool is found and seems operational, False otherwise.
    """
    tool_path = shutil.which(tool_name)
    if not tool_path:
        if required:
            logger.warning(
                f"{tool_name.capitalize()} is not installed or not in PATH. "
                f"Disabling {tool_name} integration for {analyzer_name}."
            )
        return False

    # Basic check if tool runs
    try:
        subprocess.run(
            [tool_path] + version_args, capture_output=True, check=False, text=True
        )
        logger.debug(f"Tool '{tool_name}' found at: {tool_path} for {analyzer_name}")
        return True
    except Exception as e:
        logger.warning(
            f"Failed to run '{tool_name} {' '.join(version_args)}'. "
            f"{tool_name.capitalize()} might be broken or incorrectly configured "
            f"for {analyzer_name}. Error: {e}"
        )
        return False
