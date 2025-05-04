"""Utility functions for file handling."""

import logging
import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("insect.utils.file")

# Standard text file extensions
TEXT_FILE_EXTENSIONS: Set[str] = {
    ".txt",
    ".md",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".scss",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".zsh",
    ".csh",
    ".ps1",
    ".bat",
    ".cmd",
    ".sql",
    ".r",
    ".dart",
    ".lua",
    ".swift",
    ".m",
    ".mm",
    ".cs",
    ".fs",
    ".groovy",
    ".pl",
    ".scala",
    ".clj",
    ".tsx",
    ".jsx",
    ".vue",
    ".svelte",
    ".elm",
    ".ex",
    ".exs",
    ".erl",
    ".hs",
    ".cabal",
    ".tf",
    ".tfvars",
    ".gradle",
}

# Common binary file extensions
BINARY_FILE_EXTENSIONS: Set[str] = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".obj",
    ".o",
    ".a",
    ".lib",
    ".bin",
    ".dat",
    ".db",
    ".sqlite",
    ".db3",
    ".pyc",
    ".pyo",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".qcow",
    ".qcow2",
    ".vmdk",
    ".vdi",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tiff",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".mkv",
    ".flv",
    ".webm",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".ico",
    ".swf",
}

# Regex patterns for secret detection (basic examples)
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_key": re.compile(
        r'(?i)aws[_\-\.]?(id|key|secret|token)[_\-\.]?(?:key)?[_\-\.]?(id|access|secret)?["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{16,}'
    ),
    "generic_api_key": re.compile(
        r'(?i)(api_?key|apikey|auth[_\-\.]?token)["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{8,}'
    ),
    "password": re.compile(
        r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{8,}'
    ),
    "private_key": re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"),
}


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary.

    This checks the file extension first, then examines the content
    if the extension check is inconclusive.

    Args:
        file_path: Path to the file to check.

    Returns:
        True if the file is binary, False otherwise.
    """
    # Check extension first
    suffix = file_path.suffix.lower()
    if suffix in TEXT_FILE_EXTENSIONS:
        return False
    if suffix in BINARY_FILE_EXTENSIONS:
        return True

    # If extension check is inconclusive, examine file content
    try:
        # Read the first 8KB of the file
        with open(file_path, "rb") as f:
            chunk = f.read(8192)

        # Check for null bytes or other indicators of binary content
        if b"\x00" in chunk:
            return True

        # Try to decode as UTF-8, failure suggests binary
        try:
            chunk.decode("utf-8")
            return False
        except UnicodeDecodeError:
            return True
    except OSError as e:
        logger.warning(f"Error examining file {file_path}: {e}")
        # Default to True (binary) if we can't read the file
        return True


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data.

    Higher entropy (closer to 8.0) suggests encrypted/compressed content.

    Args:
        data: Binary data to analyze.

    Returns:
        Entropy value between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    # Count byte occurrences
    counter = Counter(data)
    file_size = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / file_size
        entropy -= probability * math.log2(probability)

    return entropy


def read_file_safely(file_path: Path) -> Optional[bytes]:
    """Read a file safely, handling errors.

    Args:
        file_path: Path to the file to read.

    Returns:
        File content as bytes if successful, None otherwise.
    """
    try:
        # Always read as bytes for consistency
        with open(file_path, "rb") as f:
            content: bytes = f.read()
        return content
    except OSError as e:
        logger.warning(f"Error reading file {file_path}: {e}")
        return None


def get_file_extension_stats(files: List[Path]) -> Dict[str, int]:
    """Get statistics of file extensions in a list of files.

    Args:
        files: List of file paths.

    Returns:
        Dictionary mapping extensions to counts.
    """
    extension_counts: Dict[str, int] = {}
    for file_path in files:
        ext = file_path.suffix.lower()
        extension_counts[ext] = extension_counts.get(ext, 0) + 1
    return extension_counts


def get_lines_of_interest(
    content: str, line_numbers: List[int], context_lines: int = 2
) -> Dict[int, str]:
    """Extract specific lines from a text file with context.

    Args:
        content: The file content as a string.
        line_numbers: List of line numbers to extract (1-based).
        context_lines: Number of context lines to include before and after.

    Returns:
        Dictionary mapping line numbers to line content.
    """
    lines = content.splitlines()
    result: Dict[int, str] = {}

    for target_line in line_numbers:
        # Convert to 0-based indexing
        idx = target_line - 1
        if 0 <= idx < len(lines):
            # Include the target line
            result[target_line] = lines[idx]

            # Include context before
            for i in range(max(0, idx - context_lines), idx):
                result[i + 1] = lines[i]

            # Include context after
            for i in range(idx + 1, min(len(lines), idx + context_lines + 1)):
                result[i + 1] = lines[i]

    return result


def extract_snippet(
    content: str, start_line: int, end_line: Optional[int] = None, max_lines: int = 5
) -> str:
    """Extract a snippet from file content.

    Args:
        content: The file content as a string.
        start_line: Starting line number (1-based).
        end_line: Ending line number (1-based, inclusive).
        max_lines: Maximum number of lines to include.

    Returns:
        A snippet of the file content.
    """
    lines = content.splitlines()

    # Convert to 0-based indexing
    start_idx = max(0, start_line - 1)

    if end_line is None:
        end_idx = min(len(lines), start_idx + max_lines)
    else:
        end_idx = min(len(lines), end_line)

    # Extract lines
    snippet_lines = lines[start_idx:end_idx]

    return "\n".join(snippet_lines)
