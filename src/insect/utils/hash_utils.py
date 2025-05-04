"""Utility functions for hashing and checksumming."""

import hashlib
import secrets
import string
import uuid
from pathlib import Path
from typing import Optional, Union


def calculate_file_hash(
    file_path: Path, algorithm: str = "sha256", block_size: int = 65536
) -> Optional[str]:
    """Calculate hash for a file.

    Args:
        file_path: Path to the file to hash.
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512).
        block_size: Size of blocks to read from file.

    Returns:
        Hexadecimal string representation of the hash, or None if an error occurred.
    """
    if not file_path.exists() or not file_path.is_file():
        return None

    try:
        hash_func = getattr(hashlib, algorithm)()
    except (AttributeError, ValueError):
        return None

    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hash_func.update(block)
        result: str = hash_func.hexdigest()
        return result
    except OSError:
        return None


def calculate_string_hash(data: Union[str, bytes], algorithm: str = "sha256") -> str:
    """Calculate hash for a string or bytes.

    Args:
        data: String or bytes to hash.
        algorithm: Hash algorithm to use (md5, sha1, sha256, sha512).

    Returns:
        Hexadecimal string representation of the hash.
    """
    try:
        hash_func = getattr(hashlib, algorithm)()
    except (AttributeError, ValueError):
        # Default to sha256 if algorithm is invalid
        hash_func = hashlib.sha256()

    if isinstance(data, str):
        hash_func.update(data.encode("utf-8"))
    else:
        hash_func.update(data)

    result: str = hash_func.hexdigest()
    return result


def generate_finding_id(
    analyzer_name: str,
    file_path: str,
    line_number: Optional[int] = None,
    finding_type: str = "vulnerability",
) -> str:
    """Generate a deterministic ID for a finding.

    This ID will be consistent for the same file location and finding type.

    Args:
        analyzer_name: Name of the analyzer that found the issue.
        file_path: Path to the file where the issue was found.
        line_number: Line number where the issue was found, if applicable.
        finding_type: Type of the finding.

    Returns:
        A string ID for the finding.
    """
    # Normalize inputs
    path_str = str(file_path)
    line_str = str(line_number) if line_number is not None else "N/A"

    # Create a deterministic string based on the inputs
    data = f"{analyzer_name}:{path_str}:{line_str}:{finding_type}"

    # Generate hash and use part of it as ID
    hash_hex = calculate_string_hash(data, "sha256")

    # Format as a human-readable ID
    return f"{analyzer_name[:3].upper()}-{hash_hex[:12]}"


def generate_uuid() -> str:
    """Generate a random UUID.

    Returns:
        A string representation of a UUID.
    """
    return str(uuid.uuid4())


def generate_random_string(length: int = 12) -> str:
    """Generate a cryptographically secure random string.

    Args:
        length: Length of the random string.

    Returns:
        A random string of the specified length.
    """
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def normalize_path_for_hashing(path: Union[str, Path]) -> str:
    """Normalize a path for consistent hashing.

    Args:
        path: Path to normalize.

    Returns:
        Normalized path string.
    """
    path_str = str(path) if isinstance(path, Path) else path

    # Normalize path separators
    return path_str.replace("\\", "/")
