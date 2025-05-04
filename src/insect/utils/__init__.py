"""Utility functions for the Insect security scanner."""

# Import common utilities from modules
from insect.utils.file_utils import (
    BINARY_FILE_EXTENSIONS,
    SECRET_PATTERNS,
    TEXT_FILE_EXTENSIONS,
    calculate_entropy,
    extract_snippet,
    get_file_extension_stats,
    get_lines_of_interest,
    is_binary_file,
    read_file_safely,
)
from insect.utils.hash_utils import (
    calculate_file_hash,
    calculate_string_hash,
    generate_finding_id,
    generate_random_string,
    generate_uuid,
    normalize_path_for_hashing,
)

__all__ = [
    # File utilities
    "is_binary_file",
    "calculate_entropy",
    "read_file_safely",
    "get_file_extension_stats",
    "get_lines_of_interest",
    "extract_snippet",
    "TEXT_FILE_EXTENSIONS",
    "BINARY_FILE_EXTENSIONS",
    "SECRET_PATTERNS",
    # Hash utilities
    "calculate_file_hash",
    "calculate_string_hash",
    "generate_finding_id",
    "generate_uuid",
    "generate_random_string",
    "normalize_path_for_hashing",
]
