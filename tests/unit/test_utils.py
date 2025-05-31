"""Unit tests for utility functions."""

import hashlib
import math
import string
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

from insect.utils import (  # Hash utilities; File utilities
    SECRET_PATTERNS,
    calculate_entropy,
    calculate_file_hash,
    calculate_string_hash,
    extract_snippet,
    generate_finding_id,
    generate_random_string,
    generate_uuid,
    get_file_extension_stats,
    get_lines_of_interest,
    is_binary_file,
    normalize_path_for_hashing,
    read_file_safely,
)


class TestFileUtils:
    """Tests for file utility functions."""

    def test_is_binary_file_with_text_extension(self):
        """Test is_binary_file with text file extension."""
        with patch("pathlib.Path.suffix", ".py"):
            assert not is_binary_file(Path("test.py"))

    def test_is_binary_file_with_binary_extension(self):
        """Test is_binary_file with binary file extension."""
        with patch("pathlib.Path.suffix", ".exe"):
            assert is_binary_file(Path("test.exe"))

    def test_is_binary_file_checks_content(self):
        """Test is_binary_file checks file content when extension is inconclusive."""
        with tempfile.NamedTemporaryFile(suffix=".unknown") as temp_file:
            # Write text content
            temp_file.write(b"This is text content")
            temp_file.flush()

            assert not is_binary_file(Path(temp_file.name))

            # Write binary content (with null bytes)
            temp_file.seek(0)
            temp_file.write(b"Binary\x00content")
            temp_file.flush()

            assert is_binary_file(Path(temp_file.name))

    def test_is_binary_file_handles_errors(self):
        """Test is_binary_file handles file read errors."""
        # This particular test is tricky because we're dealing with a real file
        # but want to simulate an IO error. Need to make Path.suffix work but open fail.
        nonexistent_path = Path("nonexistent.txt")

        # Create patch context
        patch_suffix = patch.object(Path, "suffix", new_callable=lambda: ".unknown")
        patch_open = patch("builtins.open", side_effect=OSError("Test error"))
        patch_warning = patch("logging.Logger.warning")  # Suppress warning messages

        with patch_suffix, patch_open, patch_warning:
            # Should default to True (binary) on error
            assert is_binary_file(nonexistent_path) is True

    def test_calculate_entropy_empty(self):
        """Test calculate_entropy with empty data."""
        assert calculate_entropy(b"") == 0.0

    def test_calculate_entropy_single_byte(self):
        """Test calculate_entropy with single byte repeated."""
        # All same byte (no entropy)
        assert calculate_entropy(b"A" * 1000) == 0.0

    def test_calculate_entropy_uniform(self):
        """Test calculate_entropy with uniform distribution."""
        # Create data with uniform distribution of bytes (maximum entropy)
        data = bytes(range(256))
        # Maximum entropy for bytes is 8 bits
        assert math.isclose(calculate_entropy(data), 8.0, abs_tol=0.1)

    def test_read_file_safely(self):
        """Test read_file_safely function."""
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b"Test content")
            temp_file.flush()

            # Read in binary mode (default)
            content = read_file_safely(Path(temp_file.name))
            assert content == b"Test content"

            # Test error handling
            patch_open = patch("builtins.open", side_effect=OSError("Test error"))
            patch_warning = patch("logging.Logger.warning")  # Suppress warning messages

            with patch_open, patch_warning:
                assert read_file_safely(Path("nonexistent.txt")) is None

    def test_get_file_extension_stats(self):
        """Test get_file_extension_stats function."""
        paths = [
            Path("file1.py"),
            Path("file2.py"),
            Path("file3.js"),
            Path("file4.txt"),
            Path("file5"),  # No extension
        ]

        stats = get_file_extension_stats(paths)
        assert stats[".py"] == 2
        assert stats[".js"] == 1
        assert stats[".txt"] == 1
        assert stats[""] == 1  # Files with no extension

    def test_get_lines_of_interest(self):
        """Test get_lines_of_interest function."""
        content = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

        # Test single line with context
        lines = get_lines_of_interest(content, [3], context_lines=1)
        assert 2 in lines
        assert lines[2] == "Line 2"
        assert 3 in lines
        assert lines[3] == "Line 3"
        assert 4 in lines
        assert lines[4] == "Line 4"

        # Test multiple lines
        lines = get_lines_of_interest(content, [1, 5], context_lines=1)
        assert 1 in lines
        assert lines[1] == "Line 1"
        assert 2 in lines
        assert lines[2] == "Line 2"
        assert 4 in lines
        assert lines[4] == "Line 4"
        assert 5 in lines
        assert lines[5] == "Line 5"

        # Test out-of-bounds line numbers
        lines = get_lines_of_interest(content, [0, 10], context_lines=1)
        assert 0 not in lines
        assert 10 not in lines

    def test_extract_snippet(self):
        """Test extract_snippet function."""
        content = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

        # Test with start line only
        snippet = extract_snippet(content, 2, max_lines=2)
        assert snippet == "Line 2\nLine 3"

        # Test with start and end line
        snippet = extract_snippet(content, 2, end_line=4)
        assert snippet == "Line 2\nLine 3\nLine 4"

        # Test with out-of-bounds start/end
        snippet = extract_snippet(content, 0, end_line=10)
        assert snippet == "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"

    def test_secret_patterns(self):
        """Test that secret patterns compile and match correctly."""
        # Create specific test strings for each pattern to ensure they match correctly
        test_cases = {
            "aws_key": [
                "aws_key_id = 'AKIAIOSFODNN7EXAMPLE'",
                "AWS_SECRET_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            ],
            "generic_api_key": [
                "api_key = 'a1b2c3d4e5f6g7h8i9j0'",
                "APIKEY='abcdef123456'",
            ],
            "password": [
                "password = 'supersecretpassword123'",
                "pwd='password123456789'",
            ],
            "private_key": [
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFA..."
            ],
        }

        # Test each pattern against its test cases
        for pattern_name, test_strings in test_cases.items():
            pattern = SECRET_PATTERNS[pattern_name]
            for test_string in test_strings:
                match = pattern.search(test_string)
                message = f"Pattern {pattern_name} didn't match: {test_string}"
                assert match is not None, message


# Disable security warnings for SHA-1 in tests
# ruff: noqa: S324
class TestHashUtils:
    """Tests for hash utility functions."""

    def test_calculate_file_hash(self):
        """Test calculate_file_hash function."""
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(b"Test content")
            temp_file.flush()

            # Calculate hash with default algorithm (sha256)
            hash_value = calculate_file_hash(Path(temp_file.name))
            expected_hash = hashlib.sha256(b"Test content").hexdigest()
            assert hash_value == expected_hash

            # Try SHA-1 (for testing the hash calculation function only)
            hash_value = calculate_file_hash(Path(temp_file.name), algorithm="sha1")
            expected_hash = hashlib.sha1(b"Test content").hexdigest()
            assert hash_value == expected_hash

            # Test with nonexistent file
            assert calculate_file_hash(Path("nonexistent.txt")) is None

    def test_calculate_string_hash(self):
        """Test calculate_string_hash function."""
        # Test with string input
        hash_value = calculate_string_hash("Test string")
        expected_hash = hashlib.sha256(b"Test string").hexdigest()
        assert hash_value == expected_hash

        # Test with bytes input
        hash_value = calculate_string_hash(b"Test bytes")
        expected_hash = hashlib.sha256(b"Test bytes").hexdigest()
        assert hash_value == expected_hash

        # Try SHA-1 (for testing the hash calculation function only)
        hash_value = calculate_string_hash("Test string", algorithm="sha1")
        expected_hash = hashlib.sha1(b"Test string").hexdigest()
        assert hash_value == expected_hash

    def test_generate_finding_id(self):
        """Test generate_finding_id function."""
        # Basic functionality
        finding_id = generate_finding_id("test_analyzer", "file.py", 10)
        assert finding_id.startswith("TES-")
        assert len(finding_id) == 16  # "XXX-" + 12 chars

        # Consistency (same inputs should yield same ID)
        finding_id2 = generate_finding_id("test_analyzer", "file.py", 10)
        assert finding_id == finding_id2

        # Different inputs should yield different IDs
        finding_id3 = generate_finding_id("test_analyzer", "file.py", 11)
        assert finding_id != finding_id3

    @patch("uuid.uuid4")
    def test_generate_uuid(self, mock_uuid):
        """Test generate_uuid function."""
        mock_uuid.return_value = uuid.UUID("12345678-1234-5678-1234-567812345678")
        assert generate_uuid() == "12345678-1234-5678-1234-567812345678"

    def test_generate_random_string(self):
        """Test generate_random_string function."""
        # Default length
        random_str = generate_random_string()
        assert len(random_str) == 12
        assert all(c in string.ascii_letters + string.digits for c in random_str)

        # Custom length
        random_str = generate_random_string(length=20)
        assert len(random_str) == 20

    def test_normalize_path_for_hashing(self):
        """Test normalize_path_for_hashing function."""
        # Test with string
        norm_path = normalize_path_for_hashing(r"C:\path\to\file.txt")
        assert norm_path == "C:/path/to/file.txt"

        # Test with Path object
        path_obj = Path(r"C:\path\to\file.txt")
        assert normalize_path_for_hashing(path_obj) == "C:/path/to/file.txt"
