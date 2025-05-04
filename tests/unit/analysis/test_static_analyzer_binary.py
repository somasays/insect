"""Unit tests for the binary static analyzer."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from insect.analysis.binary_analyzer import HIGH_ENTROPY_THRESHOLD, BinaryAnalyzer
from insect.finding import FindingType, Severity


class TestBinaryStaticAnalyzer(unittest.TestCase):
    """Unit tests for the binary static analyzer."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_files_dir = Path(self.temp_dir) / "test_files"
        self.test_files_dir.mkdir(exist_ok=True)

        # Basic configuration for testing
        self.config = {
            "analyzers": {"binary_analyzer": True},
            "binary_analyzer": {
                "min_confidence": 0.0,
                "entropy_threshold": HIGH_ENTROPY_THRESHOLD,
                "use_yara": False,  # Don't use YARA for basic tests
                "use_file_command": True,
            },
        }

        # Create a basic binary file for testing
        self.binary_file = self.test_files_dir / "test.bin"
        with open(self.binary_file, "wb") as f:
            # MZ header for Windows EXE
            f.write(b"MZ" + b"\x00" * 100)

        # Create a high entropy binary file
        self.high_entropy_file = self.test_files_dir / "high_entropy.bin"
        with open(self.high_entropy_file, "wb") as f:
            import random

            # Create random bytes for high entropy
            random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
            f.write(random_bytes)

        # Make it executable
        os.chmod(self.high_entropy_file, 0o755)

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)

    def test_init(self):
        """Test analyzer initialization."""
        analyzer = BinaryAnalyzer(self.config)
        assert analyzer.name == "binary_analyzer"
        assert analyzer.enabled
        assert not analyzer.use_yara  # Disabled in config
        assert analyzer.entropy_threshold == HIGH_ENTROPY_THRESHOLD

    def test_supported_extensions(self):
        """Test supported file extensions."""
        analyzer = BinaryAnalyzer(self.config)
        # Check a few common binary extensions
        assert ".exe" in analyzer.supported_extensions
        assert ".dll" in analyzer.supported_extensions
        assert ".so" in analyzer.supported_extensions
        assert ".dylib" in analyzer.supported_extensions

        # Test with different file paths
        assert analyzer.can_analyze_file(Path("test.exe"))
        assert analyzer.can_analyze_file(Path("test.dll"))
        assert not analyzer.can_analyze_file(Path("test.txt"))
        assert not analyzer.can_analyze_file(Path("test.py"))

    @patch("insect.analysis.binary_analyzer.BinaryAnalyzer._calculate_entropy")
    def test_analyze_file_normal_entropy(self, mock_entropy):
        """Test analyzing a file with normal entropy."""
        mock_entropy.return_value = 6.0  # Below threshold

        analyzer = BinaryAnalyzer(self.config)
        findings = analyzer.analyze_file(self.binary_file)

        # Should not have any high entropy findings
        assert not any(f.title == "High entropy binary file" for f in findings)

    @patch("insect.analysis.binary_analyzer.BinaryAnalyzer._calculate_entropy")
    def test_analyze_file_high_entropy(self, mock_entropy):
        """Test analyzing a file with high entropy."""
        mock_entropy.return_value = 7.5  # Above threshold

        analyzer = BinaryAnalyzer(self.config)
        findings = analyzer.analyze_file(self.binary_file)

        # Should have a high entropy finding
        high_entropy_findings = [
            f for f in findings if f.title == "High entropy binary file"
        ]
        assert len(high_entropy_findings) == 1

        finding = high_entropy_findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.type == FindingType.SUSPICIOUS
        assert finding.confidence == 0.7
        assert "entropy" in finding.metadata
        assert finding.metadata["entropy"] == 7.5

    def test_analyze_executable_with_nonstandard_extension(self):
        """Test analyzing an executable file with a non-standard extension."""
        # Create file with non-standard extension
        nonstandard_exe = self.test_files_dir / "hidden_exe.data"
        shutil.copy(self.binary_file, nonstandard_exe)
        os.chmod(nonstandard_exe, 0o755)  # Make executable

        analyzer = BinaryAnalyzer(self.config)

        # Mock low entropy to isolate the executable check
        with patch(
            "insect.analysis.binary_analyzer.BinaryAnalyzer._calculate_entropy",
            return_value=6.0,
        ):
            findings = analyzer.analyze_file(nonstandard_exe)

            # Should detect suspicious executable
            suspicious_findings = [
                f
                for f in findings
                if "Executable file with non-standard extension" in f.title
            ]
            assert len(suspicious_findings) == 1

            finding = suspicious_findings[0]
            assert finding.severity == Severity.MEDIUM
            assert finding.type == FindingType.SUSPICIOUS
            assert "masquerading" in finding.tags

    def test_calculate_entropy(self):
        """Test the entropy calculation function."""
        analyzer = BinaryAnalyzer(self.config)

        # Test with uniform data (high entropy)
        import random

        random.seed(42)  # For reproducibility
        random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
        entropy = analyzer._calculate_entropy(random_bytes)
        assert entropy > 7.0

        # Test with repetitive data (low entropy)
        repetitive_bytes = b"AAAA" * 250
        entropy = analyzer._calculate_entropy(repetitive_bytes)
        assert entropy < 1.0

        # Test with empty data
        assert analyzer._calculate_entropy(b"") == 0.0

    @patch("insect.analysis.binary_analyzer.yara")
    def test_yara_integration(self, mock_yara):
        """Test integration with YARA rules."""
        # Set up mock rule match
        mock_match = MagicMock()
        mock_match.rule = "SuspiciousBinary"
        mock_match.meta = {
            "description": "Test YARA match",
            "severity": "high",
            "references": ["https://example.com/yara-rule"],
        }

        # Set up mock rules
        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        # Set up mock compile
        mock_yara.compile.return_value = mock_rules

        # Configure analyzer to use YARA
        config = self.config.copy()
        config["binary_analyzer"]["use_yara"] = True

        analyzer = BinaryAnalyzer(config)
        analyzer.compiled_rules = mock_rules
        analyzer.use_yara = True

        # Analyze file
        findings = analyzer.analyze_file(self.binary_file)

        # Should have a YARA finding
        yara_findings = [f for f in findings if f.title.startswith("YARA rule match")]
        assert len(yara_findings) == 1

        finding = yara_findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.type == FindingType.SUSPICIOUS
        assert finding.confidence == 0.8
        assert "yara" in finding.tags
        assert finding.metadata["yara_rule"] == "SuspiciousBinary"

    def test_nonexistent_file(self):
        """Test analyzing a nonexistent file."""
        analyzer = BinaryAnalyzer(self.config)
        findings = analyzer.analyze_file(Path("nonexistent_file.exe"))
        assert findings == []

    def test_empty_file(self):
        """Test analyzing an empty file."""
        empty_file = self.test_files_dir / "empty.exe"
        with open(empty_file, "wb"):
            pass  # Create empty file

        analyzer = BinaryAnalyzer(self.config)
        findings = analyzer.analyze_file(empty_file)
        assert findings == []

    def test_analyzer_error_handling(self):
        """Test error handling during analysis."""
        analyzer = BinaryAnalyzer(self.config)

        # Mock file opening to raise an exception
        with patch("builtins.open", side_effect=Exception("Test exception")):
            findings = analyzer.analyze_file(self.binary_file)

            # Should return an error finding
            assert len(findings) == 1
            finding = findings[0]
            assert finding.title == "Failed to analyze binary file"
            assert finding.type == FindingType.OTHER
            assert finding.severity == Severity.LOW
            assert "analyzer-error" in finding.tags


if __name__ == "__main__":
    unittest.main()
