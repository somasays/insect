"""Tests for the malicious character analyzer."""

from pathlib import Path

import pytest

from insect.analysis.malicious_character_analyzer import MaliciousCharacterAnalyzer
from insect.finding import FindingType


@pytest.fixture
def analyzer():
    """Create a malicious character analyzer instance."""
    config = {"malicious_character": {"sensitivity": "medium"}}
    return MaliciousCharacterAnalyzer(config)


@pytest.fixture
def high_sensitivity_analyzer():
    """Create a high sensitivity analyzer instance."""
    config = {"malicious_character": {"sensitivity": "high"}}
    return MaliciousCharacterAnalyzer(config)


class TestMaliciousCharacterAnalyzer:
    """Test the malicious character analyzer."""

    def test_analyzer_metadata(self, analyzer):
        """Test analyzer metadata."""
        assert analyzer.name == "malicious_character"
        assert analyzer.description == (
            "Detects malicious Unicode characters and obfuscation techniques"
        )
        assert analyzer.supported_extensions == {"*"}

    def test_invisible_character_detection(self, analyzer, tmp_path):
        """Test detection of invisible characters."""
        # Create file with zero-width characters
        test_file = tmp_path / "invisible.py"
        content = "def login​(username, password):  # Zero-width space after login\n"
        content += "    return True\u200b  # Another zero-width space\n"
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) == 2
        assert all(f.type == FindingType.SUSPICIOUS for f in findings)
        assert all("Invisible character" in f.title for f in findings)

    def test_bidirectional_text_detection(self, analyzer, tmp_path):
        """Test detection of bidirectional control characters."""
        # Create file with RLO (Right-to-Left Override)
        test_file = tmp_path / "bidi.py"
        content = 'if access_level != "user\u202e \u2066// Check if admin\u2069 ":\n'
        content += "    # This comment appears normal but has bidi chars\n"
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) >= 1
        assert any("Bidirectional control character" in f.title for f in findings)
        assert all(
            f.severity.value == "high" for f in findings if "Bidirectional" in f.title
        )

    def test_homograph_detection(self, analyzer, tmp_path):
        """Test detection of Unicode homograph attacks."""
        # Create file with mixed scripts (Latin and Cyrillic)
        test_file = tmp_path / "homograph.py"
        # Using Cyrillic 'а' instead of Latin 'a'
        content = "def аuthenticate(user):  # Cyrillic 'а' in authenticate\n"
        content += "    pаssword = input()  # Cyrillic 'а' in password\n"
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) >= 1
        assert any("Mixed Unicode scripts" in f.title for f in findings)

    def test_path_traversal_detection(self, analyzer, tmp_path):
        """Test detection of path traversal patterns."""
        test_file = tmp_path / "traversal.py"
        content = 'file_path = "../../../etc/passwd"\n'
        content += 'backup = "..\\\\..\\\\windows\\\\system32"\n'
        content += 'encoded = "%2e%2e%2f%2e%2e%2f"\n'
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) >= 3
        assert all(f.type == FindingType.VULNERABILITY for f in findings)
        assert all(f.severity.value == "high" for f in findings)

    def test_command_injection_detection(self, analyzer, tmp_path):
        """Test detection of command injection patterns."""
        test_file = tmp_path / "injection.sh"
        content = 'eval "echo $USER_INPUT"\n'
        content += "result=`cat /etc/passwd`\n"
        content += "data=$(curl $URL)\n"
        content += 'cmd="ls -la; rm -rf /"\n'
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) >= 3
        assert all(f.type == FindingType.VULNERABILITY for f in findings)

    def test_dangerous_filename_detection(self, analyzer, tmp_path):
        """Test detection of dangerous filenames."""
        # Test Windows reserved name
        dangerous_file = tmp_path / "CON.txt"
        dangerous_file.write_text("content")

        findings = analyzer.analyze_file(dangerous_file)
        assert len(findings) == 1
        assert findings[0].type == FindingType.SUSPICIOUS
        assert "Dangerous filename" in findings[0].title
        assert findings[0].severity.value == "high"

    def test_long_filename_detection(self, analyzer, tmp_path):
        """Test detection of excessively long filenames."""
        # Create file with very long name (200 chars works on most systems)
        long_name = "a" * 200 + ".txt"
        long_file = tmp_path / long_name
        long_file.write_text("content")

        # Test with analyzer on a path with 260+ char filename (without creating it)
        very_long_path = tmp_path / ("b" * 260 + ".txt")
        findings = analyzer.analyze_file(very_long_path)
        assert len(findings) == 1
        assert "Excessively long filename" in findings[0].title

    def test_sensitivity_levels(self, analyzer, high_sensitivity_analyzer, tmp_path):
        """Test different sensitivity levels."""
        test_file = tmp_path / "sensitivity.py"
        content = 'cmd = "echo test | grep pattern"\n'
        test_file.write_text(content, encoding="utf-8")

        # Medium sensitivity should detect command injection
        medium_findings = analyzer.analyze_file(test_file)
        assert len(medium_findings) >= 1

        # High sensitivity should detect the same or more
        high_findings = high_sensitivity_analyzer.analyze_file(test_file)
        assert len(high_findings) >= len(medium_findings)

    def test_unicode_script_detection(self, analyzer):
        """Test Unicode script detection helper."""
        assert analyzer._get_script("a") == "Latin"
        assert analyzer._get_script("а") == "Cyrillic"  # Cyrillic а
        assert analyzer._get_script("α") == "Greek"  # Greek alpha
        assert analyzer._get_script("א") == "Hebrew"
        assert analyzer._get_script("ا") == "Arabic"

    def test_mixed_content_file(self, analyzer, tmp_path):
        """Test file with multiple types of malicious patterns."""
        test_file = tmp_path / "mixed.py"
        content = "# Evil script with multiple attacks\n"
        content += 'path = "../../../etc/passwd"  # Path traversal\n'
        content += "cmd = `whoami`  # Command injection\n"
        content += 'password = "secret\u200b"  # Invisible char\n'
        content += 'if user == "admin\u202e": # Bidi attack\n'
        content += "    grant_аccess()  # Homograph attack (Cyrillic а)\n"
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)

        # Should detect multiple attack types
        types = {f.type for f in findings}
        assert FindingType.VULNERABILITY in types
        assert FindingType.SUSPICIOUS in types

        # Check for specific detections
        assert any("Path traversal" in f.title for f in findings)
        assert any("Invisible character" in f.title for f in findings)
        assert any("Bidirectional" in f.title for f in findings)

    def test_binary_file_handling(self, analyzer, tmp_path):
        """Test handling of binary files."""
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        # Should not crash on binary files
        findings = analyzer.analyze_file(binary_file)
        # May or may not have findings, but shouldn't crash
        assert isinstance(findings, list)

    def test_empty_file(self, analyzer, tmp_path):
        """Test handling of empty files."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        findings = analyzer.analyze_file(empty_file)
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_non_existent_file(self, analyzer):
        """Test handling of non-existent files."""
        findings = analyzer.analyze_file(Path("/non/existent/file.txt"))
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_special_unicode_categories(self, analyzer, tmp_path):
        """Test detection of various Unicode category characters."""
        test_file = tmp_path / "unicode_cats.txt"
        # Include format chars (Cf), control chars (Cc), private use (Co)
        # Include invisible math operators
        content = "Text with\u2061invisible\u2062operators\u2063here\n"
        content += "Control\x00\x01\x02chars\n"  # Control characters
        content += "Private\ue000use\uf8ffarea\n"  # Private use area
        test_file.write_text(content, encoding="utf-8")

        findings = analyzer.analyze_file(test_file)
        assert len(findings) > 0
        assert any("Invisible character" in f.title for f in findings)
