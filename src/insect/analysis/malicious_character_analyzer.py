"""Analyzer for detecting malicious characters and code obfuscation techniques.

This module provides detection capabilities for:
- Unicode homograph attacks
- Invisible/zero-width characters
- Bidirectional text attacks
- Path traversal sequences
- Command injection patterns
- Malicious filenames
"""

import re
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.finding import Finding, FindingType, Location, Severity


@register_analyzer
class MaliciousCharacterAnalyzer(BaseAnalyzer):
    """Detects malicious character usage and obfuscation techniques."""

    name = "malicious_character"
    description = "Detects malicious Unicode characters and obfuscation techniques"
    supported_extensions = {"*"}  # Analyze all file types

    # Unicode categories for invisible/problematic characters
    INVISIBLE_CATEGORIES = {
        "Cf",  # Format characters
        "Cc",  # Control characters
        "Co",  # Private use
    }

    # Specific invisible/zero-width characters
    INVISIBLE_CHARS = {
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\u2060",  # Word joiner
        "\u2061",  # Function application
        "\u2062",  # Invisible times
        "\u2063",  # Invisible separator
        "\u2064",  # Invisible plus
        "\u00ad",  # Soft hyphen
        "\ufeff",  # Zero-width no-break space
    }

    # Bidirectional control characters
    BIDI_CHARS = {
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }

    # Common homograph mappings (Latin vs Cyrillic/Greek)
    HOMOGRAPH_SETS = [
        {"a", "а", "ɑ", "α"},  # Latin a, Cyrillic а, Latin alpha, Greek alpha
        {"c", "с", "ϲ"},  # Latin c, Cyrillic с, Greek lunate sigma
        {"e", "е", "ε"},  # Latin e, Cyrillic е, Greek epsilon
        {"o", "о", "ο"},  # Latin o, Cyrillic о, Greek omicron
        {"p", "р", "ρ"},  # Latin p, Cyrillic р, Greek rho
        {"x", "х", "χ"},  # Latin x, Cyrillic х, Greek chi
        {"y", "у", "γ"},  # Latin y, Cyrillic у, Greek gamma
        {"B", "В", "Β"},  # Latin B, Cyrillic В, Greek Beta
        {"H", "Н", "Η"},  # Latin H, Cyrillic Н, Greek Eta
        {"M", "М", "Μ"},  # Latin M, Cyrillic М, Greek Mu
        {"T", "Т", "Τ"},  # Latin T, Cyrillic Т, Greek Tau
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.[/\\]",
        r"%2e%2e[/\\]",
        r"%252e%252e[/\\]",
        r"\.\.%2f",
        r"\.\.%5c",
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|]",  # Command separators
        r"`[^`]*`",  # Backticks
        r"\$\([^)]*\)",  # Command substitution
        r"\$\{[^}]*\}",  # Variable expansion
        r"<<\s*['\"]?(\w+)['\"]?",  # Here documents
    ]

    # Dangerous filenames
    DANGEROUS_FILENAMES = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }

    def __init__(self, config: Dict[str, Any]):
        """Initialize the analyzer with configuration.

        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        sensitivity_config = config.get("malicious_character", {})
        self.sensitivity = sensitivity_config.get("sensitivity", "medium")
        self.findings: List[Finding] = []

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for malicious character usage.

        Args:
            file_path: Path to the file

        Returns:
            List of findings
        """
        self.findings = []

        # Analyze filename
        self._analyze_filename(file_path)

        # Read content
        try:
            content = file_path.read_bytes()
        except Exception:
            return self.findings

        # Try to decode as text
        try:
            text_content = content.decode("utf-8", errors="replace")
            self._analyze_unicode(file_path, text_content)
            self._analyze_path_traversal(file_path, text_content)
            self._analyze_command_injection(file_path, text_content)
        except Exception:
            # Unable to decode as text, skip text-based analysis
            return self.findings

        return self.findings

    def _analyze_filename(self, file_path: Path) -> None:
        """Check for malicious filenames."""
        filename = file_path.name

        # Check for Windows reserved names
        base_name = file_path.stem.upper()
        if base_name in self.DANGEROUS_FILENAMES:
            self.findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    analyzer=self.name,
                    type=FindingType.SUSPICIOUS,
                    title=f"Dangerous filename detected: {filename}",
                    description="Windows reserved device name causing system issues",
                    location=Location(path=file_path),
                    severity=Severity.HIGH,
                    confidence=0.9,
                )
            )

        # Check for excessive length
        if len(filename) > 255:
            self.findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    analyzer=self.name,
                    type=FindingType.SUSPICIOUS,
                    title="Excessively long filename",
                    description="Filename exceeds typical filesystem limits",
                    location=Location(path=file_path),
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                )
            )

    def _analyze_unicode(self, file_path: Path, content: str) -> None:
        """Analyze content for Unicode-based attacks."""
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            # Check for invisible characters
            invisible_found = self._check_invisible_chars(line)
            if invisible_found:
                for char, positions in invisible_found.items():
                    char_name = unicodedata.name(char, f"U+{ord(char):04X}")
                    self.findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            analyzer=self.name,
                            type=FindingType.SUSPICIOUS,
                            title=f"Invisible character detected: {char_name}",
                            description=f"Found at positions: {positions}",
                            location=Location(path=file_path, line_start=line_num),
                            severity=(
                                Severity.HIGH
                                if char in self.BIDI_CHARS
                                else Severity.MEDIUM
                            ),
                            confidence=0.9,
                        )
                    )

            # Check for bidirectional text
            bidi_found = self._check_bidi_chars(line)
            if bidi_found:
                for char, positions in bidi_found.items():
                    char_name = unicodedata.name(char, f"U+{ord(char):04X}")
                    self.findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            analyzer=self.name,
                            type=FindingType.SUSPICIOUS,
                            title=f"Bidirectional control character: {char_name}",
                            description="Makes code appear different than it executes",
                            location=Location(
                                path=file_path,
                                line_start=line_num,
                                column_start=positions[0],
                            ),
                            severity=Severity.HIGH,
                            confidence=0.95,
                        )
                    )

            # Check for mixed scripts (homograph attacks)
            if self.sensitivity in ["medium", "high"]:
                mixed_scripts = self._check_mixed_scripts(line)
                if mixed_scripts:
                    self.findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            analyzer=self.name,
                            type=FindingType.SUSPICIOUS,
                            title="Mixed Unicode scripts detected",
                            description=f"Scripts found: {', '.join(mixed_scripts)}",
                            location=Location(path=file_path, line_start=line_num),
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                        )
                    )

    def _check_invisible_chars(self, text: str) -> Dict[str, List[int]]:
        """Check for invisible characters in text."""
        found: Dict[str, List[int]] = {}
        for i, char in enumerate(text):
            if (
                char in self.INVISIBLE_CHARS
                or unicodedata.category(char) in self.INVISIBLE_CATEGORIES
            ):
                if char not in found:
                    found[char] = []
                found[char].append(i)
        return found

    def _check_bidi_chars(self, text: str) -> Dict[str, List[int]]:
        """Check for bidirectional control characters."""
        found: Dict[str, List[int]] = {}
        for i, char in enumerate(text):
            if char in self.BIDI_CHARS:
                if char not in found:
                    found[char] = []
                found[char].append(i)
        return found

    def _check_mixed_scripts(self, text: str) -> Set[str]:
        """Check for mixed Unicode scripts in identifiers."""
        scripts = set()
        for char in text:
            if char.isalpha():
                script = self._get_script(char)
                if script:
                    scripts.add(script)

        # Only flag if we have multiple scripts and one is suspicious
        if len(scripts) > 1 and any(s in ["Cyrillic", "Greek"] for s in scripts):
            return scripts
        return set()

    def _get_script(self, char: str) -> Optional[str]:
        """Get the Unicode script of a character."""
        # Simplified script detection
        code = ord(char)
        if 0x0400 <= code <= 0x04FF:
            return "Cyrillic"
        if 0x0370 <= code <= 0x03FF:
            return "Greek"
        if 0x0041 <= code <= 0x007A:
            return "Latin"
        if 0x0590 <= code <= 0x05FF:
            return "Hebrew"
        if 0x0600 <= code <= 0x06FF:
            return "Arabic"
        return None

    def _analyze_path_traversal(self, file_path: Path, content: str) -> None:
        """Check for path traversal patterns."""
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                for match in matches:
                    line_num = content[: match.start()].count("\n") + 1
                    self.findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            analyzer=self.name,
                            type=FindingType.VULNERABILITY,
                            title="Path traversal pattern detected",
                            description=f"Found: {match.group()}",
                            location=Location(path=file_path, line_start=line_num),
                            severity=Severity.HIGH,
                            confidence=0.9,
                        )
                    )

    def _analyze_command_injection(self, file_path: Path, content: str) -> None:
        """Check for command injection patterns."""
        if self.sensitivity in ["medium", "high"]:
            for pattern in self.COMMAND_INJECTION_PATTERNS:
                matches = list(re.finditer(pattern, content))
                if matches:
                    for match in matches:
                        line_num = content[: match.start()].count("\n") + 1
                        self.findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                analyzer=self.name,
                                type=FindingType.VULNERABILITY,
                                title="Potential command injection pattern",
                                description=f"Pattern: {match.group()}",
                                location=Location(path=file_path, line_start=line_num),
                                severity=Severity.MEDIUM,
                                confidence=0.7,
                            )
                        )
