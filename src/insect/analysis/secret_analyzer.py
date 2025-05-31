"""
Enhanced secret detection analyzer with entropy analysis and custom patterns.

This module provides comprehensive secret scanning capabilities including:
- High-entropy string detection using Shannon entropy analysis
- Pattern-based detection for various secret types (API keys, passwords, tokens)
- Context-aware analysis to reduce false positives
- Support for multiple file formats and encodings
- Custom rule support for organization-specific secrets
"""

import base64
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

from ..finding import Finding, FindingType, Location, Severity
from . import BaseAnalyzer, register_analyzer

logger = logging.getLogger(__name__)


@dataclass
class SecretPattern:
    """Definition of a secret detection pattern."""

    name: str
    pattern: Pattern[str]
    description: str
    severity: Severity
    entropy_threshold: Optional[float] = None
    min_length: int = 8
    max_length: int = 200
    context_keywords: Optional[List[str]] = None
    exclude_patterns: Optional[List[Pattern[str]]] = None


class EntropyAnalyzer:
    """Analyzer for calculating entropy of strings to detect secrets."""

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        # Count frequency of each character
        frequency: Dict[str, int] = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1

        # Calculate entropy
        length = len(data)
        entropy = 0.0

        for count in frequency.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def is_high_entropy(
        data: str, threshold: float = 4.5, min_length: int = 20
    ) -> bool:
        """Check if string has high entropy indicating potential secret."""
        if len(data) < min_length:
            return False

        entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        return entropy >= threshold

    @staticmethod
    def is_base64_like(data: str) -> bool:
        """Check if string looks like base64 encoded data."""
        if len(data) < 16:
            return False

        # Check if it's valid base64
        try:
            # Remove padding to check character set
            stripped = data.rstrip("=")
            if not re.match(r"^[A-Za-z0-9+/]*$", stripped):
                return False

            # Try to decode
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False

    @staticmethod
    def is_hex_like(data: str) -> bool:
        """Check if string looks like hexadecimal encoded data."""
        if len(data) < 16 or len(data) % 2 != 0:
            return False

        return bool(re.match(r"^[a-fA-F0-9]+$", data))


@register_analyzer
class SecretAnalyzer(BaseAnalyzer):
    """Enhanced analyzer for detecting secrets with entropy analysis."""

    name = "secrets"
    description = "Enhanced secret detection with entropy analysis and pattern matching"
    supported_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
        ".xml",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".java",
        ".cs",
        ".php",
        ".rb",
        ".go",
        ".rs",
        ".cpp",
        ".c",
        ".h",
        ".sql",
        ".tf",
        ".hcl",
        ".dockerfile",
        ".md",
        ".txt",
        ".log",
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self.entropy_analyzer = EntropyAnalyzer()

        # Configuration
        analyzer_config = config.get(self.name, {})
        self.entropy_threshold = analyzer_config.get("entropy_threshold", 4.5)
        self.min_secret_length = analyzer_config.get("min_secret_length", 16)
        self.max_secret_length = analyzer_config.get("max_secret_length", 200)
        self.enable_entropy_analysis = analyzer_config.get(
            "enable_entropy_analysis", True
        )
        self.enable_pattern_matching = analyzer_config.get(
            "enable_pattern_matching", True
        )

        # Initialize secret patterns
        self.secret_patterns = self._init_secret_patterns()

        # Common false positive patterns
        self.false_positive_patterns = [
            re.compile(r"^[a-zA-Z]+$"),  # Only letters
            re.compile(r"^[0-9]+$"),  # Only numbers
            re.compile(r"^(.)\1+$"),  # Repeated characters
            re.compile(
                r"^(test|sample|example|placeholder|dummy|fake).*?", re.IGNORECASE
            ),
            re.compile(r"^(lorem|ipsum|dolor|sit|amet)", re.IGNORECASE),
            re.compile(r"^[x]{8,}$", re.IGNORECASE),  # xxx...
            re.compile(r"^[a]{8,}$", re.IGNORECASE),  # aaa...
            re.compile(r"^1{8,}$"),  # 111...
            re.compile(r"^0{8,}$"),  # 000...
        ]

        # Common non-secret file extensions and paths
        self.exclude_paths = {
            ".git",
            ".svn",
            ".hg",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            ".tox",
            "venv",
            ".venv",
            "/env/",  # Only exclude if it's a directory path, not .env files
            "dist",
            "build",
            "target",
            "bin",
            "obj",
        }

    def _init_secret_patterns(self) -> List[SecretPattern]:
        """Initialize patterns for detecting various types of secrets."""
        patterns = []

        # AWS secrets
        patterns.extend(
            [
                SecretPattern(
                    name="AWS Access Key ID",
                    pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                    description="AWS Access Key ID detected",
                    severity=Severity.HIGH,
                    min_length=20,
                    max_length=20,
                ),
                SecretPattern(
                    name="AWS Secret Access Key",
                    pattern=re.compile(r"\b([A-Za-z0-9/+=]{40})\b"),
                    description="Potential AWS Secret Access Key detected",
                    severity=Severity.HIGH,
                    entropy_threshold=4.5,
                    min_length=40,
                    max_length=40,
                    context_keywords=["aws", "secret", "access", "key"],
                ),
                SecretPattern(
                    name="AWS Session Token",
                    pattern=re.compile(r"\b(FQoGZXIvYXdzE[A-Za-z0-9/+=]{100,})\b"),
                    description="AWS Session Token detected",
                    severity=Severity.HIGH,
                    min_length=100,
                ),
            ]
        )

        # Google Cloud Platform
        patterns.extend(
            [
                SecretPattern(
                    name="Google API Key",
                    pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
                    description="Google API Key detected",
                    severity=Severity.HIGH,
                    min_length=39,
                    max_length=39,
                ),
                SecretPattern(
                    name="Google OAuth Key",
                    pattern=re.compile(
                        r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"
                    ),
                    description="Google OAuth Key detected",
                    severity=Severity.HIGH,
                ),
            ]
        )

        # GitHub
        patterns.extend(
            [
                SecretPattern(
                    name="GitHub Token",
                    pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
                    description="GitHub Personal Access Token detected",
                    severity=Severity.HIGH,
                    min_length=40,
                ),
                SecretPattern(
                    name="GitHub App Token",
                    pattern=re.compile(r"\b(ghs_[A-Za-z0-9_]{36})\b"),
                    description="GitHub App Installation Access Token detected",
                    severity=Severity.HIGH,
                    min_length=40,
                ),
            ]
        )

        # Azure
        patterns.extend(
            [
                SecretPattern(
                    name="Azure Storage Account Key",
                    pattern=re.compile(r"\b([A-Za-z0-9+/]{88}==)\b"),
                    description="Azure Storage Account Key detected",
                    severity=Severity.HIGH,
                    min_length=88,
                    max_length=88,
                    context_keywords=["azure", "storage", "account"],
                ),
            ]
        )

        # Database connection strings
        patterns.extend(
            [
                SecretPattern(
                    name="Database Connection String",
                    pattern=re.compile(
                        r"((mysql|postgresql|postgres|mongodb|redis|mssql|oracle)://[^\s\"']*?:[^\s\"']*?@[^\s\"']*)",
                        re.IGNORECASE,
                    ),
                    description="Database connection string with embedded credentials detected",
                    severity=Severity.HIGH,
                    min_length=20,
                ),
                SecretPattern(
                    name="Database Password",
                    pattern=re.compile(
                        r'(password|pwd|passwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
                        re.IGNORECASE,
                    ),
                    description="Database password detected",
                    severity=Severity.MEDIUM,
                    entropy_threshold=3.5,
                    min_length=8,
                    context_keywords=[
                        "database",
                        "db",
                        "sql",
                        "mysql",
                        "postgres",
                        "mongodb",
                    ],
                ),
            ]
        )

        # API Keys (generic patterns)
        patterns.extend(
            [
                SecretPattern(
                    name="Generic API Key",
                    pattern=re.compile(
                        r'(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_-]{16,})["\']',
                        re.IGNORECASE,
                    ),
                    description="Generic API key detected",
                    severity=Severity.HIGH,
                    entropy_threshold=4.0,
                    min_length=16,
                ),
                SecretPattern(
                    name="Bearer Token",
                    pattern=re.compile(r"\bBearer\s+([A-Za-z0-9_-]{20,})\b"),
                    description="Bearer token detected",
                    severity=Severity.HIGH,
                    entropy_threshold=4.0,
                    min_length=20,
                ),
            ]
        )

        # JWT Tokens
        patterns.extend(
            [
                SecretPattern(
                    name="JWT Token",
                    pattern=re.compile(
                        r"\bey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"
                    ),
                    description="JSON Web Token (JWT) detected",
                    severity=Severity.MEDIUM,
                    min_length=30,
                ),
            ]
        )

        # Cryptocurrency
        patterns.extend(
            [
                SecretPattern(
                    name="Bitcoin Private Key",
                    pattern=re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
                    description="Bitcoin private key detected",
                    severity=Severity.CRITICAL,
                    min_length=51,
                    max_length=52,
                ),
                SecretPattern(
                    name="Ethereum Private Key",
                    pattern=re.compile(r"\b0x[a-fA-F0-9]{64}\b"),
                    description="Ethereum private key detected",
                    severity=Severity.CRITICAL,
                    min_length=66,
                    max_length=66,
                ),
            ]
        )

        # SSH Keys
        patterns.extend(
            [
                SecretPattern(
                    name="SSH Private Key",
                    pattern=re.compile(
                        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                        re.IGNORECASE,
                    ),
                    description="SSH private key detected",
                    severity=Severity.CRITICAL,
                    min_length=30,
                ),
            ]
        )

        # Generic secrets
        patterns.extend(
            [
                SecretPattern(
                    name="Generic Secret",
                    pattern=re.compile(
                        r'(secret|token|password|passwd|pwd|key|credential)\s*[=:]\s*["\']([A-Za-z0-9_+/=-]{12,})["\']',
                        re.IGNORECASE,
                    ),
                    description="Generic secret pattern detected",
                    severity=Severity.MEDIUM,
                    entropy_threshold=3.5,
                    min_length=12,
                    exclude_patterns=[
                        re.compile(
                            r"^(test|sample|example|placeholder|dummy|fake|your_|my_)",
                            re.IGNORECASE,
                        ),
                        re.compile(r"^[a-zA-Z]+$"),  # Only letters
                    ],
                ),
            ]
        )

        # High-entropy strings
        patterns.extend(
            [
                SecretPattern(
                    name="High Entropy String",
                    pattern=re.compile(r'["\']([A-Za-z0-9+/=_-]{20,})["\']'),
                    description="High-entropy string that may be a secret",
                    severity=Severity.LOW,
                    entropy_threshold=4.8,
                    min_length=20,
                    max_length=100,
                ),
            ]
        )

        return patterns

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for secrets using both pattern matching and entropy analysis."""
        findings: List[Finding] = []

        try:
            # Skip certain paths
            if any(exclude in str(file_path) for exclude in self.exclude_paths):
                return findings

            # Read file content
            content = self._read_file_safely(file_path)
            if not content:
                return findings

            logger.debug(f"Analyzing {file_path} for secrets")

            # Pattern-based detection
            if self.enable_pattern_matching:
                findings.extend(self._detect_secrets_by_patterns(file_path, content))

            # Entropy-based detection
            if self.enable_entropy_analysis:
                findings.extend(self._detect_secrets_by_entropy(file_path, content))

            # Post-process findings to remove duplicates and false positives
            findings = self._filter_findings(findings)

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")

        return findings

    def _read_file_safely(self, file_path: Path) -> Optional[str]:
        """Safely read file content with multiple encoding attempts."""
        encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

        for encoding in encodings:
            try:
                content = file_path.read_text(encoding=encoding, errors="ignore")

                # Skip very large files (> 10MB)
                if len(content) > 10 * 1024 * 1024:
                    logger.debug(f"Skipping large file {file_path}")
                    return None

                return content
            except Exception as e:
                logger.debug(f"Failed to read {file_path} with {encoding}: {e}")
                continue

        return None

    def _detect_secrets_by_patterns(
        self, file_path: Path, content: str
    ) -> List[Finding]:
        """Detect secrets using predefined patterns."""
        findings = []

        for pattern in self.secret_patterns:
            matches = pattern.pattern.finditer(content)

            for match in matches:
                secret_value = match.group(1) if match.groups() else match.group(0)

                # Apply length filters
                if (
                    len(secret_value) < pattern.min_length
                    or len(secret_value) > pattern.max_length
                ):
                    continue

                # Apply exclude patterns
                if pattern.exclude_patterns and any(
                    exclude.search(secret_value) for exclude in pattern.exclude_patterns
                ):
                    continue

                # Check entropy if threshold is specified
                if pattern.entropy_threshold:
                    entropy = self.entropy_analyzer.calculate_shannon_entropy(
                        secret_value
                    )
                    if entropy < pattern.entropy_threshold:
                        continue

                # Check context if keywords are specified
                if pattern.context_keywords and not self._check_context(
                    content, match.start(), pattern.context_keywords
                ):
                    continue

                # Skip false positives
                if self._is_false_positive(secret_value):
                    continue

                # Calculate line number
                line_number = content[: match.start()].count("\n") + 1
                column_number = match.start() - content.rfind("\n", 0, match.start())

                finding = Finding(
                    id=f"SECRET-{pattern.name.upper().replace(' ', '_')}",
                    analyzer=self.name,
                    severity=pattern.severity,
                    title=f"Secret detected: {pattern.name}",
                    description=f"{pattern.description}\n\nDetected value: {secret_value[:20]}{'...' if len(secret_value) > 20 else ''}",
                    location=Location(
                        path=file_path,
                        line_start=line_number,
                        column_start=column_number,
                    ),
                    type=FindingType.SECRET,
                    metadata={
                        "secret_type": pattern.name,
                        "entropy": self.entropy_analyzer.calculate_shannon_entropy(
                            secret_value
                        ),
                        "length": len(secret_value),
                        "pattern_match": True,
                        "is_base64": self.entropy_analyzer.is_base64_like(secret_value),
                        "is_hex": self.entropy_analyzer.is_hex_like(secret_value),
                    },
                )

                findings.append(finding)

        return findings

    def _detect_secrets_by_entropy(
        self, file_path: Path, content: str
    ) -> List[Finding]:
        """Detect secrets using entropy analysis."""
        findings: List[Finding] = []

        # Look for high-entropy strings in common patterns
        entropy_patterns = [
            # Quoted strings
            re.compile(r'["\']([A-Za-z0-9+/=_!@#$%^&*().-]{16,100})["\']'),
            # Assignment values
            re.compile(r"=\s*([A-Za-z0-9+/=_!@#$%^&*().-]{16,100})\s*[;\n]"),
            # JSON values
            re.compile(r':\s*["\']([A-Za-z0-9+/=_!@#$%^&*().-]{16,100})["\']'),
            # YAML values
            re.compile(r":\s*([A-Za-z0-9+/=_!@#$%^&*().-]{16,100})\s*$", re.MULTILINE),
        ]

        for pattern in entropy_patterns:
            matches = pattern.finditer(content)

            for match in matches:
                candidate = match.group(1)

                # Length check
                if (
                    len(candidate) < self.min_secret_length
                    or len(candidate) > self.max_secret_length
                ):
                    continue

                # Entropy check
                if not self.entropy_analyzer.is_high_entropy(
                    candidate, self.entropy_threshold
                ):
                    continue

                # Skip false positives
                if self._is_false_positive(candidate):
                    continue

                # Skip if already detected by pattern matching
                if any(
                    finding.metadata.get("pattern_match")
                    for finding in findings
                    if candidate in finding.description
                ):
                    continue

                # Calculate line number
                line_number = content[: match.start()].count("\n") + 1
                column_number = match.start() - content.rfind("\n", 0, match.start())

                # Determine severity based on entropy and characteristics
                entropy = self.entropy_analyzer.calculate_shannon_entropy(candidate)
                severity = self._calculate_entropy_severity(candidate, entropy)

                finding = Finding(
                    id="SECRET-HIGH_ENTROPY",
                    analyzer=self.name,
                    severity=severity,
                    title="High-entropy string detected",
                    description=f"High-entropy string detected that may be a secret.\n\nEntropy: {entropy:.2f}\nDetected value: {candidate[:20]}{'...' if len(candidate) > 20 else ''}",
                    location=Location(
                        path=file_path,
                        line_start=line_number,
                        column_start=column_number,
                    ),
                    type=FindingType.SECRET,
                    metadata={
                        "secret_type": "High Entropy",
                        "entropy": entropy,
                        "length": len(candidate),
                        "pattern_match": False,
                        "is_base64": self.entropy_analyzer.is_base64_like(candidate),
                        "is_hex": self.entropy_analyzer.is_hex_like(candidate),
                    },
                )

                findings.append(finding)

        return findings

    def _check_context(self, content: str, position: int, keywords: List[str]) -> bool:
        """Check if any context keywords appear near the match position."""
        # Check 100 characters before and after the match
        start = max(0, position - 100)
        end = min(len(content), position + 100)
        context = content[start:end].lower()

        return any(keyword.lower() in context for keyword in keywords)

    def _is_false_positive(self, candidate: str) -> bool:
        """Check if a candidate string is likely a false positive."""
        return any(
            pattern.search(candidate) for pattern in self.false_positive_patterns
        )

    def _calculate_entropy_severity(
        self, candidate: str, entropy: float  # noqa: ARG002
    ) -> Severity:
        """Calculate severity based on entropy and string characteristics."""
        # High entropy thresholds
        if entropy >= 5.5:
            return Severity.HIGH
        if entropy >= 5.0:
            return Severity.MEDIUM
        if entropy >= 4.5:
            return Severity.LOW
        return Severity.LOW  # INFO doesn't exist, use LOW instead

    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings to remove duplicates and improve accuracy."""
        filtered = []
        seen_secrets = set()

        for finding in findings:
            # Extract the actual secret value from the description
            secret_start = finding.description.find("Detected value: ")
            if secret_start >= 0:
                secret_value = (
                    finding.description[secret_start + 16 :].split("...")[0].strip()
                )
            else:
                secret_value = f"{finding.location.path}:{finding.location.line_start}"

            # Skip duplicates
            if secret_value in seen_secrets:
                continue

            seen_secrets.add(secret_value)
            filtered.append(finding)

        return filtered

    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this analyzer can analyze the specified file.

        Override the base method to handle special cases like .env files.
        """
        if not self.enabled:
            return False

        if not self.supported_extensions:
            return False

        # Check normal extension
        if file_path.suffix.lower() in self.supported_extensions:
            return True

        # Handle special filenames like .env
        if file_path.name.lower() in {".env", ".gitignore", ".dockerignore"}:
            return True

        # Check if wildcard is supported
        return "*" in self.supported_extensions

    def generate_secret_report(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate a detailed report of detected secrets."""
        report: Dict[str, Any] = {
            "summary": {
                "total_secrets": len(findings),
                "by_severity": {},
                "by_type": {},
                "files_affected": len({f.location.path for f in findings}),
            },
            "secrets": [],
        }

        # Group by severity
        for severity in Severity:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                report["summary"]["by_severity"][severity.value] = count

        # Group by type
        for finding in findings:
            secret_type = finding.metadata.get("secret_type", "Unknown")
            report["summary"]["by_type"][secret_type] = (
                report["summary"]["by_type"].get(secret_type, 0) + 1
            )

        # Add individual secrets
        for finding in findings:
            report["secrets"].append(
                {
                    "type": finding.metadata.get("secret_type", "Unknown"),
                    "severity": finding.severity.value,
                    "file": finding.location.path,
                    "line": finding.location.line_start,
                    "entropy": finding.metadata.get("entropy", 0),
                    "is_base64": finding.metadata.get("is_base64", False),
                    "is_hex": finding.metadata.get("is_hex", False),
                    "pattern_match": finding.metadata.get("pattern_match", False),
                }
            )

        return report
