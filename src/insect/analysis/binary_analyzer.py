"""
Static analyzer for binary files to detect malicious or suspicious properties.

This module implements a static analyzer for binary files that uses:
1. File entropy calculation to detect potentially packed or obfuscated binaries
2. YARA rules to detect known malicious patterns
3. Basic header analysis to identify binary types
"""

import logging
import math
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List

import yara

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.analysis.static_analyzer_utils import check_tool_availability
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)

# Typical file extensions for binary files
BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".sys",
    ".o",
    ".a",
    ".lib",
    ".obj",
    ".pyc",
    ".pyd",
    ".cmxs",
    ".ko",
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".elf",
    ".out",
}

# Entropy threshold for detecting potentially packed/obfuscated binaries
# Most normal binaries have entropy below 7.0
HIGH_ENTROPY_THRESHOLD = 7.0


@register_analyzer
class BinaryAnalyzer(BaseAnalyzer):
    """Static analyzer for binary files to detect potentially malicious properties."""

    name = "binary"
    description = "Static analyzer for binary files to detect malicious properties"
    supported_extensions = BINARY_EXTENSIONS

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the Binary analyzer."""
        super().__init__(config)
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)

        # Configure entropy threshold
        self.entropy_threshold = self.analyzer_config.get(
            "entropy_threshold", HIGH_ENTROPY_THRESHOLD
        )

        # Configure external tool usage
        self.use_yara = self.analyzer_config.get("use_yara", True)
        self.use_file_command = self.analyzer_config.get("use_file_command", True)

        # Path to YARA rules
        self.yara_rules_path = self.analyzer_config.get(
            "yara_rules_path", "rules/malware"
        )
        self.compiled_rules = None

        # Check tool availability using the utility function
        if self.use_yara:
            # Check if yara is importable
            try:
                self._load_yara_rules()
            except (ImportError, Exception) as e:
                logger.warning(
                    f"Failed to initialize YARA: {str(e)}. YARA detection disabled."
                )
                self.use_yara = False

        if self.use_file_command:
            self.use_file_command = check_tool_availability(
                "file", self.name, required=False
            )

    def _load_yara_rules(self) -> None:
        """Load YARA rules from the configured path."""
        if not self.use_yara:
            return

        try:
            rules_path = Path(self.yara_rules_path)
            if rules_path.exists():
                if rules_path.is_file():
                    self.compiled_rules = yara.compile(filepath=str(rules_path))
                    logger.debug(f"Loaded YARA rules from {rules_path}")
                elif rules_path.is_dir():
                    # Compile rules from all .yar/.yara files in the directory
                    filepaths = {}
                    for file in rules_path.glob("*.yar*"):
                        filepaths[file.stem] = str(file)

                    if filepaths:
                        self.compiled_rules = yara.compile(filepaths=filepaths)
                        logger.debug(
                            f"Loaded YARA rules from {len(filepaths)} files in {rules_path}"
                        )
                    else:
                        logger.warning(f"No YARA rule files found in {rules_path}")
            else:
                logger.warning(f"YARA rules path does not exist: {rules_path}")

                # Try to load embedded rules as a fallback
                embedded_rules = """
                rule SuspiciousBinary {
                    meta:
                        description = "Simple rule to detect suspicious binary characteristics"
                        severity = "medium"
                    condition:
                        uint16(0) == 0x5A4D or // MZ header (Windows executable)
                        uint32(0) == 0x464c457f or // ELF header (Linux executable)
                        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or
                        uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe
                }
                """
                self.compiled_rules = yara.compile(source=embedded_rules)
                logger.debug("Loaded embedded YARA rules as fallback")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {str(e)}")
            self.use_yara = False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data.

        Higher entropy (closer to 8.0) indicates more randomness,
        which could be a sign of encryption, compression, or obfuscation.

        Args:
            data: Binary data to analyze

        Returns:
            Entropy value between 0.0 and 8.0
        """
        if not data:
            return 0.0

        # Count byte frequency
        byte_count = dict.fromkeys(range(256), 0)
        for byte in data:
            byte_count[byte] += 1

        # Calculate entropy
        entropy = 0.0
        for count in byte_count.values():
            if count == 0:
                continue
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return entropy

    def _get_file_type(self, file_path: Path) -> str:
        """Get the file type using the 'file' command if available.

        Args:
            file_path: Path to the file to analyze

        Returns:
            File type information or empty string if 'file' command is not available
        """
        if not self.use_file_command:
            return ""

        try:
            file_cmd_path = shutil.which("file")
            if not file_cmd_path:
                return ""

            # Use full path to file command to avoid shell injection
            # nosemgrep: subprocess-shell-true  # validated input
            result = subprocess.run(
                [file_cmd_path, "-b", str(file_path)],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.returncode != 0:
                logger.warning(f"File command failed: {result.stderr}")
                return ""

            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Error running file command: {str(e)}")
            return ""

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a binary file for suspicious or malicious properties.

        Args:
            file_path: Path to the binary file to analyze

        Returns:
            List of findings detected in the file
        """
        if not self.enabled:
            return []

        if not file_path.exists():
            return []

        findings: List[Finding] = []

        try:
            # Check if file is executable
            is_executable = os.access(file_path, os.X_OK)
            file_stats = file_path.stat()
            is_executable_perm = bool(file_stats.st_mode & stat.S_IXUSR)

            # Get file type information
            file_type = self._get_file_type(file_path)

            # Read the file in binary mode
            with open(file_path, "rb") as f:
                content = f.read()

            # Skip empty files
            if not content:
                return []

            # Calculate entropy
            entropy = self._calculate_entropy(content)

            # Check for high entropy (potential packing/obfuscation)
            if entropy >= self.entropy_threshold:
                findings.append(
                    Finding(
                        id=f"BIN101-{uuid.uuid4().hex[:8]}",
                        title="High entropy binary file",
                        description=(
                            f"Binary file has entropy level ({entropy:.2f}) above threshold "
                            f"({self.entropy_threshold}), suggesting possible packing, "
                            f"encryption, or obfuscation techniques."
                        ),
                        severity=Severity.MEDIUM,
                        type=FindingType.SUSPICIOUS,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=0.7,
                        references=[
                            "https://attack.mitre.org/techniques/T1027/002/",
                            "https://en.wikipedia.org/wiki/Shannon_entropy",
                        ],
                        tags=["binary", "entropy", "obfuscation", "packing"],
                        metadata={
                            "entropy": entropy,
                            "file_size": len(content),
                            "is_executable": is_executable or is_executable_perm,
                            "file_type": file_type,
                        },
                        remediation=(
                            "Examine this binary file closely before use. Consider using "
                            "specialized tools to check for malicious behavior."
                        ),
                        cwe_id="CWE-506",
                        cvss_score=5.5,
                    )
                )

            # Run YARA rule scan
            if self.use_yara and self.compiled_rules:
                try:
                    matches = self.compiled_rules.match(data=content)
                    for match in matches:
                        # Extract metadata if available
                        meta = getattr(match, "meta", {})
                        severity_str = meta.get("severity", "medium").lower()
                        severity_mapping = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                        }
                        severity = severity_mapping.get(severity_str, Severity.MEDIUM)

                        description = meta.get(
                            "description", f"YARA rule {match.rule} matched"
                        )

                        findings.append(
                            Finding(
                                id=f"YARA-{match.rule}-{uuid.uuid4().hex[:8]}",
                                title=f"YARA rule match: {match.rule}",
                                description=description,
                                severity=severity,
                                type=FindingType.SUSPICIOUS,
                                location=Location(path=file_path),
                                analyzer=self.name,
                                confidence=0.8,
                                references=meta.get("references", []),
                                tags=["yara", "binary", "malware-detection"],
                                metadata={
                                    "yara_rule": match.rule,
                                    "file_type": file_type,
                                    "entropy": entropy,
                                    "is_executable": is_executable
                                    or is_executable_perm,
                                },
                                remediation=(
                                    "Investigate this binary file as it matches known "
                                    "malicious patterns. Consider quarantining it until "
                                    "further analysis can be performed."
                                ),
                                cwe_id=meta.get("cwe_id", "CWE-506"),
                                cvss_score=meta.get("cvss_score", 7.5),
                            )
                        )
                except Exception as e:
                    logger.error(f"YARA scanning error on {file_path}: {str(e)}")

            # Basic check for executables in unexpected locations
            if (is_executable or is_executable_perm) and not any(
                str(file_path).lower().endswith(ext)
                for ext in [".exe", ".out", ".bin", ".sh"]
            ):
                findings.append(
                    Finding(
                        id=f"BIN102-{uuid.uuid4().hex[:8]}",
                        title="Executable file with non-standard extension",
                        description=(
                            "File has executable permissions but does not have a standard "
                            "executable extension. This could be an attempt to hide malicious code."
                        ),
                        severity=Severity.MEDIUM,
                        type=FindingType.SUSPICIOUS,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=0.6,
                        references=["https://attack.mitre.org/techniques/T1036/"],
                        tags=["binary", "executable", "masquerading"],
                        metadata={
                            "file_type": file_type,
                            "entropy": entropy,
                            "permissions": oct(file_stats.st_mode)[-3:],
                        },
                        remediation="Verify that this executable file is legitimate and needed.",
                        cwe_id="CWE-506",
                    )
                )

            # Filter findings based on confidence threshold
            findings = [f for f in findings if f.confidence >= self.min_confidence]

            return findings
        except Exception as e:
            logger.error(f"Error analyzing binary file {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze binary file",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error"],
                )
            ]
