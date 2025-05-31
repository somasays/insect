"""
Static code analyzer for Shell scripts to detect malicious code patterns.

This module implements a static analyzer for Shell scripts that uses:
1. Regular expressions to detect suspicious shell commands and patterns
2. ShellCheck integration for additional quality and security checks
"""

import json
import logging
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.analysis.additional_rules import ADDITIONAL_SHELL_PATTERNS
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)


class ShellDetectionRule:
    """Rule definition for shell script static analysis."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        finding_type: FindingType,
        regex_pattern: Pattern,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ):
        """Initialize a shell detection rule.

        Args:
            rule_id: Unique identifier for the rule
            title: Short title describing the rule
            description: Detailed description of what the rule detects
            severity: The severity level of findings from this rule
            finding_type: The type of finding this rule detects
            regex_pattern: Regular expression pattern to match
            remediation: Optional instructions for fixing the issue
            references: Optional list of reference URLs or documents
            cwe_id: Optional Common Weakness Enumeration ID
            cvss_score: Optional CVSS severity score
        """
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.finding_type = finding_type
        self.regex_pattern = regex_pattern
        self.remediation = remediation
        self.references = references or []
        self.cwe_id = cwe_id
        self.cvss_score = cvss_score


# Define detection rules for especially suspicious/malicious shell code
SHELL_RULES = [
    # Reverse shells and backdoors
    ShellDetectionRule(
        rule_id="SH101",
        title="Potential reverse shell or backdoor",
        description=(
            "The script contains patterns indicative of a reverse shell or backdoor functionality."
        ),
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(nc|netcat|ncat)\s+(-[el]|\s+.*?).*?\d+|"
            r"bash\s+(-i|.*?)\s+.*?\/dev\/(tcp|udp)|"
            r"\/dev\/(tcp|udp)\/[\w\.\-]+\/\d+|"
            r"(python|perl|ruby|php)\s+(-e|-c)\s+['\"].*?(socket|Shell|exec|system|popen|dup2).*?['\"]"
        ),
        remediation="Remove potentially malicious code that opens backdoor connections.",
        references=[
            "https://attack.mitre.org/techniques/T1059/004/",
            "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md",
        ],
        cwe_id="CWE-77",
        cvss_score=9.8,
    ),
    # Obfuscated commands (base64, hex, etc)
    ShellDetectionRule(
        rule_id="SH102",
        title="Obfuscated command execution",
        description=(
            "The script contains obfuscated commands that may hide malicious behavior."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(echo|printf)\s+['\"]([A-Za-z0-9\+/=]{20,})['\"](\s*\|\s*base64\s+(-d|--decode))|"
            r"(base64|xxd|hex)\s+(-d|--decode|-p|-r)\s+['\"]([A-Za-z0-9\+/=]{10,})['\"]|"
            r"(eval|exec)\s+\$\((echo|printf)\s+['\"]([A-Za-z0-9\+/=]{10,})['\"](\s*\|\s*(base64|xxd)\s+(-d|--decode|-p|-r))\)|"
            r"\$\(echo\s+['\"][A-Za-z0-9\+/=]{10,}['\"](\s*\|\s*base64\s+(-d|--decode))\)|"
            r"([A-Fa-f0-9]{10,}|\\x[A-Fa-f0-9]{2})"
        ),
        remediation="Investigate and remove obfuscated commands.",
        references=[
            "https://attack.mitre.org/techniques/T1027/",
        ],
        cwe_id="CWE-506",
        cvss_score=8.0,
    ),
    # Dangerous command execution
    ShellDetectionRule(
        rule_id="SH103",
        title="Dangerous command execution",
        description=(
            "The script uses dangerous command execution patterns that could execute "
            "remotely-supplied code."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"eval\s+[\$\(]|"
            r"eval\s+['\"].*?\$\{.*?\}.*?['\"]|"
            r"(\.|source)\s+<\s*\(|"
            r"(curl|wget)\s+(-s|-q|--silent|--quiet)?\s+(https?:\/\/|ftp:\/\/).*?\s*\|\s*(bash|sh)|"
            r"(curl|wget)\s+.*?\s+(-O|-o)\s+\/tmp\/.*?\s*&&\s*(bash|sh)\s+\/tmp\/"
        ),
        remediation="Avoid executing code from untrusted sources or using variables directly in eval statements.",
        references=[
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
        cwe_id="CWE-78",
        cvss_score=8.5,
    ),
    # Suspicious network activity
    ShellDetectionRule(
        rule_id="SH104",
        title="Suspicious network activity",
        description=(
            "The script contains suspicious network activities that could be used "
            "for data exfiltration or command and control."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(wget|curl|fetch|lynx)\s+.*?(https?:\/\/|ftp:\/\/).*?|"
            r"(nc|netcat|ncat)\s+.*?\s+(-z|-w|-v).*?\d+|"
            r"(ping|traceroute|nslookup|dig|whois)\s+.*?([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})|"
            r"\/dev\/(tcp|udp)\/([a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,})\/\d+"
        ),
        remediation="Review network connections for legitimacy.",
        references=[
            "https://attack.mitre.org/techniques/T1571/",
        ],
        cwe_id="CWE-200",
        cvss_score=7.5,
    ),
    # Privilege escalation attempts
    ShellDetectionRule(
        rule_id="SH105",
        title="Potential privilege escalation",
        description=(
            "The script contains patterns that may be attempting privilege escalation."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"chmod\s+(\+s|[0-7]*s[0-7]*|[0-7]*4[0-7]*[0-7]*|[0-7]*2[0-7]*[0-7]*)\s+|"
            r"(sudo|pkexec|doas)\s+(-s|-i)(\s+|\s*$)|"
            r"\/etc\/(passwd|shadow|sudoers)|"
            r"(gpasswd|usermod)\s+.*?\s+(-G\s+sudo|wheel|admin)|"
            r"(setuid|setgid)\s*\(\s*0\s*\)|"
            r"\/etc\/cron\.(d|daily|hourly|monthly|weekly)\/"
        ),
        remediation="Review and remove any unauthorized privilege escalation attempts.",
        references=[
            "https://attack.mitre.org/tactics/TA0004/",
            "https://attack.mitre.org/techniques/T1548/",
        ],
        cwe_id="CWE-250",
        cvss_score=8.0,
    ),
    # Sensitive file operations
    ShellDetectionRule(
        rule_id="SH106",
        title="Sensitive file operations",
        description=(
            "The script performs operations on sensitive system files or directories."
        ),
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(rm|unlink|mv|cp)\s+(-r|-f|-rf|-fr)?\s+\/?etc\/|"
            r">\s*\/?etc\/(passwd|shadow|hosts|resolv\.conf|ssh\/|ssl\/|cron|rc\.d\/)|"
            r"(touch|mkdir)\s+(-p)?\s+\/?etc\/|"
            r"echo\s+.*?\s*>>\s*\/?etc\/"
        ),
        remediation="Ensure all system file operations are authorized and necessary.",
        references=[
            "https://attack.mitre.org/techniques/T1222/",
        ],
        cwe_id="CWE-732",
        cvss_score=6.5,
    ),
    # Data exfiltration
    ShellDetectionRule(
        rule_id="SH107",
        title="Potential data exfiltration",
        description=(
            "The script contains patterns that could be used for data exfiltration."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(tar|gzip|zip|7z|xz)\s+.*?\s+\/home\/|"
            r"(find|grep)\s+.*?\s+-name\s+.*?\.(conf|key|pem|cert|ssh|gpg|pgp)|"
            r"(gpg|openssl)\s+(--encrypt|enc)|"
            r"(dd|hexdump|xxd)\s+.*?\s+\|\s+(nc|curl|wget)\s+"
        ),
        remediation="Review for unauthorized data collection or exfiltration.",
        references=[
            "https://attack.mitre.org/tactics/TA0010/",
        ],
        cwe_id="CWE-200",
        cvss_score=7.0,
    ),
    # Environment variable poisoning
    ShellDetectionRule(
        rule_id="SH108",
        title="Environment variable manipulation",
        description=(
            "The script manipulates environment variables in a way that could lead to "
            "security issues like path traversal or privilege escalation."
        ),
        severity=Severity.MEDIUM,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"export\s+(PATH|LD_PRELOAD|LD_LIBRARY_PATH)\s*=.*?:|"
            r"(PATH|LD_PRELOAD|LD_LIBRARY_PATH)\s*=.*?:|"
            r"export\s+(HOME|USER|SHELL)\s*=|"
            r"unset\s+(IFS|PATH)"
        ),
        remediation="Review environment variable modifications for security implications.",
        references=[
            "https://attack.mitre.org/techniques/T1574/007/",
        ],
        cwe_id="CWE-426",
        cvss_score=6.0,
    ),
    # Cronjob modification
    ShellDetectionRule(
        rule_id="SH109",
        title="Cronjob modification",
        description=(
            "The script modifies cronjobs which could be used for persistence."
        ),
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(crontab)\s+(-e|-l)|"
            r"echo\s+.*?\s*>>\s*\/etc\/cron|"
            r"echo\s+.*?\s*>>\s*\/var\/spool\/cron"
        ),
        remediation="Review cron job modifications for legitimacy.",
        references=[
            "https://attack.mitre.org/techniques/T1053/003/",
        ],
        cwe_id="CWE-264",
        cvss_score=5.5,
    ),
    # Suspicious process manipulation
    ShellDetectionRule(
        rule_id="SH110",
        title="Suspicious process manipulation",
        description=("The script manipulates processes in a suspicious manner."),
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(pkill|killall)\s+(-9)?\s+(ssh|sshd|auth|sudo|su|login|telnet|ftp|apache|nginx|httpd)|"
            r"(ps|top|lsof)\s+.*?\s+\|\s+grep\s+.*?\s+\|\s+(kill|pkill)|"
            r"(ps)\s+.*?\s+--ppid\s+.*?\s+\|\s+(kill|pkill)|"
            r"renice\s+(-n)?\s+(-|\+)?\d{1,2}\s+(-p)?\s+\d+"
        ),
        remediation="Review process manipulation for suspicious activities.",
        references=[
            "https://attack.mitre.org/techniques/T1562/001/",
        ],
        cwe_id="CWE-732",
        cvss_score=5.0,
    ),
    # Add additional shell detection rules from patterns
    *[
        ShellDetectionRule(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            finding_type=finding_type,
            regex_pattern=regex_pattern,
            remediation=remediation,
            references=references,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
        )
        for rule_id, title, description, severity, finding_type, regex_pattern, remediation, references, cwe_id, cvss_score in ADDITIONAL_SHELL_PATTERNS
    ],
]


@register_analyzer
class ShellScriptAnalyzer(BaseAnalyzer):
    """Static analyzer for shell scripts to detect potentially malicious patterns.

    This analyzer integrates with ShellCheck (if available) for additional checks
    and uses regex-based analysis to detect suspicious patterns.
    """

    name = "shell_script_analyzer"
    description = "Static analyzer for shell scripts to detect malicious patterns"
    supported_extensions = {".sh", ".bash", ".ksh", ".zsh", ".bsh"}

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the Shell script static analyzer.

        Args:
            config: Configuration dictionary for the analyzer
        """
        super().__init__(config)
        self.rules = SHELL_RULES
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)

        # Configure ShellCheck usage
        self.use_shellcheck = self.analyzer_config.get("use_shellcheck", True)
        self.shellcheck_severity = self.analyzer_config.get(
            "shellcheck_severity", "style"
        )
        self.shellcheck_install_instructions = None

        # Check if ShellCheck is available using the dependency manager
        if self.use_shellcheck:
            from insect.analysis.static_analyzer_utils import check_tool_availability

            self.use_shellcheck, self.shellcheck_install_instructions = (
                check_tool_availability("shellcheck", self.name, required=False)
            )

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a shell script file for security issues and malicious patterns.

        Args:
            file_path: Path to the shell script file to analyze

        Returns:
            List of findings detected in the file
        """
        if not self.enabled:
            return []

        if not file_path.exists():
            return []

        findings: List[Finding] = []

        try:
            # First run ShellCheck if available
            if self.use_shellcheck:
                findings.extend(self._run_shellcheck(file_path))

            # Then perform our own regex-based analysis
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Run regex-based analysis
            findings.extend(self._analyze_with_regex(file_path, content))

            # Filter findings based on confidence threshold
            findings = [f for f in findings if f.confidence >= self.min_confidence]

            return findings
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze shell script file",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error"],
                )
            ]

    def _run_shellcheck(self, file_path: Path) -> List[Finding]:
        """Run ShellCheck on a shell script file and convert results to Findings.

        Args:
            file_path: Path to the shell script file to analyze

        Returns:
            List of findings detected by ShellCheck
        """
        findings = []

        # If ShellCheck is not available, return a finding with installation instructions
        if not self.use_shellcheck:
            if self.shellcheck_install_instructions:
                findings.append(
                    Finding(
                        id=f"SHELLCHECK-MISSING-{uuid.uuid4().hex[:8]}",
                        title="ShellCheck is not installed",
                        description=(
                            "ShellCheck is not installed or not in PATH. Enhanced shell script "
                            "analysis is disabled."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.OTHER,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=1.0,
                        tags=["shellcheck", "dependency", "missing-tool"],
                        remediation=self.shellcheck_install_instructions,
                        cvss_score=0.0,
                    )
                )
            return findings

        try:
            # Use shutil.which to find full path to ShellCheck for security
            shellcheck_path = shutil.which("shellcheck")
            if not shellcheck_path:
                logger.warning("Cannot find shellcheck executable in PATH")
                return []

            # Use full path to ShellCheck to avoid shell injection
            cmd = [
                shellcheck_path,
                "--format=json",
                f"--severity={self.shellcheck_severity}",
                str(file_path),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # ShellCheck returns 0 if no issues, non-zero if issues found
            if result.returncode not in [0, 1]:
                logger.warning(
                    f"ShellCheck failed with return code {result.returncode}: {result.stderr}"
                )
                return []

            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                for issue in output:
                    # Map ShellCheck severities to our severities
                    severity_mapping = {
                        "error": Severity.HIGH,
                        "warning": Severity.MEDIUM,
                        "info": Severity.LOW,
                        "style": Severity.LOW,
                    }
                    severity = severity_mapping.get(
                        issue.get("level", "").lower(), Severity.LOW
                    )

                    # Determine finding type based on code or message
                    finding_type = FindingType.OTHER
                    message = issue.get("message", "").lower()

                    # Security/suspicious issues
                    if any(
                        kw in message
                        for kw in [
                            "injection",
                            "arbitrary",
                            "suspicious",
                            "security",
                            "backdoor",
                            "insecure",
                            "unsafe",
                            "dangerous",
                            "malicious",
                            "privilege",
                        ]
                    ):
                        finding_type = FindingType.SUSPICIOUS
                        if severity == Severity.LOW:
                            severity = Severity.MEDIUM

                    # Configuration issues
                    elif any(
                        kw in message
                        for kw in [
                            "configuration",
                            "undefined",
                            "not found",
                            "deprecated",
                            "export",
                        ]
                    ):
                        finding_type = FindingType.MISCONFIG

                    # Extract code snippet and location
                    line = issue.get("line", 1)
                    column = issue.get("column", 1)
                    endline = issue.get("endLine", line)
                    endcolumn = issue.get("endColumn", column + 1)

                    # Get the snippet if available
                    snippet = (
                        issue.get("fix", {})
                        .get("replacements", [{}])[0]
                        .get("text", "")
                    )
                    if not snippet:
                        # Use code/message as snippet if replacement text not available
                        snippet = issue.get("code", "") or message

                    # Confidence based on severity
                    confidence_mapping = {
                        "error": 0.9,
                        "warning": 0.7,
                        "info": 0.5,
                        "style": 0.4,
                    }
                    confidence = confidence_mapping.get(
                        issue.get("level", "").lower(), 0.5
                    )

                    # Create finding
                    findings.append(
                        Finding(
                            id=f"SHELLCHECK-SC{issue.get('code', 0)}-{uuid.uuid4().hex[:8]}",
                            title=f"ShellCheck: {message}",
                            description=issue.get(
                                "message", "Unknown ShellCheck issue"
                            ),
                            severity=severity,
                            type=finding_type,
                            location=Location(
                                path=file_path,
                                line_start=line,
                                line_end=endline,
                                column_start=column,
                                column_end=endcolumn,
                                snippet=snippet,
                            ),
                            analyzer="shellcheck",
                            confidence=confidence,
                            references=[
                                f"https://github.com/koalaman/shellcheck/wiki/SC{issue.get('code', 0)}"
                            ],
                            tags=["shellcheck", f"SC{issue.get('code', 0)}"],
                            remediation=f"See https://github.com/koalaman/shellcheck/wiki/SC{issue.get('code', 0)}",
                        )
                    )
            except json.JSONDecodeError:
                logger.warning(
                    f"Failed to parse ShellCheck output as JSON: {result.stdout[:200]}..."
                )
        except Exception as e:
            logger.error(f"Error running ShellCheck: {str(e)}")

        return findings

    def _analyze_with_regex(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze shell script code using regular expressions to find malicious patterns.

        Args:
            file_path: Path to the file being analyzed
            content: Content of the file

        Returns:
            List of findings detected through regex analysis
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        # Pattern for identifying potentially encoded payloads (base64, hex)
        base64_pattern = re.compile(r'["\' ]([A-Za-z0-9+/=]{20,})[\'".,;\)\]\}]')
        hex_pattern = re.compile(r'["\' ]([0-9a-fA-F]{20,})[\'".,;\)\]\}]')
        url_pattern = re.compile(
            r'[\'"`](https?://(?:[a-zA-Z0-9\-._~:/?#[\]@!$&\'\(\)\*\+,;=]|'
            r"%[0-9a-fA-F]{2})+|"
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:[:/]\S*)?)[\'"`]',
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            # Skip comment lines
            if line.strip().startswith("#") or line.strip() == "":
                continue

            line_num = i + 1

            # Check for base64 payloads
            for match in base64_pattern.finditer(line):
                if len(match.group(1)) >= 20:  # Only consider longer base64 strings
                    # Extract snippet with some context
                    start_idx = max(0, i - 2)
                    end_idx = min(len(lines), i + 3)
                    snippet = "\n".join(lines[start_idx:end_idx])

                    findings.append(
                        Finding(
                            id=f"SH102-BASE64-{uuid.uuid4().hex[:8]}",
                            title="Potential encoded payload (Base64)",
                            description=(
                                "The script contains what appears to be a base64-encoded string "
                                "that could hide malicious content."
                            ),
                            severity=Severity.MEDIUM,
                            type=FindingType.SUSPICIOUS,
                            location=Location(
                                path=file_path,
                                line_start=line_num,
                                line_end=line_num,
                                column_start=match.start(),
                                column_end=match.end(),
                                snippet=snippet,
                            ),
                            analyzer=self.name,
                            confidence=0.6,
                            references=["https://attack.mitre.org/techniques/T1027/"],
                            tags=["encoded-payload", "base64", "obfuscation", "shell"],
                            remediation="Decode and inspect this string for malicious content.",
                            cwe_id="CWE-506",
                            cvss_score=5.5,
                        )
                    )

            # Check for hex payloads
            for match in hex_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 2)
                end_idx = min(len(lines), i + 3)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"SH102-HEX-{uuid.uuid4().hex[:8]}",
                        title="Potential encoded payload (Hex)",
                        description=(
                            "The script contains what appears to be a hex-encoded string "
                            "that could hide malicious content."
                        ),
                        severity=Severity.MEDIUM,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=snippet,
                        ),
                        analyzer=self.name,
                        confidence=0.6,
                        references=["https://attack.mitre.org/techniques/T1027/"],
                        tags=["encoded-payload", "hex", "obfuscation", "shell"],
                        remediation="Decode and inspect this string for malicious content.",
                        cwe_id="CWE-506",
                        cvss_score=5.5,
                    )
                )

            # Check for URL patterns
            for match in url_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 2)
                end_idx = min(len(lines), i + 3)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"SH104-URL-{uuid.uuid4().hex[:8]}",
                        title="Suspicious network connection",
                        description=(
                            f"The script contains a URL ({match.group(0)}) that could be "
                            f"used for malicious network connections."
                        ),
                        severity=Severity.MEDIUM,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=snippet,
                        ),
                        analyzer=self.name,
                        confidence=0.7,
                        references=["https://attack.mitre.org/techniques/T1071/"],
                        tags=["network", "url", "connection", "shell"],
                        remediation="Verify this network connection is to a legitimate service.",
                        cwe_id="CWE-913",
                        cvss_score=6.5,
                    )
                )

            # Check rule-based patterns
            for rule in self.rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(line))
                    for match in matches:
                        # Extract snippet with some context (up to 2 lines before and after)
                        start_idx = max(0, i - 2)
                        end_idx = min(len(lines), i + 3)
                        snippet = "\n".join(lines[start_idx:end_idx])

                        findings.append(
                            Finding(
                                id=f"{rule.rule_id}-{uuid.uuid4().hex[:8]}",
                                title=rule.title,
                                description=rule.description,
                                severity=rule.severity,
                                type=rule.finding_type,
                                location=Location(
                                    path=file_path,
                                    line_start=line_num,
                                    line_end=line_num,
                                    column_start=match.start(),
                                    column_end=match.end(),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.7,  # Regex matches are less certain
                                references=rule.references,
                                tags=[
                                    f"rule:{rule.rule_id}",
                                    "regex",
                                    "malicious-pattern",
                                    "shell",
                                ],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

        return findings
