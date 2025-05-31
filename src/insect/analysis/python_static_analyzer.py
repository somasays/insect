"""
Static code analyzer for Python files to detect malicious code.

This module implements a static analyzer for Python code that uses:
1. Bandit for detecting security issues and potentially malicious patterns
2. Semgrep for detecting suspicious code patterns
3. Regular expressions and AST as additional detection methods
"""

import ast
import json
import logging
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.analysis.additional_rules import ADDITIONAL_PYTHON_RULES
from insect.analysis.python_ast_visitor import ASTVisitor
from insect.analysis.static_analyzer_rules import PYTHON_RULES
from insect.analysis.static_analyzer_utils import check_tool_availability
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)


@register_analyzer
class PythonStaticAnalyzer(BaseAnalyzer):
    """Static analyzer for Python code to detect potentially malicious patterns.

    This analyzer integrates with bandit and semgrep for security scanning,
    and adds additional regex and AST-based analysis to detect malicious patterns.
    """

    name = "python_static_analyzer"
    description = "Static analyzer for Python code to detect malicious patterns"
    supported_extensions = {".py"}

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the Python static analyzer."""
        super().__init__(config)
        # Combine built-in rules with additional rules
        self.rules = [rule for rule in PYTHON_RULES if rule.language == "python"]
        self.rules.extend(ADDITIONAL_PYTHON_RULES)  # type: ignore[arg-type]
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)

        # Configure external tool usage
        self.use_bandit = self.analyzer_config.get("use_bandit", True)
        self.use_semgrep = self.analyzer_config.get("use_semgrep", True)
        self.bandit_args = self.analyzer_config.get("bandit_args", ["-f", "json", "-q"])
        # Default Semgrep config for Python
        self.semgrep_args = self.analyzer_config.get(
            "semgrep_args", ["--config=p/python", "--json"]
        )

        # Store installation instructions for missing tools
        self.bandit_install_instructions = None
        self.semgrep_install_instructions = None

        # Check tool availability using the utility function
        if self.use_bandit:
            self.use_bandit, self.bandit_install_instructions = check_tool_availability(
                "bandit", self.name, required=False
            )
        if self.use_semgrep:
            self.use_semgrep, self.semgrep_install_instructions = (
                check_tool_availability("semgrep", self.name, required=False)
            )

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a Python file for security issues and malicious patterns.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            List of findings detected in the file
        """
        if not self.enabled:
            return []

        if not file_path.exists():
            return []

        findings: List[Finding] = []

        try:
            # First run integrated tools if available
            if self.use_bandit:
                findings.extend(self._run_bandit(file_path))

            if self.use_semgrep:
                findings.extend(self._run_semgrep(file_path))

            # Then perform our own analysis
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Run regex-based analysis
            findings.extend(self._analyze_with_regex(file_path, content))

            # Run AST-based analysis
            findings.extend(self._analyze_with_ast(file_path, content))

            # Filter findings based on confidence threshold
            findings = [f for f in findings if f.confidence >= self.min_confidence]

            return findings
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze Python file",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error"],
                )
            ]

    def _run_bandit(self, file_path: Path) -> List[Finding]:
        """Run bandit on a Python file and convert results to Findings.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            List of findings detected by bandit
        """
        findings = []

        # If bandit is not available, return a finding with installation instructions
        if not self.use_bandit:
            if self.bandit_install_instructions:
                findings.append(
                    Finding(
                        id=f"BANDIT-MISSING-{uuid.uuid4().hex[:8]}",
                        title="Bandit is not installed",
                        description=(
                            "Bandit is not installed or not in PATH. Enhanced Python security "
                            "analysis is disabled."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.OTHER,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=1.0,
                        tags=["bandit", "dependency", "missing-tool"],
                        remediation=self.bandit_install_instructions,
                        cvss_score=0.0,
                    )
                )
            return findings

        try:
            # Use shutil.which to find full path to tool for security
            bandit_path = shutil.which("bandit")
            if not bandit_path:
                logger.warning("Cannot find bandit executable in PATH")
                return []

            # Use full path to bandit to avoid shell injection
            cmd = [bandit_path] + self.bandit_args + [str(file_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # Bandit returns 1 when issues are found, which isn't an error for us
            if result.returncode not in [0, 1]:
                logger.warning(
                    f"Bandit failed with return code {result.returncode}: {result.stderr}"
                )
                return []

            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                for result_item in output.get("results", []):
                    severity_str = result_item.get("issue_severity", "").lower()
                    severity_mapping = {
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                    }
                    severity = severity_mapping.get(severity_str, Severity.MEDIUM)

                    confidence_str = result_item.get("issue_confidence", "").lower()
                    confidence_mapping = {
                        "high": 0.9,
                        "medium": 0.7,
                        "low": 0.5,
                    }
                    confidence = confidence_mapping.get(confidence_str, 0.7)

                    finding_type = FindingType.VULNERABILITY
                    issue_text = result_item.get("issue_text", "").lower()
                    if "malicious" in issue_text or "backdoor" in issue_text:
                        finding_type = FindingType.SUSPICIOUS

                    findings.append(
                        Finding(
                            id=f"BANDIT-{result_item.get('test_id', 'UNKNOWN')}-{uuid.uuid4().hex[:8]}",
                            title=result_item.get(
                                "test_name", "Unknown bandit finding"
                            ),
                            description=result_item.get("issue_text", ""),
                            severity=severity,
                            type=finding_type,
                            location=Location(
                                path=file_path,
                                line_start=result_item.get("line_number", 1),
                                line_end=result_item.get("line_number", 1),
                                column_start=result_item.get("col_offset", 0),
                                column_end=result_item.get("col_offset", 0) + 1,
                                snippet=result_item.get("code", ""),
                            ),
                            analyzer="bandit",
                            confidence=confidence,
                            references=[result_item.get("more_info", "")],
                            tags=[
                                "bandit",
                                f"test_id:{result_item.get('test_id', 'unknown')}",
                            ],
                            cwe_id=result_item.get("cwe", None),
                        )
                    )
            except json.JSONDecodeError:
                logger.warning(
                    f"Failed to parse bandit output as JSON: {result.stdout}"
                )
        except Exception as e:
            logger.error(f"Error running bandit: {str(e)}")

        return findings

    def _run_semgrep(self, file_path: Path) -> List[Finding]:
        """Run semgrep on a Python file and convert results to Findings.

        Args:
            file_path: Path to the Python file to analyze

        Returns:
            List of findings detected by semgrep
        """
        findings = []

        # If semgrep is not available, return a finding with installation instructions
        if not self.use_semgrep:
            if self.semgrep_install_instructions:
                findings.append(
                    Finding(
                        id=f"SEMGREP-MISSING-{uuid.uuid4().hex[:8]}",
                        title="Semgrep is not installed",
                        description=(
                            "Semgrep is not installed or not in PATH. Enhanced Python security "
                            "analysis is disabled."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.OTHER,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=1.0,
                        tags=["semgrep", "dependency", "missing-tool"],
                        remediation=self.semgrep_install_instructions,
                        cvss_score=0.0,
                    )
                )
            return findings

        try:
            # Use shutil.which to find full path to tool for security
            semgrep_path = shutil.which("semgrep")
            if not semgrep_path:
                logger.warning("Cannot find semgrep executable in PATH")
                return []

            # Use full path to semgrep to avoid shell injection
            cmd = [semgrep_path] + self.semgrep_args + [str(file_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # Parse JSON output
            try:
                output = json.loads(result.stdout)
                for result_item in output.get("results", []):
                    extra = result_item.get("extra", {})
                    severity_str = extra.get("severity", "INFO").upper()
                    severity_mapping = {
                        "ERROR": Severity.HIGH,
                        "WARNING": Severity.MEDIUM,
                        "INFO": Severity.LOW,
                    }
                    severity = severity_mapping.get(severity_str, Severity.LOW)

                    finding_type = FindingType.VULNERABILITY
                    rule_id = result_item.get("check_id", "unknown-semgrep-rule")
                    message = extra.get("message", "Unknown semgrep finding")

                    if any(
                        kw in rule_id.lower() or kw in message.lower()
                        for kw in [
                            "backdoor",
                            "malicious",
                            "insecure",
                            "suspicious",
                            "eval",
                            "exec",
                            "command injection",
                        ]
                    ):
                        finding_type = FindingType.SUSPICIOUS
                    elif any(
                        kw in rule_id.lower() or kw in message.lower()
                        for kw in ["config", "hardening", "secret", "credential"]
                    ):
                        finding_type = FindingType.MISCONFIG

                    # Extract line numbers
                    line_start = result_item.get("start", {}).get("line", 1)
                    line_end = result_item.get("end", {}).get("line", line_start)
                    col_start = result_item.get("start", {}).get("col", 0)
                    col_end = result_item.get("end", {}).get("col", 0)

                    metadata = extra.get("metadata", {})
                    references = metadata.get("references", [])
                    first_ref = references[0] if references else None
                    cwe_raw = metadata.get("cwe", None)
                    cwe_id = None
                    if isinstance(cwe_raw, list) and cwe_raw:
                        cwe_val = str(cwe_raw[0])
                        cwe_id = (
                            cwe_val
                            if cwe_val.upper().startswith("CWE-")
                            else f"CWE-{cwe_val}"
                        )
                    elif isinstance(cwe_raw, (str, int)):
                        cwe_val = str(cwe_raw)
                        cwe_id = (
                            cwe_val
                            if cwe_val.upper().startswith("CWE-")
                            else f"CWE-{cwe_val}"
                        )

                    snippet = extra.get("lines", "")
                    # if not snippet.strip():
                    #      try:
                    #          with open(file_path, 'r', encoding='utf-8', errors='ignore') as f_lines:
                    #               lines = f_lines.readlines()
                    #          _, _, snippet = self._get_snippet_context(lines, line_start - 1)
                    #      except Exception:
                    #           snippet = "[Snippet unavailable]"

                    findings.append(
                        Finding(
                            id=(
                                f"SEMGREP-{rule_id.replace('/', '-')}-"
                                f"{uuid.uuid4().hex[:8]}"
                            ),
                            title=message,
                            description=metadata.get("description", "") or message,
                            severity=severity,
                            type=finding_type,
                            location=Location(
                                path=file_path,
                                line_start=line_start,
                                line_end=line_end,
                                column_start=col_start,
                                column_end=col_end,
                                snippet=snippet,
                            ),
                            analyzer="semgrep",
                            confidence=metadata.get("confidence_level", 0.8),
                            references=(
                                [ref for ref in [first_ref] if ref] if first_ref else []
                            ),
                            tags=[
                                "semgrep",
                                f"semgrep_rule:{rule_id}",
                                "language:python",
                            ],
                            cwe_id=cwe_id,
                            remediation=metadata.get("fix", None)
                            or extra.get("fix", None),
                        )
                    )
            except json.JSONDecodeError:
                log_output = result.stdout[:500] + (
                    "..." if len(result.stdout) > 500 else ""
                )
                logger.warning(
                    f"Failed to parse semgrep output as JSON for {file_path}: {log_output}"
                )
        except Exception as e:
            logger.error(f"Error running semgrep: {str(e)}")

        return findings

    def _analyze_with_regex(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Python code using regular expressions to find malicious patterns.

        Args:
            file_path: Path to the file being analyzed
            content: Content of the file

        Returns:
            List of findings detected through regex analysis
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        # Add special case for base64 encoded payloads
        base64_pattern = re.compile(r"[\"\'` ]([A-Za-z0-9+/=]{16,})[\"\'` .,;\)\]\}]")
        hex_pattern = re.compile(r"[\"\'` ]([0-9a-fA-F]{20,})[\"\'` .,;\)\]\}]")
        url_pattern = re.compile(
            r"[\'\"` ](https?://(?:[a-zA-Z0-9\-\._~:/?#[\]@!$&\'\(\)\*\+,;=]|%[0-9a-fA-F]{2})+|https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:[:/]\S*)?)[\'\"` ]",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check for base64 payloads
            for match in base64_pattern.finditer(line):
                if len(match.group(1)) >= 16:  # Only consider longer base64 strings
                    # Extract snippet with some context
                    start_idx = max(0, i - 3)
                    end_idx = min(len(lines), i + 4)
                    snippet = "\n".join(lines[start_idx:end_idx])

                    findings.append(
                        Finding(
                            id=f"PY103-{uuid.uuid4().hex[:8]}",
                            title="Potential encoded payload",
                            description=(
                                "The code contains what appears to be a base64-encoded string "
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
                            tags=["encoded-payload", "base64", "obfuscation"],
                            remediation="Decode and inspect this string for malicious content.",
                            cwe_id="CWE-506",
                            cvss_score=5.5,
                        )
                    )

            # Check for hex payloads
            for match in hex_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"PY103-{uuid.uuid4().hex[:8]}",
                        title="Potential encoded payload",
                        description=(
                            "The code contains what appears to be a hex-encoded string "
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
                        tags=["encoded-payload", "hex", "obfuscation"],
                        remediation="Decode and inspect this string for malicious content.",
                        cwe_id="CWE-506",
                        cvss_score=5.5,
                    )
                )

            # Check for URL patterns
            for match in url_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"PY104-{uuid.uuid4().hex[:8]}",
                        title="Suspicious network connection",
                        description=(
                            f"The code contains a URL ({match.group(0)}) that could be "
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
                        tags=["network", "url", "connection"],
                        remediation="Verify this network connection is to a legitimate service.",
                        cwe_id="CWE-913",
                        cvss_score=6.5,
                    )
                )

            # Standard rule-based checks
            for rule in self.rules:
                if rule.regex_pattern:
                    matches = rule.regex_pattern.finditer(line)
                    for match in matches:
                        # Extract snippet with some context (up to 3 lines before and after)
                        start_idx = max(0, i - 3)
                        end_idx = min(len(lines), i + 4)
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
                                ],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

        return findings

    def _analyze_with_ast(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze Python code using AST parsing to find malicious patterns.

        Args:
            file_path: Path to the file being analyzed
            content: Content of the file

        Returns:
            List of findings detected through AST analysis
        """
        try:
            tree = ast.parse(content)
            visitor = ASTVisitor(file_path)
            visitor.load_source(content)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            # Return a finding about the syntax error
            return [
                Finding(
                    id=f"PY-SYNTAX-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Python syntax error",
                    description="The file contains syntax errors and could not be parsed.",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["syntax-error", "python"],
                )
            ]
        except Exception as e:
            # Return a finding about the failure to analyze the file
            return [
                Finding(
                    id=f"AST-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze Python file with AST",
                    description=f"The AST analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "ast"],
                )
            ]
