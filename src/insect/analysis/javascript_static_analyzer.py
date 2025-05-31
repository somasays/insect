"""
Static code analyzer for JavaScript files to detect malicious code.

This module implements a static analyzer for JavaScript code that uses:
1. Semgrep for detecting suspicious code patterns
2. Regular expressions for additional detection
"""

import json
import logging
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.analysis.additional_rules import ADDITIONAL_JAVASCRIPT_RULES
from insect.analysis.static_analyzer_rules import JAVASCRIPT_RULES
from insect.analysis.static_analyzer_utils import check_tool_availability
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)


@register_analyzer
class JavaScriptStaticAnalyzer(BaseAnalyzer):
    """Static analyzer for JavaScript code to detect potentially malicious patterns.

    This analyzer integrates with semgrep for security scanning and uses
    regex-based analysis to detect suspicious or malicious JavaScript patterns.
    """

    name = "javascript_static_analyzer"
    description = "Static analyzer for JavaScript code to detect malicious patterns"
    supported_extensions = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the JavaScript static analyzer."""
        super().__init__(config)
        # Combine built-in rules with additional rules
        self.rules = [
            rule for rule in JAVASCRIPT_RULES if rule.language == "javascript"
        ]
        self.rules.extend(ADDITIONAL_JAVASCRIPT_RULES)  # type: ignore[arg-type]
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)

        # Configure external tool usage (semgrep)
        self.use_semgrep = self.analyzer_config.get("use_semgrep", True)
        # Default Semgrep config for JavaScript/TypeScript
        self.semgrep_args = self.analyzer_config.get(
            "semgrep_args", ["--config=p/javascript", "--json"]
        )

        # Store installation instructions for missing tools
        self.semgrep_install_instructions = None

        # Check tool availability using the dependency manager
        if self.use_semgrep:
            self.use_semgrep, self.semgrep_install_instructions = (
                check_tool_availability("semgrep", self.name, required=False)
            )

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a JavaScript file for security issues and malicious patterns.

        Args:
            file_path: Path to the JavaScript file to analyze

        Returns:
            List of findings detected in the file
        """
        if not self.enabled:
            return []

        if not file_path.exists():
            return []

        findings: List[Finding] = []

        try:
            # First run semgrep if available
            if self.use_semgrep:
                findings.extend(self._run_semgrep(file_path))

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
                    title="Failed to analyze JavaScript file",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error"],
                )
            ]

    def _run_semgrep(self, file_path: Path) -> List[Finding]:
        """Run semgrep on a JavaScript file and convert results to Findings.

        Args:
            file_path: Path to the JavaScript file to analyze

        Returns:
            List of findings detected by semgrep
        """
        findings = []

        # If semgrep is not available, return a finding with installation instructions
        if not self.use_semgrep:
            if self.semgrep_install_instructions:
                findings.append(
                    Finding(
                        id=f"SEMGREP-JS-MISSING-{uuid.uuid4().hex[:8]}",
                        title="Semgrep is not installed",
                        description=(
                            "Semgrep is not installed or not in PATH. Enhanced JavaScript security "
                            "analysis is disabled."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.OTHER,
                        location=Location(path=file_path),
                        analyzer=self.name,
                        confidence=1.0,
                        tags=["semgrep", "dependency", "missing-tool", "javascript"],
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

                    # Categorize finding types based on rule ID and message content
                    if any(
                        kw in rule_id.lower() or kw in message.lower()
                        for kw in [
                            "backdoor",
                            "malicious",
                            "insecure",
                            "suspicious",
                            "eval",
                            "function-constructor",
                            "exec",
                            "command-injection",
                        ]
                    ):
                        finding_type = FindingType.SUSPICIOUS
                    elif any(
                        kw in rule_id.lower() or kw in message.lower()
                        for kw in [
                            "config",
                            "hardening",
                            "secret",
                            "credential",
                            "api-key",
                            "token",
                        ]
                    ):
                        finding_type = FindingType.SECRET
                    elif any(
                        kw in rule_id.lower() or kw in message.lower()
                        for kw in [
                            "xss",
                            "injection",
                            "prototype-pollution",
                            "unsafe-regex",
                            "redos",
                        ]
                    ):
                        finding_type = FindingType.VULNERABILITY

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

                    findings.append(
                        Finding(
                            id=(
                                f"SEMGREP-JS-{rule_id.replace('/', '-')}-"
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
                                "language:javascript",
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
        """Analyze JavaScript code using regular expressions to find malicious patterns.

        Args:
            file_path: Path to the file being analyzed
            content: Content of the file

        Returns:
            List of findings detected through regex analysis
        """
        findings: List[Finding] = []
        lines = content.splitlines()

        # Define JS-specific patterns
        base64_pattern = re.compile(r"[\'\"` ]([A-Za-z0-9+/=]{20,})[\'\"` .,;\)\]\}]")
        hex_pattern = re.compile(r"[\'\"` ]([0-9a-fA-F]{20,})[\'\"` .,;\)\]\}]")
        url_pattern = re.compile(
            r"[\'\"` ](https?://(?:[a-zA-Z0-9\-\._~:/?#[\]@!$&\'\(\)\*\+,;=]|%[0-9a-fA-F]{2})+|https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:[:/]\S*)?)[\'\"` ]",
            re.IGNORECASE,
        )
        eval_pattern = re.compile(
            r"\b(eval|Function|setTimeout|setInterval)\s*\(", re.IGNORECASE
        )
        dom_manipulation_pattern = re.compile(
            r"\.(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*=",
            re.IGNORECASE,
        )
        unsafe_json_pattern = re.compile(r"JSON\.parse\s*\(\s*[^)]*\)", re.IGNORECASE)
        require_import_pattern = re.compile(
            r'(require|import)\s*[\(\{]?\s*[\'"`](child_process|fs|http|https|net|crypto|os|path|process|vm)[\'"`]',
            re.IGNORECASE,
        )
        secrets_pattern = re.compile(
            r'[\"\']?(password|secret|token|key|api_?key|access_?token|auth|credentials?|passw)[_-]?[\"\']?\s*[:=]\s*[\"\']([^\"\']+)[\"\'"]',
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check for base64 payloads
            for match in base64_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS104-{uuid.uuid4().hex[:8]}",
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
                        tags=["encoded-payload", "base64", "obfuscation", "javascript"],
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
                        id=f"JS104-{uuid.uuid4().hex[:8]}",
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
                        tags=["encoded-payload", "hex", "obfuscation", "javascript"],
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
                        id=f"JS-URL-{uuid.uuid4().hex[:8]}",
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
                        tags=["network", "url", "connection", "javascript"],
                        remediation="Verify this network connection is to a legitimate service.",
                        cwe_id="CWE-913",
                        cvss_score=6.5,
                    )
                )

            # Check for eval and Function constructor
            for match in eval_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS101-{uuid.uuid4().hex[:8]}",
                        title="Unsafe code execution",
                        description=(
                            f"The code uses potentially unsafe function '{match.group(1)}' "
                            f"which can execute arbitrary code and may lead to code injection vulnerabilities."
                        ),
                        severity=Severity.HIGH,
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
                        confidence=0.8,
                        references=[
                            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!",
                            "https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval_Injection",
                        ],
                        tags=["code-execution", "eval", "injection", "javascript"],
                        remediation="Avoid using eval() and Function() constructor. Refactor to use safer alternatives.",
                        cwe_id="CWE-95",
                        cvss_score=8.0,
                    )
                )

            # Check for DOM manipulation
            for match in dom_manipulation_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS102-{uuid.uuid4().hex[:8]}",
                        title="Dangerous DOM manipulation",
                        description=(
                            f"The code uses unsafe DOM manipulation method '{match.group(1)}' "
                            f"which can lead to Cross-Site Scripting (XSS) vulnerabilities."
                        ),
                        severity=Severity.HIGH,
                        type=FindingType.VULNERABILITY,
                        location=Location(
                            path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=snippet,
                        ),
                        analyzer=self.name,
                        confidence=0.8,
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        tags=["dom", "xss", "injection", "javascript"],
                        remediation="Use safer alternatives like textContent or DOM manipulation methods (createElement, appendChild). Sanitize user input if dynamic content is required.",
                        cwe_id="CWE-79",
                        cvss_score=7.5,
                    )
                )

            # Check for unsafe JSON parsing (can lead to prototype pollution)
            for match in unsafe_json_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS-JSON-{uuid.uuid4().hex[:8]}",
                        title="Potentially unsafe JSON parsing",
                        description=(
                            "The code parses JSON that might come from an untrusted source, "
                            "which could lead to prototype pollution or injection attacks."
                        ),
                        severity=Severity.MEDIUM,
                        type=FindingType.VULNERABILITY,
                        location=Location(
                            path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            snippet=snippet,
                        ),
                        analyzer=self.name,
                        confidence=0.6,  # Lower confidence as not all JSON.parse is dangerous
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization"
                        ],
                        tags=["json", "deserialization", "javascript"],
                        remediation="Validate JSON data before parsing. Consider using JSON schemas or sanitization libraries.",
                        cwe_id="CWE-502",
                        cvss_score=5.0,
                    )
                )

            # Check for suspicious module imports
            for match in require_import_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS103-{uuid.uuid4().hex[:8]}",
                        title="Suspicious module usage",
                        description=(
                            f"The code imports/requires the '{match.group(2)}' module, commonly used "
                            f"for system interaction or networking, which could be misused."
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
                        references=[f"https://nodejs.org/api/{match.group(2)}.html"],
                        tags=["module", "import", "system-access", "javascript"],
                        remediation="Verify the legitimate need for these modules. Ensure proper sandboxing or input validation if used.",
                        cwe_id="CWE-78",
                        cvss_score=6.0,
                    )
                )

            # Check for hardcoded secrets
            for match in secrets_pattern.finditer(line):
                # Extract snippet with some context
                start_idx = max(0, i - 3)
                end_idx = min(len(lines), i + 4)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"JS105-{uuid.uuid4().hex[:8]}",
                        title="Potential hardcoded secret",
                        description=(
                            f"The code may contain a hardcoded secret ('{match.group(1)}'), "
                            f"which can lead to security vulnerabilities if exposed."
                        ),
                        severity=Severity.HIGH,
                        type=FindingType.SECRET,
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
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                        ],
                        tags=["secret", "hardcoded", "credential", "javascript"],
                        remediation="Remove secrets from source code. Use environment variables, configuration files, or secret management solutions.",
                        cwe_id="CWE-798",
                        cvss_score=7.0,
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
                                    "javascript",
                                ],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

        return findings
