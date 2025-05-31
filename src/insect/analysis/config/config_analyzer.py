"""
Configuration file analyzer for detecting security issues in various config file formats.

This module implements analyzers for common configuration files:
1. Dockerfile - Analyzes Docker configurations for security issues
2. package.json - Checks for vulnerable dependencies
3. requirements.txt - Examines Python dependencies for security concerns
4. YAML configs - Kubernetes, GitHub Actions, etc.
5. TOML configs - pyproject.toml, etc.
"""

import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

import toml
import yaml  # type: ignore[import-untyped]

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)


@dataclass
class ConfigDetectionRule:
    """Rule definition for configuration file analysis."""

    rule_id: str
    config_type: str  # dockerfile, package_json, requirements_txt, yaml, toml
    title: str
    description: str
    severity: Severity
    finding_type: FindingType
    regex_pattern: Optional[Pattern] = None
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


# ========================================================================
# Dockerfile Detection Rules
# ========================================================================

DOCKERFILE_RULES: List[ConfigDetectionRule] = [
    # Using latest tag
    ConfigDetectionRule(
        rule_id="DOCKER001",
        config_type="dockerfile",
        title="Use of 'latest' tag",
        description="Using the 'latest' tag can lead to unexpected changes and inconsistent builds.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(r"^FROM\s+([^: ]+)(:latest)?($|\s)", re.MULTILINE),
        remediation="Specify a fixed version tag for the base image.",
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
        ],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=5.0,
    ),
    # Running as root
    ConfigDetectionRule(
        rule_id="DOCKER002",
        config_type="dockerfile",
        title="Container running as root",
        description="Container is running as root, which can lead to privilege escalation if compromised.",
        severity=Severity.HIGH,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(r"^USER\s+root($|\s)", re.MULTILINE),
        remediation="Create and use a non-root user with least privileges needed.",
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
        ],
        cwe_id="CWE-250",  # Execution with Unnecessary Privileges
        cvss_score=7.5,
    ),
    # Missing USER instruction (implicitly running as root)
    ConfigDetectionRule(
        rule_id="DOCKER003",
        config_type="dockerfile",
        title="No USER instruction (running as root)",
        description="No USER instruction found, container will run as root by default.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        # This is a special case - checked in code not via regex
        remediation="Add a USER instruction to run as a non-privileged user.",
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
        ],
        cwe_id="CWE-250",  # Execution with Unnecessary Privileges
        cvss_score=6.0,
    ),
    # Exposed sensitive ports
    ConfigDetectionRule(
        rule_id="DOCKER004",
        config_type="dockerfile",
        title="Exposed sensitive port",
        description="Dockerfile exposes a sensitive port that should typically not be publicly accessible.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"^EXPOSE\s+(?:22|23|3389|5432|3306|27017|1433|6379|9200|8080|8443|9090|8888)\b",
            re.MULTILINE,
        ),
        remediation="Only expose ports that need to be publicly accessible and ensure they're secured.",
        references=["https://docs.docker.com/engine/reference/builder/#expose"],
        cwe_id="CWE-668",  # Exposure of Resource to Wrong Sphere
        cvss_score=5.5,
    ),
    # Curl pipe to shell pattern (curl | sh)
    ConfigDetectionRule(
        rule_id="DOCKER005",
        config_type="dockerfile",
        title="Curl piped to shell",
        description="Using curl piped directly to a shell is a security risk as it executes untrusted content.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"RUN\s+.*(?:curl|wget).*\s+\|\s+(?:bash|sh|ash|dash|zsh|csh|ksh)",
            re.IGNORECASE,
        ),
        remediation="Download the script first, verify its contents, then execute it.",
        references=[
            "https://blog.container-solutions.com/security-implications-of-curl-pipe-bash"
        ],
        cwe_id="CWE-494",  # Download of Code Without Integrity Check
        cvss_score=8.0,
    ),
    # Hard-coded credentials
    ConfigDetectionRule(
        rule_id="DOCKER006",
        config_type="dockerfile",
        title="Hard-coded credential in Dockerfile",
        description="Potential hard-coded credential or secret found in Dockerfile.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SECRET,
        regex_pattern=re.compile(
            r"(?:ENV|ARG)\s+(?:.*PASSWORD|.*SECRET|.*KEY|.*TOKEN|.*CREDENTIAL).*=\s*['\"][^'\"]+['\"]",
            re.IGNORECASE,
        ),
        remediation="Use build arguments or environment variables during deployment instead of hardcoding.",
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#env"
        ],
        cwe_id="CWE-798",  # Use of Hard-coded Credentials
        cvss_score=9.0,
    ),
    # Suspicious software installation
    ConfigDetectionRule(
        rule_id="DOCKER007",
        config_type="dockerfile",
        title="Suspicious software installation",
        description="Installation of software that could be used maliciously (e.g., network scanning tools).",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"RUN\s+.*(?:apt-get|apt|apk|yum|dnf)\s+(?:install|add).*(?:nmap|netcat|nc|telnet|sshpass|hydra)",
            re.IGNORECASE,
        ),
        remediation="Only install software necessary for the container's purpose.",
        references=[
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
        ],
        cwe_id="CWE-1327",  # Binding to an Unrestricted IP Address
        cvss_score=6.0,
    ),
]

# ========================================================================
# Package.json Detection Rules
# ========================================================================

PACKAGE_JSON_RULES: List[ConfigDetectionRule] = [
    # Use of vulnerable dependencies (checked via code, not regex)
    ConfigDetectionRule(
        rule_id="NPM001",
        config_type="package_json",
        title="Use of potentially vulnerable dependency",
        description="Package may contain known security vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        # This is a special case - checked in code not via regex
        remediation="Update to a newer, non-vulnerable version of the package.",
        references=[
            "https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities"
        ],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=7.5,
    ),
    # Unscoped dependencies (using * or latest)
    ConfigDetectionRule(
        rule_id="NPM002",
        config_type="package_json",
        title="Unscoped dependency version",
        description="Using '*', 'latest', or '^' can lead to unexpected breaking changes.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r'"(?:dependencies|devDependencies|peerDependencies)":\s*\{[^}]*"[^"]+"\s*:\s*"(?:\*|latest|\^[0-9]+)"',
            re.DOTALL,
        ),
        remediation="Pin dependencies to specific versions.",
        references=[
            "https://docs.npmjs.com/cli/v9/configuring-npm/package-json#dependencies"
        ],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=5.0,
    ),
    # Scripts with suspicious commands
    ConfigDetectionRule(
        rule_id="NPM003",
        config_type="package_json",
        title="Suspicious script command",
        description="Package script contains potentially malicious commands.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r'"scripts":\s*\{[^}]*"[^"]+"\s*:\s*".*(?:curl|wget|nc|netcat|eval|base64).*"',
            re.DOTALL | re.IGNORECASE,
        ),
        remediation="Review script content for malicious behavior.",
        references=[
            "https://docs.npmjs.com/cli/v9/configuring-npm/package-json#scripts"
        ],
        cwe_id="CWE-78",  # OS Command Injection
        cvss_score=8.0,
    ),
    # Potentially malicious dependencies
    ConfigDetectionRule(
        rule_id="NPM004",
        config_type="package_json",
        title="Potentially malicious dependency",
        description="Package depends on a potentially malicious or typosquatting package.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r'"(?:dependencies|devDependencies)":\s*\{[^}]*"(?:coa|ua-parser-js|event-stream|crossenv|cross-env\.js|http-proxy-agent\.js)"',
            re.DOTALL,
        ),
        remediation="Remove suspicious dependencies and review for alternative trusted packages.",
        references=[
            "https://github.com/lirantal/awesome-nodejs-security#supply-chain-security"
        ],
        cwe_id="CWE-506",  # Embedded Malicious Code
        cvss_score=8.5,
    ),
    # Hard-coded sensitive information
    ConfigDetectionRule(
        rule_id="NPM005",
        config_type="package_json",
        title="Hard-coded sensitive information",
        description="Package.json contains what appears to be hard-coded credentials or sensitive information.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SECRET,
        regex_pattern=re.compile(
            r'"(?:(?:api|app|auth)_?(?:token|key|secret|password)|password|secret|credential)"\s*:\s*"[^"]+"',
            re.IGNORECASE,
        ),
        remediation="Remove sensitive data from package.json and use environment variables instead.",
        references=["https://docs.npmjs.com/cli/v9/configuring-npm/package-json"],
        cwe_id="CWE-798",  # Use of Hard-coded Credentials
        cvss_score=9.0,
    ),
]

# ========================================================================
# Requirements.txt Detection Rules
# ========================================================================

REQUIREMENTS_TXT_RULES: List[ConfigDetectionRule] = [
    # Unscoped dependencies (using * or latest)
    ConfigDetectionRule(
        rule_id="PIP001",
        config_type="requirements_txt",
        title="Unscoped dependency version",
        description="Using '>=', '<=', or '*' can lead to unexpected breaking changes.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"^(?!#)(\w[\w\-_.]+)(?:\s*[><=]=[^,\s]+|\s*\*)", re.MULTILINE
        ),
        remediation="Pin dependencies to specific versions: package==1.2.3",
        references=[
            "https://pip.pypa.io/en/stable/reference/requirements-file-format/"
        ],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=5.0,
    ),
    # Known vulnerable packages (checked in code, not by regex)
    ConfigDetectionRule(
        rule_id="PIP002",
        config_type="requirements_txt",
        title="Known vulnerable package",
        description="Package version with known security vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        # This is a special case - checked in code not via regex
        remediation="Update to a non-vulnerable version of the package.",
        references=["https://pyup.io/safety/"],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=7.5,
    ),
    # Potentially dangerous packages
    ConfigDetectionRule(
        rule_id="PIP003",
        config_type="requirements_txt",
        title="Potentially dangerous package",
        description="Package with potentially dangerous capabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"^(?!#)(cryptography|pycrypto|paramiko|fabric|ansible|subprocess32|os-sys|sh|fabric|invoke)",
            re.MULTILINE,
        ),
        remediation="Review if these packages are necessary and ensure they're used securely.",
        references=[
            "https://pip.pypa.io/en/stable/reference/requirements-file-format/"
        ],
        cwe_id="CWE-676",  # Use of Potentially Dangerous Function
        cvss_score=6.5,
    ),
    # Direct URLs or git repositories
    ConfigDetectionRule(
        rule_id="PIP004",
        config_type="requirements_txt",
        title="Direct URL or git installation",
        description="Installing from direct URLs or git repositories bypasses package verification.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"^(?!#).*(?:git\+|https?://|git://|svn\+|hg\+)", re.MULTILINE
        ),
        remediation="Prefer installing packages from PyPI with a pinned version.",
        references=["https://pip.pypa.io/en/stable/topics/secure-installs/"],
        cwe_id="CWE-494",  # Download of Code Without Integrity Check
        cvss_score=6.0,
    ),
]

# ========================================================================
# YAML Configuration Detection Rules
# ========================================================================

YAML_RULES: List[ConfigDetectionRule] = [
    # Kubernetes - Running as root
    ConfigDetectionRule(
        rule_id="YAML001",
        config_type="yaml",
        title="Kubernetes pod running as root",
        description="Container/pod is set to run as root, which can lead to privilege escalation if compromised.",
        severity=Severity.HIGH,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"securityContext:\s+(?:runAsNonRoot:\s+false|runAsUser:\s+0)", re.MULTILINE
        ),
        remediation="Set runAsNonRoot: true and use an appropriate non-root user ID.",
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
        ],
        cwe_id="CWE-250",  # Execution with Unnecessary Privileges
        cvss_score=7.5,
    ),
    # Kubernetes - Privileged containers
    ConfigDetectionRule(
        rule_id="YAML002",
        config_type="yaml",
        title="Privileged container",
        description="Container is running in privileged mode, giving it full access to the host.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"securityContext:\s+(?:.*\n)*?\s*privileged:\s+true", re.MULTILINE
        ),
        remediation="Avoid using privileged containers. Use specific capabilities instead if needed.",
        references=[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
        ],
        cwe_id="CWE-250",  # Execution with Unnecessary Privileges
        cvss_score=9.0,
    ),
    # Kubernetes - Exposed secrets
    ConfigDetectionRule(
        rule_id="YAML003",
        config_type="yaml",
        title="Exposed secrets in YAML",
        description="Secrets or credentials directly embedded in YAML configuration.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SECRET,
        regex_pattern=re.compile(
            r"(?:password|secret|token|key|credential):\s+['\"]?[A-Za-z0-9+/=]{8,}['\"]?",
            re.IGNORECASE | re.MULTILINE,
        ),
        remediation="Use Kubernetes Secrets or external secret management solutions.",
        references=["https://kubernetes.io/docs/concepts/configuration/secret/"],
        cwe_id="CWE-798",  # Use of Hard-coded Credentials
        cvss_score=9.0,
    ),
    # GitHub Actions - Insecure workflow permissions
    ConfigDetectionRule(
        rule_id="YAML004",
        config_type="yaml",
        title="GitHub Actions insecure permissions",
        description="GitHub Actions workflow with potentially insecure permissions.",
        severity=Severity.HIGH,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"permissions:\s+(?:(?:.*\n)*?\s*contents:\s+write|(?:.*\n)*?\s*packages:\s+write|(?:.*\n)*?\s*id-token:\s+write)",
            re.MULTILINE,
        ),
        remediation="Follow principle of least privilege. Only grant necessary permissions.",
        references=[
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
        ],
        cwe_id="CWE-250",  # Execution with Unnecessary Privileges
        cvss_score=7.0,
    ),
    # GitHub Actions - Potential dependency confusion
    ConfigDetectionRule(
        rule_id="YAML005",
        config_type="yaml",
        title="GitHub Actions dependency confusion risk",
        description="Using third-party actions without pinning to a full length commit SHA.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r"uses:\s+[^@]+@(?:master|main|v\d+|latest)", re.MULTILINE
        ),
        remediation="Pin actions to a full length commit SHA instead of a branch or version tag.",
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
        ],
        cwe_id="CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
        cvss_score=5.5,
    ),
]

# ========================================================================
# TOML Configuration Detection Rules
# ========================================================================

TOML_RULES: List[ConfigDetectionRule] = [
    # Pyproject.toml - Insecure dependencies
    ConfigDetectionRule(
        rule_id="TOML001",
        config_type="toml",
        title="Insecure dependency version constraints",
        description="Using '*', '>=', or '^' can lead to automatic updates to vulnerable versions.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.MISCONFIG,
        regex_pattern=re.compile(
            r'(?:dependencies|optional-dependencies|dev-dependencies|build-requires)\s*=\s*\[[^\]]*"[^"]+\s*(?:>=|<=|\^|\*)(?:[^"]|$)',
            re.DOTALL,
        ),
        remediation="Pin dependencies to specific versions.",
        references=["https://python-poetry.org/docs/dependency-specification/"],
        cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
        cvss_score=5.0,
    ),
    # Cargo.toml - Potentially dangerous crates
    ConfigDetectionRule(
        rule_id="TOML002",
        config_type="toml",
        title="Potentially dangerous Rust crates",
        description="Using crates with potentially dangerous capabilities.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r'(?:dependencies|dev-dependencies)\s*=\s*\[[^\]]*"(?:reqwest|tokio-process|nix|libc|openssl|ssh2)"',
            re.DOTALL,
        ),
        remediation="Review if these crates are necessary and ensure they're used securely.",
        references=["https://rustsec.org/"],
        cwe_id="CWE-676",  # Use of Potentially Dangerous Function
        cvss_score=5.0,
    ),
    # Hard-coded credentials in TOML
    ConfigDetectionRule(
        rule_id="TOML003",
        config_type="toml",
        title="Hard-coded credentials in TOML",
        description="Configuration contains what appears to be hard-coded credentials.",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET,
        regex_pattern=re.compile(
            r'(?:password|token|secret|key|credential)\s*=\s*"[^"]+"', re.IGNORECASE
        ),
        remediation="Move sensitive data to environment variables or a secrets manager.",
        references=["https://12factor.net/config"],
        cwe_id="CWE-798",  # Use of Hard-coded Credentials
        cvss_score=8.0,
    ),
]


# Common lists for NPM packages and Python packages with known vulnerabilities
# This is a minimal list for demonstration - in production this would be much more comprehensive
KNOWN_VULNERABLE_NPM_PACKAGES = {
    "lodash": ["<4.17.21"],
    "elliptic": ["<6.5.4"],
    "y18n": ["<4.0.1", "<5.0.8"],
    "minimist": ["<1.2.6"],
    "node-fetch": ["<2.6.7", "<3.2.10"],
    "tar": ["<6.1.9"],
    "moment": ["<2.29.2"],
}

KNOWN_VULNERABLE_PYTHON_PACKAGES = {
    "django": ["<3.2.14", "<4.0.6"],
    "flask": ["<2.0.3", "<2.1.0"],
    "werkzeug": ["<2.0.3"],
    "requests": ["<2.26.0"],
    "pyyaml": ["<5.4"],
    "pillow": ["<9.0.1"],
    "cryptography": ["<3.3.2", "<36.0.2"],
}


@register_analyzer
class ConfigAnalyzer(BaseAnalyzer):
    """Analyzer for various configuration files to detect security issues."""

    name = "config"
    description = "Analyzer for configuration files to detect security misconfigurations and issues"
    supported_extensions = {
        ".dockerfile",
        ".Dockerfile",
        "Dockerfile",
        ".json",
        ".txt",  # For requirements.txt
        ".yml",
        ".yaml",
        ".toml",
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the config analyzer."""
        super().__init__(config)
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)
        self.docker_rules = DOCKERFILE_RULES
        self.npm_rules = PACKAGE_JSON_RULES
        self.pip_rules = REQUIREMENTS_TXT_RULES
        self.yaml_rules = YAML_RULES
        self.toml_rules = TOML_RULES

        # Configure external tool usage (optional)
        self.use_npm_audit = self.analyzer_config.get("use_npm_audit", True)
        self.use_safety = self.analyzer_config.get("use_safety", True)

        # Check for tool availability
        if self.use_npm_audit:
            self.use_npm_audit = self._check_tool_availability("npm")
        if self.use_safety:
            self.use_safety = self._check_tool_availability("safety")

    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a required external tool is available in the PATH."""
        try:
            subprocess.run(
                ["which", tool_name],
                check=False,
                capture_output=True,
            )
            return True
        except Exception:
            logger.warning(
                f"{tool_name} is not installed or not in PATH. "
                f"Disabling {tool_name} integration for {self.name}."
            )
            return False

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a configuration file for security issues.

        Args:
            file_path: Path to the configuration file to analyze

        Returns:
            List of findings detected in the file
        """
        if not self.enabled:
            return []

        if not file_path.exists():
            return []

        findings: List[Finding] = []

        try:
            # Determine file type and run appropriate analysis
            file_name = file_path.name.lower()
            file_suffix = file_path.suffix.lower()

            # Analyze Dockerfiles
            if self._is_dockerfile(file_name, file_suffix):
                findings.extend(self._analyze_dockerfile(file_path))

            # Analyze package.json
            elif file_name == "package.json":
                findings.extend(self._analyze_package_json(file_path))

            # Analyze requirements.txt
            elif file_name == "requirements.txt":
                findings.extend(self._analyze_requirements_txt(file_path))

            # Analyze YAML config files
            elif file_suffix in [".yml", ".yaml"]:
                findings.extend(self._analyze_yaml_config(file_path))

            # Analyze TOML config files
            elif file_suffix == ".toml":
                findings.extend(self._analyze_toml_config(file_path))

            # Filter findings based on confidence threshold
            findings = [f for f in findings if f.confidence >= self.min_confidence]

            return findings
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"CONFIG-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze configuration file",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error"],
                )
            ]

    def _is_dockerfile(self, file_name: str, file_suffix: str) -> bool:
        """Check if the file is a Dockerfile."""
        return (
            file_name == "dockerfile"
            or file_suffix == ".dockerfile"
            or file_name.endswith(".dockerfile")
            or file_name == "dockerfile.dev"
            or file_name == "dockerfile.prod"
            or "dockerfile" in file_name
        )

    def _analyze_dockerfile(self, file_path: Path) -> List[Finding]:
        """Analyze a Dockerfile for security issues.

        Args:
            file_path: Path to the Dockerfile to analyze

        Returns:
            List of findings detected in the Dockerfile
        """
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            lines = content.splitlines()

            # Track if USER directive exists
            has_user_directive = False

            # Analyze line by line with regex patterns
            for rule in self.docker_rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(content))

                    for match in matches:
                        # Track USER directive if found
                        if (
                            match.group(0).startswith("USER")
                            and rule.rule_id != "DOCKER002"
                        ):
                            has_user_directive = True
                            continue

                        # For FROM instruction, only flag if it's using "latest" implicitly or explicitly
                        if rule.rule_id == "DOCKER001":
                            image_name = match.group(1)
                            tag = match.group(2)
                            # If a specific tag is provided and it's not "latest", don't flag it
                            if ":" in image_name or (tag and tag != ":latest"):
                                continue

                        # Get line number and context
                        line_number = content[: match.start()].count("\n") + 1
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
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
                                    line_start=line_number,
                                    line_end=line_number,
                                    column_start=0,
                                    column_end=(
                                        len(lines[line_number - 1])
                                        if line_number <= len(lines)
                                        else 0
                                    ),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.8,
                                references=rule.references,
                                tags=["docker", "container", "security", rule.rule_id],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

            # Check for missing USER directive
            if not has_user_directive:
                for rule in self.docker_rules:
                    if rule.rule_id == "DOCKER003":
                        # Take a snippet from the beginning of the file
                        snippet = "\n".join(lines[: min(7, len(lines))])

                        findings.append(
                            Finding(
                                id=f"{rule.rule_id}-{uuid.uuid4().hex[:8]}",
                                title=rule.title,
                                description=rule.description,
                                severity=rule.severity,
                                type=rule.finding_type,
                                location=Location(
                                    path=file_path,
                                    line_start=1,  # Reference the beginning of the file
                                    line_end=1,
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.9,
                                references=rule.references,
                                tags=["docker", "container", "security", rule.rule_id],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )
                        break

            return findings
        except Exception as e:
            logger.error(f"Error analyzing Dockerfile {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"DOCKER-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze Dockerfile",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "docker"],
                )
            ]

    def _analyze_package_json(self, file_path: Path) -> List[Finding]:
        """Analyze a package.json file for security issues.

        Args:
            file_path: Path to the package.json file to analyze

        Returns:
            List of findings detected in the package.json file
        """
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
                package_data = json.loads(content)

            lines = content.splitlines()

            # Check for vulnerable dependencies using rules
            for rule in self.npm_rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(content))

                    for match in matches:
                        # Get line number and context
                        line_number = content[: match.start()].count("\n") + 1
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
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
                                    line_start=line_number,
                                    line_end=line_number,
                                    column_start=0,
                                    column_end=(
                                        len(lines[line_number - 1])
                                        if line_number <= len(lines)
                                        else 0
                                    ),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.8,
                                references=rule.references,
                                tags=["npm", "dependency", "security", rule.rule_id],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

            # Check for known vulnerable dependencies
            if "dependencies" in package_data:
                self._check_npm_dependencies(
                    file_path, package_data["dependencies"], findings, is_dev=False
                )

            if "devDependencies" in package_data:
                self._check_npm_dependencies(
                    file_path, package_data["devDependencies"], findings, is_dev=True
                )

            # Use npm audit if available
            if self.use_npm_audit:
                findings.extend(self._run_npm_audit(file_path))

            return findings
        except Exception as e:
            logger.error(f"Error analyzing package.json {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"NPM-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze package.json",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "npm"],
                )
            ]

    def _check_npm_dependencies(
        self,
        file_path: Path,
        dependencies: Dict[str, str],
        findings: List[Finding],
        is_dev: bool = False,
    ) -> None:
        """Check NPM dependencies for known vulnerabilities.

        Args:
            file_path: Path to the package.json file
            dependencies: Dictionary of dependencies and their versions
            findings: List to add findings to
            is_dev: Whether these are dev dependencies
        """
        for pkg, version in dependencies.items():
            if pkg in KNOWN_VULNERABLE_NPM_PACKAGES:
                # Simple version parsing (in a real implementation, use a proper semver parser)
                raw_version = version.replace("^", "").replace("~", "")

                # Check if version matches any vulnerable version
                for vuln_version_range in KNOWN_VULNERABLE_NPM_PACKAGES[pkg]:
                    if vuln_version_range.startswith("<") and self._version_lt(
                        raw_version, vuln_version_range[1:]
                    ):
                        findings.append(
                            Finding(
                                id=f"NPM001-{uuid.uuid4().hex[:8]}",
                                title=f"Vulnerable NPM package: {pkg}",
                                description=(
                                    f"Package {pkg}@{version} has known vulnerabilities in versions {vuln_version_range}. "
                                    f"This is a {'development' if is_dev else 'production'} dependency."
                                ),
                                severity=Severity.HIGH,
                                type=FindingType.VULNERABILITY,
                                location=Location(
                                    path=file_path,
                                    snippet=f'"dependencies": {{\n  "{pkg}": "{version}"\n}}',
                                ),
                                analyzer=self.name,
                                confidence=0.9,
                                references=["https://www.npmjs.com/advisories"],
                                tags=[
                                    "npm",
                                    "dependency",
                                    "vulnerability",
                                    "package-json",
                                ],
                                remediation=f"Update {pkg} to a version not affected by known vulnerabilities.",
                                cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
                                cvss_score=7.5,
                            )
                        )
                        break

    def _version_lt(self, version1: str, version2: str) -> bool:
        """Compare two version strings.

        Args:
            version1: First version string (e.g., "1.2.3")
            version2: Second version string (e.g., "1.3.0")

        Returns:
            True if version1 is less than version2, False otherwise
        """
        try:
            v1_parts = list(map(int, version1.split(".")))
            v2_parts = list(map(int, version2.split(".")))

            # Pad with zeros if needed
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)

            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return True
                if v1_parts[i] > v2_parts[i]:
                    return False

            return False  # Equal versions
        except (ValueError, AttributeError):
            # If we can't parse the version, return False to be safe
            return False

    def _run_npm_audit(self, file_path: Path) -> List[Finding]:
        """Run npm audit on a package.json file.

        Args:
            file_path: Path to the package.json file

        Returns:
            List of findings detected by npm audit
        """
        findings = []

        try:
            # Change to the directory containing package.json
            original_dir = os.getcwd()
            os.chdir(file_path.parent)

            # Run npm audit
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    check=False,
                    capture_output=True,
                    text=True,
                )

                # npm audit returns non-zero on vulnerabilities, which isn't an error for us
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)

                        # Extract vulnerabilities from different npm audit formats
                        vulnerabilities = {}
                        if "vulnerabilities" in audit_data:
                            vulnerabilities = audit_data["vulnerabilities"]
                        elif "advisories" in audit_data:
                            vulnerabilities = audit_data["advisories"]

                        for vuln_id, vuln_data in vulnerabilities.items():
                            # Map severity to our severity enum
                            severity_str = vuln_data.get("severity", "").lower()
                            severity_mapping = {
                                "critical": Severity.CRITICAL,
                                "high": Severity.HIGH,
                                "moderate": Severity.MEDIUM,
                                "low": Severity.LOW,
                            }
                            severity = severity_mapping.get(
                                severity_str, Severity.MEDIUM
                            )

                            # Extract details
                            package_name = vuln_data.get("name", "Unknown")
                            version = vuln_data.get("version", "Unknown")
                            title = vuln_data.get(
                                "title", f"Vulnerability in {package_name}"
                            )
                            url = vuln_data.get("url", "")

                            findings.append(
                                Finding(
                                    id=f"NPM-AUDIT-{vuln_id}-{uuid.uuid4().hex[:8]}",
                                    title=title,
                                    description=(
                                        f"npm audit found vulnerability in {package_name}@{version}: {vuln_data.get('overview', '')}"
                                    ),
                                    severity=severity,
                                    type=FindingType.VULNERABILITY,
                                    location=Location(
                                        path=file_path,
                                    ),
                                    analyzer="npm_audit",
                                    confidence=0.9,
                                    references=[url] if url else [],
                                    tags=[
                                        "npm",
                                        "audit",
                                        "dependency",
                                        "vulnerability",
                                    ],
                                    remediation=vuln_data.get(
                                        "recommendation", "Update to a patched version."
                                    ),
                                    cwe_id=f"CWE-{vuln_data.get('cwe', '1104')}",
                                    cvss_score=vuln_data.get("cvss", {}).get(
                                        "score", 5.0
                                    ),
                                )
                            )
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Failed to parse npm audit output as JSON: {result.stdout[:100]}..."
                        )
            finally:
                # Always change back to the original directory
                os.chdir(original_dir)

            return findings
        except Exception as e:
            logger.error(f"Error running npm audit: {str(e)}")
            os.chdir(original_dir)
            return []

    def _analyze_requirements_txt(self, file_path: Path) -> List[Finding]:
        """Analyze a requirements.txt file for security issues.

        Args:
            file_path: Path to the requirements.txt file to analyze

        Returns:
            List of findings detected in the requirements.txt file
        """
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            lines = content.splitlines()

            # Analyze with regex patterns
            for rule in self.pip_rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(content))

                    for match in matches:
                        # Get line number and context
                        line_number = content[: match.start()].count("\n") + 1
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
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
                                    line_start=line_number,
                                    line_end=line_number,
                                    column_start=0,
                                    column_end=(
                                        len(lines[line_number - 1])
                                        if line_number <= len(lines)
                                        else 0
                                    ),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.8,
                                references=rule.references,
                                tags=[
                                    "python",
                                    "pip",
                                    "dependency",
                                    "security",
                                    rule.rule_id,
                                ],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

            # Parse requirements.txt and check for vulnerable packages
            for line_number, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Extract package name and version
                if "==" in line:
                    parts = line.split("==")
                    if len(parts) >= 2:
                        package_name = parts[0].strip().lower()
                        version = (
                            parts[1].strip().split(";")[0].split(" ")[0]
                        )  # Handle version constraints

                        if package_name in KNOWN_VULNERABLE_PYTHON_PACKAGES:
                            for vuln_version_range in KNOWN_VULNERABLE_PYTHON_PACKAGES[
                                package_name
                            ]:
                                if vuln_version_range.startswith(
                                    "<"
                                ) and self._version_lt(version, vuln_version_range[1:]):
                                    # Create a snippet with context
                                    start_idx = max(0, line_number - 4)
                                    end_idx = min(len(lines), line_number + 3)
                                    snippet = "\n".join(lines[start_idx - 1 : end_idx])

                                    findings.append(
                                        Finding(
                                            id=f"PIP002-{uuid.uuid4().hex[:8]}",
                                            title=f"Vulnerable Python package: {package_name}",
                                            description=(
                                                f"Package {package_name}=={version} has known vulnerabilities "
                                                f"in versions {vuln_version_range}."
                                            ),
                                            severity=Severity.HIGH,
                                            type=FindingType.VULNERABILITY,
                                            location=Location(
                                                path=file_path,
                                                line_start=line_number,
                                                line_end=line_number,
                                                snippet=snippet,
                                            ),
                                            analyzer=self.name,
                                            confidence=0.9,
                                            references=[
                                                "https://pypi.org/project/safety/"
                                            ],
                                            tags=[
                                                "python",
                                                "pip",
                                                "dependency",
                                                "vulnerability",
                                            ],
                                            remediation=f"Update {package_name} to a non-vulnerable version.",
                                            cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
                                            cvss_score=7.5,
                                        )
                                    )
                                    break

            # Use safety if available
            if self.use_safety:
                findings.extend(self._run_safety(file_path))

            return findings
        except Exception as e:
            logger.error(f"Error analyzing requirements.txt {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"PIP-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze requirements.txt",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "python", "pip"],
                )
            ]

    def _run_safety(self, file_path: Path) -> List[Finding]:
        """Run safety on a requirements.txt file.

        Args:
            file_path: Path to the requirements.txt file

        Returns:
            List of findings detected by safety
        """
        findings = []

        try:
            # Run safety check
            result = subprocess.run(
                ["safety", "check", "--file", str(file_path), "--json"],
                check=False,
                capture_output=True,
                text=True,
            )

            # safety returns non-zero on vulnerabilities, which isn't an error for us
            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)

                    for vuln_data in safety_data:
                        if (
                            len(vuln_data) >= 5
                        ):  # Safety output format: [package, installed_version, affected_versions, vulnerability_id, description]
                            package_name = vuln_data[0]
                            installed_version = vuln_data[1]
                            vuln_id = vuln_data[3]
                            description = vuln_data[4]

                            findings.append(
                                Finding(
                                    id=f"SAFETY-{vuln_id}-{uuid.uuid4().hex[:8]}",
                                    title=f"Vulnerable Python package: {package_name}",
                                    description=(
                                        f"Package {package_name}=={installed_version} is vulnerable: {description}"
                                    ),
                                    severity=Severity.HIGH,
                                    type=FindingType.VULNERABILITY,
                                    location=Location(
                                        path=file_path,
                                    ),
                                    analyzer="safety",
                                    confidence=0.9,
                                    references=[
                                        f"https://pypi.org/project/{package_name}/"
                                    ],
                                    tags=[
                                        "python",
                                        "pip",
                                        "dependency",
                                        "vulnerability",
                                        "safety",
                                    ],
                                    remediation=f"Update {package_name} to a non-vulnerable version.",
                                    cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
                                    cvss_score=7.5,
                                )
                            )
                except json.JSONDecodeError:
                    logger.warning(
                        f"Failed to parse safety output as JSON: {result.stdout[:100]}..."
                    )

            return findings
        except Exception as e:
            logger.error(f"Error running safety: {str(e)}")
            return []

    def _analyze_yaml_config(self, file_path: Path) -> List[Finding]:
        """Analyze a YAML configuration file for security issues.

        Args:
            file_path: Path to the YAML file to analyze

        Returns:
            List of findings detected in the YAML configuration
        """
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()
                yaml_data = yaml.safe_load(content)  # Parse YAML

            lines = content.splitlines()

            # Analyze with regex patterns
            for rule in self.yaml_rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(content))

                    for match in matches:
                        # Get line number and context
                        line_number = content[: match.start()].count("\n") + 1
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
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
                                    line_start=line_number,
                                    line_end=line_number,
                                    column_start=0,
                                    column_end=(
                                        len(lines[line_number - 1])
                                        if line_number <= len(lines)
                                        else 0
                                    ),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.8,
                                references=rule.references,
                                tags=["yaml", "config", "security", rule.rule_id],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

            # Deep analysis of YAML structure
            # 1. Check if it's a Kubernetes manifest
            if self._is_kubernetes_manifest(yaml_data):
                findings.extend(
                    self._analyze_kubernetes_yaml(file_path, yaml_data, content, lines)
                )

            # 2. Check if it's a GitHub Actions workflow
            elif self._is_github_actions_workflow(yaml_data):
                findings.extend(
                    self._analyze_github_actions_yaml(
                        file_path, yaml_data, content, lines
                    )
                )

            return findings
        except Exception as e:
            logger.error(f"Error analyzing YAML {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"YAML-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze YAML configuration",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "yaml"],
                )
            ]

    def _is_kubernetes_manifest(self, yaml_data: Any) -> bool:
        """Check if the YAML data represents a Kubernetes manifest.

        Args:
            yaml_data: Parsed YAML data

        Returns:
            True if it's a Kubernetes manifest, False otherwise
        """
        if not isinstance(yaml_data, dict):
            return False

        # Check for Kubernetes API fields
        return (
            yaml_data.get("apiVersion") is not None
            and yaml_data.get("kind") is not None
            and yaml_data.get("metadata") is not None
        )

    def _analyze_kubernetes_yaml(
        self, file_path: Path, yaml_data: Dict, content: str, lines: List[str]
    ) -> List[Finding]:
        """Analyze a Kubernetes YAML file for security issues.

        Args:
            file_path: Path to the YAML file
            yaml_data: Parsed YAML data
            content: Raw content of the file
            lines: Lines of the file

        Returns:
            List of findings detected in the Kubernetes manifest
        """
        findings = []

        # Extract basic information
        kind = yaml_data.get("kind", "Unknown")
        name = yaml_data.get("metadata", {}).get("name", "unknown")

        # Check for specific Kubernetes issues
        # 1. Check for hostPath volumes (security risk)
        if kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
            # Extract pod spec based on resource type
            pod_spec = None
            if kind == "Pod":
                pod_spec = yaml_data.get("spec", {})
            else:
                pod_spec = yaml_data.get("spec", {}).get("template", {}).get("spec", {})

            if pod_spec and "volumes" in pod_spec:
                for i, volume in enumerate(pod_spec["volumes"]):
                    if "hostPath" in volume:
                        # Find line number (approximate)
                        hostpath_pattern = re.compile(r"hostPath:", re.MULTILINE)
                        matches = list(hostpath_pattern.finditer(content))
                        line_number = (
                            content[: matches[i].start()].count("\n") + 1
                            if i < len(matches)
                            else 1
                        )

                        # Extract snippet
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
                        snippet = "\n".join(lines[start_idx:end_idx])

                        findings.append(
                            Finding(
                                id=f"K8S-HOSTPATH-{uuid.uuid4().hex[:8]}",
                                title="Kubernetes hostPath volume mounted",
                                description=(
                                    f"The {kind} '{name}' uses a hostPath volume, which allows access to the "
                                    f"host filesystem and can be a serious security risk."
                                ),
                                severity=Severity.HIGH,
                                type=FindingType.MISCONFIG,
                                location=Location(
                                    path=file_path,
                                    line_start=line_number,
                                    line_end=line_number,
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.9,
                                references=[
                                    "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                                ],
                                tags=["kubernetes", "yaml", "security", "hostpath"],
                                remediation="Avoid using hostPath volumes when possible. Consider using more secure volume types.",
                                cwe_id="CWE-668",  # Exposure of Resource to Wrong Sphere
                                cvss_score=7.5,
                            )
                        )

        # 2. Check for privileged containers
        # Already covered by regex rules

        # 3. Check for host network
        if kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
            pod_spec = None
            if kind == "Pod":
                pod_spec = yaml_data.get("spec", {})
            else:
                pod_spec = yaml_data.get("spec", {}).get("template", {}).get("spec", {})

            if pod_spec and pod_spec.get("hostNetwork") is True:
                # Find line number (approximate)
                hostnetwork_pattern = re.compile(
                    r"hostNetwork:\s*true", re.MULTILINE | re.IGNORECASE
                )
                matches = list(hostnetwork_pattern.finditer(content))
                line_number = (
                    content[: matches[0].start()].count("\n") + 1 if matches else 1
                )

                # Extract snippet
                start_idx = max(0, line_number - 4)
                end_idx = min(len(lines), line_number + 3)
                snippet = "\n".join(lines[start_idx:end_idx])

                findings.append(
                    Finding(
                        id=f"K8S-HOSTNETWORK-{uuid.uuid4().hex[:8]}",
                        title="Kubernetes hostNetwork enabled",
                        description=(
                            f"The {kind} '{name}' uses hostNetwork: true, which gives the pod "
                            f"access to the host's network namespace and can be a security risk."
                        ),
                        severity=Severity.HIGH,
                        type=FindingType.MISCONFIG,
                        location=Location(
                            path=file_path,
                            line_start=line_number,
                            line_end=line_number,
                            snippet=snippet,
                        ),
                        analyzer=self.name,
                        confidence=0.9,
                        references=[
                            "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
                        ],
                        tags=["kubernetes", "yaml", "security", "hostnetwork"],
                        remediation="Avoid using hostNetwork unless absolutely necessary.",
                        cwe_id="CWE-668",  # Exposure of Resource to Wrong Sphere
                        cvss_score=7.5,
                    )
                )

        return findings

    def _is_github_actions_workflow(self, yaml_data: Any) -> bool:
        """Check if the YAML data represents a GitHub Actions workflow.

        Args:
            yaml_data: Parsed YAML data

        Returns:
            True if it's a GitHub Actions workflow, False otherwise
        """
        if not isinstance(yaml_data, dict):
            return False

        # Check for GitHub Actions workflow fields
        return (
            yaml_data.get("name") is not None
            and yaml_data.get("on") is not None
            and yaml_data.get("jobs") is not None
        )

    def _analyze_github_actions_yaml(
        self, file_path: Path, yaml_data: Dict, content: str, lines: List[str]
    ) -> List[Finding]:
        """Analyze a GitHub Actions workflow file for security issues.

        Args:
            file_path: Path to the YAML file
            yaml_data: Parsed YAML data
            content: Raw content of the file
            lines: Lines of the file

        Returns:
            List of findings detected in the GitHub Actions workflow
        """
        findings = []

        # Check for jobs that checkout code without pinning to a specific commit SHA
        jobs = yaml_data.get("jobs", {})
        for _job_name, job_config in jobs.items():
            if "steps" in job_config:
                for _i, step in enumerate(job_config["steps"]):
                    # Check for checkout action without pinning to a commit SHA
                    if step.get("uses", "").startswith(
                        "actions/checkout@"
                    ) and "@" in step.get("uses", ""):
                        action_ref = step.get("uses", "").split("@")[1]
                        if action_ref in ["v1", "v2", "v3", "master", "main"]:
                            # Find line number (approximate)
                            pattern = re.compile(
                                f'uses:\\s*{re.escape(step.get("uses", ""))}',
                                re.MULTILINE,
                            )
                            matches = list(pattern.finditer(content))
                            line_number = (
                                content[: matches[0].start()].count("\n") + 1
                                if matches
                                else 1
                            )

                            # Extract snippet
                            start_idx = max(0, line_number - 4)
                            end_idx = min(len(lines), line_number + 3)
                            snippet = "\n".join(lines[start_idx:end_idx])

                            findings.append(
                                Finding(
                                    id=f"GHA-CHECKOUT-{uuid.uuid4().hex[:8]}",
                                    title="GitHub Action not pinned to a specific commit",
                                    description=(
                                        f"The action '{step.get('uses', '')}' is not pinned to a specific commit SHA, "
                                        f"which is a security risk for supply chain attacks."
                                    ),
                                    severity=Severity.MEDIUM,
                                    type=FindingType.MISCONFIG,
                                    location=Location(
                                        path=file_path,
                                        line_start=line_number,
                                        line_end=line_number,
                                        snippet=snippet,
                                    ),
                                    analyzer=self.name,
                                    confidence=0.9,
                                    references=[
                                        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
                                    ],
                                    tags=[
                                        "github",
                                        "actions",
                                        "security",
                                        "supply-chain",
                                    ],
                                    remediation="Pin GitHub Actions to a full commit SHA for better security.",
                                    cwe_id="CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
                                    cvss_score=5.5,
                                )
                            )

        return findings

    def _analyze_toml_config(self, file_path: Path) -> List[Finding]:
        """Analyze a TOML configuration file for security issues.

        Args:
            file_path: Path to the TOML file to analyze

        Returns:
            List of findings detected in the TOML configuration
        """
        findings = []

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            lines = content.splitlines()

            # Analyze with regex patterns
            for rule in self.toml_rules:
                if rule.regex_pattern:
                    matches = list(rule.regex_pattern.finditer(content))

                    for match in matches:
                        # Get line number and context
                        line_number = content[: match.start()].count("\n") + 1
                        start_idx = max(0, line_number - 4)
                        end_idx = min(len(lines), line_number + 3)
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
                                    line_start=line_number,
                                    line_end=line_number,
                                    column_start=0,
                                    column_end=(
                                        len(lines[line_number - 1])
                                        if line_number <= len(lines)
                                        else 0
                                    ),
                                    snippet=snippet,
                                ),
                                analyzer=self.name,
                                confidence=0.8,
                                references=rule.references,
                                tags=["toml", "config", "security", rule.rule_id],
                                remediation=rule.remediation,
                                cwe_id=rule.cwe_id,
                                cvss_score=rule.cvss_score,
                            )
                        )

            try:
                # Parse TOML for deeper analysis
                toml_data = toml.loads(content)

                # Check specific file types
                if file_path.name == "pyproject.toml":
                    findings.extend(
                        self._analyze_pyproject_toml(
                            file_path, toml_data, content, lines
                        )
                    )
                elif file_path.name == "Cargo.toml":
                    findings.extend(
                        self._analyze_cargo_toml(file_path, toml_data, content, lines)
                    )
            except Exception as e:
                logger.warning(f"Failed to parse TOML file {file_path}: {str(e)}")

            return findings
        except Exception as e:
            logger.error(f"Error analyzing TOML {file_path}: {str(e)}")
            return [
                Finding(
                    id=f"TOML-ANALYZER-ERROR-{uuid.uuid4().hex[:8]}",
                    title="Failed to analyze TOML configuration",
                    description=f"The analyzer encountered an error: {str(e)}",
                    severity=Severity.LOW,
                    type=FindingType.OTHER,
                    location=Location(path=file_path),
                    analyzer=self.name,
                    confidence=1.0,
                    tags=["analyzer-error", "toml"],
                )
            ]

    def _analyze_pyproject_toml(
        self, file_path: Path, toml_data: Dict, content: str, lines: List[str]
    ) -> List[Finding]:
        """Analyze a pyproject.toml file for security issues.

        Args:
            file_path: Path to the TOML file
            toml_data: Parsed TOML data
            content: Raw content of the file
            lines: Lines of the file

        Returns:
            List of findings detected in the pyproject.toml file
        """
        findings = []

        # Check for dependencies
        if "project" in toml_data and "dependencies" in toml_data["project"]:
            dependencies = toml_data["project"]["dependencies"]
            if isinstance(dependencies, list):
                for dep in dependencies:
                    if isinstance(dep, str) and "==" in dep:
                        parts = dep.split("==")
                        if len(parts) >= 2:
                            package_name = parts[0].strip().lower()
                            version = parts[1].strip().split(";")[0].split(" ")[0]

                            if package_name in KNOWN_VULNERABLE_PYTHON_PACKAGES:
                                for (
                                    vuln_version_range
                                ) in KNOWN_VULNERABLE_PYTHON_PACKAGES[package_name]:
                                    if vuln_version_range.startswith(
                                        "<"
                                    ) and self._version_lt(
                                        version, vuln_version_range[1:]
                                    ):
                                        # Find line number (approximate)
                                        pattern = re.compile(
                                            f"{re.escape(dep)}", re.MULTILINE
                                        )
                                        matches = list(pattern.finditer(content))
                                        line_number = (
                                            content[: matches[0].start()].count("\n")
                                            + 1
                                            if matches
                                            else 1
                                        )

                                        # Extract snippet
                                        start_idx = max(0, line_number - 4)
                                        end_idx = min(len(lines), line_number + 3)
                                        snippet = "\n".join(lines[start_idx:end_idx])

                                        findings.append(
                                            Finding(
                                                id=f"PYPOT-VULN-{uuid.uuid4().hex[:8]}",
                                                title=f"Vulnerable Python package: {package_name}",
                                                description=(
                                                    f"Package {package_name}=={version} has known vulnerabilities "
                                                    f"in versions {vuln_version_range}."
                                                ),
                                                severity=Severity.HIGH,
                                                type=FindingType.VULNERABILITY,
                                                location=Location(
                                                    path=file_path,
                                                    line_start=line_number,
                                                    line_end=line_number,
                                                    snippet=snippet,
                                                ),
                                                analyzer=self.name,
                                                confidence=0.9,
                                                references=[
                                                    "https://pypi.org/project/safety/"
                                                ],
                                                tags=[
                                                    "python",
                                                    "dependency",
                                                    "vulnerability",
                                                    "pyproject",
                                                ],
                                                remediation=f"Update {package_name} to a non-vulnerable version.",
                                                cwe_id="CWE-1104",  # Use of Unmaintained Third Party Components
                                                cvss_score=7.5,
                                            )
                                        )
                                        break

        return findings

    def _analyze_cargo_toml(
        self,
        file_path: Path,  # noqa: ARG002
        toml_data: Dict,  # noqa: ARG002
        content: str,  # noqa: ARG002
        lines: List[str],  # noqa: ARG002
    ) -> List[Finding]:
        """Analyze a Cargo.toml file for security issues.

        Args:
            file_path: Path to the TOML file
            toml_data: Parsed TOML data
            content: Raw content of the file
            lines: Lines of the file

        Returns:
            List of findings detected in the Cargo.toml file
        """
        findings: List[Finding] = []

        # Check for dependencies with potential security issues
        # For now, this is covered by the regex rules
        # In a production system, you would integrate with RustSec advisories

        return findings

    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this analyzer can analyze the specified file.

        Args:
            file_path: Path to the file to check.

        Returns:
            True if this analyzer can analyze the file, False otherwise.
        """
        if not self.enabled:
            return False

        if not file_path.exists():
            return False

        file_name = file_path.name.lower()
        file_suffix = file_path.suffix.lower()

        # Specific file types
        if (
            file_name == "dockerfile"
            or file_suffix == ".dockerfile"
            or "dockerfile" in file_name
        ):
            return True

        if file_name == "package.json":
            return True

        if file_name == "requirements.txt":
            return True

        # Check extensions for YAML and TOML files
        if file_suffix in [".yml", ".yaml", ".toml"]:
            return True

        return super().can_analyze_file(file_path)
