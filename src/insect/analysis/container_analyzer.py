"""
Container security analyzer for Docker and container-related files.

This module provides comprehensive security analysis for containerized applications including:
- Dockerfile security best practices analysis
- Docker Compose security configuration review
- Container image vulnerability scanning
- Kubernetes security configuration analysis
- Container runtime security checks
- Supply chain security for container dependencies
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml  # type: ignore[import-untyped]

from ..finding import Finding, Severity
from . import BaseAnalyzer, register_analyzer

logger = logging.getLogger(__name__)


@dataclass
class ContainerSecurityRule:
    """Definition of a container security rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    pattern: Optional[re.Pattern] = None
    check_function: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None


@register_analyzer
class ContainerAnalyzer(BaseAnalyzer):
    """Analyzer for container security issues in Dockerfiles and related files."""

    name = "container"
    description = "Security analysis for Docker containers and orchestration files"
    supported_extensions = {".dockerfile", ".docker", ".yml", ".yaml", ".json"}

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)

        # Configuration
        analyzer_config = config.get(self.name, {})
        self.check_base_images = analyzer_config.get("check_base_images", True)
        self.check_secrets = analyzer_config.get("check_secrets", True)
        self.check_privileges = analyzer_config.get("check_privileges", True)
        self.check_networking = analyzer_config.get("check_networking", True)

        # Initialize security rules
        self.dockerfile_rules = self._init_dockerfile_rules()
        self.compose_rules = self._init_compose_rules()
        self.kubernetes_rules = self._init_kubernetes_rules()

        # Known vulnerable base images (simplified list)
        self.vulnerable_base_images = {
            "ubuntu:14.04",
            "ubuntu:16.04",
            "ubuntu:18.04",
            "debian:7",
            "debian:8",
            "debian:9",
            "centos:6",
            "centos:7",
            "alpine:3.0",
            "alpine:3.1",
            "alpine:3.2",
            "alpine:3.3",
            "node:10",
            "node:12",
            "node:14",
            "python:2.7",
            "python:3.6",
            "python:3.7",
        }

        # Sensitive file patterns
        self.sensitive_files = {
            r"/etc/passwd",
            r"/etc/shadow",
            r"/etc/hosts",
            r"/etc/ssh/",
            r"/root/",
            r"/home/",
            r"\.ssh/",
            r"\.key",
            r"\.pem",
            r"\.p12",
            r"\.pfx",
            r"id_rsa",
            r"id_dsa",
            r"\.crt",
        }

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a container-related file for security issues."""
        findings = []

        try:
            file_path.name.lower()

            # Determine file type and analyze accordingly
            if self._is_dockerfile(file_path):
                findings.extend(self._analyze_dockerfile(file_path))
            elif self._is_docker_compose(file_path):
                findings.extend(self._analyze_docker_compose(file_path))
            elif self._is_kubernetes_config(file_path):
                findings.extend(self._analyze_kubernetes_config(file_path))

        except Exception as e:
            logger.error(f"Error analyzing container file {file_path}: {e}")

        return findings

    def _is_dockerfile(self, file_path: Path) -> bool:
        """Check if file is a Dockerfile."""
        name = file_path.name.lower()
        return (
            name == "dockerfile"
            or name.startswith("dockerfile.")
            or name.endswith(".dockerfile")
            or name.endswith(".docker")
            or name.endswith("dockerfile")
        )

    def _is_docker_compose(self, file_path: Path) -> bool:
        """Check if file is a docker-compose file."""
        name = file_path.name.lower()
        return ("docker-compose" in name or "compose" in name) and name.endswith(
            (".yml", ".yaml")
        )

    def _is_kubernetes_config(self, file_path: Path) -> bool:
        """Check if file is a Kubernetes configuration."""
        if not file_path.name.endswith((".yml", ".yaml", ".json")):
            return False

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # Look for Kubernetes API version indicators
            k8s_indicators = ["apiVersion:", "kind:", "metadata:", "spec:"]
            return any(indicator in content for indicator in k8s_indicators)
        except Exception:
            return False

    def _analyze_dockerfile(self, file_path: Path) -> List[Finding]:
        """Analyze Dockerfile for security issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            # Apply Dockerfile-specific rules
            for rule in self.dockerfile_rules:
                if rule.pattern:
                    findings.extend(
                        self._apply_pattern_rule(file_path, content, lines, rule)
                    )
                elif rule.check_function:
                    method = getattr(self, rule.check_function, None)
                    if method:
                        findings.extend(method(file_path, content, lines, rule))

        except Exception as e:
            logger.error(f"Error analyzing Dockerfile {file_path}: {e}")

        return findings

    def _analyze_docker_compose(self, file_path: Path) -> List[Finding]:
        """Analyze Docker Compose file for security issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Parse YAML
            try:
                compose_data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                findings.append(
                    self._create_finding(
                        rule_id="DOCKER_COMPOSE_INVALID_YAML",
                        title="Invalid YAML in Docker Compose file",
                        description=f"Docker Compose file contains invalid YAML: {e}",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="OTHER",
                    )
                )
                return findings

            # Apply Compose-specific rules
            for rule in self.compose_rules:
                if rule.check_function:
                    method = getattr(self, rule.check_function, None)
                    if method:
                        findings.extend(method(file_path, compose_data, rule))

        except Exception as e:
            logger.error(f"Error analyzing Docker Compose file {file_path}: {e}")

        return findings

    def _analyze_kubernetes_config(self, file_path: Path) -> List[Finding]:
        """Analyze Kubernetes configuration for security issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Parse YAML
            try:
                k8s_data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                findings.append(
                    self._create_finding(
                        rule_id="K8S_INVALID_YAML",
                        title="Invalid YAML in Kubernetes configuration",
                        description=f"Kubernetes configuration contains invalid YAML: {e}",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="OTHER",
                    )
                )
                return findings

            # Apply Kubernetes-specific rules
            for rule in self.kubernetes_rules:
                if rule.check_function:
                    method = getattr(self, rule.check_function, None)
                    if method:
                        findings.extend(method(file_path, k8s_data, rule))

        except Exception as e:
            logger.error(f"Error analyzing Kubernetes config {file_path}: {e}")

        return findings

    def _apply_pattern_rule(
        self,
        file_path: Path,
        content: str,  # noqa: ARG002
        lines: List[str],
        rule: ContainerSecurityRule,
    ) -> List[Finding]:  # noqa: ARG002
        """Apply a pattern-based rule to the content."""
        findings = []

        for line_num, line in enumerate(lines, 1):
            if rule.pattern:
                matches = rule.pattern.finditer(line)
            else:
                continue
            for match in matches:
                finding = self._create_finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=line_num,
                    column_number=match.start() + 1,
                    finding_type="MISCONFIG",
                    remediation=rule.remediation,
                )
                findings.append(finding)

        return findings

    def _init_dockerfile_rules(self) -> List[ContainerSecurityRule]:
        """Initialize Dockerfile security rules."""
        rules = []

        # Running as root
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_USER_ROOT",
                title="Container runs as root user",
                description="Container is configured to run as root user, which poses security risks",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"^USER\s+(?:0|root)\s*$", re.IGNORECASE | re.MULTILINE
                ),
                remediation="Create and use a non-root user: USER 1000:1000 or USER appuser",
                references=["https://docs.docker.com/develop/dev-best-practices/"],
            )
        )

        # Secrets in environment variables
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_SECRETS_IN_ENV",
                title="Potential secrets in environment variables",
                description="Environment variables may contain sensitive information",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"ENV\s+[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)[A-Z_]*\s*[=\s]\s*[^\s]+",
                    re.IGNORECASE,
                ),
                remediation="Use build secrets or runtime environment variables instead",
                references=["https://docs.docker.com/engine/swarm/secrets/"],
            )
        )

        # Vulnerable base images
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_VULNERABLE_BASE_IMAGE",
                title="Potentially vulnerable base image",
                description="Base image may contain known vulnerabilities",
                severity=Severity.MEDIUM,
                check_function="_check_vulnerable_base_image",
            )
        )

        # Unnecessary packages
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_UNNECESSARY_PACKAGES",
                title="Potentially unnecessary packages installed",
                description="Installation of packages that may not be needed and increase attack surface",
                severity=Severity.LOW,
                pattern=re.compile(
                    r"(?:RUN|apt-get|yum|apk)\s+.*(?:install|add).*(?:curl|wget|ssh|telnet|ftp|nc|netcat|nmap|gcc|build-essential)",
                    re.IGNORECASE,
                ),
                remediation="Remove unnecessary packages and use multi-stage builds",
                references=["https://docs.docker.com/develop/dev-best-practices/"],
            )
        )

        # Privileged operations
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_PRIVILEGED_OPERATIONS",
                title="Privileged operations detected",
                description="Dockerfile contains privileged operations that may be unnecessary",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"(?:sudo|su\s|chmod\s+[0-9]*7|chown.*root|setuid|setgid)",
                    re.IGNORECASE,
                ),
                remediation="Avoid privileged operations where possible",
                references=["https://docs.docker.com/engine/security/"],
            )
        )

        # Hardcoded secrets
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_HARDCODED_SECRETS",
                title="Potential hardcoded secrets",
                description="Dockerfile may contain hardcoded sensitive information",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r'(?:password|secret|key|token)\s*[=:]\s*["\']?[a-zA-Z0-9+/=]{8,}["\']?',
                    re.IGNORECASE,
                ),
                remediation="Use build secrets or environment variables",
                references=["https://docs.docker.com/engine/swarm/secrets/"],
            )
        )

        # Missing health checks
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_NO_HEALTHCHECK",
                title="Missing health check",
                description="Dockerfile does not include a health check",
                severity=Severity.LOW,
                check_function="_check_missing_healthcheck",
            )
        )

        # Copying sensitive files
        rules.append(
            ContainerSecurityRule(
                rule_id="DOCKERFILE_COPYING_SENSITIVE_FILES",
                title="Copying potentially sensitive files",
                description="Dockerfile copies files that may contain sensitive information",
                severity=Severity.MEDIUM,
                check_function="_check_sensitive_file_copy",
            )
        )

        return rules

    def _init_compose_rules(self) -> List[ContainerSecurityRule]:
        """Initialize Docker Compose security rules."""
        rules = []

        # Privileged containers
        rules.append(
            ContainerSecurityRule(
                rule_id="COMPOSE_PRIVILEGED_CONTAINER",
                title="Privileged container configuration",
                description="Container is configured to run in privileged mode",
                severity=Severity.HIGH,
                check_function="_check_compose_privileged",
            )
        )

        # Host network mode
        rules.append(
            ContainerSecurityRule(
                rule_id="COMPOSE_HOST_NETWORK",
                title="Host network mode enabled",
                description="Container uses host network mode, which may expose host network",
                severity=Severity.MEDIUM,
                check_function="_check_compose_host_network",
            )
        )

        # Volume mounts
        rules.append(
            ContainerSecurityRule(
                rule_id="COMPOSE_DANGEROUS_VOLUME_MOUNTS",
                title="Potentially dangerous volume mounts",
                description="Container mounts sensitive host directories",
                severity=Severity.HIGH,
                check_function="_check_compose_volume_mounts",
            )
        )

        # Environment secrets
        rules.append(
            ContainerSecurityRule(
                rule_id="COMPOSE_SECRETS_IN_ENVIRONMENT",
                title="Secrets in environment variables",
                description="Environment variables may contain sensitive information",
                severity=Severity.MEDIUM,
                check_function="_check_compose_env_secrets",
            )
        )

        return rules

    def _init_kubernetes_rules(self) -> List[ContainerSecurityRule]:
        """Initialize Kubernetes security rules."""
        rules = []

        # Privileged containers
        rules.append(
            ContainerSecurityRule(
                rule_id="K8S_PRIVILEGED_CONTAINER",
                title="Privileged container in Kubernetes",
                description="Pod contains containers running in privileged mode",
                severity=Severity.HIGH,
                check_function="_check_k8s_privileged",
            )
        )

        # Host namespaces
        rules.append(
            ContainerSecurityRule(
                rule_id="K8S_HOST_NAMESPACES",
                title="Host namespace usage",
                description="Pod uses host network, PID, or IPC namespaces",
                severity=Severity.HIGH,
                check_function="_check_k8s_host_namespaces",
            )
        )

        # Security context
        rules.append(
            ContainerSecurityRule(
                rule_id="K8S_MISSING_SECURITY_CONTEXT",
                title="Missing security context",
                description="Pod or container lacks proper security context configuration",
                severity=Severity.MEDIUM,
                check_function="_check_k8s_security_context",
            )
        )

        # Resource limits
        rules.append(
            ContainerSecurityRule(
                rule_id="K8S_MISSING_RESOURCE_LIMITS",
                title="Missing resource limits",
                description="Container lacks CPU and memory resource limits",
                severity=Severity.LOW,
                check_function="_check_k8s_resource_limits",
            )
        )

        return rules

    # Dockerfile check functions
    def _check_vulnerable_base_image(
        self,
        file_path: Path,
        content: str,  # noqa: ARG002
        lines: List[str],
        rule: ContainerSecurityRule,
    ) -> List[Finding]:  # noqa: ARG002
        """Check for vulnerable base images."""
        findings = []

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith("FROM "):
                image = line[5:].strip()
                # Remove AS alias
                if " AS " in image.upper():
                    image = image.split(" AS ")[0].strip()

                if image in self.vulnerable_base_images:
                    finding = self._create_finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=f"{rule.description}: {image}",
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_num,
                        column_number=1,
                        finding_type="VULNERABILITY",
                        remediation=f"Update to a newer version of {image.split(':')[0]}",
                    )
                    findings.append(finding)

        return findings

    def _check_missing_healthcheck(
        self,
        file_path: Path,
        content: str,  # noqa: ARG002
        lines: List[str],
        rule: ContainerSecurityRule,
    ) -> List[Finding]:  # noqa: ARG002
        """Check for missing health checks."""
        has_healthcheck = any("HEALTHCHECK" in line.upper() for line in lines)

        if not has_healthcheck:
            finding = self._create_finding(
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                severity=rule.severity,
                file_path=file_path,
                line_number=1,
                column_number=1,
                finding_type="MISCONFIG",
                remediation="Add HEALTHCHECK instruction to monitor container health",
            )
            return [finding]

        return []

    def _check_sensitive_file_copy(
        self,
        file_path: Path,
        content: str,  # noqa: ARG002
        lines: List[str],
        rule: ContainerSecurityRule,
    ) -> List[Finding]:  # noqa: ARG002
        """Check for copying sensitive files."""
        findings = []

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith(("COPY ", "ADD ")):
                for pattern in self.sensitive_files:
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = self._create_finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=f"{rule.description}: {line}",
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=line_num,
                            column_number=1,
                            finding_type="SECRET",
                            remediation="Avoid copying sensitive files or use .dockerignore",
                        )
                        findings.append(finding)
                        break

        return findings

    # Docker Compose check functions
    def _check_compose_privileged(
        self, file_path: Path, compose_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for privileged containers in Docker Compose."""
        findings = []

        services = compose_data.get("services", {})
        for service_name, service_config in services.items():
            if service_config.get("privileged", False):
                finding = self._create_finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=f"{rule.description} in service '{service_name}'",
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=1,
                    column_number=1,
                    finding_type="MISCONFIG",
                    remediation="Remove privileged: true or use specific capabilities",
                )
                findings.append(finding)

        return findings

    def _check_compose_host_network(
        self, file_path: Path, compose_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for host network mode in Docker Compose."""
        findings = []

        services = compose_data.get("services", {})
        for service_name, service_config in services.items():
            network_mode = service_config.get("network_mode")
            if network_mode == "host":
                finding = self._create_finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=f"{rule.description} in service '{service_name}'",
                    severity=rule.severity,
                    file_path=file_path,
                    line_number=1,
                    column_number=1,
                    finding_type="MISCONFIG",
                    remediation="Use bridge networking and expose specific ports",
                )
                findings.append(finding)

        return findings

    def _check_compose_volume_mounts(
        self, file_path: Path, compose_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for dangerous volume mounts in Docker Compose."""
        findings = []

        dangerous_mounts = [
            "/etc",
            "/proc",
            "/sys",
            "/dev",
            "/var/run/docker.sock",
            "/root",
            "/home",
        ]

        services = compose_data.get("services", {})
        for service_name, service_config in services.items():
            volumes = service_config.get("volumes", [])
            for volume in volumes:
                if isinstance(volume, str) and ":" in volume:
                    # Handle short syntax
                    host_path = volume.split(":")[0]
                    if any(host_path.startswith(danger) for danger in dangerous_mounts):
                        finding = self._create_finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=f"{rule.description}: {volume} in service '{service_name}'",
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=1,
                            column_number=1,
                            finding_type="MISCONFIG",
                            remediation="Avoid mounting sensitive host directories",
                        )
                        findings.append(finding)

        return findings

    def _check_compose_env_secrets(
        self, file_path: Path, compose_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for secrets in environment variables."""
        findings = []

        secret_patterns = ["password", "secret", "key", "token", "credential"]

        services = compose_data.get("services", {})
        for service_name, service_config in services.items():
            environment = service_config.get("environment", {})
            if isinstance(environment, list):
                # Handle list format
                for env_var in environment:
                    if "=" in env_var:
                        var_name = env_var.split("=")[0].lower()
                        if any(pattern in var_name for pattern in secret_patterns):
                            finding = self._create_finding(
                                rule_id=rule.rule_id,
                                title=rule.title,
                                description=f"{rule.description}: {env_var.split('=')[0]} in service '{service_name}'",
                                severity=rule.severity,
                                file_path=file_path,
                                line_number=1,
                                column_number=1,
                                finding_type="SECRET",
                                remediation="Use Docker secrets or external secret management",
                            )
                            findings.append(finding)
            elif isinstance(environment, dict):
                # Handle dict format
                for var_name, _var_value in environment.items():
                    if any(pattern in var_name.lower() for pattern in secret_patterns):
                        finding = self._create_finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            description=f"{rule.description}: {var_name} in service '{service_name}'",
                            severity=rule.severity,
                            file_path=file_path,
                            line_number=1,
                            column_number=1,
                            finding_type="SECRET",
                            remediation="Use Docker secrets or external secret management",
                        )
                        findings.append(finding)

        return findings

    # Kubernetes check functions
    def _check_k8s_privileged(
        self, file_path: Path, k8s_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for privileged containers in Kubernetes."""
        findings = []

        if k8s_data.get("kind") == "Pod" or k8s_data.get("kind") == "Deployment":
            spec = k8s_data.get("spec", {})
            if k8s_data.get("kind") == "Deployment":
                spec = spec.get("template", {}).get("spec", {})

            containers = spec.get("containers", [])
            for container in containers:
                security_context = container.get("securityContext", {})
                if security_context.get("privileged", False):
                    finding = self._create_finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=f"{rule.description} in container '{container.get('name', 'unknown')}'",
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="MISCONFIG",
                        remediation="Remove privileged: true and use specific capabilities",
                    )
                    findings.append(finding)

        return findings

    def _check_k8s_host_namespaces(
        self, file_path: Path, k8s_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for host namespace usage in Kubernetes."""
        findings = []

        if k8s_data.get("kind") == "Pod" or k8s_data.get("kind") == "Deployment":
            spec = k8s_data.get("spec", {})
            if k8s_data.get("kind") == "Deployment":
                spec = spec.get("template", {}).get("spec", {})

            dangerous_settings = [
                ("hostNetwork", "host network"),
                ("hostPID", "host PID namespace"),
                ("hostIPC", "host IPC namespace"),
            ]

            for setting, description in dangerous_settings:
                if spec.get(setting, False):
                    finding = self._create_finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=f"{rule.description}: uses {description}",
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="MISCONFIG",
                        remediation=f"Remove {setting}: true",
                    )
                    findings.append(finding)

        return findings

    def _check_k8s_security_context(
        self, file_path: Path, k8s_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for missing security context in Kubernetes."""
        findings = []

        if k8s_data.get("kind") == "Pod" or k8s_data.get("kind") == "Deployment":
            spec = k8s_data.get("spec", {})
            if k8s_data.get("kind") == "Deployment":
                spec = spec.get("template", {}).get("spec", {})

            # Check pod-level security context
            pod_security_context = spec.get("securityContext", {})

            containers = spec.get("containers", [])
            for container in containers:
                container_security_context = container.get("securityContext", {})

                # Check for missing important security settings
                if not container_security_context.get(
                    "runAsNonRoot"
                ) and not pod_security_context.get("runAsNonRoot"):
                    finding = self._create_finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=f"{rule.description}: container '{container.get('name', 'unknown')}' may run as root",
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="MISCONFIG",
                        remediation="Add runAsNonRoot: true to securityContext",
                    )
                    findings.append(finding)

        return findings

    def _check_k8s_resource_limits(
        self, file_path: Path, k8s_data: Dict, rule: ContainerSecurityRule
    ) -> List[Finding]:
        """Check for missing resource limits in Kubernetes."""
        findings = []

        if k8s_data.get("kind") == "Pod" or k8s_data.get("kind") == "Deployment":
            spec = k8s_data.get("spec", {})
            if k8s_data.get("kind") == "Deployment":
                spec = spec.get("template", {}).get("spec", {})

            containers = spec.get("containers", [])
            for container in containers:
                resources = container.get("resources", {})
                limits = resources.get("limits", {})

                missing_limits = []
                if "cpu" not in limits:
                    missing_limits.append("CPU")
                if "memory" not in limits:
                    missing_limits.append("memory")

                if missing_limits:
                    finding = self._create_finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=f"{rule.description}: container '{container.get('name', 'unknown')}' missing {', '.join(missing_limits)} limits",
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=1,
                        column_number=1,
                        finding_type="MISCONFIG",
                        remediation="Add CPU and memory limits to resources.limits",
                    )
                    findings.append(finding)

        return findings

    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this analyzer can analyze the specified file."""
        if not self.enabled:
            return False

        # Check if it's a Dockerfile
        if self._is_dockerfile(file_path):
            return True

        # Check if it's a Docker Compose file
        if self._is_docker_compose(file_path):
            return True

        # Check if it's a Kubernetes config
        return bool(self._is_kubernetes_config(file_path))

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: Path,
        line_number: Optional[int] = None,
        column_number: Optional[int] = None,
        finding_type: str = "MISCONFIG",
        remediation: Optional[str] = None,
    ) -> Finding:
        """Create a finding with the correct format."""
        import uuid

        from ..finding import FindingType, Location

        # Map finding type string to enum
        type_mapping = {
            "MISCONFIG": FindingType.MISCONFIG,
            "SECRET": FindingType.SECRET,
            "VULNERABILITY": FindingType.VULNERABILITY,
            "SUSPICIOUS": FindingType.SUSPICIOUS,
            "OTHER": FindingType.OTHER,
        }

        location = Location(
            path=file_path, line_start=line_number, column_start=column_number
        )

        return Finding(
            id=f"{rule_id}-{uuid.uuid4().hex[:8]}",
            title=title,
            description=description,
            severity=severity,
            type=type_mapping.get(finding_type, FindingType.MISCONFIG),
            location=location,
            analyzer=self.name,
            remediation=remediation,
        )
