"""
AST visitor for Python code analysis.
"""

import ast
import uuid
from pathlib import Path
from typing import List, Set

from insect.finding import Finding, FindingType, Location, Severity


class ASTVisitor(ast.NodeVisitor):
    """AST visitor that detects potentially malicious patterns in Python code."""

    def __init__(self, file_path: Path):
        """Initialize the AST visitor.

        Args:
            file_path: Path to the file being analyzed
        """
        self.file_path = file_path
        self.findings: List[Finding] = []
        self.source_lines: List[str] = []
        self.imports: Set[str] = set()
        self.suspicious_calls: List[str] = []
        self.encoded_strings: List[str] = []

    def load_source(self, source: str) -> None:
        """Load the source code for snippet extraction.

        Args:
            source: The source code of the file being analyzed
        """
        self.source_lines = source.splitlines()

    def get_snippet(self, node: ast.AST) -> str:
        """Extract the code snippet for a node.

        Args:
            node: The AST node

        Returns:
            A string containing the code snippet
        """
        if not hasattr(node, "lineno") or not self.source_lines:
            return ""

        # Get start and end line numbers
        start_line = getattr(node, "lineno", 0) - 1  # Convert to 0-based
        end_line = (
            getattr(node, "end_lineno", start_line) - 1
            if hasattr(node, "end_lineno")
            else start_line
        )

        # Ensure we don't go out of bounds
        start_line = max(0, min(start_line, len(self.source_lines) - 1))
        end_line = max(0, min(end_line, len(self.source_lines) - 1))

        # Extract the snippet
        return "\n".join(self.source_lines[start_line : end_line + 1])

    def visit_import(self, node: ast.Import) -> None:
        """Visit import statements to track suspicious modules.

        Args:
            node: The AST Import node
        """
        suspicious_modules = {
            "socket",
            "subprocess",
            "ctypes",
            "paramiko",
            "telnetlib",
            "ftplib",
            "urllib.request",
            "win32api",
            "winreg",
        }

        for name in node.names:
            self.imports.add(name.name)
            if name.name in suspicious_modules:
                end_col_offset = (
                    getattr(node, "end_col_offset", node.col_offset + 1)
                    if hasattr(node, "end_col_offset")
                    else node.col_offset + 1
                )
                self.findings.append(
                    Finding(
                        id=f"PY102-{uuid.uuid4().hex[:8]}",
                        title=f"Suspicious import of {name.name}",
                        description=f"The code imports {name.name}, which is commonly used in malicious scripts.",
                        severity=Severity.MEDIUM,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=self.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            column_start=node.col_offset,
                            column_end=end_col_offset,
                            snippet=self.get_snippet(node),
                        ),
                        analyzer="python_static_analyzer",
                        confidence=0.6,  # Lower confidence as legitimate code may use these modules
                        references=["https://attack.mitre.org/techniques/T1059/006/"],
                        tags=["suspicious-import", "python"],
                        remediation="Verify the legitimacy of this import in your application context.",
                        cwe_id="CWE-912",
                    )
                )

        self.generic_visit(node)

    def visit_call(self, node: ast.Call) -> None:
        """Visit function or method call nodes looking for suspicious patterns.

        Args:
            node: The AST call node
        """
        # Check for obfuscated code execution
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            end_col_offset = (
                getattr(node, "end_col_offset", node.col_offset + 1)
                if hasattr(node, "end_col_offset")
                else node.col_offset + 1
            )
            self.findings.append(
                Finding(
                    id=f"PY101-{uuid.uuid4().hex[:8]}",
                    title="Potentially malicious code execution",
                    description="The use of eval() or exec() could be executing malicious code.",
                    severity=Severity.CRITICAL,
                    type=FindingType.SUSPICIOUS,
                    location=Location(
                        path=self.file_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        column_start=node.col_offset,
                        column_end=end_col_offset,
                        snippet=self.get_snippet(node),
                    ),
                    analyzer="python_static_analyzer",
                    confidence=0.8,
                    references=["https://attack.mitre.org/techniques/T1059/006/"],
                    tags=["code-execution", "python"],
                    remediation="Inspect what is being executed. Replace with safer alternatives.",
                    cwe_id="CWE-95",
                    cvss_score=9.0,
                )
            )

        # Check for calls to functions that could be used for code execution
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "builtins"
            and node.func.attr in ("eval", "exec")
        ):
            end_col_offset = (
                getattr(node, "end_col_offset", node.col_offset + 1)
                if hasattr(node, "end_col_offset")
                else node.col_offset + 1
            )
            self.findings.append(
                Finding(
                    id=f"PY101-{uuid.uuid4().hex[:8]}",
                    title="Obfuscated code execution",
                    description="Indirect execution via builtins module could be executing malicious code.",
                    severity=Severity.CRITICAL,
                    type=FindingType.SUSPICIOUS,
                    location=Location(
                        path=self.file_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        column_start=node.col_offset,
                        column_end=end_col_offset,
                        snippet=self.get_snippet(node),
                    ),
                    analyzer="python_static_analyzer",
                    confidence=0.9,
                    references=["https://attack.mitre.org/techniques/T1059/006/"],
                    tags=["code-execution", "obfuscated", "python"],
                    remediation="Inspect what is being executed. Replace with safer alternatives.",
                    cwe_id="CWE-95",
                    cvss_score=9.5,
                )
            )

        # Check for urlopen calls (network connections)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and hasattr(node.func.value, "value")
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "urllib"
            and node.func.value.attr == "request"
            and node.func.attr == "urlopen"
        ):
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and "http" in arg.value.lower()
                ):
                    end_col_offset = (
                        getattr(node, "end_col_offset", node.col_offset + 1)
                        if hasattr(node, "end_col_offset")
                        else node.col_offset + 1
                    )
                    self.findings.append(
                        Finding(
                            id=f"PY104-{uuid.uuid4().hex[:8]}",
                            title="Suspicious network connection",
                            description=f"The code initiates a connection to {arg.value}, which could be malicious.",
                            severity=Severity.HIGH,
                            type=FindingType.SUSPICIOUS,
                            location=Location(
                                path=self.file_path,
                                line_start=node.lineno,
                                line_end=getattr(node, "end_lineno", node.lineno),
                                column_start=node.col_offset,
                                column_end=end_col_offset,
                                snippet=self.get_snippet(node),
                            ),
                            analyzer="python_static_analyzer",
                            confidence=0.7,
                            references=["https://attack.mitre.org/techniques/T1071/"],
                            tags=["network", "url", "python"],
                            remediation="Verify this connection is to a legitimate service.",
                            cwe_id="CWE-913",
                            cvss_score=7.0,
                        )
                    )

        # Check for reverse shell patterns
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            # Check for socket connections (potential reverse shells)
            if node.func.value.id == "socket" and node.func.attr in ["connect"]:
                end_col_offset = (
                    getattr(node, "end_col_offset", node.col_offset + 1)
                    if hasattr(node, "end_col_offset")
                    else node.col_offset + 1
                )
                self.findings.append(
                    Finding(
                        id=f"PY105-{uuid.uuid4().hex[:8]}",
                        title="Potential network backdoor",
                        description=(
                            "Code establishes a socket connection that could be "
                            "part of a backdoor."
                        ),
                        severity=Severity.HIGH,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=self.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            column_start=node.col_offset,
                            column_end=end_col_offset,
                            snippet=self.get_snippet(node),
                        ),
                        analyzer="python_static_analyzer",
                        confidence=0.7,
                        references=["https://attack.mitre.org/techniques/T1571/"],
                        tags=["backdoor", "network", "python"],
                        remediation="Investigate this network connection for legitimacy.",
                        cwe_id="CWE-912",
                        cvss_score=8.0,
                    )
                )

            # Check for process manipulation
            if node.func.value.id == "subprocess" and node.func.attr in [
                "call",
                "run",
                "Popen",
            ]:
                # Check for shell commands
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        suspicious_cmds = [
                            "nc ",
                            "netcat",
                            "wget ",
                            "curl ",
                            "chmod ",
                            "base64 ",
                        ]
                        if any(cmd in arg.value.lower() for cmd in suspicious_cmds):
                            end_col_offset = (
                                getattr(node, "end_col_offset", node.col_offset + 1)
                                if hasattr(node, "end_col_offset")
                                else node.col_offset + 1
                            )
                            self.findings.append(
                                Finding(
                                    id=f"PY107-{uuid.uuid4().hex[:8]}",
                                    title="Suspicious shell command",
                                    description=(
                                        f"Code executes a shell command that could be malicious: "
                                        f"{arg.value}"
                                    ),
                                    severity=Severity.HIGH,
                                    type=FindingType.SUSPICIOUS,
                                    location=Location(
                                        path=self.file_path,
                                        line_start=node.lineno,
                                        line_end=getattr(
                                            node, "end_lineno", node.lineno
                                        ),
                                        column_start=node.col_offset,
                                        column_end=end_col_offset,
                                        snippet=self.get_snippet(node),
                                    ),
                                    analyzer="python_static_analyzer",
                                    confidence=0.8,
                                    references=[
                                        "https://attack.mitre.org/techniques/T1059/004/"
                                    ],
                                    tags=["command-execution", "suspicious", "python"],
                                    remediation="Investigate this command execution for legitimacy.",
                                    cwe_id="CWE-78",
                                    cvss_score=8.5,
                                )
                            )

        # Check for compile + eval pattern (common obfuscation technique)
        if isinstance(node.func, ast.Name) and node.func.id == "compile":
            # This is a potential code obfuscation technique
            end_col_offset = (
                getattr(node, "end_col_offset", node.col_offset + 1)
                if hasattr(node, "end_col_offset")
                else node.col_offset + 1
            )
            self.findings.append(
                Finding(
                    id=f"PY101-{uuid.uuid4().hex[:8]}",
                    title="Obfuscated code execution",
                    description="Use of compile() could be part of obfuscated code execution.",
                    severity=Severity.HIGH,
                    type=FindingType.SUSPICIOUS,
                    location=Location(
                        path=self.file_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        column_start=node.col_offset,
                        column_end=end_col_offset,
                        snippet=self.get_snippet(node),
                    ),
                    analyzer="python_static_analyzer",
                    confidence=0.7,
                    references=["https://attack.mitre.org/techniques/T1059/006/"],
                    tags=["code-execution", "obfuscated", "python"],
                    remediation="Inspect what is being compiled and executed. Replace with safer alternatives.",
                    cwe_id="CWE-95",
                    cvss_score=8.0,
                )
            )

        # Visit children
        self.generic_visit(node)

    def visit_constant(self, node: ast.Constant) -> None:
        """Visit string constants looking for encoded payloads.

        Args:
            node: The AST Constant node
        """
        if isinstance(node.value, str):
            # Check for base64-like strings
            import re

            if len(node.value) > 20 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", node.value):
                end_col_offset = (
                    getattr(node, "end_col_offset", node.col_offset + 1)
                    if hasattr(node, "end_col_offset")
                    else node.col_offset + 1
                )
                self.findings.append(
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
                            path=self.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            column_start=node.col_offset,
                            column_end=end_col_offset,
                            snippet=self.get_snippet(node),
                        ),
                        analyzer="python_static_analyzer",
                        confidence=0.6,  # Lower confidence as false positives are common
                        references=["https://attack.mitre.org/techniques/T1027/"],
                        tags=["obfuscation", "encoded", "python"],
                        remediation="Decode and inspect this string for malicious content.",
                        cwe_id="CWE-506",
                        cvss_score=5.0,
                    )
                )

            # Check for hex-encoded strings - lower threshold to catch more potential matches
            if len(node.value) > 10 and all(
                c in "0123456789abcdefABCDEF" for c in node.value
            ):
                end_col_offset = (
                    getattr(node, "end_col_offset", node.col_offset + 1)
                    if hasattr(node, "end_col_offset")
                    else node.col_offset + 1
                )
                self.findings.append(
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
                            path=self.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            column_start=node.col_offset,
                            column_end=end_col_offset,
                            snippet=self.get_snippet(node),
                        ),
                        analyzer="python_static_analyzer",
                        confidence=0.5,  # Even lower confidence
                        references=["https://attack.mitre.org/techniques/T1027/"],
                        tags=["obfuscation", "encoded", "python"],
                        remediation="Decode and inspect this string for malicious content.",
                        cwe_id="CWE-506",
                        cvss_score=5.0,
                    )
                )

        self.generic_visit(node)
