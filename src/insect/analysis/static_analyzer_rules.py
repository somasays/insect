"""
Detection rules for static code analyzers.

This module contains the primary detection rules used by static analyzers to
identify potentially malicious code patterns and security vulnerabilities.
"""

import re
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional, Pattern

from insect.finding import FindingType, Severity


@dataclass
class StaticDetectionRule:
    """Generic rule definition for static code analysis."""

    rule_id: str
    language: Literal["python", "javascript", "shell", "config", "binary", "metadata"]
    title: str
    description: str
    severity: Severity
    finding_type: FindingType
    regex_pattern: Optional[Pattern] = None
    node_types: Optional[List[Any]] = None  # AST node types (language-specific)
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


# Define detection rules for especially suspicious/malicious Python code
PYTHON_RULES: List[StaticDetectionRule] = [
    # Obfuscated code execution
    StaticDetectionRule(
        rule_id="PY101",
        language="python",
        title="Obfuscated code execution",
        description="The code contains obfuscated execution techniques that may hide malicious behavior.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:eval|exec)\s*\(\s*(?:base64|codecs|binascii|unhexlify|"
            r"__import__\(['\"]base64['\"]|compile|getattr|chr\(|'\\x|\"\\x|\\\\u)",
            re.IGNORECASE,
        ),
        remediation="Inspect the obfuscated code to determine its purpose. Remove if suspicious.",
        references=["https://attack.mitre.org/techniques/T1027/"],
        cwe_id="CWE-506",
        cvss_score=9.0,
    ),
    # Suspicious imports that might indicate malicious activity
    StaticDetectionRule(
        rule_id="PY102",
        language="python",
        title="Suspicious module imports",
        description="The code imports modules commonly used in malware or attack tools.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:import|from)\s+(?:socket|subprocess|ctypes|os|sys|pty|paramiko|"
            r"pexpect|telnetlib|ftplib|urllib\.request)\s+(?:import|\*)",
            re.IGNORECASE,
        ),
        remediation="Verify the legitimacy of these imports in your application context.",
        references=["https://attack.mitre.org/techniques/T1059/006/"],
        cwe_id="CWE-912",
        cvss_score=6.0,
    ),
    # Base64/hex encoded strings (potential obfuscation)
    StaticDetectionRule(
        rule_id="PY103",
        language="python",
        title="Encoded string literals",
        description="The code contains base64 or hex-encoded strings that could hide malicious payloads.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"['\"](?:[A-Za-z0-9+/]{30,}={0,2}|(?:\\x[0-9a-fA-F]{2}){8,}|[0-9a-fA-F]{30,})['\"]",
            re.IGNORECASE,
        ),
        remediation="Decode and inspect these strings to determine their purpose.",
        references=["https://attack.mitre.org/techniques/T1027/"],
        cwe_id="CWE-506",
        cvss_score=5.5,
    ),
    # Network connections to suspicious domains/IPs
    StaticDetectionRule(
        rule_id="PY104",
        language="python",
        title="Suspicious network connections",
        description=(
            "The code initiates connections to potentially malicious "
            "or unusual domains/IPs."
        ),
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:connect|get|post|request|urlopen)\s*\(\s*['\"]"
            r"(?:https?://(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"[^/.'\"][^/.'\"]*))['\"]",
            re.IGNORECASE,
        ),
        remediation="Verify all remote connections are to legitimate services.",
        references=["https://attack.mitre.org/techniques/T1071/"],
        cwe_id="CWE-913",
        cvss_score=7.0,
    ),
    # Backdoor indicators
    StaticDetectionRule(
        rule_id="PY105",
        language="python",
        title="Potential backdoor code",
        description="The code contains patterns indicating a backdoor, shell, or remote access capability.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:bind|listen|accept|shell|spawn|pty\.spawn|os\.dup2|"
            r"reverse_shell|backdoor|bind_shell|connect_back)\b"
        ),
        remediation="Investigate this code as it may provide unauthorized access.",
        references=["https://attack.mitre.org/techniques/T1505/003/"],
        cwe_id="CWE-912",
        cvss_score=9.5,
    ),
    # System modification indicators
    StaticDetectionRule(
        rule_id="PY106",
        language="python",
        title="System modification attempts",
        description="The code attempts to modify system files or settings.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:os\.chmod|os\.chown|shutil\.chown|os\.setuid|os\.setgid|"
            r"etc/passwd|etc/shadow|/etc/cron|/etc/init|systemd|passwd|shadow)\b"
        ),
        remediation="Verify the legitimacy of system modifications.",
        references=["https://attack.mitre.org/techniques/T1222/"],
        cwe_id="CWE-276",
        cvss_score=8.0,
    ),
    # Process/memory manipulation
    StaticDetectionRule(
        rule_id="PY107",
        language="python",
        title="Process or memory manipulation",
        description="The code manipulates other processes or memory, which could indicate malicious behavior.",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:ctypes\.windll|ctypes\.cdll|win32api|WriteProcessMemory|"
            r"VirtualAlloc|ptraceProcess|memoryview|mmap)\b",
            re.IGNORECASE,
        ),
        remediation="Investigate process/memory manipulation for legitimate usage.",
        references=["https://attack.mitre.org/techniques/T1055/"],
        cwe_id="CWE-912",
        cvss_score=8.0,
    ),
]

# Define detection rules for especially suspicious/malicious JavaScript code
JAVASCRIPT_RULES: List[StaticDetectionRule] = [
    # Unsafe code execution (eval, Function constructor)
    StaticDetectionRule(
        rule_id="JS101",
        language="javascript",
        title="Unsafe code execution",
        description="The code uses potentially unsafe functions like eval() or the Function constructor.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(r"\b(eval|Function\s*\()\b", re.IGNORECASE),
        remediation="Avoid using eval() and Function() constructor. Refactor to use safer alternatives.",
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!"
        ],
        cwe_id="CWE-95",  # Code Injection
        cvss_score=9.0,
    ),
    # Dangerous DOM manipulation (innerHTML, outerHTML, document.write)
    StaticDetectionRule(
        rule_id="JS102",
        language="javascript",
        title="Dangerous DOM manipulation",
        description="The code uses insecure methods like innerHTML, outerHTML, or document.write, which can lead to XSS.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(r"\.(innerHTML|outerHTML|write)\s*=", re.IGNORECASE),
        remediation="Use safer alternatives like textContent or DOM manipulation methods (createElement, appendChild). Sanitize user input if dynamic content is required.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        cwe_id="CWE-79",  # Cross-site Scripting (XSS)
        cvss_score=7.5,
    ),
    # Suspicious requires/imports (child_process, fs, net, http)
    StaticDetectionRule(
        rule_id="JS103",
        language="javascript",
        title="Suspicious module usage",
        description="The code requires or imports modules commonly used for system interaction or networking (e.g., child_process, fs, net), which could be misused.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(?:require|import).*['\"]?(child_process|fs|net|http|https|os)['\"]?",
            re.IGNORECASE,
        ),
        remediation="Verify the legitimate need for these modules. Ensure proper sandboxing or input validation if used.",
        references=["https://nodejs.org/api/child_process.html"],
        cwe_id="CWE-78",  # OS Command Injection (potential risk)
        cvss_score=6.0,
    ),
    # Base64/hex encoded strings (potential obfuscation)
    StaticDetectionRule(
        rule_id="JS104",
        language="javascript",
        title="Encoded string literals",
        description="The code contains base64 or hex-encoded strings that could hide malicious payloads.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"['\"](?:[A-Za-z0-9+/=]{20,}|(?:\\x[0-9a-fA-F]{2}){8,}|[0-9a-fA-F]{20,})['\"]",
            re.IGNORECASE,
        ),
        remediation="Decode and inspect these strings to determine their purpose.",
        references=["https://attack.mitre.org/techniques/T1027/"],
        cwe_id="CWE-506",  # Embedded Malicious Code
        cvss_score=5.5,
    ),
    # Hardcoded secrets or credentials
    StaticDetectionRule(
        rule_id="JS105",
        language="javascript",
        title="Potential hardcoded secret",
        description="The code may contain hardcoded API keys, passwords, or other secrets.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        # More sophisticated regex needed for higher accuracy, this is basic
        regex_pattern=re.compile(
            r"['\"]?(password|secret|apikey|api_key|token|auth|pwd|credential)[a-zA-Z0-9_]*['\"]?\s*[:=]\s*['\"].+['\"]",
            re.IGNORECASE,
        ),
        remediation="Remove secrets from source code. Use environment variables, configuration files, or secret management solutions.",
        references=[
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
        ],
        cwe_id="CWE-798",  # Use of Hard-coded Credentials
        cvss_score=7.0,
    ),
    # Insecure regular expressions (potential ReDoS)
    StaticDetectionRule(
        rule_id="JS106",
        language="javascript",
        title="Potentially insecure regular expression",
        description="The code uses complex regular expressions that might be vulnerable to Regular Expression Denial of Service (ReDoS).",
        severity=Severity.LOW,
        finding_type=FindingType.VULNERABILITY,
        # Very basic heuristic: nested quantifiers or complex character sets
        regex_pattern=re.compile(
            r"/((?:\\.|\\([^)]*\\))|[^/])*([*+?]\\{.*\\}|[*+?]{2,}|\\(\\?.+\\).*[+*])/"
        ),
        remediation="Simplify complex regular expressions. Test them against potential ReDoS attack strings.",
        references=[
            "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
        ],
        cwe_id="CWE-1333",  # Inefficient Regular Expression Complexity
        cvss_score=4.0,
    ),
]

# Additional rules are loaded and extended in each analyzer module
