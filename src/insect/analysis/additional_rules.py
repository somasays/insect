"""
Additional detection rules for static code analyzers.

This module contains additional detection rules for various languages
to enhance Insect's malicious code detection capabilities.
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


# Additional Python detection rules
ADDITIONAL_PYTHON_RULES: List[StaticDetectionRule] = [
    # Command injection vulnerability
    StaticDetectionRule(
        rule_id="PY201",
        language="python",
        title="Command injection vulnerability",
        description="The code contains patterns that could lead to command injection vulnerabilities.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run|"
            r"subprocess\.check_output|subprocess\.check_call)\s*\("
            r".*?(format|join|concat|\+\s*.*?\+|\{.*?\}|f['\"].*?\{.*?\}.*?['\"])"
        ),
        remediation="Use safe APIs like subprocess with argument lists and avoid shell=True.",
        references=[
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/77.html",
        ],
        cwe_id="CWE-77",
        cvss_score=9.5,
    ),
    # Container escape attempt
    StaticDetectionRule(
        rule_id="PY202",
        language="python",
        title="Container escape attempt",
        description="The code contains patterns that might attempt to escape from container environments.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(mount|umount|pivot_root|chroot|unshare|nsenter|setns|cgroups|"
            r"/proc/self/exe|/proc/self/fd|/proc/\d+/ns|/var/run/docker.sock|"
            r"docker\.sock|\.dockerenv|kubelet|kubectl|kubernetes)"
        ),
        remediation="Investigate code accessing container runtime or orchestration systems.",
        references=[
            "https://attack.mitre.org/techniques/T1611/",
            "https://cwe.mitre.org/data/definitions/1008.html",
        ],
        cwe_id="CWE-1008",
        cvss_score=9.0,
    ),
    # SQL injection vulnerability
    StaticDetectionRule(
        rule_id="PY203",
        language="python",
        title="SQL injection vulnerability",
        description="The code contains patterns that could lead to SQL injection vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(execute|executemany|fetchone|fetchall|fetchmany|cursor\.execute|"
            r"connection\.execute|session\.execute)\s*\("
            r".*?(format|join|concat|\+\s*.*?\+|\{.*?\}|f['\"].*?\{.*?\}.*?['\"].*?SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)"
        ),
        remediation="Use parameterized queries or ORM instead of string concatenation.",
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        cwe_id="CWE-89",
        cvss_score=8.5,
    ),
    # Template injection vulnerability
    StaticDetectionRule(
        rule_id="PY204",
        language="python",
        title="Template injection vulnerability",
        description="The code contains patterns that could lead to template injection vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(render_template|render_template_string|Template|Environment|jinja2|"
            r"mako|chameleon|django\.template)\s*\("
            r".*?(format|join|concat|\+\s*.*?\+|\{.*?\}|f['\"].*?\{.*?\}.*?['\"])"
        ),
        remediation="Use safe template APIs and avoid passing user input directly to templates.",
        references=[
            "https://portswigger.net/research/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        cwe_id="CWE-94",
        cvss_score=8.0,
    ),
    # Deserialization vulnerability
    StaticDetectionRule(
        rule_id="PY205",
        language="python",
        title="Insecure deserialization",
        description="The code uses insecure deserialization which could lead to remote code execution.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(pickle\.loads|pickle\.load|cPickle\.loads|cPickle\.load|"
            r"yaml\.load|yaml\.unsafe_load|marshal\.loads|marshal\.load|jsonpickle\.decode)\s*\("
        ),
        remediation="Use safer alternatives like json.loads() or yaml.safe_load().",
        references=[
            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
        cwe_id="CWE-502",
        cvss_score=8.5,
    ),
    # Supply Chain Attack indicators
    StaticDetectionRule(
        rule_id="PY206",
        language="python",
        title="Potential supply chain attack indicators",
        description="The code contains patterns that are common in supply chain attacks.",
        severity=Severity.CRITICAL,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"(__import__\(['\"]urllib['\"].*?urlopen|"
            r"__import__\(['\"]requests['\"].*?\.get|"
            r"getattr.*?__import__|"
            r"exec\s*\(\s*__import__\(['\"]base64['\"].*?\.b64decode|"
            r"_module.*?=.*?__import__|"
            r"globals\(\)\[.*?\]|"
            r"setup\.py.*?cmdclass|"
            r"pip\._internal|"
            r"pkg_resources.*?\._vendor)"
        ),
        remediation="Investigate code accessing package management systems.",
        references=[
            "https://attack.mitre.org/techniques/T1195/",
            "https://cwe.mitre.org/data/definitions/1104.html",
        ],
        cwe_id="CWE-1104",
        cvss_score=9.6,
    ),
    # Sensitive information exposure
    StaticDetectionRule(
        rule_id="PY207",
        language="python",
        title="Sensitive information exposure",
        description="The code contains potentially sensitive information such as credentials or keys.",
        severity=Severity.HIGH,
        finding_type=FindingType.SECRET,
        regex_pattern=re.compile(
            r"(password|passwd|token|api_?key|secret|auth_token|credential|jwt|"
            r"access_token|refresh_token|client_secret)\s*=\s*['\"][\w\-\._=]{8,}['\"]"
        ),
        remediation="Store sensitive information in environment variables or secure vaults.",
        references=[
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        cwe_id="CWE-200",
        cvss_score=7.5,
    ),
]

# Additional JavaScript detection rules
ADDITIONAL_JAVASCRIPT_RULES: List[StaticDetectionRule] = [
    # DOM-based XSS through client-side routing
    StaticDetectionRule(
        rule_id="JS201",
        language="javascript",
        title="DOM-based XSS through client-side routing",
        description="The code contains patterns that could lead to DOM-based XSS in client-side routing.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(location\.hash|location\.search|location\.href|window\.location)\s*\.\s*"
            r"(split|substr|substring|match|replace|includes|indexOf|dangerouslySetInnerHTML)"
        ),
        remediation="Use proper output encoding/escaping with client-side routing.",
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
        cwe_id="CWE-79",
        cvss_score=8.0,
    ),
    # Prototype pollution vulnerability
    StaticDetectionRule(
        rule_id="JS202",
        language="javascript",
        title="Prototype pollution vulnerability",
        description="The code contains patterns that could lead to prototype pollution vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(Object\.assign|Object\.create|Object\.defineProperty|__proto__|prototype|constructor)\s*\(\s*"
            r"(.*?user.*?|.*?input.*?|.*?param.*?|.*?data.*?|.*?req.*?|.*?body.*?)"
        ),
        remediation="Use Object.create(null) and avoid recursive merging of untrusted data.",
        references=[
            "https://github.com/OWASP/API-Security/blob/master/editions/2023/en/0xa8-security-misconfiguration.md",
            "https://cwe.mitre.org/data/definitions/1321.html",
        ],
        cwe_id="CWE-1321",
        cvss_score=7.5,
    ),
    # Insecure dependency loading
    StaticDetectionRule(
        rule_id="JS203",
        language="javascript",
        title="Insecure dependency loading",
        description="The code loads dependencies in an insecure manner that could lead to attacks.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(require|import)\s*\(\s*(.*?variable.*?|.*?concat.*?|.*?\+.*?|"
            r".*?process\.env.*?|.*?window\..*?|.*?location\..*?|.*?document\..*?)"
        ),
        remediation="Use fixed import paths and avoid dynamic imports with user input.",
        references=[
            "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
            "https://cwe.mitre.org/data/definitions/829.html",
        ],
        cwe_id="CWE-829",
        cvss_score=7.0,
    ),
    # Server-side request forgery (SSRF)
    StaticDetectionRule(
        rule_id="JS204",
        language="javascript",
        title="Server-side request forgery (SSRF) vulnerability",
        description="The code contains patterns that could lead to SSRF vulnerabilities.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(fetch|axios|http\.get|https\.get|request)\s*\(\s*"
            r"(.*?user.*?|.*?input.*?|.*?param.*?|.*?data.*?|.*?req.*?|.*?body.*?)"
        ),
        remediation="Implement URL validation and use allowlists for external resources.",
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
        cwe_id="CWE-918",
        cvss_score=8.0,
    ),
    # Insecure JWT validation
    StaticDetectionRule(
        rule_id="JS205",
        language="javascript",
        title="Insecure JWT validation",
        description="The code contains patterns that could lead to insecure JWT validation.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(jwt\.verify|jwt\.decode|verify.*?jwt|decode.*?jwt)\s*\(\s*"
            r"(.*?algorithm.*?none.*?|.*?noVerify.*?|.*?ignoreExpiration.*?true.*?)"
        ),
        remediation="Always verify JWT signatures and check expiration times.",
        references=[
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
        cwe_id="CWE-347",
        cvss_score=8.0,
    ),
    # Client-side storage of sensitive data
    StaticDetectionRule(
        rule_id="JS206",
        language="javascript",
        title="Client-side storage of sensitive data",
        description="The code stores sensitive data in client-side storage which could be insecure.",
        severity=Severity.MEDIUM,
        finding_type=FindingType.VULNERABILITY,
        regex_pattern=re.compile(
            r"(localStorage|sessionStorage|document\.cookie)\s*\.\s*(setItem|set)\s*\(\s*"
            r".*?(password|token|secret|key|auth|credentials|jwt)"
        ),
        remediation="Avoid storing sensitive data in client-side storage.",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
        cwe_id="CWE-312",
        cvss_score=6.0,
    ),
]

# Additional Shell detection rules from the ShellDetectionRule class in analyzer.py
# Note: These need to be converted to StaticDetectionRule format when used
ADDITIONAL_SHELL_PATTERNS = [
    # Suspicious file download and execution
    (
        "SH201",
        "Suspicious file download and execution",
        "The script downloads and immediately executes files which could be malicious.",
        Severity.CRITICAL,
        FindingType.SUSPICIOUS,
        re.compile(
            r"(curl|wget|fetch)\s+.*?(https?:\/\/|ftp:\/\/).*?\s+-O\s+.*?\.sh\s*(\&\&|\|\|)\s*(bash|sh|chmod|source)"
        ),
        "Inspect downloaded content before execution and use trusted sources only.",
        ["https://attack.mitre.org/techniques/T1059/004/"],
        "CWE-494",
        9.0,
    ),
    # Supply chain attack
    (
        "SH202",
        "Potential supply chain attack",
        "The script contains patterns that could be used in a supply chain attack.",
        Severity.CRITICAL,
        FindingType.SUSPICIOUS,
        re.compile(
            r"(apt-get|yum|dnf|npm|pip|gem|go)\s+install\s+.*?(\`|\$\(|<\()|"
            r"(npm|pip|gem|go)\s+.*?--registry\s+.*?"
        ),
        "Avoid dynamically determined package sources and use trusted repositories.",
        [
            "https://attack.mitre.org/techniques/T1195/",
            "https://cwe.mitre.org/data/definitions/1104.html",
        ],
        "CWE-1104",
        9.0,
    ),
    # Tampering with security tools
    (
        "SH203",
        "Security tool tampering",
        "The script attempts to disable, tamper with, or uninstall security tools.",
        Severity.CRITICAL,
        FindingType.SUSPICIOUS,
        re.compile(
            r"(systemctl|service|chkconfig)\s+(stop|disable)\s+(auditd|firewalld|iptables|selinux|apparmor|fail2ban)|"
            r"(setenforce|getenforce)\s+0|"
            r"apt-get\s+.*?remove\s+.*?(clamav|snort|aide|tripwire)|"
            r"iptables\s+-F"
        ),
        "Investigate security tool disabling attempts.",
        ["https://attack.mitre.org/techniques/T1562/001/"],
        "CWE-693",
        9.5,
    ),
    # Suspicious curl/wget options
    (
        "SH204",
        "Suspicious download options",
        "The script uses curl/wget with suspicious options that could hide malicious activity.",
        Severity.HIGH,
        FindingType.SUSPICIOUS,
        re.compile(
            r"(curl|wget)\s+.*?(--insecure|-k|--no-check-certificate|--user-agent|--connect-timeout\s+1)"
        ),
        "Avoid disabling SSL verification and using short timeouts.",
        ["https://attack.mitre.org/techniques/T1071/001/"],
        "CWE-295",
        6.5,
    ),
    # Kernel module operations
    (
        "SH205",
        "Kernel module operations",
        "The script loads or manipulates kernel modules which could indicate rootkit installation.",
        Severity.CRITICAL,
        FindingType.SUSPICIOUS,
        re.compile(
            r"(insmod|modprobe|rmmod)\s+.*?\.(ko|o)|"
            r"echo\s+.*?\s*>\s*\/proc\/sys\/|"
            r"(sysctl\s+-w|\/etc\/sysctl\.conf)"
        ),
        "Verify the legitimate need for kernel module operations.",
        ["https://attack.mitre.org/techniques/T1014/"],
        "CWE-94",
        9.0,
    ),
]
