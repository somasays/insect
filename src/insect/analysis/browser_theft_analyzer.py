"""
Browser data theft detection analyzer.

This module provides comprehensive detection capabilities for identifying code patterns
that attempt to steal browser data including:
- Browser history/cookies access
- Browser storage file reading
- Browser session hijacking
- Credential harvesting from browser password stores
- Suspicious browser extension interactions
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from ..finding import Finding, FindingType, Location, Severity
from . import BaseAnalyzer, register_analyzer

logger = logging.getLogger(__name__)


@register_analyzer
class BrowserTheftAnalyzer(BaseAnalyzer):
    """Analyzer for detecting browser data theft attempts."""

    name = "browser_theft"
    description = "Detects code patterns that attempt to steal browser data and creds"
    supported_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
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
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)

        # Configuration
        analyzer_config = config.get(self.name, {})
        self.enable_browser_history_detection = analyzer_config.get(
            "enable_browser_history_detection", True
        )
        self.enable_browser_storage_detection = analyzer_config.get(
            "enable_browser_storage_detection", True
        )
        self.enable_credential_detection = analyzer_config.get(
            "enable_credential_detection", True
        )
        self.enable_extension_detection = analyzer_config.get(
            "enable_extension_detection", True
        )

        # Initialize detection patterns
        self.browser_theft_patterns = self._init_browser_theft_patterns()

    def _init_browser_theft_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for detecting browser theft attempts."""
        patterns = []

        # Browser history and cookies theft
        if self.enable_browser_history_detection:
            patterns.extend(
                [
                    {
                        "id": "BROWSER_HISTORY_ACCESS",
                        "title": "Browser history access detected",
                        "description": "Code attempts to access browser history files or DBs",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:History|places\.sqlite|Cookies|cookies\.sqlite|Web Data|"
                            r"Favicons|Bookmarks|Login Data|Preferences|Local State|"
                            r"Current Session|Current Tabs|Last Session|Last Tabs)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1539/"],
                        "cwe_id": "CWE-200",
                    },
                    {
                        "id": "BROWSER_PROFILE_PATH",
                        "title": "Browser profile directory access",
                        "description": "Code accesses browser profile dirs with sensitive data",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:Chrome|Firefox|Safari|Edge|Opera|Brave).*?(?:User Data|Profiles?|"
                            r"Application Support|Library|AppData|\.mozilla|\.config)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1539/"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Browser storage theft (localStorage, sessionStorage, indexedDB)
        if self.enable_browser_storage_detection:
            patterns.extend(
                [
                    {
                        "id": "BROWSER_STORAGE_ACCESS",
                        "title": "Browser storage manipulation detected",
                        "description": "Code manipulates browser storage mechanisms to steal or exfiltrate data",
                        "severity": Severity.MEDIUM,
                        "pattern": re.compile(
                            r"(?:localStorage|sessionStorage|indexedDB)\.(?:getItem|setItem|clear|"
                            r"removeItem|key|length)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": [
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS"
                        ],
                        "cwe_id": "CWE-79",
                    },
                    {
                        "id": "BROWSER_CACHE_ACCESS",
                        "title": "Browser cache access detected",
                        "description": "Code attempts to access browser cache files that may contain sensitive data",
                        "severity": Severity.MEDIUM,
                        "pattern": re.compile(
                            r"(?:Cache|cache|Temp|temp)(?:/|\\\\)(?:chrome|firefox|safari|edge|opera|brave)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1005/"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Browser credential theft
        if self.enable_credential_detection:
            patterns.extend(
                [
                    {
                        "id": "BROWSER_PASSWORD_EXTRACTION",
                        "title": "Browser password extraction detected",
                        "description": "Code attempts to extract passwords from browser password managers",
                        "severity": Severity.CRITICAL,
                        "pattern": re.compile(
                            r"(?:Login Data|key4\.db|signons\.sqlite|logins\.json|"
                            r"password|credential|CryptUnprotectData|"
                            r"Windows Vault|Windows Credential Manager)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": [
                            "https://attack.mitre.org/techniques/T1555/003/"
                        ],
                        "cwe_id": "CWE-522",
                    },
                    {
                        "id": "BROWSER_FORM_DATA_THEFT",
                        "title": "Browser form data theft detected",
                        "description": "Code attempts to steal saved form data from browsers",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:autofill|form.*data|saved.*forms?|input.*values?|"
                            r"credit.*card|payment.*info|address.*data)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1555/"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Browser extension manipulation
        if self.enable_extension_detection:
            patterns.extend(
                [
                    {
                        "id": "BROWSER_EXTENSION_INJECT",
                        "title": "Browser extension injection detected",
                        "description": "Code attempts to inject or manipulate browser extensions",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:chrome\.extension|browser\.extension|webExtensions|"
                            r"Extensions(?:/|\\\\)|addon|plugin|manifest\.json)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1176/"],
                        "cwe_id": "CWE-506",
                    },
                ]
            )

        # Session hijacking patterns
        patterns.extend(
            [
                {
                    "id": "BROWSER_SESSION_HIJACK",
                    "title": "Browser session hijacking detected",
                    "description": "Code attempts to hijack or steal browser sessions",
                    "severity": Severity.CRITICAL,
                    "pattern": re.compile(
                        r"(?:document\.cookie|getCookie|setCookie|session.*token|"
                        r"JSESSIONID|PHPSESSID|ASP\.NET_SessionId|csrf.*token)",
                        re.IGNORECASE,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1539/"],
                    "cwe_id": "CWE-384",
                },
                {
                    "id": "BROWSER_XSS_PAYLOAD",
                    "title": "Cross-site scripting payload detected",
                    "description": "Code contains XSS payloads that could be used to steal browser data",
                    "severity": Severity.HIGH,
                    "pattern": re.compile(
                        r"<script[^>]*>.*(?:document\.cookie|localStorage|sessionStorage|"
                        r"window\.location|eval\(|alert\(|confirm\(|prompt\()",
                        re.IGNORECASE | re.DOTALL,
                    ),
                    "finding_type": FindingType.VULNERABILITY,
                    "references": ["https://owasp.org/www-community/attacks/xss/"],
                    "cwe_id": "CWE-79",
                },
            ]
        )

        # Data exfiltration patterns specific to browser theft
        patterns.extend(
            [
                {
                    "id": "BROWSER_DATA_EXFILTRATION",
                    "title": "Browser data exfiltration detected",
                    "description": "Code attempts to exfiltrate stolen browser data to external sources",
                    "severity": Severity.CRITICAL,
                    "pattern": re.compile(
                        r"(?:fetch|XMLHttpRequest|axios|request|urllib|requests).*"
                        r"(?:cookies?|history|passwords?|credentials?|tokens?|sessions?)",
                        re.IGNORECASE | re.DOTALL,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1041/"],
                    "cwe_id": "CWE-200",
                },
            ]
        )

        # Browser debugging and automation tools (often used maliciously)
        patterns.extend(
            [
                {
                    "id": "BROWSER_AUTOMATION_ABUSE",
                    "title": "Browser automation tool abuse detected",
                    "description": "Code uses browser automation tools in suspicious ways that could steal data",
                    "severity": Severity.MEDIUM,
                    "pattern": re.compile(
                        r"(?:selenium|puppeteer|playwright|webdriver|chromedriver|"
                        r"geckodriver|headless.*chrome|phantomjs).*"
                        r"(?:cookies?|localStorage|sessionStorage|passwords?)",
                        re.IGNORECASE | re.DOTALL,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1185/"],
                    "cwe_id": "CWE-200",
                },
            ]
        )

        return patterns

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for browser theft patterns."""
        findings: List[Finding] = []

        try:
            # Read file content
            content = self._read_file_safely(file_path)
            if not content:
                return findings

            logger.debug(f"Analyzing {file_path} for browser theft patterns")

            # Apply each pattern
            for pattern_info in self.browser_theft_patterns:
                matches = pattern_info["pattern"].finditer(content)

                for match in matches:
                    # Calculate line and column number
                    line_number = content[: match.start()].count("\n") + 1
                    column_number = match.start() - content.rfind(
                        "\n", 0, match.start()
                    )

                    # Extract the matched text for context
                    matched_text = match.group(0)

                    # Get surrounding context (50 characters before and after)
                    start_context = max(0, match.start() - 50)
                    end_context = min(len(content), match.end() + 50)
                    context = content[start_context:end_context].replace("\n", " ")

                    finding = Finding(
                        id=pattern_info["id"],
                        analyzer=self.name,
                        severity=pattern_info["severity"],
                        title=pattern_info["title"],
                        description=f"{pattern_info['description']}\n\n"
                        f"Matched pattern: {matched_text}\n"
                        f"Context: ...{context}...",
                        location=Location(
                            path=file_path,
                            line_start=line_number,
                            column_start=column_number,
                        ),
                        type=pattern_info["finding_type"],
                        metadata={
                            "matched_text": matched_text,
                            "pattern_id": pattern_info["id"],
                            "context": context,
                            "cwe_id": pattern_info.get("cwe_id"),
                        },
                        references=pattern_info.get("references", []),
                        remediation=self._get_remediation(pattern_info["id"]),
                        confidence=0.8,  # High confidence for pattern matches
                        tags=["browser", "theft", "privacy", "security"],
                    )

                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")

        return findings

    def _read_file_safely(self, file_path: Path) -> str:
        """Safely read file content with multiple encoding attempts."""
        encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

        for encoding in encodings:
            try:
                content = file_path.read_text(encoding=encoding, errors="ignore")

                # Skip very large files (> 5MB)
                if len(content) > 5 * 1024 * 1024:
                    logger.debug(f"Skipping large file {file_path}")
                    return ""

                return content
            except Exception as e:
                logger.debug(f"Failed to read {file_path} with {encoding}: {e}")
                continue

        return ""

    def _get_remediation(self, pattern_id: str) -> str:
        """Get remediation advice for specific pattern types."""
        remediation_map = {
            "BROWSER_HISTORY_ACCESS": "Remove code that accesses browser history files. If legitimate access is needed, implement proper user consent and security measures.",
            "BROWSER_PROFILE_PATH": "Avoid accessing browser profile directories. Use official browser APIs if interaction with browser data is required.",
            "BROWSER_STORAGE_ACCESS": "Ensure browser storage manipulation is for legitimate purposes only. Validate and sanitize all data before storage.",
            "BROWSER_CACHE_ACCESS": "Remove code that accesses browser cache files unless absolutely necessary and with user consent.",
            "BROWSER_PASSWORD_EXTRACTION": "Remove all code that attempts to extract browser passwords. This is a serious security violation.",
            "BROWSER_FORM_DATA_THEFT": "Remove code that steals browser form data. Implement proper data collection with user consent.",
            "BROWSER_EXTENSION_INJECT": "Remove code that manipulates browser extensions without user consent. Follow browser extension security guidelines.",
            "BROWSER_SESSION_HIJACK": "Remove session hijacking code. Implement proper session management and CSRF protection.",
            "BROWSER_XSS_PAYLOAD": "Remove XSS payloads. Sanitize all user input and use Content Security Policy (CSP).",
            "BROWSER_DATA_EXFILTRATION": "Remove data exfiltration code. Implement proper data handling with user consent and security measures.",
            "BROWSER_AUTOMATION_ABUSE": "Ensure browser automation tools are used ethically and with proper user consent.",
        }

        return remediation_map.get(
            pattern_id,
            "Review this code for potential security issues and ensure it follows security best practices.",
        )
