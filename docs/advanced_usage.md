---
layout: page
title: Advanced Usage
nav_order: 5
---

# Advanced Usage and Customization

This guide covers advanced usage scenarios and customization options for Insect.

## Table of Contents

- [Custom Rule Development](#custom-rule-development)
- [Browser Security Configuration](#browser-security-configuration)
- [CI/CD Integration](#cicd-integration)
- [Performance Optimization](#performance-optimization)
- [External Tool Integration](#external-tool-integration)
- [Extending Insect](#extending-insect)

## Custom Rule Development

Insect provides a flexible rule system that you can extend with your own custom detection rules.

### Creating a Python Detection Rule

Custom rules can be defined by creating a new Python file with rule definitions:

```python
# custom_rules.py
import re
from insect.finding import Finding, FindingType, Location, Severity
from insect.analysis.static_analyzer_rules import StaticDetectionRule

# Define a custom rule for detecting insecure random number generation
CUSTOM_PYTHON_RULES = [
    StaticDetectionRule(
        rule_id="CUSTOM-PY001",
        title="Insecure Random Number Generation",
        description="Using random module for cryptographic purposes is insecure.",
        severity=Severity.HIGH,
        finding_type=FindingType.VULNERABILITY,
        language="python",
        regex_pattern=re.compile(r"import\s+random|from\s+random\s+import"),
        remediation="Use cryptographically secure random number generation with the 'secrets' module instead.",
        references=["https://docs.python.org/3/library/secrets.html"],
        cwe_id="CWE-338",
        cvss_score=7.5,
    ),
]
```

### Integrating Custom Rules

To integrate your custom rules:

1. Create a Python package with your rules
2. Create a plugin entry point in your package's `setup.py`:

```python
setup(
    name="insect-custom-rules",
    # ...
    entry_points={
        "insect.plugins": [
            "custom_rules = your_package.custom_rules:register_rules",
        ],
    },
)
```

3. Implement the `register_rules` function:

```python
def register_rules():
    from insect.analysis.static_analyzer_rules import register_rules
    from .custom_rules import CUSTOM_PYTHON_RULES
    
    register_rules(CUSTOM_PYTHON_RULES)
```

## Browser Security Configuration

Insect includes comprehensive browser data theft detection capabilities that can be customized for different security requirements.

### Basic Browser Security Configuration

```toml
# browser-security.toml
[analyzers]
browser_theft = true
secrets = true
static = true

[browser_theft]
enable_browser_history_detection = true
enable_browser_storage_detection = true
enable_credential_detection = true
enable_extension_detection = true

[severity]
min_level = "medium"

[patterns]
# Focus on web-related files
include = ["*.js", "*.ts", "*.jsx", "*.tsx", "*.html", "*.php", "*.py"]
exclude = [
    "node_modules/*",
    "test/*",
    "tests/*",
    "*.min.js"
]
```

### Enterprise Browser Security Configuration

For enterprise environments requiring strict browser security controls:

```toml
# enterprise-browser-security.toml
[general]
include_hidden = true
max_depth = 15

[analyzers]
browser_theft = true
secrets = true
static = true
config = true

[browser_theft]
enable_browser_history_detection = true
enable_browser_storage_detection = true
enable_credential_detection = true
enable_extension_detection = true

[severity]
min_level = "low"  # Catch all potential issues

# Strict patterns for enterprise security
[patterns]
include = ["*"]
exclude = [
    # Only exclude obvious non-code files
    "*.git/*",
    "*.exe",
    "*.bin",
    "*.jpg",
    "*.png",
    "*.gif"
]

# Don't allow any browser theft patterns
[allowlist]
findings = []  # No exceptions for browser theft
```

### Browser Extension Security Configuration

Specialized configuration for scanning browser extensions:

```toml
# extension-security.toml
[analyzers]
browser_theft = true
secrets = true
javascript_static_analyzer = true

[browser_theft]
enable_browser_history_detection = true
enable_browser_storage_detection = true
enable_credential_detection = true
enable_extension_detection = true

[patterns]
include = [
    "*.js",
    "*.html",
    "*.json",
    "manifest.json",
    "content_scripts/*",
    "background/*",
    "popup/*"
]

[severity]
min_level = "medium"
```

### Custom Browser Security Rules

You can extend browser security detection with custom rules:

```python
# custom_browser_rules.py
import re
from insect.analysis.static_analyzer_rules import StaticDetectionRule
from insect.finding import FindingType, Severity

CUSTOM_BROWSER_RULES = [
    StaticDetectionRule(
        rule_id="CUSTOM-BROWSER-001",
        language="javascript",
        title="Suspicious WebRTC data channel usage",
        description="Code uses WebRTC data channels in ways that could bypass network monitoring",
        severity=Severity.HIGH,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"RTCDataChannel.*(?:send|onmessage).*(?:credentials?|passwords?|tokens?)",
            re.IGNORECASE
        ),
        remediation="Review WebRTC data channel usage for potential data exfiltration",
        references=["https://developer.mozilla.org/en-US/docs/Web/API/RTCDataChannel"],
        cwe_id="CWE-200",
        cvss_score=7.0,
    ),
    StaticDetectionRule(
        rule_id="CUSTOM-BROWSER-002",
        language="javascript",
        title="Suspicious clipboard API usage",
        description="Code accesses clipboard API in ways that could steal sensitive data",
        severity=Severity.MEDIUM,
        finding_type=FindingType.SUSPICIOUS,
        regex_pattern=re.compile(
            r"navigator\.clipboard\.(?:read|readText).*(?:password|secret|token|key)",
            re.IGNORECASE
        ),
        remediation="Ensure clipboard access is legitimate and user-consented",
        references=["https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API"],
        cwe_id="CWE-200",
        cvss_score=6.0,
    ),
]
```

### Browser Security Scanning Workflows

#### Automated Browser Extension Review

```bash
#!/bin/bash
# review-browser-extension.sh

EXTENSION_PATH=$1
REPORT_DIR="./security-reports"

if [ -z "$EXTENSION_PATH" ]; then
    echo "Usage: $0 <extension-path>"
    exit 1
fi

mkdir -p "$REPORT_DIR"

# Run comprehensive browser security scan
echo "Scanning browser extension at: $EXTENSION_PATH"
insect scan "$EXTENSION_PATH" \
    --config extension-security.toml \
    -f html \
    -o "$REPORT_DIR/extension-security-report.html" \
    --severity medium

# Extract critical findings
insect scan "$EXTENSION_PATH" \
    --config extension-security.toml \
    -f json \
    -o "$REPORT_DIR/extension-findings.json" \
    --severity critical

# Check for browser theft patterns
if grep -q '"analyzer": "browser_theft"' "$REPORT_DIR/extension-findings.json"; then
    echo "❌ CRITICAL: Browser data theft patterns detected!"
    echo "Review the detailed report at: $REPORT_DIR/extension-security-report.html"
    exit 1
else
    echo "✅ No critical browser security issues detected"
    exit 0
fi
```

#### Web Application Security Pipeline

```yaml
# web-app-security-pipeline.yml
name: Web Application Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  browser-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
          
      - name: Install Insect
        run: pip install insect
        
      - name: Scan for browser security issues
        run: |
          insect scan . \
            --config .insect/browser-security.toml \
            -f json \
            -o browser-security-findings.json \
            --severity medium
            
      - name: Check for browser theft patterns
        run: |
          if grep -q '"analyzer": "browser_theft"' browser-security-findings.json; then
            echo "Browser security violations detected!"
            jq '.findings[] | select(.analyzer == "browser_theft") | {id, title, severity, file: .location.path, line: .location.line_start}' browser-security-findings.json
            exit 1
          fi
          
      - name: Generate security report
        if: always()
        run: |
          insect scan . \
            --config .insect/browser-security.toml \
            -f html \
            -o browser-security-report.html
            
      - name: Upload security artifacts
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: browser-security-results
          path: |
            browser-security-findings.json
            browser-security-report.html
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Insect Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
          
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install insect
          
      - name: Install external tools
        run: |
          pip install bandit semgrep
          
      - name: Run Insect scan
        run: |
          insect scan . -f json -o scan-results.json --severity medium
          
      - name: Check for critical findings
        run: |
          if grep -q '"severity": "critical"' scan-results.json; then
            echo "Critical security issues found!"
            exit 1
          fi
          
      - name: Archive scan results
        uses: actions/upload-artifact@v2
        with:
          name: insect-scan-results
          path: scan-results.json
```

### GitLab CI

```yaml
stages:
  - test
  - security

insect-security-scan:
  stage: security
  image: python:3.10
  script:
    - pip install insect bandit semgrep
    - insect scan . -f json -o scan-results.json --severity medium
    - |
      if grep -q '"severity": "critical"' scan-results.json; then
        echo "Critical security issues found!"
        exit 1
      fi
  artifacts:
    paths:
      - scan-results.json
    when: always
```

### Jenkins Pipeline

```groovy
pipeline {
    agent {
        docker {
            image 'python:3.10'
        }
    }
    
    stages {
        stage('Install') {
            steps {
                sh 'pip install insect bandit semgrep'
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'insect scan . -f json -o scan-results.json --severity medium'
            }
        }
        
        stage('Check Results') {
            steps {
                script {
                    def hasCritical = sh(
                        script: 'grep -q \'"severity": "critical"\' scan-results.json',
                        returnStatus: true
                    ) == 0
                    
                    if (hasCritical) {
                        error "Critical security issues found!"
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
        }
    }
}
```

## Performance Optimization

### Caching Strategies

Insect's caching system provides significant performance benefits for repeated scans. Here are some strategies to optimize caching:

1. **Default Caching**: By default, caching is enabled in `.insect/cache` in the repository root.

2. **Custom Cache Location**: You can set a custom cache location in your configuration:

   ```toml
   [cache]
   enabled = true
   directory = "/path/to/custom/cache"
   ```

3. **CI/CD Caching**: In CI/CD environments, you can persist the cache between runs for faster builds:

   ```yaml
   # GitHub Actions example
   - name: Cache Insect results
     uses: actions/cache@v2
     with:
       path: .insect/cache
       key: ${{ runner.os }}-insect-${{ hashFiles('**/*.py', '**/*.js', '**/*.sh') }}
   ```

4. **Clearing the Cache**: If you suspect cache corruption or want to start fresh:

   ```bash
   insect scan /path/to/repo --clear-cache
   ```

### Targeted Scanning

For large repositories, you can improve performance by using targeted scanning:

1. **Include Specific Patterns**:

   ```bash
   insect scan /path/to/repo --include-pattern "src/**/*.py" --include-pattern "lib/**/*.js"
   ```

2. **Limit Scan Depth**:

   ```bash
   insect scan /path/to/repo --max-depth 5
   ```

3. **Disable Unnecessary Analyzers**:

   ```bash
   insect scan /path/to/repo --disable binary
   ```

## External Tool Integration

Insect can integrate with several external security tools to enhance scanning capabilities.

### Bandit Integration

[Bandit](https://github.com/PyCQA/bandit) is a tool designed to find common security issues in Python code.

Installation:
```bash
pip install bandit
```

Configuration:
```toml
[analyzers.python_static_analyzer]
use_bandit = true
bandit_args = ["-f", "json", "-q"]
```

### Semgrep Integration

[Semgrep](https://semgrep.dev/) is a lightweight static analysis tool for many languages.

Installation:
```bash
pip install semgrep
```

Configuration:
```toml
[analyzers.python_static_analyzer]
use_semgrep = true
semgrep_args = ["--config=p/python", "--json"]

[analyzers.javascript_static_analyzer]
use_semgrep = true
semgrep_args = ["--config=p/javascript", "--json"]
```

### ShellCheck Integration

[ShellCheck](https://www.shellcheck.net/) is a shell script static analysis tool.

Installation:
```bash
# Ubuntu/Debian
apt-get install shellcheck

# macOS
brew install shellcheck

# Windows (via chocolatey)
choco install shellcheck
```

Configuration:
```toml
[analyzers.shell_script_analyzer]
use_shellcheck = true
shellcheck_severity = "style"  # Options: style, info, warning, error
```

## Extending Insect

### Creating a Custom Analyzer

You can extend Insect by creating custom analyzers for new languages or file types:

```python
from pathlib import Path
from typing import Any, Dict, List

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.finding import Finding, FindingType, Location, Severity

@register_analyzer
class CustomAnalyzer(BaseAnalyzer):
    """Custom analyzer for specific file types."""
    
    name = "custom_analyzer"
    description = "Custom analyzer for specific file types"
    supported_extensions = {".custom", ".ext"}
    
    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the custom analyzer."""
        super().__init__(config)
        # Get analyzer-specific configuration
        self.analyzer_config = config.get(self.name, {})
        # Initialize any needed settings
        
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for security issues.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            List of findings detected in the file
        """
        findings = []
        
        # Implement your analysis logic here
        # For example:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
            
        # Detect issues in the content
        if "insecure_pattern" in content:
            findings.append(
                Finding(
                    id=f"CUSTOM-001",
                    title="Insecure pattern detected",
                    description="A potentially insecure pattern was found.",
                    severity=Severity.MEDIUM,
                    type=FindingType.VULNERABILITY,
                    location=Location(path=file_path),
                    analyzer=self.name,
                )
            )
            
        return findings
```

### Custom Output Formatters

You can also create custom output formatters:

```python
from typing import Any, Dict, List

from insect.finding import Finding
from insect.reporting.formatters import BaseFormatter, register_formatter

@register_formatter
class CustomFormatter(BaseFormatter):
    """Custom formatter for specific output format."""
    
    format_name = "custom"
    
    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings in a custom format.
        
        Args:
            findings: List of findings.
            metadata: Scan metadata.
            
        Returns:
            Formatted report as a string.
        """
        # Implement your formatting logic here
        output = []
        
        output.append("# Custom Security Report")
        output.append(f"Scan ID: {metadata.get('scan_id', 'Unknown')}")
        output.append(f"Total findings: {len(findings)}")
        
        for finding in findings:
            output.append(f"- {finding.severity.name}: {finding.title}")
            output.append(f"  Location: {finding.location}")
            output.append(f"  Description: {finding.description}")
            output.append("")
            
        return "\n".join(output)
```

### Plugin Architecture

Insect supports a plugin architecture for adding new functionality without modifying the core code:

1. Create a Python package with your extension
2. Define entry points in your package's `setup.py`:

```python
setup(
    name="insect-extension",
    # ...
    entry_points={
        "insect.analyzers": [
            "custom_analyzer = your_package.analyzers:CustomAnalyzer",
        ],
        "insect.formatters": [
            "custom_format = your_package.formatters:CustomFormatter",
        ],
        "insect.rules": [
            "custom_rules = your_package.rules:register_rules",
        ],
    },
)
```

3. Install your package, and Insect will automatically discover and use your extensions.