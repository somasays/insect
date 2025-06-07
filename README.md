<div align="center">

<img src="./assets/images/insect-logo.png" alt="Insect Logo" width="150" height="150">

# Insect Security Scanner

**Safely analyze external Git repositories for malicious content before cloning or execution**

[![PyPI version](https://badge.fury.io/py/insect.svg)](https://badge.fury.io/py/insect)
[![Python Version](https://img.shields.io/pypi/pyversions/insect.svg)](https://pypi.org/project/insect/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI/CD Status](https://github.com/somasays/insect/workflows/Test/badge.svg)](https://github.com/somasays/insect/actions)
[![Release Status](https://github.com/somasays/insect/workflows/Release/badge.svg)](https://github.com/somasays/insect/actions)

</div>

## 🚨 What is Insect?

Insect is a security tool that helps you **safely evaluate external Git repositories** before cloning them to your system. It uses container-based isolation to analyze potentially malicious code without risk to your environment.

### Primary Use Cases

- 🔍 **Vet third-party repositories** before cloning from GitHub/GitLab
- 🛡️ **Detect malware and stealers** in open-source projects  
- 🐳 **Analyze in isolation** using Docker containers for safety
- 📊 **Generate security reports** on external dependencies

## ⚡ Quick Start

### Prerequisites
- **Docker** (required for safe external repository analysis)
- **Python 3.8+**

### Analyze External Repository (Recommended)
```bash
# Install Insect
pip install insect

# Safely analyze external repository before cloning
insect clone https://github.com/suspicious/repository

# Advanced: Scan with high sensitivity for comprehensive analysis
insect clone https://github.com/example/repo --scan-args "--sensitivity high"

# Generate detailed security report
insect clone https://github.com/vendor/tool --report-path security-analysis.json
```

### Scan Local Code (Secondary Use Case)
```bash
# Scan local project (requires Docker for full features)
insect scan ./my-project --format html --output security-report.html
```

## 🔥 Key Features

- **🐳 Container Isolation**: Analyze untrusted code safely in Docker
- **🔍 Comprehensive Detection**: Find malware, credential stealers, crypto miners
- **🦄 Unicode Attack Detection**: Detect sophisticated character-based obfuscation
- **🛡️ Pre-execution Analysis**: Detect threats before code runs
- **📊 Detailed Reports**: Interactive HTML reports with threat analysis
- **⚡ Multiple Formats**: Text, JSON, HTML output options
- **🎛️ Configurable**: Adjust sensitivity for different threat models

## 🎯 What Insect Detects

### Malicious Patterns
- **Browser Data Theft**: Cookie stealers, password extractors, session hijackers
- **Cryptocurrency Theft**: Wallet stealers, private key extractors, clipboard hijackers  
- **System Compromise**: Command injection, privilege escalation, backdoors
- **Data Exfiltration**: Secret harvesters, API key stealers, data miners
- **Unicode Attacks**: Homograph attacks, invisible characters, bidirectional text manipulation

### Security Vulnerabilities
- **Code Injection**: SQL injection, XSS, command injection, path traversal
- **Character-based Attacks**: Unicode obfuscation, invisible backdoors, encoding abuse
- **Insecure Configurations**: Hardcoded credentials, weak settings
- **Dependency Issues**: Vulnerable libraries, supply chain risks

## 🦄 Advanced Unicode Attack Detection

Insect includes sophisticated detection for Unicode-based attacks that are invisible to human reviewers:

### What It Detects
- **Homograph Attacks**: Mixed scripts (Cyrillic 'а' vs Latin 'a') in identifiers
- **Invisible Characters**: Zero-width spaces, format characters, hidden Unicode
- **Bidirectional Text**: Right-to-Left Override attacks that hide malicious code
- **Encoding Abuse**: Path traversal and injection via character encoding
- **Malicious Filenames**: Reserved device names and dangerous file patterns

### Example Detection
```python
# This looks like normal code but contains Cyrillic characters
def аuthenticate(user, password):  # 'а' is Cyrillic U+0430, not Latin!
    return True  # Bypasses real authentication

# Invisible character injection
def login​(user, pass):  # Zero-width space after 'login'
    steal_credentials(user, pass)​  # Another hidden character
```

### Configuration
```toml
[analyzers.malicious_character]
enabled = true
sensitivity = "medium"  # Options: "low", "medium", "high"
```

## 🚀 Real-World Examples

### Vetting Dependencies
```bash
# Check a JavaScript library before adding to your project
insect clone https://github.com/author/js-library --report-path security-analysis.json

# Analyze a Python package source
insect clone https://github.com/author/python-package --scan-args "--severity medium"

# Comprehensive analysis of suspicious repository
insect clone https://github.com/reported/malware --scan-args "--sensitivity very_high"
```

### Security Research
```bash
# Analyze suspicious repository reported by community
insect clone https://github.com/suspicious/stealer --report-path investigation.json

# Generate detailed report for security review
insect clone https://github.com/questionable/project --scan-args "--format html"
```

### Team Integration
```bash
# Security team validation workflow
insect clone https://github.com/vendor/tool --report-path vendor-assessment.json

# Developer pre-integration check
insect clone https://github.com/library/candidate --scan-args "--severity medium"
```

## 🛡️ Safety First

**Never run untrusted code directly!** Always use Insect's container-based scanning:

```bash
# ✅ Safe: Analyze in container first
insect clone https://github.com/untrusted/repo

# ❌ Dangerous: Don't clone and run unknown code
git clone https://github.com/untrusted/repo && cd repo && ./install.sh
```

## 📖 Documentation

- [**Quick Start Guide**](docs/quick-start.md) - Get started with external repository scanning
- [**External Scanning**](docs/external-scanning.md) - Comprehensive guide for analyzing untrusted repos
- [**Threat Detection**](docs/threat-detection.md) - Examples of malicious patterns detected
- [**Container Security**](docs/container-security.md) - Docker-based isolation setup
- [**Dependency Vetting**](docs/dependency-vetting.md) - Security team workflows
- [**Internal Scanning**](docs/internal-scanning.md) - Using Insect for your own code

## 🔧 Requirements

- **Docker**: Required for safe analysis of external repositories
- **Python 3.8+**: For running Insect
- **Internet**: For cloning external repositories

## 💡 Why Use Insect?

In today's threat landscape, **malicious repositories are increasingly common**:
- Supply chain attacks through compromised packages
- Fake repositories designed to steal credentials  
- Crypto miners disguised as legitimate tools
- Browser stealers targeting developer machines

**Insect helps you stay safe** by analyzing code before it touches your system.

## Installation

```bash
pip install insect
```

Or using pipenv:

```bash
pipenv install insect
```

## Additional Commands

Check status of external dependencies:
```bash
insect deps
```

For more advanced usage and configuration options, see our [documentation](docs/).

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/somasays/insect.git
cd insect

# Setup development environment
pipenv install --dev
pipenv shell

# Install pre-commit hooks
pre-commit install
```

### Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=insect

# Run tox to test across different Python versions
tox
```

### Code Quality

```bash
# Format code
black .
isort .

# Lint code
ruff .

# Type checking
mypy .
```

For detailed development workflows, see our [contributing guide](docs/contributing.md).

## License

MIT

---

*Insect - Analyze first, trust later.*