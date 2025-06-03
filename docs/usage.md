---
layout: page
title: Usage Guide
nav_order: 6
---

# Insect Usage Guide

Insect is a security tool for safely analyzing external Git repositories for malicious content before cloning or execution. This guide covers both primary (external scanning) and secondary (internal scanning) use cases.

## Table of Contents

- [Installation](#installation)
- [Primary Use Case: External Repository Scanning](#primary-use-case-external-repository-scanning)
- [Secondary Use Case: Local Code Scanning](#secondary-use-case-local-code-scanning)
- [Command Reference](#command-reference)
  - [clone](#clone)
  - [scan](#scan)
  - [deps](#deps)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Real-World Examples](#real-world-examples)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Installation

### Using pip

```bash
pip install insect
```

### Using pipenv

```bash
pipenv install insect
```

### From Source

```bash
git clone https://github.com/yourusername/insect.git
cd insect
pip install -e .
```

## Primary Use Case: External Repository Scanning

The primary and recommended use case for Insect is analyzing external repositories safely:

```bash
# Safely analyze external repository before cloning
insect clone https://github.com/suspicious/repository

# Advanced analysis with high sensitivity
insect clone https://github.com/example/repo --scan-args "--sensitivity high"

# Generate detailed security report
insect clone https://github.com/vendor/tool --report-path security-analysis.json
```

This will:
1. Clone the repository in an isolated Docker container
2. Apply comprehensive security analysis
3. Show security findings and threat assessment
4. Prompt for confirmation before local cloning

## Secondary Use Case: Local Code Scanning

For analyzing local code (requires Docker for full security features):

```bash
# Scan local project
insect scan ./my-project

# Generate HTML report
insect scan ./my-project --format html --output security-report.html
```

## Command Reference

### clone

The `clone` command safely analyzes external repositories in containers (RECOMMENDED):

```bash
insect clone [OPTIONS] REPO_URL
```

#### Options

| Option | Description |
|--------|-------------|
| `--output-dir`, `-o` | Directory where to clone the repository (defaults to current directory) |
| `--branch`, `-b` | Branch to check out (defaults to default branch) |
| `--commit`, `-c` | Specific commit to check out (overrides branch) |
| `--image`, `-i` | Docker image to use (defaults to 'python:3.10-slim') |
| `--scan-args` | Additional arguments to pass to the insect scan command |
| `--report-path` | Path to save the scan report JSON (defaults to not saving) |

#### Example: Basic External Repository Analysis

```bash
insect clone https://github.com/suspicious/repository
```

#### Example: Generating a Detailed Security Report

```bash
insect clone https://github.com/vendor/tool --report-path security-analysis.json
```

#### Example: Analyzing Specific Branch

```bash
insect clone https://github.com/example/repo --branch develop --scan-args "--sensitivity high"
```

#### Example: High Sensitivity Analysis

```bash
insect clone https://github.com/questionable/repo --scan-args "--sensitivity very_high --format html"
```

### scan

The `scan` command analyzes local code for security issues:

```bash
insect scan [OPTIONS] REPO_PATH
```

#### Options

| Option | Description |
|--------|-------------|
| `--verbose`, `-v` | Increase verbosity (can be used multiple times) |
| `--output`, `-o` | Path to write report to (defaults to stdout) |
| `--format`, `-f` | Output format: text, json, or html (default: text) |
| `--config`, `-c` | Path to configuration file |
| `--disable` | Disable specific analyzers (can be used multiple times) |
| `--include-pattern` | Only include files matching pattern (can be used multiple times) |
| `--exclude-pattern` | Exclude files matching pattern (can be used multiple times) |
| `--max-depth` | Maximum directory depth to scan |
| `--no-secrets` | Disable secrets detection |
| `--severity` | Minimum severity level to report: low, medium, high, critical (default: low) |
| `--sensitivity` | Analysis sensitivity level: low, normal, high, very_high (default: normal) |
| `--no-cache` | Disable the scan cache (ignore cached results) |
| `--clear-cache` | Clear the scan cache before scanning |
| `--no-progress` | Disable the progress bar |

#### Example: Basic Local Scan

```bash
insect scan ./my-project
```

#### Example: Generating an HTML Report

```bash
insect scan ./my-project -f html -o security-report.html
```

#### Example: High Sensitivity Local Analysis

```bash
insect scan ./my-project --sensitivity high --severity medium
```

### deps

The `deps` command displays the status of external dependencies that enhance Insect's scanning capabilities:

```bash
insect deps [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--format`, `-f` | Output format: text or json (default: text) |
| `--output`, `-o` | Path to write dependency report to (defaults to stdout) |

#### Example: Checking Dependencies

```bash
insect deps
```

#### Example: Generating a JSON Dependencies Report

```bash
insect deps -f json -o dependencies.json
```

## Configuration

Insect can be configured using a TOML file. The default configuration is automatically loaded, but you can specify a custom configuration file with the `--config` option.

### Default Configuration

```toml
# General settings
[general]
max_depth = 10
include_hidden = false

# Analyzer settings
[analyzers]
static = true
config = true
binary = true
metadata = true
secrets = true
browser_theft = true

# File pattern settings
[patterns]
include = ["*"]
exclude = [
    "*.git/*",
    "node_modules/*",
    "venv/*",
    ".venv/*",
    "*.pyc",
    "__pycache__/*",
    "*.min.js",
    "*.min.css",
]

# Severity settings
[severity]
min_level = "low"  # Options: low, medium, high, critical

# Allowlist settings
[allowlist]
files = []
directories = []
patterns = []
findings = []  # List of finding IDs to ignore

# Cache settings
[cache]
enabled = true  # Enable or disable the scan cache
cleanup_enabled = true  # Enable or disable automatic cleanup of old cache entries
max_age_days = 30  # Maximum age of cache entries in days

# Progress bar settings
[progress]
enabled = true  # Enable or disable the progress bar

# Browser theft detection settings
[browser_theft]
enable_browser_history_detection = true
enable_browser_storage_detection = true
enable_credential_detection = true
enable_extension_detection = true
```

### Custom Configuration Example

Create a file named `insect.toml` with your custom settings:

```toml
# Custom configuration example
[general]
max_depth = 5
include_hidden = true

[analyzers]
# Disable binary analysis if not needed
binary = false
# Enable browser theft detection
browser_theft = true

[patterns]
exclude = [
    "*.git/*",
    "node_modules/*",
    "build/*",
    "dist/*",
    "*.txt"
]

[severity]
min_level = "medium"
```

Then run Insect with your custom configuration:

```bash
insect scan /path/to/your/repo --config insect.toml
```

## Output Formats

Insect supports three output formats:

### Text Output (Default)

Provides a human-readable console output with color-coded findings.

```bash
insect scan /path/to/your/repo
```

### JSON Output

Generates machine-readable structured output suitable for integration with other tools.

```bash
insect scan /path/to/your/repo -f json -o findings.json
```

### HTML Output

Creates an interactive HTML report with filtering and details on findings.

```bash
insect scan /path/to/your/repo -f html -o report.html
```

The HTML report includes:
- Summary statistics
- Findings categorized by severity and type
- Interactive filtering
- Detailed view for each finding
- Dependencies status
- Scan metadata

## Real-World Examples

### Vetting External Dependencies

```bash
# Analyze JavaScript library before adding to project
insect clone https://github.com/author/js-library --report-path js-lib-analysis.json

# Comprehensive analysis of Python package
insect clone https://github.com/author/python-package --scan-args "--sensitivity high --format html"

# Quick safety check of Go module
insect clone https://github.com/author/go-module --scan-args "--severity medium"
```

### Security Research and Investigation

```bash
# Analyze reported malicious repository
insect clone https://github.com/suspicious/stealer --scan-args "--sensitivity very_high" --report-path malware-analysis.json

# Investigate browser extension for theft patterns
insect clone https://github.com/questionable/extension --scan-args "--format html" --report-path extension-analysis.html

# Analyze crypto mining repository
insect clone https://github.com/mining/tool --report-path crypto-analysis.json
```

### Local Code Quality (Secondary Use Case)

```bash
# Scan local JavaScript project
insect scan ./js-project --exclude-pattern "node_modules/*" --exclude-pattern "dist/*" -f html -o local-js-report.html

# Analyze local Python package
insect scan ./python-package --exclude-pattern "venv/*" --exclude-pattern "*.pyc" -f json -o local-py-report.json
```

### CI/CD Integration Examples

#### External Dependency Vetting
```yaml
# GitHub Actions workflow for dependency security
name: Dependency Security Check

on:
  pull_request:
    paths:
      - 'package.json'
      - 'requirements.txt'

jobs:
  security-vet:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install Insect
      run: pip install insect
    - name: Vet new dependencies
      run: |
        # Extract and analyze new dependencies
        ./scripts/vet-dependencies.sh
    - name: Upload security reports
      uses: actions/upload-artifact@v2
      with:
        name: dependency-security-reports
        path: security-reports/
```

#### Internal Code Quality (Secondary)
```yaml
# Internal code quality workflow
name: Code Quality Scan

on:
  push:
    branches: [ main ]

jobs:
  quality-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install Insect
      run: pip install insect
    - name: Run quality scan
      run: |
        insect scan . -f json -o quality-results.json --severity medium
```

### Pre-commit Hook Example

Create a `.pre-commit-config.yaml` file:

```yaml
repos:
-   repo: local
    hooks:
    -   id: insect-scan
        name: Insect Security Scan
        entry: insect scan
        args: [--severity, medium]
        language: system
        pass_filenames: false
```

## Troubleshooting

### Missing Dependencies

If you see warnings about missing external tools:

```
Some external dependencies are missing: bandit, semgrep, shellcheck. Run 'insect deps' to see installation instructions.
```

Run `insect deps` to see installation instructions for each tool.

### Handling False Positives

If Insect reports issues that are not actual security problems:

1. Adjust your configuration to exclude those patterns
2. Add specific finding IDs to the allowlist section of your configuration:

```toml
[allowlist]
findings = ["PY-103-abc123", "JS-104-def456"]
```

### Performance Issues with Large Repositories

For large repositories:

1. Use more targeted include/exclude patterns
2. Use caching to speed up re-scans
3. Increase the minimum severity level to reduce noise

```bash
insect scan /path/to/large-repo --severity medium --max-depth 5
```

## Best Practices

### External Repository Vetting (Primary Use Case)

**Always analyze before cloning:**
```bash
# ✅ Safe: Analyze first
insect clone https://github.com/untrusted/repo

# ❌ Dangerous: Direct cloning
git clone https://github.com/untrusted/repo
```

**Regular dependency monitoring:**
- Scan dependencies before integration
- Monitor for updates that introduce new threats
- Document security assessments for compliance

**Team integration:**
- Establish vetting workflows for external code
- Create security reports for management review
- Use high sensitivity for suspicious repositories

### Local Code Quality (Secondary Use Case)

**Development workflow integration:**
- Scan before committing critical changes
- Use in CI/CD for code quality gates
- Focus on fixing critical and high-severity issues

**Configuration management:**
- Create project-specific configurations
- Exclude testing and build directories
- Adjust sensitivity based on project requirements

### Enhancing with External Tools

Install the external tools Insect can leverage:
- Bandit for Python vulnerability detection
- Semgrep for advanced semantic pattern matching
- ShellCheck for shell script analysis

Install these tools with:

```bash
# Python tools
pip install bandit semgrep

# ShellCheck (Ubuntu/Debian)
apt-get install shellcheck

# ShellCheck (macOS)
brew install shellcheck
```