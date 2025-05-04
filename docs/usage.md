# Insect Usage Guide

Insect is a security-focused CLI tool designed to scan Git repositories for potentially malicious code patterns before execution. It uses a combination of static analysis, configuration checks, and metadata examination to identify security risks in code.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Command Reference](#command-reference)
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

## Basic Usage

The most common use case for Insect is to scan a Git repository:

```bash
insect scan /path/to/repository
```

This will:
1. Discover all files in the repository
2. Apply relevant analyzers to each file
3. Generate a report of security findings

## Command Reference

### scan

The `scan` command analyzes a repository for security issues:

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
| `--no-cache` | Disable the scan cache (ignore cached results) |
| `--clear-cache` | Clear the scan cache before scanning |
| `--no-progress` | Disable the progress bar |

#### Example: Basic Scan with Text Output

```bash
insect scan /path/to/your/repo
```

#### Example: Generating an HTML Report

```bash
insect scan /path/to/your/repo -f html -o report.html
```

#### Example: Excluding Certain Patterns

```bash
insect scan /path/to/your/repo --exclude-pattern "node_modules/*" --exclude-pattern "*.min.js"
```

#### Example: Setting Minimum Severity

```bash
insect scan /path/to/your/repo --severity medium
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

### Scanning a JavaScript Project

```bash
insect scan /path/to/js-project --exclude-pattern "node_modules/*" --exclude-pattern "dist/*" -f html -o js-report.html
```

### Scanning a Python Package

```bash
insect scan /path/to/python-package --exclude-pattern "venv/*" --exclude-pattern "*.pyc" -f json -o py-report.json
```

### CI/CD Integration Example

```yaml
# In a GitHub Actions workflow
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  insect-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'
    - name: Install Insect
      run: pip install insect
    - name: Run Insect Scan
      run: |
        insect scan . -f json -o scan-results.json --severity medium
    - name: Upload scan results
      uses: actions/upload-artifact@v2
      with:
        name: insect-scan-results
        path: scan-results.json
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

### Regular Scanning

Run Insect scans regularly as part of your development workflow:
- Before merging new code
- As part of CI/CD pipelines
- When integrating third-party libraries

### Customized Configuration

Create a custom configuration file for each project:
- Exclude testing and build directories
- Focus on critical security concerns
- Adjust for language-specific needs

### Incremental Improvements

1. Start with a baseline scan
2. Address critical and high-severity findings first
3. Add allowlist entries for known, approved patterns
4. Re-scan regularly to ensure continued compliance

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