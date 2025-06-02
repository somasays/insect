---
layout: page
title: Home
---

<div align="center">
  <img src="{{ site.baseurl }}/assets/images/insect-logo.png" alt="Insect Logo" width="200"/>
  
  <h1>Insect Security Scanner</h1>
  
  <p><strong>A security-focused CLI tool designed to scan Git repositories for potentially malicious code patterns before execution.</strong></p>
  
  <p>
    <a href="https://badge.fury.io/py/insect"><img src="https://badge.fury.io/py/insect.svg" alt="PyPI version"></a>
    <a href="https://pypi.org/project/insect/"><img src="https://img.shields.io/pypi/pyversions/insect.svg" alt="Python Version"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  </p>
</div>

## Overview

Insect is a powerful security scanner that helps developers identify potential security threats in Git repositories before executing code. It combines multiple analysis techniques to provide comprehensive security coverage.

## Key Features

- **🔍 Multi-language Support**: Analyzes Python, JavaScript, Shell scripts, and more
- **🛡️ Deep Static Analysis**: Detects suspicious patterns and security vulnerabilities  
- **🔧 External Tool Integration**: Works with Bandit, Semgrep, ShellCheck, and other security tools
- **📊 Detailed Reporting**: Outputs in text, JSON, and interactive HTML formats
- **⚡ Performance Optimized**: Smart caching for faster re-scanning
- **🎛️ Flexible Configuration**: Customize analysis based on your project needs
- **🐳 Containerized Scanning**: Safe scanning of untrusted repositories in Docker containers
- **🎨 Beautiful CLI**: Rich, colorful interface with progress bars and animations

## Quick Start

### Installation

```bash
pip install insect
```

### Basic Usage

```bash
# Scan current directory
insect scan .

# Scan with high sensitivity
insect scan . --sensitivity high

# Generate HTML report
insect scan . --format html --output report.html

# Scan in Docker container (for untrusted code)
insect clone https://github.com/user/repo
```

## Documentation

- [Usage Guide](usage.html) - Complete usage instructions
- [Security Examples](security_examples.html) - Real-world security patterns detected
- [Use Cases](use_cases.html) - Common scenarios and workflows
- [Advanced Usage](advanced_usage.html) - Configuration and customization
- [Container Scanning](container_scanning.html) - Docker-based scanning for safety
- [Contributing](contributing.html) - How to contribute to the project

## Quick Examples

### Detect Secrets and Credentials
```bash
insect scan ./my-project --severity high
```

### Analyze Cryptocurrency Wallet Threats
```bash
insect scan ./crypto-app --sensitivity very_high
```

### Generate Detailed Report
```bash
insect scan ./project --format html --output security-report.html
```

## Why Insect?

In today's security landscape, it's crucial to analyze code before execution. Insect provides:

- **Proactive Security**: Catch issues before they reach production
- **Comprehensive Coverage**: Multiple analysis engines working together
- **Developer Friendly**: Easy to use with clear, actionable output
- **Extensible**: Configurable rules and integration with existing tools

## Get Started

Ready to secure your repositories? Check out our [Usage Guide](usage.html) to get started, or explore our [Security Examples](security_examples.html) to see what Insect can detect.

---

<div align="center">
  <p><em>Insect - Protecting your code from security threats, one scan at a time.</em></p>
</div>