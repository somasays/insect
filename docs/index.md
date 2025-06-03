---
layout: page
title: Home
---

<div align="center">
  <img src="{{ site.baseurl }}/assets/images/insect-logo.png" alt="Insect Logo" width="200"/>
  
  <h1>Insect Security Scanner</h1>
  
  <p><strong>Safely analyze external Git repositories for malicious content before cloning or execution</strong></p>
  
  <p>
    <a href="https://badge.fury.io/py/insect"><img src="https://badge.fury.io/py/insect.svg" alt="PyPI version"></a>
    <a href="https://pypi.org/project/insect/"><img src="https://img.shields.io/pypi/pyversions/insect.svg" alt="Python Version"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  </p>
</div>

## Overview

Insect is a security tool that helps you **safely evaluate external Git repositories** before cloning them to your system. It uses container-based isolation to analyze potentially malicious code without risk to your environment.

## Key Features

- **🐳 Container Isolation**: Analyze untrusted code safely in Docker containers
- **🔍 Comprehensive Detection**: Find malware, credential stealers, crypto miners
- **🛡️ Pre-execution Analysis**: Detect threats before code runs on your system
- **📊 Detailed Reports**: Interactive HTML reports with threat analysis
- **⚡ Multiple Formats**: Text, JSON, HTML output options
- **🎛️ Configurable**: Adjust sensitivity for different threat models
- **🔧 External Tool Integration**: Works with Bandit, Semgrep, ShellCheck, and other security tools
- **🎨 Beautiful CLI**: Rich, colorful interface with progress bars and animations

## Quick Start

### Installation

```bash
pip install insect
```

### Analyze External Repository (Recommended)

```bash
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

## Documentation

- [Quick Start Guide](quick-start.html) - Get started with external repository scanning
- [External Scanning](external-scanning.html) - Comprehensive guide for analyzing untrusted repos
- [Threat Detection](threat-detection.html) - Examples of malicious patterns detected
- [Container Security](container-security.html) - Docker-based isolation setup
- [Dependency Vetting](dependency-vetting.html) - Security team workflows
- [Usage Guide](usage.html) - Complete usage instructions
- [Internal Scanning](internal-scanning.html) - Using Insect for your own code
- [Contributing](contributing.html) - How to contribute to the project

## Quick Examples

### Vetting Dependencies
```bash
insect clone https://github.com/author/js-library --report-path security-analysis.json
```

### Analyzing Suspicious Repositories
```bash
insect clone https://github.com/reported/malware --scan-args "--sensitivity very_high"
```

### Security Research
```bash
insect clone https://github.com/questionable/project --scan-args "--format html"
```

## Why Insect?

In today's threat landscape, **malicious repositories are increasingly common**:

- **Supply Chain Attacks**: Compromised packages targeting developers
- **Credential Stealers**: Fake repositories designed to harvest credentials
- **Crypto Miners**: Hidden mining code disguised as legitimate tools
- **Browser Stealers**: Malicious code targeting developer machines

**Insect helps you stay safe** by analyzing code before it touches your system.

## Get Started

Ready to analyze external repositories safely? Check out our [Quick Start Guide](quick-start.html) to get started, or explore our [Threat Detection](threat-detection.html) examples to see what Insect can detect.

---

<div align="center">
  <p><em>Insect - Analyze first, trust later.</em></p>
</div>