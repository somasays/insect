---
layout: page
title: External Repository Scanning
nav_order: 2
---

# External Repository Scanning

This comprehensive guide covers Insect's primary use case: **safely analyzing external Git repositories** for malicious content before cloning them to your system.

## Table of Contents

- [Overview](#overview)
- [Safety Architecture](#safety-architecture)
- [Basic Workflows](#basic-workflows)
- [Advanced Analysis](#advanced-analysis)
- [Team Integration](#team-integration)
- [Threat Scenarios](#threat-scenarios)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

External repository scanning allows you to:
- **Vet third-party dependencies** before integration
- **Detect malicious repositories** designed to steal data
- **Analyze suspicious code** safely in isolation
- **Generate security reports** for team review

## Safety Architecture

### Container Isolation
Insect uses Docker containers to ensure complete isolation:

```bash
# Safe: Repository analyzed in isolated container
insect clone https://github.com/untrusted/repo

# Unsafe: Direct cloning exposes your system
git clone https://github.com/untrusted/repo  # DON'T DO THIS
```

### Pre-execution Analysis
- **Static analysis only** - no code execution
- **Pattern matching** for known malicious behaviors
- **Metadata examination** for suspicious indicators
- **Configuration analysis** for security misconfigurations

### Threat Detection
Insect identifies:
- **Malware and stealers** (browser data, crypto wallets)
- **Supply chain attacks** (compromised packages)
- **Credential harvesting** (API keys, tokens)
- **System compromise** (backdoors, privilege escalation)

## Basic Workflows

### Repository Vetting
```bash
# Basic security assessment
insect clone https://github.com/vendor/library

# High-sensitivity analysis for comprehensive detection
insect clone https://github.com/suspicious/repo --scan-args "--sensitivity very_high"

# Generate report for documentation
insect clone https://github.com/vendor/tool --report-path vendor-assessment.json
```

### Dependency Analysis
```bash
# JavaScript ecosystem
insect clone https://github.com/author/npm-package --scan-args "--severity medium"

# Python ecosystem
insect clone https://github.com/author/python-library --report-path python-lib-analysis.json

# Go ecosystem
insect clone https://github.com/author/go-module --scan-args "--format html"
```

### Security Research
```bash
# Malware analysis (high sensitivity)
insect clone https://github.com/reported/malware --scan-args "--sensitivity very_high" --report-path malware-analysis.json

# Browser stealer investigation
insect clone https://github.com/suspicious/extension --scan-args "--format html" --report-path stealer-report.html

# Crypto miner detection
insect clone https://github.com/mining/tool --report-path crypto-miner-analysis.json
```

## Advanced Analysis

### Sensitivity Levels
Configure analysis depth based on threat model:

```bash
# Low: Only obvious malicious patterns
insect clone https://github.com/trusted/repo --scan-args "--sensitivity low"

# Normal: Standard threat detection (default)
insect clone https://github.com/example/repo --scan-args "--sensitivity normal"

# High: Include speculative findings
insect clone https://github.com/questionable/repo --scan-args "--sensitivity high"

# Very High: All patterns including unusual commits
insect clone https://github.com/suspicious/repo --scan-args "--sensitivity very_high"
```

### Output Formats
Choose output format based on use case:

```bash
# Text output (default, human-readable)
insect clone https://github.com/example/repo

# JSON output (machine-readable, for automation)
insect clone https://github.com/example/repo --scan-args "--format json" --report-path results.json

# HTML output (interactive, for detailed analysis)
insect clone https://github.com/example/repo --scan-args "--format html" --report-path report.html
```

### Branch and Commit Analysis
```bash
# Analyze specific branch
insect clone https://github.com/example/repo --branch suspicious-feature

# Analyze specific commit
insect clone https://github.com/example/repo --commit a1b2c3d4

# Analyze development branch for ongoing monitoring
insect clone https://github.com/example/repo --branch develop --report-path develop-scan.json
```

## Team Integration

### Security Team Workflows
```bash
# Vendor assessment workflow
insect clone https://github.com/vendor/product --scan-args "--format html" --report-path vendor-security-assessment.html

# Incident response investigation
insect clone https://github.com/reported/threat --scan-args "--sensitivity very_high" --report-path incident-analysis.json

# Regular dependency monitoring
insect clone https://github.com/dependency/library --report-path monthly-scan-$(date +%Y-%m).json
```

### Developer Workflows
```bash
# Pre-integration dependency check
insect clone https://github.com/library/candidate --scan-args "--severity medium"

# Open source contribution review
insect clone https://github.com/project/repo --branch pr-123 --report-path pr-security-review.json

# Library upgrade safety check
insect clone https://github.com/library/repo --branch v2.0.0 --report-path upgrade-assessment.json
```

### Automated Integration
```bash
#!/bin/bash
# Automated dependency vetting script

REPO_URL="$1"
REPORT_DIR="./security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$REPORT_DIR"

echo "Analyzing $REPO_URL..."
insect clone "$REPO_URL" \
    --scan-args "--format json --severity medium" \
    --report-path "$REPORT_DIR/analysis_${TIMESTAMP}.json"

# Check for critical issues
if grep -q '"severity": "critical"' "$REPORT_DIR/analysis_${TIMESTAMP}.json"; then
    echo "❌ Critical security issues found - ABORT"
    exit 1
else
    echo "✅ No critical issues detected"
    exit 0
fi
```

## Threat Scenarios

### Supply Chain Attacks
**Scenario**: Compromised legitimate package with hidden malicious code

```bash
# Deep analysis of suspicious package update
insect clone https://github.com/popular/package --branch v2.1.0 --scan-args "--sensitivity very_high"

# Compare against known good version
insect clone https://github.com/popular/package --branch v2.0.0 --report-path baseline.json
insect clone https://github.com/popular/package --branch v2.1.0 --report-path comparison.json
```

### Typosquatting
**Scenario**: Malicious package with name similar to popular library

```bash
# Analyze suspicious package with similar name
insect clone https://github.com/author/reqeusts --scan-args "--sensitivity high" --report-path typosquat-analysis.json
# Note: "reqeusts" vs legitimate "requests"
```

### Browser Stealers
**Scenario**: Repository containing browser data theft code

```bash
# Comprehensive browser security analysis
insect clone https://github.com/suspicious/browser-tool --scan-args "--sensitivity very_high --format html" --report-path browser-stealer-analysis.html
```

### Cryptocurrency Theft
**Scenario**: Repository designed to steal crypto wallets

```bash
# Crypto wallet security analysis
insect clone https://github.com/crypto/tool --scan-args "--sensitivity very_high" --report-path crypto-theft-analysis.json
```

### Fake Security Tools
**Scenario**: Malicious repository posing as security tool

```bash
# Analysis of supposed security scanner
insect clone https://github.com/security/scanner --scan-args "--sensitivity very_high --format html" --report-path fake-tool-analysis.html
```

## Best Practices

### Regular Monitoring
```bash
# Set up regular scans of critical dependencies
#!/bin/bash
DEPENDENCIES=(
    "https://github.com/critical/lib1"
    "https://github.com/important/lib2"
    "https://github.com/essential/lib3"
)

for repo in "${DEPENDENCIES[@]}"; do
    echo "Scanning $repo..."
    insect clone "$repo" --scan-args "--format json" --report-path "reports/$(basename $repo)-$(date +%Y%m%d).json"
done
```

### Documentation Standards
```bash
# Generate standardized security assessment
insect clone https://github.com/vendor/tool --scan-args "--format html" --report-path "assessments/vendor-tool-security-$(date +%Y%m%d).html"

# Include metadata in reports
echo "Assessment Date: $(date)" >> "assessments/vendor-tool-metadata.txt"
echo "Analyst: $(whoami)" >> "assessments/vendor-tool-metadata.txt"
echo "Repository: https://github.com/vendor/tool" >> "assessments/vendor-tool-metadata.txt"
```

### Risk Assessment Matrix
| Severity | Action Required | Timeline |
|----------|----------------|----------|
| Critical | Block immediately | Immediate |
| High | Security review | 24 hours |
| Medium | Team evaluation | 1 week |
| Low | Document findings | As needed |

### Team Communication
```bash
# Generate team-friendly reports
insect clone https://github.com/vendor/library --scan-args "--format html" --report-path "reports/vendor-library-team-review.html"

# Create executive summary
echo "Security Assessment Summary" > executive-summary.txt
echo "Repository: vendor/library" >> executive-summary.txt
echo "Assessment Date: $(date)" >> executive-summary.txt
echo "Critical Issues: $(grep -c '"severity": "critical"' analysis.json)" >> executive-summary.txt
```

## Troubleshooting

### Common Issues

**Docker Not Available**
```bash
# Check Docker installation
docker --version

# Start Docker service (Linux)
sudo systemctl start docker

# Verify Docker permissions
docker run hello-world
```

**Repository Access Issues**
```bash
# Private repositories require authentication
git config --global credential.helper store

# Use personal access tokens for GitHub
export GITHUB_TOKEN="your_token_here"
```

**Analysis Failures**
```bash
# Increase timeout for large repositories
insect clone https://github.com/large/repo --scan-args "--timeout 600"

# Use custom Docker image with more tools
insect clone https://github.com/example/repo --image my-security-scanner:latest
```

**False Positives**
```bash
# Adjust sensitivity to reduce noise
insect clone https://github.com/clean/repo --scan-args "--sensitivity low"

# Use allowlist for known false positives
# (Configure in insect configuration file)
```

### Performance Optimization

**Large Repositories**
```bash
# Analyze specific directories only
insect clone https://github.com/huge/repo --scan-args "--include-pattern 'src/*'"

# Skip binary files
insect clone https://github.com/binary/repo --scan-args "--exclude-pattern '*.bin'"
```

**Batch Processing**
```bash
#!/bin/bash
# Process multiple repositories efficiently

REPOS_FILE="repositories.txt"
WORKERS=4

parallel -j$WORKERS --colsep ' ' \
    'insect clone {1} --report-path reports/{2}-{#}.json' \
    :::: "$REPOS_FILE"
```

## Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions workflow
name: Dependency Security Scan

on:
  pull_request:
    paths:
      - 'package.json'
      - 'requirements.txt'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Insect
        run: pip install insect
        
      - name: Scan new dependencies
        run: |
          # Extract and scan new dependencies
          ./scripts/scan-new-deps.sh
          
      - name: Upload security report
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: security-reports/
```

### Enterprise Integration
```bash
# Integration with security information and event management (SIEM)
insect clone https://github.com/vendor/tool --scan-args "--format json" --report-path analysis.json

# Send to SIEM system
curl -X POST https://siem.company.com/api/security-events \
    -H "Content-Type: application/json" \
    -d @analysis.json
```

---

*For more specific use cases, see [Dependency Vetting](dependency-vetting.md) and [Use Cases](use_cases.md).*