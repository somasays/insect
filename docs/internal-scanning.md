---
layout: page
title: Internal Code Scanning
nav_order: 7
---

# Internal Code Scanning

This guide covers Insect's **secondary use case**: analyzing your own code repositories for security issues and code quality improvements. While Insect's primary purpose is [external repository scanning](external-scanning.md), it also provides valuable capabilities for internal development workflows.

## Table of Contents

- [Overview](#overview)
- [When to Use Internal Scanning](#when-to-use-internal-scanning)
- [Basic Local Scanning](#basic-local-scanning)
- [Development Integration](#development-integration)
- [Team Workflows](#team-workflows)
- [CI/CD Integration](#cicd-integration)
- [Configuration for Internal Use](#configuration-for-internal-use)
- [Best Practices](#best-practices)

## Overview

Internal scanning with Insect helps development teams:
- **Identify security vulnerabilities** in their own code
- **Maintain code quality standards** across projects
- **Integrate security checks** into development workflows
- **Prepare for security audits** and compliance requirements

**Note**: For maximum security benefit, focus on [external repository scanning](external-scanning.md) to protect against supply chain attacks and malicious dependencies.

## When to Use Internal Scanning

### Appropriate Use Cases
- **Code quality audits** before releases
- **Security compliance** requirements
- **Pre-commit hooks** for development workflows
- **Legacy code assessment** during refactoring
- **Training and education** on secure coding practices

### Not Recommended For
- **Analyzing untrusted external code** (use `insect clone` instead)
- **Evaluating third-party dependencies** (use external scanning)
- **Investigating suspicious repositories** (use container-based analysis)

## Basic Local Scanning

### Simple Local Analysis

```bash
# Basic scan of current project
insect scan .

# Scan specific directory
insect scan ./src

# Generate HTML report for detailed analysis
insect scan . --format html --output security-report.html

# High sensitivity analysis for comprehensive review
insect scan . --sensitivity high --severity medium
```

### Project-Specific Scanning

```bash
# JavaScript/Node.js project
insect scan . \
    --exclude-pattern "node_modules/*" \
    --exclude-pattern "dist/*" \
    --include-pattern "*.js" \
    --include-pattern "*.ts"

# Python project
insect scan . \
    --exclude-pattern "venv/*" \
    --exclude-pattern "__pycache__/*" \
    --exclude-pattern "*.pyc" \
    --include-pattern "*.py"

# Go project
insect scan . \
    --exclude-pattern "vendor/*" \
    --exclude-pattern "*.mod" \
    --include-pattern "*.go"
```

## Development Integration

### Pre-commit Hooks

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: insect-security-scan
        name: Insect Security Scan
        entry: insect scan
        args: [--severity, medium, --no-progress]
        language: system
        pass_filenames: false
        stages: [commit]
```

Install and use:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Test hooks
pre-commit run --all-files
```

### Git Hooks Integration

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Pre-commit security scan

echo "🔍 Running security scan..."

# Run Insect scan
insect scan . --severity medium --no-progress --format json > /tmp/scan-results.json

# Check for critical or high severity issues
CRITICAL=$(grep -c '"severity": "critical"' /tmp/scan-results.json 2>/dev/null || echo "0")
HIGH=$(grep -c '"severity": "high"' /tmp/scan-results.json 2>/dev/null || echo "0")

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Commit blocked: $CRITICAL critical security issues found"
    echo "Run 'insect scan . --format html -o report.html' for details"
    exit 1
elif [ "$HIGH" -gt 3 ]; then
    echo "⚠️  Warning: $HIGH high-severity issues found"
    echo "Consider addressing these issues before committing"
fi

echo "✅ Security scan passed"
```

Make executable:

```bash
chmod +x .git/hooks/pre-commit
```

### IDE Integration

#### VS Code Integration

Create `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Insect Security Scan",
            "type": "shell",
            "command": "insect",
            "args": ["scan", ".", "--format", "json"],
            "group": {
                "kind": "test",
                "isDefault": true
            },
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            },
            "problemMatcher": []
        }
    ]
}
```

#### Custom Script for Development

```bash
#!/bin/bash
# dev-security-check.sh

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
REPORT_DIR="$PROJECT_ROOT/.insect-reports"

mkdir -p "$REPORT_DIR"

echo "🔍 Running development security scan..."

# Quick scan for immediate feedback
insect scan "$PROJECT_ROOT" \
    --severity medium \
    --format json \
    --output "$REPORT_DIR/dev-scan-$(date +%Y%m%d_%H%M%S).json"

# Parse results for developer feedback
LATEST_REPORT=$(ls -t "$REPORT_DIR"/dev-scan-*.json | head -1)

if [ -f "$LATEST_REPORT" ]; then
    CRITICAL=$(grep -c '"severity": "critical"' "$LATEST_REPORT" || echo "0")
    HIGH=$(grep -c '"severity": "high"' "$LATEST_REPORT" || echo "0")
    MEDIUM=$(grep -c '"severity": "medium"' "$LATEST_REPORT" || echo "0")
    
    echo "📊 Security Summary:"
    echo "   Critical: $CRITICAL"
    echo "   High: $HIGH"
    echo "   Medium: $MEDIUM"
    
    if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Critical issues require immediate attention"
        exit 1
    elif [ "$HIGH" -gt 0 ]; then
        echo "⚠️  High-priority issues should be addressed"
        exit 2
    else
        echo "✅ No critical security issues found"
    fi
fi
```

## Team Workflows

### Code Review Integration

```bash
#!/bin/bash
# security-review.sh - For pull request reviews

PR_BRANCH="$1"
BASE_BRANCH="${2:-main}"

if [ -z "$PR_BRANCH" ]; then
    echo "Usage: $0 <pr-branch> [base-branch]"
    exit 1
fi

echo "🔍 Security review for PR: $PR_BRANCH"

# Scan PR branch
git checkout "$PR_BRANCH"
insect scan . --format json --output "pr-scan.json"

# Scan base branch
git checkout "$BASE_BRANCH"
insect scan . --format json --output "base-scan.json"

# Compare results (simplified)
PR_ISSUES=$(grep -c '"severity":' pr-scan.json 2>/dev/null || echo "0")
BASE_ISSUES=$(grep -c '"severity":' base-scan.json 2>/dev/null || echo "0")

echo "📊 Security Comparison:"
echo "   Base branch issues: $BASE_ISSUES"
echo "   PR branch issues: $PR_ISSUES"

if [ "$PR_ISSUES" -gt "$BASE_ISSUES" ]; then
    NEW_ISSUES=$((PR_ISSUES - BASE_ISSUES))
    echo "⚠️  $NEW_ISSUES new security issues introduced"
    
    # Generate detailed report for review
    insect scan . --format html --output "pr-security-review.html"
    echo "📄 Detailed report: pr-security-review.html"
fi

# Cleanup
rm -f pr-scan.json base-scan.json
git checkout "$PR_BRANCH"
```

### Release Security Checks

```bash
#!/bin/bash
# release-security-check.sh

VERSION="$1"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "🔍 Security check for release $VERSION"

# Comprehensive scan for release
insect scan . \
    --sensitivity high \
    --format html \
    --output "security-report-$VERSION.html"

# JSON for automated processing
insect scan . \
    --sensitivity high \
    --format json \
    --output "security-data-$VERSION.json"

# Check for blocking issues
CRITICAL=$(grep -c '"severity": "critical"' "security-data-$VERSION.json" || echo "0")
HIGH=$(grep -c '"severity": "high"' "security-data-$VERSION.json" || echo "0")

echo "📊 Release Security Summary:"
echo "   Critical: $CRITICAL"
echo "   High: $HIGH"

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ RELEASE BLOCKED: Critical security issues must be resolved"
    exit 1
elif [ "$HIGH" -gt 5 ]; then
    echo "⚠️  REVIEW REQUIRED: High number of high-severity issues"
    exit 2
else
    echo "✅ RELEASE APPROVED: No blocking security issues"
fi
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Internal Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install Insect
      run: pip install insect
    
    - name: Run security scan
      run: |
        insect scan . \
          --format json \
          --output security-results.json \
          --severity medium
    
    - name: Check for blocking issues
      run: |
        CRITICAL=$(grep -c '"severity": "critical"' security-results.json || echo "0")
        HIGH=$(grep -c '"severity": "high"' security-results.json || echo "0")
        
        echo "Critical issues: $CRITICAL"
        echo "High issues: $HIGH"
        
        if [ "$CRITICAL" -gt 0 ]; then
          echo "❌ Build failed: Critical security issues found"
          exit 1
        fi
    
    - name: Upload security report
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: security-results.json
        
    - name: Comment PR with results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));
          const findings = results.findings || [];
          
          const critical = findings.filter(f => f.severity === 'critical').length;
          const high = findings.filter(f => f.severity === 'high').length;
          const medium = findings.filter(f => f.severity === 'medium').length;
          
          const comment = `## 🔍 Security Scan Results
          
          - **Critical**: ${critical}
          - **High**: ${high}  
          - **Medium**: ${medium}
          
          ${critical > 0 ? '❌ Critical issues must be resolved before merge' : '✅ No critical issues found'}`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: comment
          });
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Install Insect
                    sh 'pip install insect'
                    
                    // Run security scan
                    sh '''
                        insect scan . \
                            --format json \
                            --output security-results.json \
                            --severity medium
                    '''
                    
                    // Parse results
                    def results = readJSON file: 'security-results.json'
                    def findings = results.findings ?: []
                    
                    def critical = findings.count { it.severity == 'critical' }
                    def high = findings.count { it.severity == 'high' }
                    
                    echo "Security scan complete: ${critical} critical, ${high} high"
                    
                    if (critical > 0) {
                        error("Build failed: Critical security issues found")
                    }
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json', fingerprint: true
                }
            }
        }
    }
}
```

## Configuration for Internal Use

### Project-Specific Configuration

Create `insect.toml` in your project root:

```toml
# Internal scanning configuration

[general]
max_depth = 10
include_hidden = false

[analyzers]
static = true
config = true
binary = false  # Usually not needed for internal code
metadata = true
secrets = true
browser_theft = true
crypto_wallet = true

[patterns]
include = ["*"]
exclude = [
    "*.git/*",
    "node_modules/*",
    "venv/*", 
    ".venv/*",
    "build/*",
    "dist/*",
    "*.pyc",
    "__pycache__/*",
    "*.min.js",
    "*.min.css",
    "coverage/*",
    "*.log"
]

[severity]
min_level = "medium"  # Focus on actionable issues

[sensitivity]
level = "normal"  # Balanced approach for internal code

# Allow certain patterns common in development
[allowlist]
findings = [
    # Add specific finding IDs to ignore
]

# Optimize for development workflow
[progress]
enabled = true

[cache]
enabled = true
cleanup_enabled = true
max_age_days = 7  # Shorter for active development
```

### Language-Specific Configurations

#### JavaScript/TypeScript Projects

```toml
# insect-js.toml

[patterns]
include = ["*.js", "*.ts", "*.jsx", "*.tsx", "*.json"]
exclude = [
    "node_modules/*",
    "dist/*",
    "build/*",
    "*.min.js",
    "*.bundle.js",
    "coverage/*"
]

[analyzers]
static = true
secrets = true
config = true
browser_theft = true  # Important for web applications
```

#### Python Projects

```toml
# insect-python.toml

[patterns]
include = ["*.py", "*.pyi", "requirements*.txt", "setup.py", "setup.cfg"]
exclude = [
    "venv/*",
    ".venv/*",
    "__pycache__/*",
    "*.pyc",
    "build/*",
    "dist/*",
    "*.egg-info/*"
]

[analyzers]
static = true
secrets = true
config = true
```

## Best Practices

### Development Workflow

1. **Regular scanning** during development cycles
2. **Pre-commit hooks** for immediate feedback
3. **CI/CD integration** for automated quality gates
4. **Team training** on security findings interpretation

### Performance Optimization

```bash
# Focus on source code only
insect scan ./src --exclude-pattern "tests/*"

# Skip large generated files
insect scan . --exclude-pattern "*.bundle.js" --exclude-pattern "*.min.*"

# Use caching for faster re-scans
insect scan . --no-clear-cache

# Targeted scanning for specific file types
insect scan . --include-pattern "*.py" --include-pattern "*.js"
```

### False Positive Management

```toml
# In insect.toml
[allowlist]
findings = [
    "PY-103-abc123",  # Known false positive in test file
    "JS-104-def456"   # Acceptable risk in development code
]

files = [
    "tests/test_security.py",  # Test files with intentional vulnerabilities
    "examples/vulnerable.js"   # Example code with known issues
]
```

### Team Guidelines

1. **Establish severity thresholds** for different contexts
2. **Document security decisions** and allowlist rationale
3. **Regular configuration updates** based on team needs
4. **Balance security and productivity** in development workflows

## Integration with Security Tools

### Combining with Other Scanners

```bash
#!/bin/bash
# multi-scanner.sh - Comprehensive security analysis

echo "🔍 Running comprehensive security analysis..."

# Insect scan
insect scan . --format json --output insect-results.json

# Bandit (Python)
if command -v bandit &> /dev/null && find . -name "*.py" | head -1; then
    bandit -r . -f json -o bandit-results.json 2>/dev/null || true
fi

# ESLint security plugin (JavaScript)
if [ -f "package.json" ] && command -v eslint &> /dev/null; then
    eslint . --format json > eslint-results.json 2>/dev/null || true
fi

# Semgrep
if command -v semgrep &> /dev/null; then
    semgrep --config=auto --json --output=semgrep-results.json . 2>/dev/null || true
fi

echo "✅ Analysis complete. Check *-results.json files for details."
```

### SIEM Integration

```bash
# Convert Insect results to SIEM format
python3 << 'EOF'
import json
import sys
from datetime import datetime

with open('security-results.json') as f:
    data = json.load(f)

for finding in data.get('findings', []):
    siem_event = {
        'timestamp': datetime.now().isoformat(),
        'source': 'insect_internal_scan',
        'severity': finding['severity'],
        'category': 'code_security',
        'description': finding['title'],
        'file_path': finding.get('location', {}).get('path', ''),
        'project': data.get('scan_metadata', {}).get('repository', ''),
        'finding_id': finding['id']
    }
    print(json.dumps(siem_event))
EOF
```

---

**Note**: Remember that Insect's primary strength is in [external repository scanning](external-scanning.md) for supply chain security. Internal scanning should complement, not replace, your primary security practices focused on external threat detection.

*For comprehensive security coverage, see [External Scanning](external-scanning.md) and [Dependency Vetting](dependency-vetting.md).*