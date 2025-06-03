---
layout: page
title: Dependency Vetting
nav_order: 3
---

# Dependency Vetting with Insect

This guide focuses on using Insect for **security teams and developers** to safely vet external dependencies, third-party libraries, and open-source packages before integration into projects.

## Table of Contents

- [Overview](#overview)
- [Vetting Workflow](#vetting-workflow)
- [Security Team Processes](#security-team-processes)
- [Developer Integration](#developer-integration)
- [Ecosystem-Specific Guidance](#ecosystem-specific-guidance)
- [Automated Vetting](#automated-vetting)
- [Risk Assessment](#risk-assessment)
- [Compliance and Documentation](#compliance-and-documentation)

## Overview

Dependency vetting helps organizations:
- **Prevent supply chain attacks** through compromised packages
- **Identify malicious libraries** before they enter production
- **Document security assessments** for compliance requirements
- **Establish secure development practices** across teams

## Vetting Workflow

### Basic Vetting Process

```bash
# Step 1: Analyze dependency source repository
insect clone https://github.com/vendor/library --report-path dependency-analysis.json

# Step 2: Review security findings
# Insect will show threats, malware, and vulnerabilities

# Step 3: Make approval decision based on findings
# - No critical issues: Approve for use
# - Critical issues: Reject or investigate further
# - Medium/Low issues: Document and mitigate
```

### Comprehensive Vetting

```bash
# High-sensitivity analysis for thorough evaluation
insect clone https://github.com/suspicious/package \
    --scan-args "--sensitivity very_high --format html" \
    --report-path comprehensive-analysis.html

# Analyze specific version/release
insect clone https://github.com/vendor/library \
    --branch v2.1.0 \
    --report-path version-2.1.0-assessment.json

# Compare versions for security regressions
insect clone https://github.com/vendor/library --branch v2.0.0 --report-path baseline.json
insect clone https://github.com/vendor/library --branch v2.1.0 --report-path candidate.json
```

## Security Team Processes

### Initial Assessment

```bash
#!/bin/bash
# Security team vetting script

REPO_URL="$1"
PACKAGE_NAME=$(basename "$1" .git)
ASSESSMENT_DIR="./security-assessments/$PACKAGE_NAME"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$ASSESSMENT_DIR"

echo "🔍 Starting security assessment of $PACKAGE_NAME..."

# Comprehensive analysis
insect clone "$REPO_URL" \
    --scan-args "--sensitivity very_high --format html" \
    --report-path "$ASSESSMENT_DIR/analysis_${TIMESTAMP}.html"

# JSON for automated processing
insect clone "$REPO_URL" \
    --scan-args "--sensitivity very_high --format json" \
    --report-path "$ASSESSMENT_DIR/analysis_${TIMESTAMP}.json"

# Risk assessment
CRITICAL_COUNT=$(grep -c '"severity": "critical"' "$ASSESSMENT_DIR/analysis_${TIMESTAMP}.json" || echo "0")
HIGH_COUNT=$(grep -c '"severity": "high"' "$ASSESSMENT_DIR/analysis_${TIMESTAMP}.json" || echo "0")

echo "📊 Assessment Summary:"
echo "   Critical Issues: $CRITICAL_COUNT"
echo "   High Issues: $HIGH_COUNT"

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "❌ REJECT: Critical security issues found"
    exit 1
elif [ "$HIGH_COUNT" -gt 3 ]; then
    echo "⚠️  REVIEW: Multiple high-severity issues require evaluation"
    exit 2
else
    echo "✅ APPROVE: No critical issues detected"
    exit 0
fi
```

### Vendor Assessment Workflow

```bash
# Comprehensive vendor package evaluation
VENDOR="example-corp"
PACKAGE="security-tool"

# Create structured assessment
mkdir -p "assessments/$VENDOR"

# Analyze main package
insect clone "https://github.com/$VENDOR/$PACKAGE" \
    --scan-args "--format html --sensitivity high" \
    --report-path "assessments/$VENDOR/${PACKAGE}-security-assessment.html"

# Analyze documentation and examples
insect clone "https://github.com/$VENDOR/$PACKAGE" \
    --scan-args "--include-pattern 'examples/*' --include-pattern 'docs/*'" \
    --report-path "assessments/$VENDOR/${PACKAGE}-docs-analysis.json"

# Generate executive summary
cat > "assessments/$VENDOR/${PACKAGE}-summary.md" << EOF
# Security Assessment: $VENDOR/$PACKAGE

**Assessment Date:** $(date)
**Analyst:** $(whoami)
**Repository:** https://github.com/$VENDOR/$PACKAGE

## Risk Level
[To be filled based on analysis]

## Key Findings
[To be filled based on analysis]

## Recommendation
[To be filled based on analysis]
EOF
```

### Regular Monitoring

```bash
#!/bin/bash
# Monitor approved dependencies for new threats

APPROVED_DEPS=(
    "https://github.com/vendor1/lib1"
    "https://github.com/vendor2/lib2"
    "https://github.com/vendor3/lib3"
)

MONITOR_DIR="./security-monitoring/$(date +%Y%m)"
mkdir -p "$MONITOR_DIR"

for repo in "${APPROVED_DEPS[@]}"; do
    package_name=$(basename "$repo" .git)
    echo "🔄 Monitoring $package_name for security changes..."
    
    insect clone "$repo" \
        --scan-args "--sensitivity high --format json" \
        --report-path "$MONITOR_DIR/${package_name}-$(date +%Y%m%d).json"
        
    # Alert on new critical issues
    if grep -q '"severity": "critical"' "$MONITOR_DIR/${package_name}-$(date +%Y%m%d).json"; then
        echo "🚨 ALERT: New critical issues found in $package_name"
        # Send notification to security team
    fi
done
```

## Developer Integration

### Pre-Integration Checks

```bash
# Developer workflow for adding new dependencies

# 1. Quick safety check before detailed evaluation
insect clone https://github.com/author/new-library --scan-args "--severity medium"

# 2. If initial check passes, generate report for team review
insect clone https://github.com/author/new-library \
    --scan-args "--format html --sensitivity high" \
    --report-path new-library-security-review.html

# 3. Document decision
echo "Library: new-library" >> dependency-decisions.log
echo "Date: $(date)" >> dependency-decisions.log
echo "Decision: [APPROVED/REJECTED/CONDITIONAL]" >> dependency-decisions.log
echo "Justification: [reasoning]" >> dependency-decisions.log
echo "---" >> dependency-decisions.log
```

### IDE Integration

```bash
#!/bin/bash
# VS Code/IDE extension script for dependency vetting

dependency_url="$1"
if [ -z "$dependency_url" ]; then
    echo "Usage: $0 <github-url>"
    exit 1
fi

# Quick analysis
echo "🔍 Analyzing dependency security..."
insect clone "$dependency_url" --scan-args "--format json" > /tmp/dep_analysis.json

# Parse results
critical=$(grep -c '"severity": "critical"' /tmp/dep_analysis.json || echo "0")
high=$(grep -c '"severity": "high"' /tmp/dep_analysis.json || echo "0")

if [ "$critical" -gt 0 ]; then
    echo "❌ CRITICAL: $critical critical security issues found - DO NOT USE"
    exit 1
elif [ "$high" -gt 0 ]; then
    echo "⚠️  WARNING: $high high-severity issues found - review required"
    exit 2
else
    echo "✅ SAFE: No critical issues detected"
    exit 0
fi
```

## Ecosystem-Specific Guidance

### JavaScript/Node.js Ecosystem

```bash
# NPM package vetting
PACKAGE_NAME="suspicious-package"

# Analyze package source repository
insect clone "https://github.com/author/$PACKAGE_NAME" \
    --scan-args "--include-pattern '*.js' --include-pattern '*.json' --sensitivity high" \
    --report-path "npm-$PACKAGE_NAME-analysis.json"

# Check for common npm-specific threats
grep -E "(eval|Function|require.*http|child_process)" npm-$PACKAGE_NAME-analysis.json

# Browser-specific checks for client-side packages
insect clone "https://github.com/author/$PACKAGE_NAME" \
    --scan-args "--sensitivity very_high" \
    --report-path "browser-$PACKAGE_NAME-analysis.html"
```

### Python Ecosystem

```bash
# PyPI package vetting
PACKAGE_NAME="suspicious-python-lib"

# Analyze Python-specific threats
insect clone "https://github.com/author/$PACKAGE_NAME" \
    --scan-args "--include-pattern '*.py' --exclude-pattern 'tests/*' --sensitivity high" \
    --report-path "pypi-$PACKAGE_NAME-analysis.json"

# Check setup.py for malicious installation code
insect clone "https://github.com/author/$PACKAGE_NAME" \
    --scan-args "--include-pattern 'setup.py' --include-pattern 'setup.cfg' --sensitivity very_high" \
    --report-path "setup-$PACKAGE_NAME-analysis.json"
```

### Go Ecosystem

```bash
# Go module vetting
MODULE_PATH="github.com/author/go-module"

# Analyze Go-specific patterns
insect clone "https://$MODULE_PATH" \
    --scan-args "--include-pattern '*.go' --exclude-pattern '*_test.go' --sensitivity high" \
    --report-path "go-module-analysis.json"

# Check for unsafe operations
grep -E "(unsafe\.|reflect\.|exec\.)" go-module-analysis.json
```

### Docker/Container Images

```bash
# Container image source analysis
insect clone "https://github.com/vendor/docker-image" \
    --scan-args "--include-pattern 'Dockerfile*' --include-pattern '*.sh' --sensitivity high" \
    --report-path "container-image-analysis.html"

# Focus on Dockerfile security
insect clone "https://github.com/vendor/docker-image" \
    --scan-args "--include-pattern 'Dockerfile' --sensitivity very_high" \
    --report-path "dockerfile-security-analysis.json"
```

## Automated Vetting

### GitHub Actions Integration

```yaml
name: Dependency Security Vetting

on:
  pull_request:
    paths:
      - 'package.json'
      - 'requirements.txt'
      - 'go.mod'
      - 'Cargo.toml'

jobs:
  security-vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Install Insect
        run: pip install insect
        
      - name: Extract new dependencies
        id: deps
        run: |
          # Custom script to extract new dependencies from diff
          python3 .github/scripts/extract-new-deps.py > new_deps.txt
          
      - name: Vet dependencies
        run: |
          while read repo_url; do
            if [ ! -z "$repo_url" ]; then
              echo "Vetting $repo_url..."
              insect clone "$repo_url" --scan-args "--format json" --report-path "reports/$(basename $repo_url).json"
              
              # Check for critical issues
              if grep -q '"severity": "critical"' "reports/$(basename $repo_url).json"; then
                echo "❌ Critical issues found in $repo_url"
                exit 1
              fi
            fi
          done < new_deps.txt
          
      - name: Upload vetting reports
        uses: actions/upload-artifact@v2
        with:
          name: dependency-vetting-reports
          path: reports/
```

### Batch Processing

```bash
#!/bin/bash
# Batch process multiple dependencies

DEPENDENCIES_FILE="dependencies.txt"
REPORTS_DIR="./vetting-reports/$(date +%Y%m%d)"
PARALLEL_JOBS=4

mkdir -p "$REPORTS_DIR"

# Format: repository_url package_name
# Example: https://github.com/author/lib awesome-lib

parallel -j$PARALLEL_JOBS --colsep '\t' \
    'insect clone {1} --scan-args "--format json" --report-path "'$REPORTS_DIR'/{2}-analysis.json"' \
    :::: "$DEPENDENCIES_FILE"

# Generate summary report
echo "# Dependency Vetting Summary - $(date)" > "$REPORTS_DIR/summary.md"
echo "" >> "$REPORTS_DIR/summary.md"

for report in "$REPORTS_DIR"/*.json; do
    package=$(basename "$report" -analysis.json)
    critical=$(grep -c '"severity": "critical"' "$report" || echo "0")
    high=$(grep -c '"severity": "high"' "$report" || echo "0")
    
    if [ "$critical" -gt 0 ]; then
        status="❌ REJECT"
    elif [ "$high" -gt 2 ]; then
        status="⚠️  REVIEW"
    else
        status="✅ APPROVE"
    fi
    
    echo "- **$package**: $status (Critical: $critical, High: $high)" >> "$REPORTS_DIR/summary.md"
done
```

## Risk Assessment

### Risk Matrix

| Severity | Threat Type | Action | Timeline |
|----------|-------------|--------|----------|
| Critical | Malware, Stealers | Block immediately | Immediate |
| High | Vulnerabilities | Security review | 24 hours |
| Medium | Code quality | Team evaluation | 1 week |
| Low | Minor issues | Document | As needed |

### Assessment Criteria

```bash
#!/bin/bash
# Automated risk scoring

ANALYSIS_FILE="$1"

# Count findings by severity
CRITICAL=$(grep -c '"severity": "critical"' "$ANALYSIS_FILE" || echo "0")
HIGH=$(grep -c '"severity": "high"' "$ANALYSIS_FILE" || echo "0")
MEDIUM=$(grep -c '"severity": "medium"' "$ANALYSIS_FILE" || echo "0")

# Calculate risk score (weighted)
RISK_SCORE=$((CRITICAL * 10 + HIGH * 3 + MEDIUM * 1))

echo "Risk Assessment:"
echo "Critical: $CRITICAL"
echo "High: $HIGH"
echo "Medium: $MEDIUM"
echo "Risk Score: $RISK_SCORE"

if [ "$RISK_SCORE" -ge 10 ]; then
    echo "Risk Level: HIGH - Reject"
    exit 1
elif [ "$RISK_SCORE" -ge 5 ]; then
    echo "Risk Level: MEDIUM - Review Required"
    exit 2
else
    echo "Risk Level: LOW - Approved"
    exit 0
fi
```

## Compliance and Documentation

### Audit Trail

```bash
#!/bin/bash
# Generate compliance documentation

PACKAGE="$1"
ASSESSMENT_FILE="$2"

cat > "compliance-${PACKAGE}.md" << EOF
# Security Assessment Report: $PACKAGE

## Assessment Metadata
- **Date**: $(date)
- **Analyst**: $(whoami)
- **Tool**: Insect Security Scanner
- **Assessment ID**: $(uuidgen)

## Risk Assessment
$(python3 -c "
import json
with open('$ASSESSMENT_FILE') as f:
    data = json.load(f)
    findings = data.get('findings', [])
    critical = len([f for f in findings if f.get('severity') == 'critical'])
    high = len([f for f in findings if f.get('severity') == 'high'])
    print(f'- Critical Issues: {critical}')
    print(f'- High Issues: {high}')
")

## Security Findings
[Detailed findings from analysis]

## Recommendation
[APPROVED/REJECTED/CONDITIONAL]

## Approval Chain
- Security Analyst: [Name]
- Security Manager: [Name]
- Date Approved: [Date]

## Review Schedule
Next review due: $(date -d '+6 months' +%Y-%m-%d)
EOF
```

### Integration with Security Tools

```bash
# Export to SIEM/Security Dashboard
ASSESSMENT_FILE="$1"

# Convert to SIEM format
python3 << EOF
import json
import sys

with open('$ASSESSMENT_FILE') as f:
    data = json.load(f)

# Convert to security event format
for finding in data.get('findings', []):
    event = {
        'timestamp': data['scan_metadata']['timestamp'],
        'event_type': 'dependency_security_finding',
        'severity': finding['severity'],
        'description': finding['title'],
        'source': 'insect_scanner',
        'package': data['scan_metadata']['repository']
    }
    print(json.dumps(event))
EOF
```

## Best Practices

### Team Workflows

1. **Establish clear vetting procedures**
2. **Document all security decisions**
3. **Regular review of approved dependencies**
4. **Automated alerts for new threats**
5. **Training on threat identification**

### Technical Guidelines

1. **Use high sensitivity for unknown packages**
2. **Always analyze source repositories, not just packages**
3. **Check multiple versions for consistency**
4. **Maintain audit trails for compliance**
5. **Integrate with existing security tools**

### Risk Management

1. **Classify dependencies by risk level**
2. **Establish approval workflows**
3. **Regular re-assessment schedules**
4. **Incident response for compromised packages**
5. **Vendor security requirements**

---

*For more information, see [External Scanning Guide](external-scanning.md) and [Use Cases](use_cases.md).*