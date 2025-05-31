---
layout: page
title: Use Cases
nav_order: 4
---

# Insect Use Cases

This document provides real-world use cases for Insect in different environments and scenarios.

## Table of Contents

- [DevSecOps Integration](#devsecops-integration)
- [Third-Party Code Validation](#third-party-code-validation)
- [Corporate Security Compliance](#corporate-security-compliance)
- [Continuous Security Monitoring](#continuous-security-monitoring)
- [Browser Security Protection](#browser-security-protection)
- [Security Education](#security-education)

## DevSecOps Integration

Incorporating security into the development process from the beginning.

### Use Case: Pre-Commit Code Scanning

**Scenario**: A development team wants to prevent security issues from being committed to the codebase.

**Implementation**:

1. Install pre-commit:
   ```bash
   pip install pre-commit
   ```

2. Create a `.pre-commit-config.yaml` file:
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

3. Install the pre-commit hook:
   ```bash
   pre-commit install
   ```

**Benefits**:
- Security issues are identified before code is committed
- Immediate feedback loop for developers
- Prevents security vulnerabilities from entering the codebase

### Use Case: Pipeline Integration

**Scenario**: An organization wants to enforce security standards across all repositories.

**Implementation**:

1. Create a centralized security scanning pipeline in your CI/CD system

2. Configure it to run Insect with organization-wide rules:
   ```bash
   insect scan . -f json -o scan-results.json --config /path/to/org-rules.toml
   ```

3. Set up automatic failure for critical issues:
   ```bash
   if grep -q '"severity": "critical"' scan-results.json; then
       echo "Critical security issues found!"
       exit 1
   fi
   ```

4. Archive results for audit purposes

**Benefits**:
- Consistent security standards across all projects
- Automatic enforcement of security policies
- Historical security data for compliance and auditing

## Third-Party Code Validation

Assessing the security of external code before integration.

### Use Case: Dependency Screening

**Scenario**: A team needs to evaluate the security of a JavaScript library before adding it as a dependency.

**Implementation**:

1. Clone the library's repository:
   ```bash
   git clone https://github.com/example/library.git
   cd library
   ```

2. Run a comprehensive Insect scan:
   ```bash
   insect scan . -f html -o library-security-report.html
   ```

3. Review the security findings and make an informed decision

**Benefits**:
- Identifies potential security risks before integration
- Provides documentation for security reviews
- Helps avoid introducing vulnerabilities through dependencies

### Use Case: Open Source Contribution Validation

**Scenario**: A project maintainer needs to review security aspects of a pull request.

**Implementation**:

1. Check out the PR branch:
   ```bash
   git fetch origin pull/123/head:pr-123
   git checkout pr-123
   ```

2. Run a focused scan on the changes:
   ```bash
   git diff --name-only main... | xargs insect scan -f json -o pr-security.json
   ```

3. Review findings before merging

**Benefits**:
- Ensures contributions maintain security standards
- Provides objective security assessment of changes
- Streamlines security review process

## Corporate Security Compliance

Meeting organizational security requirements.

### Use Case: Compliance Auditing

**Scenario**: A company needs to demonstrate security controls for regulatory compliance.

**Implementation**:

1. Create a compliance-focused configuration:
   ```toml
   # compliance.toml
   [general]
   include_hidden = true
   
   [analyzers]
   secrets = true
   
   [severity]
   min_level = "low"
   ```

2. Schedule regular scans with detailed reports:
   ```bash
   insect scan /path/to/codebase -f html -o compliance-report.html --config compliance.toml
   ```

3. Store reports securely for audit trail

**Benefits**:
- Documentation for compliance audits
- Systematic approach to security validation
- Evidence of security controls

### Use Case: Security Policy Enforcement

**Scenario**: An organization needs to enforce specific security policies across all projects.

**Implementation**:

1. Define organization-wide rules in a custom configuration
   
2. Add custom rules for organization-specific policies
   
3. Distribute the configuration to all development teams
   
4. Require successful Insect scans before deployment approval

**Benefits**:
- Consistent security policies across projects
- Automated enforcement of security standards
- Reduced security review time

## Continuous Security Monitoring

Ongoing surveillance for security issues.

### Use Case: Nightly Security Scans

**Scenario**: A team wants to monitor repositories for security regressions.

**Implementation**:

1. Set up a scheduled job to run nightly:
   ```bash
   # crontab entry
   0 2 * * * cd /path/to/repo && insect scan . -f json -o /path/to/reports/scan-$(date +\%Y\%m\%d).json
   ```

2. Implement a script to compare results and alert on new issues:
   ```bash
   #!/bin/bash
   TODAY=$(date +%Y%m%d)
   YESTERDAY=$(date -d "yesterday" +%Y%m%d)
   
   NEW_ISSUES=$(diff-json /path/to/reports/scan-$YESTERDAY.json /path/to/reports/scan-$TODAY.json)
   
   if [[ -n "$NEW_ISSUES" ]]; then
       send_alert "New security issues detected: $NEW_ISSUES"
   fi
   ```

**Benefits**:
- Rapid detection of new security issues
- Tracking of security posture over time
- Immediate notification of regressions

### Use Case: Branch Security Comparison

**Scenario**: A team wants to compare security profiles between branches.

**Implementation**:

1. Scan the main branch:
   ```bash
   git checkout main
   insect scan . -f json -o main-security.json
   ```

2. Scan the feature branch:
   ```bash
   git checkout feature-branch
   insect scan . -f json -o feature-security.json
   ```

3. Compare results:
   ```bash
   python -c "import json; \
              main = json.load(open('main-security.json')); \
              feature = json.load(open('feature-security.json')); \
              print(f'Main: {len(main[\"findings\"])} issues, Feature: {len(feature[\"findings\"])} issues')"
   ```

**Benefits**:
- Objective comparison between branches
- Visibility into security impact of changes
- Data for informed merge decisions

## Browser Security Protection

Protecting users from malicious repositories that attempt to steal browser data.

### Use Case: Browser Extension Security Review

**Scenario**: A security team needs to evaluate browser extensions before allowing them in the corporate environment.

**Implementation**:

1. Obtain the browser extension source code:
   ```bash
   git clone https://github.com/example/browser-extension.git
   cd browser-extension
   ```

2. Run Insect with browser theft detection enabled:
   ```bash
   insect scan . -f html -o extension-security-report.html --severity medium
   ```

3. Review specific browser security findings:
   - Check for unauthorized cookie access
   - Identify attempts to read browser storage
   - Flag suspicious extension API usage
   - Detect data exfiltration patterns

4. Create a security assessment report

**Benefits**:
- Identifies browser data theft attempts before deployment
- Provides detailed documentation for security reviews
- Helps maintain corporate browser security policies
- Protects users from malicious extensions

### Use Case: Open Source Repository Vetting

**Scenario**: A developer wants to verify that a GitHub repository doesn't contain browser theft code before cloning and running it locally.

**Implementation**:

1. Clone the repository in a safe environment:
   ```bash
   git clone https://github.com/suspicious/repository.git
   cd repository
   ```

2. Run a comprehensive browser security scan:
   ```bash
   insect scan . --config browser-security.toml -f json -o security-assessment.json
   ```

   Where `browser-security.toml` contains:
   ```toml
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
   ```

3. Review findings for browser data theft patterns:
   - Browser history/cookies access
   - Password extraction attempts
   - Session hijacking code
   - Storage manipulation
   - Data exfiltration

4. Make an informed decision about repository safety

**Benefits**:
- Protects against browser data theft before execution
- Provides security assessment of untrusted repositories
- Helps developers make informed decisions about code safety
- Reduces risk of exposing sensitive browser data

### Use Case: Web Application Security Scanning

**Scenario**: A web development team wants to ensure their application doesn't inadvertently include patterns that could be used for browser data theft.

**Implementation**:

1. Scan the web application codebase:
   ```bash
   insect scan ./webapp --include-pattern "*.js" --include-pattern "*.html" --include-pattern "*.php" -f html -o webapp-security.html
   ```

2. Review findings for potentially dangerous patterns:
   - Unsafe localStorage/sessionStorage usage
   - Unprotected cookie handling
   - XSS vulnerabilities that could lead to data theft
   - Client-side credential handling

3. Implement security fixes:
   - Add proper input sanitization
   - Use secure cookie attributes
   - Implement Content Security Policy (CSP)
   - Review data storage practices

4. Re-scan to verify improvements

**Benefits**:
- Prevents accidental implementation of dangerous patterns
- Ensures web applications follow browser security best practices
- Protects users from potential data theft
- Helps meet security compliance requirements

### Use Case: Supply Chain Security for Web Dependencies

**Scenario**: A company needs to verify that third-party JavaScript libraries don't contain browser data theft code.

**Implementation**:

1. Create a script to scan npm packages before installation:
   ```bash
   #!/bin/bash
   PACKAGE_NAME=$1
   TEMP_DIR=$(mktemp -d)
   
   # Download package source
   cd $TEMP_DIR
   npm pack $PACKAGE_NAME
   tar -xzf *.tgz
   
   # Scan for browser theft patterns
   insect scan package/ -f json -o package-security.json --severity medium
   
   # Check results
   if grep -q '"analyzer": "browser_theft"' package-security.json; then
       echo "WARNING: Browser theft patterns detected in $PACKAGE_NAME"
       cat package-security.json
       exit 1
   else
       echo "Package $PACKAGE_NAME appears safe for browser security"
   fi
   
   # Cleanup
   rm -rf $TEMP_DIR
   ```

2. Integrate into package installation workflow:
   ```bash
   ./check-package-security.sh suspicious-package
   npm install suspicious-package  # Only if security check passes
   ```

**Benefits**:
- Prevents installation of packages with browser theft capabilities
- Protects users from malicious npm packages
- Maintains supply chain security
- Provides automated security validation for dependencies

## Security Education

Using Insect as a learning tool.

### Use Case: Developer Training

**Scenario**: A company wants to improve developers' security awareness.

**Implementation**:

1. Create a collection of vulnerable code examples
   
2. Have developers scan the examples with Insect:
   ```bash
   insect scan ./vulnerable-examples -f html -o findings.html
   ```
   
3. Review findings and discuss remediation strategies

4. Apply fixes and rescan to verify improvement

**Benefits**:
- Hands-on security training
- Practical demonstration of vulnerabilities
- Immediate feedback on remediation efforts

### Use Case: Security Challenges

**Scenario**: A team wants to create security-focused coding challenges.

**Implementation**:

1. Create intentionally vulnerable projects with hidden security issues
   
2. Challenge developers to:
   - Find issues using Insect
   - Fix all issues of medium severity or higher
   - Verify with a clean scan
   
3. Track progress and celebrate improvements

**Benefits**:
- Gamifies security learning
- Builds practical security skills
- Reinforces secure coding practices