---
layout: page
title: Quick Start Guide
nav_order: 1
---

# Quick Start: External Repository Scanning

This guide helps you get started with Insect's primary use case: **safely analyzing external Git repositories**.

## Prerequisites

1. **Install Docker** (required for safe external repo analysis)
   ```bash
   # macOS
   brew install docker
   
   # Ubuntu/Debian
   sudo apt-get install docker.io
   
   # Or download from: https://docs.docker.com/get-docker/
   ```

2. **Install Insect**
   ```bash
   pip install insect
   ```

## Basic Workflow

### Step 1: Analyze Before Cloning
```bash
# Instead of directly cloning:
# git clone https://github.com/example/suspicious-repo  ❌

# Use Insect to analyze safely first:
insect clone https://github.com/example/suspicious-repo  ✅
```

### Step 2: Review Security Report
Insect will show you:
- Number of security issues found
- Severity levels (critical, high, medium, low)
- Types of threats detected
- Sample findings for review

### Step 3: Make Informed Decision
- **No issues found**: Repository appears safe to clone
- **Issues found**: Review details and decide whether to proceed
- **Critical issues**: Avoid cloning unless you understand the risks

### Step 4: Clone if Safe
If you choose to proceed, Insect will clone the repository locally.

## Common Scenarios

### Vetting a Dependency
```bash
# Analyze before adding to your project
insect clone https://github.com/author/library-name

# Generate detailed report for team review
insect clone https://github.com/author/library-name --report-path security-report.json
```

### Investigating Suspicious Code
```bash
# High sensitivity scan for comprehensive analysis
insect clone https://github.com/suspicious/repo --scan-args "--sensitivity very_high"

# Save detailed analysis
insect clone https://github.com/suspicious/repo --report-path investigation.json --scan-args "--format html"
```

### Security Research
```bash
# Analyze specific branch
insect clone https://github.com/research/malware-sample --branch malicious-branch

# Use custom Docker image with additional tools
insect clone https://github.com/research/sample --image my-analysis-env:latest
```

## Understanding Results

### Severity Levels
- **Critical**: Immediate security threats (malware, stealers)
- **High**: Serious vulnerabilities requiring attention
- **Medium**: Security issues that should be reviewed
- **Low**: Minor issues or potential improvements

### Common Threat Types
- **Browser Data Theft**: Cookie stealers, password extractors
- **Cryptocurrency Theft**: Wallet stealers, private key extractors
- **System Compromise**: Command injection, backdoors
- **Data Exfiltration**: Secret harvesters, API key stealers

## Safety Reminders

🚨 **Never run untrusted code directly**
🐳 **Always use Docker for external repository analysis**  
📊 **Review security reports before cloning**
🔍 **When in doubt, don't clone - investigate further**

## Troubleshooting

### Docker Not Available
If you see "Docker not available":
1. Install Docker following the prerequisites above
2. Start Docker service: `sudo systemctl start docker` (Linux)
3. Verify Docker works: `docker --version`

### Permission Denied
If you get permission errors:
```bash
# Add your user to docker group (Linux)
sudo usermod -aG docker $USER
# Logout and login again
```

### Network Issues
If repository cloning fails:
- Check internet connection
- Verify repository URL is correct
- Try with a public repository first

## Next Steps

- [External Scanning Guide](external-scanning.md) - Comprehensive workflows
- [Threat Detection Examples](threat-detection.md) - What Insect finds
- [Container Security](container-security.md) - Docker setup details
- [Dependency Vetting](dependency-vetting.md) - Team workflows

## Quick Reference

```bash
# Basic analysis
insect clone https://github.com/user/repo

# High sensitivity analysis
insect clone https://github.com/user/repo --scan-args "--sensitivity very_high"

# Save detailed report
insect clone https://github.com/user/repo --report-path analysis.json

# Analyze specific branch
insect clone https://github.com/user/repo --branch feature-branch

# Check dependencies status
insect deps
```

---

*Remember: Analyze first, trust later.*