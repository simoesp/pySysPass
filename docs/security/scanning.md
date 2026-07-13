# Security & CVE Scanning Guide

## Overview

This project includes automated security scanning for:
- **Dependency vulnerabilities** (pip-audit, Safety)
- **Python code security issues** (Bandit)
- **Container & filesystem vulnerabilities** (Trivy)

## CI Integration

Security scans run automatically via Gitea Actions on:
- ✅ Every push to the primary development branch
- ✅ Every pull request targeting the primary development branch
- ✅ Weekly schedule (Sunday 00:00 UTC)

## Local Scanning

### Install Security Tools

```bash
pip install pip-audit safety bandit trivy
```

### Run Dependency Scans

```bash
# pip-audit - Check Python dependencies for known vulnerabilities
pip-audit -r requirements.txt

# Safety - Alternative vulnerability scanner
safety check -r requirements.txt
```

### Run Code Security Scan

```bash
# Bandit - Find common security issues in Python code
bandit -r app/

# With detailed output
bandit -r app/ -f json -o bandit-results.json
```

### Run Container/File System Scan

```bash
# Trivy - Comprehensive security scanner
trivy fs .

# Only show HIGH and CRITICAL severity
trivy fs . --severity HIGH,CRITICAL

# Scan Dockerfile
trivy fs Dockerfile --severity HIGH,CRITICAL
```

## Scan Tools

### pip-audit
- **Purpose**: Python dependency vulnerability scanner
- **Data Source**: PyPI, OSV (Open Source Vulnerabilities)
- **Command**: `pip-audit -r requirements.txt`

### Safety
- **Purpose**: Security audit for Python dependencies
- **Data Source**: PyUp Safety Database
- **Command**: `safety check -r requirements.txt`

### Bandit
- **Purpose**: Static analysis for Python security
- **Checks**: 50+ security checks (SQL injection, XSS, hardcoded secrets, etc.)
- **Command**: `bandit -r app/`

### Trivy
- **Purpose**: Comprehensive vulnerability scanner
- **Scans**: Filesystem, containers, Git repos, dependencies
- **Command**: `trivy fs .`

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **CRITICAL** | Exploitable vulnerabilities, RCE, data breach | 🔴 **Fix immediately** |
| **HIGH** | Significant security risk | 🟠 Fix within 7 days |
| **MEDIUM** | Moderate security risk | 🟡 Fix within 30 days |
| **LOW** | Minor security concerns | 🟢 Address when convenient |

## Gitea CI Configuration

> This section documents the upstream Gitea Actions pipeline. This repository
> does not ship CI workflows; the local scanning commands above run anywhere and
> are the supported path here.

The security scan workflow is defined in:
`.gitea/workflows/security-scan.yml`

### Workflow Triggers

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly Sunday
```

### Build Results

Security scan results are uploaded as artifacts:
- `pip-audit-results.json`
- `safety-results.json`
- `bandit-results.json`
- `trivy-results.json`

## Fixing Vulnerabilities

### 1. Update Dependencies

```bash
# Update specific vulnerable package
pip install --upgrade package-name

# Or update all to latest compatible versions
pip install --upgrade -r requirements.txt
```

### 2. Address Bandit Issues

Common Bandit findings:
- **B101**: Assert statements in production → Remove or guard
- **B301**: Pickle usage → Use JSON instead
- **B501**: Request without cert verification → Add `verify=True`
- **B701**: HTML injection → Use proper escaping
- **B104**: Hardcoded credentials → Use environment variables

### 3. Trivy Remediation

- Update base image in Dockerfile
- Remove unnecessary packages
- Fix file permissions
- Update vulnerable system packages

## Best Practices

1. **Run scans locally before pushing**
   ```bash
   make security-scan  # If you have a Makefile
   ```

2. **Keep dependencies updated**
   - Review CVE reports weekly
   - Use Dependabot or similar for automated updates

3. **Address critical issues immediately**
   - Block merges if critical vulnerabilities exist
   - Create hotfix branches for urgent patches

4. **Document exceptions**
   - If a vulnerability is not exploitable in your context, document why
   - Add `# nosec` comments for Bandit exceptions (use sparingly)

## Integration with Issue Tracker

You can automatically create issues from security findings:

```yaml
# Add to .gitea/workflows/security-scan.yml
- name: Create Issue for Critical Vulnerabilities
  if: failure()
  uses: peter-evans/create-issue-from-file@v4
  with:
    title: Security Vulnerability Detected
    content-filepath: ./security-findings.md
    labels: security, vulnerability
```

## Reporting

Generate security reports:

```bash
# Generate markdown report
bandit -r app/ -f html -o bandit-report.html

# JSON report for CI integration
pip-audit -r requirements.txt --format json --output pip-audit.json
```

## Compliance

This scanning setup supports:
- ✅ OWASP Top 10 coverage
- ✅ SAST (Static Application Security Testing)
- ✅ SCA (Software Composition Analysis)
- ✅ Container security scanning

---

**Last Updated**: 2026-06-21
**Workflow File**: `.gitea/workflows/security-scan.yml`
