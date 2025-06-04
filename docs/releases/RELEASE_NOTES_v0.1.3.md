# Release Notes - Insect v0.1.3

**Release Date:** May 31, 2025  
**Version:** 0.1.3

## 🚀 New Features

### Browser Data Theft Detection
- **NEW:** Comprehensive browser data theft protection analyzer (`BrowserTheftAnalyzer`)
- **Detection capabilities:**
  - Browser history and cookies access patterns
  - Browser storage manipulation (localStorage, sessionStorage, indexedDB)
  - Browser session hijacking and cookie theft
  - Browser password extraction from password managers
  - Browser form data and autofill theft attempts
  - Browser extension manipulation and injection
  - Browser cache access and data exfiltration
  - XSS payloads designed for browser data theft
  - Browser automation tool abuse for data harvesting

### Enhanced Documentation
- **NEW:** Comprehensive Jekyll documentation site setup
- **NEW:** Advanced security examples with browser theft scenarios
- **NEW:** Real-world remediation strategies and best practices
- **IMPROVED:** README with dynamic status badges
- **IMPROVED:** Advanced usage documentation

## 🔧 Development & Infrastructure

### Tox Integration
- **NEW:** Complete tox-based CI/CD pipeline
- **NEW:** Multiple tox environments for different development needs:
  - `tox -e all` - Full test suite with all checks
  - `tox -e lint` - Linting only (ruff, black, isort)
  - `tox -e typecheck` - Type checking only (mypy)
  - `tox -e test` - Tests with coverage
  - `tox -e dev` - Quick development feedback
  - `tox -e format` - Auto-format code

### Code Quality Improvements
- **IMPROVED:** Enhanced development workflow documentation
- **IMPROVED:** Better CI/CD pipeline management
- **FIXED:** Shell script analysis integration tests
- **FIXED:** Various linting and formatting issues

## 📊 Technical Details

### Browser Theft Analyzer
- **Patterns detected:** 12+ different browser theft techniques
- **File types supported:** Python, JavaScript, TypeScript, Shell, PHP, and more
- **Severity levels:** Critical to Medium based on threat level
- **Configuration:** Granular control over detection modules

### Detection Examples
```python
# Detects browser history access
chrome_path = "~/.config/google-chrome/Default/History"
firefox_path = "~/.mozilla/firefox/*/places.sqlite"

# Detects password extraction
login_data = "~/Chrome/Default/Login Data"
win32crypt.CryptUnprotectData(encrypted_password)

# Detects session hijacking
document.cookie
localStorage.getItem("auth_token")
```

## 🛡️ Security Impact

- **Enhanced threat detection** for browser-based malware
- **Protects against** credential harvesting and session theft
- **Identifies** sophisticated browser automation abuse
- **Comprehensive coverage** of modern browser attack vectors

## 🏗️ Breaking Changes

None. This release maintains full backward compatibility.

## 📈 Performance

- **Analysis speed:** No significant performance impact
- **Memory usage:** Minimal additional memory footprint
- **Test coverage:** Maintained at 75%+ overall coverage

## 🐛 Bug Fixes

- Fixed shellcheck integration test reliability
- Resolved import issues in various modules
- Improved error handling in browser detection patterns

## 📚 Documentation

- Added comprehensive browser theft detection examples
- Enhanced security examples with remediation strategies
- Improved development setup documentation
- Added tox usage guide for contributors

---

**Upgrade Instructions:**
```bash
pip install --upgrade insect
```

**Full Changelog:** https://github.com/somasays/insect/compare/v0.1.2...v0.1.3