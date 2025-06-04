# Release Notes - v0.1.7

**Release Date:** June 4, 2025  
**Version:** 0.1.7

## 🐛 **Bug Fixes**

### **Clone Command Directory Logic**
- **FIXED**: `insect clone` now correctly creates subdirectories when `--output-dir` is not specified
- **RESOLVED**: Issue where URLs with trailing slashes caused cloning to current working directory
- **IMPROVED**: Repository name extraction now handles all URL formats consistently
- **ENHANCED**: Better fallback logic for edge cases in URL parsing

### **Supported URL Formats**
All of these URL formats now correctly create a subdirectory named after the repository:
- `https://github.com/user/repo.git` → `./repo/`
- `https://github.com/user/repo/` → `./repo/`
- `https://github.com/user/repo` → `./repo/`
- `git@github.com:user/repo.git` → `./repo/`

## 🔧 **Technical Improvements**

### **URL Parsing Logic**
- **BEFORE**: `Path(repo_url.split("/")[-1]).stem` - failed with trailing slashes
- **AFTER**: Robust extraction using `repo_url.rstrip("/").split("/")[-1]` with proper `.git` handling
- **FALLBACK**: Uses `"cloned-repo"` as directory name if extraction fails

### **Docker Container Compatibility**
- **MAINTAINED**: All Docker container functionality remains unchanged
- **VERIFIED**: Container file copying mechanism works properly
- **TESTED**: macOS Docker Desktop volume mount fallback continues to work

## 🛡️ **Security & Compatibility**

### **No Security Impact**
- **SCANNING FUNCTIONALITY**: No changes to security analysis capabilities
- **CONTAINER ISOLATION**: Docker scanning remains fully isolated
- **DETECTION ACCURACY**: No impact on vulnerability detection

### **Backward Compatibility**
- **EXISTING WORKFLOWS**: All existing usage patterns continue to work
- **CONFIGURATION**: No changes to configuration options
- **OUTPUT FORMATS**: All report formats remain unchanged

## 🧪 **Testing**

### **Test Coverage**
- **MAINTAINED**: 66% test coverage across 264 tests (1 skipped)
- **VERIFIED**: All existing tests pass without modifications
- **ADDED**: Test coverage for new URL parsing logic

### **Quality Assurance**
- **LINTING**: All code style checks pass
- **TYPE CHECKING**: Full mypy compatibility maintained
- **FORMATTING**: Code properly formatted with black

## 📝 **User Experience**

### **Command Behavior**
- **CLEARER**: Clone destinations are now predictable for all URL formats
- **SAFER**: No accidental overwrites of current working directory
- **CONSISTENT**: Same repository name extraction logic across all scenarios

### **Error Handling**
- **IMPROVED**: Better fallback when repository name cannot be determined
- **MAINTAINED**: All existing error messages and confirmations

## 🏗️ **Breaking Changes**

None. This release maintains full backward compatibility.

## 📝 **Upgrade Instructions**

```bash
# Upgrade via pip
pip install --upgrade insect

# Verify installation
insect --version
# Should show: insect 0.1.7

# Test the fix with any repository URL
insect clone https://github.com/user/repo/
# Now correctly creates ./repo/ directory
```

## 🎯 **What's Next**

This patch release ensures reliable repository cloning behavior. Future releases will focus on:
- Enhanced security analyzer capabilities
- Performance optimizations for large repositories
- Extended language and framework support

---

**Version Information:**
- **Version:** 0.1.7
- **Python Requirements:** 3.13+
- **Breaking Changes:** None
- **Dependencies:** No changes

**Full Changelog:** https://github.com/somasays/insect/compare/v0.1.6...v0.1.7