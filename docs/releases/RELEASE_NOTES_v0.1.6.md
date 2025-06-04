# Release Notes - v0.1.6

**Release Date:** June 4, 2025  
**Version:** 0.1.6

## 🔧 **Infrastructure & Workflow Improvements**

### **CI/CD Pipeline Enhancements**
- **FIXED**: Documentation now deploys only after successful releases (instead of on every push)
- **IMPROVED**: Release workflow triggers properly on tag creation and runs tests before releasing
- **ENHANCED**: GitHub releases now automatically extract release notes from `docs/releases/` folder
- **ADDED**: Version information is properly passed from releases to documentation builds
- **ORGANIZED**: Release documentation moved to dedicated `docs/releases/` directory

### **Jekyll Documentation Fixes**
- **FIXED**: Ruby version compatibility issues preventing documentation builds
- **RESOLVED**: Liquid syntax errors in documentation that caused build failures
- **UPDATED**: Gemfile configuration optimized for both local development and GitHub Actions
- **IMPROVED**: Documentation now builds successfully in GitHub Pages workflow

## 🧹 **Code Quality & Organization**

### **Dead Code Cleanup**
- **REMOVED**: Commented-out code blocks in `python_static_analyzer.py`
- **REMOVED**: Outdated TODO comments where functionality was already implemented
- **DELETED**: Misplaced test files outside standard directory structure
- **CLEANED**: Generated dashboard HTML files now properly ignored in git

### **Project Organization**
- **MOVED**: Claude configuration files to dedicated `.claude/` directory
- **CREATED**: `claude_settings.md` for project-specific Claude preferences
- **ORGANIZED**: Release notes consolidated in `docs/releases/` folder
- **IMPROVED**: .gitignore patterns to prevent tracking of generated files

## 🚀 **Development Experience**

### **GitHub Actions Workflow**
- **SEQUENTIAL FLOW**: 
  ```
  Push to main → Test Workflow
  Create tag → Release Workflow (tests + release)
  Release success → Documentation Deployment
  ```
- **RELIABLE**: Documentation deployment only happens after successful package releases
- **AUTOMATED**: Release notes automatically included in GitHub releases
- **VERSIONED**: Documentation displays correct version information

### **Code Quality**
- **MAINTAINED**: 66% test coverage across 264 tests
- **VERIFIED**: All linting and formatting checks pass
- **CLEAN**: Removed technical debt and improved maintainability

## 🛡️ **Security & Compatibility**

### **Maintained Features**
- **ALL EXISTING SECURITY ANALYZERS**: No changes to detection capabilities
- **BACKWARD COMPATIBILITY**: No breaking changes to existing functionality
- **PERFORMANCE**: No impact on scan performance or accuracy

## 📈 **Technical Details**

### **Workflow Architecture**
- **BEFORE**: Documentation deployed in parallel with releases (potential inconsistency)
- **AFTER**: Documentation deploys only after successful releases (guaranteed consistency)

### **Release Process**
- **AUTOMATED**: GitHub releases extract content from version-specific release notes files
- **CONSISTENT**: Version information propagated to all documentation
- **RELIABLE**: Failed releases prevent documentation deployment

## 🏗️ **Breaking Changes**

None. This release maintains full backward compatibility.

## 📝 **Upgrade Instructions**

```bash
# Upgrade via pip
pip install --upgrade insect

# Verify installation
insect --version
# Should show: insect 0.1.6
```

## 🎯 **What's Next**

This maintenance release sets the foundation for more reliable development workflows. Future releases will focus on:
- Additional language support and security analyzers
- Performance optimizations for large repositories
- Enhanced reporting and dashboard features

---

**Version Information:**
- **Version:** 0.1.6
- **Python Requirements:** 3.13+
- **Breaking Changes:** None
- **Dependencies:** No changes

**Full Changelog:** https://github.com/somasays/insect/compare/v0.1.5...v0.1.6