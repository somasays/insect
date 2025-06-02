# Release Notes - v0.1.5 (Beta)

🎉 **Insect has reached Beta status!** This release focuses on major UI/UX improvements and enhanced configurability.

## 🆕 What's New

### 🎨 **Fancy CLI UI & Responsive Design**
- **Beautiful animated welcome screen** with ASCII art and color transitions
- **Responsive layout** that adapts to different terminal sizes
- **Rich progress bars** with spinners, colors, and real-time updates
- **Professional tables** with proper alignment and styling
- **Tree-structured findings display** with color-coded severity levels
- **Smart text truncation** for long paths and descriptions

### 🎛️ **Sensitivity Configuration**
- **New `--sensitivity` option** with 4 levels: `low`, `normal`, `high`, `very_high`
- **Configurable finding filters** to reduce noise from speculative detections
- **Unusual hours commits** only shown at `very_high` sensitivity
- **Customizable thresholds** for different analysis types

### 📝 **Enhanced Logging**
- **Clean console output** with no warning messages cluttering the UI
- **Comprehensive file logging** to `.insect.log` in current directory
- **Adjustable verbosity** with `-v` and `-vv` flags
- **Structured log format** with timestamps and component names

### 🌐 **Documentation & GitHub Pages**
- **Professional Jekyll theme** with dark mode support
- **Comprehensive documentation site** with usage guides and examples
- **Logo integration** in README and documentation
- **GitHub Actions workflow** for automated page deployment

## 🔧 **Technical Improvements**

### 🚀 **Performance & Usability**
- **Terminal-aware rendering** with responsive component sizing
- **Improved table layouts** that stack vertically on narrow terminals
- **Optimized progress display** with dynamic bar width adjustment
- **Better error handling** with graceful degradation

### 🎯 **Configuration Enhancements**
- **Sensitivity levels** in `config/default.toml`
- **Command-line override** for sensitivity settings
- **Backward compatible** configuration system
- **Enhanced metadata analyzer** with configurable detection rules

## 📊 **UI/UX Highlights**

### Before vs After
- ❌ **Before**: Plain text output with alignment issues
- ✅ **After**: Rich, colorful interface with proper responsive design

### Terminal Responsiveness
- **Wide terminals (>100 cols)**: Full side-by-side layout with detailed findings
- **Standard terminals (80-100 cols)**: Balanced layout with appropriate truncation  
- **Narrow terminals (<80 cols)**: Stacked layout with smart text wrapping

## 🛠️ **Developer Experience**

### New Command Options
```bash
# Scan with different sensitivity levels
insect scan . --sensitivity low        # Only obvious threats
insect scan . --sensitivity normal     # Standard detection (default)
insect scan . --sensitivity high       # Include speculative findings
insect scan . --sensitivity very_high  # Include all patterns

# Enhanced verbosity control
insect scan . -v    # Show warnings on console
insect scan . -vv   # Show info messages on console
```

### Responsive UI Examples
```bash
# Wide terminal: Rich side-by-side layout
insect scan . 

# Narrow terminal: Stacked layout
COLUMNS=60 insect scan .
```

## 🏗️ **Infrastructure**

### GitHub Pages
- **Automated deployment** via GitHub Actions
- **Professional documentation site** at https://somasays.github.io/insect
- **SEO optimization** with proper meta tags and sitemap
- **Mobile-responsive** documentation theme

### Quality Assurance
- **Code formatting** with Black and isort
- **Type checking** with mypy
- **Comprehensive testing** with pytest
- **Security scanning** with the tool itself!

## 🚀 **Beta Status**

With this release, Insect moves from **Alpha** to **Beta** status, indicating:

- ✅ **Stable core functionality** with comprehensive security detection
- ✅ **Production-ready CLI interface** with professional UX
- ✅ **Extensive configuration options** for different use cases
- ✅ **Comprehensive documentation** and usage guides
- ✅ **Active development** with regular updates and improvements

## 🔮 **What's Next**

Future releases will focus on:
- **Additional language support** (Go, Rust, Java)
- **Machine learning models** for advanced threat detection
- **IDE integrations** and editor plugins
- **Enterprise features** for team collaboration
- **Performance optimizations** for large repositories

## 📝 **Upgrade Instructions**

```bash
# Upgrade via pip
pip install --upgrade insect

# Verify installation
insect --version
# Should show: insect 0.1.5
```

## 🙏 **Acknowledgments**

Thank you to all users who provided feedback during the alpha phase. Your input has been invaluable in making Insect better!

---

**Download**: Available on [PyPI](https://pypi.org/project/insect/)  
**Documentation**: https://somasays.github.io/insect  
**Source Code**: https://github.com/somasays/insect  
**Issues**: https://github.com/somasays/insect/issues