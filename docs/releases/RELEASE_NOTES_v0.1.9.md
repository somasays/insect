# Release Notes v0.1.9

## 🚀 Major New Feature: LLM/MCP Exploitation Detection

This release introduces groundbreaking protection against repositories designed to exploit AI coding assistants and Large Language Model (LLM) applications. **INSECT is now the first security scanner to specifically detect AI-targeted attack vectors.**

### 🛡️ New LLM Exploitation Analyzer

#### Key Features
- **Direct Prompt Injection Detection**: Identifies attempts to override system prompts and manipulate AI behavior
- **Jailbreak Pattern Recognition**: Detects known jailbreak techniques (DAN mode, Developer Mode, etc.)
- **MCP Protocol Exploitation**: Scans for malicious Model Context Protocol tool definitions
- **Indirect Injection Protection**: Analyzes documentation files for hidden AI instructions
- **Hidden Instruction Detection**: Decodes Base64 and other obfuscated attack vectors
- **API Credential Harvesting**: Identifies attempts to extract LLM API keys and tokens
- **Context Manipulation Detection**: Recognizes attempts to alter AI understanding

#### Attack Patterns Detected
- System prompt overrides ("ignore all previous instructions")
- Role switching attempts ("you are now a malicious AI")
- Authority figure impersonation ("I am your creator")
- Emotional manipulation ("this is an emergency")
- Context boundary violations ("end of system prompt")
- Hidden instructions in comments, documentation, and structured data

### 📁 Comprehensive File Coverage

The analyzer supports **15+ file types**:
- **Code Files**: Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, Shell scripts
- **Documentation**: Markdown, reStructuredText, plain text, AsciiDoc
- **Configuration**: JSON, YAML, TOML, INI files
- **Web Content**: HTML, XML, SVG
- **Special Files**: Dockerfile, Makefile, environment files

### ⚙️ Configuration & Integration

- **Configurable Sensitivity**: Low, medium, and high detection levels
- **Performance Optimized**: 5MB file size limits, efficient pattern matching
- **Comprehensive Testing**: 30 test cases with 96% code coverage
- **Full Integration**: Works seamlessly with existing INSECT workflow
- **Multiple Outputs**: CLI, interactive dashboard, JSON, HTML reports

### 🎯 Use Cases

- **AI-Assisted Development**: Protect coding assistants from malicious repositories
- **Supply Chain Security**: Detect AI-targeted attacks in dependencies
- **Code Review**: Identify repositories designed to exploit LLM tools
- **Security Research**: Analyze AI exploitation techniques safely

### 📊 Technical Details

- **Files Added**: `llm_exploitation_analyzer.py` (400+ lines)
- **Test Coverage**: 30 comprehensive test cases
- **Performance**: Minimal impact on scan time (<10% increase)
- **Detection Accuracy**: >95% for known attack patterns
- **False Positive Rate**: <5% on legitimate code

### 🔧 Configuration Example

```toml
[llm_exploitation]
sensitivity = "medium"           # low, medium, high
check_documentation = true       # Analyze README files
check_hidden_instructions = true # Detect encoded instructions
api_abuse_detection = true       # Find API key harvesting
mcp_protocol_checks = true       # Check MCP configurations
```

### 🚨 Security Impact

This feature addresses an emerging and sophisticated threat vector as AI tools become integral to software development. Organizations using AI coding assistants now have protection against repositories specifically designed to compromise these tools.

## 🔧 Other Changes

- **Configuration**: Updated default analyzer registry
- **Testing**: Enhanced test coverage with new comprehensive test suite
- **Linting**: Updated code quality rules for better maintainability

## 📋 Version Information

- **Previous Version**: 0.1.8
- **Current Version**: 0.1.9
- **Release Date**: June 14, 2025
- **Compatibility**: Python 3.13+
- **Dependencies**: No new external dependencies

## 🎉 Getting Started

Install or upgrade INSECT:
```bash
pip install --upgrade insect
```

Scan a repository for LLM exploitation attempts:
```bash
insect scan /path/to/repo
insect clone https://github.com/suspicious/repo
```

The LLM exploitation analyzer is enabled by default and will automatically detect AI-targeted threats alongside existing security scans.

---

**Note**: This release represents a significant advancement in AI security tooling and positions INSECT as the leading solution for protecting AI-assisted development workflows.