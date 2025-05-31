---
layout: page
title: Contributing Guide
nav_order: 7
---

# Contributing to Insect

Thank you for your interest in contributing to Insect! This guide will help you get started with contributing to the project.

## Table of Contents

- [Setting Up Your Development Environment](#setting-up-your-development-environment)
- [Project Structure](#project-structure)
- [Adding New Features](#adding-new-features)
- [Writing Tests](#writing-tests)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Code of Conduct](#code-of-conduct)

## Setting Up Your Development Environment

### Prerequisites

- Python 3.8 or higher
- Git
- pipenv (recommended for managing dependencies)

### Setup Steps

1. Fork the repository on GitHub

2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/insect.git
   cd insect
   ```

3. Set up the development environment:
   ```bash
   pipenv install --dev
   pipenv shell
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

5. Run tests to ensure your setup works:
   ```bash
   pytest
   ```

### Development Workflow

1. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes

3. Run linting and tests:
   ```bash
   # Format code
   black .
   isort .
   
   # Lint
   ruff .
   
   # Type checking
   mypy .
   
   # Run tests
   pytest
   ```

4. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add feature X" -m "Detailed description of the changes"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a pull request on GitHub

## Project Structure

The Insect project is organized as follows:

```
insect/
├── config/               # Default configuration files
├── docs/                 # Documentation
├── src/
│   └── insect/           # Main package
│       ├── __init__.py   # Package initialization
│       ├── __main__.py   # Entry point for direct execution
│       ├── analysis/     # Analysis modules
│       │   ├── __init__.py
│       │   ├── binary_analyzer.py
│       │   ├── config/
│       │   ├── javascript_static_analyzer.py
│       │   ├── python_static_analyzer.py
│       │   ├── shell/
│       │   └── static_analyzer.py
│       ├── cli.py        # Command line interface
│       ├── config/       # Configuration handling
│       ├── core.py       # Core functionality
│       ├── finding.py    # Finding data structures
│       ├── reporting/    # Report generation
│       └── utils/        # Utility functions
├── tests/                # Test suite
│   ├── integration/
│   ├── samples/
│   └── unit/
├── Pipfile               # Dependencies
├── Pipfile.lock
├── pyproject.toml        # Project configuration
└── tox.ini               # Tox configuration
```

### Key Components:

- **analysis/**: Contains analyzers for different languages and file types
- **config/**: Handles configuration loading and validation
- **core.py**: Provides core scanning functionality
- **finding.py**: Defines the Finding data structure
- **reporting/**: Handles report generation in different formats
- **utils/**: Contains utility functions used across the project

## Adding New Features

### Adding a New Analyzer

To add support for a new language or file type:

1. Create a new file in the `analysis` directory (e.g., `ruby_analyzer.py`)

2. Define a new analyzer class that inherits from `BaseAnalyzer`:
   ```python
   from pathlib import Path
   from typing import Any, Dict, List
   
   from insect.analysis import BaseAnalyzer, register_analyzer
   from insect.finding import Finding, FindingType, Location, Severity
   
   @register_analyzer
   class RubyAnalyzer(BaseAnalyzer):
       """Static analyzer for Ruby code."""
       
       name = "ruby_analyzer"
       description = "Static analyzer for Ruby code"
       supported_extensions = {".rb"}
       
       def __init__(self, config: Dict[str, Any]) -> None:
           super().__init__(config)
           self.analyzer_config = config.get(self.name, {})
           
       def analyze_file(self, file_path: Path) -> List[Finding]:
           """Analyze a Ruby file for security issues."""
           findings = []
           
           # Implement analysis logic here
           
           return findings
   ```

3. Add tests for your analyzer in `tests/unit/analysis/test_ruby_analyzer.py`

4. Update the default configuration in `config/default.toml` to include your analyzer

### Adding a New Detection Rule

To add a new detection rule for an existing analyzer:

1. Open the relevant analyzer file or create a new rules file

2. Define a new rule:
   ```python
   from insect.analysis.static_analyzer_rules import StaticDetectionRule
   
   # Add a new rule
   RUBY_RULES = [
       StaticDetectionRule(
           rule_id="RUBY-001",
           title="Unsafe Eval Usage",
           description="Use of eval with user input is unsafe.",
           severity=Severity.HIGH,
           finding_type=FindingType.VULNERABILITY,
           language="ruby",
           regex_pattern=re.compile(r"eval\s*\("),
           remediation="Avoid using eval with user input.",
           references=["https://example.com/ruby-security"],
           cwe_id="CWE-95",
           cvss_score=8.0,
       ),
   ]
   ```

3. Register the rules in the analyzer's initialization

### Adding a New Output Format

To add a new output format:

1. Create a new file in the `reporting` directory (e.g., `xml_formatter.py`)

2. Define a new formatter class:
   ```python
   from typing import Any, Dict, List
   
   from insect.finding import Finding
   from insect.reporting.formatters import BaseFormatter, register_formatter
   
   @register_formatter
   class XMLFormatter(BaseFormatter):
       """XML formatter for Insect reports."""
       
       format_name = "xml"
       
       def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
           """Format findings as an XML string."""
           # Implement XML formatting logic
           return xml_string
   ```

3. Add tests for your formatter in `tests/unit/reporting/test_xml_formatter.py`

4. Update the CLI to support the new format

## Writing Tests

Insect uses pytest for testing. All new features should include tests.

### Test Structure

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test interactions between components
- **Samples**: Test with real-world code examples

### Writing a Test Case

```python
import pytest
from pathlib import Path

from insect.analysis.your_analyzer import YourAnalyzer
from insect.finding import Finding, FindingType, Severity

def test_your_analyzer_detects_issue():
    # Setup
    analyzer = YourAnalyzer({"your_analyzer": {}})
    test_file = Path("tests/samples/your_language/vulnerable_code.xyz")
    
    # Execute
    findings = analyzer.analyze_file(test_file)
    
    # Assert
    assert len(findings) > 0
    assert any(finding.id.startswith("YOUR-001") for finding in findings)
    assert any(finding.severity == Severity.HIGH for finding in findings)
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/analysis/test_your_analyzer.py

# Run with coverage report
pytest --cov=insect
```

## Documentation

Good documentation is crucial for the project. When adding new features, please update:

1. **Code Docstrings**: All functions, classes, and methods should have docstrings
2. **README.md**: If your change affects user-facing functionality
3. **Docs/**: Add or update relevant documentation files

### Documentation Style

- Use Markdown for documentation files
- Follow Google-style docstrings for Python code
- Include examples for user-facing features

## Pull Request Process

1. Ensure your code passes all tests and linting checks
2. Update documentation to reflect your changes
3. Add your changes to the CHANGELOG.md file
4. Submit a pull request with a clear description of the changes
5. Wait for review and address any feedback

### PR Description Template

```
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my own code
- [ ] I have added tests that prove my fix/feature works
- [ ] I have updated the documentation
- [ ] I have added an entry to the CHANGELOG.md
```

## Code of Conduct

Please review and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) when participating in this project.

### Core Principles

- **Be respectful**: Treat all contributors with respect
- **Be constructive**: Provide constructive feedback
- **Be collaborative**: Work together to improve the project
- **Focus on the best outcome**: Make decisions that improve the project for all users

Thank you for contributing to Insect!