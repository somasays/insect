# Insect Security Scanner

Insect is a security-focused command line tool designed to scan Git repositories for potentially malicious code patterns before execution. It uses a combination of static analysis, configuration checks, and metadata examination to identify security risks in code.

![Insect Logo](https://via.placeholder.com/150?text=Insect)

## Features

- **Multi-language support**: Python, JavaScript, and Shell scripts
- **Deep static analysis**: Detects suspicious patterns and security vulnerabilities
- **External tool integration**: Works with Bandit, Semgrep, and ShellCheck
- **Detailed reporting**: Text, JSON, and interactive HTML outputs
- **Performance optimization**: Caching for faster re-scanning
- **Flexible configuration**: Customize analysis based on project needs
- **Containerized scanning**: Safe scanning of untrusted repositories in Docker containers

## Installation

```bash
pip install insect
```

Or using pipenv:

```bash
pipenv install insect
```

## Quick Start

Scan a Git repository and display findings:

```bash
insect scan /path/to/repository
```

Check status of external dependencies:

```bash
insect deps
```

Generate a detailed HTML report:

```bash
insect scan /path/to/repository -f html -o report.html
```

Safely scan a repository in a container before cloning:

```bash
insect clone https://github.com/example/repository
```

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/insect.git
cd insect

# Setup development environment
pipenv install --dev
pipenv shell

# Install pre-commit hooks
pre-commit install
```

### Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=insect

# Run tox to test across different Python versions
tox
```

### Code Quality

```bash
# Format code
black .
isort .

# Lint code
ruff .

# Type checking
mypy .
```

## Documentation

For comprehensive documentation, see our [documentation index](docs/README.md) or explore:

- [Usage Guide](docs/usage.md) - Detailed instructions on using Insect
- [Security Examples](docs/security_examples.md) - Examples of security issues Insect can detect
- [Advanced Usage](docs/advanced_usage.md) - Advanced usage and customization options
- [Container Scanning](docs/container_scanning.md) - Running Insect in Docker containers
- [Use Cases](docs/use_cases.md) - Real-world use cases and applications
- [Contributing](docs/contributing.md) - Guide for contributing to Insect

## Security Issues Insect Can Detect

Insect can detect a wide range of security issues, including:

- **Command Injection**: Unsafe command execution in Python, JavaScript, and Shell scripts
- **Cross-Site Scripting (XSS)**: DOM manipulation vulnerabilities in JavaScript
- **SQL Injection**: Unsafe SQL query construction
- **Hardcoded Secrets**: API keys, tokens, and credentials in code
- **Insecure Deserialization**: Unsafe deserialization of untrusted data
- **Path Traversal**: Directory traversal vulnerabilities
- **Obfuscated Code**: Base64 encoded payloads and suspicious patterns
- **Configuration Issues**: Insecure default settings and misconfigurations

For examples of each type, see the [Security Examples](docs/security_examples.md) documentation.

## License

MIT
