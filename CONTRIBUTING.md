# Contributing to Insect

Thank you for considering contributing to Insect! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before submitting a bug report:
- Check the issue tracker to see if the bug has already been reported.
- If not, create a new issue with a descriptive title and detailed information.

### Suggesting Enhancements

- Check the issue tracker for existing enhancement requests.
- Create a new issue with a clear title and detailed description.

### Pull Requests

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes, following the code style guidelines.
4. Add tests for your changes.
5. Run the test suite to ensure all tests pass.
6. Submit a pull request.

## Development Setup

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

## Code Style

This project uses:
- [Black](https://github.com/psf/black) for code formatting
- [isort](https://github.com/PyCQA/isort) for import sorting
- [ruff](https://github.com/charliermarsh/ruff) for linting
- [mypy](https://github.com/python/mypy) for static type checking

Please ensure your code passes all these checks before submitting a pull request.

## Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=insect
```

## Release Process

1. Update the version in pyproject.toml
2. Update CHANGELOG.md
3. Create a new git tag for the version
4. Push the tag to GitHub
5. Build and upload the package to PyPI

## Thank You!

Your contributions to open source, large or small, make projects like this possible. Thank you for taking the time to contribute.
