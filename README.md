# Insect CLI

A Python command line application.

## Installation

```bash
pip install insect
```

Or using pipenv:

```bash
pipenv install insect
```

## Usage

```bash
insect --help
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

## License

MIT
