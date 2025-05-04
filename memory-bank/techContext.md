# Technical Context: Insect

## 1. Core Technology

* **Language:** Python (>= 3.8 required)
* **Package Manager:** pip
* **Distribution:** PyPI (`insect-scanner` package name)

## 2. Key Runtime Dependencies

* `gitpython`: Interacting with local Git repository metadata.
* `yara-python`: Matching binary file content against YARA rules for known patterns.
* `toml`: Loading configuration files (standard in Python 3.11+ via `tomllib`).
* `rich`: Rendering formatted and colored output to the console.
* `Jinja2`: Templating engine for generating HTML reports.
* `argparse`: Standard library for parsing command-line arguments.
* `ast`: Standard library for parsing Python code into Abstract Syntax Trees.

## 3. Development Environment & Tooling

* **Virtual Environments:** Managed via `venv`.
* **Testing Framework:** `pytest` with `pytest-cov` (coverage) and `pytest-mock`.
* **Linter:** `flake8`.
* **Formatter:** `black`.
* **Type Checker:** `mypy`.
* **Packaging Tools:** `build`, `twine`.
* **Optional:** `pre-commit` for automating checks.
* **Build System Backend:** Defined in `pyproject.toml` (e.g., `setuptools`, `hatch`).

## 4. Technical Constraints & Considerations

* **Local Execution:** Designed to run entirely locally, analyzing files on the user's machine. No external API calls for analysis are planned initially.
* **Platform Support:** Should be OS-independent (Linux, macOS, Windows) due to Python's nature, but filesystem path handling needs care.
* **Performance:** Static analysis, especially AST parsing and scanning large files/repos, can be resource-intensive. Performance optimization may be needed.
* **Dependency Management:** Relies on the Python ecosystem. Dependency conflicts are a potential issue for users. Dependencies should be pinned or have reasonable version specifiers.
* **Security:** The tool itself must handle potentially malicious file content safely during analysis (e.g., avoid executing discovered code, handle parsing errors gracefully). Input validation (paths, configs) is crucial.

## 5. Development Setup

1.  Clone the Insect repository.
2.  Create and activate a virtual environment (`python -m venv venv`, `source venv/bin/activate`).
3.  Install in editable mode with dev dependencies (`pip install -e .[dev]`).
4.  (Optional) Install pre-commit hooks (`pre-commit install`).
