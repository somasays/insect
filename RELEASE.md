# Release Process

## Prerequisites

1. Ensure you have maintainer access to the repository
2. Set up PyPI API token in repository secrets as `PYPI_API_TOKEN`
3. Ensure all tests pass locally: `make test`
4. Ensure code quality checks pass: `make lint`

## Release Steps

### 1. Prepare the Release

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md` with new features, bug fixes, and breaking changes
3. Commit changes: `git commit -m "Prepare release vX.Y.Z"`
4. Push to main: `git push origin main`

### 2. Create and Push Tag

```bash
# Create annotated tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# Push tag to trigger release workflow
git push origin vX.Y.Z
```

### 3. Automated Release

The GitHub Actions workflow will automatically:
- Run all tests and quality checks
- Build the package
- Upload to PyPI
- Create a GitHub release

### 4. Post-Release

1. Verify the package is available on PyPI: https://pypi.org/project/insect/
2. Test installation: `pip install insect==X.Y.Z`
3. Update documentation if needed

## Manual Release (if needed)

If the automated release fails, you can release manually:

```bash
# Build package
make dist

# Upload to PyPI
make release
```

## Version Numbering

Follow semantic versioning (semver):
- `MAJOR.MINOR.PATCH`
- MAJOR: breaking changes
- MINOR: new features (backward compatible)
- PATCH: bug fixes (backward compatible)