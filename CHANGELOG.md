# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.7] - 2025-06-04

### Fixed
- `insect clone` now correctly creates subdirectories when `--output-dir` is not specified
- Repository name extraction from URLs with trailing slashes
- URL parsing logic now handles all common Git URL formats consistently

### Improved
- Robust repository name extraction with proper fallback logic
- Better error handling for malformed repository URLs

## [0.1.6] - 2025-06-04

### Fixed
- Documentation now deploys only after successful releases
- Liquid syntax errors in Jekyll documentation preventing builds
- Ruby version compatibility issues in documentation workflow
- Release workflow triggers and test dependencies

### Improved
- CI/CD pipeline reliability with proper workflow sequencing
- GitHub releases now extract content from release notes files
- Project organization with Claude config in `.claude/` directory
- Code quality by removing dead code and outdated comments

### Added
- Version information propagation to documentation builds
- Automated release notes extraction in GitHub releases
- Claude settings configuration file

### Removed
- Commented-out dead code in static analyzer
- Misplaced test files outside standard structure
- Generated dashboard HTML files from version control

## [0.1.5] - 2025-05-31

### Added
- Initial project setup
