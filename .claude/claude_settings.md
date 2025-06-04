# Claude Settings

## Model Configuration
- **Default Model**: Claude Opus 4
- **Fallback Model**: Claude Sonnet 4

## Code Style Preferences
- **Language**: Python
- **Framework**: pipenv for dependency management
- **Testing**: pytest with tox for multiple environment testing
- **Code Quality**: Use ruff for linting, black for formatting

## Git Configuration
- **Email**: somasundaram@outlook.com
- **Name**: Somasundaram Sekar
- **Commit Style**: Conventional commits without "claude" mentions

## Project Structure
- **Source**: `src/insect/`
- **Tests**: `tests/`
- **Documentation**: `docs/`
- **Release Notes**: `docs/releases/`
- **Configuration**: `config/`

## Workflow Preferences
- Run `tox -e all` before committing
- Use `pipenv run` prefix for all commands
- Maintain test coverage
- Follow security best practices