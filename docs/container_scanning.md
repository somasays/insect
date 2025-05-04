# Running Insect in a Container

Insect provides the ability to run security scans in Docker containers, which offers several advantages:

1. **Isolation**: The repository is scanned in an isolated environment, preventing potential security risks
2. **Dependencies**: All dependencies are pre-installed in the container, eliminating the need to install them locally
3. **Consistency**: Every scan runs in the same environment, ensuring reproducible results
4. **Safety first**: You can scan untrusted repositories safely before cloning them to your local machine

## Using the `insect clone` Command

The `insect clone` command scans a Git repository in a Docker container and then clones it locally if the scan passes your security criteria.

### Basic Usage

```bash
insect clone https://github.com/example/repository
```

This will:
1. Pull or build a Docker image with Insect and all its dependencies
2. Clone the repository inside the container
3. Run Insect on the repository in the container
4. Show you any security issues found
5. Prompt you to confirm whether to clone the repository locally
6. Clone the repository to your current directory if confirmed

### Options

```
--output-dir, -o PATH   Directory where to clone the repository (defaults to the repository name)
--branch, -b BRANCH     Branch to check out (defaults to default branch)
--commit, -c COMMIT     Specific commit to check out (overrides branch)
--image, -i IMAGE       Docker image to use (defaults to Python 3.10 with Insect)
--scan-args ARGS        Additional arguments to pass to the insect scan command
--report-path PATH      Path to save the scan report JSON (defaults to not saving)
```

### Examples

Scan a repository and clone a specific branch:
```bash
insect clone https://github.com/example/repository --branch develop
```

Scan a repository with specific scan arguments and save the report:
```bash
insect clone https://github.com/example/repository --scan-args "--severity high --no-cache" --report-path ./scan-report.json
```

Use a custom Docker image:
```bash
insect clone https://github.com/example/repository --image my-custom-insect:latest
```

## Building a Custom Docker Image

You can build a custom Docker image for Insect using the provided Dockerfile:

```bash
docker build -t custom-insect:latest .
```

Then use it with the `insect clone` command:

```bash
insect clone https://github.com/example/repository --image custom-insect:latest
```

## Security Considerations

The `insect clone` command provides a safety checkpoint before cloning untrusted repositories. When security issues are found, you'll be shown a summary and prompted to confirm before cloning.

This is particularly useful for:
- Investigating suspicious repositories
- Vetting third-party code before using it
- Ensuring compliance with security policies

## Requirements

- Docker must be installed and running on your system
- Network access to pull the repository
- Sufficient disk space for the container and repository