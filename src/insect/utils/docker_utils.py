"""
Docker utilities for running Insect in containers.

This module provides functionality to run Insect in Docker containers
for isolated scanning of repositories.
"""

import contextlib
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# Default Docker image used for scanning
DEFAULT_DOCKER_IMAGE = "python:3.13-slim"

# Dockerfile template for Insect image
DOCKERFILE_TEMPLATE = """
FROM {base_image}

# Install git and other dependencies
RUN apt-get update && apt-get install -y \\
    git \\
    curl \\
    shellcheck \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \\
    pip install --no-cache-dir bandit semgrep gitpython yara-python

# Install Insect with specific version and verbose output for debugging
RUN pip install --no-cache-dir --upgrade --verbose insect

WORKDIR /scan

# Command to run when container starts
CMD ["bash"]
"""


def check_docker_available() -> bool:
    """Check if Docker is available on the system.

    Returns:
        bool: True if Docker is available, False otherwise.
    """
    try:
        result = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, check=False
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        logger.warning("Docker is not available on the system")
        return False


def build_insect_image(base_image: str = DEFAULT_DOCKER_IMAGE) -> Tuple[bool, str]:
    """Build a Docker image with Insect and all dependencies installed.

    Args:
        base_image: Base Docker image to use

    Returns:
        Tuple[bool, str]: (Success status, Image ID or error message)
    """
    # Create temporary directory for Dockerfile
    with tempfile.TemporaryDirectory() as temp_dir:
        dockerfile_path = Path(temp_dir) / "Dockerfile"

        # Create Dockerfile from template
        dockerfile_content = DOCKERFILE_TEMPLATE.format(base_image=base_image)
        dockerfile_path.write_text(dockerfile_content)

        # Build Docker image
        image_name = f"insect-scanner:{base_image.replace(':', '-')}"

        try:
            logger.info(f"Building Docker image {image_name} from {base_image}")
            subprocess.run(
                ["docker", "build", "-t", image_name, "-f", str(dockerfile_path), "."],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            logger.info(f"Successfully built Docker image: {image_name}")
            return True, image_name
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build Docker image: {e.stderr}")
            return False, e.stderr


def run_scan_in_container(
    repo_url: str,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    scan_args: Optional[List[str]] = None,
    image_name: Optional[str] = None,
) -> Tuple[bool, Dict[str, Union[str, List[Dict]]], str]:
    """Run Insect scan in a Docker container.

    Args:
        repo_url: URL of the Git repository to scan
        branch: Branch to check out (optional)
        commit: Specific commit to check out (optional)
        scan_args: Additional arguments for the insect scan command
        image_name: Docker image name to use

    Returns:
        Tuple[bool, Dict, str]: (Success status, Scan results as dict, Git commit hash)
    """
    # Use default image if not specified
    if not image_name:
        # Check if default image exists, build if not
        check_image = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                f"insect-scanner:{DEFAULT_DOCKER_IMAGE.replace(':', '-')}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if check_image.returncode != 0:
            success, image_result = build_insect_image()
            if not success:
                return False, {}, ""
            image_name = image_result
        else:
            image_name = f"insect-scanner:{DEFAULT_DOCKER_IMAGE.replace(':', '-')}"

    # Create temp directory for output
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        results_file = output_dir / "scan_results.json"
        commit_file = output_dir / "commit.txt"

        # Build the Docker command - use container name for file copying
        container_name = f"insect-scan-{int(time.time())}"
        docker_cmd = [
            "docker",
            "run",
            "--name",
            container_name,
            "-v",
            f"{output_dir.absolute()}:/output",
            image_name,
            "/bin/bash",
            "-c",
        ]

        # Build the container commands
        container_cmd = [f"git clone {repo_url} /scan/repo", "cd /scan/repo"]

        # Check out specific branch if specified
        if branch:
            container_cmd.append(f"git checkout {branch}")

        # Check out specific commit if specified
        if commit:
            container_cmd.append(f"git checkout {commit}")

        # Get the current commit hash and save it
        container_cmd.append("git rev-parse HEAD > /output/commit.txt")

        # Run the scan and save results
        scan_command = "insect scan . --format json --output /output/scan_results.json"
        if scan_args:
            scan_command += " " + " ".join(scan_args)
        container_cmd.append(scan_command)

        # Ensure files are synced to volume mount (helps with Docker Desktop on macOS)
        container_cmd.append("sync")

        # Combine everything into a single command
        full_command = " && ".join(container_cmd)
        docker_cmd.append(full_command)

        # Run the container
        try:
            logger.info(f"Running scan in container with image {image_name}")
            logger.debug(f"Running docker command: {' '.join(docker_cmd)}")

            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                check=False,  # Don't raise exception on non-zero exit
            )

            logger.debug(f"Container stdout: {result.stdout}")
            logger.debug(f"Container stderr: {result.stderr}")
            logger.debug(f"Container exit code: {result.returncode}")

            if result.returncode != 0:
                logger.error(
                    f"Container command failed with exit code {result.returncode}"
                )
                logger.error(f"Error output: {result.stderr}")
                logger.error(f"Standard output: {result.stdout}")
                # Clean up container if it still exists
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["docker", "rm", "-f", container_name], capture_output=True
                    )
                return False, {}, ""

            # Give Docker Desktop time to sync files on macOS
            time.sleep(1)

            # If volume mount didn't work (macOS Docker Desktop issue), copy files from container
            if not results_file.exists():
                logger.info(
                    "Volume mount didn't sync files, attempting to copy from container"
                )
                try:
                    # Copy scan results from container
                    copy_result = subprocess.run(
                        [
                            "docker",
                            "cp",
                            f"{container_name}:/output/scan_results.json",
                            str(results_file),
                        ],
                        capture_output=True,
                        text=True,
                    )

                    if copy_result.returncode == 0:
                        logger.info("Successfully copied scan results from container")
                    else:
                        logger.error(
                            f"Failed to copy scan results: {copy_result.stderr}"
                        )

                    # Copy commit hash from container
                    copy_commit_result = subprocess.run(
                        [
                            "docker",
                            "cp",
                            f"{container_name}:/output/commit.txt",
                            str(commit_file),
                        ],
                        capture_output=True,
                        text=True,
                    )

                    if copy_commit_result.returncode == 0:
                        logger.info("Successfully copied commit hash from container")

                except Exception as e:
                    logger.error(f"Failed to copy files from container: {e}")
                finally:
                    # Clean up container
                    with contextlib.suppress(Exception):
                        subprocess.run(
                            ["docker", "rm", "-f", container_name], capture_output=True
                        )

            # Read scan results
            if results_file.exists():
                with open(results_file) as f:
                    # Parse the JSON output directly
                    try:
                        scan_results = json.load(f)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse scan results: {e}")
                        # Log file contents for debugging
                        f.seek(0)
                        logger.debug(f"Results file contents: {f.read()}")
                        return False, {}, ""

                # Read commit hash
                commit_hash = ""
                if commit_file.exists():
                    with open(commit_file) as f:
                        commit_hash = f.read().strip()

                # Clean up container
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["docker", "rm", "-f", container_name], capture_output=True
                    )

                return True, scan_results, commit_hash
            logger.error(f"Scan results file not found: {results_file}")
            logger.debug(f"Container stdout: {result.stdout}")
            logger.debug(f"Container stderr: {result.stderr}")
            return False, {}, ""

        except Exception as e:
            logger.error(f"Failed to run scan in container: {str(e)}")
            return False, {}, ""


def clone_repository(repo_url: str, target_path: Path, commit_hash: str) -> bool:
    """Clone a Git repository at a specific commit.

    Args:
        repo_url: URL of the Git repository to clone
        target_path: Path where to clone the repository
        commit_hash: Specific commit to check out

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Clone the repository
        logger.info(f"Cloning {repo_url} to {target_path}")

        subprocess.run(
            ["git", "clone", repo_url, str(target_path)],
            capture_output=True,
            text=True,
            check=True,
        )

        # Check out the specific commit
        logger.info(f"Checking out commit {commit_hash}")
        subprocess.run(
            ["git", "checkout", commit_hash],
            cwd=target_path,
            capture_output=True,
            text=True,
            check=True,
        )

        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone repository: {e.stderr}")
        return False
