"""Tests for docker_utils.py module."""

import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from insect.utils.docker_utils import (
    check_docker_available,
    build_insect_image,
    run_scan_in_container,
    clone_repository,
    DEFAULT_DOCKER_IMAGE
)


def test_check_docker_available():
    """Test checking Docker availability."""
    # Mock successful case
    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=0)
        assert check_docker_available() is True
        mock_run.assert_called_once_with(
            ["docker", "--version"], 
            capture_output=True, 
            text=True, 
            check=False
        )
    
    # Mock failure case
    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=1)
        assert check_docker_available() is False
    
    # Mock exception case
    with mock.patch("subprocess.run", side_effect=FileNotFoundError()):
        assert check_docker_available() is False


def test_build_insect_image():
    """Test building Docker image for Insect."""
    # Mock successful case
    with mock.patch("tempfile.TemporaryDirectory") as mock_tempdir, \
         mock.patch("subprocess.run") as mock_run, \
         mock.patch("pathlib.Path.write_text") as mock_write:
        
        # Setup mocks
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        mock_run.return_value = mock.MagicMock(returncode=0)
        
        # Call function
        success, image_name = build_insect_image()
        
        # Verify success
        assert success is True
        assert image_name == f"insect-scanner:{DEFAULT_DOCKER_IMAGE.replace(':', '-')}"
        
        # Verify Docker build command was called
        mock_run.assert_called_once()
        docker_build_cmd = mock_run.call_args[0][0]
        assert docker_build_cmd[0:2] == ["docker", "build"]
    
    # Mock failure case
    with mock.patch("tempfile.TemporaryDirectory") as mock_tempdir, \
         mock.patch("subprocess.run") as mock_run, \
         mock.patch("pathlib.Path.write_text") as mock_write:
        
        # Setup mocks
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker build", stderr="Build failed")
        
        # Call function
        success, error = build_insect_image()
        
        # Verify failure
        assert success is False
        assert error == "Build failed"


@mock.patch("insect.utils.docker_utils.subprocess.run")
@mock.patch("insect.utils.docker_utils.build_insect_image")
def test_run_scan_in_container(mock_build, mock_run):
    """Test running scans in Docker container."""
    # Setup mocks
    mock_build.return_value = (True, "insect-scanner:test")
    
    # Mock successful Docker run
    mock_process = mock.MagicMock()
    mock_process.returncode = 0
    mock_run.return_value = mock_process
    
    # Create temp directory with test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create mock scan results
        scan_results = {
            "scan_metadata": {
                "file_count": 42,
                "finding_count": 2
            },
            "findings": [
                {
                    "id": "TEST-1",
                    "title": "Test finding 1",
                    "severity": "high"
                },
                {
                    "id": "TEST-2",
                    "title": "Test finding 2",
                    "severity": "medium"
                }
            ]
        }
        
        # Write mock scan results and commit hash
        results_path = Path(temp_dir) / "scan_results.json"
        commit_path = Path(temp_dir) / "commit_hash.txt"
        
        with open(results_path, "w") as f:
            json.dump(scan_results, f)
        
        with open(commit_path, "w") as f:
            f.write("abcdef1234567890")
        
        # Mock tempfile to return our directory
        with mock.patch("tempfile.TemporaryDirectory") as mock_tempdir:
            mock_tempdir.return_value.__enter__.return_value = temp_dir
            
            # Call function
            success, results, commit = run_scan_in_container(
                repo_url="https://github.com/example/repo",
                branch="main"
            )
            
            # Verify success
            assert success is True
            assert results == scan_results
            assert commit == "abcdef1234567890"
            
            # Verify Docker run command
            mock_run.assert_called_once()
            docker_run_cmd = mock_run.call_args[0][0]
            assert docker_run_cmd[0:2] == ["docker", "run"]
            
            # Test with custom arguments
            mock_run.reset_mock()
            
            success, results, commit = run_scan_in_container(
                repo_url="https://github.com/example/repo",
                branch="main",
                commit="1234567890abcdef",
                scan_args=["--no-cache", "--severity", "high"],
                image_name="custom-insect:latest"
            )
            
            # Verify custom args were passed
            docker_run_cmd = mock_run.call_args[0][0]
            cmd_string = docker_run_cmd[-1]  # The bash -c command
            assert "--no-cache" in cmd_string
            assert "custom-insect:latest" in docker_run_cmd


@mock.patch("subprocess.run")
def test_clone_repository(mock_run):
    """Test cloning repository at specific commit."""
    # Mock successful clone
    mock_run.return_value = mock.MagicMock(returncode=0)
    
    success = clone_repository(
        repo_url="https://github.com/example/repo",
        target_path=Path("/tmp/repo"),
        commit_hash="abcdef1234567890"
    )
    
    assert success is True
    assert mock_run.call_count == 2  # One for clone, one for checkout
    
    # Mock failure
    mock_run.reset_mock()
    mock_run.side_effect = subprocess.CalledProcessError(1, "git clone", stderr="Clone failed")
    
    success = clone_repository(
        repo_url="https://github.com/example/repo",
        target_path=Path("/tmp/repo"),
        commit_hash="abcdef1234567890"
    )
    
    assert success is False