"""Unit tests for the configuration handler."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import toml

from insect.config import handler


def test_default_config():
    """Test default configuration when no config file is provided."""
    config = handler.load_config()

    # Verify structure and some key values
    assert "general" in config
    assert "analyzers" in config
    assert "patterns" in config
    assert "severity" in config
    assert "allowlist" in config

    assert config["general"]["max_depth"] == 10
    assert config["analyzers"]["static"] is True
    assert "*.git/*" in config["patterns"]["exclude"]
    assert config["severity"]["min_level"] == "low"


def test_load_config_file_exists():
    """Test loading a configuration file that exists."""
    # Create a temporary config file
    test_config = {
        "general": {
            "max_depth": 5,
        },
        "analyzers": {
            "binary": False,
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml") as tmp:
        # Write test config to the temp file
        toml.dump(test_config, tmp)
        tmp.flush()

        # Load the config
        config_path = Path(tmp.name)
        config = handler.load_config(config_path)

        # Verify the config was merged correctly
        assert config["general"]["max_depth"] == 5  # Overridden
        assert config["analyzers"]["binary"] is False  # Overridden
        assert config["analyzers"]["static"] is True  # Default value preserved


def test_load_config_file_not_exists():
    """Test loading a configuration file that doesn't exist."""
    with patch.object(handler.logger, "warning") as mock_warning:
        config = handler.load_config(Path("/nonexistent/path/config.toml"))

        # Verify warning was logged
        mock_warning.assert_called_once()

        # Verify default config was used
        assert config["general"]["max_depth"] == 10
        assert config["analyzers"]["static"] is True


def test_load_config_file_invalid():
    """Test loading an invalid configuration file."""
    # Mock the toml.load function to raise an exception
    with patch("toml.load", side_effect=Exception("Invalid TOML")), patch.object(
        handler.logger, "error"
    ) as mock_error, patch.object(handler.logger, "debug") as mock_debug:
        # Use a mock path that "exists"
        mock_path = Path("mock_config.toml")
        with patch.object(Path, "exists", return_value=True):
            config = handler.load_config(mock_path)

            # Verify error was logged
            mock_error.assert_called_once()
            mock_debug.assert_called_once_with("Using default configuration")

            # Verify default config was used
            assert config["general"]["max_depth"] == 10
            assert config["analyzers"]["static"] is True


def test_merge_configs():
    """Test merging configuration dictionaries."""
    base = {"a": 1, "b": {"c": 2, "d": 3}, "e": [1, 2, 3]}

    override = {"a": 10, "b": {"c": 20}, "f": "new"}

    result = handler.merge_configs(base, override)

    # Verify results
    assert result["a"] == 10  # Overridden
    assert result["b"]["c"] == 20  # Nested override
    assert result["b"]["d"] == 3  # Preserved
    assert result["e"] == [1, 2, 3]  # Preserved
    assert result["f"] == "new"  # Added


def test_create_default_config_file():
    """Test creating a default configuration file."""
    # Use a temporary directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        config_path = Path(tmp_dir) / "config.toml"

        # Create the default config file
        success = handler.create_default_config_file(config_path)

        # Verify it was created successfully
        assert success is True
        assert config_path.exists()

        # Load and verify the content
        config = toml.load(config_path)
        assert config["general"]["max_depth"] == 10
        assert "*.git/*" in config["patterns"]["exclude"]


def test_create_default_config_file_error():
    """Test handling errors when creating a default configuration file."""
    # Mock os.makedirs to raise an exception
    with patch(
        "os.makedirs", side_effect=PermissionError("Permission denied")
    ), patch.object(handler.logger, "error") as mock_error:
        success = handler.create_default_config_file(Path("/invalid/path/config.toml"))

        # Verify error was logged and function returned False
        mock_error.assert_called_once()
        assert success is False


def test_is_path_allowed():
    """Test checking if a path is allowed based on allowlist."""
    config = {
        "allowlist": {
            "files": ["/path/to/ignored.py"],
            "directories": ["/path/to/ignored_dir"],
            "patterns": ["secret"],
        }
    }

    # Test with a allowed path
    assert handler.is_path_allowed(Path("/path/to/allowed.py"), config) is True

    # Test with a path in allowlisted files
    assert handler.is_path_allowed(Path("/path/to/ignored.py"), config) is False

    # Test with a path in allowlisted directory
    assert (
        handler.is_path_allowed(Path("/path/to/ignored_dir/file.py"), config) is False
    )

    # Test with a path matching allowlisted pattern
    assert handler.is_path_allowed(Path("/path/to/my_secret_file.py"), config) is False


def test_is_finding_allowed():
    """Test checking if a finding is allowed based on allowlist."""
    config = {"allowlist": {"findings": ["INSECT-001", "INSECT-002"]}}

    # Test with an allowed finding
    assert handler.is_finding_allowed("INSECT-003", config) is True

    # Test with an allowlisted finding
    assert handler.is_finding_allowed("INSECT-001", config) is False


def test_get_enabled_analyzers():
    """Test getting enabled analyzers based on config and CLI overrides."""
    config = {
        "analyzers": {"static": True, "config": True, "binary": False, "metadata": True}
    }

    # Test with no CLI overrides
    enabled = handler.get_enabled_analyzers(config)
    assert "static" in enabled
    assert "config" in enabled
    assert "binary" not in enabled
    assert "metadata" in enabled

    # Test with CLI overrides
    enabled = handler.get_enabled_analyzers(config, ["static", "metadata"])
    assert "static" not in enabled
    assert "config" in enabled
    assert "binary" not in enabled
    assert "metadata" not in enabled


def test_get_severity_index():
    """Test getting severity level index."""
    assert handler.get_severity_index("low") == 0
    assert handler.get_severity_index("medium") == 1
    assert handler.get_severity_index("high") == 2
    assert handler.get_severity_index("critical") == 3

    # Test with unknown severity (should default to low)
    with patch.object(handler.logger, "warning") as mock_warning:
        assert handler.get_severity_index("unknown") == 0
        mock_warning.assert_called_once()


def test_should_report_severity():
    """Test checking if a finding should be reported based on severity."""
    # Finding with same severity as minimum
    assert handler.should_report_severity("low", "low") is True

    # Finding with higher severity than minimum
    assert handler.should_report_severity("medium", "low") is True
    assert handler.should_report_severity("high", "medium") is True
    assert handler.should_report_severity("critical", "low") is True

    # Finding with lower severity than minimum
    assert handler.should_report_severity("low", "medium") is False
    assert handler.should_report_severity("medium", "high") is False
