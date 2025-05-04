"""Configuration handler for the Insect application."""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import toml

logger = logging.getLogger("insect.config")

# Default configuration
DEFAULT_CONFIG = {
    "general": {
        "max_depth": 10,
        "include_hidden": False,
    },
    "analyzers": {
        "static": True,
        "config": True,
        "binary": True,
        "metadata": True,
        "secrets": True,
    },
    "patterns": {
        "include": ["*"],
        "exclude": [
            "*.git/*",
            "node_modules/*",
            "venv/*",
            ".venv/*",
            "*.pyc",
            "__pycache__/*",
            "*.min.js",
            "*.min.css",
        ],
    },
    "severity": {
        "min_level": "low",  # Options: low, medium, high, critical
    },
    "allowlist": {
        "files": [],
        "directories": [],
        "patterns": [],
        "findings": [],  # List of finding IDs to ignore
    },
}

# Severity levels for findings
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from file and merge with defaults.

    Args:
        config_path: Path to the configuration file. If None, uses default config.

    Returns:
        Merged configuration dictionary.
    """
    config = DEFAULT_CONFIG.copy()

    if config_path:
        try:
            if not config_path.exists():
                logger.warning(f"Configuration file not found: {config_path}")
            else:
                user_config = toml.load(config_path)
                config = merge_configs(config, user_config)
                logger.debug(f"Loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}")
            logger.debug("Using default configuration")

    return config


def merge_configs(
    base_config: Dict[str, Any], override_config: Dict[str, Any]
) -> Dict[str, Any]:
    """Recursively merge configurations, with override_config taking precedence.

    Args:
        base_config: Base configuration dictionary.
        override_config: Override configuration dictionary.

    Returns:
        Merged configuration dictionary.
    """
    result = base_config.copy()

    for key, value in override_config.items():
        # If the key exists in base_config and both values are dictionaries, merge them
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        # Otherwise, override the value
        else:
            result[key] = value

    return result


def create_default_config_file(path: Path) -> bool:
    """Create a default configuration file at the specified path.

    Args:
        path: Path where to create the configuration file.

    Returns:
        True if the file was created successfully, False otherwise.
    """
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Write the default configuration
        with open(path, "w") as f:
            toml.dump(DEFAULT_CONFIG, f)

        logger.info(f"Created default configuration file at {path}")
        return True
    except Exception as e:
        logger.error(f"Error creating default configuration file: {e}")
        return False


def is_path_allowed(path: Path, config: Dict[str, Any]) -> bool:
    """Check if a path should be included in the scan based on allowlist.

    Args:
        path: Path to check.
        config: Configuration dictionary.

    Returns:
        True if the path is allowed, False if it should be skipped.
    """
    # Convert path to string for comparison
    path_str = str(path)

    # Check if the file is in the allowlist
    if str(path) in config["allowlist"]["files"]:
        return False

    # Check if the file is in an allowlisted directory
    for directory in config["allowlist"]["directories"]:
        if path_str.startswith(directory):
            return False

    # Check if the file matches an allowlisted pattern
    # This would need a more sophisticated implementation with glob matching
    return all(pattern not in path_str for pattern in config["allowlist"]["patterns"])


def is_finding_allowed(finding_id: str, config: Dict[str, Any]) -> bool:
    """Check if a finding should be reported based on allowlist.

    Args:
        finding_id: ID of the finding to check.
        config: Configuration dictionary.

    Returns:
        True if the finding should be reported, False if it should be ignored.
    """
    return finding_id not in config["allowlist"]["findings"]


def get_enabled_analyzers(
    config: Dict[str, Any], disabled_analyzers: Optional[List[str]] = None
) -> Set[str]:
    """Get the set of enabled analyzers based on config and CLI overrides.

    Args:
        config: Configuration dictionary.
        disabled_analyzers: List of analyzers to disable from CLI.

    Returns:
        Set of names of enabled analyzers.
    """
    # Start with all analyzers that are enabled in config
    enabled = {name for name, enabled in config["analyzers"].items() if enabled}

    # Remove analyzers disabled via CLI
    if disabled_analyzers:
        enabled = enabled - set(disabled_analyzers)

    return enabled


def get_severity_index(severity: str) -> int:
    """Get the index of a severity level.

    Args:
        severity: Severity level string (low, medium, high, critical).

    Returns:
        Index of the severity level (0-3).
    """
    try:
        return SEVERITY_LEVELS.index(severity.lower())
    except ValueError:
        logger.warning(f"Unknown severity level: {severity}, defaulting to low")
        return 0


def should_report_severity(finding_severity: str, min_severity: str) -> bool:
    """Check if a finding should be reported based on severity.

    Args:
        finding_severity: Severity of the finding.
        min_severity: Minimum severity to report.

    Returns:
        True if the finding should be reported, False otherwise.
    """
    finding_index = get_severity_index(finding_severity)
    min_index = get_severity_index(min_severity)

    return finding_index >= min_index
