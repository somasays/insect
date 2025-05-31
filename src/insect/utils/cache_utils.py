"""
Caching utilities for Insect.

This module provides a caching mechanism for faster re-scanning by storing
file hashes and analysis results.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from insect.finding import Finding
from insect.utils.hash_utils import calculate_file_hash

logger = logging.getLogger(__name__)


class ScanCache:
    """Cache for scan results to speed up re-scanning."""

    def __init__(self, repo_path: Path, cache_dir: Optional[Path] = None) -> None:
        """Initialize the scan cache.

        Args:
            repo_path: Path to the repository being scanned.
            cache_dir: Directory to store cache files. Defaults to .insect/cache
                       in the repository root.
        """
        self.repo_path = repo_path

        # Default cache location is .insect/cache in the repo
        if cache_dir is None:
            self.cache_dir = repo_path / ".insect" / "cache"
        else:
            self.cache_dir = cache_dir

        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)

        # Path to the cache file
        self.cache_file = self.cache_dir / "scan_cache.json"

        # Cache data format:
        # {
        #     "version": 1,
        #     "last_scan": ISO-8601 timestamp,
        #     "file_hashes": {
        #         "/path/to/file.py": {
        #             "hash": "sha256:...",
        #             "mtime": modification time,
        #             "analyzers": {
        #                 "analyzer_name": {
        #                     "findings": [...],
        #                     "timestamp": ISO-8601 timestamp,
        #                 }
        #             }
        #         }
        #     }
        # }
        self.cache_data = self._load_cache()

        # Keep track of how many cache hits/misses we get
        self.stats = {
            "hits": 0,
            "misses": 0,
            "files_scanned": 0,
            "files_skipped": 0,
        }

    def _load_cache(self) -> Dict[str, Any]:
        """Load cache data from disk.

        Returns:
            The loaded cache data, or a new cache if none exists.
        """
        if not self.cache_file.exists():
            logger.debug(
                f"No cache file found at {self.cache_file}, creating new cache"
            )
            return {
                "version": 1,
                "last_scan": datetime.now().isoformat(),
                "file_hashes": {},
            }

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                cache_data = json.load(f)

            # Check cache version
            if cache_data.get("version", 0) != 1:
                logger.warning("Cache version mismatch, creating new cache")
                return {
                    "version": 1,
                    "last_scan": datetime.now().isoformat(),
                    "file_hashes": {},
                }

            logger.info(
                f"Loaded scan cache with {len(cache_data.get('file_hashes', {}))} entries"
            )
            return cache_data

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning(f"Error loading cache file: {e}, creating new cache")
            return {
                "version": 1,
                "last_scan": datetime.now().isoformat(),
                "file_hashes": {},
            }

    def save_cache(self) -> None:
        """Save cache data to disk."""
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache_data, f, indent=2)
            logger.debug(f"Saved scan cache to {self.cache_file}")
        except Exception as e:
            logger.warning(f"Error saving cache file: {e}")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.

        Returns:
            Dict with cache statistics (hits, misses, files scanned, files skipped).
        """
        return self.stats

    def is_file_cached(self, file_path: Path, analyzer_name: str) -> bool:
        """Check if a file has a valid cache entry for a specific analyzer.

        Args:
            file_path: Path to the file.
            analyzer_name: Name of the analyzer.

        Returns:
            True if the file is cached for this analyzer, False otherwise.
        """
        str_path = str(file_path)

        # Check if the file is in the cache
        if str_path not in self.cache_data["file_hashes"]:
            self.stats["misses"] += 1
            return False

        file_info = self.cache_data["file_hashes"][str_path]

        # Check if the analyzer results are cached
        if analyzer_name not in file_info.get("analyzers", {}):
            self.stats["misses"] += 1
            return False

        # Check if the file has been modified since the last scan
        try:
            current_mtime = file_path.stat().st_mtime
            cached_mtime = file_info.get("mtime", 0)

            # If the modification time has changed, recalculate hash
            if current_mtime != cached_mtime:
                current_hash = calculate_file_hash(file_path)
                cached_hash = file_info.get("hash", "")

                # If the hash has changed, the file has been modified
                if current_hash != cached_hash:
                    self.stats["misses"] += 1
                    return False

                # Update the mtime if the hash hasn't changed
                file_info["mtime"] = current_mtime
        except (FileNotFoundError, OSError):
            # If we can't stat the file, assume it's not cached
            self.stats["misses"] += 1
            return False

        # File is cached and up-to-date
        self.stats["hits"] += 1
        return True

    def get_cached_findings(self, file_path: Path, analyzer_name: str) -> List[Finding]:
        """Get cached findings for a file from a specific analyzer.

        Args:
            file_path: Path to the file.
            analyzer_name: Name of the analyzer.

        Returns:
            List of findings from the cache, or an empty list if not cached.
        """
        str_path = str(file_path)

        if not self.is_file_cached(file_path, analyzer_name):
            return []

        try:
            # Get the cached findings
            cache_entry = self.cache_data["file_hashes"][str_path]["analyzers"][
                analyzer_name
            ]
            findings_dicts = cache_entry.get("findings", [])

            # Convert the dictionaries back to Finding objects
            findings = []
            for finding_dict in findings_dicts:
                try:
                    finding = Finding.from_dict(finding_dict)
                    findings.append(finding)
                except Exception as e:
                    logger.warning(f"Error deserializing cached finding: {e}")

            return findings

        except (KeyError, TypeError) as e:
            logger.warning(f"Error retrieving cached findings: {e}")
            return []

    def cache_findings(
        self, file_path: Path, analyzer_name: str, findings: List[Finding]
    ) -> None:
        """Cache findings for a file from a specific analyzer.

        Args:
            file_path: Path to the file.
            analyzer_name: Name of the analyzer.
            findings: List of findings to cache.
        """
        str_path = str(file_path)

        try:
            # Calculate the file's hash
            file_hash = calculate_file_hash(file_path)
            file_mtime = file_path.stat().st_mtime

            # Create the cache entry if it doesn't exist
            if str_path not in self.cache_data["file_hashes"]:
                self.cache_data["file_hashes"][str_path] = {
                    "hash": file_hash,
                    "mtime": file_mtime,
                    "analyzers": {},
                }
            else:
                # Update hash and mtime
                self.cache_data["file_hashes"][str_path]["hash"] = file_hash
                self.cache_data["file_hashes"][str_path]["mtime"] = file_mtime

            # Convert findings to dictionaries
            findings_dicts = [finding.to_dict() for finding in findings]

            # Cache the findings for this analyzer
            self.cache_data["file_hashes"][str_path]["analyzers"][analyzer_name] = {
                "findings": findings_dicts,
                "timestamp": datetime.now().isoformat(),
            }

            # Update the last scan timestamp
            self.cache_data["last_scan"] = datetime.now().isoformat()

        except (FileNotFoundError, OSError, TypeError, ValueError) as e:
            logger.warning(f"Error caching findings for {file_path}: {e}")

    def clean_old_entries(self, max_age_days: int = 30) -> int:
        """Clean old entries from the cache.

        Args:
            max_age_days: Maximum age of cache entries in days.

        Returns:
            Number of entries removed.
        """
        now = datetime.now()
        max_age_seconds = max_age_days * 24 * 60 * 60
        entries_removed = 0

        # Loop through all files in the cache
        for file_path in list(self.cache_data["file_hashes"].keys()):
            file_info = self.cache_data["file_hashes"][file_path]

            # Check if the file exists
            path_obj = Path(file_path)
            if not path_obj.exists():
                # Remove the entry if the file doesn't exist
                del self.cache_data["file_hashes"][file_path]
                entries_removed += 1
                continue

            # Check the age of each analyzer's findings
            if "analyzers" in file_info:
                for analyzer_name in list(file_info["analyzers"].keys()):
                    analyzer_info = file_info["analyzers"][analyzer_name]
                    timestamp_str = analyzer_info.get("timestamp")

                    if timestamp_str:
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str)
                            age_seconds = (now - timestamp).total_seconds()

                            if age_seconds > max_age_seconds:
                                # Remove old analyzer entry
                                del file_info["analyzers"][analyzer_name]
                                entries_removed += 1
                        except (ValueError, TypeError):
                            # Remove invalid timestamp entries
                            del file_info["analyzers"][analyzer_name]
                            entries_removed += 1

                # Remove the file entry if it has no analyzers left
                if not file_info["analyzers"]:
                    del self.cache_data["file_hashes"][file_path]
                    entries_removed += 1

        return entries_removed


def cache_enabled(config: Dict[str, Any]) -> bool:
    """Check if caching is enabled in the configuration.

    Args:
        config: Configuration dictionary.

    Returns:
        True if caching is enabled, False otherwise.
    """
    return config.get("cache", {}).get("enabled", True)


def get_cache_dir(config: Dict[str, Any], repo_path: Path) -> Path:
    """Get the cache directory from the configuration.

    Args:
        config: Configuration dictionary.
        repo_path: Path to the repository.

    Returns:
        Path to the cache directory.
    """
    cache_dir = config.get("cache", {}).get("directory")

    if cache_dir:
        return Path(cache_dir)

    # Default to .insect/cache in the repo
    return repo_path / ".insect" / "cache"
