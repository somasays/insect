"""Core orchestration module for Insect."""

import fnmatch
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from insect.analysis import (
    BaseAnalyzer,
    create_analyzer_instance,
    get_all_analyzer_classes,
)
from insect.config.handler import is_finding_allowed, should_report_severity
from insect.finding import Finding, FindingType, Location, Severity
from insect.utils.progress_utils import ProgressBar, get_scan_progress_formatter

logger = logging.getLogger("insect.core")


def is_git_repository(path: Path) -> bool:
    """Check if a path is a git repository.

    Args:
        path: Path to check.

    Returns:
        True if the path is a git repository, False otherwise.
    """
    git_dir = path / ".git"
    return git_dir.exists() and git_dir.is_dir()


def filter_files(
    files: List[Path], include_patterns: List[str], exclude_patterns: List[str]
) -> List[Path]:
    """Filter files based on include and exclude patterns.

    Args:
        files: List of file paths to filter.
        include_patterns: List of glob patterns to include.
        exclude_patterns: List of glob patterns to exclude.

    Returns:
        Filtered list of file paths.
    """
    # Start with all files if include_patterns contains "*", otherwise empty list
    if "*" in include_patterns:
        result = files.copy()
    else:
        result = []
        for pattern in include_patterns:
            # Use fnmatch for proper glob pattern matching
            matches = [f for f in files if fnmatch.fnmatch(str(f), pattern)]
            result.extend(matches)

    # Remove files matching exclude patterns
    for pattern in exclude_patterns:
        # Use fnmatch for proper glob pattern matching
        result = [f for f in result if not fnmatch.fnmatch(str(f), pattern)]

    return result


def discover_files(
    repo_path: Path,
    config: Dict[str, Any],
    max_depth: Optional[int] = None,
) -> List[Path]:
    """Discover files in a repository.

    Args:
        repo_path: Path to the repository.
        config: Configuration dictionary.
        max_depth: Maximum depth to search. If None, uses config value.

    Returns:
        List of file paths.
    """
    # Use provided max_depth or get from config
    if max_depth is None:
        max_depth = config["general"]["max_depth"]

    include_hidden = config["general"]["include_hidden"]
    include_patterns = config["patterns"]["include"]
    exclude_patterns = config["patterns"]["exclude"]

    # List to store all discovered files
    all_files: List[Path] = []

    # Walk through the repository
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden directories unless include_hidden is True
        if not include_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]

        # Calculate current depth relative to repo_path
        rel_path = Path(root).relative_to(repo_path)
        current_depth = 0 if rel_path == Path(".") else len(rel_path.parts)

        # Respect max_depth
        if max_depth is not None and current_depth >= max_depth:
            dirs.clear()  # Don't go deeper
            continue

        # Add files in this directory
        for filename in files:
            # Skip hidden files unless include_hidden is True
            if not include_hidden and filename.startswith("."):
                continue

            file_path = Path(root) / filename
            all_files.append(file_path)

    # Apply include/exclude filters
    filtered_files = filter_files(all_files, include_patterns, exclude_patterns)

    logger.debug(f"Discovered {len(filtered_files)} files after filtering")
    return filtered_files


def get_file_extension_stats(files: List[Path]) -> Dict[str, int]:
    """Get statistics on file extensions in the repository.

    Args:
        files: List of file paths.

    Returns:
        Dictionary mapping file extensions to count.
    """
    extension_counts: Dict[str, int] = {}
    for file_path in files:
        ext = file_path.suffix.lower()
        extension_counts[ext] = extension_counts.get(ext, 0) + 1

    return extension_counts


def create_analyzers(
    config: Dict[str, Any], enabled_analyzers: Set[str]
) -> List[BaseAnalyzer]:
    """Create analyzer instances based on configuration.

    Args:
        config: Configuration dictionary.
        enabled_analyzers: Set of enabled analyzer names.

    Returns:
        List of analyzer instances.
    """
    analyzers = []

    # Get all registered analyzer classes
    analyzer_classes = get_all_analyzer_classes()

    # Create instances of enabled analyzers
    for name, _analyzer_class in analyzer_classes.items():
        if name in enabled_analyzers:
            analyzer = create_analyzer_instance(name, config)
            if analyzer:
                analyzers.append(analyzer)
                logger.debug(f"Created analyzer: {name}")
            else:
                logger.warning(f"Failed to create analyzer: {name}")

    return analyzers


def find_analyzers_for_file(
    file_path: Path, analyzers: List[BaseAnalyzer]
) -> List[BaseAnalyzer]:
    """Find analyzers that can analyze a specific file.

    Args:
        file_path: Path to the file.
        analyzers: List of analyzer instances.

    Returns:
        List of analyzers that can analyze the file.
    """
    applicable_analyzers = []

    for analyzer in analyzers:
        if analyzer.can_analyze_file(file_path):
            applicable_analyzers.append(analyzer)

    return applicable_analyzers


def analyze_file(
    file_path: Path, analyzers: List[BaseAnalyzer], scan_cache=None
) -> List[Finding]:
    """Analyze a file with all applicable analyzers.

    Args:
        file_path: Path to the file.
        analyzers: List of analyzer instances to apply to this file.
        scan_cache: Optional cache instance for faster re-scanning.

    Returns:
        List of findings from analyzing the file.
    """
    findings = []

    # Skip non-existent files
    if not file_path.exists():
        logger.warning(f"File does not exist: {file_path}")
        return []

    # Skip directories (shouldn't happen with our file discovery)
    if file_path.is_dir():
        logger.debug(f"Skipping directory: {file_path}")
        return []

    # Apply each analyzer
    for analyzer in analyzers:
        try:
            # Double-check that analyzer can handle this file
            if not analyzer.can_analyze_file(file_path):
                logger.debug(f"Analyzer {analyzer.name} can't analyze {file_path}")
                continue

            # Check if we have cached results for this file and analyzer
            if scan_cache is not None and scan_cache.is_file_cached(
                file_path, analyzer.name
            ):
                cached_findings = scan_cache.get_cached_findings(
                    file_path, analyzer.name
                )
                if cached_findings:
                    logger.debug(
                        f"Using cached results for {file_path} with {analyzer.name}"
                    )
                    findings.extend(cached_findings)
                    continue

            # Measure analysis time for performance insights
            start_time = time.time()

            logger.debug(f"Analyzing {file_path} with {analyzer.name}")
            analyzer_findings = analyzer.analyze_file(file_path)

            # Log performance information for slow analyses
            analysis_time = time.time() - start_time
            if analysis_time > 1.0:  # Log slow analyses (>1 second)
                logger.debug(
                    f"Analyzer {analyzer.name} took {analysis_time:.2f}s for {file_path}"
                )

            # Cache the findings if a cache is provided
            if scan_cache is not None:
                scan_cache.cache_findings(file_path, analyzer.name, analyzer_findings)

            findings.extend(analyzer_findings)

            if analyzer_findings:
                logger.debug(
                    f"Found {len(analyzer_findings)} issues in {file_path} with {analyzer.name}"
                )
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {analyzer.name}: {str(e)}")

    return findings


def filter_findings(findings: List[Finding], config: Dict[str, Any]) -> List[Finding]:
    """Filter findings based on configuration.

    Args:
        findings: List of findings to filter.
        config: Configuration dictionary.

    Returns:
        Filtered list of findings.
    """
    filtered_findings = []
    min_severity = config["severity"]["min_level"]
    min_confidence = config.get("confidence", {}).get("min_level", 0.0)

    for finding in findings:
        # Skip findings in allowlist
        if not is_finding_allowed(finding.id, config):
            logger.debug(f"Skipping allowlisted finding: {finding.id}")
            continue

        # Skip findings below minimum severity
        if not should_report_severity(finding.severity.value, min_severity):
            logger.debug(
                f"Skipping finding {finding.id} with severity {finding.severity.value} "
                f"below minimum threshold {min_severity}"
            )
            continue

        # Skip findings below minimum confidence
        if finding.confidence < min_confidence:
            logger.debug(
                f"Skipping finding {finding.id} with confidence {finding.confidence} "
                f"below minimum threshold {min_confidence}"
            )
            continue

        filtered_findings.append(finding)

    return filtered_findings


def create_scan_metadata(
    repo_path: Path,
    files: List[Path],
    findings: List[Finding],
    start_time: float,
    config: Dict[str, Any],
    enabled_analyzers: Set[str],
) -> Dict[str, Any]:
    """Create metadata about the scan.

    Args:
        repo_path: Path to the repository.
        files: List of files that were scanned.
        findings: List of findings from the scan.
        start_time: Start time of the scan (time.time() format).
        config: Configuration dictionary.
        enabled_analyzers: Set of enabled analyzer names.

    Returns:
        Dictionary with scan metadata.
    """
    # Calculate scan duration
    duration = time.time() - start_time

    # Calculate file statistics
    extension_stats = get_file_extension_stats(files)

    # Calculate severity counts
    severity_counts = {severity.name: 0 for severity in Severity}
    for finding in findings:
        severity_counts[finding.severity.name] += 1

    # Calculate finding type counts
    type_counts: Dict[str, int] = {}
    for finding in findings:
        type_name = finding.type.name
        type_counts[type_name] = type_counts.get(type_name, 0) + 1

    # Calculate findings per analyzer
    analyzer_counts: Dict[str, int] = {}
    for finding in findings:
        analyzer_counts[finding.analyzer] = analyzer_counts.get(finding.analyzer, 0) + 1

    # List of unique tags across all findings
    all_tags = set()
    for finding in findings:
        if hasattr(finding, "tags") and finding.tags:
            all_tags.update(finding.tags)

    # Identify file extensions with most findings
    extension_findings: Dict[str, int] = {}
    for finding in findings:
        if hasattr(finding, "location") and finding.location.path:
            ext = finding.location.path.suffix.lower()
            extension_findings[ext] = extension_findings.get(ext, 0) + 1

    # Sort extensions by number of findings
    top_extensions_by_findings = sorted(
        extension_findings.items(), key=lambda x: x[1], reverse=True
    )[
        :5
    ]  # Top 5

    # Create the metadata dictionary
    metadata = {
        "scan_id": str(uuid.uuid4()),
        "repository": str(repo_path),
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": duration,
        "file_count": len(files),
        "finding_count": len(findings),
        "enabled_analyzers": list(enabled_analyzers),
        "extension_stats": extension_stats,
        "severity_counts": severity_counts,
        "type_counts": type_counts,
        "analyzer_counts": analyzer_counts,
        "is_git_repository": is_git_repository(repo_path),
        "tags": sorted(all_tags),
        "top_extensions_by_findings": dict(top_extensions_by_findings),
        "configuration": {
            "min_severity": config.get("severity", {}).get("min_level", "LOW"),
            "include_patterns": config.get("patterns", {}).get("include", ["*"]),
            "exclude_patterns": config.get("patterns", {}).get("exclude", []),
        },
    }

    return metadata


def scan_repository(
    repo_path: Path,
    config: Dict[str, Any],
    enabled_analyzers: Optional[Set[str]] = None,
) -> Tuple[List[Finding], Dict[str, Any]]:
    """Scan a git repository for security issues.

    Args:
        repo_path: Path to the repository.
        config: Configuration dictionary.
        enabled_analyzers: Set of enabled analyzers. If None, uses config.

    Returns:
        Tuple of (list of findings, scan metadata).
    """
    start_time = time.time()
    logger.info(f"Starting scan of repository: {repo_path}")

    # Validate repository
    if not repo_path.exists():
        logger.error(f"Repository path does not exist: {repo_path}")
        return [], {}

    # Determine enabled analyzers
    if enabled_analyzers is None:
        enabled_analyzers = {
            name for name, enabled in config["analyzers"].items() if enabled
        }

    logger.debug(f"Enabled analyzers: {enabled_analyzers}")

    # Create analyzer instances
    analyzers = create_analyzers(config, enabled_analyzers)
    logger.info(f"Created {len(analyzers)} analyzers")

    # Initialize scan cache if enabled
    scan_cache = None
    from insect.utils.cache_utils import ScanCache, cache_enabled, get_cache_dir

    if cache_enabled(config):
        cache_dir = get_cache_dir(config, repo_path)
        scan_cache = ScanCache(repo_path, cache_dir)
        logger.info(f"Scan cache initialized at {cache_dir}")
    else:
        logger.debug("Scan cache disabled by configuration")

    # Discover files
    files = discover_files(repo_path, config)
    logger.info(f"Discovered {len(files)} files to scan")

    # Get file extension statistics for reporting
    extension_stats = get_file_extension_stats(files)
    logger.debug(f"File extension statistics: {extension_stats}")

    # Initialize results list
    all_findings: List[Finding] = []

    # Track which analyzers were actually used
    used_analyzers: Set[str] = set()

    # Group files by applicable analyzers to optimize processing
    analyzer_file_map: Dict[BaseAnalyzer, List[Path]] = {}
    for analyzer in analyzers:
        analyzer_file_map[analyzer] = []

    # Map files to applicable analyzers
    for file_path in files:
        applicable_analyzers = find_analyzers_for_file(file_path, analyzers)

        for analyzer in applicable_analyzers:
            analyzer_file_map[analyzer].append(file_path)
            used_analyzers.add(analyzer.name)

    logger.debug(f"Used analyzers: {used_analyzers}")

    # Process special case analyzers that need to be run once per repository
    # (e.g., metadata_analyzer)
    repo_level_analyzers = [a for a in analyzers if a.supported_extensions == {"*"}]
    file_level_analyzers = [a for a in analyzers if a.supported_extensions != {"*"}]

    # Run repository-level analyzers first (if any files are available)
    if files and repo_level_analyzers:
        logger.info(f"Running {len(repo_level_analyzers)} repository-level analyzers")
        for analyzer in repo_level_analyzers:
            try:
                # Use the first file to trigger repository analysis
                # We don't cache repository-level analyzers
                repo_findings = analyze_file(files[0], [analyzer])
                all_findings.extend(repo_findings)

                if repo_findings:
                    logger.info(
                        f"Found {len(repo_findings)} issues with {analyzer.name}"
                    )
            except Exception as e:
                logger.error(
                    f"Error in repository-level analyzer {analyzer.name}: {str(e)}"
                )

    # Track scanning progress
    total_files = sum(len(file_list) for file_list in analyzer_file_map.values())
    processed_files = 0
    last_progress_log = 0

    # Initialize progress bar if enabled
    use_progress_bar = config.get("progress", {}).get("enabled", True)
    progress_bar = None
    if use_progress_bar and total_files > 0:
        progress_bar = ProgressBar(
            total=total_files,
            prefix="Scanning files:",
            length=40,
            dynamic=True,
        )
        # Set custom formatter for ETA display
        progress_bar.set_suffix_function(get_scan_progress_formatter())

    # Check for missing dependencies and notify user
    from insect.analysis.dependency_manager import (
        get_dependencies_status,
        install_missing_dependencies,
    )

    dependencies = get_dependencies_status()
    missing_dependencies = [
        name for name, status in dependencies.items() if status["status"] != "available"
    ]

    # Try to auto-install dependencies if option is set
    if missing_dependencies and config.get("install_deps", False):
        logger.info(
            f"Auto-installing missing dependencies: {', '.join(missing_dependencies)}"
        )

        # Install missing dependencies
        results = install_missing_dependencies()

        # Recalculate missing dependencies after installation
        dependencies = get_dependencies_status()
        missing_dependencies = [
            name
            for name, status in dependencies.items()
            if status["status"] != "available"
        ]

        # Summarize installation results
        total_deps = len(results)
        success = sum(1 for success in results.values() if success)
        failed = total_deps - success

        if failed == 0:
            logger.info("Successfully installed all missing dependencies")
        else:
            logger.warning(f"Failed to install {failed} of {total_deps} dependencies")

    if missing_dependencies:
        logger.warning(
            f"Some external dependencies are missing: {', '.join(missing_dependencies)}. "
            f"Run 'insect deps' to see installation instructions."
        )

        # Add a finding to inform users about missing dependencies
        all_findings.append(
            Finding(
                id=f"DEPENDENCIES-MISSING-{uuid.uuid4().hex[:8]}",
                title="External dependencies missing",
                description=(
                    f"Some external dependencies are not installed or not in PATH: "
                    f"{', '.join(missing_dependencies)}. This limits the thoroughness of the scan."
                ),
                severity=Severity.LOW,
                type=FindingType.OTHER,
                location=Location(path=repo_path),
                analyzer="dependency_check",
                confidence=1.0,
                tags=["dependency", "missing-tool"],
                remediation="Run 'insect deps --install-deps' to automatically install missing dependencies.",
                cvss_score=0.0,
            )
        )

    # Analyze each file with all applicable analyzers
    for analyzer in file_level_analyzers:
        analyzer_files = analyzer_file_map[analyzer]
        if not analyzer_files:
            continue

        logger.info(f"Running {analyzer.name} on {len(analyzer_files)} files")

        # Start progress bar before processing files with this analyzer
        if progress_bar and not progress_bar._start_time:
            progress_bar.start()

        for i, file_path in enumerate(analyzer_files):
            try:
                # Use the scan cache if available
                findings = analyze_file(file_path, [analyzer], scan_cache)
                all_findings.extend(findings)

                processed_files += 1

                # Update progress bar if enabled
                if progress_bar:
                    progress_bar.update()

                # Log progress at 10% intervals (when not using progress bar)
                if not progress_bar:
                    progress_percentage = (processed_files * 100) // total_files
                    if progress_percentage >= last_progress_log + 10:
                        last_progress_log = (progress_percentage // 10) * 10
                        logger.info(
                            f"Scan progress: {progress_percentage}% ({processed_files}/{total_files})"
                        )

                # Detailed logging on every 100th file or if findings were found
                if i > 0 and i % 100 == 0:
                    logger.debug(
                        f"Scanned {i}/{len(analyzer_files)} files with {analyzer.name}..."
                    )

                if findings:
                    logger.debug(
                        f"Found {len(findings)} issues in {file_path} with {analyzer.name}"
                    )
            except Exception as e:
                logger.error(
                    f"Error analyzing {file_path} with {analyzer.name}: {str(e)}"
                )

    # Finish progress bar if it was started
    if progress_bar and progress_bar._start_time:
        progress_bar.finish()

    # Save the cache after scanning all files
    if scan_cache is not None:
        scan_cache.save_cache()

        # Log cache statistics
        cache_stats = scan_cache.get_cache_stats()
        logger.info(
            f"Cache statistics: {cache_stats['hits']} hits, {cache_stats['misses']} misses, "
            f"{cache_stats['files_skipped']} files skipped"
        )

        # Clean old entries
        if config.get("cache", {}).get("cleanup_enabled", True):
            max_age_days = config.get("cache", {}).get("max_age_days", 30)
            cleaned_entries = scan_cache.clean_old_entries(max_age_days)
            if cleaned_entries > 0:
                logger.info(f"Cleaned {cleaned_entries} old entries from the cache")
                scan_cache.save_cache()  # Save again after cleanup

    # Filter findings based on configuration
    filtered_findings = filter_findings(all_findings, config)
    logger.info(
        f"Filtered {len(all_findings) - len(filtered_findings)} findings based on configuration"
    )

    # Create scan metadata
    metadata = create_scan_metadata(
        repo_path, files, filtered_findings, start_time, config, used_analyzers
    )

    # Add cache stats to metadata if available
    if scan_cache is not None:
        metadata["cache_stats"] = scan_cache.get_cache_stats()

    # Calculate time-related metrics
    files_per_second = (
        len(files) / metadata["duration_seconds"]
        if metadata["duration_seconds"] > 0
        else 0
    )
    findings_per_file = len(filtered_findings) / len(files) if len(files) > 0 else 0

    logger.info(
        f"Scan completed in {metadata['duration_seconds']:.2f}s "
        f"({files_per_second:.1f} files/s). "
        f"Found {len(filtered_findings)} security issues "
        f"({findings_per_file:.2f} findings/file)."
    )

    return filtered_findings, metadata
