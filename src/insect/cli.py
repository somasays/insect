"""Command-line interface for Insect."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from insect import __version__, core
from insect.config import handler
from insect.reporting import create_formatter

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("insect.cli")

# Setup Rich console
console = Console()


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments.

    Args:
        args: Command line arguments to parse. Defaults to sys.argv[1:].

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="insect",
        description="Insect - A security scanner for git repositories",
        epilog="Run 'insect scan --help' for more information on scanning options.",
    )

    # Version info
    parser.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}"
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a git repository for security issues"
    )

    # Dependencies command
    deps_parser = subparsers.add_parser(
        "deps", help="Display status of external dependencies"
    )

    # Clone command
    clone_parser = subparsers.add_parser(
        "clone", help="Clone and scan a git repository in a Docker container"
    )

    clone_parser.add_argument(
        "repo_url",
        type=str,
        help="URL of the git repository to clone and scan",
    )

    clone_parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        help="Directory where to clone the repository (defaults to current directory)",
    )

    clone_parser.add_argument(
        "--branch",
        "-b",
        type=str,
        help="Branch to check out (defaults to default branch)",
    )

    clone_parser.add_argument(
        "--commit",
        "-c",
        type=str,
        help="Specific commit to check out (overrides branch)",
    )

    clone_parser.add_argument(
        "--image",
        "-i",
        type=str,
        help="Docker image to use (defaults to 'python:3.10-slim')",
    )

    clone_parser.add_argument(
        "--scan-args",
        type=str,
        help="Additional arguments to pass to the insect scan command",
    )

    clone_parser.add_argument(
        "--report-path",
        type=Path,
        help="Path to save the scan report JSON (defaults to not saving)",
    )

    deps_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    deps_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Path to write dependency report to (defaults to stdout)",
    )

    deps_parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Attempt to install missing dependencies automatically",
    )

    # Verbosity control moved to scan subcommand
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )

    # Required repo path argument
    scan_parser.add_argument(
        "repo_path",
        type=Path,
        help="Path to the git repository to scan",
    )

    # Output options
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Path to write report to (defaults to stdout)",
    )

    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )

    # Scan options
    scan_parser.add_argument(
        "--config",
        "-c",
        type=Path,
        help="Path to configuration file",
    )

    scan_parser.add_argument(
        "--disable",
        action="append",
        help="Disable specific analyzers (can be used multiple times)",
    )

    scan_parser.add_argument(
        "--include-pattern",
        action="append",
        help="Only include files matching pattern (can be used multiple times)",
    )

    scan_parser.add_argument(
        "--exclude-pattern",
        action="append",
        help="Exclude files matching pattern (can be used multiple times)",
    )

    scan_parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Maximum directory depth to scan",
    )

    scan_parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Disable secrets detection",
    )

    scan_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )

    # Cache options
    scan_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable the scan cache (ignore cached results)",
    )

    scan_parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the scan cache before scanning",
    )

    # Progress bar option
    scan_parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the progress bar",
    )

    # Auto-install dependencies option
    scan_parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Attempt to install missing dependencies automatically",
    )

    # Parse arguments
    parsed_args = parser.parse_args(args)

    # Validate arguments
    if parsed_args.command is None:
        parser.print_help()
        sys.exit(1)

    # Set logging level based on verbosity
    if hasattr(parsed_args, "verbose"):
        if parsed_args.verbose == 1:
            logger.setLevel(logging.INFO)
        elif parsed_args.verbose >= 2:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.WARNING)

    return parsed_args


def main(args: Optional[List[str]] = None) -> int:
    """Run the CLI application.

    Args:
        args: Command line arguments to parse. Defaults to sys.argv[1:].

    Returns:
        Exit code.
    """
    try:
        parsed_args = parse_args(args)
        logger.debug(f"Parsed arguments: {parsed_args}")

        if parsed_args.command == "deps":
            # Display dependency information
            from insect.analysis.dependency_manager import (
                generate_dependency_report,
                install_missing_dependencies,
            )

            # Check if auto-install option is set
            if parsed_args.install_deps:
                console.print(
                    "[bold]Attempting to install missing dependencies...[/bold]"
                )

                try:
                    results = install_missing_dependencies()

                    # Summarize installation results
                    total = len(results)
                    success = sum(1 for success in results.values() if success)
                    failed = total - success

                    if failed == 0:
                        console.print(
                            f"[bold green]All {total} dependencies are now available[/bold green]"
                        )
                    else:
                        console.print(
                            f"[bold yellow]Successfully installed {success} out of {total} dependencies[/bold yellow]"
                        )
                        console.print(
                            f"[bold yellow]Failed to install {failed} dependencies[/bold yellow]"
                        )

                    console.print("\n[bold]Updated dependency status:[/bold]")
                except Exception as e:
                    logger.error(f"Error installing dependencies: {e}", exc_info=True)
                    console.print(
                        f"[bold red]Error installing dependencies:[/bold red] {e}"
                    )

            # Generate report based on format
            output_format = parsed_args.format.lower()
            output_path = parsed_args.output

            try:
                if output_path:
                    # Write to file
                    report = generate_dependency_report(output_format, output_path)
                    console.print(
                        f"\n[bold green]Dependency report written to:[/bold green] {output_path}"
                    )
                else:
                    # Display to console
                    report = generate_dependency_report(output_format)

                    if output_format == "text":
                        # For text format, add some styled console output
                        console.print(
                            "\n[bold]Insect External Dependencies Status:[/bold]\n"
                        )
                        console.print(report)
                    else:
                        # For JSON format, just print raw output
                        pass

                return 0
            except Exception as e:
                logger.error(f"Error generating dependency report: {e}", exc_info=True)
                console.print(
                    f"[bold red]Error generating dependency report:[/bold red] {e}"
                )
                return 1

        elif parsed_args.command == "clone":
            from insect.utils.docker_utils import (
                check_docker_available,
                clone_repository,
                run_scan_in_container,
            )

            # Check if Docker is available
            if not check_docker_available():
                console.print(
                    "[bold red]Docker is not available on this system.[/bold red]\n"
                    "Please install Docker and make sure it's running."
                )
                return 1

            repo_url = parsed_args.repo_url
            branch = parsed_args.branch
            commit = parsed_args.commit
            image = parsed_args.image

            # Parse scan args if provided
            scan_args = None
            if parsed_args.scan_args:
                scan_args = parsed_args.scan_args.split()

            # Determine output directory
            output_dir = (
                parsed_args.output_dir
                or Path.cwd() / Path(repo_url.split("/")[-1]).stem
            )

            # Run the scan in a container
            console.print("[bold]Running scan in Docker container...[/bold]")
            with console.status(
                "[bold blue]Scanning repository in container...[/bold blue]"
            ):
                success, scan_results, commit_hash = run_scan_in_container(
                    repo_url=repo_url,
                    branch=branch,
                    commit=commit,
                    scan_args=scan_args,
                    image_name=image,
                )

            if not success:
                console.print("[bold red]Failed to run scan in container[/bold red]")
                return 1

            # Summarize scan results
            if isinstance(scan_results, dict):
                metadata_raw: Any = scan_results.get("scan_metadata", {})
                metadata: Dict[str, Any] = (
                    metadata_raw if isinstance(metadata_raw, dict) else {}
                )
            else:
                metadata = {}
            findings = scan_results.get("findings", [])

            console.print(
                "\n[bold green]Scan completed successfully in container[/bold green]"
            )
            console.print(f"Repository: {repo_url}")
            console.print(f"Commit: {commit_hash}")
            console.print(
                f"Files scanned: {metadata.get('file_count', 0) if isinstance(metadata, dict) else 0}"
            )
            console.print(
                f"Issues found: {metadata.get('finding_count', 0) if isinstance(metadata, dict) else 0}"
            )

            # Save report if requested
            if parsed_args.report_path:
                with open(parsed_args.report_path, "w") as f:
                    json.dump(scan_results, f, indent=2)
                console.print(
                    f"[bold green]Report saved to:[/bold green] {parsed_args.report_path}"
                )

            # If no issues were found or user confirmation
            should_clone = True
            if isinstance(metadata, dict) and metadata.get("finding_count", 0) > 0:
                console.print(
                    "\n[bold yellow]Security issues were found in the repository.[/bold yellow]"
                )

                # Show a sample of findings
                if findings:
                    console.print("\n[bold]Sample of issues found:[/bold]")
                    for i, finding in enumerate(findings[:3], 1):
                        finding_item: Any = finding  # Explicit type hint for mypy
                        if isinstance(finding_item, dict):
                            console.print(
                                f"{i}. [{finding_item.get('severity', 'low')}] {finding_item.get('title', 'Unknown issue')}"
                            )
                        else:
                            console.print(
                                f"{i}. [{finding_item.severity}] {finding_item.title}"
                            )

                    if len(findings) > 3:
                        console.print(f"... and {len(findings) - 3} more issues")

                response = input("\nDo you want to proceed with cloning? (y/N): ")
                should_clone = response.lower() in ["y", "yes"]

            # Clone the repository locally if confirmed
            if should_clone:
                console.print(f"\n[bold]Cloning repository to {output_dir}...[/bold]")

                # Ensure output directory does not exist
                if output_dir.exists():
                    console.print(
                        f"[bold red]Output directory already exists: {output_dir}[/bold red]"
                    )
                    response = input("Do you want to overwrite it? (y/N): ")
                    if response.lower() in ["y", "yes"]:
                        import shutil

                        shutil.rmtree(output_dir)
                    else:
                        console.print(
                            "[bold yellow]Clone operation aborted by user[/bold yellow]"
                        )
                        return 0

                # Clone the repository
                clone_success = clone_repository(
                    repo_url=repo_url, target_path=output_dir, commit_hash=commit_hash
                )

                if clone_success:
                    console.print(
                        f"[bold green]Repository cloned successfully to {output_dir}[/bold green]"
                    )
                else:
                    console.print("[bold red]Failed to clone repository[/bold red]")
                    return 1

            return 0

        elif parsed_args.command == "scan":
            logger.info(f"Scanning repository: {parsed_args.repo_path}")
            console.print(
                f"[bold green]Repository to scan:[/bold green] {parsed_args.repo_path}"
            )

            # Load config from file if specified, or use default
            config_path = parsed_args.config
            if config_path:
                config_path = Path(config_path)

            config = handler.load_config(config_path)

            # Update config with CLI args if provided
            if parsed_args.include_pattern:
                config["patterns"]["include"] = parsed_args.include_pattern

            if parsed_args.exclude_pattern:
                config["patterns"]["exclude"] = parsed_args.exclude_pattern

            if parsed_args.max_depth is not None:
                config["general"]["max_depth"] = parsed_args.max_depth

            if parsed_args.no_secrets:
                config["analyzers"]["secrets_analyzer"] = False

            if parsed_args.severity:
                config["severity"]["min_level"] = parsed_args.severity

            # Handle cache options
            if parsed_args.no_cache:
                config["cache"] = {"enabled": False}
            elif parsed_args.clear_cache:
                # Import cache utils only if needed
                import shutil

                from insect.utils.cache_utils import get_cache_dir

                # Clear the cache directory
                cache_dir = get_cache_dir(config, Path(parsed_args.repo_path))
                if cache_dir.exists():
                    shutil.rmtree(cache_dir)
                    console.print(
                        f"[bold green]Cache cleared:[/bold green] {cache_dir}"
                    )

            # Handle progress bar option
            if parsed_args.no_progress:
                if "progress" not in config:
                    config["progress"] = {}
                config["progress"]["enabled"] = False

            # Handle auto-install dependencies option
            if parsed_args.install_deps:
                config["install_deps"] = True

            # Get enabled analyzers based on config and CLI arguments
            disabled_analyzers = parsed_args.disable or []
            enabled_analyzers = handler.get_enabled_analyzers(
                config, disabled_analyzers
            )

            # Run the scan
            with console.status("[bold blue]Scanning repository...[/bold blue]"):
                scan_findings, metadata = core.scan_repository(
                    Path(parsed_args.repo_path),
                    config,
                    enabled_analyzers=enabled_analyzers,
                )
                findings_list = scan_findings  # Use scan findings

            # Display scan results
            if not metadata:  # Check if metadata is empty (scan failed)
                console.print("\n[bold red]Scan failed[/bold red]")
                return 1

            # Generate report based on format
            output_format = parsed_args.format.lower()
            output_path = parsed_args.output

            try:
                # Create formatter for the requested format
                formatter = create_formatter(output_format, config)

                # Ensure findings are in the right format for the formatter
                findings_for_formatter: List[Any] = findings_list if "findings_list" in locals() else findings  # type: ignore[assignment]

                if output_path:
                    # Write report to file
                    output_file = formatter.write_report(
                        findings_for_formatter, metadata, output_path
                    )
                    console.print(
                        f"\n[bold green]Report written to:[/bold green] {output_file}"
                    )
                else:
                    # If format is text and no output file specified, use Rich for interactive output
                    if output_format == "text":
                        console.print(
                            f"\n[bold green]Scan Completed[/bold green] in {metadata['duration_seconds']:.2f}s"
                        )
                        console.print(f"Repository: {metadata['repository']}")
                        console.print(f"Files scanned: {metadata['file_count']}")
                        console.print(
                            f"[bold]Issues found: {metadata['finding_count']}[/bold]"
                        )

                        # Show cache statistics if available
                        if "cache_stats" in metadata:
                            cache_stats = metadata["cache_stats"]
                            console.print("\n[bold]Cache Statistics:[/bold]")
                            console.print(f"  Cache hits: {cache_stats['hits']}")
                            console.print(f"  Cache misses: {cache_stats['misses']}")
                            if cache_stats["hits"] > 0:
                                hit_percentage = (
                                    cache_stats["hits"]
                                    / (cache_stats["hits"] + cache_stats["misses"])
                                ) * 100
                                console.print(
                                    f"  Cache hit ratio: {hit_percentage:.1f}%"
                                )

                        # Display findings by severity
                        severity_counts = metadata["severity_counts"]
                        if sum(severity_counts.values()) > 0:
                            console.print("\n[bold]Issues by severity:[/bold]")
                            if (
                                "critical" in severity_counts
                                and severity_counts["critical"] > 0
                            ):
                                console.print(
                                    f"  [bold red]Critical: {severity_counts['critical']}[/bold red]"
                                )
                            if (
                                "high" in severity_counts
                                and severity_counts["high"] > 0
                            ):
                                console.print(
                                    f"  [red]High: {severity_counts['high']}[/red]"
                                )
                            if (
                                "medium" in severity_counts
                                and severity_counts["medium"] > 0
                            ):
                                console.print(
                                    f"  [yellow]Medium: {severity_counts['medium']}[/yellow]"
                                )
                            if "low" in severity_counts and severity_counts["low"] > 0:
                                console.print(
                                    f"  [blue]Low: {severity_counts['low']}[/blue]"
                                )

                        # Display detailed findings
                        findings_to_show: Any = (
                            findings_list if "findings_list" in locals() else findings
                        )
                        if findings_to_show:
                            console.print("\n[bold]Issues Details:[/bold]")
                            for i, finding in enumerate(
                                findings_to_show[:10], 1
                            ):  # Show at most 10 findings
                                finding_detail: Any = (
                                    finding  # Explicit type hint for mypy
                                )
                                color = {
                                    "critical": "bold red",
                                    "high": "red",
                                    "medium": "yellow",
                                    "low": "blue",
                                }.get(
                                    (
                                        finding_detail.get("severity", "low")
                                        if isinstance(finding_detail, dict)
                                        else finding_detail.severity.value
                                    ),
                                    "white",
                                )

                                if isinstance(finding_detail, dict):
                                    severity = finding_detail.get("severity", "low")
                                    title = finding_detail.get("title", "Unknown issue")
                                    location = finding_detail.get(
                                        "location", "Unknown location"
                                    )
                                    description = finding_detail.get(
                                        "description", "No description"
                                    )
                                else:
                                    severity = finding_detail.severity.value
                                    title = finding_detail.title
                                    location = str(finding_detail.location)
                                    description = finding_detail.description

                                console.print(
                                    f"{i}. [{color}][{severity.upper()}][/{color}] {title}"
                                )
                                console.print(f"   {location}")
                                console.print(f"   {description}")
                                console.print()

                            # If there are more findings than we showed
                            if len(findings_to_show) > 10:
                                console.print(
                                    f"... and {len(findings_to_show) - 10} more issues."
                                )
                                console.print(
                                    "Use --output and --format to get a full report."
                                )
                    else:
                        # For other formats without output file, print to stdout
                        report = formatter.format_findings(
                            findings_for_formatter, metadata
                        )

            except Exception as e:
                logger.error(f"Error generating report: {e}", exc_info=True)
                console.print(f"[bold red]Error generating report:[/bold red] {e}")
                return 1

            # Return non-zero exit code if critical or high severity issues found
            severity_counts = metadata["severity_counts"]
            if ("critical" in severity_counts and severity_counts["critical"] > 0) or (
                "high" in severity_counts and severity_counts["high"] > 0
            ):
                return 1

            return 0

        return 0
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
