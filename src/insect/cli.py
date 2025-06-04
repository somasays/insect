"""Command-line interface for Insect."""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    Column,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm

from insect import __version__, core
from insect.config import handler
from insect.reporting import create_formatter

# Setup logging
log_file = Path.cwd() / ".insect.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(),  # Keep console output for debug mode
    ],
)
logger = logging.getLogger("insect.cli")

# Set console handler to only show WARNING and above by default
console_handler = None
for log_handler in logging.getLogger().handlers:
    if isinstance(log_handler, logging.StreamHandler) and not isinstance(
        log_handler, logging.FileHandler
    ):
        console_handler = log_handler
        break

if console_handler:
    console_handler.setLevel(
        logging.ERROR
    )  # Only show errors on console to keep UI clean

# Setup Rich console for basic text output
console = Console(width=None, force_terminal=True, legacy_windows=False)

# Global flag to track if the welcome screen has been shown
_welcome_screen_shown = False

# ASCII Art for the welcome screen
INSECT_ASCII = """
    ╦ ╔╗╔ ╔═╗ ╔═╗ ╔═╗ ╔╦╗
    ║ ║║║ ╚═╗ ║╣  ║   ║
    ╩ ╝╚╝ ╚═╝ ╚═╝ ╚═╝ ╩
"""

SECURITY_ICONS = {
    "shield": "🛡️",
    "bug": "🐛",
    "warning": "⚠️",
    "check": "✅",
    "cross": "❌",
    "scan": "🔍",
    "lock": "🔒",
    "key": "🔑",
    "alert": "🚨",
    "fire": "🔥",
}


def show_welcome_screen():
    """Display a minimal welcome message."""
    # Simple, clean banner following CLI best practices
    console.print(
        f"[bold cyan]INSECT[/bold cyan] [dim]v{__version__}[/dim] - External Repository Security Scanner"
    )


def create_fancy_progress(description: str):
    """Create a fancy progress bar with spinners and colors."""
    # Get terminal width and adjust bar width accordingly
    terminal_width = console.size.width
    bar_width = max(20, min(40, terminal_width - 50))  # Responsive bar width

    return Progress(
        SpinnerColumn("dots12", style="cyan"),
        TextColumn(
            f"[bold blue]{description}", table_column=Column(min_width=25, max_width=35)
        ),
        BarColumn(bar_width=bar_width, style="green", complete_style="bright_green"),
        TaskProgressColumn(),
        "•",
        TimeElapsedColumn(),
        console=console,
        transient=False,
        expand=True,
    )


def display_scan_summary(metadata: Dict[str, Any]):
    """Display essential scan results in a clean, minimal format."""
    # Essential stats only
    duration = metadata.get("duration_seconds", 0)
    file_count = metadata.get("file_count", 0)
    severity_counts = metadata.get("severity_counts", {})
    total_issues = sum(severity_counts.values())

    # Critical stats on one line
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    urgent = critical + high

    # Single line summary following CLI best practices
    status = "[green]✓[/green]" if urgent == 0 else "[red]⚠[/red]"
    console.print(
        f"\n{status} [bold]{file_count}[/bold] files • [bold]{total_issues}[/bold] issues • {duration:.1f}s"
    )

    if urgent > 0:
        console.print(f"[red]  {critical} critical, {high} high priority[/red]")
    elif total_issues > 0:
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)
        console.print(f"[yellow]  {medium} medium, {low} low priority[/yellow]")


def display_findings_summary(findings: List[Any], metadata: Dict[str, Any]):
    """Display findings in a focused, scannable format."""
    if not findings:
        console.print("\n[green]✓ No security issues found[/green]")
        return

    # Focus on urgent issues first (CLI best practice: show most important info first)
    urgent_issues = [
        f
        for f in findings
        if hasattr(f, "severity") and f.severity.value in ["critical", "high"]
    ]

    if urgent_issues:
        console.print(
            f"\n[bold red]⚠ {len(urgent_issues)} urgent issues require attention:[/bold red]"
        )

        # Show only top 5 most critical in simplified format
        for i, finding in enumerate(urgent_issues[:5], 1):
            severity_color = "red" if finding.severity.value == "critical" else "yellow"
            # Simplified one-line format
            file_name = (
                finding.location.path.name
                if hasattr(finding.location, "path")
                else "unknown"
            )
            console.print(
                f"  [{severity_color}]{i}. {finding.severity.value.upper()}[/{severity_color}] {finding.title[:60]}"
            )
            console.print(f"     [dim]in {file_name}[/dim]")

        if len(urgent_issues) > 5:
            console.print(
                f"     [dim]... and {len(urgent_issues) - 5} more urgent issues[/dim]"
            )

    # Show summary of remaining issues
    severity_counts = metadata.get("severity_counts", {})
    medium = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)

    if medium > 0 or low > 0:
        console.print(
            f"\n[dim]Additional issues: {medium} medium, {low} low priority[/dim]"
        )


def display_next_steps(findings: List[Any], _metadata: Dict[str, Any]):
    """Display concise, actionable next steps."""
    console.print("\n[bold]Next steps:[/bold]")

    # Count urgent issues from actual findings (more reliable than metadata)
    urgent_count = len(
        [
            f
            for f in findings
            if hasattr(f, "severity") and f.severity.value in ["critical", "high"]
        ]
    )
    critical_count = len(
        [
            f
            for f in findings
            if hasattr(f, "severity") and f.severity.value == "critical"
        ]
    )

    if critical_count > 0:
        console.print(
            f"[red]• Address {critical_count} critical vulnerabilities immediately[/red]"
        )
    elif urgent_count > 0:
        console.print(f"[yellow]• Review {urgent_count} high-priority issues[/yellow]")
    else:
        console.print("[green]• No urgent action required[/green]")

    # Show one key command for more details
    console.print(
        "[dim]• Run with[/dim] [cyan]--format html[/cyan] [dim]for detailed report[/dim]"
    )


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments.

    Args:
        args: Command line arguments to parse. Defaults to sys.argv[1:].

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="insect",
        description="Safely analyze external Git repositories for malicious content before cloning",
        epilog="Primary use: 'insect clone <github-url>' for external repos. Secondary: 'insect scan <path>' for local code.",
    )

    # Version info
    parser.add_argument(
        "--version", "-V", action="version", version=f"%(prog)s {__version__}"
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Analyze local code for security issues (consider 'insect clone' for external repos)",
    )

    # Dependencies command
    deps_parser = subparsers.add_parser(
        "deps", help="Display status of external dependencies"
    )

    # Clone command
    clone_parser = subparsers.add_parser(
        "clone",
        help="Safely analyze external repository in container before cloning (RECOMMENDED)",
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
        help="Docker image to use (defaults to 'python:3.13-slim')",
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
        choices=["text", "json", "html", "dashboard-html"],
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

    scan_parser.add_argument(
        "--sensitivity",
        choices=["low", "normal", "high", "very_high"],
        default="normal",
        help="Analysis sensitivity level (default: normal). Higher levels include more speculative findings.",
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

    # Dashboard option
    scan_parser.add_argument(
        "--dashboard",
        action="store_true",
        default=True,
        help="Show interactive dashboard (default)",
    )

    scan_parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable dashboard and show simple text output",
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
            # INFO level for file, WARNING for console
            logging.getLogger().setLevel(logging.INFO)
            if console_handler:
                console_handler.setLevel(logging.WARNING)
        elif parsed_args.verbose >= 2:
            # DEBUG level for file, INFO for console
            logging.getLogger().setLevel(logging.DEBUG)
            if console_handler:
                console_handler.setLevel(logging.INFO)
        else:
            # INFO level for file (default), ERROR for console (clean UI)
            logging.getLogger().setLevel(logging.INFO)
            if console_handler:
                console_handler.setLevel(logging.ERROR)

    return parsed_args


def main(args: Optional[List[str]] = None) -> int:
    """Run the CLI application.

    Args:
        args: Command line arguments to parse. Defaults to sys.argv[1:].

    Returns:
        Exit code.
    """
    global _welcome_screen_shown  # Declare intent to modify global variable
    try:
        # Show welcome screen for interactive usage, only once per session
        if not args and len(sys.argv) > 1 and not _welcome_screen_shown:
            show_welcome_screen()
            _welcome_screen_shown = True

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
                    f"[bold cyan]{SECURITY_ICONS['key']} Attempting to install missing dependencies...[/bold cyan]"
                )

                try:
                    results = install_missing_dependencies()

                    # Summarize installation results
                    total = len(results)
                    success = sum(1 for success in results.values() if success)
                    failed = total - success

                    if failed == 0:
                        console.print(
                            f"[bold green]{SECURITY_ICONS['check']} All {total} dependencies are now available[/bold green]"
                        )
                    else:
                        console.print(
                            f"[bold yellow]{SECURITY_ICONS['warning']} Successfully installed {success} out of {total} dependencies[/bold yellow]"
                        )
                        console.print(
                            f"[bold yellow]{SECURITY_ICONS['cross']} Failed to install {failed} dependencies[/bold yellow]"
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
                        f"\n[bold green]{SECURITY_ICONS['check']} Dependency report written to:[/bold green] {output_path}"
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
                    f"[bold red]{SECURITY_ICONS['cross']} Docker is not available on this system.[/bold red]\n"
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
            if parsed_args.output_dir:
                output_dir = parsed_args.output_dir
            else:
                # Extract repository name from URL, handling various formats
                repo_name = repo_url.rstrip("/").split("/")[-1]
                if repo_name.endswith(".git"):
                    repo_name = repo_name[:-4]
                if not repo_name:  # Fallback if extraction fails
                    repo_name = "cloned-repo"
                output_dir = Path.cwd() / repo_name

            # Run the scan in a container
            console.print(
                f"[bold cyan]{SECURITY_ICONS['scan']} Running scan in Docker container...[/bold cyan]"
            )

            with create_fancy_progress(
                f"{SECURITY_ICONS['scan']} Scanning repository in container"
            ) as progress:
                task = progress.add_task("Scanning...", total=100)

                # Simulate progress updates and run scan
                success, scan_results, commit_hash = run_scan_in_container(
                    repo_url=repo_url,
                    branch=branch,
                    commit=commit,
                    scan_args=scan_args,
                    image_name=image,
                )

                # Complete the progress
                for _i in range(101):
                    progress.update(task, advance=1)
                    time.sleep(0.01)

            if not success:
                console.print(
                    f"[bold red]{SECURITY_ICONS['cross']} Failed to run scan in container[/bold red]"
                )
                return 1

            # Summarize scan results
            scan_results_dict: Dict[str, Any] = (
                scan_results if isinstance(scan_results, dict) else {}
            )
            if scan_results_dict:
                metadata_raw: Any = scan_results_dict.get("scan_metadata", {})
                metadata: Dict[str, Any] = (
                    metadata_raw if isinstance(metadata_raw, dict) else {}
                )
            else:
                metadata = {}
            findings = scan_results_dict.get("findings", [])

            console.print(
                f"\n[bold green]{SECURITY_ICONS['check']} Scan completed successfully in container[/bold green]"
            )
            console.print(
                f"[cyan]{SECURITY_ICONS['scan']} Repository:[/cyan] {repo_url}"
            )
            commit_hash_str: str = str(commit_hash) if commit_hash else "Unknown"
            console.print(
                f"[cyan]{SECURITY_ICONS['key']} Commit:[/cyan] {commit_hash_str}"
            )
            console.print(
                f"[cyan]{SECURITY_ICONS['check']} Files scanned:[/cyan] [bold green]{metadata.get('file_count', 0) if isinstance(metadata, dict) else 0}[/bold green]"
            )
            console.print(
                f"[cyan]{SECURITY_ICONS['bug']} Issues found:[/cyan] [bold red]{metadata.get('finding_count', 0) if isinstance(metadata, dict) else 0}[/bold red]"
            )

            # Save report if requested
            if parsed_args.report_path:
                with open(parsed_args.report_path, "w") as f:
                    json.dump(scan_results_dict, f, indent=2)
                console.print(
                    f"[bold green]{SECURITY_ICONS['check']} Report saved to:[/bold green] {parsed_args.report_path}"
                )

            # If no issues were found or user confirmation
            should_clone = True
            if isinstance(metadata, dict) and metadata.get("finding_count", 0) > 0:
                console.print(
                    f"\n[bold yellow]{SECURITY_ICONS['warning']} Security issues were found in the repository.[/bold yellow]"
                )

                # Show a sample of findings
                if findings:
                    console.print(
                        f"\n[bold]{SECURITY_ICONS['alert']} Sample of issues found:[/bold]"
                    )
                    for i, finding in enumerate(findings[:3], 1):
                        finding_item: Any = finding  # Explicit type hint for mypy
                        if isinstance(finding_item, dict):
                            severity = finding_item.get("severity", "low")
                            title = finding_item.get("title", "Unknown issue")
                            severity_color = {
                                "critical": "bold red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "blue",
                            }.get(severity, "white")
                            icon = SECURITY_ICONS.get(
                                (
                                    "fire"
                                    if severity == "critical"
                                    else "alert" if severity == "high" else "warning"
                                ),
                                SECURITY_ICONS["bug"],
                            )
                            console.print(
                                f"{i}. [{severity_color}]{icon} [{severity.upper()}][/{severity_color}] {title}"
                            )
                        else:
                            severity = finding_item.severity.value
                            severity_color = {
                                "critical": "bold red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "blue",
                            }.get(severity, "white")
                            icon = SECURITY_ICONS.get(
                                (
                                    "fire"
                                    if severity == "critical"
                                    else "alert" if severity == "high" else "warning"
                                ),
                                SECURITY_ICONS["bug"],
                            )
                            console.print(
                                f"{i}. [{severity_color}]{icon} [{severity.upper()}][/{severity_color}] {finding_item.title}"
                            )

                    if len(findings) > 3:
                        console.print(f"... and {len(findings) - 3} more issues")

                should_clone = Confirm.ask(
                    f"\n{SECURITY_ICONS['warning']} Do you want to proceed with cloning?",
                    default=False,
                )

            # Clone the repository locally if confirmed
            if should_clone:
                console.print(
                    f"\n[bold cyan]{SECURITY_ICONS['scan']} Cloning repository to {output_dir}...[/bold cyan]"
                )

                # Ensure output directory does not exist
                if output_dir.exists():
                    console.print(
                        f"[bold red]{SECURITY_ICONS['warning']} Output directory already exists: {output_dir}[/bold red]"
                    )
                    if Confirm.ask("Do you want to overwrite it?", default=False):
                        import shutil

                        shutil.rmtree(output_dir)
                    else:
                        console.print(
                            f"[bold yellow]{SECURITY_ICONS['cross']} Clone operation aborted by user[/bold yellow]"
                        )
                        return 0

                # Clone the repository
                clone_success = clone_repository(
                    repo_url=repo_url,
                    target_path=output_dir,
                    commit_hash=commit_hash_str,
                )

                if clone_success:
                    console.print(
                        f"[bold green]{SECURITY_ICONS['check']} Repository cloned successfully to {output_dir}[/bold green]"
                    )
                else:
                    console.print(
                        f"[bold red]{SECURITY_ICONS['cross']} Failed to clone repository[/bold red]"
                    )
                    return 1

            return 0

        elif parsed_args.command == "scan":
            # Check if this looks like a URL and suggest clone command
            repo_path_str = str(parsed_args.repo_path)
            if repo_path_str.startswith(("http", "git")):
                console.print(
                    f"[bold yellow]⚠️  Detected URL: {repo_path_str}[/bold yellow]"
                )
                console.print(
                    "[bold cyan]💡 Tip: Use 'insect clone' for external repositories:[/bold cyan]"
                )
                console.print(f"[cyan]  insect clone {repo_path_str}[/cyan]\n")

            # Show Docker warning for scan command when Docker not available
            from insect.utils.docker_utils import check_docker_available

            if not check_docker_available():
                console.print(
                    "[bold yellow]⚠️  Docker not available. For maximum safety when analyzing "
                    "external code, use 'insect clone <url>' with Docker.[/bold yellow]\n"
                )

            logger.info(f"Scanning repository: {parsed_args.repo_path}")
            console.print(
                f"[bold]Scanning:[/bold] [cyan]{parsed_args.repo_path}[/cyan]"
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

            if parsed_args.sensitivity:
                if "sensitivity" not in config:
                    config["sensitivity"] = {}
                config["sensitivity"]["level"] = parsed_args.sensitivity

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
                        f"[bold green]{SECURITY_ICONS['check']} Cache cleared:[/bold green] {cache_dir}"
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

            # Determine if progress should be shown overall (respects --no-progress via config)
            should_show_progress_overall = config.get("progress", {}).get(
                "enabled", True
            )

            if should_show_progress_overall:
                console.print(
                    f"[bold cyan]{SECURITY_ICONS['scan']} Scanning repository. Detailed progress may follow...[/bold cyan]"
                )

            # Start the scan
            # core.scan_repository is expected to show its own detailed progress bar
            # if config["progress"]["enabled"] is True, and not if False.
            # The create_fancy_progress wrapper has been removed from here.
            scan_findings, metadata = core.scan_repository(
                Path(parsed_args.repo_path),
                config,
                enabled_analyzers=enabled_analyzers,
            )
            findings_list = scan_findings  # Use scan findings

            # Display scan results
            if not metadata:  # Check if metadata is empty (scan failed)
                console.print(
                    f"\n[bold red]{SECURITY_ICONS['cross']} Scan failed[/bold red]"
                )
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
                        f"\n[bold green]{SECURITY_ICONS['check']} Report written to:[/bold green] {output_file}"
                    )
                else:
                    # If format is text and no output file specified, show dashboard or simple output
                    if output_format == "text":
                        findings_to_show: Any = (
                            findings_list if "findings_list" in locals() else findings
                        )

                        if parsed_args.no_dashboard:
                            # Simple text output
                            display_scan_summary(metadata)
                            display_findings_summary(findings_to_show, metadata)
                            display_next_steps(findings_to_show, metadata)
                            console.print()  # Clean ending
                        else:
                            # Show comprehensive interactive dashboard
                            from insect.dashboard import show_dashboard

                            show_dashboard(findings_to_show, metadata)
                    else:
                        # For other formats without output file, print to stdout
                        report_content = formatter.format_findings(
                            findings_for_formatter, metadata
                        )
                        if report_content:  # Ensure there's something to print
                            console.print(report_content)

            except Exception as e:
                logger.error(f"Error generating report: {e}", exc_info=True)
                console.print(
                    f"[bold red]{SECURITY_ICONS['cross']} Error generating report:[/bold red] {e}"
                )
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
        console.print(f"[bold red]{SECURITY_ICONS['cross']} Error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
