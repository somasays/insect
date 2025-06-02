"""Command-line interface for Insect."""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm
from rich.rule import Rule
from rich.table import Column, Table
from rich.text import Text
from rich.tree import Tree

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

# Setup Rich console
console = Console()

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
    """Display a fancy animated welcome screen."""
    console.clear()

    # Create gradient text for INSECT
    insect_text = Text()
    colors = ["red", "orange3", "yellow", "green", "blue", "purple"]

    for i, line in enumerate(INSECT_ASCII.split("\n")):
        if line.strip():
            color = colors[i % len(colors)]
            insect_text.append(line + "\n", style=f"bold {color}")

    # Create the main panel
    welcome_panel = Panel(
        Align.center(
            Text.assemble(
                insect_text,
                "\n",
                (
                    f"{SECURITY_ICONS['shield']} Security Scanner for Git Repositories {SECURITY_ICONS['shield']}",
                    "bold cyan",
                ),
                "\n",
                (f"Version {__version__}", "dim"),
                "\n\n",
                (
                    f"{SECURITY_ICONS['scan']} Ready to scan for vulnerabilities and malware",
                    "green",
                ),
            )
        ),
        title=f"{SECURITY_ICONS['fire']} Welcome to INSECT {SECURITY_ICONS['fire']}",
        border_style="bright_blue",
        box=box.DOUBLE,
    )

    with Live(welcome_panel, console=console, refresh_per_second=10) as live:
        # Animate the welcome screen
        for i in range(3):
            time.sleep(0.5)
            # Add some visual flair
            if i == 1:
                welcome_panel.title = f"{SECURITY_ICONS['alert']} Welcome to INSECT {SECURITY_ICONS['alert']}"
                welcome_panel.border_style = "bright_red"
            elif i == 2:
                welcome_panel.title = f"{SECURITY_ICONS['check']} Welcome to INSECT {SECURITY_ICONS['check']}"
                welcome_panel.border_style = "bright_green"
            live.update(welcome_panel)

    time.sleep(0.5)
    console.print(Rule(style="dim"))


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
    """Display a fancy summary of scan results."""
    terminal_width = console.size.width

    # Create summary table with responsive sizing
    summary_table = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
    summary_table.add_column("Metric", style="bold", ratio=1)
    summary_table.add_column("Value", style="bold green", ratio=1, justify="right")

    # Truncate repository path if it's too long
    repo_path = str(metadata.get("repository", "N/A"))
    if len(repo_path) > 30:
        repo_path = "..." + repo_path[-27:]

    summary_table.add_row(f"{SECURITY_ICONS['scan']} Repository", repo_path)
    summary_table.add_row(
        f"{SECURITY_ICONS['check']} Files Scanned", str(metadata.get("file_count", 0))
    )
    summary_table.add_row(
        f"{SECURITY_ICONS['bug']} Issues Found", str(metadata.get("finding_count", 0))
    )
    summary_table.add_row("⏱️ Duration", f"{metadata.get('duration_seconds', 0):.2f}s")

    # Create severity breakdown
    severity_counts = metadata.get("severity_counts", {})
    severity_table = Table(
        title=f"{SECURITY_ICONS['alert']} Issues by Severity",
        box=box.SIMPLE,
        border_style="yellow",
    )
    severity_table.add_column("Severity", style="bold", ratio=2)
    severity_table.add_column("Count", style="bold", justify="right", ratio=1)
    severity_table.add_column("Icon", justify="center", ratio=1)

    severity_styles = {
        "critical": ("bold red", SECURITY_ICONS["fire"]),
        "high": ("red", SECURITY_ICONS["alert"]),
        "medium": ("yellow", SECURITY_ICONS["warning"]),
        "low": ("blue", SECURITY_ICONS["bug"]),
    }

    for severity, count in severity_counts.items():
        if count > 0:
            style, icon = severity_styles.get(severity, ("white", "•"))
            severity_table.add_row(severity.title(), str(count), icon, style=style)

    # Responsive layout: stack tables on narrow terminals
    console.print("\n")
    if terminal_width < 80:
        # Stack tables vertically for narrow terminals
        console.print(summary_table)
        console.print("\n")
        console.print(severity_table)
    else:
        # Side by side layout for wider terminals
        console.print(Columns([summary_table, severity_table], equal=True, expand=True))
    console.print("\n")


def display_findings_tree(findings: List[Any], max_display: int = 10):
    """Display findings in a fancy tree structure."""
    terminal_width = console.size.width

    if not findings:
        console.print(
            Panel(
                Align.center(f"{SECURITY_ICONS['check']} No security issues found!"),
                title="Results",
                border_style="green",
            )
        )
        return

    tree = Tree(f"{SECURITY_ICONS['bug']} Security Issues Found", style="bold red")

    # Group findings by severity
    severity_groups: Dict[str, List[Any]] = {}
    for finding in findings[:max_display]:
        if isinstance(finding, dict):
            severity = finding.get("severity", "low")
        else:
            severity = finding.severity.value

        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(finding)

    # Add branches for each severity
    severity_order = ["critical", "high", "medium", "low"]
    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }

    for severity in severity_order:
        if severity in severity_groups:
            count = len(severity_groups[severity])
            icon = SECURITY_ICONS.get(
                (
                    "fire"
                    if severity == "critical"
                    else (
                        "alert"
                        if severity == "high"
                        else "warning" if severity == "medium" else "bug"
                    )
                ),
                "•",
            )
            branch = tree.add(
                f"{icon} {severity.title()} ({count})",
                style=severity_styles.get(severity, "white"),
            )

            # Adjust display count based on terminal width
            findings_to_show = min(
                5 if terminal_width > 100 else 3, len(severity_groups[severity])
            )

            for finding in severity_groups[severity][:findings_to_show]:
                if isinstance(finding, dict):
                    title = finding.get("title", "Unknown issue")
                    location = finding.get("location", "Unknown location")
                else:
                    title = finding.title
                    location = str(finding.location)

                # Truncate long titles and locations for narrow terminals
                if terminal_width < 80:
                    if len(title) > 50:
                        title = title[:47] + "..."
                    if len(location) > 60:
                        location = "..." + location[-57:]
                elif terminal_width < 120:
                    if len(title) > 70:
                        title = title[:67] + "..."
                    if len(location) > 80:
                        location = "..." + location[-77:]

                finding_text = f"{title}\n{location}"
                branch.add(finding_text, style="dim")

    console.print(tree)

    if len(findings) > max_display:
        console.print(f"\n[dim]... and {len(findings) - max_display} more issues[/dim]")
        console.print(
            "[dim]Use --output and --format options for a complete report[/dim]"
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
    try:
        # Show welcome screen for interactive usage
        if not args and len(sys.argv) > 1:
            show_welcome_screen()

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
            output_dir = (
                parsed_args.output_dir
                or Path.cwd() / Path(repo_url.split("/")[-1]).stem
            )

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
            logger.info(f"Scanning repository: {parsed_args.repo_path}")
            console.print(
                f"[bold green]{SECURITY_ICONS['scan']} Repository to scan:[/bold green] [cyan]{parsed_args.repo_path}[/cyan]"
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

            # Run the scan with fancy progress bar
            with create_fancy_progress(
                f"{SECURITY_ICONS['scan']} Scanning repository"
            ) as progress:
                task = progress.add_task("Scanning files...", total=100)

                # Start the scan
                scan_findings, metadata = core.scan_repository(
                    Path(parsed_args.repo_path),
                    config,
                    enabled_analyzers=enabled_analyzers,
                )
                findings_list = scan_findings  # Use scan findings

                # Complete progress
                progress.update(task, completed=100)

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
                    # If format is text and no output file specified, use Rich for interactive output
                    if output_format == "text":
                        # Display fancy summary
                        display_scan_summary(metadata)

                        console.print(
                            f"\n[bold green]{SECURITY_ICONS['check']} Scan Completed[/bold green] in [bold cyan]{metadata['duration_seconds']:.2f}s[/bold cyan]"
                        )

                        # Show cache statistics if available
                        if "cache_stats" in metadata:
                            cache_stats = metadata["cache_stats"]
                            cache_table = Table(
                                title=f"{SECURITY_ICONS['key']} Cache Statistics",
                                box=box.ROUNDED,
                                border_style="blue",
                                width=min(
                                    50, console.size.width - 10
                                ),  # Responsive width
                            )
                            cache_table.add_column("Metric", style="bold blue", ratio=2)
                            cache_table.add_column(
                                "Value", style="bold green", justify="right", ratio=1
                            )

                            cache_table.add_row("Cache hits", str(cache_stats["hits"]))
                            cache_table.add_row(
                                "Cache misses", str(cache_stats["misses"])
                            )

                            if cache_stats["hits"] > 0:
                                hit_percentage = (
                                    cache_stats["hits"]
                                    / (cache_stats["hits"] + cache_stats["misses"])
                                ) * 100
                                cache_table.add_row(
                                    "Hit ratio", f"{hit_percentage:.1f}%"
                                )

                            console.print(cache_table)

                        # Display findings using the fancy tree view

                        # Display detailed findings using the fancy tree view
                        findings_to_show: Any = (
                            findings_list if "findings_list" in locals() else findings
                        )
                        display_findings_tree(findings_to_show)
                    else:
                        # For other formats without output file, print to stdout
                        report = formatter.format_findings(
                            findings_for_formatter, metadata
                        )

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
