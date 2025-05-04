"""Command-line interface for Insect."""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from insect import __version__
from insect.config import handler
from insect import core

# Setup logging
logging.basicConfig(
    level=logging.INFO,
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

        if parsed_args.command == "scan":
            logger.info(f"Scanning repository: {parsed_args.repo_path}")
            console.print(
                f"[bold green]Repository to scan:[/bold green] {parsed_args.repo_path}"
            )
            
            # Load config from file if specified, or use default
            config_path = parsed_args.config
            if config_path:
                config_path = Path(config_path)
            
            config = handler.load_config(config_path)
            
            # Get enabled analyzers based on config and CLI arguments
            disabled_analyzers = parsed_args.disable or []
            enabled_analyzers = handler.get_enabled_analyzers(config, disabled_analyzers)
            
            # Run the scan
            with console.status("[bold blue]Scanning repository...[/bold blue]"):
                findings, metadata = core.scan_repository(
                    Path(parsed_args.repo_path),
                    config,
                    enabled_analyzers=enabled_analyzers
                )
            
            # Display scan results
            if not metadata:  # Check if metadata is empty (scan failed)
                console.print("\n[bold red]Scan failed[/bold red]")
                return 1
                
            console.print(f"\n[bold green]Scan Completed[/bold green] in {metadata['duration_seconds']:.2f}s")
            console.print(f"Repository: {metadata['repository']}")
            console.print(f"Files scanned: {metadata['file_count']}")
            console.print(f"[bold]Issues found: {metadata['finding_count']}[/bold]")
            
            # Display findings by severity
            severity_counts = metadata["severity_counts"]
            if sum(severity_counts.values()) > 0:
                console.print("\n[bold]Issues by severity:[/bold]")
                if severity_counts["critical"] > 0:
                    console.print(f"  [bold red]Critical: {severity_counts['critical']}[/bold red]")
                if severity_counts["high"] > 0:
                    console.print(f"  [red]High: {severity_counts['high']}[/red]")
                if severity_counts["medium"] > 0:
                    console.print(f"  [yellow]Medium: {severity_counts['medium']}[/yellow]")
                if severity_counts["low"] > 0:
                    console.print(f"  [blue]Low: {severity_counts['low']}[/blue]")
            
            # TODO: Add detailed findings reporting
            # For now, just print basic info about each finding
            if findings:
                console.print("\n[bold]Issues Details:[/bold]")
                for i, finding in enumerate(findings[:10], 1):  # Show at most 10 findings
                    color = {
                        "critical": "bold red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue"
                    }.get(finding.severity.value, "white")
                    
                    console.print(f"{i}. [{color}][{finding.severity.value.upper()}][/{color}] {finding.title}")
                    console.print(f"   {finding.location}")
                    console.print(f"   {finding.description}")
                    console.print()
                
                # If there are more findings than we showed
                if len(findings) > 10:
                    console.print(f"... and {len(findings) - 10} more issues.")
            
            # Return non-zero exit code if critical or high severity issues found
            if severity_counts["critical"] > 0 or severity_counts["high"] > 0:
                return 1
            
            return 0

        return 0
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
