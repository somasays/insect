#!/usr/bin/env python3
"""
Test script to examine UI alignment issues in Insect CLI.
"""

import os
import sys
from pathlib import Path

# Add src to path to import insect modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

from insect.cli import (
    create_fancy_progress,
    display_scan_summary,
    display_findings_tree,
    console,
    SECURITY_ICONS,
)
from insect.finding import Finding, Severity, FindingType, Location
from rich.console import Console
from rich.table import Table
from rich import box


def test_progress_bar():
    """Test progress bar alignment at different terminal widths."""
    print("\n=== Testing Progress Bar ===")

    # Test with fancy progress
    with create_fancy_progress("Testing alignment") as progress:
        task = progress.add_task("Processing files...", total=100)
        for i in range(101):
            progress.update(task, advance=1)
            if i % 20 == 0:
                import time

                time.sleep(0.05)


def test_scan_summary():
    """Test scan summary table alignment."""
    print("\n=== Testing Scan Summary ===")

    # Mock metadata with various field lengths
    metadata = {
        "repository": "/very/long/path/to/some/repository/with/a/very/long/name",
        "file_count": 12345,
        "finding_count": 567,
        "duration_seconds": 123.456,
        "severity_counts": {"critical": 5, "high": 15, "medium": 89, "low": 458},
    }

    display_scan_summary(metadata)


def test_findings_tree():
    """Test findings tree alignment."""
    print("\n=== Testing Findings Tree ===")

    # Create sample findings with various title lengths
    findings = []

    # Short title
    findings.append(
        Finding(
            id="TEST-001",
            title="SQL injection vulnerability",
            description="Basic SQL injection found",
            severity=Severity.CRITICAL,
            type=FindingType.VULNERABILITY,
            location=Location(Path("src/db.py"), 45),
            analyzer="static_analyzer",
            confidence=0.9,
        )
    )

    # Very long title
    findings.append(
        Finding(
            id="TEST-002",
            title="Extremely long vulnerability title that might cause alignment issues when displayed in terminal output",
            description="This is a test finding with a very long title",
            severity=Severity.HIGH,
            type=FindingType.VULNERABILITY,
            location=Location(
                Path("src/really/deep/nested/directory/structure/file.py"), 123
            ),
            analyzer="browser_theft_analyzer",
            confidence=0.8,
        )
    )

    # Medium length title
    findings.append(
        Finding(
            id="TEST-003",
            title="Hardcoded API key detected in configuration",
            description="API key found in config",
            severity=Severity.MEDIUM,
            type=FindingType.SECRET,
            location=Location(Path("config/settings.json"), 12),
            analyzer="secret_analyzer",
            confidence=0.95,
        )
    )

    # Test with different amounts
    display_findings_tree(findings, max_display=5)


def test_table_responsiveness():
    """Test table behavior at different widths."""
    print("\n=== Testing Table Responsiveness ===")

    # Create a table with long content
    table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
    table.add_column("Short", style="bold", min_width=10)
    table.add_column("Medium Length Column", style="green", min_width=20)
    table.add_column(
        "Very Long Column Header That Might Overflow", style="red", min_width=30
    )

    table.add_row(
        "A", "Normal text", "This is a very long piece of text that might cause issues"
    )
    table.add_row(
        "B", "Short", "Another long piece of content that could break alignment"
    )
    table.add_row("C", "Very long content here", "Normal")

    console.print(table)


def test_different_terminal_widths():
    """Test behavior at different simulated terminal widths."""
    print("\n=== Testing Different Terminal Widths ===")

    # Get current console width
    original_width = console.size.width
    print(f"Current terminal width: {original_width}")

    # Test metadata that would stress the layout
    metadata = {
        "repository": "/extremely/long/path/to/repository/that/might/cause/issues",
        "file_count": 999999,
        "finding_count": 1234,
        "duration_seconds": 9999.99,
        "severity_counts": {"critical": 999, "high": 888, "medium": 777, "low": 666},
    }

    # Test display at current width
    print(f"\nAt width {original_width}:")
    display_scan_summary(metadata)


if __name__ == "__main__":
    print("Testing Insect CLI UI Alignment")
    print("=" * 50)

    test_progress_bar()
    test_scan_summary()
    test_findings_tree()
    test_table_responsiveness()
    test_different_terminal_widths()

    print("\nTest completed. Check output for alignment issues.")
