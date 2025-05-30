"""Text formatter for Insect reports."""

from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

from insect.finding import Finding, Severity
from insect.reporting.formatters import BaseFormatter


class TextFormatter(BaseFormatter):
    """Text formatter for Insect reports."""

    format_name = "text"

    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings as a text string.

        Args:
            findings: List of findings.
            metadata: Scan metadata.

        Returns:
            Formatted report as a text string.
        """
        console = Console(record=True, width=100)

        # Report header
        console.print("\n[bold]Insect Security Report[/bold]")
        console.print(f"Repository: {metadata['repository']}")
        console.print(f"Scan ID: {metadata['scan_id']}")
        console.print(f"Timestamp: {metadata['timestamp']}")
        console.print(f"Duration: {metadata['duration_seconds']:.2f} seconds")
        console.print(f"Files scanned: {metadata['file_count']}")

        # Summary statistics
        console.print("\n[bold]Summary:[/bold]")
        console.print(f"Total issues found: {metadata['finding_count']}")

        # Issues by severity
        severity_counts = metadata.get("severity_counts", {})
        if severity_counts and sum(severity_counts.values()) > 0:
            console.print("\n[bold]Issues by severity:[/bold]")
            severity_table = Table(show_header=False)
            severity_table.add_column("Severity", style="bold")
            severity_table.add_column("Count")

            # Add rows in descending order of severity
            severities = [
                ("CRITICAL", "bold red"),
                ("HIGH", "red"),
                ("MEDIUM", "yellow"),
                ("LOW", "blue"),
            ]

            for sev_name, style in severities:
                if severity_counts.get(sev_name.lower(), 0) > 0:
                    severity_table.add_row(
                        f"[{style}]{sev_name}[/{style}]",
                        str(severity_counts.get(sev_name.lower(), 0)),
                    )

            console.print(severity_table)

        # Issues by type
        type_counts = metadata.get("type_counts", {})
        if type_counts:
            console.print("\n[bold]Issues by type:[/bold]")
            type_table = Table(show_header=False)
            type_table.add_column("Type", style="bold")
            type_table.add_column("Count")

            for type_name, count in sorted(
                type_counts.items(), key=lambda x: x[1], reverse=True
            ):
                type_table.add_row(type_name.title(), str(count))

            console.print(type_table)

        # Detailed findings
        if findings:
            console.print("\n[bold]Detailed Findings:[/bold]")

            # Sort findings by severity (most severe first)
            findings_by_severity: Dict[Severity, List[Finding]] = {}
            for sev in Severity:
                findings_by_severity[sev] = []

            for finding in findings:
                findings_by_severity[finding.severity].append(finding)

            # Severity levels in descending order
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
            ]:
                severity_findings = findings_by_severity[severity]
                if not severity_findings:
                    continue

                style_map = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                }
                style = style_map[severity]

                console.print(f"\n[{style}]{severity.name} Severity Issues:[/{style}]")

                for i, finding in enumerate(severity_findings, 1):
                    console.print(f"\n{i}. [{style}]{finding.title}[/{style}]")
                    console.print(f"   ID: {finding.id}")
                    console.print(f"   Type: {finding.type.name.title()}")
                    console.print(f"   Location: {finding.location}")
                    console.print(f"   Description: {finding.description}")

                    if finding.remediation:
                        console.print(f"   Remediation: {finding.remediation}")

                    if finding.references:
                        console.print("   References:")
                        for ref in finding.references:
                            console.print(f"     - {ref}")

        return console.export_text()
