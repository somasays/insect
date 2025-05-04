"""Report formatter factory and base class for Insect."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from insect.finding import Finding


class BaseFormatter:
    """Base class for report formatters."""

    format_name = "base"

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the formatter.

        Args:
            config: Configuration dictionary.
        """
        self.config = config

    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings as a string.

        Args:
            findings: List of findings.
            metadata: Scan metadata.

        Returns:
            Formatted report as a string.
        """
        raise NotImplementedError("Subclasses must implement format_findings")

    def write_report(
        self,
        findings: List[Finding],
        metadata: Dict[str, Any],
        output_path: Optional[Path] = None,
    ) -> Union[str, Path]:
        """Format findings and write to file if output_path is provided.

        Args:
            findings: List of findings.
            metadata: Scan metadata.
            output_path: Path to write report to. If None, returns the formatted string.

        Returns:
            If output_path is None, returns the formatted string.
            Otherwise, returns the path to the written file.
        """
        formatted_report = self.format_findings(findings, metadata)

        if output_path is None:
            return formatted_report

        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(formatted_report)

        return output_path


def create_formatter(format_name: str, config: Dict[str, Any]) -> BaseFormatter:
    """Create a formatter instance based on format name.

    Args:
        format_name: Name of the format ("text", "json", "html").
        config: Configuration dictionary.

    Returns:
        Formatter instance.

    Raises:
        ValueError: If format_name is not supported.
    """
    from insect.reporting.html_formatter import HtmlFormatter
    from insect.reporting.json_formatter import JsonFormatter
    from insect.reporting.text_formatter import TextFormatter

    formatters = {
        "text": TextFormatter,
        "json": JsonFormatter,
        "html": HtmlFormatter,
    }

    if format_name not in formatters:
        raise ValueError(
            f"Unsupported format: {format_name}. "
            f"Supported formats: {', '.join(formatters.keys())}"
        )

    return formatters[format_name](config)
