"""Interactive CLI Dashboard for Insect Security Scanner."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    ProgressBar,
    RichLog,
    Static,
    Tree,
)
from textual.widgets.tree import TreeNode

from insect.finding import Finding


class ScanSummaryWidget(Static):
    """Widget displaying scan summary information."""
    
    def __init__(self, metadata: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.metadata = metadata
    
    def compose(self) -> ComposeResult:
        repo_path = str(self.metadata.get("repository", "Unknown"))
        # Expand relative paths and show the full scanned path
        if repo_path != "Unknown":
            expanded_path = Path(repo_path).expanduser().resolve()
            display_path = str(expanded_path)
        else:
            display_path = "Unknown"
        
        # Use total_files_processed if available, otherwise fall back to file_count
        total_files_processed = self.metadata.get("total_files_processed", 0)
        file_count = self.metadata.get("file_count", 0)
        files_scanned = total_files_processed if total_files_processed > 0 else file_count
        
        duration = self.metadata.get("duration_seconds", 0)
        finding_count = self.metadata.get("finding_count", 0)
        
        # Create a more compact horizontal layout with full path
        yield Static(f"🔍 [bold]{display_path}[/bold] | 📁 {files_scanned:,} files | ⏱️ {duration:.1f}s | 🐛 [bold]{finding_count:,} issues[/bold]", classes="scan-info")


class RiskOverviewWidget(Static):
    """Widget displaying risk assessment and severity breakdown."""
    
    def __init__(self, metadata: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.metadata = metadata
    
    def compose(self) -> ComposeResult:
        severity_counts = self.metadata.get("severity_counts", {})
        # Convert uppercase severity names to lowercase for consistency
        severity_counts_lower = {k.lower(): v for k, v in severity_counts.items()}
        total_issues = sum(severity_counts_lower.values())
        
        # Calculate overall risk level
        critical = severity_counts_lower.get("critical", 0)
        high = severity_counts_lower.get("high", 0)
        
        if critical > 0:
            risk_level = "[red]🔥 CRITICAL[/red]"
        elif high > 0:
            risk_level = "[yellow]⚠️  HIGH[/yellow]"
        elif total_issues > 10:
            risk_level = "[blue]📊 MEDIUM[/blue]"
        else:
            risk_level = "[green]✅ LOW[/green]"
        
        # More compact risk display
        severity_display = []
        for severity, icon in [
            ("critical", "🔥"),
            ("high", "⚠️"),
            ("medium", "📊"),
            ("low", "🐛")
        ]:
            count = severity_counts_lower.get(severity, 0)
            if count > 0:
                color = {
                    "critical": "red",
                    "high": "yellow", 
                    "medium": "blue",
                    "low": "green"
                }[severity]
                severity_display.append(f"{icon}[{color}]{count}[/{color}]")
        
        yield Static(f"[bold]Risk:[/bold] {risk_level} | {' '.join(severity_display)}", classes="risk-level")


class FileExplorerWidget(Tree):
    """File explorer widget showing repository structure with issue counts."""
    
    def __init__(self, findings: List[Finding], metadata: Dict[str, Any], **kwargs):
        # Get actual repository name from expanded path
        repo_path = metadata.get("repository", ".")
        expanded_path = Path(repo_path).expanduser().resolve()
        repo_name = expanded_path.name if expanded_path.name else "Repository"
        super().__init__(repo_name, **kwargs)
        self.findings = findings
        self.metadata = metadata
        self._file_issues: Dict[str, List[Finding]] = {}
        self._directory_issue_counts: Dict[str, int] = {}
        self._build_file_tree()
    
    def _build_file_tree(self):
        """Build the file tree with issue counts."""
        # Group findings by file
        for finding in self.findings:
            if hasattr(finding, 'location') and finding.location and hasattr(finding.location, 'path') and finding.location.path:
                file_path = str(finding.location.path)
                if file_path not in self._file_issues:
                    self._file_issues[file_path] = []
                self._file_issues[file_path].append(finding)
        
        if not self._file_issues:
            # If no files have issues, show a message
            self.root.add("📄 No files with issues found")
            return
        
        # Calculate directory issue counts
        self._calculate_directory_counts()
        
        # Build tree structure
        repo_path = Path(self.metadata.get("repository", "."))
        directory_nodes = {}
        
        # Create all necessary directory nodes first
        for relative_file_path in self._file_issues.keys():
            path_parts = Path(relative_file_path).parts
            # Create directory nodes for each parent directory (excluding the file itself)
            for i in range(len(path_parts) - 1):
                dir_path = "/".join(path_parts[:i+1])
                if dir_path and dir_path not in directory_nodes:
                    self._create_directory_node(dir_path, path_parts[:i+1], directory_nodes)
        
        # Add files to their respective directories
        for relative_file_path in self._file_issues.keys():
            self._add_file_to_directory(relative_file_path, directory_nodes)
        
        # Expand the root node
        self.root.expand()
    
    def _calculate_directory_counts(self):
        """Calculate issue counts for each directory."""
        for file_path, issues in self._file_issues.items():
            path_parts = Path(file_path).parts
            issue_count = len(issues)
            
            # Add counts to all parent directories
            for i in range(len(path_parts)):
                if i < len(path_parts) - 1:  # Skip the file itself
                    dir_path = "/".join(path_parts[:i+1])
                    self._directory_issue_counts[dir_path] = self._directory_issue_counts.get(dir_path, 0) + issue_count
    
    def _create_directory_node(self, dir_path: str, path_parts: tuple, directory_nodes: Dict[str, Any]):
        """Create a directory node with issue count."""
        if dir_path in directory_nodes:
            return directory_nodes[dir_path]
        
        parent_node = self.root
        parent_path = None
        
        # Find the parent node
        if len(path_parts) > 1:
            parent_path = "/".join(path_parts[:-1])
            if parent_path in directory_nodes:
                parent_node = directory_nodes[parent_path]
        
        # Get issue count and worst severity for this directory
        issue_count = self._directory_issue_counts.get(dir_path, 0)
        worst_severity = self._get_worst_severity_in_directory(dir_path)
        
        # Create the directory node with issue count
        dir_name = path_parts[-1]
        if issue_count > 0:
            severity_colors = {
                "critical": "red",
                "high": "yellow",
                "medium": "blue", 
                "low": "green"
            }
            color = severity_colors.get(worst_severity, "white")
            dir_node = parent_node.add(f"📁 {dir_name} [{color}]({issue_count})[/{color}]")
        else:
            dir_node = parent_node.add(f"📁 {dir_name}")
        
        dir_node.data = {
            "path": dir_path,
            "type": "directory",
            "name": dir_name
        }
        
        directory_nodes[dir_path] = dir_node
        return dir_node
    
    def _get_worst_severity_in_directory(self, dir_path: str) -> str:
        """Get the worst severity level for issues in a directory."""
        worst_severity = "low"
        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        for file_path, issues in self._file_issues.items():
            # Check if file is in this directory or subdirectory
            file_parts = Path(file_path).parts
            dir_parts = Path(dir_path).parts if dir_path != "/" else ()
            
            # If file is in this directory or subdirectory
            if len(file_parts) > len(dir_parts) and file_parts[:len(dir_parts)] == dir_parts:
                for issue in issues:
                    severity = issue.severity.value.lower()
                    if severity_priority.get(severity, 0) > severity_priority.get(worst_severity, 0):
                        worst_severity = severity
        
        return worst_severity
    
    def _add_file_to_directory(self, relative_file_path: str, directory_nodes: Dict[str, Any]):
        """Add a file to its parent directory."""
        try:
            path_parts = Path(relative_file_path).parts
            issue_count = len(self._file_issues.get(relative_file_path, []))
            
            if issue_count == 0:
                return
            
            # Find the parent directory node
            parent_node = self.root
            if len(path_parts) > 1:
                parent_dir_path = "/".join(path_parts[:-1])
                if parent_dir_path in directory_nodes:
                    parent_node = directory_nodes[parent_dir_path]
            
            # Add the file node
            filename = path_parts[-1]
            worst_severity = max(
                (f.severity.value.lower() for f in self._file_issues[relative_file_path]),
                key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0)
            )
            severity_colors = {
                "critical": "red",
                "high": "yellow",
                "medium": "blue", 
                "low": "green"
            }
            color = severity_colors.get(worst_severity, "white")
            file_node = parent_node.add(f"📄 {filename} [{color}]({issue_count})[/{color}]")
            file_node.data = {
                "path": relative_file_path,
                "type": "file",
                "issues": self._file_issues.get(relative_file_path, [])
            }
            
        except Exception as e:
            # Skip files we can't process
            pass
    
    def get_file_issues(self, file_path: str) -> List[Finding]:
        """Get issues for a specific file."""
        return self._file_issues.get(file_path, [])


class IssueDetailWidget(VerticalScroll):
    """Widget showing detailed issues for selected file."""
    
    selected_file: reactive[Optional[str]] = reactive(None)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.issues: List[Finding] = []
        self.current_issue_index: int = 0
    
    def update_issues(self, file_path: str, issues: List[Finding]):
        """Update the issues displayed for a file."""
        self.selected_file = file_path
        self.issues = issues
        self.current_issue_index = 0
        self._refresh_content()
    
    def _refresh_content(self):
        """Refresh the content display."""
        self.query("*").remove()
        
        if not self.selected_file:
            self.mount(Static("[dim]Select a file to view issues[/dim]", classes="help-text"))
            return
        
        if not self.issues:
            self.mount(Static(f"[green]✅ No issues found in {self.selected_file}[/green]"))
            return
        
        # File header with navigation info - more compact
        filename = Path(self.selected_file).name
        navigation_info = f" ({self.current_issue_index + 1}/{len(self.issues)})" if len(self.issues) > 1 else ""
        nav_hint = " | n/m to navigate" if len(self.issues) > 1 else ""
        self.mount(Static(f"[bold]{filename}{navigation_info}[/bold]{nav_hint}", classes="file-header"))
        
        # Show current issue
        if 0 <= self.current_issue_index < len(self.issues):
            issue = self.issues[self.current_issue_index]
            
            # Issue severity and title
            severity = issue.severity.value.lower()
            color = {
                "critical": "red",
                "high": "yellow", 
                "medium": "blue",
                "low": "green"
            }.get(severity, "white")
            
            self.mount(Static(f"[bold {color}]{severity.upper()}[/bold {color}] - {issue.title}", classes="issue-title"))
            
            # Location info with line number prominently displayed
            if hasattr(issue.location, 'line') and issue.location.line:
                self.mount(Static(f"[bold]📍 Line {issue.location.line}[/bold]", classes="line-info"))
            
            # Description - more compact
            if issue.description:
                desc = issue.description[:150] + "..." if len(issue.description) > 150 else issue.description
                self.mount(Static(f"\n{desc}", classes="issue-desc"))
            
            # Remediation if available - more compact
            if issue.remediation:
                remediation = issue.remediation[:150] + "..." if len(issue.remediation) > 150 else issue.remediation
                self.mount(Static(f"\n[blue]💡 {remediation}[/blue]", classes="remediation"))
            
            # Additional info
            if hasattr(issue, 'confidence') and issue.confidence < 1.0:
                self.mount(Static(f"\n[dim]Confidence: {issue.confidence:.1%}[/dim]"))
            
            if hasattr(issue, 'tags') and issue.tags:
                self.mount(Static(f"[dim]Tags: {', '.join(issue.tags)}[/dim]"))
    
    def next_issue(self):
        """Navigate to next issue."""
        if self.issues and self.current_issue_index < len(self.issues) - 1:
            self.current_issue_index += 1
            self._refresh_content()
    
    def previous_issue(self):
        """Navigate to previous issue."""
        if self.issues and self.current_issue_index > 0:
            self.current_issue_index -= 1
            self._refresh_content()


class SummaryInsightsWidget(Static):
    """Widget displaying key insights and important summaries from the scan."""
    
    def __init__(self, findings: List[Finding], metadata: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.findings = findings
        self.metadata = metadata
    
    def compose(self) -> ComposeResult:
        yield Static("[bold]📋 Key Insights[/bold]", classes="section-header")
        
        severity_counts = self.metadata.get("severity_counts", {})
        severity_counts_lower = {k.lower(): v for k, v in severity_counts.items()}
        total_issues = sum(severity_counts_lower.values())
        
        if total_issues == 0:
            yield Static("[green]✅ No security issues found - Repository appears secure![/green]")
            return
        
        # Risk assessment
        critical = severity_counts_lower.get("critical", 0)
        high = severity_counts_lower.get("high", 0)
        medium = severity_counts_lower.get("medium", 0)
        low = severity_counts_lower.get("low", 0)
        
        # Compact priority alerts
        alerts = []
        if critical > 0:
            alerts.append(f"[red]🚨 {critical} CRITICAL[/red]")
        if high > 0:
            alerts.append(f"[yellow]⚠️ {high} HIGH[/yellow]")
        if medium > 0:
            alerts.append(f"[blue]📊 {medium} MEDIUM[/blue]")
        if low > 0:
            alerts.append(f"[green]🐛 {low} LOW[/green]")
        
        if alerts:
            yield Static(" | ".join(alerts))
        
        # Top issue types - more compact
        type_counts = self.metadata.get("type_counts", {})
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:2]
            type_summary = [f"{issue_type.replace('_', ' ').title()}: {count}" for issue_type, count in top_types]
            if type_summary:
                yield Static(f"[bold]🎯 Top Issues:[/bold] {' | '.join(type_summary)}")
        
        # Most affected files - compact
        file_issue_counts = {}
        for finding in self.findings:
            if hasattr(finding, 'location') and finding.location and hasattr(finding.location, 'path') and finding.location.path:
                file_path = str(finding.location.path)
                file_issue_counts[file_path] = file_issue_counts.get(file_path, 0) + 1
        
        if file_issue_counts:
            top_files = sorted(file_issue_counts.items(), key=lambda x: x[1], reverse=True)[:2]
            file_summary = [f"{Path(file_path).name}: {count}" for file_path, count in top_files]
            if file_summary:
                yield Static(f"[bold]📁 Top Files:[/bold] {' | '.join(file_summary)}")
        
        # Security recommendations - compact
        recommendations = []
        if critical > 0 or high > 0:
            recommendations.append("Address critical/high issues first")
        if "secrets" in str(type_counts.keys()).lower():
            recommendations.append("Rotate exposed secrets")
        if total_issues > 10:
            recommendations.append("Consider automated CI/CD checks")
        
        if recommendations:
            yield Static(f"[bold]🛡️ Actions:[/bold] {' | '.join(recommendations)}")


class StatsWidget(Static):
    """Widget displaying scan statistics and performance metrics."""
    
    def __init__(self, metadata: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.metadata = metadata
    
    def compose(self) -> ComposeResult:
        yield Static("[bold]📊 Scan Statistics[/bold]", classes="section-header")
        yield Static("")
        
        # Performance metrics
        duration = self.metadata.get("duration_seconds", 0)
        file_count = self.metadata.get("file_count", 0)
        files_per_sec = file_count / duration if duration > 0 else 0
        
        yield Static(f"⚡ [bold]Speed:[/bold] {files_per_sec:.1f} files/sec")
        
        # Cache stats
        cache_stats = self.metadata.get("cache_stats", {})
        if cache_stats:
            hits = cache_stats.get("hits", 0)
            misses = cache_stats.get("misses", 0)
            total = hits + misses
            if total > 0:
                hit_rate = (hits / total) * 100
                yield Static(f"💾 [bold]Cache Hit Rate:[/bold] {hit_rate:.1f}%")
        
        # Analyzer info
        analyzer_counts = self.metadata.get("analyzer_counts", {})
        if analyzer_counts:
            yield Static("")
            yield Static("[bold]🔍 Analyzer Results[/bold]")
            for analyzer, count in sorted(analyzer_counts.items(), key=lambda x: x[1], reverse=True):
                yield Static(f"  • {analyzer}: {count} findings")


class InsectDashboard(App):
    """Main dashboard application for Insect scan results."""
    
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-gutter: 0 1;
        grid-rows: auto auto 1fr;
    }
    
    #scan-summary {
        column-span: 2;
        height: auto;
        max-height: 6;
        border: solid $primary;
        margin-bottom: 1;
    }
    
    #insights-summary {
        column-span: 2;
        height: auto;
        max-height: 10;
        border: solid $warning;
        margin-bottom: 1;
        overflow: auto;
    }
    
    #file-explorer {
        border: solid $success;
        min-height: 10;
    }
    
    #issue-detail {
        border: solid $error;
        min-height: 10;
    }
    
    .scan-info {
        margin: 0 1;
        padding: 0;
    }
    
    .file-header {
        background: $primary 20%;
        padding: 1;
        margin-bottom: 0;
    }
    
    .issue-title {
        margin-left: 2;
        color: $text;
    }
    
    .issue-desc {
        margin-left: 4;
        color: $text-muted;
        text-style: italic;
    }
    
    .remediation {
        margin-left: 4;
        margin-bottom: 1;
    }
    
    .help-text {
        text-align: center;
        margin: 4;
        color: $text-muted;
    }
    
    .section-header {
        margin-bottom: 1;
    }
    
    .line-info {
        background: $warning 20%;
        padding: 1;
        margin: 0;
        border-left: thick $warning;
    }
    """
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("e", "export", "Export Report"),
        ("n", "next_issue", "Next Issue"),
        ("m", "previous_issue", "Previous Issue"),
    ]
    
    def __init__(self, findings: List[Finding], metadata: Dict[str, Any]):
        super().__init__()
        self.findings = findings
        self.metadata = metadata
        self.title = "INSECT Security Dashboard"
        self.sub_title = f"Scanned {metadata.get('file_count', 0)} files"
    
    def compose(self) -> ComposeResult:
        """Create child widgets for the dashboard."""
        yield Header()
        
        with Container(id="scan-summary"):
            yield ScanSummaryWidget(self.metadata)
        
        with Container(id="insights-summary"):
            yield SummaryInsightsWidget(self.findings, self.metadata)
        
        with Container(id="file-explorer"):
            yield FileExplorerWidget(self.findings, self.metadata)
        
        with Container(id="issue-detail"):
            yield IssueDetailWidget()
        
        yield Footer()
    
    @on(Tree.NodeSelected)
    def on_file_selected(self, event: Tree.NodeSelected) -> None:
        """Handle file selection in the explorer."""
        node_data = event.node.data
        if node_data and node_data.get("type") == "file":
            file_path = node_data["path"]
            issues = node_data.get("issues", [])
            
            issue_widget = self.query_one("#issue-detail IssueDetailWidget", IssueDetailWidget)
            issue_widget.update_issues(file_path, issues)
    
    def action_refresh(self) -> None:
        """Refresh the dashboard."""
        self.app.bell()
    
    def action_export(self) -> None:
        """Export detailed report."""
        self.app.bell()
    
    def action_next_issue(self) -> None:
        """Navigate to next issue in current file."""
        issue_widget = self.query_one("#issue-detail IssueDetailWidget", IssueDetailWidget)
        issue_widget.next_issue()
    
    def action_previous_issue(self) -> None:
        """Navigate to previous issue in current file."""
        issue_widget = self.query_one("#issue-detail IssueDetailWidget", IssueDetailWidget)
        issue_widget.previous_issue()


def show_dashboard(findings: List[Finding], metadata: Dict[str, Any]) -> None:
    """Show the interactive dashboard with scan results."""
    try:
        app = InsectDashboard(findings, metadata)
        app.run()
    except Exception as e:
        # Fallback to simple text output if dashboard fails
        print(f"Dashboard failed to start: {e}")
        print(f"\nScan Summary:")
        print(f"Repository: {metadata.get('repository', 'Unknown')}")
        print(f"Files scanned: {metadata.get('file_count', 0)}")
        print(f"Issues found: {metadata.get('finding_count', 0)}")
        print(f"Duration: {metadata.get('duration_seconds', 0):.2f}s")
        
        if findings:
            print(f"\nTop issues:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding.severity.value.upper()}: {finding.title}")
                if hasattr(finding.location, 'path'):
                    print(f"     in {finding.location.path}")
        else:
            print("\n✅ No security issues found!")