"""Dashboard HTML formatter for Insect reports - mirrors CLI dashboard layout."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from insect.finding import Finding
from insect.reporting.formatters import BaseFormatter


class DashboardHtmlFormatter(BaseFormatter):
    """HTML formatter that creates a dashboard identical to the CLI dashboard."""

    format_name = "dashboard-html"

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the dashboard HTML formatter.
        
        Args:
            config: Configuration dictionary (optional).
        """
        super().__init__(config or {})

    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings as an interactive HTML dashboard.

        Args:
            findings: List of findings.
            metadata: Scan metadata.

        Returns:
            Formatted dashboard as an HTML string.
        """
        # Check if we need to append dependency information
        from insect.analysis.dependency_manager import get_dependencies_status

        dependencies = get_dependencies_status()

        # Group findings by file for the file explorer
        file_issues = {}
        for finding in findings:
            if hasattr(finding, 'location') and finding.location and hasattr(finding.location, 'path') and finding.location.path:
                file_path = str(finding.location.path)
                if file_path not in file_issues:
                    file_issues[file_path] = []
                file_issues[file_path].append(finding)

        # Convert findings to a format usable in the template
        formatted_findings = []
        for finding in findings:
            try:
                # Safely extract location information
                location_str = str(finding.location) if finding.location else "Unknown"
                location_file = str(finding.location.path) if (finding.location and hasattr(finding.location, 'path') and finding.location.path) else "Unknown"
                location_line = getattr(finding.location, 'line_start', None) if finding.location else None
                
                formatted_findings.append(
                    {
                        "id": getattr(finding, 'id', 'unknown'),
                        "title": getattr(finding, 'title', 'Unknown Issue'),
                        "description": getattr(finding, 'description', ''),
                        "severity": finding.severity.value if hasattr(finding, 'severity') and finding.severity else "unknown",
                        "severity_label": finding.severity.name if hasattr(finding, 'severity') and finding.severity else "Unknown",
                        "type": finding.type.value if hasattr(finding, 'type') and finding.type else "unknown",
                        "type_label": finding.type.name.title() if hasattr(finding, 'type') and finding.type and hasattr(finding.type, 'name') else "Unknown",
                        "location": location_str,
                        "location_file": location_file,
                        "location_line": location_line,
                        "remediation": getattr(finding, 'remediation', '') or "",
                        "references": getattr(finding, 'references', []) or [],
                        "confidence": f"{getattr(finding, 'confidence', 0) * 100:.0f}%",
                        "analyzer": getattr(finding, 'analyzer', 'unknown'),
                        "created_at": finding.created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(finding, 'created_at') and finding.created_at else "Unknown",
                        "cwe_id": getattr(finding, 'cwe_id', '') or "",
                        "cvss_score": getattr(finding, 'cvss_score', None),
                    }
                )
            except Exception as e:
                # Log the error and skip this finding
                print(f"Warning: Error processing finding: {e}")
                continue

        # Prepare file tree data
        file_tree_data = self._build_file_tree_data(file_issues, metadata)

        # JSON encode the data for use in JavaScript with error handling
        try:
            findings_json = json.dumps(formatted_findings, default=str, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Error encoding findings to JSON: {e}")
            findings_json = "[]"
            
        try:
            metadata_json = json.dumps(metadata, default=str, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Error encoding metadata to JSON: {e}")
            metadata_json = "{}"
            
        try:
            dependencies_json = json.dumps(dependencies, default=str, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Error encoding dependencies to JSON: {e}")
            dependencies_json = "{}"
            
        try:
            file_tree_json = json.dumps(file_tree_data, default=str, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Error encoding file tree to JSON: {e}")
            file_tree_json = '{"name": "Repository", "children": [], "issues": 0}'

        # Generate scan summary data with error handling
        try:
            repo_path = str(metadata.get("repository", "Unknown"))
            if repo_path != "Unknown":
                try:
                    expanded_path = Path(repo_path).expanduser().resolve()
                    display_path = str(expanded_path)
                except Exception:
                    display_path = repo_path  # fallback to original path
            else:
                display_path = "Unknown"

            total_files_processed = metadata.get("total_files_processed", 0)
            file_count = metadata.get("file_count", 0)
            files_scanned = total_files_processed if total_files_processed > 0 else file_count
            
            duration = metadata.get("duration_seconds", 0)
            finding_count = metadata.get("finding_count", 0)
            
            # Risk assessment
            severity_counts = metadata.get("severity_counts", {})
            severity_counts_lower = {}
            
            # Safely convert severity counts to lowercase
            try:
                severity_counts_lower = {str(k).lower(): int(v) for k, v in severity_counts.items() if v is not None}
            except Exception:
                severity_counts_lower = {}
                
            total_issues = sum(severity_counts_lower.values())
            
            critical = severity_counts_lower.get("critical", 0)
            high = severity_counts_lower.get("high", 0)
            
            if critical > 0:
                risk_level = "CRITICAL"
                risk_class = "critical"
            elif high > 0:
                risk_level = "HIGH"
                risk_class = "high"
            elif total_issues > 10:
                risk_level = "MEDIUM"
                risk_class = "medium"
            else:
                risk_level = "LOW"
                risk_class = "low"

        except Exception as e:
            print(f"Warning: Error generating scan summary: {e}")
            # Set safe defaults
            display_path = "Unknown"
            files_scanned = 0
            duration = 0
            finding_count = 0
            risk_level = "UNKNOWN"
            risk_class = "low"

        # Generate insights data
        try:
            insights_data = self._generate_insights_data(findings, metadata)
        except Exception as e:
            print(f"Warning: Error generating insights: {e}")
            insights_data = {"alerts": [], "top_types": [], "top_files": [], "recommendations": []}

        # Generate the HTML
        template = self._get_dashboard_html_template()

        # Insert the data into the template
        html = template.replace("{{REPORT_TITLE}}", "INSECT Security Dashboard")
        html = html.replace("{{REPOSITORY_PATH}}", display_path)
        html = html.replace("{{FILES_SCANNED}}", f"{files_scanned:,}")
        html = html.replace("{{SCAN_DURATION}}", f"{duration:.1f}s")
        html = html.replace("{{FINDING_COUNT}}", f"{finding_count:,}")
        html = html.replace("{{RISK_LEVEL}}", risk_level)
        html = html.replace("{{RISK_CLASS}}", risk_class)
        html = html.replace("{{FINDINGS_JSON}}", findings_json)
        html = html.replace("{{METADATA_JSON}}", metadata_json)
        html = html.replace("{{DEPENDENCIES_JSON}}", dependencies_json)
        html = html.replace("{{FILE_TREE_JSON}}", file_tree_json)
        html = html.replace("{{INSIGHTS_JSON}}", json.dumps(insights_data))

        return html

    def _build_file_tree_data(self, file_issues: Dict[str, List[Finding]], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Build file tree data structure for the explorer."""
        if not file_issues:
            return {"name": "Repository", "children": [], "issues": 0}

        # Get repository name
        repo_path = metadata.get("repository", ".")
        expanded_path = Path(repo_path).expanduser().resolve()
        repo_name = expanded_path.name if expanded_path.name else "Repository"

        # Build tree structure
        tree = {"name": repo_name, "type": "directory", "children": [], "issues": 0}
        directory_nodes = {"": tree}

        for file_path, issues in file_issues.items():
            try:
                path_parts = Path(file_path).parts
                if not path_parts:  # Skip empty paths
                    continue
                    
                current_path = ""
                
                # Create directory nodes (skip if only one part - root file)
                for i, part in enumerate(path_parts[:-1]):
                    parent_path = current_path
                    current_path = "/".join(path_parts[:i+1])
                    
                    if current_path not in directory_nodes:
                        parent_node = directory_nodes.get(parent_path, tree)
                        dir_node = {
                            "name": part,
                            "type": "directory",
                            "path": current_path,
                            "children": [],
                            "issues": 0
                        }
                        parent_node["children"].append(dir_node)
                        directory_nodes[current_path] = dir_node

                # Add file node
                parent_path = "/".join(path_parts[:-1]) if len(path_parts) > 1 else ""
                parent_node = directory_nodes.get(parent_path, tree)
                
                # Get worst severity for file (with safe access)
                severity_values = []
                for f in issues:
                    try:
                        if hasattr(f, 'severity') and f.severity and hasattr(f.severity, 'value'):
                            severity_values.append(f.severity.value.lower())
                    except:
                        continue
                
                worst_severity = "low"  # default
                if severity_values:
                    worst_severity = max(
                        severity_values,
                        key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0)
                    )
                
                # Build findings data safely
                findings_data = []
                for f in issues:
                    try:
                        finding_data = {
                            "id": getattr(f, 'id', 'unknown'),
                            "title": getattr(f, 'title', 'Unknown Issue'),
                            "description": getattr(f, 'description', ''),
                            "severity": f.severity.value if hasattr(f, 'severity') and f.severity else "unknown",
                            "line": getattr(f.location, 'line_start', None) if hasattr(f, 'location') and f.location else None,
                            "remediation": getattr(f, 'remediation', '') or ""
                        }
                        findings_data.append(finding_data)
                    except Exception as e:
                        print(f"Warning: Error processing finding for file tree: {e}")
                        continue
                
                file_node = {
                    "name": path_parts[-1] if path_parts else "unknown_file",
                    "type": "file",
                    "path": file_path,
                    "issues": len(issues),
                    "worst_severity": worst_severity,
                    "findings": findings_data
                }
                parent_node["children"].append(file_node)
                
            except Exception as e:
                print(f"Warning: Error processing file path {file_path}: {e}")
                continue

        # Calculate directory issue counts
        def calculate_directory_issues(node):
            if node["type"] == "file":
                return node["issues"]
            
            total = 0
            for child in node["children"]:
                total += calculate_directory_issues(child)
            node["issues"] = total
            return total

        calculate_directory_issues(tree)
        return tree

    def _generate_insights_data(self, findings: List[Finding], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights data for the dashboard."""
        try:
            severity_counts = metadata.get("severity_counts", {})
            
            # Safely convert severity counts
            severity_counts_lower = {}
            try:
                severity_counts_lower = {str(k).lower(): int(v) for k, v in severity_counts.items() if v is not None}
            except Exception:
                severity_counts_lower = {}
                
            total_issues = sum(severity_counts_lower.values())
            
            if total_issues == 0:
                return {
                    "alerts": ["✅ No security issues found - Repository appears secure!"],
                    "top_types": [],
                    "top_files": [],
                    "recommendations": []
                }
            
            # Priority alerts
            alerts = []
            critical = severity_counts_lower.get("critical", 0)
            high = severity_counts_lower.get("high", 0)
            medium = severity_counts_lower.get("medium", 0)
            low = severity_counts_lower.get("low", 0)
            
            if critical > 0:
                alerts.append(f"🚨 {critical} CRITICAL")
            if high > 0:
                alerts.append(f"⚠️ {high} HIGH")
            if medium > 0:
                alerts.append(f"📊 {medium} MEDIUM")
            if low > 0:
                alerts.append(f"🐛 {low} LOW")
            
            # Top issue types
            type_counts = metadata.get("type_counts", {})
            top_types_formatted = []
            try:
                if type_counts:
                    top_types = sorted(type_counts.items(), key=lambda x: int(x[1]) if x[1] is not None else 0, reverse=True)[:2]
                    top_types_formatted = [f"{str(issue_type).replace('_', ' ').title()}: {count}" for issue_type, count in top_types]
            except Exception as e:
                print(f"Warning: Error processing top types: {e}")
            
            # Most affected files
            file_issue_counts = {}
            try:
                for finding in findings:
                    try:
                        if hasattr(finding, 'location') and finding.location and hasattr(finding.location, 'path') and finding.location.path:
                            file_path = str(finding.location.path)
                            file_issue_counts[file_path] = file_issue_counts.get(file_path, 0) + 1
                    except Exception:
                        continue
            except Exception as e:
                print(f"Warning: Error processing file counts: {e}")
            
            top_files_formatted = []
            try:
                if file_issue_counts:
                    top_files = sorted(file_issue_counts.items(), key=lambda x: x[1], reverse=True)[:2]
                    top_files_formatted = [f"{Path(file_path).name}: {count}" for file_path, count in top_files]
            except Exception as e:
                print(f"Warning: Error processing top files: {e}")
            
            # Security recommendations
            recommendations = []
            try:
                if critical > 0 or high > 0:
                    recommendations.append("Address critical/high issues first")
                if type_counts and "secrets" in str(type_counts.keys()).lower():
                    recommendations.append("Rotate exposed secrets")
                if total_issues > 10:
                    recommendations.append("Consider automated CI/CD checks")
            except Exception as e:
                print(f"Warning: Error generating recommendations: {e}")
            
            return {
                "alerts": alerts,
                "top_types": top_types_formatted,
                "top_files": top_files_formatted,
                "recommendations": recommendations
            }
            
        except Exception as e:
            print(f"Warning: Error in insights generation: {e}")
            return {
                "alerts": ["Error generating insights"],
                "top_types": [],
                "top_files": [],
                "recommendations": []
            }

    def _get_dashboard_html_template(self) -> str:
        """Get the HTML template that mirrors the CLI dashboard layout."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{REPORT_TITLE}}</title>
    <style>
        :root {
            --primary-color: #3b82f6;
            --primary-dark: #1d4ed8;
            --critical-color: #ef4444;
            --high-color: #f97316;
            --medium-color: #eab308;
            --low-color: #22c55e;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --error-color: #ef4444;
            --background: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
        }

        body {
            font-family: 'SF Mono', 'Monaco', 'Cascadia Code', 'Roboto Mono', monospace;
            line-height: 1.5;
            color: var(--text-color);
            background-color: var(--background);
            margin: 0;
            padding: 1rem;
        }

        .dashboard {
            display: grid;
            grid-template-rows: auto auto 1fr;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            height: 100vh;
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            grid-column: 1 / -1;
            background-color: var(--card-bg);
            border: 2px solid var(--primary-color);
            border-radius: 0.5rem;
            padding: 1rem;
        }

        .scan-info {
            font-size: 1rem;
            font-weight: bold;
        }

        .insights {
            grid-column: 1 / -1;
            background-color: var(--card-bg);
            border: 2px solid var(--warning-color);
            border-radius: 0.5rem;
            padding: 1rem;
            max-height: 200px;
            overflow-y: auto;
        }

        .file-explorer {
            background-color: var(--card-bg);
            border: 2px solid var(--success-color);
            border-radius: 0.5rem;
            padding: 1rem;
            overflow-y: auto;
        }

        .issue-detail {
            background-color: var(--card-bg);
            border: 2px solid var(--error-color);
            border-radius: 0.5rem;
            padding: 1rem;
            overflow-y: auto;
        }

        .section-title {
            font-size: 1.1rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: var(--primary-color);
        }

        .tree-item {
            padding: 0.25rem 0;
            cursor: pointer;
            border-radius: 0.25rem;
            user-select: none;
        }

        .tree-item:hover {
            background-color: rgba(59, 130, 246, 0.1);
        }

        .tree-item.selected {
            background-color: rgba(59, 130, 246, 0.2);
        }

        .tree-item.directory {
            font-weight: 500;
        }

        .tree-item.file {
            margin-left: 1rem;
        }

        .tree-children {
            margin-left: 1rem;
            display: none;
        }

        .tree-children.expanded {
            display: block;
        }

        .severity-critical { color: var(--critical-color); }
        .severity-high { color: var(--high-color); }
        .severity-medium { color: var(--medium-color); }
        .severity-low { color: var(--low-color); }

        .issue-header {
            background-color: rgba(59, 130, 246, 0.1);
            padding: 0.75rem;
            border-radius: 0.25rem;
            margin-bottom: 0.5rem;
            border-left: 4px solid var(--primary-color);
        }

        .issue-content {
            padding: 0.5rem;
        }

        .issue-navigation {
            text-align: center;
            margin-bottom: 1rem;
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        .nav-buttons {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin-top: 0.5rem;
        }

        .nav-button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-family: inherit;
        }

        .nav-button:hover {
            background-color: var(--primary-dark);
        }

        .nav-button:disabled {
            background-color: var(--border-color);
            cursor: not-allowed;
        }

        .help-text {
            text-align: center;
            color: var(--text-muted);
            font-style: italic;
            margin: 2rem 0;
        }

        .expand-icon {
            display: inline-block;
            width: 1rem;
            margin-right: 0.25rem;
            transition: transform 0.2s;
        }

        .expand-icon.expanded {
            transform: rotate(90deg);
        }

        .keyboard-hint {
            position: fixed;
            bottom: 1rem;
            right: 1rem;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 0.75rem;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .export-button {
            position: fixed;
            top: 1rem;
            right: 1rem;
            background-color: var(--success-color);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-family: inherit;
            font-weight: bold;
        }

        .export-button:hover {
            background-color: #059669;
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
                grid-template-rows: auto auto auto auto;
            }
            
            .header, .insights {
                grid-column: 1;
            }
        }
    </style>
</head>
<body>
    <button class="export-button" onclick="exportReport()">📄 Export Report</button>
    
    <div class="dashboard">
        <div class="header">
            <div class="scan-info">
                🔍 <strong>{{REPOSITORY_PATH}}</strong> | 📁 {{FILES_SCANNED}} files | ⏱️ {{SCAN_DURATION}} | 🐛 <strong>{{FINDING_COUNT}} issues</strong>
            </div>
            <div style="margin-top: 0.5rem;">
                <strong>Risk:</strong> <span class="severity-{{RISK_CLASS}}">{{RISK_LEVEL}}</span>
            </div>
        </div>

        <div class="insights">
            <div class="section-title">📋 Key Insights</div>
            <div id="insights-content">
                <!-- Populated by JavaScript -->
            </div>
        </div>

        <div class="file-explorer">
            <div class="section-title">📁 File Explorer</div>
            <div id="file-tree">
                <!-- Populated by JavaScript -->
            </div>
        </div>

        <div class="issue-detail">
            <div class="section-title">🐛 Issue Details</div>
            <div id="issue-content">
                <div class="help-text">Select a file to view issues</div>
            </div>
        </div>
    </div>

    <div class="keyboard-hint">
        <div><strong>Navigation:</strong></div>
        <div>Click files to view issues</div>
        <div>Use Next/Previous buttons to navigate issues</div>
        <div>E - Export detailed report</div>
    </div>

    <script>
        // Data from the backend
        const findings = {{FINDINGS_JSON}};
        const metadata = {{METADATA_JSON}};
        const fileTree = {{FILE_TREE_JSON}};
        const insights = {{INSIGHTS_JSON}};
        
        let selectedFile = null;
        let currentIssueIndex = 0;

        // Initialize the dashboard
        function initializeDashboard() {
            renderInsights();
            renderFileTree();
            
            // Add keyboard navigation
            document.addEventListener('keydown', handleKeyPress);
        }

        function renderInsights() {
            const insightsContent = document.getElementById('insights-content');
            let html = '';
            
            if (insights.alerts.length > 0) {
                html += '<div style="margin-bottom: 0.5rem;">' + insights.alerts.join(' | ') + '</div>';
            }
            
            if (insights.top_types.length > 0) {
                html += '<div><strong>🎯 Top Issues:</strong> ' + insights.top_types.join(' | ') + '</div>';
            }
            
            if (insights.top_files.length > 0) {
                html += '<div><strong>📁 Top Files:</strong> ' + insights.top_files.join(' | ') + '</div>';
            }
            
            if (insights.recommendations.length > 0) {
                html += '<div><strong>🛡️ Actions:</strong> ' + insights.recommendations.join(' | ') + '</div>';
            }
            
            insightsContent.innerHTML = html;
        }

        function renderFileTree() {
            const fileTreeElement = document.getElementById('file-tree');
            fileTreeElement.innerHTML = renderTreeNode(fileTree, 0);
        }

        function renderTreeNode(node, depth) {
            let html = '';
            const indent = '  '.repeat(depth);
            
            if (node.type === 'directory') {
                const hasChildren = node.children && node.children.length > 0;
                const expandIcon = hasChildren ? '<span class="expand-icon">▶</span>' : '<span class="expand-icon"> </span>';
                const issueCount = node.issues > 0 ? ` (${node.issues})` : '';
                
                html += `<div class="tree-item directory" data-path="${node.path || ''}" onclick="toggleDirectory('${node.path || ''}')">
                    ${indent}${expandIcon}📁 ${node.name}${issueCount}
                </div>`;
                
                if (hasChildren) {
                    html += `<div class="tree-children" id="children-${node.path || 'root'}">`;
                    for (const child of node.children) {
                        html += renderTreeNode(child, depth + 1);
                    }
                    html += '</div>';
                }
            } else if (node.type === 'file' && node.issues > 0) {
                const severityClass = node.worst_severity ? `severity-${node.worst_severity}` : '';
                html += `<div class="tree-item file ${severityClass}" data-path="${node.path}" onclick="selectFile('${node.path}')">
                    ${indent}📄 ${node.name} (${node.issues})
                </div>`;
            }
            
            return html;
        }

        function toggleDirectory(path) {
            const childrenElement = document.getElementById(`children-${path || 'root'}`);
            const expandIcon = event.target.querySelector('.expand-icon');
            
            if (childrenElement) {
                childrenElement.classList.toggle('expanded');
                if (expandIcon) {
                    expandIcon.classList.toggle('expanded');
                }
            }
        }

        function selectFile(filePath) {
            // Clear previous selection
            document.querySelectorAll('.tree-item.selected').forEach(el => el.classList.remove('selected'));
            
            // Select new file
            event.target.classList.add('selected');
            selectedFile = filePath;
            currentIssueIndex = 0;
            
            // Find file in tree to get its findings
            const fileNode = findFileInTree(fileTree, filePath);
            if (fileNode && fileNode.findings) {
                renderIssueDetails(fileNode.findings);
            }
        }

        function findFileInTree(node, targetPath) {
            if (node.type === 'file' && node.path === targetPath) {
                return node;
            }
            
            if (node.children) {
                for (const child of node.children) {
                    const result = findFileInTree(child, targetPath);
                    if (result) return result;
                }
            }
            
            return null;
        }

        function renderIssueDetails(issues) {
            const issueContent = document.getElementById('issue-content');
            
            if (!issues || issues.length === 0) {
                issueContent.innerHTML = '<div class="help-text">No issues found in selected file</div>';
                return;
            }
            
            const issue = issues[currentIssueIndex];
            const filename = selectedFile ? selectedFile.split('/').pop() : 'Unknown';
            const navigationInfo = issues.length > 1 ? ` (${currentIssueIndex + 1}/${issues.length})` : '';
            const navHint = issues.length > 1 ? ' | Use navigation buttons below' : '';
            
            let html = `
                <div class="issue-header">
                    <strong>${filename}${navigationInfo}</strong>${navHint}
                </div>
            `;
            
            if (issues.length > 1) {
                html += `
                    <div class="issue-navigation">
                        <div class="nav-buttons">
                            <button class="nav-button" onclick="previousIssue()" ${currentIssueIndex === 0 ? 'disabled' : ''}>
                                ← Previous
                            </button>
                            <button class="nav-button" onclick="nextIssue()" ${currentIssueIndex === issues.length - 1 ? 'disabled' : ''}>
                                Next →
                            </button>
                        </div>
                    </div>
                `;
            }
            
            const severityClass = `severity-${issue.severity}`;
            html += `
                <div class="issue-content">
                    <div style="margin-bottom: 1rem;">
                        <span class="${severityClass}"><strong>${issue.severity.toUpperCase()}</strong></span> - ${issue.title}
                    </div>
            `;
            
            if (issue.line) {
                html += `<div style="margin-bottom: 0.5rem;"><strong>📍 Line ${issue.line}</strong></div>`;
            }
            
            if (issue.description) {
                const desc = issue.description.length > 150 ? issue.description.substring(0, 150) + '...' : issue.description;
                html += `<div style="margin-bottom: 0.5rem;">${desc}</div>`;
            }
            
            if (issue.remediation) {
                const remediation = issue.remediation.length > 150 ? issue.remediation.substring(0, 150) + '...' : issue.remediation;
                html += `<div style="margin-bottom: 0.5rem; color: var(--primary-color);">💡 ${remediation}</div>`;
            }
            
            html += '</div>';
            issueContent.innerHTML = html;
        }

        function nextIssue() {
            const fileNode = findFileInTree(fileTree, selectedFile);
            if (fileNode && fileNode.findings && currentIssueIndex < fileNode.findings.length - 1) {
                currentIssueIndex++;
                renderIssueDetails(fileNode.findings);
            }
        }

        function previousIssue() {
            const fileNode = findFileInTree(fileTree, selectedFile);
            if (fileNode && fileNode.findings && currentIssueIndex > 0) {
                currentIssueIndex--;
                renderIssueDetails(fileNode.findings);
            }
        }

        function handleKeyPress(event) {
            switch(event.key.toLowerCase()) {
                case 'n':
                    nextIssue();
                    break;
                case 'm':
                    previousIssue();
                    break;
                case 'e':
                    exportReport();
                    break;
            }
        }

        function exportReport() {
            // Create a detailed HTML report
            const reportData = {
                metadata: metadata,
                findings: findings,
                timestamp: new Date().toISOString()
            };
            
            // Create and download JSON report
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataBlob = new Blob([dataStr], {type: 'application/json'});
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `insect-report-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            
            alert('Report exported successfully!');
        }

        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', initializeDashboard);
    </script>
</body>
</html>
"""