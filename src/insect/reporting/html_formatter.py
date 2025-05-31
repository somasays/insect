"""HTML formatter for Insect reports."""

import json
from datetime import datetime
from typing import Any, Dict, List

from insect.finding import Finding
from insect.reporting.formatters import BaseFormatter


class HtmlFormatter(BaseFormatter):
    """HTML formatter for Insect reports."""

    format_name = "html"

    def format_findings(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Format findings as an HTML string.

        Args:
            findings: List of findings.
            metadata: Scan metadata.

        Returns:
            Formatted report as an HTML string.
        """
        # Check if we need to append dependency information
        from insect.analysis.dependency_manager import get_dependencies_status

        dependencies = get_dependencies_status()

        # Convert findings to a format usable in the template
        formatted_findings = []
        for finding in findings:
            formatted_findings.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "severity_label": finding.severity.name,
                    "type": finding.type.value,
                    "type_label": finding.type.name.title(),
                    "location": str(finding.location),
                    "location_file": str(finding.location.path),
                    "location_line": finding.location.line_start,
                    "remediation": finding.remediation or "",
                    "references": finding.references,
                    "confidence": f"{finding.confidence * 100:.0f}%",
                    "analyzer": finding.analyzer,
                    "created_at": finding.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "cwe_id": finding.cwe_id or "",
                    "cvss_score": finding.cvss_score,
                }
            )

        # JSON encode the findings and metadata for use in the JavaScript
        findings_json = json.dumps(formatted_findings)
        metadata_json = json.dumps(metadata)
        dependencies_json = json.dumps(dependencies)

        # Create severity stats for the summary
        severity_stats = []
        for sev in ["critical", "high", "medium", "low"]:
            count = metadata.get("severity_counts", {}).get(sev, 0)
            severity_stats.append(
                {
                    "name": sev.upper(),
                    "count": count,
                    "class": sev,
                }
            )

        # Create type stats for the summary
        type_stats = []
        for type_name, count in metadata.get("type_counts", {}).items():
            type_stats.append(
                {
                    "name": type_name.title(),
                    "count": count,
                    "class": type_name.lower(),
                }
            )

        severity_stats_json = json.dumps(severity_stats)
        type_stats_json = json.dumps(type_stats)

        # Generate the HTML
        template = self._get_html_template()

        # Insert the data into the template
        html = template.replace("{{REPORT_TITLE}}", "Insect Security Report")
        html = html.replace("{{REPOSITORY}}", metadata.get("repository", "Unknown"))
        html = html.replace("{{SCAN_ID}}", metadata.get("scan_id", "Unknown"))
        html = html.replace(
            "{{TIMESTAMP}}", metadata.get("timestamp", datetime.now().isoformat())
        )
        html = html.replace(
            "{{DURATION}}", f"{metadata.get('duration_seconds', 0):.2f} seconds"
        )
        html = html.replace("{{FILES_SCANNED}}", str(metadata.get("file_count", 0)))
        html = html.replace("{{TOTAL_FINDINGS}}", str(metadata.get("finding_count", 0)))
        html = html.replace("{{FINDINGS_JSON}}", findings_json)
        html = html.replace("{{METADATA_JSON}}", metadata_json)
        html = html.replace("{{SEVERITY_STATS_JSON}}", severity_stats_json)
        html = html.replace("{{TYPE_STATS_JSON}}", type_stats_json)
        html = html.replace("{{DEPENDENCIES_JSON}}", dependencies_json)

        return html

    def _get_html_template(self) -> str:
        """Get the HTML template for the report.

        Returns:
            The HTML template string.
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{REPORT_TITLE}}</title>
    <style>
        :root {
            --primary-color: #3b82f6;  /* Blue */
            --primary-dark: #1d4ed8;    /* Darker Blue */
            --critical-color: #ef4444;  /* Red */
            --high-color: #f97316;      /* Orange */
            --medium-color: #eab308;    /* Yellow */
            --low-color: #22c55e;       /* Green */
            --background: #f8fafc;      /* Light Gray */
            --card-bg: #ffffff;         /* White */
            --text-color: #1e293b;      /* Slate */
            --border-color: #e2e8f0;    /* Light Slate */
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            color: var(--text-color);
            background-color: var(--background);
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1rem;
        }
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 1rem 0;
            margin-bottom: 2rem;
        }
        header h1 {
            margin: 0;
            font-size: 1.8rem;
            font-weight: 600;
        }
        header p {
            margin: 0.5rem 0 0 0;
            opacity: 0.9;
        }
        .card {
            background-color: var(--card-bg);
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        h2, h3 {
            margin-top: 0;
            color: var(--primary-dark);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .stat-card {
            background-color: var(--card-bg);
            border-radius: 0.5rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            padding: 1rem;
            text-align: center;
        }
        .stat-card .stat-value {
            font-size: 2rem;
            font-weight: 600;
            margin: 0.5rem 0;
        }
        .stat-card .stat-label {
            font-size: 0.875rem;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .tab-container {
            margin-bottom: 1.5rem;
        }
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1rem;
        }
        .tab {
            padding: 0.75rem 1rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            font-weight: 500;
        }
        .tab.active {
            border-bottom-color: var(--primary-color);
            color: var(--primary-color);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        th, td {
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: #f1f5f9;
            font-weight: 500;
        }
        tr:hover {
            background-color: #f8fafc;
        }
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        .severity-critical {
            background-color: var(--critical-color);
        }
        .severity-high {
            background-color: var(--high-color);
        }
        .severity-medium {
            background-color: var(--medium-color);
        }
        .severity-low {
            background-color: var(--low-color);
        }
        .finding-details {
            display: none;
            padding: 1rem;
            background-color: #f1f5f9;
            border-radius: 0.25rem;
            margin-top: 0.5rem;
        }
        .finding-details dl {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 0.5rem;
            margin: 0;
        }
        .finding-details dt {
            font-weight: 600;
            color: #475569;
        }
        .finding-details dd {
            margin: 0;
        }
        .reference-list {
            margin: 0;
            padding-left: 1.5rem;
        }
        .toggle-details {
            background: none;
            border: none;
            color: var(--primary-color);
            cursor: pointer;
            font-size: 0.875rem;
            padding: 0.25rem 0.5rem;
            margin-left: 0.5rem;
        }
        .toggle-details:hover {
            text-decoration: underline;
        }
        .filter-controls {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        .filter-group {
            display: flex;
            flex-direction: column;
            min-width: 200px;
        }
        .filter-group label {
            font-weight: 500;
            margin-bottom: 0.25rem;
        }
        .filter-group select {
            padding: 0.5rem;
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            background-color: white;
        }
        .search-group {
            flex-grow: 1;
        }
        .search-group input {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
        }
        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem 0;
            border-top: 1px solid var(--border-color);
            font-size: 0.875rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{{REPORT_TITLE}}</h1>
            <p>Repository: {{REPOSITORY}}</p>
        </div>
    </header>

    <div class="container">
        <div class="card">
            <h2>Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-label">Files Scanned</div>
                    <div class="stat-value">{{FILES_SCANNED}}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Findings</div>
                    <div class="stat-value">{{TOTAL_FINDINGS}}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Scan Duration</div>
                    <div class="stat-value">{{DURATION}}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Scan ID</div>
                    <div class="stat-value" style="font-size: 0.9rem;">{{SCAN_ID}}</div>
                </div>
            </div>
        </div>

        <div class="tab-container">
            <div class="tabs">
                <div class="tab active" data-tab="findings">Findings</div>
                <div class="tab" data-tab="statistics">Statistics</div>
                <div class="tab" data-tab="metadata">Metadata</div>
                <div class="tab" data-tab="dependencies">Dependencies</div>
            </div>

            <div id="findings" class="tab-content active">
                <div class="card">
                    <h3>Security Findings</h3>
                    <div class="filter-controls">
                        <div class="filter-group">
                            <label for="severity-filter">Severity</label>
                            <select id="severity-filter">
                                <option value="all">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label for="type-filter">Type</label>
                            <select id="type-filter">
                                <option value="all">All Types</option>
                                <!-- Dynamically populated -->
                            </select>
                        </div>
                        <div class="filter-group search-group">
                            <label for="search-input">Search</label>
                            <input type="text" id="search-input" placeholder="Search in findings...">
                        </div>
                    </div>
                    <table id="findings-table">
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Location</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Dynamically populated -->
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="statistics" class="tab-content">
                <div class="card">
                    <h3>Findings by Severity</h3>
                    <table id="severity-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Dynamically populated -->
                        </tbody>
                    </table>
                </div>

                <div class="card">
                    <h3>Findings by Type</h3>
                    <table id="type-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Count</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Dynamically populated -->
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="metadata" class="tab-content">
                <div class="card">
                    <h3>Scan Metadata</h3>
                    <table>
                        <tr>
                            <th>Timestamp</th>
                            <td>{{TIMESTAMP}}</td>
                        </tr>
                        <tr>
                            <th>Repository</th>
                            <td>{{REPOSITORY}}</td>
                        </tr>
                        <tr>
                            <th>Scan ID</th>
                            <td>{{SCAN_ID}}</td>
                        </tr>
                        <tr>
                            <th>Duration</th>
                            <td>{{DURATION}}</td>
                        </tr>
                    </table>
                </div>
            </div>

            <div id="dependencies" class="tab-content">
                <div class="card">
                    <h3>External Dependencies Status</h3>
                    <p>These dependencies enhance Insect's scanning capabilities when installed.</p>
                    <table id="dependencies-table">
                        <thead>
                            <tr>
                                <th>Tool</th>
                                <th>Status</th>
                                <th>Description</th>
                                <th>Version</th>
                                <th>Path</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Dynamically populated -->
                        </tbody>
                    </table>
                </div>

                <div class="card">
                    <h3>Installation Instructions</h3>
                    <div id="missing-dependencies">
                        <!-- Dynamically populated -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer container">
        <p>Generated by Insect Security Scanner</p>
    </div>

    <script>
        // Data from the backend
        const findings = {{FINDINGS_JSON}};
        const metadata = {{METADATA_JSON}};
        const severityStats = {{SEVERITY_STATS_JSON}};
        const typeStats = {{TYPE_STATS_JSON}};
        const dependencies = {{DEPENDENCIES_JSON}};

        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        // Populate findings table
        function populateFindingsTable(filteredFindings = findings) {
            const tableBody = document.querySelector('#findings-table tbody');
            tableBody.innerHTML = '';

            if (filteredFindings.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = `<td colspan="5">No findings match the current filters.</td>`;
                tableBody.appendChild(row);
                return;
            }

            filteredFindings.forEach((finding, index) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${finding.title}</td>
                    <td><span class="severity-badge severity-${finding.severity}">${finding.severity_label}</span></td>
                    <td>${finding.type_label}</td>
                    <td>${finding.location}</td>
                    <td>
                        <button class="toggle-details" data-index="${index}">Details</button>
                    </td>
                `;

                const detailsRow = document.createElement('tr');
                detailsRow.innerHTML = `
                    <td colspan="5">
                        <div class="finding-details" id="details-${index}">
                            <dl>
                                <dt>ID:</dt>
                                <dd>${finding.id}</dd>

                                <dt>Description:</dt>
                                <dd>${finding.description}</dd>

                                <dt>Severity:</dt>
                                <dd><span class="severity-badge severity-${finding.severity}">${finding.severity_label}</span></dd>

                                <dt>Type:</dt>
                                <dd>${finding.type_label}</dd>

                                <dt>Location:</dt>
                                <dd>${finding.location}</dd>

                                <dt>Analyzer:</dt>
                                <dd>${finding.analyzer}</dd>

                                <dt>Confidence:</dt>
                                <dd>${finding.confidence}</dd>

                                ${finding.remediation ? `<dt>Remediation:</dt><dd>${finding.remediation}</dd>` : ''}

                                ${finding.cwe_id ? `<dt>CWE ID:</dt><dd>${finding.cwe_id}</dd>` : ''}

                                ${finding.cvss_score ? `<dt>CVSS Score:</dt><dd>${finding.cvss_score}</dd>` : ''}

                                ${finding.references && finding.references.length > 0 ? `
                                    <dt>References:</dt>
                                    <dd>
                                        <ul class="reference-list">
                                            ${finding.references.map(ref => `<li>${ref}</li>`).join('')}
                                        </ul>
                                    </dd>` : ''}
                            </dl>
                        </div>
                    </td>
                `;

                tableBody.appendChild(row);
                tableBody.appendChild(detailsRow);
            });

            // Add event listeners for details toggle
            document.querySelectorAll('.toggle-details').forEach(button => {
                button.addEventListener('click', () => {
                    const index = button.dataset.index;
                    const detailsElement = document.getElementById(`details-${index}`);

                    if (detailsElement.style.display === 'block') {
                        detailsElement.style.display = 'none';
                        button.textContent = 'Details';
                    } else {
                        detailsElement.style.display = 'block';
                        button.textContent = 'Hide';
                    }
                });
            });
        }

        // Populate statistics tables
        function populateStatisticsTables() {
            // Severity stats
            const severityTableBody = document.querySelector('#severity-table tbody');
            severityTableBody.innerHTML = '';

            severityStats.forEach(stat => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><span class="severity-badge severity-${stat.class}">${stat.name}</span></td>
                    <td>${stat.count}</td>
                `;
                severityTableBody.appendChild(row);
            });

            // Type stats
            const typeTableBody = document.querySelector('#type-table tbody');
            typeTableBody.innerHTML = '';

            typeStats.forEach(stat => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${stat.name}</td>
                    <td>${stat.count}</td>
                `;
                typeTableBody.appendChild(row);
            });
        }

        // Filter handling
        function applyFilters() {
            const severityFilter = document.getElementById('severity-filter').value;
            const typeFilter = document.getElementById('type-filter').value;
            const searchText = document.getElementById('search-input').value.toLowerCase();

            let filteredFindings = findings;

            // Apply severity filter
            if (severityFilter !== 'all') {
                filteredFindings = filteredFindings.filter(finding => finding.severity === severityFilter);
            }

            // Apply type filter
            if (typeFilter !== 'all') {
                filteredFindings = filteredFindings.filter(finding => finding.type === typeFilter);
            }

            // Apply search filter
            if (searchText) {
                filteredFindings = filteredFindings.filter(finding =>
                    finding.title.toLowerCase().includes(searchText) ||
                    finding.description.toLowerCase().includes(searchText) ||
                    finding.location.toLowerCase().includes(searchText)
                );
            }

            populateFindingsTable(filteredFindings);
        }

        // Initialize filters
        function initializeFilters() {
            // Get unique types from findings
            const types = Array.from(new Set(findings.map(finding => finding.type)));

            // Populate type filter dropdown
            const typeFilter = document.getElementById('type-filter');
            types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type.charAt(0).toUpperCase() + type.slice(1);
                typeFilter.appendChild(option);
            });

            // Add event listeners for filters
            document.getElementById('severity-filter').addEventListener('change', applyFilters);
            document.getElementById('type-filter').addEventListener('change', applyFilters);
            document.getElementById('search-input').addEventListener('input', applyFilters);
        }

        // Populate dependencies tables
        function populateDependenciesTables() {
            // Populate dependencies table
            const tableBody = document.querySelector('#dependencies-table tbody');
            tableBody.innerHTML = '';

            // Status icons/classes mapping
            const statusMap = {
                'available': { icon: '✓', class: 'severity-low' },
                'not_found': { icon: '✗', class: 'severity-high' },
                'version_mismatch': { icon: '⚠', class: 'severity-medium' },
                'broken': { icon: '✗', class: 'severity-high' }
            };

            // Sort dependencies by status (available first, then others)
            const dependenciesArray = Object.entries(dependencies)
                .map(([name, info]) => ({ name, ...info }))
                .sort((a, b) => {
                    // Sort by status first (available at top)
                    if (a.status === 'available' && b.status !== 'available') return -1;
                    if (a.status !== 'available' && b.status === 'available') return 1;
                    // Then alphabetically by name
                    return a.name.localeCompare(b.name);
                });

            dependenciesArray.forEach(dep => {
                const row = document.createElement('tr');
                const status = statusMap[dep.status] || { icon: '?', class: '' };

                row.innerHTML = `
                    <td><strong>${dep.name}</strong></td>
                    <td><span class="severity-badge ${status.class}">${status.icon} ${dep.status.replace('_', ' ').toUpperCase()}</span></td>
                    <td>${dep.description}</td>
                    <td>${dep.version}</td>
                    <td>${dep.path}</td>
                `;
                tableBody.appendChild(row);
            });

            // Populate installation instructions for missing dependencies
            const missingDepsDiv = document.getElementById('missing-dependencies');
            missingDepsDiv.innerHTML = '';

            const missingDeps = dependenciesArray.filter(dep => dep.status !== 'available');

            if (missingDeps.length === 0) {
                missingDepsDiv.innerHTML = '<p>All dependencies are available. No installation required.</p>';
                return;
            }

            missingDeps.forEach(dep => {
                const depDiv = document.createElement('div');
                depDiv.className = 'card';
                depDiv.style.marginBottom = '1rem';
                depDiv.style.padding = '1rem';

                depDiv.innerHTML = `
                    <h4>${dep.name}</h4>
                    <p>${dep.description}</p>
                    <p><strong>Installation:</strong> ${dep.install}</p>
                `;
                missingDepsDiv.appendChild(depDiv);
            });
        }

        // Initialize the page
        document.addEventListener('DOMContentLoaded', () => {
            populateFindingsTable();
            populateStatisticsTables();
            populateDependenciesTables();
            initializeFilters();
        });
    </script>
</body>
</html>
"""
