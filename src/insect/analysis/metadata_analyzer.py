"""
Static analyzer for Git repository metadata to detect suspicious patterns.

This module implements an analyzer for Git repository metadata that:
1. Checks for unusual commit patterns (e.g., large binary blobs, overnight commits)
2. Identifies potentially risky contributors (e.g., one-time committers)
3. Finds sensitive information in commit messages
4. Analyzes branch naming patterns for potential issues
"""

import logging
import os
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import git
from git import Repo

from insect.analysis import BaseAnalyzer, register_analyzer
from insect.finding import Finding, FindingType, Location, Severity

logger = logging.getLogger(__name__)

# Patterns for sensitive information in commit messages
SENSITIVE_PATTERNS = [
    r"password\s*[=:]\s*[\w\d_-]+",
    r"secret\s*[=:]\s*[\w\d_-]+",
    r"token\s*[=:]\s*[\w\d_-]+",
    r"key\s*[=:]\s*[\w\d_-]+",
    r"credential\s*[=:]\s*[\w\d_-]+",
    r"api[-_]?key\s*[=:]\s*[\w\d_-]+",
]

# Night time hours (UTC) for detecting suspicious commit times
NIGHT_START_HOUR = 22  # 10 PM
NIGHT_END_HOUR = 6  # 6 AM

# Thresholds for suspicious patterns
LARGE_COMMIT_THRESHOLD = 1000  # files
LARGE_BINARY_THRESHOLD = 10 * 1024 * 1024  # 10 MB


@register_analyzer
class MetadataAnalyzer(BaseAnalyzer):
    """Static analyzer for Git repository metadata to detect suspicious patterns."""

    name = "metadata"
    description = "Analyzes Git repository metadata for suspicious patterns"
    supported_extensions = {
        "*"
    }  # Operates on the repository level, not individual files

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the metadata analyzer."""
        super().__init__(config)
        self.analyzer_config = config.get(self.name, {})
        self.min_confidence = self.analyzer_config.get("min_confidence", 0.0)

        # Configure specific analyzers
        self.check_commits = self.analyzer_config.get("check_commits", True)
        self.check_contributors = self.analyzer_config.get("check_contributors", True)
        self.check_branches = self.analyzer_config.get("check_branches", True)

        # Configure specific thresholds
        self.large_commit_threshold = self.analyzer_config.get(
            "large_commit_threshold", LARGE_COMMIT_THRESHOLD
        )
        self.large_binary_threshold = self.analyzer_config.get(
            "large_binary_threshold", LARGE_BINARY_THRESHOLD
        )

        # Maximum commits to analyze
        self.max_commits = self.analyzer_config.get("max_commits", 100)

        # Night time detection (can be customized)
        self.night_start_hour = self.analyzer_config.get(
            "night_start_hour", NIGHT_START_HOUR
        )
        self.night_end_hour = self.analyzer_config.get("night_end_hour", NIGHT_END_HOUR)

        # Git repository handle (initialized when needed)
        self.repo: Optional[Repo] = None

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Analyze repository metadata.

        This method is called on a per-file basis, but for metadata analysis,
        we only need to analyze once per repository. So, we'll check if the file
        is in a git repository, and if so, analyze the repository if we haven't already.

        Args:
            file_path: Path to the file, which is used to find the Git repository.

        Returns:
            List of findings identified in the repository metadata.
        """
        if not self.enabled:
            return []

        findings = []

        try:
            # Try to get the Git repository from the file path
            repo_path = self._find_git_repository(file_path)
            if not repo_path:
                return []

            # If the file is in a git repository and we haven't analyzed it yet,
            # initialize the repository and analyze it
            if self.repo is None:
                try:
                    self.repo = Repo(repo_path)

                    # If the repository is valid, analyze it
                    if not self.repo.bare:
                        if self.check_commits:
                            findings.extend(self._analyze_commits())

                        if self.check_contributors:
                            findings.extend(self._analyze_contributors())

                        if self.check_branches:
                            findings.extend(self._analyze_branches())
                except git.InvalidGitRepositoryError:
                    logger.debug(f"Not a valid git repository: {repo_path}")
                except git.NoSuchPathError:
                    logger.debug(f"Git repository path not found: {repo_path}")
                except Exception as e:
                    logger.error(f"Error initializing git repository: {str(e)}")
                    findings.append(
                        self._create_error_finding(
                            file_path, f"Failed to initialize git repository: {str(e)}"
                        )
                    )
        except Exception as e:
            logger.error(f"Error analyzing repository metadata: {str(e)}")
            findings.append(
                self._create_error_finding(
                    file_path, f"Failed to analyze repository metadata: {str(e)}"
                )
            )

        return findings

    def _find_git_repository(self, file_path: Path) -> Optional[str]:
        """
        Find the Git repository containing the specified file.

        Args:
            file_path: Path to a file.

        Returns:
            Path to the Git repository, or None if not found.
        """
        try:
            current_dir = file_path.parent.absolute()

            # Walk up the directory tree to find .git directory
            while current_dir != current_dir.parent:
                git_dir = current_dir / ".git"
                if git_dir.exists() and git_dir.is_dir():
                    return str(current_dir)
                current_dir = current_dir.parent

            return None
        except Exception as e:
            logger.error(f"Error finding git repository: {str(e)}")
            return None

    def _analyze_commits(self) -> List[Finding]:
        """
        Analyze commit history for suspicious patterns.

        Returns:
            List of findings related to commit history.
        """
        if not self.repo:
            return []

        findings = []

        try:
            # Get commit history
            commits = list(self.repo.iter_commits(max_count=self.max_commits))

            # Check for sensitive information in commit messages
            for commit in commits:
                # Check for sensitive information in commit messages
                findings.extend(self._check_commit_message(commit))

                # Check for unusual commit times
                findings.extend(self._check_commit_time(commit))

                # Check for large commits
                findings.extend(self._check_commit_size(commit))

                # Check for large binary files
                findings.extend(self._check_binary_files(commit))

        except Exception as e:
            logger.error(f"Error analyzing commit history: {str(e)}")
            findings.append(
                self._create_error_finding(
                    Path(self.repo.working_dir),
                    f"Failed to analyze commit history: {str(e)}",
                )
            )

        return findings

    def _check_commit_message(self, commit: git.Commit) -> List[Finding]:
        """
        Check commit message for sensitive information.

        Args:
            commit: Git commit object.

        Returns:
            List of findings related to sensitive information in commit messages.
        """
        findings = []

        try:
            message = commit.message

            for pattern in SENSITIVE_PATTERNS:
                message_str = (
                    message
                    if isinstance(message, str)
                    else message.decode("utf-8", errors="ignore")
                )
                matches = re.finditer(pattern, message_str, re.IGNORECASE)

                for match in matches:
                    # Extract the matched text for the finding
                    matched_text = match.group(0)

                    # Create a finding for the sensitive information
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            title="Sensitive information in commit message",
                            description=(
                                f"Commit {commit.hexsha[:8]} contains potentially sensitive "
                                f"information in its commit message: {matched_text}"
                            ),
                            severity=Severity.MEDIUM,
                            type=FindingType.SECRET,
                            location=Location(
                                path=(
                                    Path(self.repo.working_dir)
                                    if self.repo
                                    else Path(".")
                                ),
                            ),
                            analyzer=self.name,
                            confidence=0.7,
                            tags=["git", "sensitive-data", "commit-message"],
                            metadata={
                                "commit_hash": commit.hexsha,
                                "commit_author": f"{commit.author.name} <{commit.author.email}>",
                                "commit_date": commit.committed_datetime.isoformat(),
                                "pattern": pattern,
                                "matched_text": matched_text,
                            },
                            remediation=(
                                "Rewrite git history to remove the sensitive information using "
                                "git-filter-repo or similar tools. Update any leaked credentials."
                            ),
                        )
                    )
        except Exception as e:
            logger.error(f"Error checking commit message: {str(e)}")

        return findings

    def _check_commit_time(self, commit: git.Commit) -> List[Finding]:
        """
        Check for unusual commit times.

        Args:
            commit: Git commit object.

        Returns:
            List of findings related to unusual commit times.
        """
        findings = []

        try:
            # Check for commits made during night hours
            commit_time = commit.committed_datetime.time()

            # Logic to handle night hours spanning midnight
            if self.night_start_hour > self.night_end_hour:
                is_night = (
                    commit_time.hour >= self.night_start_hour
                    or commit_time.hour < self.night_end_hour
                )
            else:
                is_night = (
                    self.night_start_hour <= commit_time.hour < self.night_end_hour
                )

            if is_night:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="Commit made during unusual hours",
                        description=(
                            f"Commit {commit.hexsha[:8]} was made during night hours "
                            f"({commit.committed_datetime.strftime('%H:%M:%S')}), which may "
                            f"indicate suspicious activity."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=(
                                Path(self.repo.working_dir) if self.repo else Path(".")
                            ),
                        ),
                        analyzer=self.name,
                        confidence=0.5,  # Lower confidence as this is somewhat speculative
                        tags=["git", "unusual-time", "night-commit"],
                        metadata={
                            "commit_hash": commit.hexsha,
                            "commit_author": f"{commit.author.name} <{commit.author.email}>",
                            "commit_date": commit.committed_datetime.isoformat(),
                            "commit_time": commit.committed_datetime.strftime(
                                "%H:%M:%S"
                            ),
                        },
                        remediation=(
                            "Investigate the commit to ensure it was legitimate. "
                            "Consider implementing a policy for code review of commits "
                            "made during unusual hours."
                        ),
                    )
                )
        except Exception as e:
            logger.error(f"Error checking commit time: {str(e)}")

        return findings

    def _check_commit_size(self, commit: git.Commit) -> List[Finding]:
        """
        Check for unusually large commits.

        Args:
            commit: Git commit object.

        Returns:
            List of findings related to unusually large commits.
        """
        findings = []

        try:
            # For efficiency, we only check if we have parents to compare against
            if not commit.parents:
                return []

            # Get the diff between this commit and its parent
            parent = commit.parents[0]
            diffs = parent.diff(commit)

            # Check if the commit modifies too many files
            if len(diffs) > self.large_commit_threshold:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="Unusually large commit",
                        description=(
                            f"Commit {commit.hexsha[:8]} modifies {len(diffs)} files, which is "
                            f"above the threshold of {self.large_commit_threshold}. Large commits "
                            f"can indicate automated code changes, code drops, or potential security issues."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=(
                                Path(self.repo.working_dir) if self.repo else Path(".")
                            ),
                        ),
                        analyzer=self.name,
                        confidence=0.6,
                        tags=["git", "large-commit"],
                        metadata={
                            "commit_hash": commit.hexsha,
                            "commit_author": f"{commit.author.name} <{commit.author.email}>",
                            "commit_date": commit.committed_datetime.isoformat(),
                            "files_changed": len(diffs),
                            "threshold": self.large_commit_threshold,
                        },
                        remediation=(
                            "Review the commit to ensure it contains only legitimate changes. "
                            "Consider splitting large commits into smaller, logical units for "
                            "better maintainability and security reviews."
                        ),
                    )
                )
        except Exception as e:
            logger.error(f"Error checking commit size: {str(e)}")

        return findings

    def _check_binary_files(self, commit: git.Commit) -> List[Finding]:
        """
        Check for large binary files in commits.

        Args:
            commit: Git commit object.

        Returns:
            List of findings related to binary files.
        """
        findings = []

        try:
            # For efficiency, we only check if we have parents to compare against
            if not commit.parents:
                return []

            # Get the diff between this commit and its parent
            parent = commit.parents[0]
            diffs = parent.diff(commit)

            # Check for binary files
            for diff in diffs:
                # Skip if not a binary file or if deleted
                if not diff.b_blob or diff.deleted_file:
                    continue

                # Check if it's a binary file and exceeds size threshold
                if diff.b_blob.size > self.large_binary_threshold:
                    # Get the file path
                    file_path = diff.b_path if diff.b_path else "unknown"

                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            title="Large binary file committed",
                            description=(
                                f"Commit {commit.hexsha[:8]} adds or modifies a large binary file "
                                f"'{file_path}' ({diff.b_blob.size / 1024 / 1024:.2f} MB), which exceeds "
                                f"the threshold of {self.large_binary_threshold / 1024 / 1024:.2f} MB. "
                                f"Large binary files in repositories can indicate improper use of version "
                                f"control or potentially malicious code."
                            ),
                            severity=Severity.MEDIUM,
                            type=FindingType.SUSPICIOUS,
                            location=Location(
                                path=(
                                    Path(os.path.join(self.repo.working_dir, file_path))
                                    if self.repo
                                    else Path(file_path)
                                ),
                            ),
                            analyzer=self.name,
                            confidence=0.7,
                            tags=["git", "binary-file", "large-file"],
                            metadata={
                                "commit_hash": commit.hexsha,
                                "commit_author": f"{commit.author.name} <{commit.author.email}>",
                                "commit_date": commit.committed_datetime.isoformat(),
                                "file_path": file_path,
                                "file_size_bytes": diff.b_blob.size,
                                "threshold_bytes": self.large_binary_threshold,
                            },
                            remediation=(
                                "Review the binary file to ensure it is legitimate and necessary. "
                                "Consider using Git LFS for large files or exclude them from version "
                                "control if appropriate."
                            ),
                        )
                    )
        except Exception as e:
            logger.error(f"Error checking binary files: {str(e)}")

        return findings

    def _analyze_contributors(self) -> List[Finding]:
        """
        Analyze contributor patterns for suspicious activity.

        Returns:
            List of findings related to contributor patterns.
        """
        if not self.repo:
            return []

        findings = []

        try:
            # Get all commit authors
            authors: Dict[str, int] = {}
            commits = list(self.repo.iter_commits(max_count=self.max_commits))

            # Count commits per author
            for commit in commits:
                author_identity = f"{commit.author.name} <{commit.author.email}>"
                authors[author_identity] = authors.get(author_identity, 0) + 1

            # Check for one-time contributors (possibly suspicious)
            one_time_contributors = [
                (author, count) for author, count in authors.items() if count == 1
            ]

            if one_time_contributors:
                # Find which commits these contributors made
                one_time_commits = {}
                for commit in commits:
                    author_identity = f"{commit.author.name} <{commit.author.email}>"
                    if author_identity in [a[0] for a in one_time_contributors]:
                        one_time_commits[author_identity] = commit.hexsha

                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="One-time contributors detected",
                        description=(
                            f"Detected {len(one_time_contributors)} one-time contributors to the repository. "
                            f"While potentially legitimate, one-time contributors can sometimes indicate "
                            f"suspicious activity or compromised accounts."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=Path(self.repo.working_dir),
                        ),
                        analyzer=self.name,
                        confidence=0.4,  # Lower confidence as this is often legitimate
                        tags=["git", "contributor-analysis"],
                        metadata={
                            "one_time_contributors": [
                                a[0] for a in one_time_contributors
                            ],
                            "one_time_commits": one_time_commits,
                            "commit_count": len(commits),
                        },
                        remediation=(
                            "Review commits made by one-time contributors to ensure they are legitimate. "
                            "Consider implementing a more thorough code review process for new contributors."
                        ),
                    )
                )
        except Exception as e:
            logger.error(f"Error analyzing contributors: {str(e)}")
            findings.append(
                self._create_error_finding(
                    Path(self.repo.working_dir),
                    f"Failed to analyze contributors: {str(e)}",
                )
            )

        return findings

    def _analyze_branches(self) -> List[Finding]:
        """
        Analyze branch patterns for potential issues.

        Returns:
            List of findings related to branch patterns.
        """
        if not self.repo:
            return []

        findings = []

        try:
            # Get all branches
            branches = self.repo.branches

            # Check for suspicious branch names
            suspicious_terms = [
                "backdoor",
                "bypass",
                "hack",
                "malware",
                "exploit",
                "temp",
                "hidden",
            ]

            suspicious_branches = []
            for branch in branches:
                branch_name = branch.name.lower()
                for term in suspicious_terms:
                    if term in branch_name:
                        suspicious_branches.append(branch.name)
                        break

            if suspicious_branches:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="Suspicious branch names detected",
                        description=(
                            f"Detected {len(suspicious_branches)} branches with potentially suspicious names: "
                            f"{', '.join(suspicious_branches)}. These names may indicate unauthorized "
                            f"or problematic code changes."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.SUSPICIOUS,
                        location=Location(
                            path=Path(self.repo.working_dir),
                        ),
                        analyzer=self.name,
                        confidence=0.5,
                        tags=["git", "branch-analysis"],
                        metadata={
                            "suspicious_branches": suspicious_branches,
                            "total_branches": len(list(branches)),
                        },
                        remediation=(
                            "Review the suspicious branches to ensure they contain only legitimate code. "
                            "Consider deleting or renaming branches that are no longer needed or have "
                            "misleading names."
                        ),
                    )
                )

            # Check for stale branches
            current_time = datetime.now()
            stale_branches = []
            for branch in branches:
                try:
                    # Get the latest commit on the branch
                    latest_commit = next(
                        self.repo.iter_commits(branch.name, max_count=1)
                    )
                    commit_time = latest_commit.committed_datetime

                    # Check if the branch hasn't been updated in over 6 months
                    time_difference = current_time - commit_time.replace(tzinfo=None)
                    if time_difference > timedelta(days=180):
                        stale_branches.append(
                            {
                                "name": branch.name,
                                "last_commit": commit_time.isoformat(),
                                "days_inactive": time_difference.days,
                            }
                        )
                except (git.GitCommandError, StopIteration):
                    # Skip branches with no commits
                    continue

            if stale_branches:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        title="Stale branches detected",
                        description=(
                            f"Detected {len(stale_branches)} branches that haven't been updated in over 6 months. "
                            f"Stale branches can indicate abandoned code that may contain security issues or technical debt."
                        ),
                        severity=Severity.LOW,
                        type=FindingType.OTHER,
                        location=Location(
                            path=Path(self.repo.working_dir),
                        ),
                        analyzer=self.name,
                        confidence=0.6,
                        tags=["git", "branch-analysis", "stale-branch"],
                        metadata={
                            "stale_branches": stale_branches,
                            "total_branches": len(list(branches)),
                        },
                        remediation=(
                            "Review stale branches and consider merging or deleting them to maintain "
                            "repository health. Ensure any security fixes from the main branch are "
                            "applied to active branches."
                        ),
                    )
                )
        except Exception as e:
            logger.error(f"Error analyzing branches: {str(e)}")
            findings.append(
                self._create_error_finding(
                    Path(self.repo.working_dir), f"Failed to analyze branches: {str(e)}"
                )
            )

        return findings

    def _create_error_finding(self, file_path: Path, error_message: str) -> Finding:
        """
        Create an error finding.

        Args:
            file_path: Path to the file or directory associated with the error.
            error_message: Error message.

        Returns:
            Error finding.
        """
        return Finding(
            id=str(uuid.uuid4()),
            title="Failed to analyze repository metadata",
            description=error_message,
            severity=Severity.LOW,
            type=FindingType.OTHER,
            location=Location(path=file_path),
            analyzer=self.name,
            confidence=1.0,
            tags=["analyzer-error"],
        )
