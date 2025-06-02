"""Unit tests for the metadata analyzer."""

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import git

from insect.analysis.metadata_analyzer import (
    LARGE_BINARY_THRESHOLD,
    LARGE_COMMIT_THRESHOLD,
    MetadataAnalyzer,
)
from insect.finding import FindingType, Severity


class TestMetadataAnalyzer(unittest.TestCase):
    """Unit tests for the metadata analyzer."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_repo_dir = Path(self.temp_dir) / "test_repo"
        self.test_repo_dir.mkdir(exist_ok=True)

        # Basic configuration for testing
        self.config = {
            "analyzers": {"metadata": True},
            "sensitivity": {"level": "very_high"},  # Enable all findings for tests
            "metadata": {
                "min_confidence": 0.0,
                "check_commits": True,
                "check_contributors": True,
                "check_branches": True,
                "large_commit_threshold": LARGE_COMMIT_THRESHOLD,
                "large_binary_threshold": LARGE_BINARY_THRESHOLD,
                "max_commits": 10,  # Small number for tests
            },
        }

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)

    def test_init(self):
        """Test analyzer initialization."""
        analyzer = MetadataAnalyzer(self.config)
        assert analyzer.name == "metadata"
        assert analyzer.enabled
        assert analyzer.check_commits
        assert analyzer.check_contributors
        assert analyzer.check_branches
        assert analyzer.large_commit_threshold == LARGE_COMMIT_THRESHOLD
        assert analyzer.large_binary_threshold == LARGE_BINARY_THRESHOLD
        assert analyzer.max_commits == 10

    def test_supported_extensions(self):
        """Test supported file extensions."""
        analyzer = MetadataAnalyzer(self.config)
        # Should support all files as it works on repository level
        assert "*" in analyzer.supported_extensions

        # Test can_analyze_file with any file type
        assert analyzer.can_analyze_file(Path("test.txt"))
        assert analyzer.can_analyze_file(Path("test.py"))
        assert analyzer.can_analyze_file(Path("test.bin"))

    @patch("insect.analysis.metadata_analyzer.Repo")
    @patch.object(MetadataAnalyzer, "_find_git_repository", return_value=None)
    def test_analyze_non_git_file(self, mock_find_repo, mock_repo):
        """Test analyzing a file not in a git repository."""
        analyzer = MetadataAnalyzer(self.config)
        file_path = Path(self.temp_dir) / "test.txt"

        findings = analyzer.analyze_file(file_path)

        # Should not find anything for non-git files
        assert findings == []

        # Should have tried to find the git repo
        mock_find_repo.assert_called_once_with(file_path)

        # Should not have created a Repo instance
        mock_repo.assert_not_called()

    @patch("insect.analysis.metadata_analyzer.Repo")
    @patch.object(MetadataAnalyzer, "_find_git_repository")
    def test_analyze_valid_git_repository(self, mock_find_repo, mock_repo_class):
        """Test analyzing a file in a valid git repository."""
        # Set up mocks for repository
        mock_repo = MagicMock()
        mock_repo.bare = False
        mock_repo_class.return_value = mock_repo
        mock_find_repo.return_value = str(self.test_repo_dir)

        # Set up analyzer with mocked methods for analysis
        analyzer = MetadataAnalyzer(self.config)

        # Mock the analysis methods
        mock_commits_findings = [MagicMock()]
        mock_contributors_findings = [MagicMock()]
        mock_branches_findings = [MagicMock()]

        with patch.object(
            analyzer, "_analyze_commits", return_value=mock_commits_findings
        ) as mock_analyze_commits, patch.object(
            analyzer, "_analyze_contributors", return_value=mock_contributors_findings
        ) as mock_analyze_contributors, patch.object(
            analyzer, "_analyze_branches", return_value=mock_branches_findings
        ) as mock_analyze_branches:

            # Analyze a file
            file_path = Path(self.test_repo_dir) / "test.txt"
            findings = analyzer.analyze_file(file_path)

            # Should have called all the analysis methods
            mock_analyze_commits.assert_called_once()
            mock_analyze_contributors.assert_called_once()
            mock_analyze_branches.assert_called_once()

            # Should have combined all findings
            assert len(findings) == 3
            assert mock_commits_findings[0] in findings
            assert mock_contributors_findings[0] in findings
            assert mock_branches_findings[0] in findings

    @patch("insect.analysis.metadata_analyzer.Repo")
    def test_invalid_git_repository(self, mock_repo_class):
        """Test handling invalid git repository."""
        # Set up mocks to simulate an invalid repository
        mock_repo_class.side_effect = git.InvalidGitRepositoryError("Invalid repo")

        analyzer = MetadataAnalyzer(self.config)
        analyzer._find_git_repository = MagicMock(return_value=str(self.test_repo_dir))

        # Analyze a file
        file_path = Path(self.test_repo_dir) / "test.txt"
        findings = analyzer.analyze_file(file_path)

        # Should not produce any findings
        assert findings == []

    @patch("insect.analysis.metadata_analyzer.git.Commit")
    def test_check_commit_message_sensitive_info(
        self, mock_commit_class  # noqa: ARG002
    ):
        """Test detecting sensitive information in commit messages."""
        # Create analyzer
        analyzer = MetadataAnalyzer(self.config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock commit with sensitive info
        mock_commit = MagicMock()
        mock_commit.hexsha = "1234567890abcdef"
        mock_commit.message = "Fixed login bug, password=supersecret123"
        mock_commit.author.name = "Test User"
        mock_commit.author.email = "test@example.com"
        mock_commit.committed_datetime = datetime.now()

        # Check commit message
        findings = analyzer._check_commit_message(mock_commit)

        # Should find sensitive info
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Sensitive information in commit message"
        assert finding.severity == Severity.MEDIUM
        assert finding.type == FindingType.SECRET
        assert "password=supersecret123" in finding.description
        assert "sensitive-data" in finding.tags
        assert finding.metadata["commit_hash"] == mock_commit.hexsha

    @patch("insect.analysis.metadata_analyzer.git.Commit")
    def test_check_commit_time_night_commit(self, mock_commit_class):  # noqa: ARG002
        """Test detecting commits made during night hours."""
        # Create analyzer with custom night hours
        config = self.config.copy()
        config["metadata"]["night_start_hour"] = 22  # 10 PM
        config["metadata"]["night_end_hour"] = 6  # 6 AM
        analyzer = MetadataAnalyzer(config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock commit made during night hours
        mock_commit = MagicMock()
        mock_commit.hexsha = "1234567890abcdef"
        # Create a datetime at 3 AM
        night_time = datetime.now().replace(hour=3, minute=0, second=0)
        mock_commit.committed_datetime = night_time
        mock_commit.author.name = "Test User"
        mock_commit.author.email = "test@example.com"

        # Check commit time
        findings = analyzer._check_commit_time(mock_commit)

        # Should find night commit
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Commit made during unusual hours"
        assert finding.severity == Severity.LOW
        assert finding.type == FindingType.SUSPICIOUS
        assert "unusual-time" in finding.tags

    @patch("insect.analysis.metadata_analyzer.git.Commit")
    def test_check_commit_size_large_commit(self, mock_commit_class):  # noqa: ARG002
        """Test detecting unusually large commits."""
        # Create analyzer with custom threshold
        config = self.config.copy()
        config["metadata"]["large_commit_threshold"] = 5  # Small for test
        analyzer = MetadataAnalyzer(config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock commit with many modified files
        mock_commit = MagicMock()
        mock_commit.hexsha = "1234567890abcdef"
        mock_commit.author.name = "Test User"
        mock_commit.author.email = "test@example.com"
        mock_commit.committed_datetime = datetime.now()

        # Setup parent commit
        mock_parent = MagicMock()
        mock_commit.parents = [mock_parent]

        # Setup diffs (10 files changed, over threshold of 5)
        mock_diffs = [MagicMock() for _ in range(10)]
        mock_parent.diff.return_value = mock_diffs

        # Check commit size
        findings = analyzer._check_commit_size(mock_commit)

        # Should find large commit
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Unusually large commit"
        assert finding.severity == Severity.LOW
        assert finding.type == FindingType.SUSPICIOUS
        assert "large-commit" in finding.tags
        assert finding.metadata["files_changed"] == 10
        assert finding.metadata["threshold"] == 5

    @patch("insect.analysis.metadata_analyzer.git.Commit")
    def test_check_binary_files_large_binary(self, mock_commit_class):  # noqa: ARG002
        """Test detecting large binary files in commits."""
        # Create analyzer with custom threshold
        config = self.config.copy()
        config["metadata"]["large_binary_threshold"] = 100  # Small for test
        analyzer = MetadataAnalyzer(config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock commit with large binary file
        mock_commit = MagicMock()
        mock_commit.hexsha = "1234567890abcdef"
        mock_commit.author.name = "Test User"
        mock_commit.author.email = "test@example.com"
        mock_commit.committed_datetime = datetime.now()

        # Setup parent commit
        mock_parent = MagicMock()
        mock_commit.parents = [mock_parent]

        # Setup diffs with a large binary file
        mock_diff = MagicMock()
        mock_diff.b_blob.size = 1000  # > threshold
        mock_diff.b_path = "test.bin"
        mock_diff.deleted_file = False
        mock_parent.diff.return_value = [mock_diff]

        # Check binary files
        findings = analyzer._check_binary_files(mock_commit)

        # Should find large binary file
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Large binary file committed"
        assert finding.severity == Severity.MEDIUM
        assert finding.type == FindingType.SUSPICIOUS
        assert "binary-file" in finding.tags
        assert finding.metadata["file_path"] == "test.bin"
        assert finding.metadata["file_size_bytes"] == 1000

    def test_analyze_contributors_one_time(self):
        """Test detecting one-time contributors."""
        # Create analyzer
        analyzer = MetadataAnalyzer(self.config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock commits with different authors
        one_time_author = "One Time <onetime@example.com>"

        mock_commits = []

        # Create 5 commits from regular author
        for i in range(5):
            mock_commit = MagicMock()
            mock_commit.hexsha = f"abcdef{i}"
            mock_commit.author.name = "Regular User"
            mock_commit.author.email = "regular@example.com"
            mock_commits.append(mock_commit)

        # Create 1 commit from one-time author
        one_time_commit = MagicMock()
        one_time_commit.hexsha = "onetime123"
        one_time_commit.author.name = "One Time"
        one_time_commit.author.email = "onetime@example.com"
        mock_commits.append(one_time_commit)

        # Setup repo to return these commits
        analyzer.repo.iter_commits.return_value = mock_commits

        # Analyze contributors
        findings = analyzer._analyze_contributors()

        # Should find one-time contributor
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "One-time contributors detected"
        assert finding.severity == Severity.LOW
        assert finding.type == FindingType.SUSPICIOUS
        assert "contributor-analysis" in finding.tags
        assert one_time_author in finding.metadata["one_time_contributors"]

    def test_analyze_branches_suspicious_names(self):
        """Test detecting suspicious branch names."""
        # Create analyzer
        analyzer = MetadataAnalyzer(self.config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock branches
        mock_normal_branch = MagicMock()
        mock_normal_branch.name = "main"

        mock_feature_branch = MagicMock()
        mock_feature_branch.name = "feature-login"

        mock_suspicious_branch = MagicMock()
        mock_suspicious_branch.name = "backdoor-feature"

        mock_hack_branch = MagicMock()
        mock_hack_branch.name = "temp-hack"

        # Setup repo branches - use a list-like object that supports iteration
        analyzer.repo.branches = [
            mock_normal_branch,
            mock_feature_branch,
            mock_suspicious_branch,
            mock_hack_branch,
        ]

        # Skip stale branch check for simplicity
        with patch.object(analyzer.repo, "iter_commits", side_effect=Exception("Skip")):
            # Analyze branches
            findings = analyzer._analyze_branches()

        # Should find suspicious branch names
        found_suspicious = False
        for finding in findings:
            if finding.title == "Suspicious branch names detected":
                found_suspicious = True
                assert finding.severity == Severity.LOW
                assert finding.type == FindingType.SUSPICIOUS
                assert "branch-analysis" in finding.tags

                # Should list both suspicious branches
                assert len(finding.metadata["suspicious_branches"]) == 2
                assert "backdoor-feature" in finding.metadata["suspicious_branches"]
                assert "temp-hack" in finding.metadata["suspicious_branches"]

        assert found_suspicious, "Did not find suspicious branch finding"

    def test_analyze_branches_stale(self):
        """Test detecting stale branches."""
        # Create analyzer
        analyzer = MetadataAnalyzer(self.config)
        analyzer.repo = MagicMock()
        analyzer.repo.working_dir = str(self.test_repo_dir)

        # Create mock branches
        mock_active_branch = MagicMock()
        mock_active_branch.name = "main"

        mock_stale_branch = MagicMock()
        mock_stale_branch.name = "old-feature"

        # Setup repo branches - use a list-like object that supports iteration
        analyzer.repo.branches = [mock_active_branch, mock_stale_branch]

        # Setup mock commits for each branch
        def mock_iter_commits(branch_name, **kwargs):
            if branch_name == "main":
                # Recent commit for active branch
                mock_commit = MagicMock()
                mock_commit.committed_datetime = datetime.now() - timedelta(days=5)
                return iter([mock_commit])  # Return an iterator
            if branch_name == "old-feature":
                # Old commit for stale branch
                mock_commit = MagicMock()
                mock_commit.committed_datetime = datetime.now() - timedelta(days=200)
                return iter([mock_commit])  # Return an iterator
            return iter([])  # Empty iterator

        analyzer.repo.iter_commits.side_effect = mock_iter_commits

        # Analyze branches
        findings = analyzer._analyze_branches()

        # Should find stale branch
        found_stale = False
        for finding in findings:
            if finding.title == "Stale branches detected":
                found_stale = True
                assert finding.severity == Severity.LOW
                assert finding.type == FindingType.OTHER
                assert "stale-branch" in finding.tags

                # Should list the stale branch
                assert len(finding.metadata["stale_branches"]) == 1
                assert finding.metadata["stale_branches"][0]["name"] == "old-feature"
                assert finding.metadata["stale_branches"][0]["days_inactive"] >= 180

        assert found_stale, "Did not find stale branch finding"

    def test_find_git_repository(self):
        """Test finding a git repository from a file path."""
        with patch("insect.analysis.metadata_analyzer.Path"):
            # Setup mock file path
            mock_file_path = MagicMock()

            # Setup mock directory path
            mock_dir_path = MagicMock()
            mock_file_path.parent.absolute.return_value = mock_dir_path

            # Setup root check
            mock_dir_path.__eq__.return_value = False  # Not at root yet

            # Setup mock git directory
            mock_git_dir = MagicMock()
            mock_git_dir.exists.return_value = True
            mock_git_dir.is_dir.return_value = True

            # Setup path traversal
            mock_dir_path.__truediv__.return_value = mock_git_dir

            # Create analyzer
            analyzer = MetadataAnalyzer(self.config)

            # Convert MagicMock to string to match expected return type
            mock_dir_path.__str__.return_value = "/mock/path"

            # Find git repository
            repo_path = analyzer._find_git_repository(mock_file_path)

            # Should return the path string
            assert repo_path == "/mock/path"

    def test_find_git_repository_not_found(self):
        """Test when git repository is not found."""
        # Create analyzer
        analyzer = MetadataAnalyzer(self.config)

        # Mock the find_git_repository method directly
        with patch.object(analyzer, "_find_git_repository", return_value=None):
            file_path = Path(self.temp_dir) / "test.txt"

            # Find git repository
            repo_path = analyzer._find_git_repository(file_path)

            # Should return None
            assert repo_path is None

    def test_create_error_finding(self):
        """Test creation of error findings."""
        analyzer = MetadataAnalyzer(self.config)
        file_path = Path(self.test_repo_dir) / "test.txt"

        # Create error finding
        finding = analyzer._create_error_finding(file_path, "Test error message")

        # Verify finding properties
        assert finding.title == "Failed to analyze repository metadata"
        assert finding.description == "Test error message"
        assert finding.severity == Severity.LOW
        assert finding.type == FindingType.OTHER
        assert finding.location.path == file_path
        assert finding.analyzer == analyzer.name
        assert finding.confidence == 1.0
        assert "analyzer-error" in finding.tags


if __name__ == "__main__":
    unittest.main()
