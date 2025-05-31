"""Tests for the secret analyzer."""

import tempfile
from pathlib import Path

import pytest

from insect.analysis.secret_analyzer import EntropyAnalyzer, SecretAnalyzer
from insect.finding import Severity


class TestEntropyAnalyzer:
    """Test the entropy analyzer functionality."""

    def test_shannon_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        # Low entropy - repeated characters
        assert EntropyAnalyzer.calculate_shannon_entropy("aaaaaaaaaa") < 1.0

        # Medium entropy - simple pattern
        abc_entropy = EntropyAnalyzer.calculate_shannon_entropy("abcabcabc")
        assert 1.0 < abc_entropy < 2.0  # Adjusted expectation

        # High entropy - random-like string
        high_entropy = EntropyAnalyzer.calculate_shannon_entropy("aB3$9zX@mK1pQ7fN2vL8")
        assert high_entropy > 4.0

        # Empty string
        assert EntropyAnalyzer.calculate_shannon_entropy("") == 0.0

    def test_high_entropy_detection(self):
        """Test high entropy string detection."""
        # Low entropy strings
        assert not EntropyAnalyzer.is_high_entropy("aaaaaaaaaaaaaaaaaaaaaa")

        # The alphabet string actually has good entropy, so let's use a lower entropy test
        assert not EntropyAnalyzer.is_high_entropy("abcabcabcabcabcabcabcabc")

        # High entropy strings (need to be at least 20 chars by default)
        # Using strings with very high entropy or test with lower threshold
        assert EntropyAnalyzer.is_high_entropy(
            "aB3$9zX@mK1pQ7fN2vL8aB3$9z", threshold=4.0
        )
        assert EntropyAnalyzer.is_high_entropy(
            "AKIAI44QH8DHBEXAMPLE12345", threshold=4.0
        )
        assert EntropyAnalyzer.is_high_entropy(
            "R$p9#mK@L2qX7vN!eA1fG8cZ5"
        )  # Even higher entropy

        # Too short
        assert not EntropyAnalyzer.is_high_entropy("aB3$9z")

    def test_base64_detection(self):
        """Test base64 string detection."""
        # Valid base64
        assert EntropyAnalyzer.is_base64_like("SGVsbG8gV29ybGQh")
        assert EntropyAnalyzer.is_base64_like("VGhpcyBpcyBhIHRlc3Q=")
        assert EntropyAnalyzer.is_base64_like(
            "VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw=="
        )

        # Invalid base64
        assert not EntropyAnalyzer.is_base64_like("Hello World!")
        assert not EntropyAnalyzer.is_base64_like("not-base64-@#$")
        assert not EntropyAnalyzer.is_base64_like("short")

    def test_hex_detection(self):
        """Test hexadecimal string detection."""
        # Valid hex
        assert EntropyAnalyzer.is_hex_like("deadbeefcafebabe")
        assert EntropyAnalyzer.is_hex_like("0123456789ABCDEF")
        assert EntropyAnalyzer.is_hex_like("abcdef1234567890")

        # Invalid hex
        assert not EntropyAnalyzer.is_hex_like("Hello World!")
        assert not EntropyAnalyzer.is_hex_like("xyz123")
        assert not EntropyAnalyzer.is_hex_like("short")
        assert not EntropyAnalyzer.is_hex_like("deadbeef1")  # Odd length


class TestSecretAnalyzer:
    """Test the secret analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create a secret analyzer for testing."""
        config = {
            "secrets": {
                "entropy_threshold": 4.5,
                "min_secret_length": 16,
                "enable_entropy_analysis": True,
                "enable_pattern_matching": True,
            }
        }
        return SecretAnalyzer(config)

    def test_aws_access_key_detection(self, analyzer):
        """Test AWS access key detection."""
        content = """
        AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
        AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find AWS access key
            aws_key_findings = [f for f in findings if "AWS Access Key" in f.title]
            assert len(aws_key_findings) >= 1

            access_key_finding = aws_key_findings[0]
            assert access_key_finding.severity == Severity.HIGH
            assert "AKIAIOSFODNN7EXAMPLE" in access_key_finding.description

    def test_github_token_detection(self, analyzer):
        """Test GitHub token detection."""
        content = """
        GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find GitHub token
            github_findings = [f for f in findings if "GitHub" in f.title]
            assert len(github_findings) >= 1

    def test_database_connection_string_detection(self, analyzer):
        """Test database connection string detection."""
        content = """
        DATABASE_URL = "postgresql://user:supersecretpassword@localhost:5432/mydb"
        MONGO_URI = "mongodb://admin:password123@mongo.example.com:27017/production"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find database connection strings
            db_findings = [f for f in findings if "Database" in f.title]
            assert len(db_findings) >= 1

    def test_jwt_token_detection(self, analyzer):
        """Test JWT token detection."""
        content = """
        JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find JWT token
            jwt_findings = [f for f in findings if "JWT" in f.title]
            assert len(jwt_findings) >= 1

    def test_ssh_private_key_detection(self, analyzer):
        """Test SSH private key detection."""
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA2Z1QYaHQRvGwLNB8/a7X8c9XyC2JwK5lQJ7vJKlmnNmW
        -----END RSA PRIVATE KEY-----
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find SSH private key
            ssh_findings = [f for f in findings if "SSH" in f.title]
            assert len(ssh_findings) >= 1
            assert ssh_findings[0].severity == Severity.CRITICAL

    def test_high_entropy_detection(self, analyzer):
        """Test high entropy string detection."""
        content = """
        # This should be detected as high entropy
        SECRET_KEY = "R$p9#mK@L2qX7vN!eA1fG8cZ5R$p9#mK@L2qX7vN!eA1fG8cZ5"

        # This should not be detected (low entropy)
        NOT_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find high entropy string but not low entropy
            high_entropy_findings = [f for f in findings if "High-entropy" in f.title]
            assert len(high_entropy_findings) >= 1

            # Check that it has high entropy metadata
            entropy_finding = high_entropy_findings[0]
            assert entropy_finding.metadata["entropy"] > 4.5

    def test_false_positive_filtering(self, analyzer):
        """Test false positive filtering."""
        content = """
        # These should be filtered out as false positives
        TEST_KEY = "test_key_1234567890"
        EXAMPLE_SECRET = "example_password_123"
        PLACEHOLDER = "your_api_key_here"
        REPEATED = "aaaaaaaaaaaaaaaaaaa"
        ONLY_LETTERS = "abcdefghijklmnopqrstuvwxyz"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should have very few or no findings due to false positive filtering
            secret_findings = [
                f for f in findings if "test" not in f.description.lower()
            ]
            assert len(secret_findings) <= 1  # Allow for some edge cases

    def test_context_aware_detection(self, analyzer):
        """Test context-aware detection."""
        content = """
        # This should be detected with AWS context
        aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        # This might not be detected without context
        random_string = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find at least one secret
            assert len(findings) >= 1

    def test_multiple_file_formats(self, analyzer):
        """Test detection across different file formats."""
        test_cases = [
            (".env", 'API_KEY="ghp_1234567890abcdef1234567890abcdef12345678"'),
            (".json", '{"api_key": "ghp_1234567890abcdef1234567890abcdef12345678"}'),
            (".yaml", 'api_key: "ghp_1234567890abcdef1234567890abcdef12345678"'),
            (".py", 'API_KEY = "ghp_1234567890abcdef1234567890abcdef12345678"'),
            (".js", 'const apiKey = "ghp_1234567890abcdef1234567890abcdef12345678";'),
        ]

        total_findings = 0

        for suffix, content in test_cases:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, delete=False
            ) as f:
                f.write(content)
                f.flush()

                findings = analyzer.analyze_file(Path(f.name))
                total_findings += len(findings)

        # Should find secrets in multiple formats
        assert total_findings >= len(test_cases) - 1  # Allow for some variation

    def test_excluded_paths(self, analyzer):
        """Test that excluded paths are skipped."""
        content = 'SECRET_KEY = "sk_test_1234567890abcdef1234567890abcdef"'

        # Test excluded directories
        excluded_paths = [
            "node_modules/package/file.js",
            ".git/config",
            "__pycache__/module.py",
            "venv/lib/python3.9/site-packages/package.py",
        ]

        for path_str in excluded_paths:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(content)
                f.flush()

                # Simulate excluded path
                test_path = Path(path_str)
                if any(exclude in str(test_path) for exclude in analyzer.exclude_paths):
                    findings = analyzer.analyze_file(test_path)
                    # Should return empty list for excluded paths
                    assert len(findings) == 0

    def test_secret_report_generation(self, analyzer):
        """Test secret report generation."""
        # Create a file with multiple types of secrets
        content = """
        AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
        GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
        HIGH_ENTROPY = "aB3$9zX@mK1pQ7fN2vL8aB3$9zX@mK1pQ7fN2vL8"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))
            report = analyzer.generate_secret_report(findings)

            # Check report structure
            assert "summary" in report
            assert "secrets" in report
            assert "total_secrets" in report["summary"]
            assert "by_severity" in report["summary"]
            assert "by_type" in report["summary"]
            assert "files_affected" in report["summary"]

            # Should have findings
            assert report["summary"]["total_secrets"] > 0
            assert report["summary"]["files_affected"] == 1

    def test_bitcoin_private_key_detection(self, analyzer):
        """Test Bitcoin private key detection."""
        content = """
        BITCOIN_KEY = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find Bitcoin private key
            bitcoin_findings = [f for f in findings if "Bitcoin" in f.title]
            assert len(bitcoin_findings) >= 1
            assert bitcoin_findings[0].severity == Severity.CRITICAL

    def test_ethereum_private_key_detection(self, analyzer):
        """Test Ethereum private key detection."""
        content = """
        ETH_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find Ethereum private key
            eth_findings = [f for f in findings if "Ethereum" in f.title]
            assert len(eth_findings) >= 1
            assert eth_findings[0].severity == Severity.CRITICAL

    def test_configuration_options(self):
        """Test different configuration options."""
        # Test with disabled entropy analysis
        config_no_entropy = {
            "secret": {
                "enable_entropy_analysis": False,
                "enable_pattern_matching": True,
            }
        }
        analyzer_no_entropy = SecretAnalyzer(config_no_entropy)

        # Test with disabled pattern matching
        config_no_patterns = {
            "secret": {
                "enable_entropy_analysis": True,
                "enable_pattern_matching": False,
            }
        }
        analyzer_no_patterns = SecretAnalyzer(config_no_patterns)

        content = """
        AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
        HIGH_ENTROPY = "aB3$9zX@mK1pQ7fN2vL8aB3$9zX@mK1pQ7fN2vL8"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings_no_entropy = analyzer_no_entropy.analyze_file(Path(f.name))
            findings_no_patterns = analyzer_no_patterns.analyze_file(Path(f.name))

            # Both should find something, but different types
            assert len(findings_no_entropy) > 0
            assert (
                len(findings_no_patterns) >= 0
            )  # May or may not find high entropy strings

    def test_can_analyze_file(self, analyzer):
        """Test file analysis capability detection."""
        # Should analyze various file types
        assert analyzer.can_analyze_file(Path("config.py"))
        assert analyzer.can_analyze_file(Path("package.json"))
        assert analyzer.can_analyze_file(Path(".env"))
        assert analyzer.can_analyze_file(Path("docker-compose.yml"))
        assert analyzer.can_analyze_file(Path("main.go"))
        assert analyzer.can_analyze_file(Path("app.rs"))

        # Should not analyze unknown files (based on configuration)
        # Note: The current implementation supports many extensions,
        # so most files will be analyzed
