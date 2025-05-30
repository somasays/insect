"""Unit tests for the configuration file analyzer."""

from typing import Dict

import pytest

from insect.analysis.config.config_analyzer import ConfigAnalyzer


@pytest.fixture
def config() -> Dict:
    """Create a basic configuration for the analyzer."""
    return {"analyzers": {"config_analyzer": True}}


@pytest.fixture
def temp_dockerfile(tmp_path):
    """Create a temporary Dockerfile with security issues."""
    dockerfile_content = """FROM python
RUN apt-get update && apt-get install -y nmap curl
USER root
EXPOSE 22
ENV DB_PASSWORD="supersecret123"
RUN curl https://example.com/setup.sh | bash
CMD ["python", "app.py"]
"""
    dockerfile_path = tmp_path / "Dockerfile"
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    return dockerfile_path


@pytest.fixture
def temp_package_json(tmp_path):
    """Create a temporary package.json with security issues."""
    package_json_content = """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15",
    "express": "^4.17.1",
    "moment": "*"
  },
  "devDependencies": {
    "nodemon": "latest"
  },
  "scripts": {
    "start": "node app.js",
    "test": "echo 'No tests yet'",
    "build": "curl https://example.com/build.sh | bash"
  },
  "api_key": "sk_test_12345abcdefABCDEF"
}
"""
    package_json_path = tmp_path / "package.json"
    with open(package_json_path, "w") as f:
        f.write(package_json_content)
    return package_json_path


@pytest.fixture
def temp_requirements_txt(tmp_path):
    """Create a temporary requirements.txt with security issues."""
    requirements_content = """# Web framework
django==3.1.0
# HTTP
requests>=2.20.0
# YAML parser
pyyaml==5.3.0
git+https://github.com/example/insecure-package.git
"""
    requirements_path = tmp_path / "requirements.txt"
    with open(requirements_path, "w") as f:
        f.write(requirements_content)
    return requirements_path


@pytest.fixture
def temp_kubernetes_yaml(tmp_path):
    """Create a temporary Kubernetes YAML with security issues."""
    k8s_content = """apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  hostNetwork: true
  securityContext:
    runAsUser: 0
    privileged: true
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-path
      mountPath: /host
  volumes:
  - name: host-path
    hostPath:
      path: /
"""
    k8s_path = tmp_path / "pod.yaml"
    with open(k8s_path, "w") as f:
        f.write(k8s_content)
    return k8s_path


@pytest.fixture
def temp_github_actions_yaml(tmp_path):
    """Create a temporary GitHub Actions workflow with security issues."""
    actions_content = """name: Test workflow

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write
    steps:
      - uses: actions/checkout@v3
      - name: Setup Node
        uses: actions/setup-node@v2
      - name: Build and test
        run: |
          npm ci
          npm test
"""
    actions_path = tmp_path / "workflow.yml"
    with open(actions_path, "w") as f:
        f.write(actions_content)
    return actions_path


@pytest.fixture
def temp_pyproject_toml(tmp_path):
    """Create a temporary pyproject.toml with security issues."""
    pyproject_content = """[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "test-project"
version = "0.1.0"
description = "Test project"
dependencies = [
    "django==3.1.0",
    "pyyaml>=5.3.0",
    "cryptography>=3.2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=6.0.0",
    "black>=20.8b1",
]

[tool.black]
line-length = 88
target-version = ["py38"]

[tool.config]
api_secret = "verysecretstring123"
"""
    pyproject_path = tmp_path / "pyproject.toml"
    with open(pyproject_path, "w") as f:
        f.write(pyproject_content)
    return pyproject_path


def test_dockerfile_analysis(config, temp_dockerfile):
    """Test analysis of Dockerfiles for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_dockerfile)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues
    finding_ids = [finding.id.split("-")[0] for finding in findings]

    # Check for Use of 'latest' tag
    assert "DOCKER001" in finding_ids

    # Check for Container running as root
    assert "DOCKER002" in finding_ids

    # Check for Hard-coded credentials
    assert "DOCKER006" in finding_ids

    # Check for Curl piped to shell
    assert "DOCKER005" in finding_ids

    # Check for exposed sensitive port
    assert "DOCKER004" in finding_ids

    # Check for suspicious software installation
    assert "DOCKER007" in finding_ids


def test_package_json_analysis(config, temp_package_json):
    """Test analysis of package.json files for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_package_json)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues
    finding_ids = [finding.id.split("-")[0] for finding in findings]

    # Check for unscoped dependency version
    assert any(id.startswith("NPM002") for id in finding_ids)

    # Check for suspicious script command
    assert any(id.startswith("NPM003") for id in finding_ids)

    # Check for hard-coded credentials
    assert any(id.startswith("NPM005") for id in finding_ids)

    # Check for identified vulnerable package
    assert any(id.startswith("NPM001") for id in finding_ids)

    # Verify vulnerable lodash is detected (either by NPM001 or other id)
    vulnerable_lodash = False
    for finding in findings:
        if (
            "lodash" in finding.description.lower()
            and "vuln" in finding.description.lower()
        ):
            vulnerable_lodash = True
            break
    assert vulnerable_lodash


def test_requirements_txt_analysis(config, temp_requirements_txt):
    """Test analysis of requirements.txt files for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_requirements_txt)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues
    finding_ids = [finding.id.split("-")[0] for finding in findings]

    # Check for unscoped dependency version
    assert any(id.startswith("PIP001") for id in finding_ids)

    # Check for direct URL installation
    assert any(id.startswith("PIP004") for id in finding_ids)

    # Verify vulnerable django is detected
    vulnerable_django = False
    for finding in findings:
        if (
            "django" in finding.description.lower()
            and "vuln" in finding.description.lower()
        ):
            vulnerable_django = True
            break
    assert vulnerable_django


def test_kubernetes_yaml_analysis(config, temp_kubernetes_yaml):
    """Test analysis of Kubernetes YAML files for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_kubernetes_yaml)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues
    [finding.id.split("-")[0] for finding in findings]
    finding_tags = []
    for finding in findings:
        finding_tags.extend(finding.tags)

    # Check for privileged container
    assert any("privileged" in finding.description.lower() for finding in findings)

    # Check for hostNetwork
    assert any("hostnetwork" in finding.description.lower() for finding in findings)

    # Check for runAsUser: 0 or root
    assert any("root" in finding.description.lower() for finding in findings)


def test_github_actions_yaml_analysis(config, temp_github_actions_yaml):
    """Test analysis of GitHub Actions workflow files for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_github_actions_yaml)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues

    # Check for insecure permissions in GitHub Actions
    assert any(
        "permission" in finding.title.lower()
        or "permission" in finding.description.lower()
        for finding in findings
    )

    # Check for permissions: write
    assert any("permissions" in finding.description.lower() for finding in findings)


def test_pyproject_toml_analysis(config, temp_pyproject_toml):
    """Test analysis of pyproject.toml files for security issues."""
    analyzer = ConfigAnalyzer(config)
    findings = analyzer.analyze_file(temp_pyproject_toml)

    # Verify we have findings
    assert len(findings) > 0

    # Check detection of specific issues

    # Check for hard-coded credentials
    assert any("credential" in finding.description.lower() for finding in findings)

    # Verify vulnerable django is detected
    vulnerable_django = False
    for finding in findings:
        if (
            "django" in finding.description.lower()
            and "vuln" in finding.description.lower()
        ):
            vulnerable_django = True
            break
    assert vulnerable_django
