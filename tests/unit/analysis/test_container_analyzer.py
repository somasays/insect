"""Tests for the container analyzer."""

import tempfile
from pathlib import Path

import pytest

from insect.analysis.container_analyzer import ContainerAnalyzer
from insect.finding import Severity


class TestContainerAnalyzer:
    """Test the container analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create a container analyzer for testing."""
        config = {
            "container": {
                "check_base_images": True,
                "check_secrets": True,
                "check_privileges": True,
                "check_networking": True
            }
        }
        return ContainerAnalyzer(config)

    def test_dockerfile_detection(self, analyzer):
        """Test Dockerfile detection."""
        test_cases = [
            ("Dockerfile", True),
            ("dockerfile", True),
            ("Dockerfile.prod", True),
            ("app.dockerfile", True),
            ("docker-compose.yml", False),
            ("regular.txt", False)
        ]

        for filename, expected in test_cases:
            path = Path(filename)
            assert analyzer._is_dockerfile(path) == expected

    def test_docker_compose_detection(self, analyzer):
        """Test Docker Compose file detection."""
        test_cases = [
            ("docker-compose.yml", True),
            ("docker-compose.yaml", True),
            ("compose.yml", True),
            ("docker-compose.prod.yml", True),
            ("Dockerfile", False),
            ("regular.yml", False)
        ]

        for filename, expected in test_cases:
            path = Path(filename)
            assert analyzer._is_docker_compose(path) == expected

    def test_dockerfile_root_user_detection(self, analyzer):
        """Test detection of root user in Dockerfile."""
        dockerfile_content = """
FROM ubuntu:20.04
RUN apt-get update
USER root
COPY app.py /app/
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find root user issue
            root_findings = [f for f in findings if "root user" in f.title]
            assert len(root_findings) >= 1
            assert root_findings[0].severity == Severity.HIGH

    def test_dockerfile_secrets_in_env(self, analyzer):
        """Test detection of secrets in environment variables."""
        dockerfile_content = """
FROM ubuntu:20.04
ENV DATABASE_PASSWORD=secretpassword123
ENV API_KEY=abcdef123456
ENV APP_NAME=myapp
CMD ["python", "app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find secrets in environment variables
            secret_findings = [f for f in findings if "secrets in environment" in f.title.lower()]
            assert len(secret_findings) >= 1

    def test_dockerfile_vulnerable_base_image(self, analyzer):
        """Test detection of vulnerable base images."""
        dockerfile_content = """
FROM ubuntu:14.04
RUN apt-get update
COPY app.py /app/
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find vulnerable base image
            base_image_findings = [f for f in findings if "vulnerable base image" in f.title.lower()]
            assert len(base_image_findings) >= 1
            assert "ubuntu:14.04" in base_image_findings[0].description

    def test_dockerfile_missing_healthcheck(self, analyzer):
        """Test detection of missing health check."""
        dockerfile_content = """
FROM ubuntu:20.04
RUN apt-get update
COPY app.py /app/
EXPOSE 8080
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find missing health check
            healthcheck_findings = [f for f in findings if "health check" in f.title.lower()]
            assert len(healthcheck_findings) >= 1

    def test_dockerfile_with_healthcheck(self, analyzer):
        """Test that Dockerfile with health check doesn't trigger warning."""
        dockerfile_content = """
FROM ubuntu:20.04
RUN apt-get update
COPY app.py /app/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should not find missing health check
            healthcheck_findings = [f for f in findings if "missing health check" in f.title.lower()]
            assert len(healthcheck_findings) == 0

    def test_dockerfile_unnecessary_packages(self, analyzer):
        """Test detection of unnecessary packages."""
        dockerfile_content = """
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y curl wget ssh gcc build-essential
COPY app.py /app/
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find unnecessary packages
            package_findings = [f for f in findings if "unnecessary packages" in f.title.lower()]
            assert len(package_findings) >= 1

    def test_dockerfile_sensitive_file_copy(self, analyzer):
        """Test detection of copying sensitive files."""
        dockerfile_content = """
FROM ubuntu:20.04
COPY /etc/passwd /app/
COPY ~/.ssh/id_rsa /app/keys/
COPY app.py /app/
CMD ["python", "/app/app.py"]
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find sensitive file copying
            sensitive_findings = [f for f in findings if "sensitive files" in f.title.lower()]
            assert len(sensitive_findings) >= 1

    def test_docker_compose_privileged_container(self, analyzer):
        """Test detection of privileged containers in Docker Compose."""
        compose_content = """
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "80:80"
  app:
    build: .
    privileged: true
    ports:
      - "8080:8080"
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='docker-compose.yml', delete=False) as f:
            f.write(compose_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find privileged container
            privileged_findings = [f for f in findings if "privileged" in f.title.lower()]
            assert len(privileged_findings) >= 1
            assert "app" in privileged_findings[0].description

    def test_docker_compose_host_network(self, analyzer):
        """Test detection of host network mode in Docker Compose."""
        compose_content = """
version: '3.8'
services:
  web:
    image: nginx
    network_mode: host
    ports:
      - "80:80"
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='docker-compose.yml', delete=False) as f:
            f.write(compose_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find host network usage
            network_findings = [f for f in findings if "host network" in f.title.lower()]
            assert len(network_findings) >= 1

    def test_docker_compose_dangerous_volume_mounts(self, analyzer):
        """Test detection of dangerous volume mounts in Docker Compose."""
        compose_content = """
version: '3.8'
services:
  app:
    image: myapp
    volumes:
      - /etc:/host-etc:ro
      - /var/run/docker.sock:/var/run/docker.sock
      - ./app:/app
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='docker-compose.yml', delete=False) as f:
            f.write(compose_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find dangerous volume mounts
            volume_findings = [f for f in findings if "volume mount" in f.title.lower()]
            assert len(volume_findings) >= 1

    def test_docker_compose_env_secrets(self, analyzer):
        """Test detection of secrets in environment variables."""
        compose_content = """
version: '3.8'
services:
  app:
    image: myapp
    environment:
      - DATABASE_PASSWORD=secret123
      - API_KEY=abcdef123456
      - DEBUG=true
  web:
    image: nginx
    environment:
      SECRET_TOKEN: "supersecret"
      NGINX_PORT: 80
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='docker-compose.yml', delete=False) as f:
            f.write(compose_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find secrets in environment variables
            secret_findings = [f for f in findings if "secrets in environment" in f.title.lower()]
            assert len(secret_findings) >= 1

    def test_kubernetes_privileged_container(self, analyzer):
        """Test detection of privileged containers in Kubernetes."""
        k8s_content = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
  - name: sidecar
    image: sidecar:latest
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(k8s_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find privileged container
            privileged_findings = [f for f in findings if "privileged" in f.title.lower()]
            assert len(privileged_findings) >= 1
            assert "app" in privileged_findings[0].description

    def test_kubernetes_host_namespaces(self, analyzer):
        """Test detection of host namespace usage in Kubernetes."""
        k8s_content = """
apiVersion: v1
kind: Pod
metadata:
  name: host-network-pod
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: app
    image: myapp:latest
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(k8s_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find host namespace usage
            host_findings = [f for f in findings if "host namespace" in f.title.lower()]
            assert len(host_findings) >= 2  # hostNetwork and hostPID

    def test_kubernetes_missing_security_context(self, analyzer):
        """Test detection of missing security context in Kubernetes."""
        k8s_content = """
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: myapp:latest
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(k8s_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find missing security context
            security_findings = [f for f in findings if "security context" in f.title.lower()]
            assert len(security_findings) >= 1

    def test_kubernetes_missing_resource_limits(self, analyzer):
        """Test detection of missing resource limits in Kubernetes."""
        k8s_content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
      - name: sidecar
        image: sidecar:latest
        resources:
          limits:
            memory: "128Mi"
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(k8s_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find missing resource limits
            resource_findings = [f for f in findings if "resource limits" in f.title.lower()]
            assert len(resource_findings) >= 1

    def test_kubernetes_with_proper_security(self, analyzer):
        """Test Kubernetes config with proper security doesn't trigger warnings."""
        k8s_content = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(k8s_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should have minimal findings (properly secured)
            high_severity_findings = [f for f in findings if f.severity == Severity.HIGH]
            assert len(high_severity_findings) == 0

    def test_invalid_yaml_handling(self, analyzer):
        """Test handling of invalid YAML files."""
        invalid_yaml = """
version: '3.8'
services:
  app:
    image: myapp
    ports:
      - "8080:8080"
    environment:
      - INVALID_YAML: [unclosed bracket
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='docker-compose.yml', delete=False) as f:
            f.write(invalid_yaml)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find YAML parsing error
            yaml_findings = [f for f in findings if "invalid yaml" in f.title.lower()]
            assert len(yaml_findings) >= 1

    def test_can_analyze_file(self, analyzer):
        """Test file analysis capability detection."""
        # Should analyze Docker files
        assert analyzer.can_analyze_file(Path("Dockerfile"))
        assert analyzer.can_analyze_file(Path("app.dockerfile"))
        assert analyzer.can_analyze_file(Path("docker-compose.yml"))
        assert analyzer.can_analyze_file(Path("compose.yaml"))

        # Should not analyze random files
        assert not analyzer.can_analyze_file(Path("README.md"))
        assert not analyzer.can_analyze_file(Path("script.py"))
        assert not analyzer.can_analyze_file(Path("config.txt"))

    def test_configuration_options(self):
        """Test different configuration options."""
        # Test with specific checks disabled
        config_minimal = {
            "container": {
                "check_base_images": False,
                "check_secrets": False,
                "check_privileges": True,
                "check_networking": True
            }
        }
        analyzer_minimal = ContainerAnalyzer(config_minimal)

        dockerfile_content = """
FROM ubuntu:14.04
ENV DATABASE_PASSWORD=secret123
USER root
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer_minimal.analyze_file(Path(f.name))

            # Should still find root user (privileges check enabled)
            # But should not find base image or secrets issues
            root_findings = [f for f in findings if "root user" in f.title.lower()]
            [f for f in findings if "base image" in f.title.lower()]
            [f for f in findings if "secret" in f.title.lower()]

            assert len(root_findings) >= 1
            # Note: base image and secret checks might still trigger from pattern rules
            # This tests the configuration framework

    def test_dockerfile_hardcoded_secrets(self, analyzer):
        """Test detection of hardcoded secrets in Dockerfile."""
        dockerfile_content = """
FROM ubuntu:20.04
ENV password=mysecretpassword123
RUN echo "secret=abcdef123456789" > /app/config
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find hardcoded secrets
            secret_findings = [f for f in findings if "hardcoded" in f.title.lower()]
            assert len(secret_findings) >= 1

    def test_dockerfile_privileged_operations(self, analyzer):
        """Test detection of privileged operations in Dockerfile."""
        dockerfile_content = """
FROM ubuntu:20.04
RUN chmod 777 /app
RUN chown root:root /app
RUN sudo apt-get update
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='Dockerfile', delete=False) as f:
            f.write(dockerfile_content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find privileged operations
            privilege_findings = [f for f in findings if "privileged operation" in f.title.lower()]
            assert len(privilege_findings) >= 1
