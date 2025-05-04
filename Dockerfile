FROM python:3.10-slim

# Install git and other dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir bandit semgrep gitpython yara-python jinja2 click toml rich

# Create directories
RUN mkdir -p /insect /scan /scan/output

# Copy and install Insect
COPY . /insect/
WORKDIR /insect
RUN pip install -e .

# Set permissions for output directory
WORKDIR /scan
RUN chmod 777 /scan/output

# Test Insect installation
RUN insect --version

# Default command - run bash
CMD ["bash"]