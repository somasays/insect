"""
Static code analyzer for detecting malicious code patterns.

This module serves as a unified interface to the more specialized analyzers:
1. Python static analyzer - for Python code
2. JavaScript static analyzer - for JavaScript/TypeScript code
3. Binary analyzer - for analyzing binary files

Each analyzer implements specific detection rules for its target file type.
"""

# Import individual analyzers to register them
from insect.analysis.binary_analyzer import BinaryAnalyzer
from insect.analysis.container_analyzer import ContainerAnalyzer
from insect.analysis.javascript_static_analyzer import JavaScriptStaticAnalyzer
from insect.analysis.python_static_analyzer import PythonStaticAnalyzer
from insect.analysis.secret_analyzer import SecretAnalyzer
from insect.analysis.vulnerability_analyzer import VulnerabilityAnalyzer

__all__ = [
    "PythonStaticAnalyzer",
    "JavaScriptStaticAnalyzer",
    "BinaryAnalyzer",
    "VulnerabilityAnalyzer",
    "SecretAnalyzer",
    "ContainerAnalyzer",
]
