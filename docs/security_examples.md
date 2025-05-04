# Security Issues Detection Examples

This document provides examples of common security issues that Insect can detect, along with explanations and remediation advice.

## Table of Contents

- [Python Security Issues](#python-security-issues)
- [JavaScript Security Issues](#javascript-security-issues)
- [Shell Script Security Issues](#shell-script-security-issues)
- [Configuration Security Issues](#configuration-security-issues)
- [Secret Detection](#secret-detection)

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