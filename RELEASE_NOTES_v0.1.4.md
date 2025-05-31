# Release Notes - Insect v0.1.4

**Release Date:** May 31, 2025  
**Version:** 0.1.4

## 🚀 Major New Feature: Cryptocurrency Wallet Protection

This release introduces **Cryptocurrency Wallet Protection**, a comprehensive security analyzer designed to detect malicious code patterns that attempt to steal cryptocurrency assets, wallets, and private keys.

### 💰 Crypto Wallet Analyzer

**NEW:** `CryptoWalletAnalyzer` - Advanced protection against cryptocurrency theft
- **16 detection patterns** covering all major cryptocurrency theft techniques
- **Multi-cryptocurrency support** including Bitcoin, Ethereum, Litecoin, Dogecoin, Monero, and more
- **Comprehensive file type coverage** for Python, JavaScript, TypeScript, Shell scripts, and others
- **Severity-based classification** from Critical to Low based on threat level

## 🛡️ Detection Capabilities

### Core Cryptocurrency Theft Protection
- **Wallet File Access Detection** (`CRYPTO_WALLET_FILE_ACCESS`)
  - Detects access to `wallet.dat`, keystore files, and wallet directories
  - Identifies attempts to copy or read cryptocurrency wallet storage
  - Covers Bitcoin Core, Electrum, Ethereum, and other popular wallets

- **Private Key Extraction** (`CRYPTO_PRIVATE_KEY_EXTRACTION`)
  - Identifies attempts to extract private keys in various formats (hex, WIF, extended keys)
  - Detects key decryption and derivation manipulation
  - Flags suspicious key handling patterns

- **Seed Phrase Harvesting** (`CRYPTO_SEED_PHRASE_HARVEST`)
  - Detects attempts to steal mnemonic seed phrases (12/24-word recovery phrases)
  - Identifies BIP39 word list manipulation
  - Flags entropy extraction from seed phrases

### Advanced Threat Detection
- **Hardware Wallet Access** (`CRYPTO_HARDWARE_WALLET_ACCESS`)
  - Detects unauthorized Ledger, Trezor, and KeepKey device access
  - Identifies suspicious USB/HID device communication
  - Flags WebUSB and hardware wallet API abuse

- **Cryptocurrency Stealer Behavior** (`CRYPTO_STEALER_BEHAVIOR`)
  - Detects clipboard monitoring for cryptocurrency addresses
  - Identifies address replacement attacks (clipboard hijacking)
  - Flags cryptocurrency address pattern monitoring

- **Exchange API Abuse** (`CRYPTO_EXCHANGE_API_ABUSE`)
  - Identifies unauthorized cryptocurrency exchange API usage
  - Detects withdrawal and transfer operations using stolen credentials
  - Covers major exchanges like Binance, Coinbase, Kraken

- **Mining Abuse Detection** (`CRYPTO_MINING_ABUSE`)
  - Detects unauthorized cryptocurrency mining operations
  - Identifies CryptoNight, XMRig, and other mining software usage
  - Flags suspicious mining pool connections

- **Crypto API Monitoring** (`CRYPTO_API_SUSPICIOUS_CALLS`)
  - Monitors suspicious blockchain RPC calls
  - Detects mass address balance checking
  - Identifies dangerous operations like `dumpprivkey`

## 📊 Technical Implementation

### Pattern Detection Examples

**Wallet File Access:**
```python
# DETECTED: Critical - Wallet file access
bitcoin_wallet = os.path.expanduser("~/.bitcoin/wallet.dat")
ethereum_keystore = os.path.expanduser("~/.ethereum/keystore/UTC--*")
```

**Private Key Extraction:**
```python
# DETECTED: Critical - Private key extraction
private_key = "0x1234567890abcdef..." # 64-character hex key
wif_key = "5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS" # WIF format
```

**Seed Phrase Harvesting:**
```python
# DETECTED: Critical - Seed phrase theft
recovery_phrase = input("Enter your 12-word recovery phrase: ")
mnemonic_words = "abandon abandon abandon ... about"
```

**Clipboard Hijacking:**
```python
# DETECTED: Critical - Cryptocurrency stealer behavior  
if re.match(btc_pattern, clipboard_data):
    pyperclip.copy(attacker_btc_address)  # Replace with attacker's address
```

### Configuration Options

New configuration section in `config/default.toml`:
```toml
[crypto_wallet]
enable_wallet_file_detection = true
enable_private_key_detection = true
enable_seed_phrase_detection = true
enable_crypto_api_detection = true
enable_address_enumeration_detection = true
```

## 🧪 Comprehensive Testing

**19 test cases** ensuring robust detection:
- Wallet file access patterns
- Private key extraction attempts
- Seed phrase harvesting techniques
- Hardware wallet access attempts
- Cryptocurrency stealer behavior
- Exchange API abuse
- Mining abuse detection
- Multi-language coverage
- Configuration option testing
- False positive reduction

## 📚 Enhanced Documentation

### Security Examples Expansion
- **NEW:** Complete cryptocurrency wallet theft detection section
- **NEW:** Real-world malware examples and remediation strategies
- **NEW:** Hardware wallet security best practices
- **NEW:** Legitimate cryptocurrency development guidelines

### README Updates
- **IMPROVED:** Added cryptocurrency wallet theft protection to feature list
- **IMPROVED:** Enhanced security capabilities documentation
- **IMPROVED:** Updated examples with crypto theft scenarios

## 🛡️ Security Impact

This release significantly enhances protection against:
- ❌ **Cryptocurrency wallet theft** - Protects wallet files and directories
- ❌ **Private key extraction** - Prevents unauthorized key access
- ❌ **Seed phrase harvesting** - Blocks mnemonic theft attempts
- ❌ **Hardware wallet attacks** - Detects device manipulation attempts
- ❌ **Exchange account takeover** - Identifies API credential abuse
- ❌ **Clipboard hijacking** - Prevents address replacement attacks
- ❌ **Unauthorized mining** - Detects cryptojacking attempts
- ❌ **Cryptocurrency data exfiltration** - Blocks sensitive data theft

## 🔧 Usage Examples

### Basic Cryptocurrency Security Scan
```bash
# Scan for cryptocurrency theft patterns
insect scan /path/to/repository
```

### Focused Crypto Wallet Protection
```bash
# Scan with crypto-focused configuration
insect scan /path/to/repository --severity critical --format html -o crypto-security-report.html
```

### Custom Crypto Security Configuration
```toml
[analyzers]
crypto_wallet = true
secrets = true
static = true

[crypto_wallet]
enable_wallet_file_detection = true
enable_private_key_detection = true
enable_seed_phrase_detection = true

[severity]
min_level = "high"
```

## 📈 Performance & Quality

- **Test Coverage:** 88% coverage for the crypto wallet analyzer
- **Performance Impact:** Minimal overhead with efficient pattern matching
- **Memory Usage:** Lightweight implementation with negligible memory footprint
- **Code Quality:** Full compliance with project linting and formatting standards

## 🚀 Integration & Compatibility

- **Seamless Integration:** Works alongside existing analyzers without conflicts
- **Backward Compatibility:** No breaking changes to existing functionality
- **Multi-Platform Support:** Works across Windows, macOS, and Linux
- **File Type Support:** Analyzes Python, JavaScript, TypeScript, Shell scripts, PHP, Go, Rust, C/C++, Java, C#, and Ruby files

## 🏗️ Breaking Changes

None. This release maintains full backward compatibility with all existing features and configurations.

## 🔄 Upgrade Instructions

1. **Update Insect:**
   ```bash
   pip install --upgrade insect
   ```

2. **Verify New Features:**
   ```bash
   insect scan /path/to/test/repository
   ```

3. **Optional Configuration:**
   - Cryptocurrency wallet protection is enabled by default
   - Customize detection modules in your configuration file if needed

## 🎯 Coming Soon

The following cryptocurrency security features are planned for future releases:
- System information gathering detection
- Keylogger pattern identification  
- Screen capture/recording detection
- Network traffic interception checks
- Process injection/DLL hijacking detection

---

**Version Information:**
- **Version:** 0.1.4
- **Python Requirements:** 3.13+
- **Breaking Changes:** None
- **New Dependencies:** None

**Full Changelog:** https://github.com/somasays/insect/compare/v0.1.3...v0.1.4