"""
Cryptocurrency wallet theft detection analyzer.

This module provides comprehensive detection capabilities for identifying code patterns
that attempt to steal cryptocurrency wallets including:
- Wallet file access patterns (wallet.dat, keystore files)
- Private key extraction attempts
- Seed phrase harvesting code
- Suspicious crypto API interactions
- Wallet address enumeration
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from ..finding import Finding, FindingType, Location, Severity
from . import BaseAnalyzer, register_analyzer

logger = logging.getLogger(__name__)


@register_analyzer
class CryptoWalletAnalyzer(BaseAnalyzer):
    """Analyzer for detecting cryptocurrency wallet theft attempts."""

    name = "crypto_wallet"
    description = (
        "Detects code patterns that attempt to steal cryptocurrency wallets and keys"
    )
    supported_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".java",
        ".cs",
        ".php",
        ".rb",
        ".go",
        ".rs",
        ".cpp",
        ".c",
        ".h",
    }

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)

        # Configuration
        analyzer_config = config.get(self.name, {})
        self.enable_wallet_file_detection = analyzer_config.get(
            "enable_wallet_file_detection", True
        )
        self.enable_private_key_detection = analyzer_config.get(
            "enable_private_key_detection", True
        )
        self.enable_seed_phrase_detection = analyzer_config.get(
            "enable_seed_phrase_detection", True
        )
        self.enable_crypto_api_detection = analyzer_config.get(
            "enable_crypto_api_detection", True
        )
        self.enable_address_enumeration_detection = analyzer_config.get(
            "enable_address_enumeration_detection", True
        )

        # Initialize detection patterns
        self.crypto_wallet_patterns = self._init_crypto_wallet_patterns()

    def _init_crypto_wallet_patterns(self) -> List[Dict[str, Any]]:
        """Initialize patterns for detecting crypto wallet theft attempts."""
        patterns = []

        # Wallet file access patterns
        if self.enable_wallet_file_detection:
            patterns.extend(
                [
                    {
                        "id": "CRYPTO_WALLET_FILE_ACCESS",
                        "title": "Cryptocurrency wallet file access detected",
                        "description": "Code attempts to access cryptocurrency wallet files",
                        "severity": Severity.CRITICAL,
                        "pattern": re.compile(
                            r"(?:wallet\.dat|wallet\.json|keystore|UTC--|"
                            r"default_wallet|electrum\.dat|bitcoin-qt|"
                            r"\.wallet|wallets?\.db|\.btc|\.eth|\.ltc)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1005/"],
                        "cwe_id": "CWE-200",
                    },
                    {
                        "id": "CRYPTO_WALLET_DIR_ACCESS",
                        "title": "Cryptocurrency wallet directory access",
                        "description": "Code accesses cryptocurrency wallet directories",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:Bitcoin|Ethereum|Litecoin|Dogecoin|Monero|Zcash|Dash|"
                            r"Electrum|Exodus|Atomic|Coinbase|Binance|MetaMask|"
                            r"\.bitcoin|\.ethereum|\.litecoin|\.dogecoin|\.monero|"
                            r"wallet(?:s)?(?:/|\\\\)|keystore(?:/|\\\\))",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1005/"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Private key extraction patterns
        if self.enable_private_key_detection:
            patterns.extend(
                [
                    {
                        "id": "CRYPTO_PRIVATE_KEY_EXTRACTION",
                        "title": "Cryptocurrency private key extraction detected",
                        "description": "Code attempts to extract or manipulate private keys",
                        "severity": Severity.CRITICAL,
                        "pattern": re.compile(
                            r"(?:private.*key|privateKey|privkey|priv_key|"
                            r"0x[a-fA-F0-9]{64}|[a-fA-F0-9]{64}.*key|"
                            r"WIF.*key|extended.*private|xprv|"
                            r"decrypt.*key|unlock.*key|extract.*key)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1555/"],
                        "cwe_id": "CWE-522",
                    },
                    {
                        "id": "CRYPTO_KEY_DERIVATION_ABUSE",
                        "title": "Cryptocurrency key derivation manipulation",
                        "description": "Code manipulates key derivation functions to extract keys",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:bip39|bip32|bip44|hdkey|hierarchical.*deterministic|"
                            r"master.*key|child.*key|derive.*key|path.*key|"
                            r"m/44'/0'/0'|PBKDF2|scrypt.*key)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": [
                            "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki"
                        ],
                        "cwe_id": "CWE-327",
                    },
                ]
            )

        # Seed phrase harvesting patterns
        if self.enable_seed_phrase_detection:
            patterns.extend(
                [
                    {
                        "id": "CRYPTO_SEED_PHRASE_HARVEST",
                        "title": "Cryptocurrency seed phrase harvesting detected",
                        "description": "Code attempts to harvest or steal mnemonic seed phrases",
                        "severity": Severity.CRITICAL,
                        "pattern": re.compile(
                            r"(?:mnemonic|seed.*phrase|recovery.*phrase|"
                            r"12.*words?|24.*words?|backup.*phrase|"
                            r"word.*list|secret.*phrase|passphrase|"
                            r"BIP39.*words?|wordlist|entropy)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": [
                            "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki"
                        ],
                        "cwe_id": "CWE-200",
                    },
                    {
                        "id": "CRYPTO_MNEMONIC_GENERATION",
                        "title": "Suspicious mnemonic generation detected",
                        "description": "Code generates or validates mnemonic phrases in suspicious ways",
                        "severity": Severity.MEDIUM,
                        "pattern": re.compile(
                            r"(?:generate.*mnemonic|create.*seed|random.*words?|"
                            r"entropy.*words?|validate.*mnemonic|check.*phrase|"
                            r"word.*validation|phrase.*validation)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": [
                            "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki"
                        ],
                        "cwe_id": "CWE-330",
                    },
                ]
            )

        # Crypto API interaction patterns
        if self.enable_crypto_api_detection:
            patterns.extend(
                [
                    {
                        "id": "CRYPTO_API_SUSPICIOUS_CALLS",
                        "title": "Suspicious cryptocurrency API interactions",
                        "description": "Code makes suspicious calls to cryptocurrency APIs",
                        "severity": Severity.HIGH,
                        "pattern": re.compile(
                            r"(?:blockchain\.info|blockchair\.com|blockcypher\.com|"
                            r"etherscan\.io|bscscan\.com|polygonscan\.com|"
                            r"api\.bitcoin|api\.ethereum|rpc\.bitcoin|"
                            r"web3\.eth|bitcoin.*rpc|ethereum.*rpc|"
                            r"getbalance|listaccounts|dumpprivkey|"
                            r"exportprivkey|importprivkey)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1041/"],
                        "cwe_id": "CWE-200",
                    },
                    {
                        "id": "CRYPTO_EXCHANGE_API_ABUSE",
                        "title": "Cryptocurrency exchange API abuse detected",
                        "description": "Code abuses cryptocurrency exchange APIs to steal funds",
                        "severity": Severity.CRITICAL,
                        "pattern": re.compile(
                            r"(?:binance.*api|coinbase.*api|kraken.*api|"
                            r"bitfinex.*api|huobi.*api|okex.*api|"
                            r"withdraw|transfer.*funds?|api.*key|secret.*key|"
                            r"trading.*api|exchange.*api|market.*api)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1041/"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Wallet address enumeration patterns
        if self.enable_address_enumeration_detection:
            patterns.extend(
                [
                    {
                        "id": "CRYPTO_ADDRESS_ENUMERATION",
                        "title": "Cryptocurrency address enumeration detected",
                        "description": "Code enumerates or scans cryptocurrency addresses",
                        "severity": Severity.MEDIUM,
                        "pattern": re.compile(
                            r"(?:address.*scan|wallet.*scan|balance.*check|"
                            r"bulk.*address|mass.*address|enumerate.*address|"
                            r"address.*list|wallet.*sweep|address.*generator|"
                            r"vanity.*address|brain.*wallet)",
                            re.IGNORECASE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://attack.mitre.org/techniques/T1018/"],
                        "cwe_id": "CWE-200",
                    },
                    {
                        "id": "CRYPTO_ADDRESS_PATTERN_MATCHING",
                        "title": "Cryptocurrency address pattern matching",
                        "description": "Code uses regex patterns to identify cryptocurrency addresses",
                        "severity": Severity.LOW,
                        "pattern": re.compile(
                            r"(?:\^?[13][a-km-zA-HJ-NP-Z1-9]{25,34}\$?|"  # Bitcoin
                            r"\^?0x[a-fA-F0-9]{40}\$?|"  # Ethereum
                            r"\^?[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\$?|"  # Litecoin
                            r"\^?D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\$?|"  # Dogecoin
                            r"bc1[a-z0-9]{39,59}|"  # Bitcoin Bech32
                            r"[a-zA-Z0-9]{95}.*address)",  # Generic crypto address pattern
                            re.MULTILINE,
                        ),
                        "finding_type": FindingType.SUSPICIOUS,
                        "references": ["https://en.bitcoin.it/wiki/Address"],
                        "cwe_id": "CWE-200",
                    },
                ]
            )

        # Hardware wallet interaction patterns
        patterns.extend(
            [
                {
                    "id": "CRYPTO_HARDWARE_WALLET_ACCESS",
                    "title": "Hardware wallet access detected",
                    "description": "Code attempts to interact with hardware wallets",
                    "severity": Severity.HIGH,
                    "pattern": re.compile(
                        r"(?:ledger|trezor|keepkey|coldcard|bitbox|"
                        r"hardware.*wallet|usb.*wallet|hid.*device|"
                        r"u2f.*device|webusb|usb.*communication)",
                        re.IGNORECASE,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1200/"],
                    "cwe_id": "CWE-200",
                },
            ]
        )

        # Crypto mining and stealer patterns
        patterns.extend(
            [
                {
                    "id": "CRYPTO_STEALER_BEHAVIOR",
                    "title": "Cryptocurrency stealer behavior detected",
                    "description": "Code exhibits behavior typical of cryptocurrency stealers",
                    "severity": Severity.CRITICAL,
                    "pattern": re.compile(
                        r"(?:clipboard.*hook|clipboard.*monitor|"
                        r"address.*replace|wallet.*replace|"
                        r"copy.*hook|paste.*hook|steal.*crypto|"
                        r"crypto.*stealer|wallet.*stealer|clipper)",
                        re.IGNORECASE,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1115/"],
                    "cwe_id": "CWE-200",
                },
                {
                    "id": "CRYPTO_MINING_ABUSE",
                    "title": "Cryptocurrency mining abuse detected",
                    "description": "Code performs unauthorized cryptocurrency mining",
                    "severity": Severity.MEDIUM,
                    "pattern": re.compile(
                        r"(?:cryptonight|monero.*mining|xmrig|cpuminer|"
                        r"mining.*pool|stratum.*protocol|hashrate|"
                        r"gpu.*mining|asic.*mining|proof.*of.*work|"
                        r"nonce.*mining|difficulty.*target)",
                        re.IGNORECASE,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1496/"],
                    "cwe_id": "CWE-400",
                },
            ]
        )

        # Data exfiltration patterns specific to crypto theft
        patterns.extend(
            [
                {
                    "id": "CRYPTO_DATA_EXFILTRATION",
                    "title": "Cryptocurrency data exfiltration detected",
                    "description": "Code attempts to exfiltrate stolen cryptocurrency data",
                    "severity": Severity.CRITICAL,
                    "pattern": re.compile(
                        r"(?:fetch|XMLHttpRequest|axios|request|urllib|requests).*"
                        r"(?:wallet|private.*key|seed|mnemonic|crypto|bitcoin|ethereum)",
                        re.IGNORECASE | re.DOTALL,
                    ),
                    "finding_type": FindingType.SUSPICIOUS,
                    "references": ["https://attack.mitre.org/techniques/T1041/"],
                    "cwe_id": "CWE-200",
                },
            ]
        )

        return patterns

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for crypto wallet theft patterns."""
        findings: List[Finding] = []

        try:
            # Read file content
            content = self._read_file_safely(file_path)
            if not content:
                return findings

            logger.debug(f"Analyzing {file_path} for crypto wallet theft patterns")

            # Apply each pattern
            for pattern_info in self.crypto_wallet_patterns:
                matches = pattern_info["pattern"].finditer(content)

                for match in matches:
                    # Calculate line and column number
                    line_number = content[: match.start()].count("\n") + 1
                    column_number = match.start() - content.rfind(
                        "\n", 0, match.start()
                    )

                    # Extract the matched text for context
                    matched_text = match.group(0)

                    # Get surrounding context (50 characters before and after)
                    start_context = max(0, match.start() - 50)
                    end_context = min(len(content), match.end() + 50)
                    context = content[start_context:end_context].replace("\n", " ")

                    finding = Finding(
                        id=pattern_info["id"],
                        analyzer=self.name,
                        severity=pattern_info["severity"],
                        title=pattern_info["title"],
                        description=f"{pattern_info['description']}\n\n"
                        f"Matched pattern: {matched_text}\n"
                        f"Context: ...{context}...",
                        location=Location(
                            path=file_path,
                            line_start=line_number,
                            column_start=column_number,
                        ),
                        type=pattern_info["finding_type"],
                        metadata={
                            "matched_text": matched_text,
                            "pattern_id": pattern_info["id"],
                            "context": context,
                            "cwe_id": pattern_info.get("cwe_id"),
                        },
                        references=pattern_info.get("references", []),
                        remediation=self._get_remediation(pattern_info["id"]),
                        confidence=0.8,  # High confidence for pattern matches
                        tags=["cryptocurrency", "wallet", "theft", "security"],
                    )

                    findings.append(finding)

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")

        return findings

    def _read_file_safely(self, file_path: Path) -> str:
        """Safely read file content with multiple encoding attempts."""
        encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]

        for encoding in encodings:
            try:
                content = file_path.read_text(encoding=encoding, errors="ignore")

                # Skip very large files (> 5MB)
                if len(content) > 5 * 1024 * 1024:
                    logger.debug(f"Skipping large file {file_path}")
                    return ""

                return content
            except Exception as e:
                logger.debug(f"Failed to read {file_path} with {encoding}: {e}")
                continue

        return ""

    def _get_remediation(self, pattern_id: str) -> str:
        """Get remediation advice for specific pattern types."""
        remediation_map = {
            "CRYPTO_WALLET_FILE_ACCESS": "Remove code that accesses cryptocurrency wallet files. If legitimate access is needed, implement proper user consent and security measures.",
            "CRYPTO_WALLET_DIR_ACCESS": "Avoid accessing cryptocurrency wallet directories. Use official wallet APIs if interaction with wallet data is required.",
            "CRYPTO_PRIVATE_KEY_EXTRACTION": "Remove all code that attempts to extract private keys. This is a serious security violation and potential theft.",
            "CRYPTO_KEY_DERIVATION_ABUSE": "Remove code that manipulates key derivation functions maliciously. Ensure proper cryptographic practices.",
            "CRYPTO_SEED_PHRASE_HARVEST": "Remove code that harvests seed phrases. This is theft and violates user privacy and security.",
            "CRYPTO_MNEMONIC_GENERATION": "Ensure mnemonic generation uses secure randomness and is for legitimate purposes only.",
            "CRYPTO_API_SUSPICIOUS_CALLS": "Review cryptocurrency API calls for legitimacy. Remove unauthorized data collection.",
            "CRYPTO_EXCHANGE_API_ABUSE": "Remove code that abuses exchange APIs. Implement proper authentication and user consent.",
            "CRYPTO_ADDRESS_ENUMERATION": "Remove address enumeration code unless for legitimate security research with proper authorization.",
            "CRYPTO_ADDRESS_PATTERN_MATCHING": "Ensure address pattern matching is for legitimate purposes and not for theft or surveillance.",
            "CRYPTO_HARDWARE_WALLET_ACCESS": "Remove unauthorized hardware wallet access code. Use official APIs with user consent.",
            "CRYPTO_STEALER_BEHAVIOR": "Remove all cryptocurrency stealer behavior. This is malicious and potentially illegal.",
            "CRYPTO_MINING_ABUSE": "Remove unauthorized mining code. Implement proper user consent for any mining activities.",
            "CRYPTO_DATA_EXFILTRATION": "Remove cryptocurrency data exfiltration code. Implement proper data handling with user consent.",
        }

        return remediation_map.get(
            pattern_id,
            "Review this code for potential cryptocurrency theft issues and ensure it follows security and legal best practices.",
        )
