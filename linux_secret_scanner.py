#!/usr/bin/env python3
"""
linux_secret_scanner.py

Recursively scan files in a Linux system for secrets using the exact same logic
and regex patterns from the Go objectsecretscanner package.

Includes:
- All secret regex patterns (AWS, Azure, Google, GitHub, Slack, etc.)
- Exclusion logic for fake/test secrets
- Validation functions (Luhn for cards, IBAN, MAC)
- Multiline pattern support (PEM/PGP keys)
- Secret limiting by type and sensitivity

Usage:
  python3 linux_secret_scanner.py -r /path/to/scan -o results.json -c results.csv
"""

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import csv

# Directories to skip by default
DEFAULT_SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/run"}
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file

# ==================== SECRET PATTERNS ====================
# Exact patterns from object_secret_scanner.go

# Secret Types (Keys)
KEY_AWS_ACCESS_KEY = "aws-access-key"
KEY_AWS_ACCESS_KEY_B64 = "aws-access-key-b64"
KEY_AWS_SECRET_KEY = "aws-secret-key"
KEY_AWS_SESSION_TOKEN = "aws-session-token"
KEY_AWS_MWS_AUTH_TOKEN = "aws-mws-auth-token"

KEY_AZURE_STORAGE_KEY = "azure-storage-key"
KEY_AZURE_SAS_TOKEN = "azure-sas-token"

KEY_GOOGLE_API_KEY = "google-api-key"
KEY_GOOGLE_API_KEY_B64 = "google-api-key-b64"
KEY_GOOGLE_OAUTH_ACCESS_TOKEN = "google-oauth-access-token"
KEY_GOOGLE_OAUTH_CLIENT_SECRET = "google-oauth-client-secret"
KEY_FIREBASE_CLOUD_MESSAGING = "firebase-cloud-messaging-key"

KEY_GITHUB_TOKEN = "github-token"
KEY_GITHUB_PAT = "github-pat"

KEY_SLACK_TOKEN = "slack-token"
KEY_SLACK_APP_TOKEN = "slack-app-token"

KEY_FACEBOOK_ACCESS_TOKEN = "facebook-access-token"
KEY_FACEBOOK_ACCESS_TOKEN_B64 = "facebook-access-token-b64"

KEY_GENERIC_API_KEY = "generic-api-key"
KEY_JWT = "jwt"

KEY_PEM_PRIVATE_KEY = "pem-private-key"
KEY_PGP_PRIVATE_KEY = "pgp-private-key"

KEY_US_SSN = "U.S._Social_Security_Number"
KEY_MASTERCARD = "MasterCard_Number"
KEY_VISA = "Visa_Card_Number"
KEY_DISCOVER = "Discover_Credit_Card_Number"
KEY_JCB = "JCB_Credit_Card_Number"
KEY_AMEX = "Amex_Credit_Card_Number"
KEY_GENERAL_CARD = "Credit_Card_Number"
KEY_EMAIL1 = "Email"
KEY_EMAIL2 = "Email"
KEY_IPV6 = "IPv6"
KEY_MAC_ADDRESS = "MAC_Address"
KEY_IBAN = "IBAN_Number"
KEY_PHONE = "Phone_Number"
KEY_LAST_NAME = "Last_Name"
KEY_CITY = "City"
KEY_ZIP = "Zip"
KEY_FIRST_NAME = "First_Name"

# Sensitivity Types
SENSITIVITY_SECRET = "Secret"
SENSITIVITY_PII = "PII"
SENSITIVITY_PCI = "PCI"
SENSITIVITY_PHI = "PHI"

# Single-line patterns for secrets
SECRETS_PATTERNS_SINGLE_LINE = {
    # AWS
    KEY_AWS_ACCESS_KEY: r'\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
    KEY_AWS_ACCESS_KEY_B64: r'\b(QTNU|QUtJQ|QUdQQ|QUlEQ|QVJPQ|QUlQQ|QU5QQ|QU5WQ|QVNJQ)[%a-zA-Z0-9+/]{20,24}={0,2}\b',
    KEY_AWS_SECRET_KEY: r'(?i)(?:\baws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=\s]\s*["\']?([A-Za-z0-9+/=]{35,})|\bAWS_SECRET_ACCESS_KEY\s*=\s*["\']?([A-Za-z0-9+/=]{35,}))',
    KEY_AWS_SESSION_TOKEN: r'(?i)\baws[_-]?session[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{60,})',
    KEY_AWS_MWS_AUTH_TOKEN: r'\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',

    # Azure
    KEY_AZURE_STORAGE_KEY: r'(?i)\bAccountKey=([A-Za-z0-9+/]{70,90}={0,2})',
    KEY_AZURE_SAS_TOKEN: r'(?:\?|&)sv=\d{4}-\d{2}-\d{2}[^"\'\s]*&sig=[A-Za-z0-9%+/=]{15,}',

    # Google
    KEY_GOOGLE_API_KEY: r'\bAIzaSy[0-9A-Za-z\-_]{33}\b',
    KEY_GOOGLE_API_KEY_B64: r'\bQUl6YQ[A-Za-z0-9+/]{40,60}={0,2}\b',
    KEY_GOOGLE_OAUTH_ACCESS_TOKEN: r'\bya29\.[0-9A-Za-z_-]{20,200}\b',
    KEY_GOOGLE_OAUTH_CLIENT_SECRET: r'(?i)\bclient[_-]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{24,40})\b',
    KEY_FIREBASE_CLOUD_MESSAGING: r'\bAAAA[A-Za-z0-9_-]{4,}:[A-Za-z0-9_-]{100,}\b',

    # GitHub
    KEY_GITHUB_TOKEN: r'\bgh[pousr]_[A-Za-z0-9]{20,255}\b',
    KEY_GITHUB_PAT: r'\bgithub_pat_[A-Za-z0-9_]{22,255}\b',

    # Slack
    KEY_SLACK_TOKEN: r'\bxox[pbars]-\d{10,}(?:-\d{10,}){1,2}-[A-Za-z0-9]{24,}\b',
    KEY_SLACK_APP_TOKEN: r'\bxapp-\d-[A-Za-z0-9]{32}\b',

    # Facebook
    KEY_FACEBOOK_ACCESS_TOKEN: r'\b(?:^|[^0-9A-Za-z_+-]|\\[0abfnrtv]|(?:%|\\x)[0-9A-Fa-f]{2}|\\[0-7]{3}|\\[Uu][0-9A-Fa-f]{4}|\x1B\[[0-9;]{0,80}m)(?P<value>EAA[0-9A-Za-z]{80,800})\b',
    KEY_FACEBOOK_ACCESS_TOKEN_B64: r'\bRUFBQ0VkRW9zZTBjQk[%a-zA-Z0-9+/]+={0,2}\b',

    # Generic/Other
    KEY_JWT: r'\b[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{8,}\b',
    KEY_GENERIC_API_KEY: r'(?i)\b(api[_-]?key|token|bearer|authorization|secret)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,100})\b',
}

# Single-line patterns for sensitive data (PII/PCI/PHI)
SENSITIVE_PATTERNS_SINGLE_LINE = {
    KEY_US_SSN: r'\b([0-9]{3}-[0-9]{2}-[0-9]{4})\b',
    KEY_MASTERCARD: r'\b((?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b',
    KEY_VISA: r'\b(4\d{3}(?:[\s\-]?\d{4}){3})\b',
    KEY_DISCOVER: r'\b(6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b',
    KEY_JCB: r'\b(?:(?:35\d{2}(?:[\s\-]?\d{4}){3})|(?:(?:2131|1800)(?:[ \-]*\d){11}))\b',
    KEY_EMAIL1: r'\b([A-Za-z0-9](?:[A-Za-z0-9\._%+\-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9\.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,})\b',
    KEY_IPV6: r'\b((?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4})\b',
    KEY_MAC_ADDRESS: r'\b((?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2}))\b',
    KEY_IBAN: r'\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z\d]?){0,16})\b',
    KEY_PHONE: r'(?i)"phone"\s*:\s*"([^"]+)"',
    KEY_LAST_NAME: r'(?i)"last_name"\s*:\s*"([^"]+)"',
    KEY_CITY: r'(?i)"city"\s*:\s*"([^"]+)"',
    KEY_FIRST_NAME: r'(?i)"first_name"\s*:\s*"([^"]+)"',
    KEY_ZIP: r'(?i)"zip"\s*:\s*"([^"]+)"',
}

# Multiline patterns
SECRETS_PATTERNS_MULTILINE = {
    KEY_PEM_PRIVATE_KEY: r'(?m)-----BEGIN[A-Z0-9 _-]+?\s?PRIVATE KEY-----[\s\S]+?-----END[A-Z0-9 _-]+?\s?PRIVATE KEY-----',
    KEY_PGP_PRIVATE_KEY: r'(?m)-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----',
}

# Single-line patterns to find start of multiline patterns
SECRETS_PATTERNS_MULTILINE_SINGLE = {
    KEY_PEM_PRIVATE_KEY: r'(?m)-----BEGIN[A-Z0-9 _-]+?\s?PRIVATE KEY-----',
    KEY_PGP_PRIVATE_KEY: r'(?m)-----BEGIN PGP PRIVATE KEY BLOCK-----',
}

# Key to sensitivity mapping
KEY_TO_SENSITIVITY = {
    # AWS
    KEY_AWS_ACCESS_KEY: SENSITIVITY_SECRET,
    KEY_AWS_ACCESS_KEY_B64: SENSITIVITY_SECRET,
    KEY_AWS_SECRET_KEY: SENSITIVITY_SECRET,
    KEY_AWS_SESSION_TOKEN: SENSITIVITY_SECRET,
    KEY_AWS_MWS_AUTH_TOKEN: SENSITIVITY_SECRET,

    # Azure
    KEY_AZURE_STORAGE_KEY: SENSITIVITY_SECRET,
    KEY_AZURE_SAS_TOKEN: SENSITIVITY_SECRET,

    # Google
    KEY_GOOGLE_API_KEY: SENSITIVITY_SECRET,
    KEY_GOOGLE_API_KEY_B64: SENSITIVITY_SECRET,
    KEY_GOOGLE_OAUTH_ACCESS_TOKEN: SENSITIVITY_SECRET,
    KEY_GOOGLE_OAUTH_CLIENT_SECRET: SENSITIVITY_SECRET,
    KEY_FIREBASE_CLOUD_MESSAGING: SENSITIVITY_SECRET,

    # GitHub
    KEY_GITHUB_TOKEN: SENSITIVITY_SECRET,
    KEY_GITHUB_PAT: SENSITIVITY_SECRET,

    # Slack
    KEY_SLACK_TOKEN: SENSITIVITY_SECRET,
    KEY_SLACK_APP_TOKEN: SENSITIVITY_SECRET,

    # Facebook
    KEY_FACEBOOK_ACCESS_TOKEN: SENSITIVITY_SECRET,
    KEY_FACEBOOK_ACCESS_TOKEN_B64: SENSITIVITY_SECRET,

    # Generic/Other
    KEY_GENERIC_API_KEY: SENSITIVITY_SECRET,
    KEY_JWT: SENSITIVITY_SECRET,

    # Private Keys
    KEY_PEM_PRIVATE_KEY: SENSITIVITY_SECRET,
    KEY_PGP_PRIVATE_KEY: SENSITIVITY_SECRET,

    # PII
    KEY_US_SSN: SENSITIVITY_PII,
    KEY_EMAIL1: SENSITIVITY_PII,
    KEY_IPV6: SENSITIVITY_PII,
    KEY_MAC_ADDRESS: SENSITIVITY_PII,
    KEY_IBAN: SENSITIVITY_PII,
    KEY_PHONE: SENSITIVITY_PII,
    KEY_LAST_NAME: SENSITIVITY_PII,
    KEY_CITY: SENSITIVITY_PII,
    KEY_ZIP: SENSITIVITY_PII,
    KEY_FIRST_NAME: SENSITIVITY_PII,

    # PCI
    KEY_MASTERCARD: SENSITIVITY_PCI,
    KEY_VISA: SENSITIVITY_PCI,
    KEY_DISCOVER: SENSITIVITY_PCI,
    KEY_JCB: SENSITIVITY_PCI,
    KEY_GENERAL_CARD: SENSITIVITY_PCI,
}

# Per-key limits (from secret_limiter.go)
KEY_LIMITS = {
    KEY_EMAIL1: 50,
    KEY_GENERIC_API_KEY: 50,
    KEY_US_SSN: 50,
    KEY_GENERAL_CARD: 50,
}

# ==================== EXCLUSION LOGIC ====================
# From processors/exclusion.go

# Exclusion regex patterns
EXCLUSION_PATTERNS = [
    # AWS keys with test keywords ANYWHERE
    re.compile(r'^AKIA.*(TEST|EXAMPLE|DUMMY|FAKE|MOCK|TEMPLATE|SAMPLE|DEMO|EXMPL).*$'),

    # Google API keys with test keywords
    re.compile(r'^AIza.*(TEST|EXAMPLE|DUMMY|FAKE|MOCK|TEMPLATE|SAMPLE|DEMO|EXMPL).*$'),

    # GitHub tokens with test keywords
    re.compile(r'^gh[pousr]_.*(TEST|EXAMPLE|DUMMY|FAKE|MOCK|TEMPLATE|SAMPLE|DEMO|EXMPL).*$'),
    re.compile(r'^github_pat_.*(TEST|EXAMPLE|DUMMY|FAKE|MOCK|TEMPLATE|SAMPLE|DEMO|EXMPL).*$'),

    # Slack tokens with test keywords
    re.compile(r'^xox[pbars]-.*(TEST|EXAMPLE|DUMMY|FAKE|MOCK|TEMPLATE|SAMPLE|DEMO|EXMPL).*$'),

    # Secrets that START with test keywords
    re.compile(r'(?i)^(test|example|dummy|fake|mock|template|sample|demo|exmpl)[_-]'),

    # Placeholder patterns
    re.compile(r'(?i)(your|my|user|customer)[_-]?(key|secret|token|api|password)'),
    re.compile(r'<[^>]+>'),      # <API_KEY>
    re.compile(r'\{[^}]+\}'),    # {API_KEY}
    re.compile(r'\$\{[^}]+\}'),  # ${API_KEY}

    # Repeated characters
    re.compile(r'0{10,}|1{10,}|X{10,}|x{10,}'),

    # All zeros/ones AWS keys
    re.compile(r'^AKIA(0{16}|1{16})$'),
]

EXCLUSION_KEYWORDS = [
    "TEST", "EXAMPLE", "DUMMY", "FAKE", "MOCK",
    "TEMPLATE", "PLACEHOLDER", "REDACTED",
    "SAMPLE", "DEMO", "EXMPL",
]

def should_exclude_secret(secret: str, custom_exclusions: List[str] = None) -> bool:
    """Check if a secret should be excluded (is fake/test)"""
    # Check regex patterns
    for pattern in EXCLUSION_PATTERNS:
        if pattern.match(secret):
            return True

    # Check if entirely composed of test keywords + basic chars
    upper = secret.upper()
    cleaned_secret = upper
    for keyword in EXCLUSION_KEYWORDS:
        cleaned_secret = cleaned_secret.replace(keyword, "")

    # If after removing keywords, only separators/numbers remain, it's fake
    cleaned_secret = cleaned_secret.strip("_- 0123456789")
    if len(cleaned_secret) < 5:
        return True

    # Check custom exclusions
    if custom_exclusions:
        for custom in custom_exclusions:
            if custom.upper() in upper:
                return True

    return False

# ==================== VALIDATION FUNCTIONS ====================
# From processors/cardvalidation.go, ibanvalidation.go, macvalidation.go

def luhn_validation(card_number: str) -> bool:
    """Validate credit card using Luhn algorithm"""
    # Extract only digits
    digits = [int(c) for c in card_number if c.isdigit()]

    number_len = len(digits)
    if number_len < 13 or number_len > 19:
        return False

    total = 0
    alternate = False

    for i in range(number_len - 1, -1, -1):
        digit = digits[i]
        if alternate:
            digit *= 2
            if digit > 9:
                digit = (digit % 10) + 1

        alternate = not alternate
        total += digit

    return total % 10 == 0

def iban_validation(iban: str) -> bool:
    """Validate IBAN using ISO 13616"""
    # Move the four initial characters to the end
    iban = iban[4:] + iban[:4]

    # Replace letters with numbers (A=10, B=11, ..., Z=35)
    mods = ""
    for c in iban:
        if c.isalpha() and c.isupper():
            mods += str(ord(c) - 55)
        else:
            mods += c

    try:
        # Check if mod 97 equals 1
        return int(mods) % 97 == 1
    except ValueError:
        return False

def mac_validation(mac: str) -> bool:
    """Validate MAC address format"""
    # Check common MAC address patterns
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
        r'^([0-9A-Fa-f]{2}){6}$',
    ]
    for pattern in patterns:
        if re.match(pattern, mac):
            return True
    return False

# Validation mapping (from PostProcessFuncs in object_secret_scanner.go)
POST_PROCESS_FUNCS = {
    KEY_VISA: luhn_validation,
    KEY_MASTERCARD: luhn_validation,
    KEY_DISCOVER: luhn_validation,
    KEY_JCB: luhn_validation,
    KEY_AMEX: luhn_validation,
    KEY_IBAN: iban_validation,
    KEY_MAC_ADDRESS: mac_validation,
}

# ==================== SECRET LIMITER ====================

class SecretLimiter:
    """Track and limit secrets by type and sensitivity"""

    def __init__(self, max_all: int = 0, max_secrets: int = 0, max_pii: int = 0,
                 max_pci: int = 0, max_phi: int = 0):
        self.counters = {
            "allSecretTypes": {"max": max_all, "current": 0},
            SENSITIVITY_SECRET: {"max": max_secrets, "current": 0},
            SENSITIVITY_PII: {"max": max_pii, "current": 0},
            SENSITIVITY_PCI: {"max": max_pci, "current": 0},
            SENSITIVITY_PHI: {"max": max_phi, "current": 0},
        }

        # Add per-key limits
        for key, limit in KEY_LIMITS.items():
            self.counters[key] = {"max": limit, "current": 0}

    def increment(self, secret_type: str, count: int = 1) -> Tuple[bool, int, str]:
        """Increment counters and check if limit reached. Returns (limit_reached, over_by, limit_type)"""
        # Get sensitivity
        sensitivity = KEY_TO_SENSITIVITY.get(secret_type, "")

        # Check sensitivity limit
        if sensitivity and sensitivity in self.counters:
            counter = self.counters[sensitivity]
            if counter["max"] > 0:
                counter["current"] += count
                if counter["current"] >= counter["max"]:
                    over_by = counter["current"] - counter["max"]
                    return True, over_by, f"sensitivity_{sensitivity}"

        # Check specific type limit
        if secret_type in self.counters:
            counter = self.counters[secret_type]
            if counter["max"] > 0:
                counter["current"] += count
                if counter["current"] >= counter["max"]:
                    over_by = counter["current"] - counter["max"]
                    return True, over_by, f"key_{secret_type}"

        # Check all types limit
        all_counter = self.counters["allSecretTypes"]
        if all_counter["max"] > 0:
            all_counter["current"] += count
            if all_counter["current"] >= all_counter["max"]:
                over_by = all_counter["current"] - all_counter["max"]
                return True, over_by, "all"

        return False, 0, ""

    def limit_reached(self, secret_type_or_sensitivity: str) -> bool:
        """Check if limit is reached for a type or sensitivity"""
        if secret_type_or_sensitivity in self.counters:
            counter = self.counters[secret_type_or_sensitivity]
            return counter["max"] > 0 and counter["current"] >= counter["max"]
        return False

# ==================== FILE SCANNING ====================

def should_skip_path(path: str, no_skip: bool) -> bool:
    """Check if path should be skipped"""
    if no_skip:
        return False
    for skip_dir in DEFAULT_SKIP_DIRS:
        if path == skip_dir or path.startswith(skip_dir + os.sep):
            return True
    return False

def read_file_text(path: str, max_bytes: int) -> Optional[str]:
    """Read file as text"""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    return data.decode("latin-1")
                except Exception:
                    return data.decode("utf-8", errors="replace")
    except (PermissionError, IsADirectoryError):
        return None
    except Exception:
        return None

def redact_secret(s: str, max_len: int = 120) -> str:
    """Redact long secrets for display"""
    if len(s) <= max_len:
        return s
    return f"{s[:40]}...[{len(s)}b]...{s[-40:]}"

def scan_file_for_secrets(
    path: str,
    compiled_patterns: Dict[str, re.Pattern],
    max_bytes: int,
    context: int,
    enable_exclusion: bool,
    custom_exclusions: List[str],
    secret_limiter: SecretLimiter,
    quiet: bool
) -> List[Dict[str, Any]]:
    """Scan a file for secret patterns"""
    results = []

    txt = read_file_text(path, max_bytes)
    if not txt:
        return results

    lines = txt.split("\n")
    seek_offset = 0

    for line_num, line in enumerate(lines):
        for key, pattern in compiled_patterns.items():
            # Check if limit reached before scanning
            sensitivity = KEY_TO_SENSITIVITY.get(key, "")
            if secret_limiter.limit_reached(key) or secret_limiter.limit_reached(sensitivity):
                if not quiet:
                    print(f"[!] Limit reached for {key} / {sensitivity}, skipping", file=sys.stderr)
                continue

            matches = pattern.finditer(line)
            for m in matches:
                secret = m.group(0)

                # Apply exclusion logic
                if enable_exclusion and should_exclude_secret(secret, custom_exclusions):
                    if not quiet:
                        print(f"[DEBUG] Excluded secret: {redact_secret(secret)}", file=sys.stderr)
                    continue

                # Apply validation if needed
                if key in POST_PROCESS_FUNCS:
                    if not POST_PROCESS_FUNCS[key](secret):
                        continue

                # Extract context
                ctx_start = max(0, m.start() - context)
                ctx_end = min(len(line), m.end() + context)
                context_snippet = line[ctx_start:ctx_end].replace("\n", " ")

                results.append({
                    "file": path,
                    "line": line_num + 1,
                    "secret_type": key,
                    "sensitivity": sensitivity,
                    "secret": redact_secret(secret),
                    "start": m.start(),
                    "end": m.end(),
                    "seek_position": seek_offset + m.start(),
                    "context": context_snippet[:300]
                })

                # Increment limiter
                limit_reached, over_by, limit_type = secret_limiter.increment(key)
                if limit_reached:
                    if not quiet:
                        print(f"[!] Limit reached: {key} / {limit_type} / {over_by} over", file=sys.stderr)
                    # Remove the last over_by detections
                    if over_by > 0 and len(results) > over_by:
                        results = results[:-over_by]
                    return results

        seek_offset += len(line) + 1

    return results

def scan_file_wrapper(
    path: str,
    single_line_patterns: Dict[str, re.Pattern],
    multiline_patterns: Dict[str, re.Pattern],
    multiline_single_patterns: Dict[str, re.Pattern],
    max_bytes: int,
    context: int,
    enable_exclusion: bool,
    custom_exclusions: List[str],
    secret_limiter: SecretLimiter,
    quiet: bool
) -> List[Dict[str, Any]]:
    """Wrapper to scan file with multiline support"""
    results = []

    txt = read_file_text(path, max_bytes)
    if not txt:
        return results

    # Check for multiline patterns first
    line_search_patterns = single_line_patterns.copy()
    for key, pattern in multiline_patterns.items():
        if pattern.search(txt):
            if not quiet:
                print(f"[DEBUG] Multiline pattern found: {key}", file=sys.stderr)
            # Add the single-line version to search
            line_search_patterns[key] = multiline_single_patterns[key]

    # Scan with single-line patterns
    results = scan_file_for_secrets(
        path, line_search_patterns, max_bytes, context,
        enable_exclusion, custom_exclusions, secret_limiter, quiet
    )

    return results

def iter_files(root: str, follow_symlinks: bool, no_skip: bool):
    """Iterate over files to scan"""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        if should_skip_path(dirpath, no_skip):
            dirnames[:] = []
            continue
        for fn in filenames:
            yield os.path.join(dirpath, fn)

def write_csv(path: str, data: List[Dict[str, Any]]):
    """Write results to CSV"""
    fieldnames = ["file", "line", "secret_type", "sensitivity", "secret", "start", "end", "seek_position", "context"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in data:
            writer.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Scan files for secrets using exact Go objectsecretscanner logic")
    ap.add_argument("--root", "-r", default=".", help="Root path to scan")
    ap.add_argument("--secrets", action="store_true", default=True, help="Scan for secrets (default: True)")
    ap.add_argument("--sensitive", action="store_true", help="Scan for sensitive data (PII/PCI/PHI)")
    ap.add_argument("--threads", "-t", type=int, default=6, help="Number of threads")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Max file size to scan")
    ap.add_argument("--out-json", "-o", default="results.json", help="Output JSON file")
    ap.add_argument("--out-csv", "-c", default="results.csv", help="Output CSV file")
    ap.add_argument("--no-skip", action="store_true", help="Don't skip default directories")
    ap.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    ap.add_argument("--quiet", action="store_true", help="Quiet mode")
    ap.add_argument("--context", type=int, default=40, help="Context chars around match")

    # Exclusion options
    # replacement (preferred)
    ap.add_argument("--enable-exclusion", dest="enable_exclusion", action="store_true",
                    help="Enable exclusion logic")
    ap.add_argument("--no-enable-exclusion", dest="enable_exclusion", action="store_false",
                    help="Disable exclusion logic")
    ap.set_defaults(enable_exclusion=True)  # set the default you want: True or False
    ap.add_argument("--custom-exclusions", nargs="*", default=[], help="Custom exclusion keywords")

    # Limiting options
    ap.add_argument("--max-all", type=int, default=0, help="Max total secrets (0 = unlimited)")
    ap.add_argument("--max-secrets", type=int, default=0, help="Max Secret type (0 = unlimited)")
    ap.add_argument("--max-pii", type=int, default=0, help="Max PII (0 = unlimited)")
    ap.add_argument("--max-pci", type=int, default=0, help="Max PCI (0 = unlimited)")
    ap.add_argument("--max-phi", type=int, default=0, help="Max PHI (0 = unlimited)")

    args = ap.parse_args()

    # Build pattern maps
    single_line_patterns = {}
    if args.secrets:
        single_line_patterns.update(SECRETS_PATTERNS_SINGLE_LINE)
    if args.sensitive:
        single_line_patterns.update(SENSITIVE_PATTERNS_SINGLE_LINE)

    # Compile patterns
    compiled_single = {}
    for name, pattern in single_line_patterns.items():
        try:
            compiled_single[name] = re.compile(pattern, re.MULTILINE | re.DOTALL)
        except re.error as e:
            print(f"[!] Failed to compile pattern {name}: {e}", file=sys.stderr)

    compiled_multiline = {}
    compiled_multiline_single = {}
    if args.secrets:
        for name, pattern in SECRETS_PATTERNS_MULTILINE.items():
            try:
                compiled_multiline[name] = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error as e:
                print(f"[!] Failed to compile multiline pattern {name}: {e}", file=sys.stderr)

        for name, pattern in SECRETS_PATTERNS_MULTILINE_SINGLE.items():
            try:
                compiled_multiline_single[name] = re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error as e:
                print(f"[!] Failed to compile multiline-single pattern {name}: {e}", file=sys.stderr)

    if not compiled_single and not compiled_multiline:
        print("No valid patterns. Exiting.", file=sys.stderr)
        sys.exit(2)

    if not args.quiet:
        print(f"[+] Scanning {args.root} with {len(compiled_single)} single-line and {len(compiled_multiline)} multiline patterns...")

    # Create secret limiter
    secret_limiter = SecretLimiter(
        max_all=args.max_all,
        max_secrets=args.max_secrets,
        max_pii=args.max_pii,
        max_pci=args.max_pci,
        max_phi=args.max_phi
    )

    results = []
    files_iter = iter_files(args.root, args.follow_symlinks, args.no_skip)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = {
            ex.submit(
                scan_file_wrapper,
                f,
                compiled_single,
                compiled_multiline,
                compiled_multiline_single,
                args.max_bytes,
                args.context,
                args.enable_exclusion,
                args.custom_exclusions,
                secret_limiter,
                args.quiet
            ): f for f in files_iter
        }

        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    results.extend(res)
            except Exception as e:
                if not args.quiet:
                    print(f"[!] Error scanning {futures[fut]}: {e}", file=sys.stderr)

    # Write results
    with open(args.out_json, "w", encoding="utf-8") as of:
        json.dump(results, of, indent=2, ensure_ascii=False)
    if not args.quiet:
        print(f"[+] Wrote {len(results)} matches to {args.out_json}")

    write_csv(args.out_csv, results)
    if not args.quiet:
        print(f"[+] Wrote CSV with {len(results)} rows to {args.out_csv}")

    sys.exit(0 if not results else 3)

if __name__ == "__main__":
    main()
