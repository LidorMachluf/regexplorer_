# Linux Secret Scanner

A Python script that replicates the exact secret scanning logic from the Go `objectsecretscanner` package for testing on Linux systems.

## Features

### Secret Detection Patterns (Identical to Go Implementation)

**Cloud Provider Secrets:**
- AWS: Access Keys, Secret Keys, Session Tokens, MWS Auth Tokens
- Azure: Storage Keys, SAS Tokens
- Google: API Keys (plain & base64), OAuth tokens, Firebase Cloud Messaging
- GitHub: Personal Access Tokens, App Tokens
- Slack: Bot/User/App tokens
- Facebook: Access Tokens (plain & base64)

**Generic Secrets:**
- API Keys (generic pattern)
- JWT Tokens
- Private Keys: PEM & PGP (multiline support)

**Sensitive Data (PII/PCI/PHI):**
- U.S. Social Security Numbers
- Credit Cards: Visa, Mastercard, Discover, JCB, Amex
- Email Addresses
- Phone Numbers, MAC Addresses, IBAN Numbers
- IPv6 Addresses
- Personal Data: First Name, Last Name, City, Zip

### Advanced Features

**1. Exclusion Logic** (from `processors/exclusion.go`)
Automatically filters out fake/test secrets:
- Regex patterns for test keywords (TEST, EXAMPLE, DUMMY, FAKE, MOCK, etc.)
- Placeholder detection: `<API_KEY>`, `{API_KEY}`, `${API_KEY}`
- Repeated characters: `000000000000`, `XXXXXXXXXXXX`
- Custom exclusion keywords via CLI

**2. Validation Functions** (from `processors/`)
- **Luhn Algorithm**: Validates credit card numbers
- **IBAN Validation**: ISO 13616 compliant
- **MAC Address Validation**: Standard format checking

**3. Multiline Pattern Support**
- Detects PEM private keys across multiple lines
- Detects PGP private key blocks
- Reports precise line/column information

**4. Secret Limiting**
- Per-secret-type limits (e.g., max 50 emails)
- Per-sensitivity limits (Secret/PII/PCI/PHI)
- Global total limit

## Usage

### Basic Scan
```bash
python3 linux_secret_scanner.py -r /path/to/scan -o results.json -c results.csv
```

### Scan with Sensitive Data (PII/PCI/PHI)
```bash
python3 linux_secret_scanner.py -r /path/to/scan --sensitive -o results.json -c results.csv
```

### Disable Exclusions (Show All Matches)
```bash
python3 linux_secret_scanner.py -r /path/to/scan --enable-exclusion=false -o results.json
```

### Custom Exclusions
```bash
python3 linux_secret_scanner.py -r /path/to/scan --custom-exclusions MYCOMPANY STAGING -o results.json
```

### Limiting Secrets
```bash
# Limit total secrets to 100
python3 linux_secret_scanner.py -r /path/to/scan --max-all 100 -o results.json

# Limit by sensitivity
python3 linux_secret_scanner.py -r /path/to/scan --max-secrets 50 --max-pii 100 --max-pci 10 -o results.json
```

### Performance Tuning
```bash
# Increase threads and max file size
python3 linux_secret_scanner.py -r /path/to/scan --threads 12 --max-bytes 20971520 -o results.json
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-r, --root` | Root path to scan | `.` |
| `--secrets` | Scan for secrets | `True` |
| `--sensitive` | Scan for PII/PCI/PHI | `False` |
| `-t, --threads` | Number of threads | `6` |
| `--max-bytes` | Max file size (bytes) | `10485760` (10MB) |
| `-o, --out-json` | JSON output file | `results.json` |
| `-c, --out-csv` | CSV output file | `results.csv` |
| `--no-skip` | Don't skip default dirs | `False` |
| `--follow-symlinks` | Follow symlinks | `False` |
| `--quiet` | Quiet mode | `False` |
| `--context` | Context chars around match | `40` |
| `--enable-exclusion` | Enable exclusion logic | `True` |
| `--custom-exclusions` | Custom exclusion keywords | `[]` |
| `--max-all` | Max total secrets (0=unlimited) | `0` |
| `--max-secrets` | Max Secret type | `0` |
| `--max-pii` | Max PII | `0` |
| `--max-pci` | Max PCI | `0` |
| `--max-phi` | Max PHI | `0` |

## Output Format

### JSON Output
```json
[
  {
    "file": "/path/to/file.txt",
    "line": 42,
    "secret_type": "aws-access-key",
    "sensitivity": "Secret",
    "secret": "AKIA****************",
    "start": 15,
    "end": 35,
    "seek_position": 1234,
    "context": "aws_access_key = AKIA****************"
  }
]
```

### CSV Output
Includes: file, line, secret_type, sensitivity, secret, start, end, seek_position, context

## Default Skipped Directories

For performance and noise reduction, these directories are skipped by default:
- `/proc`
- `/sys`
- `/dev`
- `/run`
- `/var/lib/docker`
- `/var/run`

Use `--no-skip` to scan these directories.

## Testing

A test file is included (`test_secrets.txt`) with various secret formats:

```bash
# Test the scanner
mkdir -p /tmp/secret_test
cp test_secrets.txt /tmp/secret_test/
python3 linux_secret_scanner.py -r /tmp/secret_test --sensitive -o test_results.json -c test_results.csv
```

## Implementation Notes

This script is a **faithful Python port** of the Go implementation with:

1. **Exact Regex Patterns**: All patterns copied verbatim from `object_secret_scanner.go`
2. **Same Exclusion Logic**: Implemented from `processors/exclusion.go`
3. **Same Validation**: Luhn, IBAN, and MAC validation from `processors/`
4. **Same Limiting**: Secret limiter logic from `secret_limiter.go`
5. **Same Multiline Handling**: Two-pass approach for PEM/PGP keys

## Comparison with Go Implementation

| Feature | Go Package | Python Script |
|---------|------------|---------------|
| Secret Patterns | ✅ All patterns | ✅ Identical |
| Exclusion Logic | ✅ Full | ✅ Full |
| Validation (Luhn/IBAN/MAC) | ✅ | ✅ |
| Multiline Support | ✅ | ✅ |
| Secret Limiting | ✅ | ✅ |
| Line/Column Info | ✅ | ✅ |
| Performance | ⚡ Native Go | 🐍 Python (slower) |

## Exit Codes

- `0`: No secrets found
- `3`: Secrets found (check output files)
- `2`: No valid regex patterns loaded
