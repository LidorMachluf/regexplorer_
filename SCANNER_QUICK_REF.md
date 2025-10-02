# Linux Secret Scanner - Quick Reference

## Files Created
- `linux_secret_scanner.py` - Main scanner (25KB)
- `linux_secret_scanner_README.md` - Full documentation
- `SCANNER_QUICK_REF.md` - This quick reference

## One-Line Examples

```bash
# Basic scan
python3 linux_secret_scanner.py -r /app -o secrets.json -c secrets.csv

# With PII/PCI/PHI
python3 linux_secret_scanner.py -r /app --sensitive -o secrets.json -c secrets.csv

# Full system scan (careful!)
python3 linux_secret_scanner.py -r / --max-all 1000 -o secrets.json -c secrets.csv

# With custom exclusions
python3 linux_secret_scanner.py -r /app --custom-exclusions COMPANY STAGING -o secrets.json

# High performance
python3 linux_secret_scanner.py -r /app --threads 16 --max-bytes 52428800 -o secrets.json
```

## Key Options

| Flag | Description | Default |
|------|-------------|---------|
| `-r, --root` | Directory to scan | `.` |
| `--secrets` | Scan for secrets | `True` |
| `--sensitive` | Include PII/PCI/PHI | `False` |
| `-t, --threads` | Number of threads | `6` |
| `--max-bytes` | Max file size | `10MB` |
| `--enable-exclusion` | Filter fake secrets | `True` |
| `--custom-exclusions` | Custom keywords | `[]` |
| `--max-all` | Total limit | `0` (unlimited) |
| `--quiet` | Quiet mode | `False` |

## What Gets Detected

**Secrets (30+ patterns):**
- AWS, Azure, Google Cloud credentials
- GitHub, Slack, Facebook tokens
- API keys, JWT tokens
- PEM/PGP private keys

**Sensitive Data (PII/PCI/PHI):**
- SSN, Credit Cards, IBAN
- Emails, Phone numbers, MAC addresses
- Personal data fields

## What Gets Excluded

- Test/fake keywords: TEST, EXAMPLE, DUMMY, FAKE, MOCK, TEMPLATE, SAMPLE, DEMO
- Placeholders: `<API_KEY>`, `{TOKEN}`, `${SECRET}`
- Repeated chars: `000000000000`, `XXXXXXXXXXXX`
- Invalid credit cards (Luhn check)
- Invalid IBANs/MACs

## Output Format

**JSON:**
```json
{
  "file": "/path/to/file",
  "line": 42,
  "secret_type": "aws-access-key",
  "sensitivity": "Secret",
  "secret": "AKIA...",
  "start": 10,
  "end": 30,
  "seek_position": 1234,
  "context": "..."
}
```

**CSV:** Same fields, tab-separated for easy viewing

## Exit Codes
- `0` = No secrets found
- `3` = Secrets found (check output)
- `2` = No valid patterns

## Common Workflows

### 1. Docker Container Scan
```bash
docker cp linux_secret_scanner.py container_id:/tmp/
docker exec container_id python3 /tmp/linux_secret_scanner.py -r / --max-all 500 -o /tmp/secrets.json
docker cp container_id:/tmp/secrets.json ./
```

### 2. EC2 Instance Scan
```bash
scp linux_secret_scanner.py ec2-user@instance:/tmp/
ssh ec2-user@instance "python3 /tmp/linux_secret_scanner.py -r /var/www --sensitive -o /tmp/secrets.json"
scp ec2-user@instance:/tmp/secrets.json ./
```

### 3. Kubernetes Pod Scan
```bash
kubectl cp linux_secret_scanner.py pod-name:/tmp/
kubectl exec pod-name -- python3 /tmp/linux_secret_scanner.py -r / --max-all 500 -o /tmp/secrets.json
kubectl cp pod-name:/tmp/secrets.json ./secrets.json
```

### 4. CI/CD Pipeline
```bash
python3 linux_secret_scanner.py -r . --quiet -o secrets.json
if [ $? -eq 3 ]; then
  echo "ERROR: Secrets detected!"
  cat secrets.json
  exit 1
fi
```

## Comparison with Go Implementation

| Feature | Go | Python |
|---------|----|----|
| Regex Patterns | ✅ | ✅ Identical |
| Exclusion Logic | ✅ | ✅ Identical |
| Validation (Luhn/IBAN) | ✅ | ✅ Identical |
| Multiline Support | ✅ | ✅ Identical |
| Secret Limiting | ✅ | ✅ Identical |
| Performance | ⚡ Fast | 🐍 Slower |

## Tips

1. **Start with limits**: Use `--max-all 100` to avoid overwhelming output
2. **Use exclusions**: Add company-specific test keywords with `--custom-exclusions`
3. **Test on small dirs first**: Verify patterns before full system scan
4. **Quiet mode for scripts**: Use `--quiet` and check exit code
5. **Increase threads**: Use `--threads 16` on large filesystems
