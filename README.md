# guardspine-verify

> **Verify GuardSpine evidence bundles offline - no trust required.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/guardspine-verify.svg)](https://pypi.org/project/guardspine-verify/)

## Installation

```bash
pip install guardspine-verify
```

Or install from source:

```bash
git clone https://github.com/DNYoussef/guardspine-verify.git
cd guardspine-verify
pip install -e .
```

## Quick Start

```bash
# Verify a JSON bundle
guardspine-verify bundle.json

# Verify a ZIP export
guardspine-verify evidence-bundle-2024-01-15.zip

# Verbose output
guardspine-verify bundle.json --verbose

# Output JSON report
guardspine-verify bundle.json --format json > report.json

# Verify multiple bundles
guardspine-verify bundle1.json bundle2.json bundle3.json
```

## What It Verifies

| Check | Description |
|-------|-------------|
| Hash Chain | Previous hash references match |
| Root Hash | Computed Merkle root matches stored root |
| Content Hashes | Each item's content hash is valid |
| Signatures | Cryptographic signatures verify |
| Sequence | Chain sequence numbers are contiguous |
| AI Provenance | AI signer model IDs are present |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Bundle verified successfully |
| 1 | Verification failed |
| 2 | Invalid input (file not found, parse error) |

## Python API

```python
from guardspine_verify import verify_bundle, verify_bundle_data, VerificationResult

# Verify a bundle file
result: VerificationResult = verify_bundle("bundle.json")

if result.verified:
    print("Bundle verified!")
    print(f"Evidence items: {result.item_count}")
    print(f"Signatures: {result.signature_count}")
else:
    print(f"Verification failed: {result.errors}")

# Verify bundle data directly
import json
with open("bundle.json") as f:
    bundle = json.load(f)

result = verify_bundle_data(bundle)
print(f"Status: {result.status}")
print(f"Hash chain: {result.hash_chain_status}")
print(f"Signatures: {result.signature_status}")
```

## Verification Result

```python
@dataclass
class VerificationResult:
    verified: bool
    status: str  # "verified" | "mismatch" | "error"
    hash_chain_status: str
    root_hash_status: str
    content_hash_status: str
    signature_status: str
    item_count: int
    signature_count: int
    errors: list[str]
    warnings: list[str]
    verified_at: datetime
```

## Supported Algorithms

| Algorithm | Status |
|-----------|--------|
| SHA-256 | Supported |
| Ed25519 | Supported |
| RSA-SHA256 | Supported |
| ECDSA-P256 | Supported |

## Supported Input Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| JSON | `.json` | Single bundle file |
| ZIP | `.zip` | Exported bundle package |
| Directory | folder | Unpacked bundle with manifest |

## Batch Verification

```python
from guardspine_verify import verify_bundles

results = verify_bundles([
    "bundle1.json",
    "bundle2.json",
    "bundle3.json",
])

for path, result in results.items():
    status = "PASS" if result.verified else "FAIL"
    print(f"{path}: {status}")
```

## Integration with CI/CD

```yaml
# GitHub Actions
- name: Verify Evidence Bundles
  run: |
    pip install guardspine-verify
    guardspine-verify ./evidence/*.json
```

```yaml
# GitLab CI
verify-evidence:
  script:
    - pip install guardspine-verify
    - guardspine-verify ./evidence/*.json
```

## Security

This verifier:
- **Does not require network access**
- **Does not phone home**
- **Does not store any data**
- **Is fully auditable** (open source)
- **Has no external dependencies** for core verification

## Related Projects

| Project | Description |
|---------|-------------|
| [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) | Bundle specification |
| [GuardSpine](https://github.com/DNYoussef/GuardSpine) | Full governance platform |
| [guardspine-connector-template](https://github.com/DNYoussef/guardspine-connector-template) | Connector SDK |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 - See [LICENSE](LICENSE).

---

**GuardSpine**: Verifiable governance evidence you don't have to trust.
