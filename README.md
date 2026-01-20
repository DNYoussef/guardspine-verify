# guardspine-verify

> **Verify GuardSpine evidence bundles offline - no trust required.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## Installation

```bash
pip install guardspine-verify
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
```

## What It Verifies

| Check | Description |
|-------|-------------|
| Hash Chain | Previous hash references match |
| Root Hash | Computed Merkle root matches stored root |
| Content Hashes | Each item's content hash is valid |
| Signatures | Cryptographic signatures verify |
| Sequence | Chain sequence numbers are contiguous |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Bundle verified successfully |
| 1 | Verification failed |
| 2 | Invalid input (file not found, parse error) |

## Python API

```python
from guardspine_verify import verify_bundle, VerificationResult

# Verify a bundle file
result: VerificationResult = verify_bundle("bundle.json")

if result.verified:
    print("Bundle verified!")
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

## Security

This verifier:
- **Does not require network access**
- **Does not phone home**
- **Does not store any data**
- **Is fully auditable** (open source)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 - See [LICENSE](LICENSE).

---

**GuardSpine**: Verifiable governance evidence you don't have to trust.
