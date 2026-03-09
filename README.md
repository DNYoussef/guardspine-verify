# guardspine-verify

> **Verify GuardSpine evidence bundles offline -- no trust required.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/guardspine-verify.svg)](https://pypi.org/project/guardspine-verify/)

**Spec Version**: v0.2.0 + v0.2.1 | **Package Version**: 0.2.1

## What This Is

An offline CLI and Python library for verifying GuardSpine evidence bundles.
Given a sealed bundle (JSON or ZIP), it recomputes every hash from scratch and
compares against stored values. If anything was tampered with, verification fails.

No network access. No trust assumptions. Fully auditable.

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

### Dependencies

- `guardspine-kernel>=0.2.0` -- canonical JSON serialization (RFC 8785). The
  verifier delegates all canonical JSON computation to the kernel to guarantee
  cross-language hash parity.
- `cryptography>=41.0` -- signature verification (Ed25519, RSA, ECDSA).
- `click>=8.0` -- CLI framework.
- `rich>=13.0` -- terminal output formatting.
- `jsonschema>=4.0` -- schema validation.

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

# Verify with a public key (cryptographic signature check)
guardspine-verify bundle.json --public-key signer.pub
```

## How Verification Works

The verifier runs six checks in order:

1. **Version validation** -- bundle version must be `0.2.0` or `0.2.1`.

2. **Hash chain integrity** -- each chain entry's `chain_hash` is recomputed as
   `SHA-256("sequence|item_id|content_type|content_hash|previous_hash")` and
   compared to the stored value. Previous-hash linkage is verified entry by
   entry, starting from `"genesis"`.

3. **Root hash validation** -- the Merkle root is recomputed as
   `SHA-256(concat(all chain_hash values))` and compared to the stored
   `root_hash`.

4. **Content hash validation** -- for each item, the content is serialized to
   canonical JSON (via `guardspine-kernel`) and hashed with SHA-256. The result
   must match the stored `content_hash`.

5. **Chain-to-items binding** -- every item must have exactly one chain entry
   with matching `item_id`, `content_hash`, `content_type`, and `sequence`.
   Unbound items and orphaned chain entries are both errors.

6. **Signature verification** -- validates signature format (algorithm,
   base64 encoding). When a PEM public key is provided via `--public-key`,
   performs cryptographic verification. Supports Ed25519, RSA-SHA256,
   ECDSA-P256, and HMAC-SHA256.

All content hashing uses canonical JSON from `guardspine-kernel` to guarantee
byte-identical output across Python, TypeScript, and Lean implementations.

## What It Verifies

| Check | Description |
|-------|-------------|
| **Version** | Bundle version must be `0.2.0` or `0.2.1` |
| **Hash Chain** | Each entry's `previous_hash` matches prior `chain_hash`; `chain_hash` recomputed and compared |
| **Chain Binding** | Chain entries map 1:1 to items (count, item_id, content_hash, content_type, sequence) |
| **Root Hash** | Computed Merkle root matches stored root |
| **Content Hashes** | Each item's `content_hash` matches SHA-256 of canonical JSON content |
| **Signatures** | Format validation; cryptographic verification with `--public-key` |
| **Sanitization** | Optional: `--check-sanitized` validates redaction metadata and token consistency |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Bundle verified successfully |
| 1 | Verification failed |
| 2 | Invalid input (file not found, parse error, bad public key) |

## CLI Reference

```
guardspine-verify BUNDLE_PATH [OPTIONS]

Options:
  -v, --verbose              Show detailed output
  -f, --format [text|json]   Output format (default: text)
  -k, --public-key PATH     PEM public key for cryptographic signature verification
  --check-sanitized          Validate sanitization attestations and [HIDDEN:*] token consistency
  --require-sanitized        Fail if sanitization block is missing or invalid
  --fail-on-raw-entropy      Treat high-entropy survivor candidates as hard failures
  --version                  Show version and exit
```

## Python API

```python
from guardspine_verify import verify_bundle, verify_bundle_data, VerificationResult

# Verify from file path
result = verify_bundle("bundle.json")

# Verify from dict
import json
with open("bundle.json") as f:
    bundle = json.load(f)

result = verify_bundle_data(bundle)

if result.verified:
    print("Bundle verified")
else:
    for error in result.errors:
        print(f"  - {error}")

# With cryptographic signature verification
with open("signer.pub", "rb") as f:
    public_key_pem = f.read()

result = verify_bundle("bundle.json", public_key_pem=public_key_pem)

# With sanitization checks
result = verify_bundle_data(
    bundle,
    check_sanitized=True,
    require_sanitized=True,
    fail_on_raw_entropy=True,
)
```

### VerificationResult

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
    details: dict[str, Any]
```

### Exported Functions

| Function | Purpose |
|----------|---------|
| `verify_bundle(path, ...)` | Verify from file path (JSON or ZIP) |
| `verify_bundle_data(bundle, ...)` | Verify from dict |
| `verify_hash_chain(bundle)` | Hash chain check only |
| `verify_root_hash(bundle)` | Root hash check only |
| `verify_content_hashes(bundle)` | Content hash check only |
| `verify_signatures(bundle, ...)` | Signature check only |
| `verify_sanitization(bundle, ...)` | Sanitization check only |

## Optional Lean Binary Integration

The verifier can optionally delegate hash-chain and content-hash verification
to a compiled Lean binary for formal-verification-grade assurance. This is
entirely optional -- the Python path is the default.

To enable Lean verification, set the `GUARDSPINE_LEAN_BIN` environment variable
to the path of the compiled GuardSpine Lean binary:

```bash
export GUARDSPINE_LEAN_BIN=/path/to/guardspine-lean
```

The Lean binary handles: version validation, hash chain verification, root hash
verification, content hash verification, and cross-check. Python continues to
handle signature verification, sanitization checks, and CLI formatting.

The shim communicates with the Lean binary via JSON over stdin/stdout with a
30-second timeout.

## Sanitization Verification

guardspine-verify validates [PII-Shield](https://github.com/aragossa/pii-shield)
sanitization attestations embedded in evidence bundles.

When bundles are sanitized before sealing (e.g., by codeguard-action), the
`sanitization` block attests what engine was used, how many redactions were
applied, and what token format was used. The verifier checks:

- `sanitization.redaction_count` matches actual `[HIDDEN:<id>]` token count
- Required fields: `engine_name`, `engine_version`, `method`, `token_format`, `status`
- `token_format` matches the canonical `[HIDDEN:<id>]` declaration
- High-entropy strings that survived sanitization (optional hard fail)

Hash fields (`content_hash`, `chain_hash`, `root_hash`, `*_hash`) and
cryptographic fields (`signatures`, `signature_value`, `public_key_id`,
`immutability_proof`) are excluded from entropy analysis to avoid false positives.

```bash
# Check sanitization attestation (warn on issues)
guardspine-verify bundle.json --check-sanitized

# Require sanitization (fail if missing or invalid)
guardspine-verify bundle.json --require-sanitized

# Treat post-sanitization high-entropy survivors as failures
guardspine-verify bundle.json --require-sanitized --fail-on-raw-entropy
```

## ZIP Safety

ZIP bundle loading enforces safety limits to prevent zip bombs and resource
exhaustion:

- Maximum ZIP file size: 100 MB
- Maximum entries per ZIP: 1000
- Maximum `bundle.json` size: 50 MB
- Compression ratio check: rejects ratios above 100x

## Supported Algorithms

| Algorithm | Type | Status |
|-----------|------|--------|
| SHA-256 | Hash | Content hashing, chain hashing |
| Ed25519 | Signature | Supported |
| RSA-SHA256 | Signature | Supported |
| ECDSA-P256 | Signature | Supported |
| HMAC-SHA256 | Signature | Supported (requires `--hmac-secret` or API param) |

## Supported Input Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| JSON | `.json` | Single bundle file |
| ZIP | `.zip` | Exported bundle package (must contain `bundle.json`) |

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

## Cross-Language Parity

guardspine-verify uses `guardspine-kernel` (the Python port of the canonical
TypeScript kernel) for all canonical JSON serialization. This guarantees that
bundles sealed by any language implementation (TypeScript, Python, Lean) produce
byte-identical hashes and can be verified by any other implementation.

Golden vector tests validate hash parity against
`guardspine-spec/fixtures/golden-vectors/v0.2.0.json`.

## Architecture

```
guardspine_verify/
  __init__.py          Public API exports
  cli.py               Click CLI (text + JSON output via Rich)
  verifier.py          Core verification logic
  lean_shim.py         Optional Lean binary bridge (GUARDSPINE_LEAN_BIN)
```

Key design decisions:

- **No duplicated code.** Canonical JSON delegates to `guardspine-kernel`.
  Previously this module carried its own 40-line implementation; that has been
  removed in favor of the single canonical source.
- **Lean is optional.** The `lean_shim.py` module discovers the Lean binary
  exclusively via the `GUARDSPINE_LEAN_BIN` environment variable. No
  hard-coded paths, no fallback search.
- **Signatures are Python-only.** Even when using the Lean backend, signature
  verification and sanitization checks run in Python (via `cryptography`).

## Related Projects

| Project | Description |
|---------|-------------|
| [guardspine-kernel](https://github.com/DNYoussef/guardspine-kernel) | Canonical TypeScript kernel |
| [guardspine-kernel-py](https://github.com/DNYoussef/guardspine-kernel-py) | Python port (canonical JSON, hashing) |
| [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) | Bundle specification |
| [GuardSpine](https://github.com/DNYoussef/GuardSpine) | Full governance platform |
| [codeguard-action](https://github.com/DNYoussef/codeguard-action) | GitHub Action for code review governance |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 -- See [LICENSE](LICENSE).
