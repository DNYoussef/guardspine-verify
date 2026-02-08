"""
Core verification logic for GuardSpine evidence bundles.
"""

import hashlib
import json
import math
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.exceptions import InvalidSignature
import base64


@dataclass
class VerificationResult:
    """Result of bundle verification."""

    verified: bool
    status: str  # "verified" | "mismatch" | "error"
    hash_chain_status: str
    root_hash_status: str
    content_hash_status: str
    signature_status: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)


def canonical_json(obj: Any) -> bytes:
    """Convert object to canonical JSON bytes (RFC 8785 compatible subset)."""
    return _serialize_value(obj).encode("utf-8")


def _serialize_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_serialize_value(v) for v in value) + "]"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            items.append(json.dumps(str(key), ensure_ascii=False) + ":" + _serialize_value(value[key]))
        return "{" + ",".join(items) + "}"
    # Fallback for non-JSON types
    return "null"


def _serialize_number(num: float) -> str:
    if isinstance(num, bool):
        return "true" if num else "false"
    if isinstance(num, int):
        return str(num)
    if not math.isfinite(num):
        return "null"
    # Align with @guardspine/kernel canonicalization rules.
    if num.is_integer():
        # Only emit non-exponent integers within safe range
        if abs(num) < 9_007_199_254_740_991 and abs(num) < 1e20:
            return str(int(num))
    # Use JSON serialization for floats (matches JS JSON.stringify)
    return json.dumps(num, ensure_ascii=False)


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash and return as 'sha256:hex' string."""
    h = hashlib.sha256(data).hexdigest()
    return f"sha256:{h}"


HIDDEN_TOKEN_RE = re.compile(r"\[HIDDEN:[A-Za-z0-9_-]{6,64}\]")
HIGH_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_.\-]{24,}")
HEX_64_RE = re.compile(r"^[a-f0-9]{64}$")


_ENTROPY_SKIP_KEYS = {"signatures", "signature_value", "public_key_id", "immutability_proof"}


def _walk_strings(value: Any, _parent_key: str | None = None):
    """Yield all string values from arbitrarily nested JSON-like data."""
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _walk_strings(item, _parent_key)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _ENTROPY_SKIP_KEYS or key.endswith("_hash"):
                continue
            if isinstance(key, str):
                yield key
            yield from _walk_strings(item, key)
        return


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_hash_or_digest(candidate: str) -> bool:
    low = candidate.lower()
    if low.startswith("sha256:"):
        return True
    if HEX_64_RE.match(low):
        return True
    if low.startswith(("md5:", "sha1:", "sha512:")):
        return True
    return False


def _has_mixed_charset(candidate: str) -> bool:
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    has_symbol = any(not c.isalnum() for c in candidate)
    return sum([has_lower, has_upper, has_digit, has_symbol]) >= 3


def _find_entropy_survivors(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Find likely secret-like survivors that escaped sanitization.

    This is heuristic only and intentionally conservative to reduce false positives.
    """
    survivors: list[dict[str, Any]] = []
    seen: set[str] = set()
    for text in _walk_strings(bundle):
        for match in HIGH_ENTROPY_CANDIDATE_RE.findall(text):
            candidate = match.strip()
            if (
                candidate in seen
                or _looks_like_hash_or_digest(candidate)
                or not _has_mixed_charset(candidate)
            ):
                continue
            entropy = _shannon_entropy(candidate)
            if entropy < 4.0:
                continue
            seen.add(candidate)
            survivors.append(
                {
                    "preview": candidate[:24] + ("..." if len(candidate) > 24 else ""),
                    "length": len(candidate),
                    "entropy": round(entropy, 3),
                }
            )
    return survivors


def verify_sanitization(
    bundle: dict[str, Any],
    require_sanitized: bool = False,
    fail_on_raw_entropy: bool = False,
) -> dict[str, Any]:
    """
    Verify optional sanitization attestation and redaction token consistency.
    """
    summary = bundle.get("sanitization")
    if not summary:
        if require_sanitized:
            return {
                "valid": False,
                "errors": ["Missing sanitization block (required by policy)"],
                "warnings": [],
                "token_count": 0,
                "unique_tokens": 0,
                "token_occurrences": {},
                "raw_entropy_survivors": [],
            }
        return {
            "valid": True,
            "errors": [],
            "warnings": ["No sanitization block present"],
            "token_count": 0,
            "unique_tokens": 0,
            "token_occurrences": {},
            "raw_entropy_survivors": [],
        }

    errors: list[str] = []
    warnings: list[str] = []

    for field in ("engine_name", "engine_version", "method", "token_format", "status"):
        if not isinstance(summary.get(field), str) or not summary.get(field):
            errors.append(f"sanitization.{field} must be a non-empty string")

    redaction_count = summary.get("redaction_count")
    if not isinstance(redaction_count, int) or redaction_count < 0:
        errors.append("sanitization.redaction_count must be a non-negative integer")
        redaction_count = 0

    if not isinstance(summary.get("redactions_by_type"), dict):
        errors.append("sanitization.redactions_by_type must be an object")

    if summary.get("token_format") != "[HIDDEN:<id>]":
        warnings.append("sanitization.token_format differs from canonical [HIDDEN:<id>] declaration")

    tokens: list[str] = []
    for text in _walk_strings(bundle):
        tokens.extend(HIDDEN_TOKEN_RE.findall(text))

    token_occurrences: dict[str, int] = {}
    for token in tokens:
        token_occurrences[token] = token_occurrences.get(token, 0) + 1

    if redaction_count is not None and len(tokens) != redaction_count:
        msg = f"sanitization.redaction_count={redaction_count} but {len(tokens)} [HIDDEN:*] token occurrences were found"
        if require_sanitized:
            errors.append(msg)
        else:
            warnings.append(msg)

    survivors = _find_entropy_survivors(bundle)
    if survivors:
        msg = f"Detected {len(survivors)} high-entropy survivor candidate(s) after sanitization"
        if fail_on_raw_entropy:
            errors.append(msg)
        else:
            warnings.append(msg)

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "token_count": len(tokens),
        "unique_tokens": len(token_occurrences),
        "token_occurrences": token_occurrences,
        "raw_entropy_survivors": survivors,
    }


def _validate_public_key_pem(public_key_pem: bytes) -> None:
    """
    Validate that the provided bytes are a well-formed PEM public key.

    Raises:
        ValueError: If the key cannot be loaded or is not a supported public key type.
    """
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid PEM public key: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Failed to load public key: {exc}") from exc

    supported_types = (
        ed25519.Ed25519PublicKey,
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
    )
    if not isinstance(key, supported_types):
        raise ValueError(
            f"Unsupported public key type: {type(key).__name__}. "
            f"Supported: Ed25519, RSA, ECDSA"
        )


def verify_bundle(
    path: str | Path,
    public_key_pem: bytes | None = None,
    hmac_secret: bytes | None = None,
    require_signatures: bool = False,
    check_sanitized: bool = False,
    require_sanitized: bool = False,
    fail_on_raw_entropy: bool = False,
) -> VerificationResult:
    """
    Verify a bundle from a file path.

    Supports:
    - JSON files (.json)
    - ZIP exports (.zip)

    Args:
        path: Path to the bundle file
        public_key_pem: Optional PEM-encoded public key for signature verification
        hmac_secret: Optional HMAC secret for HMAC-SHA256 signature verification
        require_signatures: If True, bundle MUST have valid signatures to pass
        check_sanitized: If True, evaluate sanitization attestations and token consistency
        require_sanitized: If True, fail verification if sanitization block is missing/invalid
        fail_on_raw_entropy: If True, entropy survivor candidates become hard failures

    Returns:
        VerificationResult with verification status
    """
    path = Path(path)

    # Validate public key upfront if provided
    if public_key_pem is not None:
        try:
            _validate_public_key_pem(public_key_pem)
        except ValueError as e:
            return VerificationResult(
                verified=False,
                status="error",
                hash_chain_status="unknown",
                root_hash_status="unknown",
                content_hash_status="unknown",
                signature_status="unknown",
                errors=[str(e)],
            )

    if not path.exists():
        return VerificationResult(
            verified=False,
            status="error",
            hash_chain_status="unknown",
            root_hash_status="unknown",
            content_hash_status="unknown",
            signature_status="unknown",
            errors=[f"File not found: {path}"],
        )

    try:
        if path.suffix == ".zip":
            bundle = _load_zip_bundle(path)
        elif path.suffix == ".json":
            with open(path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        else:
            return VerificationResult(
                verified=False,
                status="error",
                hash_chain_status="unknown",
                root_hash_status="unknown",
                content_hash_status="unknown",
                signature_status="unknown",
                errors=[f"Unsupported file format: {path.suffix}"],
            )

        return verify_bundle_data(
            bundle,
            public_key_pem=public_key_pem,
            hmac_secret=hmac_secret,
            require_signatures=require_signatures,
            check_sanitized=check_sanitized,
            require_sanitized=require_sanitized,
            fail_on_raw_entropy=fail_on_raw_entropy,
        )

    except json.JSONDecodeError as e:
        return VerificationResult(
            verified=False,
            status="error",
            hash_chain_status="unknown",
            root_hash_status="unknown",
            content_hash_status="unknown",
            signature_status="unknown",
            errors=[f"JSON parse error: {e}"],
        )
    except Exception as e:
        return VerificationResult(
            verified=False,
            status="error",
            hash_chain_status="unknown",
            root_hash_status="unknown",
            content_hash_status="unknown",
            signature_status="unknown",
            errors=[f"Verification error: {e}"],
        )


# ZIP safety limits
MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_ZIP_ENTRIES = 1000
MAX_BUNDLE_JSON_SIZE = 50 * 1024 * 1024  # 50 MB


def _load_zip_bundle(path: Path) -> dict[str, Any]:
    """
    Load bundle from ZIP export with safety limits.

    Security:
    - Rejects ZIP files larger than MAX_ZIP_SIZE_BYTES (100 MB)
    - Rejects ZIP files with more than MAX_ZIP_ENTRIES entries
    - Rejects bundle.json larger than MAX_BUNDLE_JSON_SIZE (50 MB)
    - Prevents zip bomb attacks by checking compressed vs uncompressed ratio
    """
    # Check total ZIP file size
    zip_size = path.stat().st_size
    if zip_size > MAX_ZIP_SIZE_BYTES:
        raise ValueError(
            f"ZIP file too large: {zip_size:,} bytes (max: {MAX_ZIP_SIZE_BYTES:,} bytes)"
        )

    with zipfile.ZipFile(path, "r") as zf:
        # Check number of entries (zip bomb protection)
        entry_count = len(zf.namelist())
        if entry_count > MAX_ZIP_ENTRIES:
            raise ValueError(
                f"ZIP has too many entries: {entry_count} (max: {MAX_ZIP_ENTRIES})"
            )

        # Look for bundle.json in the ZIP
        for name in zf.namelist():
            if name.endswith("bundle.json"):
                # Check uncompressed size (zip bomb protection)
                info = zf.getinfo(name)
                if info.file_size > MAX_BUNDLE_JSON_SIZE:
                    raise ValueError(
                        f"bundle.json too large: {info.file_size:,} bytes "
                        f"(max: {MAX_BUNDLE_JSON_SIZE:,} bytes)"
                    )

                # Check compression ratio (zip bomb protection)
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > 100:  # Suspicious compression ratio
                        raise ValueError(
                            f"Suspicious compression ratio: {ratio:.1f}x "
                            f"(possible zip bomb)"
                        )

                with zf.open(name) as f:
                    return json.load(f)

        raise ValueError("No bundle.json found in ZIP file")


# Supported bundle versions
SUPPORTED_VERSIONS = ["0.2.0", "0.2.1"]


def verify_bundle_data(
    bundle: dict[str, Any],
    public_key_pem: bytes | None = None,
    hmac_secret: bytes | None = None,
    require_signatures: bool = False,
    check_sanitized: bool = False,
    require_sanitized: bool = False,
    fail_on_raw_entropy: bool = False,
) -> VerificationResult:
    """
    Verify a bundle from its data dictionary.

    Performs all verification checks:
    1. Version validation (MUST be in SUPPORTED_VERSIONS)
    2. Hash chain integrity
    3. Root hash validation
    4. Content hash validation
    5. Signature verification (cryptographic if public_key provided)
    6. Optional sanitization policy checks (if enabled)

    Args:
        bundle: Bundle data as dictionary
        public_key_pem: Optional PEM-encoded public key for cryptographic verification
        hmac_secret: Optional HMAC secret for HMAC-SHA256 signature verification
        require_signatures: If True, bundle MUST have valid signatures to pass
        check_sanitized: If True, evaluate sanitization attestations and token consistency
        require_sanitized: If True, fail when sanitization block is missing/invalid
        fail_on_raw_entropy: If True, entropy survivor candidates become hard failures

    Returns:
        VerificationResult with verification status
    """
    # Validate public key upfront if provided
    if public_key_pem is not None:
        try:
            _validate_public_key_pem(public_key_pem)
        except ValueError as e:
            return VerificationResult(
                verified=False,
                status="error",
                hash_chain_status="unknown",
                root_hash_status="unknown",
                content_hash_status="unknown",
                signature_status="unknown",
                errors=[str(e)],
            )

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {}

    # 0. Verify bundle version
    version = bundle.get("version")
    if not version:
        errors.append("Missing required field: version")
    elif version not in SUPPORTED_VERSIONS:
        errors.append(
            f"Unsupported bundle version: {version}. "
            f"Supported: {', '.join(SUPPORTED_VERSIONS)}"
        )
    details["version"] = {"value": version, "supported": version in SUPPORTED_VERSIONS if version else False}

    # 1. Verify hash chain
    hash_chain_result = verify_hash_chain(bundle)
    hash_chain_status = "verified" if hash_chain_result["valid"] else "mismatch"
    if not hash_chain_result["valid"]:
        errors.extend(hash_chain_result.get("errors", []))
    details["hash_chain"] = hash_chain_result

    # 2. Verify root hash
    root_hash_result = verify_root_hash(bundle)
    root_hash_status = "verified" if root_hash_result["valid"] else "mismatch"
    if not root_hash_result["valid"]:
        errors.extend(root_hash_result.get("errors", []))
    details["root_hash"] = root_hash_result

    # 3. Verify content hashes
    content_hash_result = verify_content_hashes(bundle)
    content_hash_status = "verified" if content_hash_result["valid"] else "mismatch"
    if not content_hash_result["valid"]:
        errors.extend(content_hash_result.get("errors", []))
    details["content_hashes"] = content_hash_result

    # 3.5. Verify chain-to-items BINDING (Task #11, #12, #13)
    # Every item MUST have a corresponding chain entry with matching item_id
    binding_result = verify_chain_to_items_binding(bundle)
    if not binding_result["valid"]:
        errors.extend(binding_result.get("errors", []))
    details["chain_binding"] = binding_result

    # 4. Verify signatures (if any)
    signature_result = verify_signatures(bundle, public_key_pem=public_key_pem, hmac_secret=hmac_secret)
    signature_status = "verified" if signature_result["valid"] else "mismatch"
    if not signature_result["valid"]:
        errors.extend(signature_result.get("errors", []))
    warnings.extend(signature_result.get("warnings", []))
    details["signatures"] = signature_result

    # 5. Check signature requirement
    signatures_present = len(bundle.get("signatures", [])) > 0
    if require_signatures and not signatures_present:
        errors.append(
            "Bundle MUST have signatures when require_signatures=True, but none present"
        )
        signature_status = "missing"
    elif require_signatures and not signature_result.get("cryptographically_verified", False):
        # If signatures are present but not cryptographically verified
        if public_key_pem is None and hmac_secret is None:
            errors.append(
                "require_signatures=True but no public_key_pem or hmac_secret provided "
                "for cryptographic verification"
            )
            signature_status = "unverified"

    # 6. Optional sanitization checks
    sanitization_checked = check_sanitized or require_sanitized or fail_on_raw_entropy
    sanitization_valid = True
    if sanitization_checked:
        sanitization_result = verify_sanitization(
            bundle,
            require_sanitized=require_sanitized,
            fail_on_raw_entropy=fail_on_raw_entropy,
        )
        details["sanitization"] = sanitization_result
        sanitization_valid = sanitization_result.get("valid", False)
        if not sanitization_valid:
            errors.extend(sanitization_result.get("errors", []))
        warnings.extend(sanitization_result.get("warnings", []))

    # Overall result
    version_valid = version in SUPPORTED_VERSIONS if version else False
    all_valid = (
        version_valid
        and hash_chain_result["valid"]
        and root_hash_result["valid"]
        and content_hash_result["valid"]
        and binding_result["valid"]  # Chain-to-items binding
        and signature_result["valid"]
        and (sanitization_valid or not sanitization_checked)
        and (not require_signatures or signature_result.get("cryptographically_verified", False))
    )

    return VerificationResult(
        verified=all_valid,
        status="verified" if all_valid else "mismatch",
        hash_chain_status=hash_chain_status,
        root_hash_status=root_hash_status,
        content_hash_status=content_hash_status,
        signature_status=signature_status,
        errors=errors,
        warnings=warnings,
        details=details,
    )


def _extract_chain_entries(proof: dict[str, Any]) -> list[dict[str, Any]]:
    """Return hash chain entries for both v0.2.0 and legacy formats."""
    chain = proof.get("hash_chain")
    if isinstance(chain, list):
        return chain
    if isinstance(chain, dict):
        entries = chain.get("entries")
        if isinstance(entries, list):
            return entries
    return []


def verify_hash_chain(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Verify the hash chain integrity (v0.2.0 schema).

    Checks:
    - Each entry has item_id and content_type fields
    - chain_hash = SHA-256(\"sequence|item_id|content_type|content_hash|previous_hash\")
    - Sequence numbers are contiguous starting from 0
    - Previous chain_hash linkage is correct

    Args:
        bundle: Bundle data

    Returns:
        Dict with 'valid' bool and optional 'errors' list
    """
    proof = bundle.get("immutability_proof")
    if not proof:
        return {"valid": False, "errors": ["Missing immutability_proof"]}

    entries = _extract_chain_entries(proof)
    if not entries:
        return {"valid": False, "errors": ["Empty hash chain"]}

    errors: list[str] = []

    # Validate entry structure
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"Hash chain entry at position {i} is not a dict")
            return {"valid": False, "errors": errors, "entries_checked": 0}

    # Check sequence continuity and required v0.2.0 fields
    for i, entry in enumerate(entries):
        seq = entry.get("sequence", entry.get("sequence_number"))
        if seq != i:
            errors.append(
                f"Sequence gap at position {i}: expected {i}, got {seq}"
            )
        if "item_id" not in entry:
            errors.append(f"Hash chain entry {i}: missing required field 'item_id'")
        if "content_type" not in entry:
            errors.append(f"Hash chain entry {i}: missing required field 'content_type'")

    # Recompute and verify chain_hash for each entry
    previous_hash = "genesis"
    for i, entry in enumerate(entries):
        seq = entry.get("sequence", entry.get("sequence_number", i))
        item_id = entry.get("item_id", "")
        content_type = entry.get("content_type", "")
        content_hash = entry.get("content_hash", "")
        prev_hash = entry.get("previous_hash", "")

        # Verify previous_hash linkage
        if i > 0 and prev_hash != previous_hash:
            errors.append(
                f"Hash chain broken at sequence {i}: "
                f"expected previous_hash={previous_hash}, got {prev_hash}"
            )

        # Recompute chain_hash: SHA-256(\"sequence|item_id|content_type|content_hash|previous_hash\")
        chain_input = f"{seq}|{item_id}|{content_type}|{content_hash}|{prev_hash}"
        computed_chain_hash = compute_sha256(chain_input.encode("utf-8"))

        stored_chain_hash = entry.get("chain_hash")
        if not stored_chain_hash:
            errors.append(f"Hash chain entry {i}: missing chain_hash")
        elif computed_chain_hash != stored_chain_hash:
            errors.append(
                f"Hash chain entry {i}: chain_hash mismatch "
                f"(computed={computed_chain_hash}, stored={stored_chain_hash})"
            )

        # Use the stored chain_hash as previous_hash for the next entry
        previous_hash = stored_chain_hash or computed_chain_hash

    return {"valid": len(errors) == 0, "errors": errors, "entries_checked": len(entries)}


def verify_root_hash(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Verify the Merkle root hash.

    Computes the root hash from all content hashes and compares
    to the stored root_hash.

    Args:
        bundle: Bundle data

    Returns:
        Dict with 'valid' bool and optional 'errors' list
    """
    proof = bundle.get("immutability_proof")
    if not proof:
        return {"valid": False, "errors": ["Missing immutability_proof"]}

    stored_root = proof.get("root_hash")
    if not stored_root:
        return {"valid": False, "errors": ["Missing root_hash in immutability_proof"]}

    entries = _extract_chain_entries(proof)
    if not entries:
        return {"valid": False, "errors": ["Empty hash chain"]}

    # Compute root hash as SHA-256 of concatenation of all chain_hash values
    _HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
    chain_hash_values: list[str] = []
    for idx, entry in enumerate(entries):
        ch = entry.get("chain_hash", "")
        if not isinstance(ch, str):
            return {
                "valid": False,
                "errors": [f"Hash chain entry {idx}: chain_hash is not a string"],
            }
        if not _HASH_RE.match(ch):
            return {
                "valid": False,
                "errors": [
                    f"Hash chain entry {idx}: chain_hash is not valid sha256:hex: {ch!r}"
                ],
            }
        chain_hash_values.append(ch)

    concatenated = "".join(chain_hash_values).encode("utf-8")
    computed_root = compute_sha256(concatenated)

    if computed_root != stored_root:
        return {
            "valid": False,
            "errors": [f"Root hash mismatch: computed={computed_root}, stored={stored_root}"],
            "computed": computed_root,
            "stored": stored_root,
        }

    return {"valid": True, "computed": computed_root, "stored": stored_root}


def verify_chain_to_items_binding(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Verify chain-to-items BINDING: every item has a matching chain entry.

    This is a critical security check that ensures:
    1. COUNT: Number of items == number of chain entries
    2. BINDING: Each item has a chain entry with matching item_id
    3. CROSS-REFERENCE: Chain content_hash matches item content_hash

    Without this check, an attacker could add items not covered by the hash chain,
    which would then be "unbound" and could be modified without detection.

    Args:
        bundle: Bundle data

    Returns:
        Dict with 'valid' bool and 'errors' list
    """
    items = bundle.get("items", [])
    proof = bundle.get("immutability_proof", {})
    chain = _extract_chain_entries(proof)

    errors: list[str] = []

    # COUNT validation (Task #12)
    if len(items) != len(chain):
        errors.append(
            f"Chain-to-items COUNT mismatch: {len(items)} items but {len(chain)} chain entries. "
            f"Every item MUST have exactly one chain entry."
        )

    # Build lookup for chain entries by item_id
    chain_by_item_id: dict[str, dict[str, Any]] = {}
    for entry in chain:
        entry_item_id = entry.get("item_id")
        if entry_item_id:
            if entry_item_id in chain_by_item_id:
                errors.append(
                    f"Duplicate item_id in hash chain: '{entry_item_id}'. "
                    f"Each item_id MUST appear exactly once."
                )
            chain_by_item_id[entry_item_id] = entry

    # BINDING validation (Task #11) - every item has a chain entry
    for idx, item in enumerate(items):
        item_id = item.get("item_id")
        if not item_id:
            errors.append(f"Item at index {idx}: missing item_id")
            continue

        if item_id not in chain_by_item_id:
            errors.append(
                f"UNBOUND item: '{item_id}' has no matching chain entry. "
                f"Item is not covered by the hash chain and cannot be verified."
            )
            continue

        # CROSS-REFERENCE validation (Task #13) - content_hash matches
        chain_entry = chain_by_item_id[item_id]
        item_content_hash = item.get("content_hash", "")
        chain_content_hash = chain_entry.get("content_hash", "")

        if item_content_hash != chain_content_hash:
            errors.append(
                f"Item '{item_id}': content_hash mismatch. "
                f"Item has {item_content_hash[:20]}..., chain has {chain_content_hash[:20]}..."
            )

        # Verify content_type matches
        item_content_type = item.get("content_type", "")
        chain_content_type = chain_entry.get("content_type", "")
        if item_content_type != chain_content_type:
            errors.append(
                f"Item '{item_id}': content_type mismatch. "
                f"Item has '{item_content_type}', chain has '{chain_content_type}'"
            )

        # Verify sequence matches position
        item_sequence = item.get("sequence")
        chain_sequence = chain_entry.get("sequence")
        if item_sequence != chain_sequence:
            errors.append(
                f"Item '{item_id}': sequence mismatch. "
                f"Item has sequence {item_sequence}, chain has {chain_sequence}"
            )

    # Check for chain entries without items (orphaned chain entries)
    item_ids = {item.get("item_id") for item in items if item.get("item_id")}
    for chain_item_id in chain_by_item_id:
        if chain_item_id not in item_ids:
            errors.append(
                f"ORPHAN chain entry: '{chain_item_id}' has no matching item. "
                f"Chain entry references non-existent item."
            )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "items_checked": len(items),
        "chain_entries_checked": len(chain),
    }


def verify_content_hashes(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Verify content hashes of all evidence items.

    Computes SHA-256 of each item's content and compares
    to the stored content_hash.

    Args:
        bundle: Bundle data

    Returns:
        Dict with 'valid' bool and optional 'errors' list
    """
    items = bundle.get("items", [])
    if not items:
        return {"valid": False, "errors": ["No evidence items"]}

    errors: list[str] = []
    checked = 0

    for item in items:
        item_id = item.get("item_id", "unknown")
        stored_hash = item.get("content_hash")
        content = item.get("content")

        if not stored_hash:
            errors.append(f"Item {item_id}: missing content_hash")
            continue

        if content is None:
            errors.append(f"Item {item_id}: missing content")
            continue

        computed_hash = compute_sha256(canonical_json(content))

        if computed_hash != stored_hash:
            errors.append(
                f"Item {item_id}: content hash mismatch "
                f"(computed={computed_hash[:20]}..., stored={stored_hash[:20]}...)"
            )

        checked += 1

    return {"valid": len(errors) == 0, "errors": errors, "items_checked": checked}


def verify_signatures(
    bundle: dict[str, Any],
    public_key_pem: bytes | None = None,
    hmac_secret: bytes | None = None,
) -> dict[str, Any]:
    """
    Verify cryptographic signatures.

    When public_key_pem is provided, performs actual cryptographic verification.
    Otherwise, only validates signature format and structure.

    Args:
        bundle: Bundle data
        public_key_pem: Optional PEM-encoded public key for cryptographic verification

    Returns:
        Dict with 'valid' bool, 'errors' list, and 'warnings' list
    """
    signatures = bundle.get("signatures", [])

    if not signatures:
        return {
            "valid": True,
            "warnings": ["No signatures present - bundle is unsigned"],
            "signatures_checked": 0,
            "cryptographically_verified": False,
        }

    errors: list[str] = []
    warnings: list[str] = []
    verified_count = 0
    crypto_verified_count = 0

    for sig in signatures:
        sig_id = sig.get("signature_id", sig.get("signer", "unknown"))
        algorithm = sig.get("algorithm") or sig.get("type")
        signer = sig.get("signer", {})
        signature_value = sig.get("signature_value") or sig.get("signature")

        # Handle both old schema (signer as dict) and new schema (signer as string)
        if isinstance(signer, dict):
            signer_name = signer.get("display_name", "unknown")
            signer_type = signer.get("signer_type", "unknown")
        else:
            signer_name = signer
            signer_type = "service"

        # Validate required fields
        if not algorithm:
            errors.append(f"Signature {sig_id}: missing algorithm/type")
            continue

        _SUPPORTED_ALGORITHMS = {
            "ed25519", "rsa-sha256", "ecdsa-p256", "ecdsa-sha256", "hmac-sha256",
        }
        if algorithm not in _SUPPORTED_ALGORITHMS:
            errors.append(f"Signature {sig_id}: unsupported algorithm {algorithm}")
            continue

        if not signature_value:
            errors.append(f"Signature {sig_id}: missing signature_value/signature")
            continue

        # Validate base64 encoding (skip for HMAC which may be hex)
        if algorithm != "hmac-sha256":
            try:
                base64.b64decode(signature_value)
            except Exception:
                errors.append(f"Signature {sig_id}: invalid base64 encoding")
                continue

        # Attempt cryptographic verification if public key is provided
        if public_key_pem and algorithm != "hmac-sha256":
            # Build content to verify (must match what was signed)
            content_to_verify = _build_content_for_verification(bundle)

            is_valid = verify_signature_with_key(
                signature=sig,
                public_key_pem=public_key_pem,
                content_to_verify=content_to_verify,
            )

            if is_valid:
                crypto_verified_count += 1
                verified_count += 1
            else:
                errors.append(
                    f"Signature {sig_id} by {signer_name}: "
                    f"CRYPTOGRAPHIC VERIFICATION FAILED"
                )
        elif algorithm == "hmac-sha256":
            if not hmac_secret:
                errors.append(
                    f"Signature {sig_id} by {signer_name}: "
                    f"HMAC-SHA256 requires a secret parameter but none was provided"
                )
                continue
            import hmac as hmac_mod
            content_to_verify = _build_content_for_verification(bundle)
            expected_mac = hmac_mod.new(hmac_secret, content_to_verify, hashlib.sha256).hexdigest()
            # signature_value may be hex or base64-encoded hex
            if hmac_mod.compare_digest(expected_mac, signature_value):
                crypto_verified_count += 1
                verified_count += 1
            else:
                errors.append(
                    f"Signature {sig_id} by {signer_name}: "
                    f"HMAC-SHA256 VERIFICATION FAILED"
                )
        elif not public_key_pem:
            warnings.append(
                f"Signature {sig_id} by {signer_name} ({algorithm}): "
                f"FORMAT VALID ONLY - no public key provided for cryptographic verification"
            )
            verified_count += 1  # Format is valid

    # Determine overall validity
    # If public key was provided, require at least one crypto verification
    if public_key_pem:
        valid = len(errors) == 0 and crypto_verified_count > 0
    else:
        valid = len(errors) == 0

    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "signatures_checked": verified_count,
        "signatures_total": len(signatures),
        "cryptographically_verified": crypto_verified_count > 0,
        "crypto_verified_count": crypto_verified_count,
    }


def _build_content_for_verification(bundle: dict[str, Any]) -> bytes:
    """Build the canonical content that was signed for verification.

    The bundle is serialized WITHOUT the 'signatures' array so that the
    signature can be verified against the content it actually covers.
    """
    # Strip signatures from the bundle before canonicalization
    bundle_without_sigs = {k: v for k, v in bundle.items() if k != "signatures"}

    return canonical_json(bundle_without_sigs)


def verify_signature_with_key(
    signature: dict[str, Any],
    public_key_pem: bytes,
    content_to_verify: bytes,
) -> bool:
    """
    Verify a signature using the provided public key.

    Args:
        signature: Signature object from bundle
        public_key_pem: PEM-encoded public key
        content_to_verify: The content that was signed

    Returns:
        True if signature is valid, False otherwise
    """
    algorithm = signature.get("algorithm")
    raw_sig = signature.get("signature_value") or signature.get("signature", "")

    # Validate signature_value is a string before decoding
    if not isinstance(raw_sig, str) or not raw_sig:
        return False

    try:
        signature_value = base64.b64decode(raw_sig)
    except Exception:
        return False

    if not isinstance(public_key_pem, bytes) or not public_key_pem:
        return False

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError):
        return False

    try:
        if algorithm == "ed25519":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(signature_value, content_to_verify)
            return True

        elif algorithm == "rsa-sha256":
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            public_key.verify(
                signature_value,
                content_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True

        elif algorithm in ("ecdsa-p256", "ecdsa-sha256"):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            public_key.verify(
                signature_value,
                content_to_verify,
                ec.ECDSA(hashes.SHA256()),
            )
            return True

        return False

    except InvalidSignature:
        return False
    except Exception:
        # Log-worthy but not a crash -- key/sig mismatch or corrupt data
        return False
