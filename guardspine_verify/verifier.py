"""
Core verification logic for GuardSpine evidence bundles.
"""

import hashlib
import json
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
    """Convert object to canonical JSON bytes (RFC 8785 style)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash and return as 'sha256:hex' string."""
    h = hashlib.sha256(data).hexdigest()
    return f"sha256:{h}"


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
) -> VerificationResult:
    """
    Verify a bundle from a file path.

    Supports:
    - JSON files (.json)
    - ZIP exports (.zip)

    Args:
        path: Path to the bundle file
        public_key_pem: Optional PEM-encoded public key for signature verification

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

        return verify_bundle_data(bundle, public_key_pem=public_key_pem)

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


def _load_zip_bundle(path: Path) -> dict[str, Any]:
    """Load bundle from ZIP export."""
    with zipfile.ZipFile(path, "r") as zf:
        # Look for bundle.json in the ZIP
        for name in zf.namelist():
            if name.endswith("bundle.json"):
                with zf.open(name) as f:
                    return json.load(f)

        raise ValueError("No bundle.json found in ZIP file")


def verify_bundle_data(
    bundle: dict[str, Any],
    public_key_pem: bytes | None = None,
) -> VerificationResult:
    """
    Verify a bundle from its data dictionary.

    Performs all verification checks:
    1. Hash chain integrity
    2. Root hash validation
    3. Content hash validation
    4. Signature verification (cryptographic if public_key provided)

    Args:
        bundle: Bundle data as dictionary
        public_key_pem: Optional PEM-encoded public key for cryptographic verification

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

    # 4. Verify signatures (if any)
    signature_result = verify_signatures(bundle, public_key_pem=public_key_pem)
    signature_status = "verified" if signature_result["valid"] else "mismatch"
    if not signature_result["valid"]:
        errors.extend(signature_result.get("errors", []))
    warnings.extend(signature_result.get("warnings", []))
    details["signatures"] = signature_result

    # Overall result
    all_valid = (
        hash_chain_result["valid"]
        and root_hash_result["valid"]
        and content_hash_result["valid"]
        and signature_result["valid"]
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


def verify_hash_chain(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Verify the hash chain integrity.

    Checks:
    - Each entry's previous_hash matches the prior entry's content_hash
    - Sequence numbers are contiguous starting from 0

    Args:
        bundle: Bundle data

    Returns:
        Dict with 'valid' bool and optional 'errors' list
    """
    proof = bundle.get("immutability_proof")
    if not proof:
        return {"valid": True, "warnings": ["No immutability proof present"]}

    chain = proof.get("hash_chain", {})
    entries = chain.get("entries", [])

    if not entries:
        return {"valid": True, "warnings": ["Empty hash chain"]}

    errors: list[str] = []

    # Validate entry structure
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"Hash chain entry at position {i} is not a dict")
            return {"valid": False, "errors": errors, "entries_checked": 0}

    # Check sequence continuity
    for i, entry in enumerate(entries):
        if entry.get("sequence_number") != i:
            errors.append(
                f"Sequence gap at position {i}: expected {i}, got {entry.get('sequence_number')}"
            )

    # Check previous hash references
    for i in range(1, len(entries)):
        current = entries[i]
        previous = entries[i - 1]

        expected_prev = previous.get("content_hash")
        actual_prev = current.get("previous_hash")

        if expected_prev != actual_prev:
            errors.append(
                f"Hash chain broken at sequence {i}: "
                f"expected previous_hash={expected_prev}, got {actual_prev}"
            )

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
        return {"valid": True, "warnings": ["No immutability proof present"]}

    stored_root = proof.get("root_hash")
    if not stored_root:
        return {"valid": True, "warnings": ["No root hash present"]}

    chain = proof.get("hash_chain", {})
    entries = chain.get("entries", [])

    if not entries:
        return {"valid": True, "warnings": ["Empty hash chain"]}

    # Compute root hash by concatenating all content hashes
    content_hashes = [e.get("content_hash", "") for e in entries]

    # Validate hash format before concatenation
    import re
    _HEX_RE = re.compile(r"^[0-9a-f]{64}$")
    hash_values: list[str] = []
    for idx, h in enumerate(content_hashes):
        if not isinstance(h, str):
            return {
                "valid": False,
                "errors": [f"Hash chain entry {idx}: content_hash is not a string"],
            }
        raw = h.replace("sha256:", "", 1)
        if not _HEX_RE.match(raw):
            return {
                "valid": False,
                "errors": [
                    f"Hash chain entry {idx}: content_hash is not valid sha256 hex: {h!r}"
                ],
            }
        hash_values.append(raw)

    # Remove 'sha256:' prefix for concatenation
    concatenated = "".join(hash_values).encode("utf-8")

    computed_root = compute_sha256(concatenated)

    if computed_root != stored_root:
        return {
            "valid": False,
            "errors": [f"Root hash mismatch: computed={computed_root}, stored={stored_root}"],
            "computed": computed_root,
            "stored": stored_root,
        }

    return {"valid": True, "computed": computed_root, "stored": stored_root}


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
        return {"valid": True, "warnings": ["No evidence items"]}

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
            warnings.append(
                f"Signature {sig_id} by {signer_name}: "
                f"HMAC-SHA256 requires shared secret (not public key)"
            )
            verified_count += 1  # Format is valid
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
    """Build the canonical content that was signed for verification."""
    # Try new CodeGuard format first (hash_chain, summary, provenance)
    if "hash_chain" in bundle:
        canonical = json.dumps(
            {
                "hash_chain": bundle.get("hash_chain", {}),
                "summary": bundle.get("summary", {}),
                "provenance": bundle.get("provenance", {}),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return canonical.encode()

    # Try github-action format (bundle_id, hash_chain, summary)
    if "bundle_id" in bundle:
        canonical = json.dumps(
            {
                "bundle_id": bundle["bundle_id"],
                "hash_chain": bundle.get("hash_chain", {}),
                "summary": bundle.get("summary", {}),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return canonical.encode()

    # Fallback: use immutability_proof if present
    if "immutability_proof" in bundle:
        proof = bundle["immutability_proof"]
        canonical = json.dumps(proof, sort_keys=True, separators=(",", ":"))
        return canonical.encode()

    # Last resort: hash the entire bundle
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    return canonical.encode()


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
