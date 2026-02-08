import base64
import json
import sys
from copy import deepcopy
from pathlib import Path

from guardspine_verify import verify_bundle_data
from guardspine_verify.verifier import canonical_json, compute_sha256


def _load_vector(name: str) -> dict:
    path = Path(__file__).parent / "test_vectors" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _reseal_bundle(bundle: dict) -> dict:
    items = bundle.get("items", [])
    chain = []
    previous = "genesis"
    for idx, item in enumerate(items):
        item["sequence"] = idx
        item["content_hash"] = compute_sha256(canonical_json(item["content"]))
        chain_input = (
            f"{idx}|{item['item_id']}|{item['content_type']}|{item['content_hash']}|{previous}"
        ).encode("utf-8")
        chain_hash = compute_sha256(chain_input)
        chain.append(
            {
                "sequence": idx,
                "item_id": item["item_id"],
                "content_type": item["content_type"],
                "content_hash": item["content_hash"],
                "previous_hash": previous,
                "chain_hash": chain_hash,
            }
        )
        previous = chain_hash
    bundle["immutability_proof"]["hash_chain"] = chain
    bundle["immutability_proof"]["root_hash"] = compute_sha256(
        "".join(entry["chain_hash"] for entry in chain).encode("utf-8")
    )
    return bundle


def test_verify_accepts_valid_bundle_vector():
    bundle = _load_vector("valid-bundle.json")
    result = verify_bundle_data(bundle)
    assert result.verified is True
    assert result.status == "verified"


def test_verify_rejects_tampered_bundle_vector():
    bundle = _load_vector("tampered-hash-chain.json")
    result = verify_bundle_data(bundle)
    assert result.verified is False
    assert result.status in ("mismatch", "error")
    assert result.errors


def test_verify_external_signed_bundle_with_pem():
    bundle = _load_vector("external-signed-bundle.json")
    pem = (Path(__file__).parent / "test_vectors" / "external-public-key.pem").read_bytes()
    result = verify_bundle_data(bundle, public_key_pem=pem)
    assert result.verified is True
    assert result.status == "verified"
    assert result.details.get("signatures", {}).get("cryptographically_verified") is True


def test_verify_accepts_v021_bundle_version():
    bundle = _load_vector("valid-bundle.json")
    bundle["version"] = "0.2.1"
    result = verify_bundle_data(bundle)
    assert result.verified is True
    assert result.status == "verified"


def test_verify_sanitization_block_when_check_enabled():
    bundle = _load_vector("valid-bundle.json")
    bundle["version"] = "0.2.1"
    bundle["items"][0]["content"]["msg"] = "masked [HIDDEN:abc123] value"
    bundle["sanitization"] = {
        "engine_name": "pii-shield",
        "engine_version": "1.1.0",
        "method": "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": "sha256:1a2b3c4d",
        "redaction_count": 1,
        "redactions_by_type": {"email": 1},
        "status": "sanitized",
    }
    bundle = _reseal_bundle(bundle)

    result = verify_bundle_data(bundle, check_sanitized=True)
    assert result.verified is True
    assert result.details["sanitization"]["valid"] is True
    assert result.details["sanitization"]["token_count"] == 1


def test_require_sanitized_fails_when_missing():
    bundle = _load_vector("valid-bundle.json")
    result = verify_bundle_data(bundle, require_sanitized=True)
    assert result.verified is False
    assert any("Missing sanitization block" in err for err in result.errors)


def test_fail_on_raw_entropy_flags_survivors():
    bundle = _load_vector("valid-bundle.json")
    bundle = deepcopy(bundle)
    bundle["version"] = "0.2.1"
    bundle["items"][0]["content"]["leak"] = "EXAMPLE_HIGH_ENTROPY_TOKEN_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    bundle["sanitization"] = {
        "engine_name": "pii-shield",
        "engine_version": "1.1.0",
        "method": "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": "sha256:1a2b3c4d",
        "redaction_count": 0,
        "redactions_by_type": {},
        "status": "partial",
    }
    bundle = _reseal_bundle(bundle)

    result = verify_bundle_data(bundle, check_sanitized=True, fail_on_raw_entropy=True)
    assert result.verified is False
    assert any("high-entropy survivor" in err for err in result.errors)


def test_c6_require_signatures_rejects_without_crypto(tmp_path):
    """C6: require_signatures=True must fail when no public_key is provided,
    even if format-valid signatures are present."""
    bundle = deepcopy(_load_vector("valid-bundle.json"))
    bundle["signatures"] = [
        {
            "signature_id": "sig-fake-001",
            "algorithm": "ed25519",
            "signer": {"display_name": "test-signer", "signer_type": "service"},
            "signature_value": base64.b64encode(b"x" * 64).decode(),
            "signed_at": "2026-01-01T00:00:00Z",
        }
    ]
    result = verify_bundle_data(bundle, require_signatures=True)
    assert result.verified is False, (
        "require_signatures=True with no public_key must reject, "
        f"but got verified={result.verified}, errors={result.errors}"
    )


def test_c7_signed_bundle_entropy_skips_signature_fields():
    """C7: Entropy scanner must NOT flag signature_value or other crypto fields."""
    bundle = deepcopy(_load_vector("valid-bundle.json"))
    bundle["version"] = "0.2.1"
    # Add a format-valid signature with high-entropy base64 value
    bundle["signatures"] = [
        {
            "signature_id": "sig-entropy-test",
            "algorithm": "ed25519",
            "signer": {"display_name": "ci-signer", "signer_type": "service"},
            "signature_value": base64.b64encode(b"\xde\xad" * 48).decode(),
            "signed_at": "2026-01-01T00:00:00Z",
            "public_key_id": "key-AAAABBBBCCCCDDDDeeeeFFFF1234567890abcdef",
        }
    ]
    bundle["sanitization"] = {
        "engine_name": "pii-shield",
        "engine_version": "1.1.0",
        "method": "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": "sha256:1a2b3c4d",
        "redaction_count": 0,
        "redactions_by_type": {},
        "status": "sanitized",
    }
    bundle = _reseal_bundle(bundle)

    result = verify_bundle_data(bundle, check_sanitized=True, fail_on_raw_entropy=True)
    # Should NOT fail due to signature fields being high-entropy
    entropy_errors = [e for e in result.errors if "high-entropy survivor" in e]
    assert len(entropy_errors) == 0, (
        f"Entropy scanner flagged signature fields as survivors: {entropy_errors}"
    )


def test_h9_redaction_count_mismatch_is_error_when_require_sanitized():
    """H9: redaction_count mismatch must be an error (not warning) when require_sanitized=True."""
    bundle = deepcopy(_load_vector("valid-bundle.json"))
    bundle["version"] = "0.2.1"
    # Insert 2 HIDDEN tokens into content
    bundle["items"][0]["content"]["msg"] = "masked [HIDDEN:aaa111] and [HIDDEN:bbb222] value"
    bundle["sanitization"] = {
        "engine_name": "pii-shield",
        "engine_version": "1.1.0",
        "method": "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": "sha256:1a2b3c4d",
        "redaction_count": 5,  # claims 5 but only 2 exist
        "redactions_by_type": {"email": 5},
        "status": "sanitized",
    }
    bundle = _reseal_bundle(bundle)

    result = verify_bundle_data(bundle, require_sanitized=True)
    assert result.verified is False
    mismatch_errors = [e for e in result.errors if "redaction_count=" in e]
    assert len(mismatch_errors) > 0, (
        f"Expected redaction_count mismatch in errors, got errors={result.errors}, warnings={result.warnings}"
    )


def test_h10_redaction_count_zero_still_detects_mismatch():
    """H10: redaction_count=0 must still detect mismatch when HIDDEN tokens exist."""
    bundle = deepcopy(_load_vector("valid-bundle.json"))
    bundle["version"] = "0.2.1"
    # Insert 3 HIDDEN tokens but claim 0 redactions
    bundle["items"][0]["content"]["msg"] = "[HIDDEN:xxx111] [HIDDEN:yyy222] [HIDDEN:zzz333]"
    bundle["sanitization"] = {
        "engine_name": "pii-shield",
        "engine_version": "1.1.0",
        "method": "deterministic_hmac",
        "token_format": "[HIDDEN:<id>]",
        "salt_fingerprint": "sha256:1a2b3c4d",
        "redaction_count": 0,  # claims 0 but 3 exist
        "redactions_by_type": {},
        "status": "sanitized",
    }
    bundle = _reseal_bundle(bundle)

    # Without require_sanitized: mismatch should appear in warnings
    result = verify_bundle_data(bundle, check_sanitized=True)
    mismatch_warnings = [w for w in result.warnings if "redaction_count=0" in w]
    assert len(mismatch_warnings) > 0, (
        f"Expected redaction_count=0 mismatch in warnings, got warnings={result.warnings}"
    )

    # With require_sanitized: mismatch should appear in errors
    result2 = verify_bundle_data(bundle, require_sanitized=True)
    mismatch_errors = [e for e in result2.errors if "redaction_count=0" in e]
    assert len(mismatch_errors) > 0, (
        f"Expected redaction_count=0 mismatch in errors, got errors={result2.errors}"
    )


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------

def test_cli_help_exits_zero():
    """CLI --help should exit 0."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "guardspine_verify.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"--help exited with {result.returncode}: {result.stderr}"
    assert "GuardSpine" in result.stdout or "guardspine" in result.stdout.lower()


def test_cli_verify_golden_vector_exits_zero():
    """CLI should exit 0 when verifying the golden valid-bundle.json."""
    import subprocess
    vector_path = str(Path(__file__).parent / "test_vectors" / "valid-bundle.json")
    result = subprocess.run(
        [sys.executable, "-m", "guardspine_verify.cli", vector_path],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"CLI exited with {result.returncode} for valid-bundle.json.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
