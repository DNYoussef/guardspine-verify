import json
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
