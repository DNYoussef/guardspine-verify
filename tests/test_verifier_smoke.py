import json
from pathlib import Path

from guardspine_verify import verify_bundle_data


def _load_vector(name: str) -> dict:
    path = Path(__file__).parent / "test_vectors" / name
    return json.loads(path.read_text(encoding="utf-8"))


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
