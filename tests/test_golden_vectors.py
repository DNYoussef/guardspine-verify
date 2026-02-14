import json
import os
from pathlib import Path
import pytest
from guardspine_verify.verifier import verify_bundle_data

# Resolve path to golden vectors
# 1. Env var: FIXTURES_DIR
# 2. Fallback: Relative path to guardspine-spec/fixtures/golden-vectors
current_dir = Path(__file__).parent
default_fixtures_dir = current_dir.parent.parent / "guardspine-spec" / "fixtures" / "golden-vectors"
FIXTURES_DIR = Path(os.environ.get("FIXTURES_DIR", default_fixtures_dir))
VECTORS_PATH = FIXTURES_DIR / "v0.2.0.json"

def test_golden_vectors_verification():
    if not VECTORS_PATH.exists():
        pytest.skip(f"Golden vectors file not found at {VECTORS_PATH}")

    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    for case in vectors:
        print(f"Testing vector: {case['id']}")
        
        # Construct a bundle that matches what verifier expects
        # The golden vector 'expected' has 'items' and 'immutability_proof'.
        # We need to wrap this in a top-level bundle structure (bundle_id, version, etc.)
        
        expected_data = case["expected"]
        
        bundle = {
            "bundle_id": "test-bundle-id",
            "version": "0.2.0",
            "created_at": "2023-01-01T00:00:00Z",
            "provider": "test-provider",
            "items": expected_data["items"],
            "immutability_proof": expected_data["immutability_proof"],
            "metadata": {
                "artifact_id": "test-artifact",
                "risk_tier": "low",
                "scope": "test:scope",
                "provider": "test-provider"
            }
        }
        
        # Verify
        # This will raise an exception if verification fails
        results = verify_bundle_data(bundle)
        
        # Assert all checks passed
        assert results.verified is True, f"Verification failed. Status: {results.status}, Errors: {results.errors}"
        assert results.status == "verified"
        assert results.hash_chain_status == "verified"
        assert results.root_hash_status == "verified"
        assert results.content_hash_status == "verified"

if __name__ == "__main__":
    pytest.main([__file__])
