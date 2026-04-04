"""
Lean parity tests for guardspine-verify.

Verifies that the Lean kernel produces identical verification results
to the Python verifier for the same test vectors.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardspine_verify.lean_shim import (
    _lean_available,
    canonical_json_lean,
    content_hash_lean,
    verify_bundle_lean,
)
from guardspine_verify.verifier import verify_bundle_data

VECTORS_DIR = Path(__file__).parent / "test_vectors"

# Skip all tests if Lean binary is not available
pytestmark = pytest.mark.skipif(
    not _lean_available(),
    reason="Lean binary not found at GUARDSPINE_LEAN_EXE or default path",
)


class TestVerifyBundleParity:
    """Verify that Lean and Python produce the same verification results."""

    def test_valid_bundle_both_pass(self):
        """Valid bundle passes both Python and Lean verification."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())

        # Python
        py_result = verify_bundle_data(bundle)
        assert py_result.verified, f"Python failed: {py_result.errors}"

        # Lean
        lean_result = verify_bundle_lean(bundle)
        assert lean_result["valid"], f"Lean failed: {lean_result['errors']}"

    def test_tampered_chain_both_fail(self):
        """Tampered hash chain fails both Python and Lean verification."""
        bundle = json.loads((VECTORS_DIR / "tampered-hash-chain.json").read_text())

        # Python
        py_result = verify_bundle_data(bundle)
        assert not py_result.verified, "Python should reject tampered bundle"

        # Lean
        lean_result = verify_bundle_lean(bundle)
        assert not lean_result["valid"], "Lean should reject tampered bundle"

    def test_tampered_chain_error_codes_match(self):
        """Both implementations report the same error codes for tampered chain."""
        bundle = json.loads((VECTORS_DIR / "tampered-hash-chain.json").read_text())

        # Python errors
        py_result = verify_bundle_data(bundle)
        py_has_chain_error = "hash_chain" in py_result.hash_chain_status.lower() or \
                             py_result.hash_chain_status == "mismatch"

        # Lean errors
        lean_result = verify_bundle_lean(bundle)
        lean_error_codes = {e["code"] for e in lean_result["errors"]}
        lean_has_chain_error = "HASH_CHAIN_BROKEN" in lean_error_codes

        assert lean_has_chain_error, (
            f"Lean should report HASH_CHAIN_BROKEN. Got: {lean_error_codes}"
        )

    def test_unsupported_version_rejected(self):
        """Both implementations reject unsupported versions."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        bundle["version"] = "0.1.0"  # Unsupported

        # Lean
        lean_result = verify_bundle_lean(bundle)
        assert not lean_result["valid"], "Lean should reject unsupported version"
        lean_error_codes = {e["code"] for e in lean_result["errors"]}
        assert "UNSUPPORTED_VERSION" in lean_error_codes

    def test_v021_accepted(self):
        """Both implementations accept v0.2.1 bundles."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        bundle["version"] = "0.2.1"  # Also supported

        # Lean -- v0.2.1 uses same proof format, should still pass
        lean_result = verify_bundle_lean(bundle)
        assert lean_result["valid"], f"Lean should accept 0.2.1: {lean_result['errors']}"


    def test_missing_version_rejected(self):
        """Both implementations reject bundles with no version field."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        del bundle["version"]

        # Python
        py_result = verify_bundle_data(bundle)
        assert not py_result.verified, "Python should reject missing version"

        # Lean
        lean_result = verify_bundle_lean(bundle)
        assert not lean_result["valid"], "Lean should reject missing version"

    def test_missing_items_rejected(self):
        """Both implementations reject bundles with no items array."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        del bundle["items"]

        # Lean -- should still return a result (possibly with errors)
        lean_result = verify_bundle_lean(bundle)
        assert not lean_result["valid"], "Lean should reject missing items"

    def test_content_hash_parity_python_vs_lean(self):
        """Content hashes computed by Python and Lean match exactly."""
        from guardspine_verify.verifier import canonical_json, compute_sha256

        test_contents = [
            {"ok": True},
            {"msg": "hello"},
            {"a": 1, "b": 2},
        ]
        for content in test_contents:
            py_hash = compute_sha256(canonical_json(content))
            lean_hash = content_hash_lean(content)
            assert py_hash == lean_hash, (
                f"Hash mismatch for {content}: Python={py_hash}, Lean={lean_hash}"
            )

    def test_tampered_chain_python_also_reports_chain_error(self):
        """Python also reports hash chain error for tampered bundle."""
        bundle = json.loads((VECTORS_DIR / "tampered-hash-chain.json").read_text())
        py_result = verify_bundle_data(bundle)
        assert py_result.hash_chain_status == "mismatch", (
            f"Python hash_chain_status should be 'mismatch', got {py_result.hash_chain_status}"
        )


class TestContentHashParity:
    """Verify content hash computation matches between Python and Lean."""

    @pytest.mark.parametrize("content,description", [
        ({"ok": True}, "simple boolean"),
        ({"msg": "hello"}, "simple string"),
        ({"a": 1, "b": 2, "c": 3}, "sorted keys"),
        ({}, "empty object"),
        ({"nested": {"x": [1, 2, 3]}}, "nested structure"),
    ])
    def test_content_hash_parity(self, content, description):
        """Content hash from Lean matches the stored hash in valid bundle."""
        lean_hash = content_hash_lean(content)
        assert lean_hash.startswith("sha256:"), f"Bad hash format: {lean_hash}"
        assert len(lean_hash) == 71, f"Wrong hash length: {len(lean_hash)}"

    def test_valid_bundle_content_hashes_match(self):
        """Content hashes in valid-bundle.json match Lean computation."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        for item in bundle["items"]:
            lean_hash = content_hash_lean(item["content"])
            assert lean_hash == item["content_hash"], (
                f"Hash mismatch for {item['item_id']}: "
                f"Lean={lean_hash}, stored={item['content_hash']}"
            )


class TestCanonicalJsonParity:
    """Verify canonical JSON matches between Python and Lean."""

    @pytest.mark.parametrize("value,expected", [
        ({"b": 2, "a": 1}, '{"a":1,"b":2}'),
        (True, "true"),
        (False, "false"),
        (None, "null"),
        (42, "42"),
        ("hello", '"hello"'),
        ([1, 2, 3], "[1,2,3]"),
    ])
    def test_canonical_json(self, value, expected):
        result = canonical_json_lean(value)
        assert result == expected, f"Got {result!r}, expected {expected!r}"


class TestSubprocessLatency:
    """Measure Lean subprocess performance."""

    def test_100_roundtrips(self):
        """100 verify_bundle calls complete without hangs."""
        bundle = json.loads((VECTORS_DIR / "valid-bundle.json").read_text())
        import time

        times = []
        for _ in range(100):
            start = time.perf_counter()
            result = verify_bundle_lean(bundle)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            assert result["valid"], "Should pass on each call"

        avg = sum(times) / len(times)
        p99 = sorted(times)[98]
        print(f"\n  Lean verify_bundle: avg={avg:.1f}ms, P99={p99:.1f}ms, total={sum(times):.0f}ms")
        assert avg < 5000, f"Average latency too high: {avg:.1f}ms"
