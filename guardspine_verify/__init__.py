"""
GuardSpine Verify - Offline verification for evidence bundles.

Usage:
    from guardspine_verify import verify_bundle, verify_bundle_data

    # Verify a file
    result = verify_bundle("bundle.json")

    # Verify bundle data
    result = verify_bundle_data(bundle_dict)
"""

from .verifier import (
    VerificationResult,
    verify_bundle,
    verify_bundle_data,
    verify_hash_chain,
    verify_root_hash,
    verify_content_hashes,
    verify_signatures,
    verify_sanitization,
)

__version__ = "0.2.1"
__all__ = [
    "VerificationResult",
    "verify_bundle",
    "verify_bundle_data",
    "verify_hash_chain",
    "verify_root_hash",
    "verify_content_hashes",
    "verify_signatures",
    "verify_sanitization",
]
