# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 GuardSpine, Inc.
# Licensed under the Business Source License 1.1. See LICENSE for terms.
# Change License: Apache-2.0. Change Date: see LICENSE.
"""
Lean shim for guardspine-verify.

Delegates bundle verification to the compiled Lean binary via subprocess.
Raises RuntimeError if the Lean binary is not available (no Python fallback).
Use _lean_available() to check before calling.

The Lean kernel handles: version validation, hash chain verification,
root hash verification, content hash verification, cross-check.
Python handles: signature verification, sanitization, CLI formatting.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

# Lean binary location: env var only (no hard-coded paths)
_LEAN_PATH = os.environ.get("GUARDSPINE_LEAN_BIN") or os.environ.get("GUARDSPINE_LEAN_EXE")
LEAN_EXE: Path | None = Path(_LEAN_PATH) if _LEAN_PATH else None


def _lean_available() -> bool:
    """Check if the Lean binary exists and is executable."""
    return LEAN_EXE is not None and LEAN_EXE.is_file()


def _call_lean(entrypoint: str, payload: dict[str, Any]) -> Any:
    """Call the Lean subprocess bridge and return the result."""
    if LEAN_EXE is None:
        raise RuntimeError(
            "Lean binary not configured. "
            "Set GUARDSPINE_LEAN_BIN to the path of the guardspine binary."
        )
    start = time.perf_counter()
    proc = subprocess.run(
        [str(LEAN_EXE), entrypoint],
        input=json.dumps(payload) + "\n",
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    if proc.returncode != 0:
        stderr = proc.stderr.strip() if proc.stderr else ""
        raise RuntimeError(
            f"Lean subprocess failed (exit {proc.returncode}, {elapsed_ms:.1f}ms): {stderr}"
        )

    response = json.loads(proc.stdout)
    if not response.get("ok"):
        raise RuntimeError(f"Lean error: {response.get('error', 'unknown')}")
    return response["result"]


def verify_bundle_lean(bundle: dict[str, Any]) -> dict[str, Any]:
    """Verify a bundle using the Lean kernel.

    Returns a dict with:
        valid: bool
        errors: list[dict] with code and message

    This covers: version check, hash chain, root hash,
    content hashes, and cross-check (items vs chain).
    Signature and sanitization checks are NOT included
    (handled Python-side).
    """
    # Send the full bundle to Lean's verify_bundle entrypoint
    result = _call_lean("verify_bundle", bundle)
    return result


def canonical_json_lean(value: Any) -> str:
    """Compute canonical JSON using the Lean kernel."""
    result = _call_lean("canonical_json", {"value": value})
    return result


def content_hash_lean(content: Any) -> str:
    """Compute content hash using the Lean kernel."""
    result = _call_lean("compute_content_hash", {"content": content})
    return result
