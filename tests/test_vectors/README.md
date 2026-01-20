# Test Vectors for GuardSpine Verification

This directory contains known-good and known-bad bundles for testing verification implementations.

## Test Cases

| File | Expected Result | What It Tests |
|------|-----------------|---------------|
| `valid-bundle.json` | PASS | Complete valid bundle with proper hash chain |
| `tampered-hash-chain.json` | FAIL | Hash chain has been modified (broken link) |

## Usage

```bash
# Should pass
guardspine-verify tests/test_vectors/valid-bundle.json
# Exit code: 0

# Should fail
guardspine-verify tests/test_vectors/tampered-hash-chain.json
# Exit code: 1
```

## Implementing Your Own Verifier

If you're implementing verification in another language, these test vectors define the expected behavior:

### valid-bundle.json

```
Hash Chain Verification:
  Entry 0: content_hash = sha256:e3b0c44298fc1c149...
           previous_hash = null (first entry)

  Entry 1: content_hash = sha256:d7a8fbb307d78094...
           previous_hash = sha256:e3b0c44298fc1c149... (matches Entry 0)

Result: PASS - chain is unbroken
```

### tampered-hash-chain.json

```
Hash Chain Verification:
  Entry 0: content_hash = sha256:e3b0c44298fc1c149...
           previous_hash = null (first entry)

  Entry 1: content_hash = sha256:d7a8fbb307d78094...
           previous_hash = sha256:TAMPERED_WRONG_HASH... (DOES NOT MATCH Entry 0)

Result: FAIL - chain is broken at entry 1
```

## Adding New Test Vectors

When adding new test cases:

1. Include `_comment` field explaining the test
2. Include `_expected_result` field (PASS or FAIL with reason)
3. If tampered, include `_tampered_field` indicating what was modified
4. Update this README with the new test case

## Verification Checks

A compliant verifier MUST check:

1. **Hash Chain Integrity**: Each entry's `previous_hash` matches the prior entry's `content_hash`
2. **Content Hashes**: Each item's `content_hash` matches the hash of its `content`
3. **Root Hash**: The `root_hash` correctly summarizes the entire chain
4. **Signatures**: Cryptographic signatures are valid (if signature verification is enabled)
5. **Sequence Numbers**: Entries are in sequential order starting from 0
