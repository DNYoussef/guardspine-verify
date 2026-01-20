# Hello Bundle: Your First 60 Seconds with GuardSpine

**The pitch:** *"You don't need to trust me. Verify the bundle yourself."*

## What You're Looking At

This is an **evidence bundle** - a cryptographically verifiable record of:
- What changed
- Who approved it
- When it happened
- That nothing was tampered with

## Try It Yourself (15 seconds)

```bash
# Install the verifier
pip install guardspine-verify

# Verify a known-good bundle
curl -sL https://raw.githubusercontent.com/DNYoussef/guardspine-verify/main/tests/test_vectors/valid-bundle.json -o bundle.json
guardspine-verify bundle.json
```

**Output:**
```
+------------------+--------+
| Check            | Status |
+------------------+--------+
| Hash Chain       | PASS   |
| Content Hashes   | PASS   |
| Sequence         | PASS   |
+------------------+--------+

BUNDLE VERIFIED
```

## Now Try a Tampered Bundle (15 seconds)

```bash
# Try to verify a tampered bundle
curl -sL https://raw.githubusercontent.com/DNYoussef/guardspine-verify/main/tests/test_vectors/tampered-hash-chain.json -o tampered.json
guardspine-verify tampered.json
```

**Output:**
```
+------------------+--------+
| Check            | Status |
+------------------+--------+
| Hash Chain       | FAIL   |
| Content Hashes   | PASS   |
| Sequence         | PASS   |
+------------------+--------+

VERIFICATION FAILED
Error: Hash chain broken at entry 1
  Expected: sha256:e3b0c44298fc1c149...
  Found:    sha256:TAMPERED_WRONG_HASH...
```

## What Just Happened?

1. The **valid bundle** has an unbroken hash chain - each entry links to the previous one
2. The **tampered bundle** had its hash chain modified - verification caught it immediately
3. **You ran this offline** - no network call to GuardSpine servers needed

## Why This Matters

When your auditor asks: *"How do I know this evidence wasn't modified?"*

Your answer: *"Run `guardspine-verify` yourself. The math proves it."*

## Next Steps

- [Read the spec](https://github.com/DNYoussef/guardspine-spec) - understand the bundle format
- [Build a connector](https://github.com/DNYoussef/guardspine-connector-template) - emit bundles from your systems
- [Try GuardSpine Platform](https://guardspine.io) - approval UI, workflow automation

---

**GuardSpine**: Evidence infrastructure for the AI office.
