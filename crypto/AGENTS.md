# Contents

- `crypto/` pins the envelope scheme: ECDSA P-256 low-S signatures over
  canonical JSON, ECDH-P256 device pairing, AES-GCM-256 payloads with
  associated data.

# Guidelines

- WebCrypto primitives only — no native dependencies, so Bun, browsers
  and Node all execute the same code path.
- Low-S signatures only; reject high-S forms on verify.
- Envelopes authenticate the full header (version, sender device,
  recipient device, key ids, nonce) as associated data.
- Any change to a primitive, encoding, or canonicalization requires new
  test vectors in `wire/` plus a version bump.
