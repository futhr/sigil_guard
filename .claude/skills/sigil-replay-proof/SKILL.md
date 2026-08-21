---
name: sigil-replay-proof
description: "Apply automatically when SigilGuard must prove that a previously accepted confirmation or nonce cannot be reused, an expired/rotated trust bundle or key is rejected, canonical action/payload digests bind correctly, tampering fails, or v3 compatibility survives the change."
---

# SigilGuard replay proof

Build deterministic fixtures for original, tampered action, tampered payload, wrong actor/origin/sink,
expired/not-yet-valid, repeated nonce/confirmation, rotated/revoked bundle/key, malformed input, and
supported v3 shapes. Exercise public APIs and stable compatibility fields.

Use property/fuzz checks where canonicalization or parser state space warrants them. Verify package
and generic consumer behavior when public contracts change. Never add network access or a permanent
legacy shim to make replay pass.
