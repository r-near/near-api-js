---
"near-api-js": minor
---

Add explicit ML-DSA-65 seed-phrase generation and recovery using NEP-649, with hardened derivation paths and optional BIP39 passphrases. Expose both default paths in both key trees through `deriveSeedPhraseKeys`. Existing Ed25519 defaults and key outputs are unchanged.
