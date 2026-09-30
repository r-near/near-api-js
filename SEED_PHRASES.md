# Seed phrases

Import seed-phrase utilities from `near-api-js/seed-phrase`. These APIs use English BIP39 mnemonics and return the existing `KeyPair` objects used by NEAR signers.

## Existing Ed25519 keys

Existing calls and key outputs are unchanged:

```typescript
import { generateSeedPhrase, parseSeedPhrase } from 'near-api-js/seed-phrase';

const { seedPhrase, keyPair } = generateSeedPhrase(); // 12 words, Ed25519
const recovered = parseSeedPhrase(seedPhrase);
```

The default derivation path remains `m/44'/397'/0'`. Calling either function without options does not switch an existing account to a post-quantum key.

## NEP-649 ML-DSA-65 keys

This implements the [current draft NEP-649](https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/nep-0649.md), with interoperability checked against that revision's reference vectors. The proposal is not yet finalized.

Select the new key type explicitly:

```typescript
import { generateSeedPhrase, parseSeedPhrase, type SeedPhraseOptions } from 'near-api-js/seed-phrase';

const options: SeedPhraseOptions = {
    keyType: 'ml-dsa-65',
    derivationPath: "m/44'/397'/0'/0'/1'",
};
const { seedPhrase, keyPair } = generateSeedPhrase(options); // 24 words
const recovered = parseSeedPhrase(seedPhrase, options);
```

The key type, path, and BIP39 passphrase must match when recovering a key. With no explicit path, ML-DSA-65 also uses `m/44'/397'/0'`, but NEP-649 separates its derivation tree from Ed25519. The same phrase and path therefore produce independent keys for the two key types.

New ML-DSA-65 phrases contain 24 words. Recovery accepts existing valid 12-, 15-, 18-, 21-, and 24-word phrases. Recovering a shorter phrase does not increase its original entropy. ML-DSA-65 recovery validates the mnemonic checksum and accepts only hardened NEAR paths: `m/44'/397'/account'` or `m/44'/397'/account'/change'/index'` with optional additional hardened components. Each index must be between 0 and 2147483647. The incomplete four-component form is rejected.

ML-DSA-65 private keys serialize with the `ml-dsa-65:` prefix and the 4032-byte expanded secret key expected by `KeyPair.fromString`. The derived key can sign messages and transactions using the existing API; transaction support also depends on the target network's protocol version.

## BIP39 passphrases

Both key types accept an optional `passphrase` in `SeedPhraseOptions`. The passphrase is part of key derivation; a different passphrase produces a different valid key, with no wrong-passphrase error. Passphrases are Unicode NFKD-normalized and case-sensitive. They are not included in the returned mnemonic, so store recovery instructions securely and never log the mnemonic, passphrase, or secret key.

## Recover both default paths and trees

```typescript
import { deriveSeedPhraseKeys } from 'near-api-js/seed-phrase';

const candidates = deriveSeedPhraseKeys(seedPhrase);
for (const { keyType, derivationPath, keyPair } of candidates) {
    // Use this candidate in your recovery flow (see the RPC hash distinction below).
}
```

`deriveSeedPhraseKeys(seedPhrase, { passphrase })` returns four candidates: Ed25519 and ML-DSA-65, each at `m/44'/397'/0'` and `m/44'/397'/0'/0'/1'`. It only derives keys locally; it does not scan the network, identify accounts, add access keys, or search custom paths. Use `parseSeedPhrase` with the exact options when a custom path was used.

ML-DSA-65 candidates contain full public keys. RPC access-key lists instead return `ml-dsa-65-hash:` handles, so their strings cannot be compared directly. NEP-645 defines the handle as `ml-dsa-65-hash:` plus base58 of SHA3-256 over the UTF-8 domain `near:ml-dsa-65-pubkey-hash:v1` concatenated with the raw 1952-byte public key. Account discovery and that RPC-handle matching remain the wallet application's responsibility.

The derivation is implemented by `near-seed-phrase`. See [NEP-649](https://github.com/near/NEPs/pull/649) and its [independent reference vectors](https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/assets/nep-0649/test-vectors.json) for the algorithm and interoperability data.
