import {
    deriveSeedPhraseKeys as internalDeriveSeedPhraseKeys,
    generateSeedPhrase as internalGenerateSeedPhrase,
    parseSeedPhrase as internalParseSeedPhrase,
    type SeedPhraseOptions,
} from 'near-seed-phrase';
import type { KeyPairString } from '../crypto/constants.js';
import { KeyPair } from '../crypto/key_pair.js';

export type { SeedPhraseOptions } from 'near-seed-phrase';

/**
 * Derive a key pair from an English seed phrase.
 *
 * Without options, preserves the legacy Ed25519 derivation at `m/44'/397'/0'`.
 * Set `keyType: 'ml-dsa-65'` to opt into the NEP-649 post-quantum derivation tree.
 * Keep the key type, derivation path, and any BIP39 passphrase with your recovery
 * instructions: changing any of them produces a different key.
 *
 * @param seedPhrase The mnemonic to recover. Existing 12-word phrases are supported.
 * @param options Key type, hardened NEAR derivation path, and optional BIP39 passphrase.
 */
export function parseSeedPhrase(seedPhrase: string, options?: SeedPhraseOptions): KeyPair {
    const { secretKey } = internalParseSeedPhrase(seedPhrase, options);

    return KeyPair.fromString(secretKey as KeyPairString);
}

/**
 * Generate an English seed phrase and its key pair.
 *
 * Defaults to a 12-word Ed25519 phrase for backwards compatibility. Explicitly
 * selecting `keyType: 'ml-dsa-65'` generates a 24-word NEP-649 phrase.
 *
 * @param options Key type, hardened NEAR derivation path, and optional BIP39 passphrase.
 */
export function generateSeedPhrase(options?: SeedPhraseOptions): { seedPhrase: string; keyPair: KeyPair } {
    const { seedPhrase, secretKey } = internalGenerateSeedPhrase(undefined, options);

    return {
        seedPhrase,
        keyPair: KeyPair.fromString(secretKey as KeyPairString),
    };
}

/** A key pair and the derivation settings needed to recover it. */
export interface SeedPhraseKey {
    keyType: 'ed25519' | 'ml-dsa-65';
    derivationPath: string;
    keyPair: KeyPair;
}

/**
 * Derive the four NEP-649 default recovery candidates: the Ed25519 and ML-DSA-65
 * trees at `m/44'/397'/0'` and `m/44'/397'/0'/0'/1'`.
 *
 * This does not discover accounts or custom derivation paths on the network.
 * @param seedPhrase The English mnemonic to recover.
 * @param options The BIP39 passphrase, if one was used when the keys were created.
 */
export function deriveSeedPhraseKeys(seedPhrase: string, options?: { passphrase?: string }): SeedPhraseKey[] {
    return internalDeriveSeedPhraseKeys(seedPhrase, options).map(({ keyType, derivationPath, secretKey }) => ({
        keyType,
        derivationPath,
        keyPair: KeyPair.fromString(secretKey as KeyPairString),
    }));
}
