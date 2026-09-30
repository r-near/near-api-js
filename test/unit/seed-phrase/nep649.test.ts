import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { KeyPair } from '../../../src/crypto/key_pair.js';
import { deriveSeedPhraseKeys, generateSeedPhrase, parseSeedPhrase } from '../../../src/seed-phrase/index.js';
import { baseDecode } from '../../../src/utils/index.js';

const legacyPhrase = 'tag interest match crew twin proof cushion visit ball square aim armed';
const mnemonic =
    'orbit pill once attitude garbage prefer afford what banner weird path present dream tide unfold despair inject physical lens battle fancy finish fever toward';
const shortPath = "m/44'/397'/0'";
const fullPath = "m/44'/397'/0'/0'/1'";
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

describe('NEP-649 seed phrases', () => {
    // SHA-256 digests of the complete official expanded secret/public key bytes.
    // Source: https://github.com/vsavchyn-dev/NEPs/blob/cecbad372435edd17607a0a45401ab2cf5839fc8/neps/assets/nep-0649/test-vectors.json
    test.each([
        {
            derivationPath: shortPath,
            secretDigest: '22552d23d11aa06162499d16b7264eeb4f4f0b0eeebc37b23cbc92188c9f82aa',
            publicDigest: '377c1d992fb7b6f7975f9d1ad81c41ea80c27587ea8714b51e62057923937391',
        },
        {
            derivationPath: "m/44'/397'/1'/0'/1'",
            secretDigest: 'fda52994570099e3d7d4bdafff160422b96391d70625887e43b58edc79ab55b4',
            publicDigest: '6243d09f02e2adc4698cab290b8ddbdeb8da9399a38f81172d02bb40122c7780',
        },
    ])('matches the independent vector at $derivationPath', ({ derivationPath, secretDigest, publicDigest }) => {
        const key = parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65', derivationPath });
        expect(key.toString()).toMatch(/^ml-dsa-65:/);
        const secret = baseDecode(key.toString().split(':')[1]!);
        const publicKey = key.getPublicKey().data;
        expect(secret.length).toBe(4032);
        expect(publicKey.length).toBe(1952);
        expect(digest(secret)).toBe(secretDigest);
        expect(digest(publicKey)).toBe(publicDigest);
    });

    test('opts into ML-DSA-65 without changing the legacy default', () => {
        const legacy = parseSeedPhrase(legacyPhrase);
        expect(parseSeedPhrase(legacyPhrase, {}).toString()).toBe(legacy.toString());
        expect(parseSeedPhrase(legacyPhrase, { keyType: 'ed25519' }).toString()).toBe(legacy.toString());
        expect(parseSeedPhrase(legacyPhrase, { keyType: 'ml-dsa-65' }).toString()).toMatch(/^ml-dsa-65:/);
        expect(parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65' }).toString()).toBe(
            parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65', derivationPath: shortPath }).toString()
        );
    });

    test('supports an explicit legacy derivation path', () => {
        // Captured from the published near-seed-phrase@0.2.1 before this change.
        expect(parseSeedPhrase(legacyPhrase, { derivationPath: "m/44'/397'/1'" }).toString()).toBe(
            'ed25519:2zJ8fEQnBGM5jCckTDdrQLiLyK2zZ4Ld3JbS8PpGJ6AXBCmLTV56PVbRayqb2r3hGFbmk5m9nn4xVZLdw6aDJySr'
        );
    });

    test('normalizes mnemonic case and whitespace', () => {
        const irregular = `  ${mnemonic.toUpperCase().split(' ').join('\n\t')}  `;
        expect(parseSeedPhrase(irregular, { keyType: 'ml-dsa-65' }).toString()).toBe(
            parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65' }).toString()
        );
    });

    test('normalizes compatibility characters before validating the mnemonic', () => {
        const fullwidth = mnemonic.replace(/[a-z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 0xfee0));
        expect(parseSeedPhrase(fullwidth, { keyType: 'ml-dsa-65' }).toString()).toBe(
            parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65' }).toString()
        );
    });

    test('forwards the BIP39 passphrase, including Unicode normalization', () => {
        const withPassphrase = parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65', passphrase: 'caf\u00e9' });
        expect(withPassphrase.toString()).not.toBe(parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65' }).toString());
        expect(withPassphrase.toString()).toBe(
            parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65', passphrase: 'cafe\u0301' }).toString()
        );
    });

    test.each(['', 'not a mnemonic', Array(12).fill('abandon').join(' ')])('rejects an invalid PQ phrase', (phrase) => {
        expect(() => parseSeedPhrase(phrase, { keyType: 'ml-dsa-65' })).toThrow();
    });

    test.each(['', 'm', "m/44'/397'/0", "m/44'/397'/0'/0'", "m/44'/397'/2147483648'"])(
        'rejects an invalid PQ path: %s',
        (derivationPath) => {
            expect(() => parseSeedPhrase(mnemonic, { keyType: 'ml-dsa-65', derivationPath })).toThrow();
        }
    );

    test('rejects unsupported key types at runtime', () => {
        // @ts-expect-error JavaScript callers can still supply an unsupported key type.
        expect(() => parseSeedPhrase(mnemonic, { keyType: 'secp256k1' })).toThrow();
    });

    test('retains 12-word Ed25519 generation by default', () => {
        const { seedPhrase, keyPair } = generateSeedPhrase();
        expect(seedPhrase.split(' ')).toHaveLength(12);
        expect(keyPair.toString()).toMatch(/^ed25519:/);
        expect(parseSeedPhrase(seedPhrase).toString()).toBe(keyPair.toString());
    });

    test('generates and recovers a 24-word PQ phrase with explicit options', () => {
        const options = { keyType: 'ml-dsa-65', derivationPath: fullPath, passphrase: 'test passphrase' } as const;
        const { seedPhrase, keyPair } = generateSeedPhrase(options);
        expect(seedPhrase.split(' ')).toHaveLength(24);
        expect(keyPair.toString()).toMatch(/^ml-dsa-65:/);
        expect(parseSeedPhrase(seedPhrase, options).toString()).toBe(keyPair.toString());
        const restored = KeyPair.fromString(keyPair.toString());
        const message = new TextEncoder().encode('NEP-649 recovery round trip');
        const { signature } = restored.sign(message);
        expect(keyPair.verify(message, signature)).toBe(true);
        expect(keyPair.verify(new TextEncoder().encode('different message'), signature)).toBe(false);
        expect(generateSeedPhrase(options).seedPhrase).not.toBe(seedPhrase);
    });

    test('returns both default paths in both trees for recovery', () => {
        const options = { passphrase: 'recovery passphrase' };
        const candidates = deriveSeedPhraseKeys(legacyPhrase, options);
        expect(candidates).toHaveLength(4);
        const expected = ['ed25519', 'ml-dsa-65'].flatMap((keyType) =>
            [shortPath, fullPath].map((path) => `${keyType}:${path}`)
        );
        expect(candidates.map(({ keyType, derivationPath }) => `${keyType}:${derivationPath}`).sort()).toEqual(
            expected.sort()
        );
        for (const { keyType, derivationPath, keyPair } of candidates) {
            expect(keyPair.toString()).toBe(
                parseSeedPhrase(legacyPhrase, { ...options, keyType, derivationPath }).toString()
            );
        }
        expect(new Set(candidates.map(({ keyPair }) => keyPair.getPublicKey().toString())).size).toBe(4);
    });

    test('recovers the original Ed25519 keys alongside the PQ candidates', () => {
        const candidates = deriveSeedPhraseKeys(legacyPhrase).filter(({ keyType }) => keyType === 'ed25519');
        const keysByPath = Object.fromEntries(
            candidates.map(({ derivationPath, keyPair }) => [derivationPath, keyPair.getPublicKey().toString()])
        );
        // Both expected public keys come from published near-seed-phrase@0.2.1.
        expect(keysByPath).toEqual({
            [shortPath]: 'ed25519:9uMmkWHWqnqwFcAhH2tS3x3cc4hzGKa5TGWFajMXGkDX',
            [fullPath]: 'ed25519:9UNVzLPmhrE9Snn9oK9eJN8d4XHFVz6Wr3hbvYk1fctp',
        });
    });
});
