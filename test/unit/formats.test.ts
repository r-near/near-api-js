import { afterEach, describe, expect, it, vi } from 'vitest';

type ProviderConstructor = new (connection: {
    url: string;
}) => {
    viewAccount(params: { accountId: string }): Promise<unknown>;
};
type ErrorConstructor = abstract new (...args: never[]) => Error;

async function expectPublicErrorConstructor(
    JsonRpcProvider: ProviderConstructor,
    AccountDoesNotExistError: ErrorConstructor
) {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(
            JSON.stringify({
                jsonrpc: '2.0',
                id: '1',
                error: {
                    name: 'HANDLER_ERROR',
                    cause: {
                        name: 'UNKNOWN_ACCOUNT',
                        info: {
                            requested_account_id: 'missing.testnet',
                            block_hash: 'block-hash',
                            block_height: 1,
                        },
                    },
                    code: -32000,
                    message: 'Account does not exist',
                },
            }),
            { headers: { 'content-type': 'application/json' } }
        )
    );

    await expect(
        new JsonRpcProvider({ url: 'http://unused' }).viewAccount({ accountId: 'missing.testnet' })
    ).rejects.toBeInstanceOf(AccountDoesNotExistError);
}

describe('published formats', () => {
    afterEach(() => vi.restoreAllMocks());

    it('loads the ESM and CommonJS bundles', async () => {
        const esm = await import('near-api-js');
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const cjs = require('near-api-js');

        expect(esm.KeyPair).toBeTypeOf('function');
        expect(cjs.KeyPair).toBeTypeOf('function');
    });

    it('derives and recovers ML-DSA-65 keys from both seed-phrase bundles', async () => {
        const esm = await import('near-api-js/seed-phrase');
        const cjs = require('near-api-js/seed-phrase') as typeof esm;
        const phrase = 'tag interest match crew twin proof cushion visit ball square aim armed';

        for (const bundle of [esm, cjs]) {
            const key = bundle.parseSeedPhrase(phrase, { keyType: 'ml-dsa-65' });
            expect(key.toString()).toMatch(/^ml-dsa-65:/);
            expect(key.getPublicKey().data).toHaveLength(1952);
            const message = new TextEncoder().encode('published seed-phrase format');
            expect(key.verify(message, key.sign(message).signature)).toBe(true);
            expect(bundle.deriveSeedPhraseKeys(phrase)).toHaveLength(4);
            const generated = bundle.generateSeedPhrase({ keyType: 'ml-dsa-65' });
            expect(generated.seedPhrase.split(' ')).toHaveLength(24);
            expect(bundle.parseSeedPhrase(generated.seedPhrase, { keyType: 'ml-dsa-65' }).toString()).toBe(
                generated.keyPair.toString()
            );
        }

        expect(esm.parseSeedPhrase(phrase, { keyType: 'ml-dsa-65' }).toString()).toBe(
            cjs.parseSeedPhrase(phrase, { keyType: 'ml-dsa-65' }).toString()
        );
    });

    it('preserves RPC error identity in the ESM build', async () => {
        const { JsonRpcProvider } = await import('near-api-js');
        const { AccountDoesNotExistError } = await import('near-api-js/rpc-errors');

        await expectPublicErrorConstructor(JsonRpcProvider, AccountDoesNotExistError);
    });

    it('preserves RPC error identity in the CommonJS build', async () => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { JsonRpcProvider } = require('near-api-js');
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { AccountDoesNotExistError } = require('near-api-js/rpc-errors');

        await expectPublicErrorConstructor(JsonRpcProvider, AccountDoesNotExistError);
    });
});
