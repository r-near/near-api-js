import * as seedPhrase from 'near-api-js/seed-phrase';
import { expect, test } from 'vitest';

test('import from "near-api-js/seed-phrase" exposes only certain objects', () => {
    expect(seedPhrase).toMatchInlineSnapshot(`
      {
        "deriveSeedPhraseKeys": [Function],
        "generateSeedPhrase": [Function],
        "parseSeedPhrase": [Function],
      }
    `);
});

test('published seed-phrase entry point supports ML-DSA-65 recovery', () => {
    const generated = seedPhrase.generateSeedPhrase({ keyType: 'ml-dsa-65' });
    expect(generated.seedPhrase.split(' ')).toHaveLength(24);
    expect(seedPhrase.parseSeedPhrase(generated.seedPhrase, { keyType: 'ml-dsa-65' }).toString()).toBe(
        generated.keyPair.toString()
    );
    expect(seedPhrase.deriveSeedPhraseKeys(generated.seedPhrase)).toHaveLength(4);
});
